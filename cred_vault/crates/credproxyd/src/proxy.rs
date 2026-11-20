//! Data plane: transparent TLS capture.
//!
//! SNI (or the original destination IP when SNI is absent) determines the
//! target. The inner Host must agree with it. Every header is scanned for a
//! registered fakecred bound to the target; bound fakecreds are replaced by
//! their inline `real_cred` (including inside an `Authorization: Basic`
//! credential), and everything else is forwarded unchanged. A fakecred the
//! daemon substituted never leaves it (headers only; body and query are not
//! scanned by design).

use std::borrow::Cow;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue, AUTHORIZATION, HOST};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::audit::{self, Audit};
use crate::placeholder::{contains_anchor, DISCOVERY_ANCHORS};
use crate::registry::Entry;
use crate::runtime::{BoxError, ResBody, Runtime, Shared};

pub enum ProxyError {
    Reject(StatusCode, &'static str),
    Internal(anyhow::Error),
}

impl From<anyhow::Error> for ProxyError {
    fn from(e: anyhow::Error) -> Self {
        ProxyError::Internal(e)
    }
}

// ---------------------------------------------------------------------------
// Target selection
// ---------------------------------------------------------------------------

/// The origin identity for one captured connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// DNS SNI (no trailing dot, lowercased).
    Dns(String),
    /// IP literal from SNI or the original destination.
    Ip(IpAddr),
}

impl Target {
    /// SNI wins when present. An IP SNI must equal the original destination
    /// IP; no SNI falls back to the original destination IP.
    fn from_handshake(orig: SocketAddr, sni: Option<&str>) -> Result<Target, &'static str> {
        match sni.filter(|s| !s.is_empty()) {
            Some(sni) => {
                let sni = sni.trim_end_matches('.').to_ascii_lowercase();
                if let Ok(ip) = sni.parse::<IpAddr>() {
                    if ip != orig.ip() {
                        return Err("IP SNI does not match the original destination");
                    }
                    Ok(Target::Ip(ip))
                } else {
                    Ok(Target::Dns(sni))
                }
            }
            None => Ok(Target::Ip(orig.ip())),
        }
    }

    fn host(&self) -> String {
        match self {
            Target::Dns(host) => host.clone(),
            Target::Ip(ip) => ip.to_string(),
        }
    }

    /// Host header / authority for the origin. The port is omitted at 443 and
    /// IPv6 literals are bracketed.
    fn authority(&self, port: u16) -> String {
        match self {
            Target::Dns(host) => {
                if port == 443 {
                    host.clone()
                } else {
                    format!("{host}:{port}")
                }
            }
            Target::Ip(ip) if port == 443 => {
                if ip.is_ipv6() {
                    format!("[{ip}]")
                } else {
                    ip.to_string()
                }
            }
            Target::Ip(ip) => {
                if ip.is_ipv6() {
                    format!("[{ip}]:{port}")
                } else {
                    format!("{ip}:{port}")
                }
            }
        }
    }

    fn server_name(&self) -> anyhow::Result<ServerName<'static>> {
        match self {
            Target::Dns(host) => ServerName::try_from(host.clone())
                .map_err(|_| anyhow!("bad DNS target for origin TLS: {host}")),
            Target::Ip(ip) => Ok(ServerName::IpAddress((*ip).into())),
        }
    }
}

// ---------------------------------------------------------------------------
// Transparent capture
// ---------------------------------------------------------------------------

pub struct Transparent {
    /// Snapshot source consulted per connection, so a CA rotation reaches new
    /// connections without rebinding.
    pub shared: Shared,
    pub ingress: &'static str,
}

/// Handles one accepted TCP connection from the transparent listener.
pub async fn handle_transparent_conn(stream: TcpStream, peer: SocketAddr, conn: Transparent) {
    let local = stream.local_addr().ok();
    let orig = match crate::ingress::original_dst(stream.as_raw_fd()) {
        Ok(dst) => dst,
        Err(e) => {
            eprintln!(
                "{}: peer={peer} SO_ORIGINAL_DST failed: {e}; closing",
                conn.ingress
            );
            return;
        }
    };
    // A direct connection to the transparent listener has no REDIRECT/DNAT, so
    // SO_ORIGINAL_DST reports the listener itself. Reject it rather than
    // handing a MITM leaf for an arbitrary name to anyone who can dial the
    // listener.
    if local == Some(orig) {
        eprintln!(
            "{}: peer={peer} not redirected (original_dst == local {orig}); closing",
            conn.ingress
        );
        return;
    }
    eprintln!("{}: peer={peer} original_dst={orig}", conn.ingress);
    serve_mitm(stream, orig, conn).await;
}

pub async fn serve_mitm<S>(stream: S, orig: SocketAddr, conn: Transparent)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Transparent { shared, ingress } = conn;
    let rt = crate::runtime::snapshot(&shared).await;
    let Some(mitm) = rt.mitm.clone() else {
        eprintln!("{ingress}: no MITM CA; closing");
        return;
    };
    let acceptor = mitm.acceptor(Some(orig.ip()));
    let tls = match tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(e)) => {
            eprintln!("{ingress}: TLS handshake failed: {e}");
            return;
        }
        Err(_) => {
            eprintln!("{ingress}: TLS handshake timeout");
            return;
        }
    };

    if tls.get_ref().1.alpn_protocol() != Some(&b"http/1.1"[..]) {
        eprintln!("{ingress}: ALPN is not http/1.1; closing");
        return;
    }
    let target = match Target::from_handshake(orig, tls.get_ref().1.server_name()) {
        Ok(target) => target,
        Err(e) => {
            eprintln!("{ingress}: {e}; closing");
            return;
        }
    };
    eprintln!("{ingress}: target={} alpn=http/1.1", target.host());

    let io = TokioIo::new(tls);
    let svc = service_fn(move |req| {
        let shared = shared.clone();
        let target = target.clone();
        async move {
            let rt = crate::runtime::snapshot(&shared).await;
            handle_transparent_request(req, rt, target, orig, ingress).await
        }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, svc)
        .await
    {
        eprintln!("{ingress}: inner HTTP connection error: {e}");
    }
}

async fn handle_transparent_request(
    req: Request<Incoming>,
    rt: Arc<Runtime>,
    target: Target,
    orig: SocketAddr,
    ingress: &'static str,
) -> Result<Response<ResBody>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    match transparent_dispatch(req, &rt, &target, orig, method, path, ingress).await {
        Ok(resp) => Ok(resp),
        Err(ProxyError::Reject(code, msg)) => Ok(text_response(code, msg)),
        Err(ProxyError::Internal(e)) => {
            eprintln!("{ingress}: internal error: {e:#}");
            Ok(text_response(StatusCode::BAD_GATEWAY, "upstream error"))
        }
    }
}

async fn transparent_dispatch(
    req: Request<Incoming>,
    rt: &Runtime,
    target: &Target,
    orig: SocketAddr,
    method: Method,
    path: String,
    ingress: &'static str,
) -> Result<Response<ResBody>, ProxyError> {
    // The inner Host must agree with the handshake target. HTTP/1.0 may omit
    // it. Exactly one Host is accepted; duplicates are a smuggling shape.
    let host_values: Vec<_> = req.headers().get_all(HOST).iter().collect();
    let host_ok = match host_values.as_slice() {
        [value] => {
            let s = value
                .to_str()
                .map_err(|_| ProxyError::Reject(StatusCode::FORBIDDEN, "non-ascii Host header"))?;
            host_header_matches(s, target, orig.port())
        }
        [] => req.version() == hyper::Version::HTTP_10,
        _ => false,
    };
    if !host_ok {
        eprintln!("{ingress}: reject inner Host != target ({})", target.host());
        return Err(ProxyError::Reject(
            StatusCode::FORBIDDEN,
            "inner Host does not match the target",
        ));
    }

    // Only registered fakecreds bound to this target are substituted.
    // Everything else is forwarded unchanged.
    let mut candidates: Vec<Arc<Entry>> = Vec::new();
    for (name, value) in req.headers() {
        if contains_anchor(name.as_str()) {
            eprintln!("{ingress}: reject discovery anchor in header name {name}");
            return Err(ProxyError::Reject(
                StatusCode::FORBIDDEN,
                "fakecred in header name",
            ));
        }
        let bytes = value.as_bytes();
        let raw_anchor = DISCOVERY_ANCHORS
            .iter()
            .any(|a| bytes_contain(bytes, a.as_bytes()));
        // Header values carrying an anchor must be ASCII so the token can be
        // compared exactly; anything else fails closed. A value without an
        // anchor is not a fakecred position and passes through.
        let s = match value.to_str() {
            Ok(s) => s,
            Err(_) if raw_anchor => {
                return Err(ProxyError::Reject(
                    StatusCode::FORBIDDEN,
                    "non-ascii fakecred header",
                ))
            }
            Err(_) => continue,
        };
        for view in discovery_views(name, s) {
            for (start, end) in token_runs(&view) {
                let token = &view[start..end];
                if !contains_anchor(token) {
                    continue;
                }
                let Some(entry) = rt.registry.get(token) else {
                    eprintln!("{ingress}: pass through unregistered fakecred in header {name}");
                    continue;
                };
                if !entry.hosts.iter().any(|p| p.matches(&target.host())) {
                    eprintln!(
                        "{ingress}: pass through fakecred of credential {} not bound to {}",
                        entry.name,
                        target.host()
                    );
                    continue;
                }
                if candidates.iter().any(|e| e.fake_cred == entry.fake_cred) {
                    continue;
                }
                eprintln!(
                    "{ingress}: fakecred_hit credential={} host={}",
                    entry.name,
                    target.host()
                );
                candidates.push(entry.clone());
            }
        }
    }

    let substitutions: Vec<Substitution> = candidates
        .into_iter()
        .map(|entry| Substitution {
            placeholder: entry.fake_cred.clone(),
            real: entry.real_cred.clone(),
            name: entry.name.clone(),
            user_id: entry.user_id.clone(),
            user_name: entry.user_name.clone(),
        })
        .collect();

    forward_transparent(
        req,
        rt,
        target,
        orig,
        method,
        &path,
        &substitutions,
        ingress,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn forward_transparent(
    req: Request<Incoming>,
    rt: &Runtime,
    target: &Target,
    orig: SocketAddr,
    method: Method,
    path: &str,
    rewrite: &[Substitution],
    ingress: &'static str,
) -> Result<Response<ResBody>, ProxyError> {
    let headers = rewrite_headers(&req, rewrite)?;
    reject_anchor_left(ingress, &headers, rewrite)?;

    let host_value = target.authority(orig.port());

    let pq = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let uri: hyper::Uri = pq.parse().map_err(|_| anyhow!("bad inner URI {pq}"))?;
    let names = audit_names(rewrite);
    let fake_creds = audit_fake_creds(rewrite);
    let user_ids = audit_users(rewrite, |s| &s.user_id);
    let user_names = audit_users(rewrite, |s| &s.user_name);
    let body = req.into_body().map_err(BoxError::from).boxed();
    let host_label = format!("{}:{}", target.host(), orig.port());
    let upstream = match send_origin(
        rt,
        orig,
        target,
        &method,
        &headers,
        &host_value,
        uri,
        body,
        ingress,
    )
    .await
    {
        Ok(resp) => resp,
        Err(e) => {
            audit::emit(&Audit {
                ingress,
                user_id: &user_ids,
                user_name: &user_names,
                name: &names,
                fake_cred: &fake_creds,
                host: &host_label,
                method: method.as_str(),
                path,
                status: StatusCode::BAD_GATEWAY.as_u16(),
                decision: "error",
            });
            return Err(e.into());
        }
    };

    let response = relay_response(upstream)?;
    let status = response.status();

    if !rewrite.is_empty() {
        eprintln!(
            "{ingress}: substituted credentials={names} host={}",
            target.host()
        );
    }
    audit::emit(&Audit {
        ingress,
        user_id: &user_ids,
        user_name: &user_names,
        name: &names,
        fake_cred: &fake_creds,
        host: &host_label,
        method: method.as_str(),
        path,
        status: status.as_u16(),
        decision: if rewrite.is_empty() {
            "passthrough"
        } else {
            "substitute"
        },
    });

    Ok(response)
}

/// One fakecred rewritten on the transparent path.
struct Substitution {
    placeholder: String,
    real: String,
    name: String,
    user_id: String,
    user_name: String,
}

/// Rewrites every header that carries a substituted fakecred; headers without
/// one are copied as they arrived. Hop-by-hop headers and the inbound `Host`
/// are dropped (rebuilt from the target).
fn rewrite_headers(
    req: &Request<Incoming>,
    rewrite: &[Substitution],
) -> Result<Vec<(HeaderName, HeaderValue)>, ProxyError> {
    let mut headers = Vec::new();
    for (name, value) in req.headers() {
        if is_hop_by_hop(name) || *name == HOST {
            continue;
        }
        let rewritten = match value.to_str() {
            Ok(s) => rewrite_value(name, s, rewrite)?,
            Err(_) => None,
        };
        headers.push((name.clone(), rewritten.unwrap_or_else(|| value.clone())));
    }
    Ok(headers)
}

/// Rewrites fakecred occurrences in one header value. A fakecred in the value
/// itself is replaced in place; one inside a `Basic` credential is replaced in
/// the decoded `user:password` pair and the result re-encoded, so the origin
/// receives `Basic base64(user:<real>)` and never the encoding of the
/// fakecred. Any other value is left as it arrived.
fn rewrite_value(
    name: &HeaderName,
    value: &str,
    rewrite: &[Substitution],
) -> Result<Option<HeaderValue>, ProxyError> {
    let hit = |text: &str| rewrite.iter().any(|sub| text.contains(&sub.placeholder));
    let replace = |text: &str| {
        let mut out = text.to_string();
        for sub in rewrite {
            out = out.replace(&sub.placeholder, &sub.real);
        }
        out
    };
    let invalid = || ProxyError::Reject(StatusCode::FORBIDDEN, "rewritten header is not valid");

    if hit(value) {
        return HeaderValue::from_str(&replace(value))
            .map(Some)
            .map_err(|_| invalid());
    }
    if *name == AUTHORIZATION {
        if let Some((user, password)) = basic_credentials(value) {
            if hit(&user) || hit(&password) {
                return basic_header(&replace(&user), &replace(&password))
                    .map(Some)
                    .ok_or_else(invalid);
            }
        }
    }
    Ok(None)
}

/// The views of one header value that fakecred discovery scans: the value as
/// sent, plus — for `Authorization` — the decoded user and password of a
/// `Basic` credential, because HTTP clients base64 the token there (RFC 7617).
fn discovery_views<'a>(name: &HeaderName, value: &'a str) -> Vec<Cow<'a, str>> {
    let mut views = vec![Cow::Borrowed(value)];
    if *name == AUTHORIZATION {
        if let Some((user, password)) = basic_credentials(value) {
            views.push(Cow::Owned(user));
            views.push(Cow::Owned(password));
        }
    }
    views
}

/// Decodes an `Authorization: Basic` value. The scheme matches
/// case-insensitively (RFC 9110); the remainder is base64 of UTF-8
/// `user:password`, split at the first colon. Anything else yields `None` and
/// the header is treated as ordinary material.
fn basic_credentials(value: &str) -> Option<(String, String)> {
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let encoded = encoded.trim();
    let engine = base64::engine::general_purpose::STANDARD;
    let raw = engine
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(encoded))
        .ok()?;
    let text = String::from_utf8(raw).ok()?;
    let (user, password) = text.split_once(':')?;
    Some((user.to_string(), password.to_string()))
}

/// The `Authorization: Basic` value for a decoded credential pair.
fn basic_header(user: &str, password: &str) -> Option<HeaderValue> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
    HeaderValue::from_str(&format!("Basic {encoded}")).ok()
}

/// Invariant: a fakecred the daemon substituted never leaves it. Tokens
/// deliberately left untouched (unregistered / unbound) are the agent's own
/// material and pass through as they arrived.
fn reject_anchor_left(
    ingress: &str,
    headers: &[(HeaderName, HeaderValue)],
    rewrite: &[Substitution],
) -> Result<(), ProxyError> {
    for (name, value) in headers {
        let leaked = contains_anchor(name.as_str())
            || rewrite
                .iter()
                .any(|sub| bytes_contain(value.as_bytes(), sub.placeholder.as_bytes()));
        if leaked {
            eprintln!("{ingress}: reject rewrite left a discovery anchor in {name}");
            return Err(ProxyError::Reject(
                StatusCode::FORBIDDEN,
                "fakecred remained after rewrite",
            ));
        }
    }
    Ok(())
}

fn audit_join(rewrite: &[Substitution], pick: impl Fn(&Substitution) -> &str) -> String {
    if rewrite.is_empty() {
        return "-".to_string();
    }
    let mut values: Vec<&str> = rewrite.iter().map(pick).collect();
    values.sort_unstable();
    values.dedup();
    values.join(",")
}

fn audit_names(rewrite: &[Substitution]) -> String {
    audit_join(rewrite, |s| &s.name)
}

fn audit_fake_creds(rewrite: &[Substitution]) -> String {
    audit_join(rewrite, |s| &s.placeholder)
}

fn audit_users(rewrite: &[Substitution], pick: impl Fn(&Substitution) -> &str) -> String {
    audit_join(rewrite, pick)
}

/// Copies an upstream response to the agent, dropping hop-by-hop headers. The
/// body keeps streaming; nothing is collected.
fn relay_response(upstream: Response<Incoming>) -> Result<Response<ResBody>, ProxyError> {
    let mut rb = Response::builder().status(upstream.status());
    for (name, value) in upstream.headers() {
        if is_hop_by_hop(name) {
            continue;
        }
        rb = rb.header(name, value);
    }
    let body = upstream.into_body().map_err(BoxError::from).boxed();
    rb.body(body)
        .map_err(|e| anyhow!("build response: {e}").into())
}

/// Connects to the original destination over verified TLS and sends the
/// rewritten request. Errors are surfaced to the caller, which audits them.
#[allow(clippy::too_many_arguments)]
async fn send_origin(
    rt: &Runtime,
    orig: SocketAddr,
    target: &Target,
    method: &Method,
    headers: &[(HeaderName, HeaderValue)],
    host_value: &str,
    uri: hyper::Uri,
    body: ResBody,
    ingress: &'static str,
) -> anyhow::Result<Response<Incoming>> {
    let mut builder = Request::builder().method(method.clone()).uri(uri);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder = builder.header(HOST, host_value);
    let outbound = builder
        .body(body)
        .map_err(|e| anyhow!("build outbound request: {e}"))?;

    let tcp = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(orig))
        .await
        .map_err(|_| anyhow!("origin connect timed out ({orig})"))?
        .map_err(|e| anyhow!("origin connect failed ({orig}): {e}"))?;
    let server_name = target.server_name()?;
    let tls = tokio_rustls::TlsConnector::from(rt.upstream_tls.clone())
        .connect(server_name, tcp)
        .await
        .map_err(|e| anyhow!("origin TLS failed ({}): {e}", target.host()))?;

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|e| anyhow!("origin h1 handshake failed: {e}"))?;
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            eprintln!("{ingress}: origin connection error: {e}");
        }
    });
    sender
        .send_request(outbound)
        .await
        .map_err(|e| anyhow!("origin request failed: {e}"))
}

fn host_header_matches(value: &str, target: &Target, orig_port: u16) -> bool {
    let value = value.trim();
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return false;
        };
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = if after.is_empty() {
            None
        } else {
            match after.strip_prefix(':').and_then(|p| p.parse::<u16>().ok()) {
                Some(p) => Some(p),
                None => return false,
            }
        };
        (host, port)
    } else {
        match value.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => match p.parse::<u16>() {
                Ok(port) => (h, Some(port)),
                Err(_) => return false,
            },
            _ => (value, None),
        }
    };
    if port.is_some_and(|p| p != orig_port) {
        return false;
    }
    match target {
        Target::Dns(name) => host.trim_end_matches('.').eq_ignore_ascii_case(name),
        Target::Ip(ip) => host
            .parse::<IpAddr>()
            .is_ok_and(|candidate| candidate == *ip),
    }
}

/// Token runs are the maximal runs of characters that can be part of a
/// credential. `=` is deliberately excluded so `token=<fakecred>` still yields
/// the bare fakecred; quotes and commas split.
fn token_runs(s: &str) -> Vec<(usize, usize)> {
    fn is_token_char(c: char) -> bool {
        c.is_ascii_alphanumeric()
            || matches!(c, '-' | '_' | '.' | ':' | '~' | '+' | '/' | '%' | '@')
    }
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in s.char_indices() {
        if is_token_char(c) {
            start.get_or_insert(i);
        } else if let Some(st) = start.take() {
            out.push((st, i));
        }
    }
    if let Some(st) = start {
        out.push((st, s.len()));
    }
    out
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "proxy-connection"
            | "keep-alive"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "proxy-authenticate"
            | "proxy-authorization"
    )
}

fn text_response(code: StatusCode, msg: &'static str) -> Response<ResBody> {
    let body = Full::new(Bytes::from_static(msg.as_bytes()))
        .map_err(|never: Infallible| match never {})
        .boxed();
    Response::builder()
        .status(code)
        .header("content-type", "text/plain; charset=utf-8")
        .body(body)
        .expect("static response")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extra(rewrite: &[Substitution]) -> String {
        audit_fake_creds(rewrite)
    }

    #[test]
    fn token_runs_split_on_delimiters() {
        let runs = token_runs("Bearer fcred-abc, x=\"fcred-def\"");
        let tokens: Vec<&str> = runs
            .iter()
            .map(|(s, e)| &"Bearer fcred-abc, x=\"fcred-def\""[*s..*e])
            .collect();
        assert!(tokens.contains(&"fcred-abc"));
        assert!(tokens.contains(&"fcred-def"));
        assert!(tokens.contains(&"Bearer"));
    }

    #[test]
    fn basic_credentials_decodes_user_and_password() {
        let token = "fcred-0123456789abcdef0123456789abcdef";
        let value = basic_header("git", token).unwrap();
        let (user, password) = basic_credentials(value.to_str().unwrap()).unwrap();
        assert_eq!(user, "git");
        assert_eq!(password, token);

        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:a:b");
        assert_eq!(
            basic_credentials(&format!("bAsIc {encoded}")),
            Some(("alice".to_string(), "a:b".to_string()))
        );
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode("git:x");
        assert_eq!(
            basic_credentials(&format!("Basic {encoded}")),
            Some(("git".to_string(), "x".to_string()))
        );

        for value in [
            "Bearer fcred-0123456789abcdef0123456789abcdef",
            "Basic",
            "Basic !!!!",
            "Basic //79",
            &format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode("nocolon")
            ),
        ] {
            assert_eq!(basic_credentials(value), None, "{value}");
        }
    }

    #[test]
    fn host_header_must_match_target_and_port() {
        let dns = Target::Dns("api.example.com".to_string());
        assert!(host_header_matches("api.example.com", &dns, 443));
        assert!(host_header_matches("API.example.com.", &dns, 443));
        assert!(host_header_matches("api.example.com:8443", &dns, 8443));
        assert!(!host_header_matches("api.example.com:8443", &dns, 443));
        assert!(!host_header_matches("other.example.com", &dns, 443));

        let v4 = Target::Ip("127.0.0.1".parse().unwrap());
        assert!(host_header_matches("127.0.0.1", &v4, 443));
        assert!(!host_header_matches("127.0.0.2", &v4, 443));

        let v6 = Target::Ip("::1".parse().unwrap());
        assert!(host_header_matches("[::1]:8443", &v6, 8443));
        assert!(!host_header_matches("[::1", &v6, 8443));
    }

    #[test]
    fn target_selection_and_authority() {
        let orig: SocketAddr = "10.0.0.5:443".parse().unwrap();
        assert_eq!(
            Target::from_handshake(orig, Some("API.example.com.")).unwrap(),
            Target::Dns("api.example.com".to_string())
        );
        assert_eq!(
            Target::from_handshake(orig, Some("10.0.0.5")).unwrap(),
            Target::Ip("10.0.0.5".parse().unwrap())
        );
        assert!(Target::from_handshake(orig, Some("10.0.0.6")).is_err());
        assert_eq!(
            Target::from_handshake(orig, None).unwrap(),
            Target::Ip("10.0.0.5".parse().unwrap())
        );

        let dns = Target::Dns("api.example.com".to_string());
        assert_eq!(dns.authority(443), "api.example.com");
        assert_eq!(dns.authority(8443), "api.example.com:8443");
        let v6 = Target::Ip("::1".parse().unwrap());
        assert_eq!(v6.authority(8443), "[::1]:8443");
        assert_eq!(v6.authority(443), "[::1]");
    }

    #[test]
    fn audit_joins_sorted_unique_values() {
        let rewrite = vec![
            Substitution {
                placeholder: "fcred-b".into(),
                real: "r1".into(),
                name: "b".into(),
                user_id: "u2".into(),
                user_name: "bob".into(),
            },
            Substitution {
                placeholder: "fcred-a".into(),
                real: "r2".into(),
                name: "a".into(),
                user_id: "u2".into(),
                user_name: "alice".into(),
            },
        ];
        assert_eq!(extra(&rewrite), "fcred-a,fcred-b");
        assert_eq!(audit_names(&rewrite), "a,b");
        assert_eq!(audit_users(&rewrite, |s| &s.user_id), "u2");
        assert_eq!(audit_users(&rewrite, |s| &s.user_name), "alice,bob");
    }
}
