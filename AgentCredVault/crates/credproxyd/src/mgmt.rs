//! Management plane: HTTP/1.1 + JSON over `/run/credsvault/mgmt.sock`.
//!
//! This is a thin adapter. It parses the request, checks that the peer is
//! root, maps method+path to one [`control::execute`] operation, and maps the
//! result to an HTTP status. No business logic is duplicated here: all
//! validation and persistence live in `control`.
//!
//! Authentication is root-only: socket mode `0600` plus `SO_PEERCRED`. The
//! listener is AF_UNIX only; there is no TCP or cross-machine mode.

use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::bootstrap::Settings;
use crate::control::{self, CtlError, Ctx};

const MAX_HEAD: usize = 32 * 1024;
const MAX_CONNECTIONS: usize = 16;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct MgmtConfig {
    pub socket: PathBuf,
    pub max_body: usize,
}

impl MgmtConfig {
    pub fn from_settings(settings: &Settings) -> Result<MgmtConfig> {
        Ok(MgmtConfig {
            socket: settings.mgmt_socket.clone(),
            max_body: settings.mgmt_max_body,
        })
    }
}

/// Binds and chmods the management socket. A stale socket from an unclean exit
/// is unlinked first; otherwise the daemon could not restart.
pub fn bind(cfg: &MgmtConfig) -> Result<UnixListener> {
    if let Some(parent) = cfg.socket.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create mgmt socket directory {}", parent.display()))?;
    }
    let _ = std::fs::remove_file(&cfg.socket);
    let listener = UnixListener::bind(&cfg.socket)
        .with_context(|| format!("bind mgmt socket {}", cfg.socket.display()))?;
    std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod mgmt socket {}", cfg.socket.display()))?;
    eprintln!("credproxyd: management plane {}", cfg.socket.display());
    Ok(listener)
}

pub async fn serve_listener(ctx: Arc<Ctx>, listener: UnixListener, cfg: Arc<MgmtConfig>) {
    let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = match limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return,
        };
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                eprintln!("mgmt: accept failed: {e}");
                continue;
            }
        };
        let ctx = ctx.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if timeout(CONNECTION_TIMEOUT, handle(ctx, stream, cfg))
                .await
                .is_err()
            {
                eprintln!("mgmt: connection timed out");
            }
        });
    }
}

#[derive(Debug)]
struct HttpError {
    status: u16,
    code: &'static str,
    message: String,
}

impl HttpError {
    fn new(status: u16, code: &'static str, message: impl Into<String>) -> HttpError {
        HttpError {
            status,
            code,
            message: message.into(),
        }
    }

    fn invalid(message: impl Into<String>) -> HttpError {
        HttpError::new(400, "invalid_argument", message)
    }

    fn not_found(message: impl Into<String>) -> HttpError {
        HttpError::new(404, "not_found", message)
    }
}

struct Head {
    method: String,
    target: String,
    headers: HashMap<String, String>,
    content_length: Option<usize>,
}

async fn handle(ctx: Arc<Ctx>, stream: UnixStream, cfg: Arc<MgmtConfig>) {
    let peer = match stream.peer_cred() {
        Ok(peer) => peer,
        Err(e) => {
            eprintln!("mgmt: SO_PEERCRED failed: {e}");
            return;
        }
    };
    let uid = peer.uid();
    // Production accepts root only. The `test-hooks` build (used exclusively by
    // the integration tests) also accepts the daemon's own euid, so the suite
    // can exercise the management plane without running as root.
    #[cfg(feature = "test-hooks")]
    let allowed = uid == 0 || uid == unsafe { libc::geteuid() };
    #[cfg(not(feature = "test-hooks"))]
    let allowed = uid == 0;
    let started = Instant::now();
    let (reader, mut writer) = stream.into_split();
    if !allowed {
        let body = json!({"error": "management plane is root-only", "code": "forbidden"});
        let _ = write_response(&mut writer, 403, Some(&body), &[]).await;
        eprintln!("mgmt: reject non-root uid {uid}");
        return;
    }

    let mut reader = BufReader::new(reader);
    let head = match read_head(&mut reader).await {
        Ok(head) => head,
        Err(e) => {
            let body = json!({"error": e.message, "code": e.code});
            let _ = write_response(&mut writer, e.status, Some(&body), &[]).await;
            eprintln!("mgmt: uid {uid} malformed request: {}", e.message);
            return;
        }
    };

    if head.headers.contains_key("transfer-encoding") {
        let body = json!({"error": "Transfer-Encoding is not supported; use Content-Length", "code": "invalid_argument"});
        let _ = write_response(&mut writer, 400, Some(&body), &[]).await;
        return;
    }
    if let Some(len) = head.content_length {
        if len > cfg.max_body {
            let body = json!({"error": "request body too large", "code": "too_large"});
            let _ = write_response(&mut writer, 413, Some(&body), &[]).await;
            eprintln!("mgmt: uid {uid} {} {} -> 413", head.method, head.target);
            return;
        }
    }

    let result = dispatch(&ctx, &head, &mut reader).await;
    let (status, response) = match result {
        Ok(outcome) => {
            let status = outcome.status;
            let body = if status == 204 {
                None
            } else {
                Some(outcome.result.unwrap_or_else(|| json!({})))
            };
            (status, body)
        }
        Err(e) => {
            let body = json!({"error": e.message, "code": e.code});
            (e.status, Some(body))
        }
    };
    let _ = write_response(&mut writer, status, response.as_ref(), &[]).await;
    eprintln!(
        "mgmt: uid={uid} {} {} -> {status} ({} ms)",
        head.method,
        head.target,
        started.elapsed().as_millis()
    );
}

struct Outcome {
    status: u16,
    result: Option<Value>,
}

struct Route {
    op: &'static str,
    args: Value,
    success: u16,
}

impl Route {
    fn new(op: &'static str, args: Value, success: u16) -> Route {
        Route { op, args, success }
    }
}

/// Query parameters, already split and percent-decoded. The set of accepted
/// keys is decided per route.
type Query = HashMap<String, String>;

async fn dispatch(
    ctx: &Ctx,
    head: &Head,
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
) -> Result<Outcome, HttpError> {
    let (path, raw_query) = match head.target.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (head.target.as_str(), None),
    };
    let segments = decode_path(path)?;
    let segments: Vec<&str> = segments.iter().map(String::as_str).collect();
    let query = parse_query(raw_query)?;

    // Route first so a GET never reads a body it will not use. Only the exact
    // method of each URL is accepted.
    let route = match (head.method.as_str(), segments.as_slice()) {
        ("GET", ["v1", "health"]) => {
            no_query(&query)?;
            Route::new("health", json!({}), 200)
        }
        ("GET", ["v1", "credentials", "list"]) => {
            no_query(&query)?;
            Route::new("credentials.list", json!({}), 200)
        }
        ("GET", ["v1", "credential", "get"]) => {
            only_query(&query, &["fake_cred"])?;
            Route::new("credential.get", fake_cred_arg(&query)?, 200)
        }
        ("POST", ["v1", "credential", "add"]) => {
            no_query(&query)?;
            Route::new("credential.add", json!({}), 201)
        }
        ("POST", ["v1", "credential", "update"]) => {
            only_query(&query, &["fake_cred"])?;
            Route::new("credential.update", fake_cred_arg(&query)?, 200)
        }
        ("POST", ["v1", "credential", "remove"]) => {
            only_query(&query, &["fake_cred"])?;
            Route::new("credential.remove", fake_cred_arg(&query)?, 204)
        }
        ("GET", ["v1", "validate"]) => {
            no_query(&query)?;
            Route::new("validate", json!({}), 200)
        }
        ("GET", ["v1", "dump"]) => {
            only_query(&query, &["secrets", "redacted"])?;
            Route::new(
                "dump",
                json!({
                    "secrets": query_bool(&query, "secrets")?,
                    "redacted": query_bool(&query, "redacted")?,
                }),
                200,
            )
        }
        ("POST", ["v1", "ca", "init"]) => {
            no_query(&query)?;
            Route::new("ca.init", json!({}), 200)
        }
        // A known path with the wrong method is still not a route.
        _ => return Err(HttpError::not_found("unknown management path")),
    };

    let body = read_body(reader, head).await?;
    let mut args = route.args;
    if !body.is_null() {
        let Some(obj) = body.as_object() else {
            return Err(HttpError::invalid("request body must be a JSON object"));
        };
        let Some(target) = args.as_object_mut() else {
            return Err(HttpError::invalid("internal argument shape"));
        };
        for (key, value) in obj {
            // Query-derived arguments (the object name) win over the body, so
            // a request cannot address a different object than its URL says.
            if !target.contains_key(key) {
                target.insert(key.clone(), value.clone());
            }
        }
    }

    let reply = control::execute(ctx, route.op, args).await;
    match reply {
        Ok(result) => Ok(Outcome {
            status: route.success,
            result: Some(result),
        }),
        Err(e) => Err(map_ctl_error(&e)),
    }
}

fn map_ctl_error(e: &CtlError) -> HttpError {
    let status = match e.code {
        "invalid_argument" | "unsupported" => 400,
        "unauthorized" => 401,
        "forbidden" => 403,
        "not_found" => 404,
        "already_exists" | "conflict" => 409,
        "too_large" => 413,
        "store" => 503,
        _ => 500,
    };
    HttpError::new(status, e.code, e.message.clone())
}

fn no_query(query: &Query) -> Result<(), HttpError> {
    if let Some(key) = query.keys().next() {
        return Err(HttpError::invalid(format!(
            "unknown query parameter {key:?} for this route"
        )));
    }
    Ok(())
}

fn only_query(query: &Query, allowed: &[&str]) -> Result<(), HttpError> {
    if let Some(key) = query.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(HttpError::invalid(format!(
            "unknown query parameter {key:?}"
        )));
    }
    Ok(())
}

fn fake_cred_arg(query: &Query) -> Result<Value, HttpError> {
    match query.get("fake_cred") {
        Some(fake_cred) if !fake_cred.is_empty() => Ok(json!({ "fake_cred": fake_cred })),
        Some(_) => Err(HttpError::invalid("query parameter \"fake_cred\" is empty")),
        None => Err(HttpError::invalid("missing query parameter \"fake_cred\"")),
    }
}

fn query_bool(query: &Query, key: &str) -> Result<bool, HttpError> {
    match query.get(key).map(String::as_str) {
        None | Some("false" | "0" | "") => Ok(false),
        Some("true" | "1") => Ok(true),
        Some(other) => Err(HttpError::invalid(format!(
            "{key} must be true or false, got {other:?}"
        ))),
    }
}

fn parse_query(raw: Option<&str>) -> Result<Query, HttpError> {
    let mut out = Query::new();
    let Some(raw) = raw else {
        return Ok(out);
    };
    if raw.is_empty() {
        return Ok(out);
    }
    for pair in raw.split('&') {
        if pair.is_empty() {
            return Err(HttpError::invalid("empty query parameter"));
        }
        let (key, value) = match pair.split_once('=') {
            Some((key, value)) => (key, value),
            None => (pair, ""),
        };
        let key = percent_decode(key)?;
        let value = percent_decode(value)?;
        if key.is_empty() {
            return Err(HttpError::invalid("empty query parameter name"));
        }
        if out.insert(key.clone(), value).is_some() {
            return Err(HttpError::invalid(format!(
                "duplicate query parameter {key:?}"
            )));
        }
    }
    Ok(out)
}

fn decode_path(path: &str) -> Result<Vec<String>, HttpError> {
    if !path.starts_with('/') {
        return Err(HttpError::invalid("request target must start with '/'"));
    }
    if path == "/" {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for segment in path[1..].split('/') {
        out.push(percent_decode(segment)?);
    }
    Ok(out)
}

fn percent_decode(segment: &str) -> Result<String, HttpError> {
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(HttpError::invalid("truncated percent escape"));
                }
                let hi = hex_digit(bytes[i + 1])
                    .ok_or_else(|| HttpError::invalid("bad percent escape"))?;
                let lo = hex_digit(bytes[i + 2])
                    .ok_or_else(|| HttpError::invalid("bad percent escape"))?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).map_err(|_| HttpError::invalid("path segment is not UTF-8"))
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

async fn read_head(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
) -> Result<Head, HttpError> {
    let mut total = 0usize;
    let request_line = read_line(reader, &mut total).await?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| HttpError::invalid("missing request method"))?;
    let target = parts
        .next()
        .ok_or_else(|| HttpError::invalid("missing request target"))?;
    let version = parts
        .next()
        .ok_or_else(|| HttpError::invalid("missing HTTP version"))?;
    if parts.next().is_some() || !version.starts_with("HTTP/1.") {
        return Err(HttpError::invalid("malformed request line"));
    }

    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let line = read_line(reader, &mut total).await?;
        if line.is_empty() {
            break;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| HttpError::invalid("malformed header"))?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_string();
        if name.is_empty() {
            return Err(HttpError::invalid("empty header name"));
        }
        if headers.insert(name.clone(), value).is_some() {
            return Err(HttpError::invalid(format!("duplicate header {name}")));
        }
    }

    let content_length = match headers.get("content-length") {
        Some(raw) => Some(
            raw.parse::<usize>()
                .map_err(|_| HttpError::invalid("bad Content-Length"))?,
        ),
        None => None,
    };
    Ok(Head {
        method: method.to_string(),
        target: target.to_string(),
        headers,
        content_length,
    })
}

async fn read_line(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    total: &mut usize,
) -> Result<String, HttpError> {
    let mut buf = Vec::new();
    let n = reader
        .read_until(b'\n', &mut buf)
        .await
        .map_err(|e| HttpError::invalid(format!("read request: {e}")))?;
    if n == 0 {
        return Err(HttpError::invalid("connection closed before headers"));
    }
    *total += n;
    if *total > MAX_HEAD {
        return Err(HttpError::new(
            431,
            "too_large",
            "request headers too large",
        ));
    }
    if buf.last() == Some(&b'\n') {
        buf.pop();
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf).map_err(|_| HttpError::invalid("headers are not UTF-8"))
}

async fn read_body(
    reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>,
    head: &Head,
) -> Result<Value, HttpError> {
    let Some(len) = head.content_length else {
        return Ok(Value::Null);
    };
    if len == 0 {
        return Ok(Value::Null);
    }
    let mut body = vec![0u8; len];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|e| HttpError::invalid(format!("read body: {e}")))?;
    serde_json::from_slice(&body)
        .map_err(|e| HttpError::invalid(format!("request body is not JSON: {e}")))
}

async fn write_response(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    status: u16,
    body: Option<&Value>,
    extra: &[(&str, &str)],
) -> std::io::Result<()> {
    let reason = status_reason(status);
    let payload = body.map(|v| serde_json::to_vec(v).expect("serializable JSON"));
    let mut head = format!("HTTP/1.1 {status} {reason}\r\nConnection: close\r\n");
    if payload.is_some() {
        head.push_str("Content-Type: application/json\r\n");
    }
    for (name, value) in extra {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str(&format!(
        "Content-Length: {}\r\n\r\n",
        payload.as_ref().map_or(0, Vec::len)
    ));
    writer.write_all(head.as_bytes()).await?;
    if let Some(payload) = payload {
        writer.write_all(&payload).await?;
    }
    writer.flush().await
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_reasons() {
        assert_eq!(status_reason(201), "Created");
        assert_eq!(status_reason(204), "No Content");
    }

    #[test]
    fn path_decoding_rejects_bad_escapes() {
        assert_eq!(
            decode_path("/v1/credentials/list").unwrap(),
            vec!["v1", "credentials", "list"]
        );
        assert_eq!(
            decode_path("/v1/credential/get").unwrap(),
            vec!["v1", "credential", "get"]
        );
        assert!(decode_path("/v1/%zz").is_err());
        assert!(decode_path("v1/health").is_err());
    }

    #[test]
    fn query_parsing_is_strict() {
        let q = parse_query(Some("fake_cred=a&redacted=true")).unwrap();
        assert_eq!(q["fake_cred"], "a");
        assert!(parse_query(Some("fake_cred=a&fake_cred=b")).is_err());
        assert!(parse_query(Some("fake_cred=a&&x=b")).is_err());
        assert!(parse_query(Some("=a")).is_err());
        assert_eq!(
            parse_query(Some("fake_cred=a%2Fb")).unwrap()["fake_cred"],
            "a/b"
        );
        assert!(only_query(&q, &["fake_cred"]).is_err());
        assert!(no_query(&q).is_err());
        assert!(no_query(&Query::new()).is_ok());
    }

    #[test]
    fn booleans_and_fakecred() {
        let q = parse_query(Some("secrets=true&redacted=0")).unwrap();
        assert!(query_bool(&q, "secrets").unwrap());
        assert!(!query_bool(&q, "redacted").unwrap());
        assert!(!query_bool(&q, "other").unwrap());
        let bad = parse_query(Some("secrets=maybe")).unwrap();
        assert!(query_bool(&bad, "secrets").is_err());

        assert!(fake_cred_arg(&Query::new()).is_err());
        assert!(fake_cred_arg(&parse_query(Some("fake_cred=")).unwrap()).is_err());
        assert_eq!(
            fake_cred_arg(&parse_query(Some("fake_cred=fcred-x")).unwrap()).unwrap(),
            json!({"fake_cred": "fcred-x"})
        );
    }

    #[test]
    fn error_mapping() {
        let e = map_ctl_error(&CtlError::new("forbidden", "no"));
        assert_eq!(e.status, 403);
        assert_eq!(e.code, "forbidden");
        assert_eq!(map_ctl_error(&CtlError::conflict("no")).status, 409);
        assert_eq!(map_ctl_error(&CtlError::invalid("no")).status, 400);
        assert_eq!(map_ctl_error(&CtlError::unsupported("no")).status, 400);
        assert_eq!(map_ctl_error(&CtlError::new("store", "down")).status, 503);
        assert_eq!(map_ctl_error(&CtlError::internal("x")).status, 500);
    }
}
