//! Transparent-capture L7 behaviour driven directly through `serve_mitm` over a
//! Unix socket pair: the origin address is supplied by the test instead of
//! `SO_ORIGINAL_DST`, so no root, listener or ingress is needed. This is the
//! shared body used by the netfilter ingress.
//!
//! The assertion that matters: a fakecred is substituted only when it is
//! registered and bound to the target host; everything else is forwarded
//! unchanged.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use credstore::backend::FileBackend;
use credstore::server::{self, ServerConfig};
use credstore::store::Store;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixStream};
use tokio_rustls::TlsAcceptor;

use crate::config::{CaMaterial, DaemonConfig};
use crate::control::{self, Ctx};
use crate::proxy::Transparent;
use crate::runtime::{self, Runtime, Shared};
use crate::store_client::StoreClient;
use crate::trust::{self, CaPem};

fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

/// Drives one control-plane operation in-process. The HTTP adapter is
/// exercised separately; this harness only needs the business operations and
/// the runtime swap.
async fn ctl(h: &Harness, op: &str, args: Value) -> Value {
    control::execute(&h.ctx, op, args)
        .await
        .unwrap_or_else(|e| panic!("control op {op} failed: {} ({})", e.message, e.code))
}

struct FixedCert(Arc<CertifiedKey>);

impl std::fmt::Debug for FixedCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FixedCert")
    }
}

impl ResolvesServerCert for FixedCert {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

/// Test origin certificate for the supplied SANs, signed by the test CA.
fn upstream_acceptor_for(ca: &CaPem, names: Vec<String>) -> TlsAcceptor {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_params = CertificateParams::from_ca_cert_pem(&ca.cert).expect("CA params");
    let ca_key = KeyPair::from_pem(&ca.key).expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA issuer");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(names).expect("leaf params");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "test upstream");
    let leaf = params
        .signed_by(&leaf_key, &ca_cert, &ca_key)
        .expect("leaf signed by test CA");
    let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let signing_key =
        rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(key_der))
            .expect("signing key");
    let certified = Arc::new(CertifiedKey::new(vec![leaf.der().clone()], signing_key));
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(FixedCert(certified)));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsAcceptor::from(Arc::new(cfg))
}

struct Upstream {
    port: u16,
    seen: Arc<Mutex<Vec<BTreeMap<String, String>>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    async fn start(ca: &CaPem) -> Upstream {
        Upstream::start_named(ca, vec!["localhost".to_string()]).await
    }

    async fn start_named(ca: &CaPem, names: Vec<String>) -> Upstream {
        let acceptor = upstream_acceptor_for(ca, names);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let captured = seen.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let captured = captured.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
                        let captured = captured.clone();
                        async move {
                            let mut headers = BTreeMap::new();
                            for (name, value) in req.headers() {
                                headers.insert(
                                    name.as_str().to_string(),
                                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                );
                            }
                            captured.lock().unwrap().push(headers);
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", "application/json")
                                    .body(Full::new(Bytes::from_static(b"{\"ok\":true}")))
                                    .unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), svc)
                        .await;
                });
            }
        });
        Upstream {
            port,
            seen,
            _task: task,
        }
    }

    fn last(&self) -> BTreeMap<String, String> {
        self.seen
            .lock()
            .unwrap()
            .last()
            .cloned()
            .unwrap_or_default()
    }

    fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

fn client_config(ca_pem: &str) -> Arc<rustls::ClientConfig> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(cfg)
}

/// Creates a test scratch directory. `CREDPROXY_TEST_KEEP=1` keeps it on disk
/// after the test (vault files, sockets, logs) instead of deleting it on drop.
/// One process-wide CA: `TEST_UPSTREAM_CA` is a `OnceLock`, so every test in
/// this binary must sign its upstream with the first CA that was installed.
fn test_ca() -> &'static CaPem {
    static CA: std::sync::OnceLock<CaPem> = std::sync::OnceLock::new();
    CA.get_or_init(|| {
        let ca = trust::generate_ca().expect("CA");
        let _ = crate::runtime::TEST_UPSTREAM_CA.set(ca.cert.clone().into_bytes());
        ca
    })
}

fn scratch(prefix: &str) -> tempfile::TempDir {
    let keep = std::env::var_os("CREDPROXY_TEST_KEEP").is_some();
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix).disable_cleanup(keep);
    let dir = builder.tempdir().unwrap();
    if keep {
        eprintln!("kept test dir: {}", dir.path().display());
    }
    dir
}

struct Harness {
    _dir: tempfile::TempDir,
    ctx: Arc<Ctx>,
    shared: Shared,
    ca_pem: String,
    _store: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Harness {
    async fn start(ca: &CaPem) -> Harness {
        let dir = scratch("transparent");
        let root = dir.path().join("vault");
        std::fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store_sock = dir.path().join("store.sock");
        let store = Arc::new(Store::new(FileBackend::open(&root).unwrap()));
        let store_task = tokio::spawn(server::run(
            store,
            ServerConfig {
                socket: store_sock.clone(),
                allow_uid: None,
                max_connections: 16,
            },
        ));
        for _ in 0..200 {
            if store_sock.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let listen = format!("127.0.0.1:{}", free_port());
        let config = DaemonConfig {
            ca: Some(CaMaterial {
                cert: ca.cert.clone(),
                key: ca.key.clone(),
            }),
            ..Default::default()
        };
        let state_path = dir.path().join("daemon.json");
        crate::config::daemon_config_save(&state_path, &config).unwrap();

        // Same runtime construction the daemon performs at startup, minus the
        // listeners: the test supplies the stream and its destination directly.
        let store_client = Arc::new(StoreClient::connect(&store_sock).await.unwrap());
        let model = control::load_model(&store_client, &state_path)
            .await
            .expect("model");
        let rt = Runtime::build(
            model.config.clone(),
            model.credentials.clone(),
            store_client.clone(),
            None,
        )
        .expect("runtime");
        let shared = runtime::shared(rt);

        let ctx = Ctx::new(
            shared.clone(),
            store_client.clone(),
            state_path,
            listen,
            None,
        );

        Harness {
            _dir: dir,
            ctx,
            shared,
            ca_pem: ca.cert.clone(),
            _store: store_task,
        }
    }
}

/// One TLS session into `serve_mitm`; `dst` is the origin the test declares.
async fn open(
    h: &Harness,
    cfg: Arc<rustls::ClientConfig>,
    dst: SocketAddr,
    sni: &str,
) -> tokio_rustls::client::TlsStream<UnixStream> {
    let (client, server) = UnixStream::pair().expect("socketpair");
    let shared = h.shared.clone();
    tokio::spawn(async move {
        crate::proxy::serve_mitm(
            server,
            dst,
            Transparent {
                shared,
                ingress: "test",
            },
        )
        .await;
    });

    let connector = tokio_rustls::TlsConnector::from(cfg);
    let name = ServerName::try_from(sni.to_string()).unwrap();
    tokio::time::timeout(Duration::from_secs(10), connector.connect(name, client))
        .await
        .expect("TLS handshake in time")
        .expect("TLS handshake")
}

/// Sends one HTTP/1.1 request, advertising `sni` in the TLS handshake and
/// `host_header` in the inner request.
async fn l7_request(
    h: &Harness,
    cfg: Arc<rustls::ClientConfig>,
    dst: SocketAddr,
    sni: &str,
    host_header: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut tls = open(h, cfg, dst, sni).await;

    let mut req =
        format!("GET /secret-path HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n");
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    tls.write_all(req.as_bytes()).await.unwrap();
    let mut raw = Vec::new();
    tls.read_to_end(&mut raw).await.unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    (status, body.to_string())
}

type KaSender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

/// Opens one keep-alive session and returns a client sender, so a test can send
/// several requests over the same TLS session.
async fn keepalive(
    h: &Harness,
    cfg: Arc<rustls::ClientConfig>,
    dst: SocketAddr,
    sni: &str,
) -> KaSender {
    let tls = open(h, cfg, dst, sni).await;
    let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .expect("inner HTTP handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    sender
}

async fn keepalive_request(sender: &mut KaSender, host: &str, token: &str) -> (u16, String) {
    let req = Request::builder()
        .method("GET")
        .uri("/secret-path")
        .header("host", host)
        .header("authorization", format!("Bearer {token}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = tokio::time::timeout(Duration::from_secs(10), sender.send_request(req))
        .await
        .expect("response in time")
        .expect("request");
    let status = resp.status().as_u16();
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&body).into_owned())
}

fn add_credential(name: &str, host: &str, real: &str, user: &str) -> Value {
    json!({
        "name": name,
        "type": "https",
        "user_id": "u-01",
        "user_name": user,
        "allowed_hosts": [host],
        "real_cred": real,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn transparent_capture_decision_38() {
    let ca = test_ca();
    let upstream = Upstream::start(ca).await;
    let h = Harness::start(ca).await;
    let cfg = client_config(&h.ca_pem);
    let dst = SocketAddr::from((Ipv4Addr::LOCALHOST, upstream.port));
    let host = format!("localhost:{}", upstream.port);

    // One credential bound to localhost and one bound to another host.
    let bound = ctl(
        &h,
        "credential.add",
        add_credential("web", "localhost", "real-secret-value", "alice"),
    )
    .await;
    let bound = &bound;
    let bound_token = bound["fake_cred"].as_str().unwrap().to_string();
    assert_eq!(bound["allowed_hosts"], json!(["localhost"]));
    assert!(bound.get("real_cred").is_none());

    let escaped = ctl(
        &h,
        "credential.add",
        add_credential("other", "other.example", "other-real", "bob"),
    )
    .await;
    let escaped = &escaped;
    let escaped_token = escaped["fake_cred"].as_str().unwrap().to_string();

    // 1. Registered and bound to this host: the header value is rewritten in
    //    place, keeping its surrounding syntax.
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", &format!("Bearer {bound_token}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    let seen = upstream.last();
    assert_eq!(
        seen.get("authorization").map(String::as_str),
        Some("Bearer real-secret-value")
    );
    assert_eq!(seen.get("host").map(String::as_str), Some(host.as_str()));

    // 2. Unregistered placeholder: passed through unchanged.
    let unknown = "fcred-ffffffffffffffffffffffffffffffff";
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", &format!("Bearer {unknown}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some(format!("Bearer {unknown}").as_str())
    );

    // 3. Registered but bound to a different host: passed through unchanged.
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", &format!("Bearer {escaped_token}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some(format!("Bearer {escaped_token}").as_str())
    );

    // 4. Several placeholders in one header are substituted together.
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("X-Pair", &format!("a={bound_token};b={bound_token}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("x-pair").map(String::as_str),
        Some("a=real-secret-value;b=real-secret-value")
    );

    // 5. Inner Host must match the handshake target.
    let before = upstream.count();
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &format!("other.example:{}", upstream.port),
        &[("Authorization", &format!("Bearer {bound_token}"))],
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(
        body.contains("inner Host does not match the target"),
        "{body}"
    );
    assert_eq!(upstream.count(), before, "nothing forwarded");

    // 6. Discovery anchors in a header name are rejected.
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("fcred-marker", "x")],
    )
    .await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains("fakecred in header name"), "{body}");

    // 7. A credential whose binding does not include this host is not
    //    substituted even when the token is valid.
    ctl(
        &h,
        "credential.update",
        json!({ "fake_cred": bound_token, "allowed_hosts": ["localhost.invalid"] }),
    )
    .await;
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", &format!("Bearer {bound_token}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some(format!("Bearer {bound_token}").as_str())
    );

    // 8. A bound credential whose origin is unreachable yields 502 and an
    //    error audit line; the daemon keeps serving.
    let dead_port = free_port();
    let dead = ctl(
        &h,
        "credential.add",
        add_credential("dead", "localhost", "dead-real", "carol"),
    )
    .await;
    let dead = &dead;
    let dead_token = dead["fake_cred"].as_str().unwrap().to_string();
    let dead_dst = SocketAddr::from((Ipv4Addr::LOCALHOST, dead_port));
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dead_dst,
        "localhost",
        &format!("localhost:{dead_port}"),
        &[("Authorization", &format!("Bearer {dead_token}"))],
    )
    .await;
    assert_eq!(status, 502, "{body}");

    // 9. Live apply reaches an existing keep-alive connection: the runtime is
    //    snapshotted per request, not per accepted connection.
    ctl(
        &h,
        "credential.update",
        json!({ "fake_cred": bound_token, "allowed_hosts": ["localhost"] }),
    )
    .await;
    let mut ka = keepalive(&h, cfg.clone(), dst, "localhost").await;
    let (status, body) = keepalive_request(&mut ka, &host, &bound_token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some("Bearer real-secret-value")
    );
    ctl(
        &h,
        "credential.update",
        json!({ "fake_cred": bound_token, "allowed_hosts": ["localhost.invalid"] }),
    )
    .await;
    let (status, body) = keepalive_request(&mut ka, &host, &bound_token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some(format!("Bearer {bound_token}").as_str())
    );

    // 10. A bound placeholder in the password position of a Basic credential
    //     (what git sends for Smart HTTP) is substituted after decoding and
    //     re-encoded; the origin never sees the placeholder.
    ctl(
        &h,
        "credential.update",
        json!({ "fake_cred": bound_token, "allowed_hosts": ["localhost"] }),
    )
    .await;
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", &basic("git", &bound_token))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some(basic("git", "real-secret-value").as_str())
    );

    // 11. An unregistered token in the Basic password position is forwarded
    //     unchanged, encoding included.
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", &basic("git", unknown))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some(basic("git", unknown).as_str())
    );

    // 12. A registered-but-unbound token in the Basic password position is
    //     forwarded unchanged.
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", &basic("git", &escaped_token))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some(basic("git", &escaped_token).as_str())
    );

    // 13. A Basic value that does not decode to UTF-8 user:password is
    //     forwarded unchanged rather than rejected.
    let (status, body) = l7_request(
        &h,
        cfg.clone(),
        dst,
        "localhost",
        &host,
        &[("Authorization", "Basic //79")],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some("Basic //79")
    );
}

/// An IP-literal target: rustls does not send SNI for an IP `ServerName`, so
/// the proxy must fall back to `SO_ORIGINAL_DST`, sign an IP SAN leaf, and
/// still bind the credential to the literal host.
#[tokio::test(flavor = "multi_thread")]
async fn ip_literal_target_uses_original_destination() {
    let ca = test_ca();
    let upstream = Upstream::start_named(ca, vec!["127.0.0.1".to_string()]).await;
    let h = Harness::start(ca).await;

    let created = ctl(
        &h,
        "credential.add",
        add_credential("ip-cred", "127.0.0.1", "sk-ip-secret", "u-ip"),
    )
    .await;
    let token = created["fake_cred"].as_str().unwrap();
    let dst = SocketAddr::from(([127, 0, 0, 1], upstream.port));
    let host = format!("127.0.0.1:{}", upstream.port);

    // No SNI is transmitted for an IP name; the target is the original
    // destination IP and the Host header must agree with it.
    let (status, body) = l7_request(
        &h,
        client_config(&h.ca_pem),
        dst,
        "127.0.0.1",
        &host,
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.last().get("authorization").map(String::as_str),
        Some("Bearer sk-ip-secret")
    );

    // DNS Host against an IP target is a mismatch, not a substitution.
    let (status, _) = l7_request(
        &h,
        client_config(&h.ca_pem),
        dst,
        "127.0.0.1",
        "localhost",
        &[("Authorization", &format!("Bearer {token}"))],
    )
    .await;
    assert_eq!(status, 403);
}

/// `Authorization: Basic` value for `user:password`.
fn basic(user: &str, password: &str) -> String {
    use base64::Engine as _;
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
    )
}
