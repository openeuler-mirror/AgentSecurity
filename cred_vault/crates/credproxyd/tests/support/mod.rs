//! Shared scaffolding for the credproxyd integration tests.
//!
//! Cargo builds every file directly under `tests/` as its own binary and
//! compiles this module into each of them; a helper a given binary does not
//! use is merely unused there, which is what the `dead_code` allowance covers.

#![allow(dead_code)]

#[cfg(not(feature = "test-hooks"))]
compile_error!(
    "these integration tests spawn the daemon with `--lock-file`, which only exists in a \
     `test-hooks` build; run them with `--features test-hooks`"
);

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use credstore::backend::FileBackend;
use credstore::server::{self, ServerConfig};
use credstore::store::Store;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Frame, Incoming};
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use serde_json::{json, Value};
use tokio::process::{Child, Command};

use credproxyd::trust::CaPem;

// ------------------------------------------------------------------- scratch

/// A test scratch directory. `CREDPROXY_TEST_KEEP=1` keeps it on disk after
/// the test (vault files, sockets, logs) instead of deleting it on drop.
pub fn scratch(prefix: &str) -> tempfile::TempDir {
    let keep = std::env::var_os("CREDPROXY_TEST_KEEP").is_some();
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix).disable_cleanup(keep);
    let dir = builder.tempdir().unwrap();
    if keep {
        eprintln!("kept test dir: {}", dir.path().display());
    }
    dir
}

pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Test-only override of the global instance lock. One path per test
/// binary: the daemons a single test spawns share it, so the "second daemon is
/// rejected" case is still exercised.
pub fn test_lock_path() -> PathBuf {
    std::env::temp_dir().join(format!("credproxyd-test-{}.lock", std::process::id()))
}

// --------------------------------------------------------------- the vault

/// A real `credstore` server over a scratch vault. Dropping the harness aborts
/// the server task; the scratch directory removes the files.
pub struct StoreHarness {
    _dir: tempfile::TempDir,
    pub sock: PathBuf,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Drop for StoreHarness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub async fn start_store(prefix: &str) -> StoreHarness {
    let dir = scratch(prefix);
    let root = dir.path().join("vault");
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = dir.path().join("store.sock");
    let store = Arc::new(Store::new(FileBackend::open(&root).unwrap()));
    let task = tokio::spawn(server::run(
        store,
        ServerConfig {
            socket: sock.clone(),
            allow_uid: None,
            max_connections: 16,
        },
    ));
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    StoreHarness {
        _dir: dir,
        sock,
        task,
    }
}

// ------------------------------------------------------------ mock upstream

/// One request the mock origin received, as the daemon forwarded it.
#[derive(Clone)]
pub struct Captured {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: BTreeMap<String, String>,
    pub body: String,
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

/// Test origin certificate for `localhost`, signed by the test CA.
pub fn upstream_acceptor(ca: &CaPem) -> tokio_rustls::TlsAcceptor {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ca_params = CertificateParams::from_ca_cert_pem(&ca.cert).expect("CA params");
    let ca_key = KeyPair::from_pem(&ca.key).expect("CA key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("CA issuer");
    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
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
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

/// A real TLS origin on loopback, trusted through the daemon's `upstream_ca`.
pub struct Upstream {
    pub port: u16,
    pub seen: Arc<Mutex<Vec<Captured>>>,
    _task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    pub async fn start(ca: &CaPem) -> Upstream {
        let acceptor = upstream_acceptor(ca);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
                            let method = req.method().to_string();
                            let path = req.uri().path().to_string();
                            let query = req.uri().query().map(|q| q.to_string());
                            let mut headers = BTreeMap::new();
                            for (name, value) in req.headers() {
                                headers.insert(
                                    name.as_str().to_string(),
                                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                                );
                            }
                            let wants_sse = req
                                .headers()
                                .get("accept")
                                .and_then(|v| v.to_str().ok())
                                .map(|v| v.contains("text/event-stream"))
                                .unwrap_or(false);
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
                                .unwrap_or_default();
                            captured.lock().unwrap().push(Captured {
                                method,
                                path,
                                query,
                                headers,
                                body,
                            });
                            let (content_type, body): (&str, BoxBody<Bytes, Infallible>) =
                                if wants_sse {
                                    ("text/event-stream", SseChunks { sent: 0 }.boxed())
                                } else {
                                    let payload = json!({ "ok": true }).to_string();
                                    ("application/json", Full::new(Bytes::from(payload)).boxed())
                                };
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header("content-type", content_type)
                                    .header("x-upstream", "mock")
                                    .body(body)
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
}

/// Two-frame streaming body, so the daemon is tested against a chunked
/// upstream response rather than a buffered one.
struct SseChunks {
    sent: usize,
}

impl hyper::body::Body for SseChunks {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        let me = self.get_mut();
        if me.sent >= 2 {
            return Poll::Ready(None);
        }
        me.sent += 1;
        let chunk = format!("data: chunk-{}\n\n", me.sent);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(chunk)))))
    }

    fn is_end_stream(&self) -> bool {
        self.sent >= 2
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::default()
    }
}

// ----------------------------------------------------------- the daemon binary

pub fn daemon_bin() -> &'static str {
    env!("CARGO_BIN_EXE_credproxyd")
}

/// Spawns the daemon with `args`. No environment variable decides anything:
/// the programs read no env, so an inherited value cannot change
/// what the test runs. The `test-hooks` feature is enforced at compile time.
///
/// The global instance lock is redirected to [`test_lock_path`] unless
/// the caller already passed `--lock-file`: without the hook the daemon needs
/// `/run/credproxy/credproxyd.lock`, which a non-root test cannot create.
pub fn spawn_daemon<S: AsRef<std::ffi::OsStr>>(args: &[S]) -> Child {
    let has_lock = args.iter().any(|a| a.as_ref() == "--lock-file");
    let mut cmd = daemon_command();
    cmd.args(args);
    if !has_lock {
        cmd.arg("--lock-file").arg(test_lock_path());
    }
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    cmd.spawn().expect("spawn credproxyd")
}

/// The bootstrap flags most tests need. The daemon's own configuration file is
/// redirected to a scratch path (`--state-file`, a `test-hooks` flag) so tests
/// never touch `/var/lib/credsvault`, and an explicit bootstrap config file
/// keeps the host's `/etc/credsvault/credproxyd.json` out of the run. No
/// `listen_transparent` is written, so the daemon uses the built-in default.
pub fn spawn_daemon_with(store: &Path, mgmt: &Path, state: &Path, wait_ms: u64) -> Child {
    spawn_daemon_with_listen(store, mgmt, state, wait_ms, None)
}

/// Like [`spawn_daemon_with`], but with the transparent listener placed on a
/// chosen address (tests use a free port so they never contend for 4100).
pub fn spawn_daemon_with_listen(
    store: &Path,
    mgmt: &Path,
    state: &Path,
    wait_ms: u64,
    listen: Option<&str>,
) -> Child {
    let config = state.with_extension("bootstrap.json");
    if let Some(parent) = config.parent() {
        std::fs::create_dir_all(parent).expect("create bootstrap config directory");
    }
    let mut body = serde_json::Map::new();
    if let Some(listen) = listen {
        body.insert(
            "listen_transparent".to_string(),
            serde_json::Value::String(listen.to_string()),
        );
    }
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::Value::Object(body)).unwrap(),
    )
    .expect("write test bootstrap config");
    spawn_daemon(&bootstrap_args(store, mgmt, state, &config, wait_ms))
}

/// Like [`spawn_daemon_with`], but through a bootstrap config file so an extra
/// origin trust root can be supplied (the proxy tests point the daemon at their
/// mock upstream's CA), with stderr captured to a file the test can read while
/// the daemon runs.
pub fn spawn_daemon_logging(
    store: &Path,
    mgmt: &Path,
    state: &Path,
    wait_ms: u64,
    config_path: &Path,
    upstream_ca: Option<&Path>,
    stderr_path: &Path,
) -> Child {
    let body = serde_json::to_vec(&json!({
        "store_socket": store,
        "mgmt_socket": mgmt,
        "store_wait_ms": wait_ms,
        "upstream_ca": upstream_ca,
    }))
    .unwrap();
    std::fs::write(config_path, body).unwrap();
    let mut cmd = daemon_command();
    cmd.args([
        "--config",
        config_path.to_str().expect("config path is UTF-8"),
        "--state-file",
        state.to_str().expect("state path is UTF-8"),
        "--lock-file",
        test_lock_path().to_str().expect("lock path is UTF-8"),
    ])
    .stdout(std::process::Stdio::null())
    .stderr(std::fs::File::create(stderr_path).unwrap())
    .kill_on_drop(true);
    cmd.spawn().expect("spawn credproxyd")
}

fn daemon_command() -> Command {
    let mut cmd = Command::new(daemon_bin());
    cmd.arg("run");
    cmd
}

fn bootstrap_args(
    store: &Path,
    mgmt: &Path,
    state: &Path,
    config: &Path,
    wait_ms: u64,
) -> Vec<String> {
    vec![
        "--config".to_string(),
        config.display().to_string(),
        "--store-socket".to_string(),
        store.display().to_string(),
        "--mgmt-socket".to_string(),
        mgmt.display().to_string(),
        "--state-file".to_string(),
        state.display().to_string(),
        "--store-wait-ms".to_string(),
        wait_ms.to_string(),
        "--lock-file".to_string(),
        test_lock_path().display().to_string(),
    ]
}

pub async fn wait_for_path(path: &Path, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

pub async fn wait_output(child: Child, within: Duration) -> std::process::Output {
    tokio::time::timeout(within, child.wait_with_output())
        .await
        .expect("daemon exits in time")
        .expect("wait")
}

pub fn sigterm(child: &Child) {
    let pid = child.id().expect("child pid") as i32;
    unsafe {
        libc::kill(pid, libc::SIGTERM);
    }
}

// ------------------------------------------------------- management plane
// AF_UNIX socket carrying HTTP/1.1 with JSON bodies.

/// One management-plane request over the socket, blocking. Extra headers are
/// for the optional `Authorization: Bearer` case.
pub fn mgmt_http(
    sock: &Path,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    use std::os::unix::net::UnixStream;
    let mut stream = UnixStream::connect(sock).expect("connect management socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    HttpResponse {
        status,
        headers,
        body: body.to_string(),
    }
}

/// A management-plane JSON request. `target` carries the query, `body` the
/// JSON object (serialized as `{}` when `None`).
pub fn mgmt_call(sock: &Path, method: &str, target: &str, body: Option<Value>) -> HttpResponse {
    let body = body
        .map(|v| v.to_string())
        .unwrap_or_else(|| "{}".to_string());
    mgmt_http(
        sock,
        method,
        target,
        &[("Content-Type", "application/json")],
        &body,
    )
}

/// A management-plane request that must succeed, returning the decoded JSON
/// (`Value::Null` for an empty 204 body).
pub fn mgmt_ok(sock: &Path, method: &str, target: &str, body: Option<Value>) -> Value {
    let resp = mgmt_call(sock, method, target, body);
    assert!(
        (200..300).contains(&resp.status),
        "{method} {target} failed with {}: {}",
        resp.status,
        resp.body
    );
    if resp.body.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&resp.body)
            .unwrap_or_else(|e| panic!("bad JSON reply: {e}: {}", resp.body))
    }
}

// -------------------------------------------------------- minimal HTTP client
// HTTP/1.1 with `Connection: close`, read to EOF. Enough to drive the LLM
// ingress and to read what the mock upstream received.

pub struct HttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: String,
}

pub fn http(
    port: u16,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect ingress");
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut req = format!(
        "{method} {target} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        req.push_str(&format!("{name}: {value}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);
    stream.write_all(req.as_bytes()).unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    let text = String::from_utf8_lossy(&raw).into_owned();
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_string());
        }
    }
    HttpResponse {
        status,
        headers,
        body: body.to_string(),
    }
}

// ---------------------------------------------------------------- test policy

/// Project test policy: integration tests run against the normal (release)
/// build; the dev profile is for unit tests only.
#[test]
fn integration_tests_run_on_the_normal_build() {
    if cfg!(debug_assertions) {
        panic!(
            "integration tests must run with --release (normal build); \
             run unit tests with `cargo test --lib` instead"
        );
    }
}
