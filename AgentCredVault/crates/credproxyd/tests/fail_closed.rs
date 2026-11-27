//! Store-outage semantics with the real value inline in the vault object:
//! the data plane keeps serving from the loaded runtime snapshot while the
//! store is unreachable (no per-request store lookup, no 502).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use credproxyd::config::CaMaterial;
use credproxyd::control::{self, Ctx};
use credproxyd::proxy::Transparent;
use credproxyd::runtime::{self, Runtime, Shared};
use credproxyd::store_client::StoreClient;
use credproxyd::trust;
use rustls::pki_types::ServerName;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

mod support;
use support::*;

/// Bidirectional relay in front of the store, so the test can sever the
/// daemon's store connection without stopping the store's accept loop.
struct Relay {
    socket: PathBuf,
    tasks: Arc<std::sync::Mutex<Vec<tokio::task::AbortHandle>>>,
    _dir: tempfile::TempDir,
}

impl Relay {
    async fn start(target: PathBuf) -> Relay {
        let dir = scratch("relay");
        let socket = dir.path().join("relay.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let tasks = Arc::new(std::sync::Mutex::new(Vec::new()));
        let handles = tasks.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut client, _)) = listener.accept().await else {
                    return;
                };
                let target = target.clone();
                let handle = tokio::spawn(async move {
                    let Ok(mut upstream) = UnixStream::connect(&target).await else {
                        return;
                    };
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
                handles.lock().unwrap().push(handle.abort_handle());
            }
        });
        Relay {
            socket,
            tasks,
            _dir: dir,
        }
    }

    fn sever(&self) {
        for task in self.tasks.lock().unwrap().drain(..) {
            task.abort();
        }
    }
}

struct Harness {
    _dir: tempfile::TempDir,
    _store: StoreHarness,
    relay: Relay,
    ctx: Arc<Ctx>,
    shared: Shared,
    ca: trust::CaPem,
}

impl Harness {
    async fn start() -> Harness {
        let store = start_store("credproxyd-fail-closed").await;
        let relay = Relay::start(store.sock.clone()).await;
        let dir = scratch("fail-closed");
        let state = dir.path().join("state.json");
        let ca = trust::generate_ca().expect("CA");
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, &ca.cert).unwrap();

        let listen = format!("127.0.0.1:{}", free_port());
        let config = credproxyd::config::DaemonConfig {
            ca: Some(CaMaterial {
                cert: ca.cert.clone(),
                key: ca.key.clone(),
            }),
            ..Default::default()
        };
        credproxyd::config::daemon_config_save(&state, &config).unwrap();

        let store_client = Arc::new(StoreClient::connect(&relay.socket).await.unwrap());
        let model = control::load_model(&store_client, &state)
            .await
            .expect("model");
        let rt = Runtime::build(
            model.config.clone(),
            model.credentials.clone(),
            store_client.clone(),
            Some(ca_path.clone()),
        )
        .expect("runtime");
        let shared = runtime::shared(rt);
        let ctx = Ctx::new(shared.clone(), store_client, state, listen, Some(ca_path));
        Harness {
            _dir: dir,
            _store: store,
            relay,
            ctx,
            shared,
            ca,
        }
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

async fn request(h: &Harness, dst: SocketAddr, host: &str, token: &str) -> (u16, String) {
    let (client, server) = UnixStream::pair().expect("socketpair");
    let shared = h.shared.clone();
    tokio::spawn(async move {
        credproxyd::proxy::serve_mitm(
            server,
            dst,
            Transparent {
                shared,
                ingress: "test",
            },
        )
        .await;
    });
    let connector = tokio_rustls::TlsConnector::from(client_config(&h.ca.cert));
    let name = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(10), connector.connect(name, client))
        .await
        .expect("TLS handshake in time")
        .expect("TLS handshake");
    let req = format!(
        "GET /secret HTTP/1.1\r\nHost: {host}\r\n\
         Authorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
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

#[tokio::test(flavor = "multi_thread")]
async fn data_plane_survives_store_outage() {
    let h = Harness::start().await;
    let upstream = Upstream::start(&h.ca).await;

    let created = control::execute(
        &h.ctx,
        "credential.add",
        json!({
            "name": "c1",
            "type": "https",
            "user_id": "u-01",
            "user_name": "alice",
            "real_cred": "sk-real-secret",
            "allowed_hosts": ["localhost"],
        }),
    )
    .await
    .expect("add");
    let token = created["fake_cred"].as_str().unwrap().to_string();
    let dst = SocketAddr::from(([127, 0, 0, 1], upstream.port));
    let host = format!("localhost:{}", upstream.port);

    let (status, body) = request(&h, dst, &host, &token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.seen.lock().unwrap().last().unwrap().headers["authorization"],
        "Bearer sk-real-secret"
    );

    // Losing the store connection does not affect the loaded real value: the
    // data plane reads the runtime snapshot only.
    h.relay.sever();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let (status, body) = request(&h, dst, &host, &token).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        upstream.seen.lock().unwrap().last().unwrap().headers["authorization"],
        "Bearer sk-real-secret"
    );
}

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
