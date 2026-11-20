//! End-to-end management behaviour: the real `credclient` binary talks to the
//! real `credproxyd` binary over a real `credstore` server.
//!
//! All phases run in one test so the temporary listeners are never contended.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use credproxyd::store_client::StoreClient;
use credstore::backend::FileBackend;
use credstore::server::{self, ServerConfig};
use credstore::store::Store;
use serde_json::Value;
use tokio::process::{Child, Command};

fn client_bin() -> &'static str {
    env!("CARGO_BIN_EXE_credclient")
}

/// Creates a test scratch directory. `CREDPROXY_TEST_KEEP=1` keeps it on disk
/// after the test (vault files, sockets, logs) instead of deleting it on drop.
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

fn daemon_bin() -> PathBuf {
    std::env::current_exe()
        .expect("test binary path")
        .parent()
        .expect("deps dir")
        .parent()
        .expect("target dir")
        .join("credproxyd")
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().unwrap().port()
}

/// The daemon takes its global instance lock at its default `/run` path unless
/// it was built with `test-hooks`, and a non-root test cannot create that path.
/// Check the binary for the hook first so the failure names the build command
/// instead of looking like a daemon that died at startup.
fn daemon_hook_args(dir: &Path) -> Vec<std::ffi::OsString> {
    let help = std::process::Command::new(daemon_bin())
        .args(["run", "--help"])
        .output()
        .expect("credproxyd run --help");
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(
        text.contains("--lock-file") && text.contains("--state-file"),
        "the daemon was built without the `test-hooks` feature; build with \
         `--features credproxyd/test-hooks` before running this suite"
    );
    vec![
        "--lock-file".into(),
        dir.join("credproxyd.lock").into_os_string(),
    ]
}

struct Harness {
    _dir: tempfile::TempDir,
    store_sock: PathBuf,
    mgmt: PathBuf,
    state: PathBuf,
    listen: String,
    daemon: Option<Child>,
    _server: tokio::task::JoinHandle<anyhow::Result<()>>,
}

impl Harness {
    /// Starts a store and one daemon. `extra` is merged into the bootstrap
    /// config file.
    async fn start(prefix: &str, extra: Value) -> Harness {
        let dir = scratch(prefix);
        let root = dir.path().join("vault");
        std::fs::create_dir(&root).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let store_sock = dir.path().join("store.sock");
        let store = Arc::new(Store::new(FileBackend::open(&root).unwrap()));
        let server_task = tokio::spawn(server::run(
            store.clone(),
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
        let mgmt = dir.path().join("mgmt.sock");
        let state = dir.path().join("state").join("daemon.json");

        // The transparent listener is a bootstrap input: an ephemeral port
        // instead of the fixed 4100 used by other suites.
        let listen = format!("127.0.0.1:{}", free_port());
        let mut bootstrap = serde_json::json!({
            "store_socket": store_sock,
            "mgmt_socket": mgmt,
            "store_wait_ms": 2_000,
            "listen_transparent": listen.clone(),
        });
        for (key, value) in extra.as_object().expect("extra must be an object") {
            bootstrap[key] = value.clone();
        }
        let bootstrap_path = dir.path().join("bootstrap.json");
        std::fs::write(&bootstrap_path, serde_json::to_vec(&bootstrap).unwrap()).unwrap();

        let daemon = Command::new(daemon_bin())
            .arg("run")
            .arg("--config")
            .arg(&bootstrap_path)
            .arg("--state-file")
            .arg(&state)
            .args(daemon_hook_args(dir.path()))
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn credproxyd");

        for _ in 0..500 {
            if mgmt.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(mgmt.exists(), "management socket appears");

        Harness {
            _dir: dir,
            store_sock,
            mgmt,
            state,
            listen,
            daemon: Some(daemon),
            _server: server_task,
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.daemon.take();
    }
}

struct CliOutput {
    code: i32,
    stdout: String,
    stderr: String,
}

async fn cli(mgmt: &Path, args: &[&str], stdin: Option<&str>) -> CliOutput {
    cli_with(mgmt, &[], args, stdin).await
}

async fn cli_with(mgmt: &Path, global: &[&str], args: &[&str], stdin: Option<&str>) -> CliOutput {
    let mut cmd = Command::new(client_bin());
    cmd.arg("--mgmt-socket").arg(mgmt).args(global).args(args);
    cmd.stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    if stdin.is_some() {
        cmd.stdin(std::process::Stdio::piped());
    } else {
        cmd.stdin(std::process::Stdio::null());
    }
    let mut child = cmd.spawn().expect("spawn credclient");
    if let Some(text) = stdin {
        use tokio::io::AsyncWriteExt;
        let mut pipe = child.stdin.take().unwrap();
        pipe.write_all(text.as_bytes()).await.unwrap();
        drop(pipe);
    }
    let out = child.wait_with_output().await.expect("credclient output");
    CliOutput {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

fn json(out: &CliOutput) -> Value {
    serde_json::from_str(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "stdout is not JSON: {e}\nstdout: {}\nstderr: {}",
            out.stdout, out.stderr
        )
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn management_cli_end_to_end() {
    let h = Harness::start("credclient-e2e", serde_json::json!({})).await;

    // -- startup generates the CA; `ca init` needs --force to rotate ---------
    let out = cli(&h.mgmt, &["ca", "init"], None).await;
    assert_eq!(out.code, 1, "rotation requires --force");
    assert!(out.stderr.contains("already configured"), "{}", out.stderr);
    let forced = cli(&h.mgmt, &["ca", "init", "--force"], None).await;
    assert_eq!(forced.code, 0, "stderr: {}", forced.stderr);
    assert!(
        forced.stdout.starts_with("-----BEGIN CERTIFICATE-----"),
        "{}",
        forced.stdout
    );

    // -- credential add: the real comes from stdin ---------------------------
    let out = cli(
        &h.mgmt,
        &[
            "credential",
            "add",
            "--name",
            "c1",
            "--type",
            "https",
            "--user-id",
            "u-01",
            "--user-name",
            "alice",
            "--allow-host",
            "localhost",
        ],
        Some("sk-test-real\n"),
    )
    .await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let added = json(&out);
    assert_eq!(added["name"], "c1");
    assert_eq!(added["type"], "https");
    assert_eq!(added["user_id"], "u-01");
    assert_eq!(added["user_name"], "alice");
    assert_eq!(added["allowed_hosts"], serde_json::json!(["localhost"]));
    let key = added["fake_cred"].as_str().expect("fake_cred").to_string();
    assert_eq!(key.len(), 38);
    assert!(key.starts_with("fcred-"));
    assert!(
        !out.stdout.contains("sk-test-real"),
        "stdout must not carry the real"
    );

    // -- a value file is the alternative to stdin, and the two are exclusive -
    let value_file = h._dir.path().join("secret-b.txt");
    std::fs::write(&value_file, "secret-b\n").unwrap();
    let out = cli(
        &h.mgmt,
        &[
            "credential",
            "add",
            "--name",
            "c2",
            "--user-id",
            "u-02",
            "--user-name",
            "bob",
            "--allow-host",
            "example.com",
            "--value-file",
            value_file.to_str().unwrap(),
        ],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let c2_key = json(&out)["fake_cred"].as_str().unwrap().to_string();
    let out = cli(
        &h.mgmt,
        &[
            "credential",
            "add",
            "--name",
            "c3",
            "--user-id",
            "u-02",
            "--user-name",
            "bob",
            "--allow-host",
            "example.com",
            "--value-file",
            value_file.to_str().unwrap(),
            "--value-stdin",
        ],
        Some("x\n"),
    )
    .await;
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("mutually exclusive"), "{}", out.stderr);

    // -- client-side argument errors leave the vault untouched --------------
    let out = cli(
        &h.mgmt,
        &[
            "credential",
            "add",
            "--name",
            "both",
            "--user-id",
            "u-01",
            "--user-name",
            "alice",
        ],
        Some("x\n"),
    )
    .await;
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("--allow-host"), "{}", out.stderr);

    // -- daemon-side rejections surface with the daemon's code --------------
    let out = cli(
        &h.mgmt,
        &[
            "credential",
            "add",
            "--name",
            "c1",
            "--user-id",
            "u-01",
            "--user-name",
            "alice",
            "--allow-host",
            "localhost",
        ],
        Some("other-real\n"),
    )
    .await;
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("already exists"), "{}", out.stderr);

    // The same real may back a second credential, which gets its own fakecred.
    let out = cli(
        &h.mgmt,
        &[
            "credential",
            "add",
            "--name",
            "shared-real",
            "--user-id",
            "u-01",
            "--user-name",
            "alice",
            "--allow-host",
            "localhost",
        ],
        Some("sk-test-real\n"),
    )
    .await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let shared = json(&out);
    assert_eq!(shared["name"], "shared-real");
    assert_ne!(shared["fake_cred"].as_str().unwrap(), key.as_str());
    assert!(!out.stdout.contains("sk-test-real"));

    // -- live apply: an update is visible to the next command ---------------
    let out = cli(
        &h.mgmt,
        &[
            "credential",
            "update",
            "--fake-cred",
            &key,
            "--user-name",
            "bob",
        ],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert_eq!(json(&out)["user_name"], "bob");
    let out = cli(&h.mgmt, &["dump"], None).await;
    assert_eq!(json(&out)["credentials"][&key]["user_name"], "bob");

    let out = cli(
        &h.mgmt,
        &["credential", "update", "--fake-cred", &key],
        None,
    )
    .await;
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("at least one field"), "{}", out.stderr);

    // -- validate succeeds on a consistent vault -----------------------------
    let out = cli(&h.mgmt, &["validate"], None).await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert_eq!(json(&out)["violations"], serde_json::json!([]));

    // -- dump masks the CA key and the real by default -----------------------
    let out = cli(&h.mgmt, &["dump"], None).await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let dump = json(&out);
    assert_eq!(dump["config"]["ca"]["key"], "<redacted>");
    assert_eq!(dump["credentials"][&key]["fake_cred"], key);
    assert!(dump["credentials"][&key].get("real_cred").is_none());
    assert!(
        !out.stdout.contains("sk-test-real"),
        "default dump leaks the real"
    );

    // -- --secrets prints both; --redacted drops both ------------------------
    let out = cli(&h.mgmt, &["dump", "--secrets"], None).await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let full = json(&out);
    assert_ne!(full["config"]["ca"]["key"], "<redacted>");
    assert_eq!(full["credentials"][&key]["real_cred"], "sk-test-real");

    let out = cli(&h.mgmt, &["dump", "--redacted"], None).await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let red = json(&out);
    assert!(red["config"]["ca"].is_null());
    assert_eq!(
        red["credentials"][&key],
        serde_json::json!({
            "name": "c1",
            "type": "https",
            "user_id": "u-01",
            "user_name": "bob",
            "fake_cred": key,
        })
    );

    let out = cli(&h.mgmt, &["dump", "--secrets", "--redacted"], None).await;
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("mutually exclusive"), "{}", out.stderr);

    // -- health reports the bootstrap-config listener ----------------------
    let out = cli(&h.mgmt, &["health"], None).await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    assert_eq!(json(&out)["listen_transparent"], h.listen);

    // -- a corrupt credential object makes validate exit 3 ------------------
    let store = StoreClient::connect(&h.store_sock).await.unwrap();
    store.data_put("credential.bad", b"not json").await.unwrap();
    let out = cli(&h.mgmt, &["validate"], None).await;
    assert_eq!(out.code, 3, "stderr: {}", out.stderr);
    assert!(out.stderr.contains("data/credential.bad"), "{}", out.stderr);
    store.data_delete("credential.bad").await.unwrap();

    // -- remove deletes the object and its inline real ----------------------
    let out = cli(
        &h.mgmt,
        &["credential", "remove", "--fake-cred", &c2_key],
        None,
    )
    .await;
    assert_eq!(out.code, 0, "stderr: {}", out.stderr);
    let objects = store.data_list().await.unwrap();
    assert!(
        !objects.iter().any(|n| n == &c2_key),
        "the object goes with the credential: {objects:?}"
    );
    let out = cli(
        &h.mgmt,
        &["credential", "remove", "--fake-cred", &c2_key],
        None,
    )
    .await;
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("not found"), "{}", out.stderr);

    // -- the daemon's own configuration holds the CA, not the listener ------
    let stored: Value = serde_json::from_slice(&std::fs::read(&h.state).unwrap()).unwrap();
    assert!(stored.get("server").is_none(), "{stored}");
    assert!(stored["ca"]["cert"]
        .as_str()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));

    // -- unreachable management socket is an operational error --------------
    let out = cli(&h.mgmt.with_extension("missing"), &["validate"], None).await;
    assert_eq!(out.code, 1);
    assert!(
        out.stderr.contains("is credproxyd running"),
        "{}",
        out.stderr
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
