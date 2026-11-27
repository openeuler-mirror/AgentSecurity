//! End-to-end management plane over the real daemon and vault.
//!
//! One test drives every phase sequentially because the binary-level instance
//! lock is per-process, not per-socket. Every request goes over the single
//! `/run/credsvault/mgmt.sock`-style AF_UNIX socket (redirected to a scratch
//! path) with HTTP/1.1 + JSON.

use std::path::Path;
use std::time::Duration;

use credproxyd::trust;
use serde_json::{json, Value};
use tokio::process::Child;

mod support;
use support::*;

fn spawn_with(dir: &Path, store: &Path, mgmt: &Path, state: &Path, extra: Value) -> Child {
    let config = dir.join("bootstrap.json");
    let mut body = json!({
        "store_socket": store.display().to_string(),
        "mgmt_socket": mgmt.display().to_string(),
        "store_wait_ms": 2_000,
    });
    let target = body.as_object_mut().unwrap();
    for (key, value) in extra.as_object().expect("extra must be an object") {
        target.insert(key.clone(), value.clone());
    }
    std::fs::write(&config, serde_json::to_vec(&body).unwrap()).unwrap();
    spawn_daemon(&[
        "--config",
        config.to_str().unwrap(),
        "--state-file",
        state.to_str().unwrap(),
        // spawn_daemon would add this too; keep the path explicit so the
        // helper's "already passed" check stays honest.
        "--lock-file",
        test_lock_path().to_str().unwrap(),
    ])
}

async fn stop(daemon: Child) {
    sigterm(&daemon);
    let _ = wait_output(daemon, Duration::from_secs(5)).await;
}

fn parse(resp: &HttpResponse) -> Value {
    serde_json::from_str(&resp.body)
        .unwrap_or_else(|e| panic!("body is not JSON ({e}): {}", resp.body))
}

fn get(sock: &Path, path: &str) -> HttpResponse {
    mgmt_call(sock, "GET", path, None)
}

/// The code field of an error reply.
fn code(resp: &HttpResponse) -> String {
    parse(resp)["code"].as_str().unwrap_or_default().to_string()
}

fn add_body(name: &str, user: &str, real: &str, host: &str) -> Value {
    json!({
        "name": name,
        "type": "https",
        "user_id": "u-01",
        "user_name": user,
        "real_cred": real,
        "allowed_hosts": [host],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn mgmt_end_to_end() {
    let store = start_store("credproxyd-mgmt").await;
    let dir = scratch("mgmt-e2e");
    let mgmt = dir.path().join("mgmt.sock");
    let state = dir.path().join("state").join("daemon.json");
    let transparent_port = free_port();

    let ca = trust::generate_ca().expect("CA");
    let ca_path = dir.path().join("upstream-ca.pem");
    std::fs::write(&ca_path, &ca.cert).unwrap();
    let daemon = spawn_with(
        dir.path(),
        &store.sock,
        &mgmt,
        &state,
        json!({
            "upstream_ca": ca_path.display().to_string(),
            "listen_transparent": format!("127.0.0.1:{transparent_port}"),
        }),
    );
    assert!(
        wait_for_path(&mgmt, Duration::from_secs(10)).await,
        "management socket appears"
    );
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(&mgmt).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "management socket mode");

    let resp = get(&mgmt, "/v1/health");
    assert_eq!(resp.status, 200, "{}", resp.body);
    let health = parse(&resp);
    assert_eq!(health["status"], "ok");
    assert_eq!(health["store"], "ok");
    assert!(health["version"].as_str().is_some());
    assert_eq!(
        health["listen_transparent"],
        format!("127.0.0.1:{transparent_port}")
    );
    assert_eq!(health["credentials"], 0);

    let resp = get(&mgmt, "/v1/credentials/list");
    assert_eq!(resp.status, 200);
    assert_eq!(parse(&resp)["credentials"], json!([]));

    let created = mgmt_ok(
        &mgmt,
        "POST",
        "/v1/credential/add",
        Some(add_body("c1", "alice", "sk-admin-secret", "localhost")),
    );
    let key = created["fake_cred"]
        .as_str()
        .expect("fake_cred")
        .to_string();
    assert!(key.starts_with("fcred-"));
    assert_eq!(created["name"], "c1");
    assert_eq!(created["type"], "https");
    assert_eq!(created["user_id"], "u-01");
    assert_eq!(created["user_name"], "alice");
    assert_eq!(created["allowed_hosts"], json!(["localhost"]));
    assert!(
        created.get("real_cred").is_none(),
        "the view never carries the real"
    );
    assert!(!created.to_string().contains("sk-admin-secret"));

    // Metadata read by fakecred; never the real.
    let resp = get(&mgmt, &format!("/v1/credential/get?fake_cred={key}"));
    assert_eq!(resp.status, 200, "{}", resp.body);
    let view = parse(&resp);
    assert_eq!(view["fake_cred"], key);
    assert_eq!(view["name"], "c1");
    assert!(view.get("real_cred").is_none());
    assert!(!resp.body.contains("sk-admin-secret"));

    // Dump masks the real by default, even when a body asks otherwise: the
    // body is not read for GET routes.
    let resp = mgmt_http(
        &mgmt,
        "GET",
        "/v1/dump",
        &[("Content-Type", "application/json")],
        r#"{"secrets":true}"#,
    );
    assert_eq!(resp.status, 200, "{}", resp.body);
    let dump = parse(&resp);
    assert!(dump["credentials"][&key].get("real_cred").is_none());
    assert!(!resp.body.contains("sk-admin-secret"));

    // The real can be opened explicitly.
    let resp = get(&mgmt, "/v1/dump?secrets=true");
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(
        parse(&resp)["credentials"][&key]["real_cred"],
        "sk-admin-secret"
    );

    // Redacted trims to identity only.
    let resp = get(&mgmt, "/v1/dump?redacted=true");
    assert_eq!(resp.status, 200);
    assert_eq!(
        parse(&resp)["credentials"][&key],
        json!({
            "name": "c1",
            "type": "https",
            "user_id": "u-01",
            "user_name": "alice",
            "fake_cred": key,
        })
    );

    let resp = get(&mgmt, "/v1/dump?secrets=true&redacted=true");
    assert_eq!(resp.status, 400, "{}", resp.body);
    assert_eq!(code(&resp), "invalid_argument");

    let resp = get(&mgmt, "/v1/validate");
    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(parse(&resp)["violations"], json!([]));

    // Update changes metadata and hosts but never the real or the type.
    let updated = mgmt_ok(
        &mgmt,
        "POST",
        &format!("/v1/credential/update?fake_cred={key}"),
        Some(json!({"user_name": "bob"})),
    );
    assert_eq!(updated["user_name"], "bob");
    let resp = get(&mgmt, &format!("/v1/credential/get?fake_cred={key}"));
    assert_eq!(parse(&resp)["user_name"], "bob");

    let resp = mgmt_call(
        &mgmt,
        "POST",
        &format!("/v1/credential/update?fake_cred={key}"),
        Some(json!({"real_cred": "sk-new"})),
    );
    assert_eq!(resp.status, 400, "{}", resp.body);
    assert_eq!(code(&resp), "invalid_argument");

    let resp = mgmt_call(
        &mgmt,
        "POST",
        &format!("/v1/credential/update?fake_cred={key}"),
        None,
    );
    assert_eq!(resp.status, 400, "{}", resp.body);
    assert_eq!(code(&resp), "invalid_argument");

    let resp = mgmt_call(
        &mgmt,
        "POST",
        &format!("/v1/credential/update?fake_cred={key}"),
        Some(json!({"allowed_hosts": ["example.com:443"]})),
    );
    assert_eq!(resp.status, 400, "{}", resp.body);
    assert_eq!(code(&resp), "invalid_argument");

    // Query semantics: fake_cred only from the query, strict key set, no
    // duplicates.
    let resp = get(&mgmt, "/v1/credential/get");
    assert_eq!(resp.status, 400, "{}", resp.body);
    let resp = get(
        &mgmt,
        &format!("/v1/credential/get?fake_cred={key}&fake_cred=x"),
    );
    assert_eq!(resp.status, 400, "{}", resp.body);
    let resp = get(&mgmt, &format!("/v1/credential/get?fcred={key}"));
    assert_eq!(resp.status, 400, "{}", resp.body);
    // A known path with the wrong method is not a route.
    let resp = get(&mgmt, &format!("/v1/credential/remove?fake_cred={key}"));
    assert_eq!(resp.status, 404, "{}", resp.body);
    assert_eq!(code(&resp), "not_found");
    let resp = mgmt_call(&mgmt, "POST", "/v1/nope", None);
    assert_eq!(resp.status, 404);
    assert_eq!(code(&resp), "not_found");

    // Errors: duplicate name, invalid host, bad name.
    let resp = mgmt_call(
        &mgmt,
        "POST",
        "/v1/credential/add",
        Some(add_body("c1", "alice", "sk-other", "localhost")),
    );
    assert_eq!(resp.status, 409, "{}", resp.body);
    assert_eq!(code(&resp), "already_exists");

    // One real may back more than one credential; the response still never
    // echoes the real.
    let shared = mgmt_ok(
        &mgmt,
        "POST",
        "/v1/credential/add",
        Some(add_body("c2", "alice", "sk-admin-secret", "localhost")),
    );
    assert_eq!(shared["name"], "c2");
    assert!(!shared.to_string().contains("sk-admin-secret"));

    let resp = mgmt_call(
        &mgmt,
        "POST",
        "/v1/credential/add",
        Some(add_body("c3", "alice", "sk-c3", "example.com:443")),
    );
    assert_eq!(resp.status, 400, "{}", resp.body);
    assert_eq!(code(&resp), "invalid_argument");

    let resp = mgmt_call(
        &mgmt,
        "POST",
        "/v1/credential/add",
        Some(add_body("a/b", "alice", "sk-c4", "example.com")),
    );
    assert_eq!(resp.status, 400, "{}", resp.body);

    let resp = mgmt_call(
        &mgmt,
        "POST",
        "/v1/credential/add",
        Some(json!({
            "name": "c5", "type": "llm", "user_id": "u-01", "user_name": "alice",
            "real_cred": "sk-c5", "allowed_hosts": ["example.com"],
        })),
    );
    assert_eq!(resp.status, 400, "{}", resp.body);
    assert_eq!(code(&resp), "invalid_argument");

    // Remove deletes the object and its inline real.
    let resp = mgmt_call(
        &mgmt,
        "POST",
        &format!("/v1/credential/remove?fake_cred={key}"),
        None,
    );
    assert_eq!(resp.status, 204, "{}", resp.body);
    assert!(resp.body.is_empty());
    let resp = get(&mgmt, &format!("/v1/credential/get?fake_cred={key}"));
    assert_eq!(resp.status, 404);
    let resp = mgmt_call(
        &mgmt,
        "POST",
        &format!("/v1/credential/remove?fake_cred={key}"),
        None,
    );
    assert_eq!(resp.status, 404);

    // The listener is a bootstrap input: it is reported by `health` and has no
    // management-plane setter.
    let resp = mgmt_call(
        &mgmt,
        "POST",
        "/v1/settings/set",
        Some(json!({"listen_transparent": "127.0.0.1:1"})),
    );
    assert_eq!(resp.status, 404, "{}", resp.body);

    // Startup generated a CA; `ca init` without force is a conflict, and
    // `--force` rotates.
    let dump = parse(&get(&mgmt, "/v1/dump"));
    let pem = dump["config"]["ca"]["cert"]
        .as_str()
        .expect("startup CA")
        .to_string();
    let resp = mgmt_call(&mgmt, "POST", "/v1/ca/init", None);
    assert_eq!(resp.status, 409, "{}", resp.body);
    assert_eq!(code(&resp), "already_exists");
    let rotated = mgmt_ok(&mgmt, "POST", "/v1/ca/init", Some(json!({"force": true})));
    assert_ne!(rotated["cert"].as_str().unwrap(), pem);

    // Dump masks the CA private key unless secrets is set.
    let dump = parse(&get(&mgmt, "/v1/dump"));
    assert_eq!(dump["config"]["ca"]["key"], "<redacted>");
    assert!(dump["config"]["ca"]["cert"]
        .as_str()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
    let dump = parse(&get(&mgmt, "/v1/dump?secrets=true"));
    assert!(dump["config"]["ca"]["key"]
        .as_str()
        .unwrap()
        .contains("BEGIN PRIVATE KEY"));

    let dump = parse(&get(&mgmt, "/v1/dump?redacted=true"));
    assert!(dump["config"]["ca"].is_null());

    // The daemon's own configuration file holds the CA only; the listener is
    // never written there.
    let stored: Value = serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
    assert!(stored.get("server").is_none(), "{stored}");
    assert!(stored["ca"]["cert"]
        .as_str()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));

    stop(daemon).await;

    // ---------------------------------------------------------------- phase B
    // The body limit rejects early.
    let dir_b = scratch("mgmt-body-limit");
    let mgmt_b = dir_b.path().join("mgmt.sock");
    let state_b = dir_b.path().join("state").join("daemon.json");
    let daemon_b = spawn_with(
        dir_b.path(),
        &store.sock,
        &mgmt_b,
        &state_b,
        json!({
            "mgmt_max_body": 64,
            "listen_transparent": format!("127.0.0.1:{}", free_port()),
        }),
    );
    assert!(wait_for_path(&mgmt_b, Duration::from_secs(10)).await);

    let big = format!(r#"{{"name":"{}"}}"#, "x".repeat(100));
    let resp = mgmt_http(
        &mgmt_b,
        "POST",
        "/v1/credential/add",
        &[("Content-Type", "application/json")],
        &big,
    );
    assert_eq!(resp.status, 413, "{}", resp.body);
    assert_eq!(code(&resp), "too_large");

    stop(daemon_b).await;
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
