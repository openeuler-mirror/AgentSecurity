//! Binary-level startup and failure semantics.
//!
//! The scenarios share one real `credstore` server and run sequentially in a
//! single test. The skeleton scenario needs the default transparent listener,
//! so when a deployed instance already holds it the test asserts that bind
//! failure and runs the lifecycle half on a free port instead.

use std::time::Duration;

use credproxyd::bootstrap::DEFAULT_LISTEN_TRANSPARENT;
use credproxyd::config::{Credential, CredentialType, DaemonConfig, SCHEMA_VERSION};
use credproxyd::store_client::StoreClient;

mod support;
use support::*;

const KEY: &str = "fcred-0123456789abcdef0123456789abcdef";

fn credential() -> Credential {
    Credential {
        schema_version: SCHEMA_VERSION,
        name: "c".to_string(),
        kind: CredentialType::Https,
        user_id: "u-01".to_string(),
        user_name: "alice".to_string(),
        fake_cred: KEY.to_string(),
        real_cred: "real-secret".to_string(),
        allowed_hosts: vec!["api.example.com".to_string()],
        rules: None,
    }
}

/// Whether the default transparent listener can be bound right now.
fn default_ingress_is_free() -> bool {
    std::net::TcpListener::bind(DEFAULT_LISTEN_TRANSPARENT).is_ok()
}

#[tokio::test(flavor = "multi_thread")]
async fn daemon_lifecycle() {
    let store = start_store("credproxyd-daemon").await;
    let dir = scratch("credproxy-mgmt");
    let mgmt = dir.path().join("mgmt.sock");
    let state = dir.path().join("state").join("daemon.json");

    // 1. Empty vault: the daemon writes its own configuration file and a local
    //    CA, the management socket appears, and SIGTERM stops the daemon
    //    cleanly. The listener is not part of the stored configuration.
    let skeleton_free = default_ingress_is_free();
    let skeleton = |path: &std::path::Path| {
        let stored = std::fs::read(path).expect("skeleton daemon config");
        let parsed: DaemonConfig = serde_json::from_slice(&stored).unwrap();
        assert_eq!(parsed.schema_version, 2, "current daemon config shape");
        assert!(parsed.ca.is_some(), "local CA is generated on first start");
        let raw = String::from_utf8_lossy(&stored);
        assert!(
            !raw.contains("listen_transparent") && !raw.contains("\"server\""),
            "the listener is a bootstrap input, not stored state: {raw}"
        );
    };
    let first = spawn_daemon_with(&store.sock, &mgmt, &state, 2_000);
    let mut d = if skeleton_free {
        assert!(
            wait_for_path(&mgmt, Duration::from_secs(10)).await,
            "management socket did not appear"
        );
        skeleton(&state);
        first
    } else {
        // A deployed daemon owns the default listener. The CA and configuration
        // are still written before the bind, so that half stays covered; the
        // lifecycle half moves to a free port.
        let out = wait_output(first, Duration::from_secs(10)).await;
        assert!(!out.status.success(), "bind conflict must be fatal");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("Address already in use"), "{stderr}");
        skeleton(&state);
        let listen = format!("127.0.0.1:{}", free_port());
        let d = spawn_daemon_with_listen(&store.sock, &mgmt, &state, 2_000, Some(&listen));
        assert!(
            wait_for_path(&mgmt, Duration::from_secs(10)).await,
            "management socket did not appear on the seeded port"
        );
        d
    };
    assert!(
        d.try_wait().expect("try_wait").is_none(),
        "daemon still running"
    );
    assert!(test_lock_path().exists(), "daemon lock file");

    // 2. A second daemon on the same lock is rejected before it touches the
    //    store.
    let second = spawn_daemon_with(&store.sock, &mgmt, &state, 1_000);
    let out = wait_output(second, Duration::from_secs(5)).await;
    assert!(!out.status.success(), "second daemon must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("another credproxyd is running"), "{stderr}");

    sigterm(&d);
    let out = wait_output(d, Duration::from_secs(5)).await;
    assert!(out.status.success(), "clean shutdown on SIGTERM");

    // 3. An inline real value is required: startup is refused and reported.
    let mgmt2 = dir.path().join("mgmt2.sock");
    let state2 = dir.path().join("state2").join("daemon.json");
    let listen2 = format!("127.0.0.1:{}", free_port());
    let mut broken = credential();
    broken.real_cred.clear();
    let client = StoreClient::connect(&store.sock).await.unwrap();
    client
        .data_put(KEY, &serde_json::to_vec(&broken).unwrap())
        .await
        .unwrap();
    let d2 = spawn_daemon_with_listen(&store.sock, &mgmt2, &state2, 2_000, Some(&listen2));
    let out = wait_output(d2, Duration::from_secs(10)).await;
    assert!(!out.status.success(), "missing real must refuse startup");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("real_cred is empty"), "{stderr}");
    assert!(!mgmt2.exists(), "no management socket after failed startup");

    // 4. Store unavailable: the daemon exits after the retry window.
    let missing = dir.path().join("nope.sock");
    let mgmt3 = dir.path().join("mgmt3.sock");
    let state3 = dir.path().join("state3").join("daemon.json");
    let d3 = spawn_daemon_with(&missing, &mgmt3, &state3, 300);
    let out = wait_output(d3, Duration::from_secs(10)).await;
    assert!(!out.status.success(), "unreachable store must exit nonzero");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("credstore not reachable"), "{stderr}");

    // 5. A corrupt daemon configuration file refuses startup instead of being
    //    replaced with a fresh skeleton.
    let mgmt4 = dir.path().join("mgmt4.sock");
    let state4 = dir.path().join("state4").join("daemon.json");
    std::fs::create_dir_all(state4.parent().unwrap()).unwrap();
    std::fs::write(&state4, b"not json").unwrap();
    let d4 = spawn_daemon_with(&store.sock, &mgmt4, &state4, 2_000);
    let out = wait_output(d4, Duration::from_secs(10)).await;
    assert!(
        !out.status.success(),
        "corrupt daemon config must refuse startup"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("parse daemon config"), "{stderr}");
    let stored = std::fs::read(&state4).unwrap();
    assert_eq!(stored, b"not json", "the corrupt file is left untouched");

    // 6. A credential object named outside `data/<fake_cred>` refuses startup:
    //    the vault format is the v1 one, not a mix.
    let mgmt5 = dir.path().join("mgmt5.sock");
    let state5 = dir.path().join("state5").join("daemon.json");
    let listen5 = format!("127.0.0.1:{}", free_port());
    client
        .data_put(KEY, &serde_json::to_vec(&credential()).unwrap())
        .await
        .unwrap();
    client.data_put("keystore.x", b"{}").await.unwrap();
    let d5 = spawn_daemon_with_listen(&store.sock, &mgmt5, &state5, 2_000, Some(&listen5));
    let out = wait_output(d5, Duration::from_secs(10)).await;
    assert!(!out.status.success(), "stray object must refuse startup");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("not a credential object"), "{stderr}");
    assert!(!mgmt5.exists(), "no management socket after failed startup");
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
