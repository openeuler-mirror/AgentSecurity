//! Startup loading and model validation against a real `credstore` server.
//!
//! The vault holds one `data/<fake_cred>` object per credential at
//! `schema_version = 1`; the daemon's own configuration lives in its own file,
//! not in the vault.

use std::path::PathBuf;

use credproxyd::config::{credential_object, Credential, CredentialType, SCHEMA_VERSION};
use credproxyd::control::load_model;
use credproxyd::store_client::StoreClient;

const KEY: &str = "fcred-0123456789abcdef0123456789abcdef";
const KEY2: &str = "fcred-fedcba9876543210fedcba9876543210";
mod support;
use support::*;

/// The store server plus one client connection: every test here loads a model
/// from the same store it seeds.
struct Harness {
    _store: StoreHarness,
    _dir: tempfile::TempDir,
    state: PathBuf,
    client: StoreClient,
}

async fn harness() -> Harness {
    let store = start_store("credproxyd-startup").await;
    let dir = scratch("credproxyd-startup-state");
    let state = dir.path().join("daemon.json");
    let client = StoreClient::connect(&store.sock).await.unwrap();
    Harness {
        _store: store,
        _dir: dir,
        state,
        client,
    }
}

fn credential(name: &str, key: &str, real: &str) -> Credential {
    Credential {
        schema_version: SCHEMA_VERSION,
        name: name.to_string(),
        kind: CredentialType::Https,
        user_id: "u-01".to_string(),
        user_name: "alice".to_string(),
        fake_cred: key.to_string(),
        real_cred: real.to_string(),
        allowed_hosts: vec!["api.example.com".to_string()],
        rules: None,
    }
}

async fn write_credential(h: &Harness, credential: &Credential) {
    h.client
        .data_put(
            &credential_object(&credential.fake_cred),
            &serde_json::to_vec(credential).unwrap(),
        )
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn store_client_roundtrip() {
    let h = harness().await;
    h.client.data_put(KEY, b"{}").await.unwrap();
    assert_eq!(h.client.data_get(KEY).await.unwrap(), b"{}");
    assert_eq!(h.client.data_list().await.unwrap(), vec![KEY.to_string()]);
    h.client.data_delete(KEY).await.unwrap();
    assert!(h._store.sock.exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn skeleton_config_is_written_once_and_loads() {
    let h = harness().await;
    let first = load_model(&h.client, &h.state).await.unwrap();
    assert_eq!(first.config, credproxyd::config::DaemonConfig::default());
    assert!(first.credentials.is_empty());
    assert!(h.state.exists(), "skeleton daemon config is written");
    // A second load reads the same file and does not rewrite it.
    let second = load_model(&h.client, &h.state).await.unwrap();
    assert_eq!(second.config, first.config);
}

#[tokio::test(flavor = "multi_thread")]
async fn complete_model_loads_with_inline_real() {
    let h = harness().await;
    write_credential(&h, &credential("b", KEY, "real-secret")).await;
    let model = load_model(&h.client, &h.state).await.unwrap();
    assert_eq!(model.credentials.len(), 1);
    assert_eq!(model.credentials[KEY].fake_cred, KEY);
    assert_eq!(model.credentials[KEY].real_cred, "real-secret");
    assert_eq!(model.credentials[KEY].name, "b");
}

#[tokio::test(flavor = "multi_thread")]
async fn old_schema_versions_are_refused_with_a_rebuild_message() {
    for version in [2u32, 3] {
        let h = harness().await;
        let mut c = credential("b", KEY, "real-secret");
        c.schema_version = version;
        write_credential(&h, &c).await;
        let err = load_model(&h.client, &h.state)
            .await
            .expect_err("must fail");
        let text = format!("{err:#}");
        assert!(
            text.contains(&format!("unsupported schema_version {version}")),
            "{text}"
        );
        assert!(text.contains("old storage format"), "{text}");
        assert!(text.contains("rebuild the vault"), "{text}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_real_refuses_startup() {
    let h = harness().await;
    write_credential(&h, &credential("c", KEY, "")).await;
    let err = load_model(&h.client, &h.state)
        .await
        .expect_err("must fail");
    let text = format!("{err:#}");
    assert!(text.contains("real_cred is empty"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn shared_real_loads() {
    // One real value may back several credentials; fakecred is the key.
    let h = harness().await;
    write_credential(&h, &credential("c1", KEY, "same-secret")).await;
    write_credential(&h, &credential("c2", KEY2, "same-secret")).await;
    let model = load_model(&h.client, &h.state).await.expect("must load");
    assert_eq!(model.credentials.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn duplicate_names_refuse_startup() {
    let h = harness().await;
    write_credential(&h, &credential("same", KEY, "one")).await;
    write_credential(&h, &credential("same", KEY2, "two")).await;
    let err = load_model(&h.client, &h.state)
        .await
        .expect_err("must fail");
    assert!(
        format!("{err:#}").contains("duplicate credential name"),
        "{err:#}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn corrupt_credential_json_refuses_startup() {
    let h = harness().await;
    h.client.data_put(KEY, b"not json").await.unwrap();
    let err = load_model(&h.client, &h.state)
        .await
        .expect_err("must fail");
    assert!(
        format!("{err:#}").contains(&format!("parse data/{KEY}")),
        "{err:#}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_credential_object_refuses_startup() {
    let h = harness().await;
    h.client.data_put("config", b"{}").await.unwrap();
    let err = load_model(&h.client, &h.state)
        .await
        .expect_err("must fail");
    let text = format!("{err:#}");
    assert!(text.contains("not a credential object"), "{text}");
    assert!(text.contains("rebuild the vault"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn body_fakecred_must_match_the_object_key() {
    let h = harness().await;
    // Stored under KEY2, but the body claims KEY.
    let c = credential("b", KEY, "real-secret");
    h.client
        .data_put(KEY2, &serde_json::to_vec(&c).unwrap())
        .await
        .unwrap();
    let err = load_model(&h.client, &h.state)
        .await
        .expect_err("must fail");
    let text = format!("{err:#}");
    assert!(text.contains("does not match the object key"), "{text}");
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
