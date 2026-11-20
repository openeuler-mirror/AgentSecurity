//! Immutable runtime snapshot and its construction.
//!
//! Data-plane tasks clone the `Arc<Runtime>` they need; the management plane
//! builds a complete replacement and swaps it under the write lock.
//! No lock is held while serving a request.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use tokio::sync::RwLock;

use crate::config::{Credential, DaemonConfig, Model};
use crate::registry::Registry;
use crate::store_client::StoreClient;
use crate::trust;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
pub type ResBody = BoxBody<Bytes, BoxError>;

pub struct Runtime {
    pub config: DaemonConfig,
    /// Keyed by fakecred.
    pub credentials: BTreeMap<String, Credential>,
    pub registry: Registry,
    pub upstream_tls: Arc<rustls::ClientConfig>,
    /// MITM CA signer; `None` only before the CA exists.
    pub mitm: Option<Arc<trust::Mitm>>,
    pub store: Arc<StoreClient>,
    pub built_at: Instant,
}

pub type Shared = Arc<RwLock<Arc<Runtime>>>;

impl Runtime {
    /// Builds a complete snapshot. `store` is used for request-time store
    /// access; construction itself performs no IPC.
    pub fn build(
        config: DaemonConfig,
        credentials: BTreeMap<String, Credential>,
        store: Arc<StoreClient>,
        upstream_ca: Option<PathBuf>,
    ) -> Result<Runtime> {
        let model = Model {
            config,
            credentials,
        };
        model.validate().context("model validation failed")?;

        let registry = Registry::build(&model).context("build registry")?;
        let upstream_tls =
            Arc::new(build_upstream_tls(upstream_ca.as_deref()).context("build upstream TLS")?);
        let mitm = match &model.config.ca {
            Some(ca) => Some(Arc::new(
                trust::Mitm::new(&ca.as_pem()).context("load MITM CA")?,
            )),
            None => None,
        };

        Ok(Runtime {
            config: model.config,
            credentials: model.credentials,
            registry,
            upstream_tls,
            mitm,
            store,
            built_at: Instant::now(),
        })
    }

    pub fn model(&self) -> Model {
        Model {
            config: self.config.clone(),
            credentials: self.credentials.clone(),
        }
    }

    pub fn credential(&self, fake_cred: &str) -> Option<&Credential> {
        self.credentials.get(fake_cred)
    }
}

/// Build the shared cell from a complete runtime.
pub fn shared(runtime: Runtime) -> Shared {
    Arc::new(RwLock::new(Arc::new(runtime)))
}

pub async fn snapshot(shared: &Shared) -> Arc<Runtime> {
    shared.read().await.clone()
}

/// In-process test injection for the origin trust store. A test that builds the
/// runtime in-process cannot pass a bootstrap config file per instance, so it
/// registers its CA here instead (the same trust injection, in-process).
#[cfg(test)]
pub(crate) static TEST_UPSTREAM_CA: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();

fn build_root_store(upstream_ca: Option<&Path>) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Test-only trust injection, from the bootstrap config's `upstream_ca`.
    // Production omits it and uses the standard roots only.
    if let Some(ca_path) = upstream_ca {
        let display = ca_path.display();
        let pem = std::fs::read(ca_path).with_context(|| format!("read test CA {display}"))?;
        for cert in rustls_pemfile::certs(&mut &pem[..]) {
            roots.add(cert?)?;
        }
    }
    #[cfg(test)]
    if let Some(pem) = TEST_UPSTREAM_CA.get() {
        for cert in rustls_pemfile::certs(&mut &pem[..]) {
            roots.add(cert?)?;
        }
    }
    Ok(roots)
}

/// Origin TLS for the transparent path. ALPN is pinned to `http/1.1`;
/// certificate verification is never disabled.
fn build_upstream_tls(upstream_ca: Option<&Path>) -> Result<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(build_root_store(upstream_ca)?)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

impl crate::config::CaMaterial {
    pub fn as_pem(&self) -> trust::CaPem {
        trust::CaPem {
            cert: self.cert.clone(),
            key: self.key.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CredentialType, SCHEMA_VERSION};

    fn credential(name: &str, key: &str) -> Credential {
        Credential {
            schema_version: SCHEMA_VERSION,
            name: name.to_string(),
            kind: CredentialType::Https,
            user_id: "u-01".to_string(),
            user_name: "alice".to_string(),
            fake_cred: key.to_string(),
            real_cred: format!("real-{name}"),
            allowed_hosts: vec!["api.example.com".to_string()],
            rules: None,
        }
    }

    #[tokio::test]
    async fn registry_is_keyed_by_fakecred() {
        let mut credentials = BTreeMap::new();
        credentials.insert(
            "fcred-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            credential("a", "fcred-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        let rt = Runtime::build(
            DaemonConfig::default(),
            credentials,
            crate::store_client::StoreClient::dummy(),
            None,
        )
        .unwrap();
        assert!(rt.mitm.is_none());
        assert_eq!(rt.registry.len(), 1);
        assert!(rt
            .registry
            .get("fcred-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_some());
    }

    #[tokio::test]
    async fn invalid_model_is_rejected_before_use() {
        let mut credentials = BTreeMap::new();
        credentials.insert(
            "fcred-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            credential("same", "fcred-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );
        credentials.insert(
            "fcred-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            credential("same", "fcred-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        );
        let err = Runtime::build(
            DaemonConfig::default(),
            credentials,
            crate::store_client::StoreClient::dummy(),
            None,
        )
        .err()
        .expect("duplicate name");
        assert!(err.to_string().contains("validation"));
    }
}
