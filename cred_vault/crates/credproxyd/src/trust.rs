//! Trust material: the local CA lives in the daemon's own configuration; every
//! transparent-capture handshake gets a fresh leaf for the target host.
//!
//! Target selection happens in the cert resolver: a DNS SNI is used as a DNS
//! SAN, no SNI falls back to the `SO_ORIGINAL_DST` IP as an IP SAN, and an SNI
//! that is an IP literal is certified as an IP SAN. The proxy validates the
//! SNI/original-destination relationship after the handshake.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio_rustls::TlsAcceptor;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaPem {
    pub cert: String,
    pub key: String,
}

struct CaMaterial {
    /// rcgen's `signed_by` uses the issuer params and key; the issuer's own
    /// signature is not recomputed.
    cert: Certificate,
    key: KeyPair,
}

/// A loaded CA that can mint a per-connection acceptor.
pub struct Mitm {
    ca: Arc<Mutex<CaMaterial>>,
}

impl std::fmt::Debug for Mitm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mitm")
    }
}

impl Mitm {
    pub fn new(ca: &CaPem) -> Result<Mitm> {
        let ca_params = CertificateParams::from_ca_cert_pem(&ca.cert)
            .context("parse CA certificate from the daemon configuration")?;
        let ca_key =
            KeyPair::from_pem(&ca.key).context("parse CA key from the daemon configuration")?;
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .context("rebuild CA issuer params")?;
        Ok(Mitm {
            ca: Arc::new(Mutex::new(CaMaterial {
                cert: ca_cert,
                key: ca_key,
            })),
        })
    }

    /// Builds the server config for one accepted connection. `fallback` is the
    /// original destination IP, used when the ClientHello carries no SNI.
    pub fn acceptor(&self, fallback: Option<IpAddr>) -> TlsAcceptor {
        let resolver = TargetResolver {
            ca: self.ca.clone(),
            fallback,
        };
        let mut cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        TlsAcceptor::from(Arc::new(cfg))
    }
}

struct TargetResolver {
    ca: Arc<Mutex<CaMaterial>>,
    fallback: Option<IpAddr>,
}

impl std::fmt::Debug for TargetResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TargetResolver")
    }
}

impl ResolvesServerCert for TargetResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let target = match hello.server_name() {
            Some(sni) if !sni.is_empty() => sni.to_ascii_lowercase(),
            _ => self.fallback?.to_string(),
        };
        sign_leaf(&self.ca, &target)
    }
}

fn sign_leaf(ca: &Arc<Mutex<CaMaterial>>, target: &str) -> Option<Arc<CertifiedKey>> {
    let mut params = match target.parse::<IpAddr>() {
        Ok(ip) => {
            let mut params = CertificateParams::new(Vec::<String>::new()).ok()?;
            params.subject_alt_names.push(SanType::IpAddress(ip));
            params
        }
        Err(_) => {
            if target.is_empty() || target.contains('/') {
                return None;
            }
            CertificateParams::new(vec![target.to_string()]).ok()?
        }
    };
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, target);
    params.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate().ok()?;
    let leaf = {
        let ca = ca.lock().ok()?;
        params.signed_by(&leaf_key, &ca.cert, &ca.key).ok()?
    };

    let key_der = PrivatePkcs8KeyDer::from(leaf_key.serialize_der());
    let signing_key =
        rustls::crypto::ring::sign::any_supported_type(&PrivateKeyDer::Pkcs8(key_der)).ok()?;
    Some(Arc::new(CertifiedKey::new(
        vec![leaf.der().clone()],
        signing_key,
    )))
}

/// Generate a new local CA (ECDSA P-256) and return its PEM pair.
pub fn generate_ca() -> Result<CaPem> {
    let key = KeyPair::generate().context("generate CA key")?;
    let mut params = CertificateParams::new(Vec::<String>::new()).context("CA params")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "credsvault local CA");
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert = params.self_signed(&key).context("self-sign CA")?;
    Ok(CaPem {
        cert: cert.pem(),
        key: key.serialize_pem(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ca_builds_a_mitm() {
        let ca = generate_ca().unwrap();
        assert!(ca.cert.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(ca.key.contains("PRIVATE KEY"));
        let mitm = Mitm::new(&ca).expect("MITM builds");
        let _ = mitm.acceptor(Some("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn corrupt_ca_is_rejected() {
        let ca = CaPem {
            cert: "not a cert".to_string(),
            key: "not a key".to_string(),
        };
        assert!(Mitm::new(&ca).is_err());
    }
}
