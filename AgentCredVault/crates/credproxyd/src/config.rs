//! Data model and validation.
//!
//! The vault holds one business object per credential: `data/<fake_cred>`, a
//! complete credential at `schema_version = 1`. The daemon's own
//! configuration — the CA material — is persisted by the daemon itself, not in
//! the vault. The transparent listener is a bootstrap input and is not stored
//! here.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context, Result};
use hyper::header::HeaderValue;
use serde::{Deserialize, Serialize};

use crate::placeholder;
use crate::policy;

/// Version of one stored credential object.
pub const SCHEMA_VERSION: u32 = 1;
/// Version of the daemon's own configuration file.
pub const DAEMON_SCHEMA_VERSION: u32 = 2;
/// Earlier daemon configuration embedded the listener; it is read once (the
/// stored address is ignored) and rewritten at the current version.
const LEGACY_DAEMON_SCHEMA_VERSION: u32 = 1;

pub fn credential_object(fake_cred: &str) -> String {
    fake_cred.to_string()
}

pub fn credential_from_object(name: &str) -> Option<&str> {
    placeholder::valid_key(name).then_some(name)
}

// ---------------------------------------------------------------------------
// Daemon-owned configuration
// ---------------------------------------------------------------------------

/// The daemon's own persisted configuration. Location and on-disk shape are
/// implementation details. Only the CA lives here: the listener is a bootstrap
/// input, so there is a single definition of where the daemon binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DaemonConfig {
    pub schema_version: u32,
    /// Present only after CA generation/rotation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca: Option<CaMaterial>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        DaemonConfig {
            schema_version: DAEMON_SCHEMA_VERSION,
            ca: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaMaterial {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
struct VersionProbe {
    #[serde(default)]
    schema_version: u32,
}

/// Version 1 shape: the listener was stored here. Read only to migrate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyDaemonConfigV1 {
    #[allow(dead_code)]
    schema_version: u32,
    #[serde(default)]
    server: Option<LegacyServerV1>,
    #[serde(default)]
    ca: Option<CaMaterial>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyServerV1 {
    #[serde(default)]
    listen_transparent: Option<String>,
}

/// Reads the daemon configuration. `Ok(None)` means the file does not exist.
/// A version-1 file is converted in memory; its stored listener is dropped
/// because the listener now comes from the bootstrap configuration.
pub fn daemon_config_read(path: &Path) -> Result<Option<DaemonConfig>> {
    Ok(read_migrating(path)?.map(|(config, _)| config))
}

/// Reads the configuration and reports the listener that a legacy file still
/// carries, so the caller can warn and persist the current shape.
fn read_migrating(path: &Path) -> Result<Option<(DaemonConfig, Option<String>)>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("read daemon config {}", path.display())),
    };
    let probe: VersionProbe = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse daemon config {}", path.display()))?;
    let (config, legacy_listener) = match probe.schema_version {
        DAEMON_SCHEMA_VERSION => {
            let config: DaemonConfig = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse daemon config {}", path.display()))?;
            (config, None)
        }
        LEGACY_DAEMON_SCHEMA_VERSION => {
            let legacy: LegacyDaemonConfigV1 = serde_json::from_slice(&bytes)
                .with_context(|| format!("parse daemon config {}", path.display()))?;
            let listener = legacy.server.and_then(|server| server.listen_transparent);
            (
                DaemonConfig {
                    schema_version: DAEMON_SCHEMA_VERSION,
                    ca: legacy.ca,
                },
                listener,
            )
        }
        other => bail!(
            "daemon config {}: unsupported schema_version {}",
            path.display(),
            other
        ),
    };
    validate_daemon_config(&config).with_context(|| format!("daemon config {}", path.display()))?;
    Ok(Some((config, legacy_listener)))
}

/// Reads the daemon configuration, writing the default skeleton when the file
/// is absent, and migrating a version-1 file forward. A corrupt or unreadable
/// file is fatal.
pub fn daemon_config_load_or_create(path: &Path) -> Result<DaemonConfig> {
    match read_migrating(path)? {
        Some((config, legacy_listener)) => {
            if let Some(listener) = legacy_listener {
                eprintln!(
                    "credproxyd: daemon config {}: the stored listener {listener} is no longer \
                     used (listen_transparent is a bootstrap config input); rewriting the file",
                    path.display()
                );
                daemon_config_save(path, &config)?;
            }
            Ok(config)
        }
        None => {
            let config = DaemonConfig::default();
            daemon_config_save(path, &config)?;
            eprintln!(
                "credproxyd: daemon config {} was missing; wrote the default skeleton",
                path.display()
            );
            Ok(config)
        }
    }
}

/// Atomically replaces the daemon configuration: same-directory temporary file,
/// `fsync`, `rename`. The file is `0600` and its directory `0700`.
pub fn daemon_config_save(path: &Path, config: &DaemonConfig) -> Result<()> {
    validate_daemon_config(config)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create daemon config directory {}", parent.display()))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod daemon config directory {}", parent.display()))?;

    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(config).context("encode daemon config")?;
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .with_context(|| format!("open daemon config temp file {}", tmp.display()))?;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod daemon config temp file {}", tmp.display()))?;
        file.write_all(&bytes)
            .with_context(|| format!("write daemon config temp file {}", tmp.display()))?;
        file.sync_all()
            .with_context(|| format!("sync daemon config temp file {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, path)
        .with_context(|| format!("replace daemon config {}", path.display()))?;
    // Durability of the rename itself. A failure here is not fatal: the new
    // file is already in place for this boot.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

pub fn validate_daemon_config(config: &DaemonConfig) -> Result<()> {
    if config.schema_version != DAEMON_SCHEMA_VERSION {
        bail!(
            "unsupported daemon config schema_version {}",
            config.schema_version
        );
    }
    if let Some(ca) = &config.ca {
        if ca.cert.trim().is_empty() || ca.key.trim().is_empty() {
            bail!("daemon config ca.cert and ca.key must both be non-empty PEM");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Vault credential object
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialType {
    Https,
}

impl CredentialType {
    pub fn as_str(self) -> &'static str {
        match self {
            CredentialType::Https => "https",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    pub schema_version: u32,
    /// Human-readable name; required, globally unique and mutable.
    pub name: String,
    #[serde(rename = "type")]
    pub kind: CredentialType,
    /// User id from the management identity; audit only.
    pub user_id: String,
    /// User name from the management identity; audit only.
    pub user_name: String,
    /// The fakecred itself: storage key and API identifier. Immutable.
    pub fake_cred: String,
    /// Real secret, inline in this object.
    pub real_cred: String,
    /// Host-only allowlist: domains or IP literals, no port or wildcard.
    pub allowed_hosts: Vec<String>,
    /// `null` or omitted means no operation-level restriction; V1 rejects a
    /// non-empty value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<serde_json::Value>,
}

/// `[A-Za-z0-9._-]`, 1–`max` characters, first character alphanumeric.
pub fn valid_ident(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

/// `[a-z0-9_-]`, 1–128 characters.
pub fn valid_user_field(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'_'))
}

/// Parses one stored credential object: version gate, JSON, then semantics.
/// `object_id` is the storage key (`data/<fake_cred>`).
pub fn parse_credential(bytes: &[u8], object_id: &str) -> Result<Credential> {
    let label = format!("data/{object_id}");
    let probe: VersionProbe =
        serde_json::from_slice(bytes).with_context(|| format!("parse {label}"))?;
    if probe.schema_version != SCHEMA_VERSION {
        bail!(
            "credential {object_id}: unsupported schema_version {} \
             (old storage format; rebuild the vault)",
            probe.schema_version
        );
    }
    let credential: Credential =
        serde_json::from_slice(bytes).with_context(|| format!("parse {label}"))?;
    validate_credential(&credential, object_id)?;
    Ok(credential)
}

pub fn validate_credential(c: &Credential, object_id: &str) -> Result<()> {
    let ctx = || format!("credential {object_id}");
    if c.schema_version != SCHEMA_VERSION {
        bail!(
            "{}: unsupported schema_version {} (old storage format; rebuild the vault)",
            ctx(),
            c.schema_version
        );
    }
    if !valid_ident(&c.name, 64) {
        bail!("{}: invalid name", ctx());
    }
    if !valid_user_field(&c.user_id) {
        bail!("{}: invalid user_id", ctx());
    }
    if !valid_user_field(&c.user_name) {
        bail!("{}: invalid user_name", ctx());
    }
    if !placeholder::valid_key(&c.fake_cred) {
        bail!("{}: invalid fake_cred", ctx());
    }
    if c.fake_cred != object_id {
        bail!(
            "data/{object_id}: fake_cred {:?} does not match the object key",
            c.fake_cred
        );
    }
    validate_real_cred(&c.real_cred).with_context(ctx)?;

    if c.kind != CredentialType::Https {
        bail!("{}: unsupported credential type", ctx());
    }
    if c.allowed_hosts.is_empty() {
        bail!("{}: allowed_hosts must not be empty", ctx());
    }
    policy::parse_hosts(&c.allowed_hosts).with_context(ctx)?;
    if non_empty_rules(&c.rules) {
        bail!("{}: rules are not implemented in v1", ctx());
    }
    Ok(())
}

/// The real value is written into an HTTP header on every request, so it must
/// be a single valid header value.
pub fn validate_real_cred(secret: &str) -> Result<()> {
    if secret.is_empty() {
        bail!("real_cred is empty");
    }
    if secret.contains('\0') {
        bail!("real_cred contains NUL");
    }
    if HeaderValue::from_bytes(secret.as_bytes()).is_err() {
        bail!("real_cred contains characters that cannot appear in an HTTP header value");
    }
    if secret.chars().count() > 1024 {
        bail!("real_cred is over 1024 characters");
    }
    if secret.len() > 4096 {
        bail!("real_cred is over 4096 bytes");
    }
    Ok(())
}

fn non_empty_rules(rules: &Option<serde_json::Value>) -> bool {
    rules.as_ref().is_some_and(|r| match r {
        serde_json::Value::Null => false,
        serde_json::Value::Object(o) => !o.is_empty(),
        serde_json::Value::Array(a) => !a.is_empty(),
        _ => true,
    })
}

/// Cross-object invariants.
pub fn validate_model(
    config: &DaemonConfig,
    credentials: &BTreeMap<String, Credential>,
) -> Result<()> {
    validate_daemon_config(config)?;
    let mut names = HashSet::new();
    let mut keys = HashSet::new();
    for (id, credential) in credentials {
        validate_credential(credential, id)?;
        if !names.insert(credential.name.as_str()) {
            bail!("duplicate credential name {:?} ({id})", credential.name);
        }
        if !keys.insert(credential.fake_cred.as_str()) {
            bail!(
                "fake_cred {} appears in more than one credential ({id})",
                credential.fake_cred
            );
        }
        // `real_cred` is not an index key, so duplicates do not create lookup
        // ambiguity.
    }
    Ok(())
}

/// Parsed model snapshot, keyed by fakecred.
#[derive(Debug, Clone)]
pub struct Model {
    pub config: DaemonConfig,
    pub credentials: BTreeMap<String, Credential>,
}

impl Model {
    pub fn validate(&self) -> Result<()> {
        validate_model(&self.config, &self.credentials)
    }

    pub fn credential_values(&self) -> impl Iterator<Item = &Credential> {
        self.credentials.values()
    }

    /// Name uniqueness check used by add/update before the full model check.
    pub fn name_taken(&self, name: &str, except_fake_cred: Option<&str>) -> bool {
        self.credentials
            .values()
            .any(|c| c.name == name && except_fake_cred.is_none_or(|key| c.fake_cred != key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "fcred-0123456789abcdef0123456789abcdef";
    const KEY2: &str = "fcred-fedcba9876543210fedcba9876543210";

    fn https(name: &str, key: &str, real: &str) -> Credential {
        Credential {
            schema_version: SCHEMA_VERSION,
            name: name.to_string(),
            kind: CredentialType::Https,
            user_id: "u-01".to_string(),
            user_name: "alice".to_string(),
            fake_cred: key.to_string(),
            real_cred: real.to_string(),
            allowed_hosts: vec!["postman-echo.com".to_string()],
            rules: None,
        }
    }

    fn model() -> Model {
        let mut credentials = BTreeMap::new();
        credentials.insert(KEY.to_string(), https("postman", KEY, "real-a"));
        credentials.insert(KEY2.to_string(), https("atomgit", KEY2, "real-b"));
        Model {
            config: DaemonConfig::default(),
            credentials,
        }
    }

    #[test]
    fn default_daemon_config_roundtrips() {
        let c = DaemonConfig::default();
        assert_eq!(c.schema_version, 2, "listener removed from stored config");
        assert!(c.ca.is_none());
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("\"ca\""));
        assert!(
            !json.contains("server"),
            "the listener is not stored: {json}"
        );
        let back: DaemonConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn legacy_v1_listener_is_dropped_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.json");
        std::fs::write(
            &path,
            r#"{"schema_version":1,"server":{"listen_transparent":"10.0.0.1:8443"},"ca":{"cert":"CERT","key":"KEY"}}"#,
        )
        .unwrap();
        let config = daemon_config_load_or_create(&path).expect("migrate v1");
        assert_eq!(config.schema_version, DAEMON_SCHEMA_VERSION);
        assert_eq!(
            config.ca.as_ref().map(|ca| ca.cert.as_str()),
            Some("CERT"),
            "the CA survives the migration"
        );
        let stored = std::fs::read_to_string(&path).unwrap();
        assert!(!stored.contains("listen_transparent"), "{stored}");
        assert!(!stored.contains("\"server\""), "{stored}");
    }

    #[test]
    fn future_daemon_schema_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("daemon.json");
        std::fs::write(&path, r#"{"schema_version":3}"#).unwrap();
        let err = daemon_config_read(&path).unwrap_err().to_string();
        assert!(err.contains("unsupported schema_version"), "{err}");
    }

    #[test]
    fn valid_model_passes() {
        assert!(model().validate().is_ok());
    }

    #[test]
    fn object_roundtrips_at_v1() {
        let c = https("postman", KEY, "real-b");
        let bytes = serde_json::to_vec(&c).unwrap();
        let parsed = parse_credential(&bytes, KEY).unwrap();
        assert_eq!(parsed, c);
        assert_eq!(parsed.kind, CredentialType::Https);
    }

    #[test]
    fn old_schema_is_refused() {
        for version in [2, 3] {
            let mut c = https("postman", KEY, "real-a");
            c.schema_version = version;
            let bytes = serde_json::to_vec(&c).unwrap();
            let err = parse_credential(&bytes, KEY).unwrap_err().to_string();
            assert!(err.contains("old storage format"), "{err}");
            assert!(err.contains("rebuild the vault"), "{err}");
        }
    }

    #[test]
    fn rejects_duplicate_name_and_fakecred_mismatch() {
        let mut m = model();
        m.credentials.get_mut(KEY2).unwrap().name = "postman".to_string();
        assert!(m.validate().is_err());

        let mut m = model();
        m.credentials.get_mut(KEY2).unwrap().fake_cred = KEY.to_string();
        assert!(m.validate().is_err());
    }

    #[test]
    fn accepts_shared_real() {
        let mut m = model();
        m.credentials.get_mut(KEY2).unwrap().real_cred = "real-a".to_string();
        assert!(m.validate().is_ok());
    }

    #[test]
    fn rejects_non_empty_rules() {
        let mut c = https("postman", KEY, "real-b");
        c.rules = Some(serde_json::json!({"method": "GET"}));
        assert!(validate_credential(&c, KEY).is_err());
    }

    #[test]
    fn empty_rules_are_treated_as_absent() {
        for rules in [serde_json::json!([]), serde_json::json!({})] {
            let mut c = https("postman", KEY, "real-b");
            c.rules = Some(rules);
            assert!(validate_credential(&c, KEY).is_ok());
        }
    }

    #[test]
    fn rejects_empty_or_unbound_hosts() {
        let mut c = https("postman", KEY, "real-b");
        c.allowed_hosts.clear();
        assert!(validate_credential(&c, KEY).is_err());

        let mut c = https("postman", KEY, "real-b");
        c.allowed_hosts = vec!["*.example.com".to_string()];
        assert!(validate_credential(&c, KEY).is_err());

        let mut c = https("postman", KEY, "real-b");
        c.allowed_hosts = vec!["example.com:443".to_string()];
        assert!(validate_credential(&c, KEY).is_err());
    }

    #[test]
    fn ident_rules() {
        assert!(valid_ident("agent-a", 64));
        assert!(valid_ident("a.b_c", 64));
        assert!(!valid_ident("", 64));
        assert!(!valid_ident("-a", 64));
        assert!(!valid_ident("a/b", 64));
        assert!(!valid_ident(&"a".repeat(65), 64));

        assert!(valid_user_field("u-01_a"));
        assert!(!valid_user_field("U-01"));
        assert!(!valid_user_field("alice smith"));
        assert!(!valid_user_field(&"a".repeat(129)));
    }

    #[test]
    fn daemon_config_save_is_atomic_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/daemon.json");
        let config = DaemonConfig {
            ca: Some(CaMaterial {
                cert: "CERT".to_string(),
                key: "KEY".to_string(),
            }),
            ..Default::default()
        };
        daemon_config_save(&path, &config).unwrap();
        assert_eq!(daemon_config_read(&path).unwrap(), Some(config.clone()));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);

        daemon_config_save(&path, &DaemonConfig::default()).unwrap();
        assert_eq!(
            daemon_config_read(&path).unwrap(),
            Some(DaemonConfig::default())
        );
    }
}
