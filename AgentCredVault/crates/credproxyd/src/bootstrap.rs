//! Process bootstrap parameters.
//!
//! These are the settings the daemon needs *before* it can reach the vault:
//! the vault socket, the management socket, how long to wait for the vault,
//! the management body limit, and an optional extra trust root for the origin
//! (`upstream_ca`, test/demo only). They may come from a JSON file in addition
//! to the command line.
//!
//! Scope is deliberately limited to bootstrap. The transparent listen address
//! is a deployment input and lives here; the CA lives in the daemon's own
//! configuration file, and credentials live in the vault
//! (`data/<fake_cred>`). Those two are not accepted here: `deny_unknown_fields`
//! makes such a key a hard error instead of a silently ignored second source
//! of truth. `capture` is accepted because deployment-specific netfilter
//! parameters (bridge, subnet, gateway) are inputs to the rules the daemon
//! installs and owns at startup.
//!
//! Precedence per field: command line > config file > built-in default. No
//! program reads environment variables; `upstream_ca`, `mgmt_max_body` and
//! `listen_transparent` have no command-line form and come from the file only.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::capture::CaptureFileConfig;

pub const DEFAULT_STORE_SOCKET: &str = "/run/cvstore/store.sock";
pub const DEFAULT_MGMT_SOCKET: &str = "/run/credsvault/mgmt.sock";
pub const DEFAULT_STORE_WAIT_MS: u64 = 10_000;
pub const DEFAULT_CONFIG_FILE: &str = "/etc/credsvault/credproxyd.json";
pub const DEFAULT_MGMT_MAX_BODY: usize = 1024 * 1024;
/// The only data-plane ingress: transparent TLS capture.
pub const DEFAULT_LISTEN_TRANSPARENT: &str = "0.0.0.0:4100";

/// The on-disk shape. Every field is optional: an omitted field falls through
/// to the next source.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub store_socket: Option<PathBuf>,
    pub mgmt_socket: Option<PathBuf>,
    pub store_wait_ms: Option<u64>,
    /// Test/demo only: PEM added to the origin trust store. Production omits it
    /// and verification uses `webpki_roots` alone.
    pub upstream_ca: Option<PathBuf>,
    /// Maximum request body; larger requests get 413 without reading it.
    pub mgmt_max_body: Option<usize>,
    /// Transparent-capture listen address (`ip:port`). Omitted means the
    /// built-in default `0.0.0.0:4100`. Binding fails startup if the port is
    /// taken.
    pub listen_transparent: Option<String>,
    /// Deployment-specific netfilter inputs. The daemon installs the rules;
    /// omitting this section leaves netfilter untouched (the listener then
    /// accepts only explicitly redirected connections).
    pub capture: Option<CaptureFileConfig>,
}

/// Fully resolved bootstrap settings, with defaults already applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    pub store_socket: PathBuf,
    pub mgmt_socket: PathBuf,
    pub store_wait_ms: u64,
    pub upstream_ca: Option<PathBuf>,
    pub mgmt_max_body: usize,
    pub listen_transparent: SocketAddr,
    pub capture: Option<CaptureFileConfig>,
}

impl Settings {
    pub fn resolve(
        file: FileConfig,
        store_socket: Option<PathBuf>,
        mgmt_socket: Option<PathBuf>,
        store_wait_ms: Option<u64>,
    ) -> Result<Settings> {
        let listen_transparent = match file.listen_transparent {
            Some(value) => parse_listen(&value, "listen_transparent")?,
            None => DEFAULT_LISTEN_TRANSPARENT
                .parse()
                .expect("built-in listen default is a valid address"),
        };
        Ok(Settings {
            store_socket: store_socket
                .or(file.store_socket)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_STORE_SOCKET)),
            mgmt_socket: mgmt_socket
                .or(file.mgmt_socket)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_MGMT_SOCKET)),
            store_wait_ms: store_wait_ms
                .or(file.store_wait_ms)
                .unwrap_or(DEFAULT_STORE_WAIT_MS),
            upstream_ca: file.upstream_ca,
            mgmt_max_body: file.mgmt_max_body.unwrap_or(DEFAULT_MGMT_MAX_BODY),
            listen_transparent,
            capture: file.capture,
        })
    }
}

/// Parses an `ip:port` listener address. Used for the bootstrap listen address
/// and for the daemon's effective listener reported to the management plane.
pub fn parse_listen(value: &str, field: &str) -> Result<SocketAddr> {
    value
        .parse()
        .with_context(|| format!("{field} {value:?}: expected ip:port"))
}

/// Reads the config file.
///
/// `explicit` is the `--config` value. When it is given the file must exist
/// and parse — a typo must not silently fall back to defaults. When it is
/// absent, `default_path` is used only if it exists.
///
/// Returns the file contents and the path that was actually read (for the
/// startup log), so an operator can tell which file is in effect.
pub fn load(explicit: Option<&Path>, default_path: &Path) -> Result<(FileConfig, Option<PathBuf>)> {
    let (path, required) = match explicit {
        Some(path) => (path.to_path_buf(), true),
        None => (default_path.to_path_buf(), false),
    };
    if !required && !path.exists() {
        return Ok((FileConfig::default(), None));
    }
    let bytes =
        std::fs::read(&path).with_context(|| format!("read config file {}", path.display()))?;
    let file = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse config file {}", path.display()))?;
    Ok((file, Some(path)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("credproxyd.json");
        std::fs::write(&path, body).unwrap();
        path
    }

    fn scratch() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn args_beat_file_and_file_beats_defaults() {
        let dir = scratch();
        let path = file(
            dir.path(),
            r#"{"store_socket":"/from/file/store.sock","store_wait_ms":1234,"upstream_ca":"/from/file/ca.pem"}"#,
        );
        let (cfg, used) = load(Some(&path), Path::new("/nonexistent/default.json")).unwrap();
        assert_eq!(used.as_deref(), Some(path.as_path()));
        let s =
            Settings::resolve(cfg, None, Some(PathBuf::from("/from/arg/mgmt.sock")), None).unwrap();
        assert_eq!(s.store_socket, PathBuf::from("/from/file/store.sock"));
        assert_eq!(s.store_wait_ms, 1234);
        assert_eq!(s.mgmt_socket, PathBuf::from("/from/arg/mgmt.sock"));
        assert_eq!(s.upstream_ca, Some(PathBuf::from("/from/file/ca.pem")));
    }

    #[test]
    fn defaults_apply_when_no_source_sets_a_field() {
        let s = Settings::resolve(FileConfig::default(), None, None, None).unwrap();
        assert_eq!(s.store_socket, PathBuf::from(DEFAULT_STORE_SOCKET));
        assert_eq!(s.mgmt_socket, PathBuf::from(DEFAULT_MGMT_SOCKET));
        assert_eq!(s.store_wait_ms, DEFAULT_STORE_WAIT_MS);
        assert_eq!(s.upstream_ca, None);
        assert_eq!(s.mgmt_max_body, DEFAULT_MGMT_MAX_BODY);
        assert_eq!(
            s.listen_transparent,
            DEFAULT_LISTEN_TRANSPARENT.parse().unwrap(),
            "the listener defaults to 0.0.0.0:4100"
        );
        assert_eq!(s.capture, None);
    }

    #[test]
    fn listen_comes_from_the_file() {
        let dir = scratch();
        let path = file(dir.path(), r#"{"listen_transparent":"10.12.0.1:8443"}"#);
        let (cfg, _) = load(Some(&path), Path::new("ignored")).unwrap();
        let s = Settings::resolve(cfg, None, None, None).unwrap();
        assert_eq!(s.listen_transparent, "10.12.0.1:8443".parse().unwrap());
    }

    #[test]
    fn invalid_listen_is_rejected() {
        let dir = scratch();
        for body in [
            r#"{"listen_transparent":"not-an-address"}"#,
            r#"{"listen_transparent":":4100"}"#,
        ] {
            let path = file(dir.path(), body);
            let (cfg, _) = load(Some(&path), Path::new("ignored")).unwrap();
            let err = Settings::resolve(cfg, None, None, None)
                .unwrap_err()
                .to_string();
            assert!(err.contains("expected ip:port"), "{body}: {err}");
        }
    }

    #[test]
    fn capture_section_is_parsed_from_the_file() {
        let dir = scratch();
        let path = file(
            dir.path(),
            r#"{"capture":{"interface":"virbr-cpb","subnet":"192.168.56.0/24","gateway":"192.168.56.1"}}"#,
        );
        let (cfg, _) = load(Some(&path), Path::new("ignored")).unwrap();
        let s = Settings::resolve(cfg, None, None, None).unwrap();
        let capture = s.capture.expect("capture section");
        assert_eq!(capture.interface, "virbr-cpb");
        assert_eq!(capture.subnet, "192.168.56.0/24");
        assert_eq!(capture.gateway, "192.168.56.1");
    }

    #[test]
    fn mgmt_settings_come_from_the_file() {
        let dir = scratch();
        let path = file(
            dir.path(),
            r#"{"mgmt_socket":"/tmp/mgmt.sock","mgmt_max_body":2048}"#,
        );
        let (cfg, _) = load(Some(&path), Path::new("ignored")).unwrap();
        let s = Settings::resolve(cfg, None, None, None).unwrap();
        assert_eq!(s.mgmt_socket, PathBuf::from("/tmp/mgmt.sock"));
        assert_eq!(s.mgmt_max_body, 2048);
    }

    #[test]
    fn removed_mgmt_access_fields_are_rejected() {
        let dir = scratch();
        for body in [
            r#"{"mgmt_uids":[1000]}"#,
            r#"{"mgmt_group":"credproxy-admin"}"#,
            r#"{"mgmt_token_file":"/tmp/token"}"#,
        ] {
            let path = file(dir.path(), body);
            let err = load(Some(&path), Path::new("ignored"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("parse config file"), "{body}: {err}");
        }
    }

    #[test]
    fn missing_default_file_is_not_an_error() {
        let dir = scratch();
        let (cfg, used) = load(None, &dir.path().join("absent.json")).unwrap();
        assert!(used.is_none());
        assert!(cfg.store_socket.is_none());
    }

    #[test]
    fn missing_explicit_file_is_an_error() {
        let dir = scratch();
        let err = load(Some(&dir.path().join("absent.json")), Path::new("ignored"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("read config file"), "{err}");
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let dir = scratch();
        for body in [
            r#"{"listen_http":"127.0.0.1:4100"}"#,
            r#"{"ctl_socket":"/run/credproxy/ctl.sock"}"#,
            r#"{"admin_socket":"/run/credproxy/admin.sock"}"#,
            r#"{"transparent_loopback":"127.0.0.1:4110"}"#,
        ] {
            let path = file(dir.path(), body);
            let err = load(Some(&path), Path::new("ignored"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("parse config file"), "{body}: {err}");
        }
    }

    #[test]
    fn wrong_types_are_rejected() {
        let dir = scratch();
        let path = file(dir.path(), r#"{"store_wait_ms":"soon"}"#);
        assert!(load(Some(&path), Path::new("ignored")).is_err());
    }
}
