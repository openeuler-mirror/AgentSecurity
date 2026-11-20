//! Host matching for `allowed_hosts`.
//!
//! Each entry is a domain or an IP literal. No port, scheme, path or wildcard
//! is accepted. Domains are case-insensitive and ignore one trailing dot; IP
//! literals match exactly.

use std::net::IpAddr;

use anyhow::{bail, Context, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    /// Normalized domain, or the canonical text of an IP literal.
    pub host: String,
    /// Present when the entry is an IP literal.
    pub ip: Option<IpAddr>,
}

impl HostPattern {
    pub fn parse(entry: &str) -> Result<Self> {
        if entry.is_empty() {
            bail!("allowed_hosts entry is empty");
        }
        if entry.contains('*') {
            bail!("allowed_hosts entry {entry:?} must not contain a wildcard");
        }
        if entry.contains('/') || entry.contains('?') || entry.contains('#') {
            bail!("allowed_hosts entry {entry:?} must be a bare host");
        }
        if entry.contains(char::is_whitespace) {
            bail!("allowed_hosts entry {entry:?} contains whitespace");
        }

        // A bracketed IPv6 literal is accepted as a convenience, but the
        // stored form is the unbracketed address.
        let raw = if entry.starts_with('[') && entry.ends_with(']') {
            &entry[1..entry.len() - 1]
        } else {
            entry
        };
        if let Ok(ip) = raw.parse::<IpAddr>() {
            return Ok(HostPattern {
                host: ip.to_string(),
                ip: Some(ip),
            });
        }
        if raw.contains(':') {
            bail!("allowed_hosts entry {entry:?} is not a valid IP literal");
        }

        let host = raw.trim_end_matches('.').to_ascii_lowercase();
        validate_domain(&host).with_context(|| format!("allowed_hosts entry {entry:?}"))?;
        Ok(HostPattern { host, ip: None })
    }

    pub fn matches(&self, host: &str) -> bool {
        let host = normalize_host(host);
        if let Some(ip) = self.ip {
            return host
                .parse::<IpAddr>()
                .is_ok_and(|candidate| candidate == ip);
        }
        host == self.host
    }
}

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = if host.starts_with('[') && host.ends_with(']') {
        &host[1..host.len() - 1]
    } else {
        host
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn validate_domain(host: &str) -> Result<()> {
    if host.is_empty() {
        bail!("empty domain");
    }
    if host.len() > 253 {
        bail!("domain is over 253 characters");
    }
    for label in host.split('.') {
        if label.is_empty() {
            bail!("empty domain label");
        }
        if label.len() > 63 {
            bail!("domain label is over 63 characters");
        }
        if label.starts_with('-') || label.ends_with('-') {
            bail!("domain label {label:?} starts or ends with '-'");
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            bail!("domain label {label:?} has characters outside [a-z0-9-]");
        }
    }
    Ok(())
}

pub fn parse_hosts(entries: &[String]) -> Result<Vec<HostPattern>> {
    entries
        .iter()
        .map(|e| HostPattern::parse(e))
        .collect::<Result<Vec<_>>>()
}

pub fn matches_any(patterns: &[HostPattern], host: &str) -> bool {
    patterns.iter().any(|p| p.matches(host))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_and_ip_matching() {
        let p = HostPattern::parse("api.example.com").unwrap();
        assert!(p.matches("api.example.com"));
        assert!(p.matches("API.example.com."));
        assert!(!p.matches("evil.example.com"));

        let ip = HostPattern::parse("127.0.0.1").unwrap();
        assert!(ip.matches("127.0.0.1"));
        assert!(!ip.matches("127.0.0.2"));

        let v6 = HostPattern::parse("[::1]").unwrap();
        assert!(v6.matches("::1"));
        assert!(v6.matches("[::1]"));
    }

    #[test]
    fn rejects_ports_wildcards_and_paths() {
        for entry in [
            "api.example.com:443",
            "*.example.com",
            "*",
            "api.example.com/v1",
            "a/*.example.com",
            "api example.com",
            "",
        ] {
            assert!(HostPattern::parse(entry).is_err(), "{entry}");
        }
    }

    #[test]
    fn matches_any_over_set() {
        let patterns =
            parse_hosts(&["api.deepseek.com".to_string(), "10.0.0.5".to_string()]).unwrap();
        assert!(matches_any(&patterns, "api.deepseek.com"));
        assert!(matches_any(&patterns, "10.0.0.5"));
        assert!(!matches_any(&patterns, "other.example.com"));
    }
}
