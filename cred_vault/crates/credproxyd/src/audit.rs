//! Audit line format. Values only: never header values, bodies or real
//! secrets. Fields are `key=value`; characters that would break the line are
//! percent-encoded.

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy)]
pub struct Audit<'a> {
    pub ingress: &'a str,
    pub user_id: &'a str,
    pub user_name: &'a str,
    pub name: &'a str,
    pub fake_cred: &'a str,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub decision: &'a str,
}

pub fn emit(a: &Audit<'_>) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    eprintln!(
        "audit ts={ts} ingress={} user_id={} user_name={} name={} fake_cred={} host={} \
         method={} path={} status={} decision={}",
        encode(a.ingress),
        encode(a.user_id),
        encode(a.user_name),
        encode(a.name),
        encode(a.fake_cred),
        encode(a.host),
        encode(a.method),
        encode(a.path),
        a.status,
        encode(a.decision)
    );
}

fn encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_graphic() && b != b'=' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    if out.is_empty() {
        out.push('-');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_unsafe_bytes() {
        assert_eq!(encode("a b"), "a%20b");
        assert_eq!(encode("a=b"), "a%3Db");
        assert_eq!(encode(""), "-");
        assert_eq!(encode("/v1/chat"), "/v1/chat");
        assert_eq!(encode("api.example.com"), "api.example.com");
    }
}
