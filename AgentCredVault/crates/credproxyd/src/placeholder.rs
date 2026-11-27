//! fakecred shape.
//!
//! A fakecred is `fcred-` followed by 32 lowercase hex characters (38 bytes),
//! generated from a UUIDv7. It is used in its raw form everywhere: as the
//! stored object key (`data/<fake_cred>`), the API identifier, the audit
//! field and the agent-side value.

use uuid::Uuid;

/// Fixed prefix of every fakecred.
pub const PREFIX: &str = "fcred-";
/// Random part: 32 lowercase hex characters.
pub const RANDOM_LEN: usize = 32;
/// Full fakecred: prefix plus random part.
pub const KEY_LEN: usize = PREFIX.len() + RANDOM_LEN;

/// Anchors used for header discovery and leak scanning.
pub const DISCOVERY_ANCHORS: [&str; 1] = ["fcred-"];

/// `fcred-` followed by exactly 32 lowercase hex characters.
pub fn valid_key(s: &str) -> bool {
    s.len() == KEY_LEN
        && s.starts_with(PREFIX)
        && s[PREFIX.len()..]
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// `fcred-` plus the 32 lowercase hex characters of a UUIDv7.
///
/// UUIDv7 carries a millisecond timestamp in its first 48 bits, so keys
/// generated in different milliseconds are always distinct; same-millisecond
/// keys are separated by the remaining random bits (and, within one process,
/// by the crate's monotonic counter).
pub fn generate_key() -> String {
    let mut out = String::with_capacity(KEY_LEN);
    out.push_str(PREFIX);
    out.push_str(&Uuid::now_v7().simple().to_string());
    out
}

pub fn contains_anchor(value: &str) -> bool {
    DISCOVERY_ANCHORS.iter().any(|a| value.contains(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_shape_and_uniqueness() {
        let a = generate_key();
        let b = generate_key();
        assert_eq!(a.len(), KEY_LEN);
        assert!(a.starts_with(PREFIX));
        assert!(valid_key(&a));
        assert!(a[PREFIX.len()..]
            .bytes()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert_ne!(a, b);
    }

    #[test]
    fn random_part_is_a_uuid_v7() {
        let key = generate_key();
        let parsed = Uuid::parse_str(&key[PREFIX.len()..]).expect("UUID text");
        assert_eq!(parsed.get_version_num(), 7);
    }

    #[test]
    fn validation_is_lowercase_hex_only() {
        assert!(valid_key("fcred-0123456789abcdef0123456789abcdef"));
        assert!(!valid_key("0123456789abcdef0123456789abcdef"));
        assert!(!valid_key("fcred-0123456789ABCDEF0123456789abcdef"));
        assert!(!valid_key("fcred-0123456789abcdef"));
        assert!(contains_anchor("fcred-0123456789abcdef0123456789abcdef"));
        assert!(!contains_anchor("sk-plain"));
    }
}
