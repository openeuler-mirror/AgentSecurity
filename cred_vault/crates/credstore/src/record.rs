//! Validation for `data` objects.
//!
//! The vault no longer stores credential records: real values live inline in
//! `data/keystore.<binding>` objects, which arrive through `DataPut` like any
//! other data object. Only the `data` name/content validation lives here.

use crate::ipc::Status;

pub const DATA_NAME_MAX: usize = 128;
pub const DATA_CONTENT_MAX: usize = 4 * 1024 * 1024;

/// `data` name: 1–128 printable ASCII bytes, no `/` or `\`, not `.` / `..`,
/// no leading/trailing space, not starting with `_` (reserved).
pub fn validate_data_name(name: &[u8]) -> bool {
    if name.is_empty() || name.len() > DATA_NAME_MAX {
        return false;
    }
    if name.iter().any(|b| !(0x20..=0x7e).contains(b)) {
        return false;
    }
    if name.contains(&b'/') || name.contains(&b'\\') {
        return false;
    }
    if name == b"." || name == b".." {
        return false;
    }
    if name.first() == Some(&b' ') || name.last() == Some(&b' ') {
        return false;
    }
    if name.first() == Some(&b'_') {
        return false;
    }
    true
}

pub fn validate_data_content(content: &[u8]) -> Result<(), Status> {
    if content.len() > DATA_CONTENT_MAX {
        return Err(Status::TooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_name_validation() {
        assert!(validate_data_name(b"config"));
        assert!(validate_data_name(b"keystore.openai-prod"));
        assert!(!validate_data_name(b""));
        assert!(!validate_data_name(b"_internal"));
        assert!(!validate_data_name(b"a/b"));
        assert!(!validate_data_name(b"a\\b"));
        assert!(!validate_data_name(b"."));
        assert!(!validate_data_name(b".."));
        assert!(!validate_data_name(b" leading"));
        assert!(!validate_data_name(b"trailing "));
        assert!(!validate_data_name(&[b'a'; DATA_NAME_MAX + 1]));
        assert!(!validate_data_name(b"tab\tname"));
    }
}
