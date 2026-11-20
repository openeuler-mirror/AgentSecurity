//! credstore — credential vault (storage + record-level release condition).
//!
//! Implementation of the vault's logical interface (namespace operations and
//! statuses), the record model and the backend contract; `ipc.rs` carries the
//! AF_UNIX wire protocol. The vault is a separate process that shares nothing
//! but sockets with `credproxyd`.
//!
//! The vault does not interpret `data` objects and does not parse business
//! JSON: the only value it decodes is its own record envelope (`record.rs`). It
//! does not substitute credentials, does not evaluate policy and does not open
//! network connections.

pub mod backend;
pub mod ipc;
pub mod record;
pub mod server;
pub mod store;

pub use ipc::Status;

#[cfg(test)]
pub mod testutil {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    /// Creates a 0700 vault root under `parent` (tempdirs themselves are not
    /// necessarily private, and the backend refuses anything else).
    pub fn make_root(parent: &Path) -> PathBuf {
        let root = parent.join("vault");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }
}
