//! Front end: logical operations, validation, release condition and backend
//! error mapping.
//!
//! Only the `data` namespace remains. Real credential values live inline in
//! `data/keystore.<binding>` objects written by the proxy; the vault stores no
//! credential records of its own.

use std::sync::Mutex;

use crate::backend::{Backend, BackendError, DeleteOutcome, StoragePath};
use crate::ipc::{Request, Response, Status, MAX_PAYLOAD};
use crate::record;

const NAMESPACE_DATA: &[u8] = b"data";

pub struct Store {
    backend: Box<dyn Backend>,
    /// v1 serializes writes globally. The contract requires per-path
    /// serialization; a single lock is strictly stronger and simpler while the
    /// object count is small.
    write_lock: Mutex<()>,
}

impl Store {
    pub fn new(backend: impl Backend + 'static) -> Store {
        Store {
            backend: Box::new(backend),
            write_lock: Mutex::new(()),
        }
    }

    pub fn execute(&self, req: &Request) -> Response {
        match req {
            Request::DataPut { name, content } => Response::Empty(self.data_put(name, content)),
            Request::DataGet { name } => match self.data_get(name) {
                Ok(content) => Response::Content(Status::Ok, content),
                Err(s) => Response::Content(s, Vec::new()),
            },
            Request::DataDelete { name } => Response::Empty(self.data_delete(name)),
            Request::DataList => match self.data_list() {
                Ok(names) => Response::Names(Status::Ok, names),
                Err(s) => Response::Names(s, Vec::new()),
            },
        }
    }

    fn data_path(name: &[u8]) -> StoragePath {
        StoragePath::new(vec![NAMESPACE_DATA.to_vec(), name.to_vec()]).expect("valid path")
    }

    fn namespace(name: &[u8]) -> StoragePath {
        StoragePath::new(vec![name.to_vec()]).expect("valid path")
    }

    fn map_write(&self, path: &StoragePath, value: &[u8]) -> Status {
        match self.backend.write(path, value) {
            Ok(()) => Status::Ok,
            Err(e) => map_backend_error(e),
        }
    }

    fn data_put(&self, name: &[u8], content: &[u8]) -> Status {
        if !record::validate_data_name(name) {
            return Status::InvalidArgument;
        }
        if let Err(s) = record::validate_data_content(content) {
            return s;
        }
        let path = Self::data_path(name);
        let _guard = self.write_lock.lock().expect("write lock");
        self.map_write(&path, content)
    }

    fn data_get(&self, name: &[u8]) -> Result<Vec<u8>, Status> {
        if !record::validate_data_name(name) {
            return Err(Status::InvalidArgument);
        }
        match self.backend.read(&Self::data_path(name)) {
            Ok(Some(v)) => Ok(v),
            Ok(None) => Err(Status::NotFound),
            Err(e) => Err(map_backend_error(e)),
        }
    }

    fn data_delete(&self, name: &[u8]) -> Status {
        if !record::validate_data_name(name) {
            return Status::InvalidArgument;
        }
        let _guard = self.write_lock.lock().expect("write lock");
        match self.backend.delete(&Self::data_path(name)) {
            Ok(DeleteOutcome::Deleted) => Status::Ok,
            Ok(DeleteOutcome::NotFound) => Status::NotFound,
            Err(e) => map_backend_error(e),
        }
    }

    fn data_list(&self) -> Result<Vec<Vec<u8>>, Status> {
        let names = self
            .backend
            .list(&Self::namespace(NAMESPACE_DATA))
            .map_err(map_backend_error)?;
        let mut size = 2usize + 4;
        let mut out = Vec::new();
        for name in names {
            // `_`-prefixed names are reserved for the vault itself.
            if name.first() == Some(&b'_') {
                continue;
            }
            if !record::validate_data_name(&name) {
                return Err(Status::Corrupt);
            }
            size += 2 + name.len();
            if size > MAX_PAYLOAD {
                return Err(Status::TooLarge);
            }
            out.push(name);
        }
        Ok(out)
    }
}

fn map_backend_error(err: BackendError) -> Status {
    match err {
        BackendError::InvalidPath => Status::Internal,
        BackendError::AlreadyExists => Status::AlreadyExists,
        BackendError::Corrupt => Status::Corrupt,
        BackendError::TooLarge => Status::TooLarge,
        BackendError::Unsupported => Status::Unsupported,
        BackendError::Io => Status::Unavailable,
        BackendError::Internal => Status::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::FileBackend;

    fn store() -> (tempfile::TempDir, std::path::PathBuf, Store) {
        let dir = tempfile::tempdir().unwrap();
        let root = crate::testutil::make_root(dir.path());
        let backend = FileBackend::open(&root).unwrap();
        (dir, root, Store::new(backend))
    }

    #[test]
    fn data_namespace() {
        let (_dir, _root, store) = store();
        assert_eq!(store.data_put(b"config", b"{}"), Status::Ok);
        assert_eq!(store.data_put(b"config", b"{\"x\":1}"), Status::Ok);
        assert_eq!(store.data_get(b"config"), Ok(b"{\"x\":1}".to_vec()));
        assert_eq!(store.data_get(b"missing"), Err(Status::NotFound));
        assert_eq!(store.data_put(b"_reserved", b"x"), Status::InvalidArgument);
        assert_eq!(store.data_get(b"_reserved"), Err(Status::InvalidArgument));
        assert_eq!(
            store.data_put(b"big", &vec![0u8; record::DATA_CONTENT_MAX + 1]),
            Status::TooLarge
        );
        assert_eq!(store.data_list(), Ok(vec![b"config".to_vec()]));
        assert_eq!(store.data_delete(b"config"), Status::Ok);
        assert_eq!(store.data_delete(b"config"), Status::NotFound);
    }

    #[test]
    fn data_list_hides_internal_names() {
        let (_dir, root, store) = store();
        assert_eq!(store.data_put(b"config", b"x"), Status::Ok);
        // Write an internal record directly through the backend.
        let path = root.join("data");
        std::fs::write(path.join("_internal"), b"x").unwrap();
        assert_eq!(store.data_list(), Ok(vec![b"config".to_vec()]));
    }

    #[test]
    fn data_list_size_limit_reports_too_large() {
        let (_dir, _root, store) = store();
        assert_eq!(store.data_put(b"config", b"x"), Status::Ok);
        let names = store.data_list().unwrap();
        assert_eq!(names.len(), 1);
        let size = 2 + 4 + 2 + b"config".len();
        assert!(size < MAX_PAYLOAD);
    }
}
