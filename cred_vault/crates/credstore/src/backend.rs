//! Backend: the `(path, value)` storage primitive behind the vault front end.
//!
//! v1 ships one active backend: a local file backend. It stores each logical
//! object as a file under `<root>/<namespace>/<name>`, using every path
//! segment verbatim as a file name.
//!
//! Segment rules: `StoragePath::new` accepts only single path components —
//! non-empty, not `.` or `..`, no NUL, no `/`. The layout therefore assumes a
//! case-sensitive file system: `Config` and `config` are different objects,
//! and a segment may use any other printable byte. Names starting with `_`
//! are reserved for backend-internal entries (atomic-write temp files) and
//! never appear in `list`.
//!
//! Atomicity: `write` goes to a same-directory temp file, is fsynced, renamed
//! over the target, and the directory is fsynced before the call returns.

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const MAX_VALUE: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendError {
    InvalidPath,
    AlreadyExists,
    Corrupt,
    TooLarge,
    Unsupported,
    Io,
    Internal,
}

impl BackendError {
    fn from_io(err: &std::io::Error) -> BackendError {
        match err.raw_os_error() {
            Some(libc::EEXIST) => BackendError::AlreadyExists,
            Some(libc::ENOENT) => BackendError::Io,
            Some(libc::EISDIR) => BackendError::InvalidPath,
            Some(libc::ELOOP) => BackendError::Corrupt,
            _ => BackendError::Io,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoragePath(Vec<Vec<u8>>);

impl StoragePath {
    /// v1 uses one segment for a namespace directory and two for an object;
    /// deeper paths are not part of the contract yet.
    pub fn new(segments: Vec<Vec<u8>>) -> Result<StoragePath, BackendError> {
        if segments.is_empty() || segments.len() > 2 {
            return Err(BackendError::InvalidPath);
        }
        for seg in &segments {
            if seg.is_empty()
                || seg == b"."
                || seg == b".."
                || seg.contains(&0)
                || seg.contains(&b'/')
            {
                return Err(BackendError::InvalidPath);
            }
        }
        Ok(StoragePath(segments))
    }

    pub fn segments(&self) -> &[Vec<u8>] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    pub kind: FileKind,
    pub size: Option<u64>,
    pub modified: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteOutcome {
    Deleted,
    NotFound,
}

pub trait Backend: Send + Sync {
    fn read(&self, path: &StoragePath) -> Result<Option<Vec<u8>>, BackendError>;
    fn write(&self, path: &StoragePath, value: &[u8]) -> Result<(), BackendError>;
    fn delete(&self, path: &StoragePath) -> Result<DeleteOutcome, BackendError>;
    fn list(&self, dir: &StoragePath) -> Result<Vec<Vec<u8>>, BackendError>;
    fn stat(&self, path: &StoragePath) -> Result<Option<FileStat>, BackendError>;
}

pub struct FileBackend {
    root: PathBuf,
    tmp_counter: AtomicU64,
}

impl FileBackend {
    /// Opens (creating if needed) the data directory and checks its owner and
    /// mode: the directory must be owned by the current euid and must not be
    /// group- or world-accessible.
    pub fn open(root: impl Into<PathBuf>) -> std::io::Result<FileBackend> {
        let root = root.into();
        if !root.exists() {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&root)?;
        }
        let md = fs::metadata(&root)?;
        if !md.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{}: not a directory", root.display()),
            ));
        }
        let euid = unsafe { libc::geteuid() };
        if md.uid() != euid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{}: owner uid {} is not the vault uid {}",
                    root.display(),
                    md.uid(),
                    euid
                ),
            ));
        }
        if md.mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{}: mode {:o} is group/world accessible; expected 0700",
                    root.display(),
                    md.mode() & 0o7777
                ),
            ));
        }
        Ok(FileBackend {
            root,
            tmp_counter: AtomicU64::new(0),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn resolve(&self, path: &StoragePath) -> PathBuf {
        let mut out = self.root.clone();
        for seg in path.segments() {
            out.push(OsStr::from_bytes(seg));
        }
        out
    }

    fn namespace_dir(&self, path: &StoragePath) -> PathBuf {
        let mut out = self.root.clone();
        out.push(OsStr::from_bytes(&path.segments()[0]));
        out
    }

    fn ensure_parent(&self, path: &Path) -> Result<(), BackendError> {
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)
                    .map_err(|e| BackendError::from_io(&e))?;
            }
        }
        Ok(())
    }

    fn fsync_dir(&self, dir: &Path) -> Result<(), BackendError> {
        let f = File::open(dir).map_err(|e| BackendError::from_io(&e))?;
        f.sync_all().map_err(|e| BackendError::from_io(&e))
    }

    fn write_file(&self, path: &Path, value: &[u8]) -> Result<(), BackendError> {
        if value.len() > MAX_VALUE {
            return Err(BackendError::TooLarge);
        }
        self.ensure_parent(path)?;
        let dir = path.parent().ok_or(BackendError::InvalidPath)?;
        let n = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
        let tmp = dir.join(format!("_tmp.{}.{}", std::process::id(), n));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)?;
            file.write_all(value)?;
            file.sync_all()?;
            fs::rename(&tmp, path)?;
            Ok::<(), std::io::Error>(())
        })();
        match result {
            Ok(()) => self.fsync_dir(dir),
            Err(e) => {
                let _ = fs::remove_file(&tmp);
                Err(BackendError::from_io(&e))
            }
        }
    }
}

/// Checks that `path` is a data directory owned by the current euid with mode
/// `0700`. Used by the binary before it starts serving.
pub fn check_data_dir(path: &Path) -> std::io::Result<()> {
    let md = fs::metadata(path)?;
    let euid = unsafe { libc::geteuid() };
    if !md.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{}: not a directory", path.display()),
        ));
    }
    if md.uid() != euid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{}: owner uid {} != euid {}",
                path.display(),
                md.uid(),
                euid
            ),
        ));
    }
    if md.mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{}: mode {:o} is group/world accessible; expected 0700",
                path.display(),
                md.mode() & 0o7777
            ),
        ));
    }
    Ok(())
}

impl Backend for FileBackend {
    fn read(&self, path: &StoragePath) -> Result<Option<Vec<u8>>, BackendError> {
        let file_path = self.resolve(path);
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&file_path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(BackendError::from_io(&e)),
        };
        if file
            .metadata()
            .map_err(|e| BackendError::from_io(&e))?
            .is_dir()
        {
            return Err(BackendError::InvalidPath);
        }
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .map_err(|e| BackendError::from_io(&e))?;
        if buf.len() > MAX_VALUE {
            return Err(BackendError::TooLarge);
        }
        Ok(Some(buf))
    }

    fn write(&self, path: &StoragePath, value: &[u8]) -> Result<(), BackendError> {
        let file_path = self.resolve(path);
        self.write_file(&file_path, value)
    }

    fn delete(&self, path: &StoragePath) -> Result<DeleteOutcome, BackendError> {
        let file_path = self.resolve(path);
        match fs::remove_file(&file_path) {
            Ok(()) => {
                if let Some(dir) = file_path.parent() {
                    self.fsync_dir(dir)?;
                }
                Ok(DeleteOutcome::Deleted)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DeleteOutcome::NotFound),
            Err(e) => Err(BackendError::from_io(&e)),
        }
    }

    fn list(&self, dir: &StoragePath) -> Result<Vec<Vec<u8>>, BackendError> {
        let dir_path = self.namespace_dir(dir);
        let md = match fs::metadata(&dir_path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(BackendError::from_io(&e)),
        };
        if !md.is_dir() {
            return Err(BackendError::InvalidPath);
        }
        let mut names = Vec::new();
        let entries = fs::read_dir(&dir_path).map_err(|e| BackendError::from_io(&e))?;
        for entry in entries {
            let entry = entry.map_err(|e| BackendError::from_io(&e))?;
            let os = entry.file_name();
            let raw = os.as_bytes();
            // `_`-prefixed names are backend-internal (atomic-write temp
            // files); logical names never start with `_`.
            if raw.first() == Some(&b'_') {
                continue;
            }
            names.push(raw.to_vec());
        }
        Ok(names)
    }

    fn stat(&self, path: &StoragePath) -> Result<Option<FileStat>, BackendError> {
        let file_path = self.resolve(path);
        let md = match fs::symlink_metadata(&file_path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(BackendError::from_io(&e)),
        };
        let ft = md.file_type();
        if ft.is_symlink() {
            return Err(BackendError::Corrupt);
        }
        let kind = if ft.is_dir() {
            FileKind::Dir
        } else {
            FileKind::File
        };
        let size = match kind {
            FileKind::File => Some(md.len()),
            FileKind::Dir => None,
        };
        let modified = md.mtime();
        Ok(Some(FileStat {
            kind,
            size,
            modified: Some(modified),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(segments: &[&[u8]]) -> StoragePath {
        StoragePath::new(segments.iter().map(|s| s.to_vec()).collect()).unwrap()
    }

    #[test]
    fn segments_are_used_verbatim() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::open(crate::testutil::make_root(dir.path())).unwrap();
        let p = path(&[b"data", b"keystore.openai-prod"]);
        backend.write(&p, b"x").unwrap();
        assert!(backend
            .root()
            .join("data")
            .join("keystore.openai-prod")
            .is_file());
        assert_eq!(
            backend.list(&path(&[b"data"])).unwrap(),
            vec![b"keystore.openai-prod".to_vec()]
        );
    }

    #[test]
    fn rejects_bad_segments() {
        assert_eq!(StoragePath::new(vec![]), Err(BackendError::InvalidPath));
        assert_eq!(
            StoragePath::new(vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]),
            Err(BackendError::InvalidPath)
        );
        assert_eq!(
            StoragePath::new(vec![b"..".to_vec()]),
            Err(BackendError::InvalidPath)
        );
        assert_eq!(
            StoragePath::new(vec![b"a\0b".to_vec()]),
            Err(BackendError::InvalidPath)
        );
        assert_eq!(
            StoragePath::new(vec![b"a/b".to_vec()]),
            Err(BackendError::InvalidPath)
        );
    }

    #[test]
    fn list_skips_backend_internal_names() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::open(crate::testutil::make_root(dir.path())).unwrap();
        backend.write(&path(&[b"data", b"config"]), b"x").unwrap();
        // A leftover atomic-write temp file is not a logical object.
        fs::write(backend.root().join("data").join("_tmp.1.2"), b"partial").unwrap();
        assert_eq!(
            backend.list(&path(&[b"data"])).unwrap(),
            vec![b"config".to_vec()]
        );
    }

    #[test]
    fn roundtrip_write_read_delete_list() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::open(crate::testutil::make_root(dir.path())).unwrap();
        let p = path(&[b"data", b"config"]);
        assert_eq!(backend.read(&p).unwrap(), None);
        backend.write(&p, b"hello").unwrap();
        assert_eq!(backend.read(&p).unwrap(), Some(b"hello".to_vec()));
        backend.write(&p, b"replaced").unwrap();
        assert_eq!(backend.read(&p).unwrap(), Some(b"replaced".to_vec()));
        let names = backend.list(&path(&[b"data"])).unwrap();
        assert_eq!(names, vec![b"config".to_vec()]);
        assert_eq!(backend.delete(&p).unwrap(), DeleteOutcome::Deleted);
        assert_eq!(backend.delete(&p).unwrap(), DeleteOutcome::NotFound);
        assert_eq!(backend.read(&p).unwrap(), None);
        assert!(backend.list(&path(&[b"data"])).unwrap().is_empty());
    }

    #[test]
    fn rejects_world_readable_root() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("vault");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(FileBackend::open(&root).is_err());
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(FileBackend::open(&root).is_ok());
    }

    #[test]
    fn files_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::open(crate::testutil::make_root(dir.path())).unwrap();
        let p = path(&[b"data", b"config"]);
        backend.write(&p, b"x").unwrap();
        let md = fs::metadata(backend.resolve(&p)).unwrap();
        assert_eq!(md.mode() & 0o777, 0o600);
    }

    #[test]
    fn stat_reports_kind_and_size() {
        let dir = tempfile::tempdir().unwrap();
        let backend = FileBackend::open(crate::testutil::make_root(dir.path())).unwrap();
        let p = path(&[b"data", b"config"]);
        assert_eq!(backend.stat(&p).unwrap(), None);
        backend.write(&p, b"12345").unwrap();
        let st = backend.stat(&p).unwrap().unwrap();
        assert_eq!(st.kind, FileKind::File);
        assert_eq!(st.size, Some(5));
    }
}
