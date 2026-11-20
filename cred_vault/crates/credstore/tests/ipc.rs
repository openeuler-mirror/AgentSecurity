//! End-to-end IPC tests against a real `credstore` server on a temp socket.
//!
//! These exercise the wire protocol rather than the
//! in-process store API: framing, opcodes, status codes, error handling and
//! the peer-uid gate.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use credstore::backend::FileBackend;
use credstore::ipc::{
    Header, Status, HEADER_LEN, MAGIC, MSG_REQUEST, OP_DATA_DELETE, OP_DATA_GET, OP_DATA_LIST,
    OP_DATA_PUT, VERSION,
};
use credstore::server::{self, ServerConfig};
use credstore::store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

struct Harness {
    _dir: tempfile::TempDir,
    sock: PathBuf,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

/// Creates a test scratch directory. `CREDPROXY_TEST_KEEP=1` keeps it on disk
/// after the test (vault files, sockets, logs) instead of deleting it on drop.
fn scratch(prefix: &str) -> tempfile::TempDir {
    let keep = std::env::var_os("CREDPROXY_TEST_KEEP").is_some();
    let mut builder = tempfile::Builder::new();
    builder.prefix(prefix).disable_cleanup(keep);
    let dir = builder.tempdir().unwrap();
    if keep {
        eprintln!("kept test dir: {}", dir.path().display());
    }
    dir
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn start_with_uid(allow_uid: Option<u32>) -> Harness {
    let dir = scratch("credstore-test");
    let root = dir.path().join("vault");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock = dir.path().join("store.sock");
    let store = Arc::new(Store::new(FileBackend::open(&root).unwrap()));
    let cfg = ServerConfig {
        socket: sock.clone(),
        allow_uid,
        max_connections: 16,
    };
    let task = tokio::spawn(server::run(store, cfg));
    for _ in 0..200 {
        if sock.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Harness {
        _dir: dir,
        sock,
        task,
    }
}

async fn start() -> Harness {
    start_with_uid(None).await
}

fn frame(opcode: u8, request_id: u64, payload: &[u8]) -> Vec<u8> {
    let header = Header {
        msg_type: MSG_REQUEST,
        opcode,
        request_id,
        payload_len: payload.len() as u32,
    };
    let mut out = header.encode().to_vec();
    out.extend_from_slice(payload);
    out
}

async fn call(sock: &PathBuf, opcode: u8, payload: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = UnixStream::connect(sock).await.unwrap();
    stream.write_all(&frame(opcode, 7, payload)).await.unwrap();
    let (status, body) = read_response(&mut stream).await;
    (status, body)
}

async fn read_response(stream: &mut UnixStream) -> (u16, Vec<u8>) {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0..4], MAGIC);
    assert_eq!(u16::from_le_bytes([header[4], header[5]]), VERSION);
    assert_eq!(header[6], 1, "response msg_type");
    let payload_len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let mut payload = vec![0u8; payload_len as usize];
    stream.read_exact(&mut payload).await.unwrap();
    let status = u16::from_le_bytes([payload[0], payload[1]]);
    (status, payload)
}

fn data_put_payload(name: &[u8], content: &[u8]) -> Vec<u8> {
    let mut out = (name.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(name);
    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
    out.extend_from_slice(content);
    out
}

fn data_name_payload(name: &[u8]) -> Vec<u8> {
    let mut out = (name.len() as u16).to_le_bytes().to_vec();
    out.extend_from_slice(name);
    out
}

#[tokio::test(flavor = "multi_thread")]
async fn retired_credential_opcodes_are_unsupported() {
    let h = start().await;
    for opcode in 1..=4 {
        let (st, _) = call(&h.sock, opcode, b"").await;
        assert_eq!(st, Status::Unsupported.code(), "opcode {opcode}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn data_lifecycle() {
    let h = start().await;
    let (st, _) = call(&h.sock, OP_DATA_PUT, &data_put_payload(b"config", b"{}")).await;
    assert_eq!(st, Status::Ok.code());
    let (st, body) = call(&h.sock, OP_DATA_GET, &data_name_payload(b"config")).await;
    assert_eq!(st, Status::Ok.code());
    let len = u32::from_le_bytes(body[2..6].try_into().unwrap()) as usize;
    assert_eq!(&body[6..6 + len], b"{}");
    let (st, body) = call(&h.sock, OP_DATA_LIST, &[]).await;
    assert_eq!(st, Status::Ok.code());
    assert_eq!(&body[2..6], &1u32.to_le_bytes());
    let name_len = u16::from_le_bytes(body[6..8].try_into().unwrap()) as usize;
    assert_eq!(&body[8..8 + name_len], b"config");
    let (st, _) = call(&h.sock, OP_DATA_DELETE, &data_name_payload(b"config")).await;
    assert_eq!(st, Status::Ok.code());
    let (st, _) = call(&h.sock, OP_DATA_GET, &data_name_payload(b"config")).await;
    assert_eq!(st, Status::NotFound.code());
}

#[tokio::test(flavor = "multi_thread")]
async fn reserved_data_name_is_rejected() {
    let h = start().await;
    let (st, _) = call(&h.sock, OP_DATA_PUT, &data_put_payload(b"_internal", b"x")).await;
    assert_eq!(st, Status::InvalidArgument.code());
}

#[tokio::test(flavor = "multi_thread")]
async fn protocol_errors_close_the_connection() {
    let h = start().await;

    // Unknown opcode -> UNSUPPORTED, then close.
    let (st, _) = call(&h.sock, 99, b"").await;
    assert_eq!(st, Status::Unsupported.code());

    // Version mismatch -> UNSUPPORTED.
    let mut stream = UnixStream::connect(&h.sock).await.unwrap();
    let mut f = frame(OP_DATA_LIST, 1, b"");
    f[4..6].copy_from_slice(&2u16.to_le_bytes());
    stream.write_all(&f).await.unwrap();
    let (st, _) = read_response(&mut stream).await;
    assert_eq!(st, Status::Unsupported.code());

    // Response msg_type sent to the server -> INVALID_ARGUMENT.
    let mut stream = UnixStream::connect(&h.sock).await.unwrap();
    let mut f = frame(OP_DATA_LIST, 1, b"");
    f[6] = 1;
    stream.write_all(&f).await.unwrap();
    let (st, _) = read_response(&mut stream).await;
    assert_eq!(st, Status::InvalidArgument.code());

    // Oversized payload_len -> TOO_LARGE without sending a payload.
    let mut stream = UnixStream::connect(&h.sock).await.unwrap();
    let header = Header {
        msg_type: MSG_REQUEST,
        opcode: OP_DATA_LIST,
        request_id: 1,
        payload_len: 8 * 1024 * 1024 + 1,
    };
    stream.write_all(&header.encode()).await.unwrap();
    let (st, _) = read_response(&mut stream).await;
    assert_eq!(st, Status::TooLarge.code());

    // Trailing bytes in a request payload -> INVALID_ARGUMENT.
    let mut payload = data_name_payload(b"config");
    payload.push(0);
    let (st, _) = call(&h.sock, OP_DATA_GET, &payload).await;
    assert_eq!(st, Status::InvalidArgument.code());

    // Bad magic: connection is closed without a response.
    let mut stream = UnixStream::connect(&h.sock).await.unwrap();
    let mut f = frame(OP_DATA_LIST, 1, b"");
    f[0..4].copy_from_slice(b"XXXX");
    stream.write_all(&f).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .expect("server closes")
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn request_id_is_echoed() {
    let h = start().await;
    let mut stream = UnixStream::connect(&h.sock).await.unwrap();
    let f = frame(OP_DATA_LIST, 0x1122_3344_5566_7788, b"");
    stream.write_all(&f).await.unwrap();
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header).await.unwrap();
    let id = u64::from_le_bytes(header[8..16].try_into().unwrap());
    assert_eq!(id, 0x1122_3344_5566_7788);
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_uid_mismatch_is_rejected() {
    let me = unsafe { libc::geteuid() };
    let h = start_with_uid(Some(me.wrapping_add(1))).await;
    let mut stream = UnixStream::connect(&h.sock).await.unwrap();
    // The server closes the connection without reading; the write may fail
    // with EPIPE, and closing an AF_UNIX socket that still holds unread data
    // may surface as EOF or as ECONNRESET depending on timing. All three mean
    // "no response".
    if stream.write_all(&frame(OP_DATA_LIST, 1, b"")).await.is_ok() {
        let mut buf = [0u8; 1];
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("rejected peer received {n} bytes"),
            Err(_) => panic!("rejected peer is not closed within 5s"),
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn missing_data_and_malformed_name() {
    let h = start().await;
    let (st, _) = call(&h.sock, OP_DATA_DELETE, &data_name_payload(b"missing")).await;
    assert_eq!(st, Status::NotFound.code());
    // A name longer than the wire field allows cannot be encoded; send a
    // truncated name payload instead to exercise the parser's length check.
    let mut payload = (credstore::record::DATA_NAME_MAX as u16 + 1)
        .to_le_bytes()
        .to_vec();
    payload.push(0);
    let (st, _) = call(&h.sock, OP_DATA_GET, &payload).await;
    assert_eq!(st, Status::InvalidArgument.code());
}

/// Project test policy: integration tests run against the normal (release)
/// build; the dev profile is for unit tests only.
#[test]
fn integration_tests_run_on_the_normal_build() {
    if cfg!(debug_assertions) {
        panic!(
            "integration tests must run with --release (normal build); \
             run unit tests with `cargo test --lib` instead"
        );
    }
}
