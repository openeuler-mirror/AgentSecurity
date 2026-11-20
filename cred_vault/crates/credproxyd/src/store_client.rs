//! Client side of the AF_UNIX wire protocol shared with `credstore`.
//!
//! The daemon is the vault's only client. One long-lived connection; requests
//! are serialized by a mutex, which is permitted by the protocol (per
//! connection requests are serial; at most 16 connections).
//!
//! A status error means the vault answered and the request is rejected.
//! A connection or framing error on a connection the daemon has been using
//! means the connection is unusable: the daemon must exit. The exception is
//! the vault's own 60 s idle close: if the connection has been idle at least
//! [`IDLE_CLOSE_GRACE`] and not a byte of the next request reached the wire,
//! the request is retried once on a new connection instead of killing the
//! daemon. If the vault is really gone, that reconnect fails and the daemon
//! still exits.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tokio::time::timeout;

#[cfg(test)]
use std::sync::Arc;

/// Framing constants are restated here, not imported: the three processes
/// share sockets, not crates. The values are the published wire contract.
const MAGIC: [u8; 4] = *b"CSIP";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 20;
const MAX_PAYLOAD: usize = 8 * 1024 * 1024;
const MSG_REQUEST: u8 = 0;
const MSG_RESPONSE: u8 = 1;

const OP_DATA_PUT: u8 = 5;
const OP_DATA_GET: u8 = 6;
const OP_DATA_DELETE: u8 = 7;
const OP_DATA_LIST: u8 = 8;

/// Status codes of the wire protocol; values are a published contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    NotFound,
    Mismatch,
    Corrupt,
    AlreadyExists,
    InvalidArgument,
    TooLarge,
    Unavailable,
    Internal,
    Unsupported,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "OK",
            Status::NotFound => "NOT_FOUND",
            Status::Mismatch => "MISMATCH",
            Status::Corrupt => "CORRUPT",
            Status::AlreadyExists => "ALREADY_EXISTS",
            Status::InvalidArgument => "INVALID_ARGUMENT",
            Status::TooLarge => "TOO_LARGE",
            Status::Unavailable => "UNAVAILABLE",
            Status::Internal => "INTERNAL",
            Status::Unsupported => "UNSUPPORTED",
        }
    }
}

const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_RETRY_TOTAL: Duration = Duration::from_secs(10);
const DEFAULT_RETRY_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// The vault answered with a non-OK status.
    Status(Status),
    /// I/O failure or EOF: the connection cannot be reused.
    Connection(String),
    /// The peer violated the framing contract.
    Protocol(String),
}

impl StoreError {
    pub fn is_fatal(&self) -> bool {
        matches!(self, StoreError::Connection(_) | StoreError::Protocol(_))
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Status(s) => write!(f, "store status {}", s.as_str()),
            StoreError::Connection(e) => write!(f, "store connection: {e}"),
            StoreError::Protocol(e) => write!(f, "store protocol: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<Status> for StoreError {
    fn from(s: Status) -> Self {
        StoreError::Status(s)
    }
}

pub struct StoreClient {
    path: PathBuf,
    conn: Mutex<Conn>,
    next_id: AtomicU64,
}

struct Conn {
    stream: UnixStream,
    /// When the last response on this connection was read. Used to tell the
    /// vault's 60 s idle close apart from a connection lost while the daemon
    /// was using it.
    last_ok: Instant,
}

impl Conn {
    fn new(stream: UnixStream) -> Conn {
        Conn {
            stream,
            last_ok: Instant::now(),
        }
    }
}

/// A write that never started is retried once only if the connection has been
/// idle at least this long; the vault closes idle connections at 60 s. Shorter
/// failures mean the connection was lost while in use and stay fatal.
const IDLE_CLOSE_GRACE: Duration = Duration::from_secs(50);

impl StoreClient {
    pub async fn connect(path: &Path) -> Result<Self> {
        let stream = UnixStream::connect(path)
            .await
            .with_context(|| format!("connect credstore socket {}", path.display()))?;
        Ok(StoreClient {
            path: path.to_path_buf(),
            conn: Mutex::new(Conn::new(stream)),
            next_id: AtomicU64::new(0),
        })
    }

    /// Startup retry window: 10 s total, 200 ms interval.
    pub async fn connect_with_retry(path: &Path, total: Duration) -> Result<Self> {
        let deadline = tokio::time::Instant::now() + total;
        loop {
            match Self::connect(path).await {
                Ok(client) => return Ok(client),
                Err(e) => {
                    if tokio::time::Instant::now() + DEFAULT_RETRY_INTERVAL >= deadline {
                        return Err(e.context(format!(
                            "credstore socket {} not ready after {} ms",
                            path.display(),
                            total.as_millis()
                        )));
                    }
                    tokio::time::sleep(DEFAULT_RETRY_INTERVAL).await;
                }
            }
        }
    }

    pub fn default_retry_window() -> Duration {
        DEFAULT_RETRY_TOTAL
    }

    /// A client backed by a socket pair that no server ever answers on.
    /// Used by unit tests that only need a placeholder `Arc<StoreClient>`.
    #[cfg(test)]
    pub fn dummy() -> Arc<Self> {
        let (stream, _peer) = UnixStream::pair().expect("socketpair");
        Arc::new(StoreClient {
            path: PathBuf::new(),
            conn: Mutex::new(Conn::new(stream)),
            next_id: AtomicU64::new(0),
        })
    }

    async fn request(&self, opcode: u8, payload: Vec<u8>) -> Result<(Status, Vec<u8>), StoreError> {
        let request_id = self.next_id.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        let header = RawHeader {
            msg_type: MSG_REQUEST,
            opcode,
            request_id,
            payload_len: payload.len() as u32,
        };
        let mut frame = Vec::with_capacity(HEADER_LEN + payload.len());
        frame.extend_from_slice(&header.encode());
        frame.extend_from_slice(&payload);

        let mut conn = self.conn.lock().await;
        match write_frame(&mut conn.stream, &frame).await {
            Ok(()) => {
                let reply = read_response(&mut conn.stream, opcode, request_id).await?;
                conn.last_ok = Instant::now();
                Ok(reply)
            }
            // The vault closes connections that stay idle for 60 s. If the
            // connection had been idle long enough and not a byte of this
            // request reached the wire, the request cannot have been applied,
            // so reconnect once and resend. A connection lost while in use
            // stays fatal.
            Err(WriteFailure::NotStarted) if conn.last_ok.elapsed() >= IDLE_CLOSE_GRACE => {
                eprintln!("credproxyd: store connection was idle-closed; reconnecting");
                let stream = UnixStream::connect(&self.path).await.map_err(|e| {
                    StoreError::Connection(format!(
                        "reconnect to {} failed: {e}",
                        self.path.display()
                    ))
                })?;
                conn.stream = stream;
                conn.last_ok = Instant::now();
                write_frame(&mut conn.stream, &frame)
                    .await
                    .map_err(WriteFailure::into_store)?;
                let reply = read_response(&mut conn.stream, opcode, request_id).await?;
                conn.last_ok = Instant::now();
                Ok(reply)
            }
            Err(e) => Err(e.into_store()),
        }
    }

    pub async fn data_put(&self, name: &str, content: &[u8]) -> Result<(), StoreError> {
        let mut payload = Vec::with_capacity(2 + name.len() + 4 + content.len());
        payload.extend_from_slice(&(name.len() as u16).to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        payload.extend_from_slice(&(content.len() as u32).to_le_bytes());
        payload.extend_from_slice(content);
        expect_empty(self.request(OP_DATA_PUT, payload).await?)
    }

    pub async fn data_get(&self, name: &str) -> Result<Vec<u8>, StoreError> {
        let (status, body) = self.request(OP_DATA_GET, name_payload(name)).await?;
        if status != Status::Ok {
            return Err(StoreError::Status(status));
        }
        let mut c = Cursor::new(&body);
        let out = c.bytes()?;
        c.finish()?;
        Ok(out)
    }

    pub async fn data_delete(&self, name: &str) -> Result<(), StoreError> {
        expect_empty(self.request(OP_DATA_DELETE, name_payload(name)).await?)
    }

    pub async fn data_list(&self) -> Result<Vec<String>, StoreError> {
        let (status, body) = self.request(OP_DATA_LIST, Vec::new()).await?;
        if status != Status::Ok {
            return Err(StoreError::Status(status));
        }
        let mut c = Cursor::new(&body);
        let count = c.u32()? as usize;
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let len = c.u16()? as usize;
            let name = c.take(len)?;
            out.push(
                String::from_utf8(name.to_vec())
                    .map_err(|_| StoreError::Protocol("data name is not UTF-8".into()))?,
            );
        }
        c.finish()?;
        Ok(out)
    }
}

/// Outcome of writing one request frame.
enum WriteFailure {
    /// Not a single byte of the frame reached the socket, so the vault cannot
    /// have seen (let alone applied) the request.
    NotStarted,
    Other(StoreError),
}

impl WriteFailure {
    fn into_store(self) -> StoreError {
        match self {
            WriteFailure::NotStarted => {
                StoreError::Connection("request never reached the vault".to_string())
            }
            WriteFailure::Other(e) => e,
        }
    }
}

/// Writes the whole frame, reporting whether any byte made it onto the wire.
async fn write_frame(stream: &mut UnixStream, frame: &[u8]) -> Result<(), WriteFailure> {
    let mut written = 0usize;
    while written < frame.len() {
        let failed = |written: usize| match written {
            0 => WriteFailure::NotStarted,
            n => WriteFailure::Other(StoreError::Connection(format!(
                "write failed after {n} bytes"
            ))),
        };
        match timeout(WRITE_TIMEOUT, stream.write(&frame[written..])).await {
            Err(_) => {
                return Err(match written {
                    0 => WriteFailure::NotStarted,
                    n => WriteFailure::Other(StoreError::Connection(format!(
                        "write timed out after {n} bytes"
                    ))),
                })
            }
            Ok(Err(e)) => {
                return Err(match written {
                    0 => WriteFailure::NotStarted,
                    n => WriteFailure::Other(StoreError::Connection(format!(
                        "write failed after {n} bytes: {e}"
                    ))),
                })
            }
            Ok(Ok(0)) => return Err(failed(written)),
            Ok(Ok(n)) => written += n,
        }
    }
    Ok(())
}

/// Reads and validates one response frame from an established connection.
async fn read_response(
    stream: &mut UnixStream,
    opcode: u8,
    request_id: u64,
) -> Result<(Status, Vec<u8>), StoreError> {
    let mut raw = [0u8; HEADER_LEN];
    timeout(RESPONSE_TIMEOUT, stream.read_exact(&mut raw))
        .await
        .map_err(|_| StoreError::Connection("response timed out".to_string()))?
        .map_err(|e| StoreError::Connection(format!("read header failed: {e}")))?;

    let header = RawHeader::decode(&raw)?;
    if header.msg_type != MSG_RESPONSE {
        return Err(StoreError::Protocol(format!(
            "msg_type {} is not a response",
            header.msg_type
        )));
    }
    if header.opcode != opcode {
        return Err(StoreError::Protocol(format!(
            "opcode echo {} != {opcode}",
            header.opcode
        )));
    }
    if header.request_id != request_id {
        return Err(StoreError::Protocol(format!(
            "request_id echo {} != {request_id}",
            header.request_id
        )));
    }
    let mut body = vec![0u8; header.payload_len as usize];
    timeout(RESPONSE_TIMEOUT, stream.read_exact(&mut body))
        .await
        .map_err(|_| StoreError::Connection("response body timed out".to_string()))?
        .map_err(|e| StoreError::Connection(format!("read body failed: {e}")))?;

    if body.len() < 2 {
        return Err(StoreError::Protocol("response shorter than status".into()));
    }
    let status = status_from_code(u16::from_le_bytes([body[0], body[1]]))?;
    let rest = body[2..].to_vec();
    if status != Status::Ok && !rest.is_empty() {
        return Err(StoreError::Protocol(
            "error response carried a body".to_string(),
        ));
    }
    Ok((status, rest))
}

fn name_payload(name: &str) -> Vec<u8> {
    let mut payload = (name.len() as u16).to_le_bytes().to_vec();
    payload.extend_from_slice(name.as_bytes());
    payload
}

fn expect_empty((status, body): (Status, Vec<u8>)) -> Result<(), StoreError> {
    if !body.is_empty() {
        return Err(StoreError::Protocol("unexpected response body".into()));
    }
    if status != Status::Ok {
        return Err(StoreError::Status(status));
    }
    Ok(())
}

fn status_from_code(code: u16) -> Result<Status, StoreError> {
    Ok(match code {
        0 => Status::Ok,
        1 => Status::NotFound,
        2 => Status::Mismatch,
        3 => Status::Corrupt,
        4 => Status::AlreadyExists,
        5 => Status::InvalidArgument,
        6 => Status::TooLarge,
        7 => Status::Unavailable,
        8 => Status::Internal,
        9 => Status::Unsupported,
        other => return Err(StoreError::Protocol(format!("unknown status code {other}"))),
    })
}

struct RawHeader {
    msg_type: u8,
    opcode: u8,
    request_id: u64,
    payload_len: u32,
}

impl RawHeader {
    fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6] = self.msg_type;
        out[7] = self.opcode;
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.payload_len.to_le_bytes());
        out
    }

    fn decode(buf: &[u8; HEADER_LEN]) -> Result<Self, StoreError> {
        if buf[0..4] != MAGIC {
            return Err(StoreError::Protocol("bad magic".to_string()));
        }
        let version = u16::from_le_bytes([buf[4], buf[5]]);
        if version != VERSION {
            return Err(StoreError::Protocol(format!(
                "unsupported protocol version {version}"
            )));
        }
        let payload_len = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        if payload_len as usize > MAX_PAYLOAD {
            return Err(StoreError::Protocol(
                "response payload over the frame limit".to_string(),
            ));
        }
        Ok(RawHeader {
            msg_type: buf[6],
            opcode: buf[7],
            request_id: u64::from_le_bytes(buf[8..16].try_into().expect("8 bytes")),
            payload_len,
        })
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        if self.buf.len() < n {
            return Err(StoreError::Protocol("truncated response".into()));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn bytes(&mut self) -> Result<Vec<u8>, StoreError> {
        let len = self.u32()? as usize;
        if len > MAX_PAYLOAD {
            return Err(StoreError::Protocol("length over frame limit".into()));
        }
        Ok(self.take(len)?.to_vec())
    }

    fn finish(self) -> Result<(), StoreError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(StoreError::Protocol("trailing response bytes".into()))
        }
    }
}

/// Log and terminate when the connection to the vault is gone: a store crash
/// means the daemon exits, because the deployment script starts both processes
/// and the daemon must not keep serving from a dead vault.
pub fn fatal_if_connection(err: &StoreError) -> bool {
    if err.is_fatal() {
        eprintln!("credproxyd: {err}; exiting (store connection is required)");
        std::process::exit(1);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_codes_match_the_contract() {
        for (code, status) in [
            (0, Status::Ok),
            (1, Status::NotFound),
            (2, Status::Mismatch),
            (3, Status::Corrupt),
            (4, Status::AlreadyExists),
            (5, Status::InvalidArgument),
            (6, Status::TooLarge),
            (7, Status::Unavailable),
            (8, Status::Internal),
            (9, Status::Unsupported),
        ] {
            assert_eq!(status_from_code(code).unwrap(), status);
        }
        assert!(status_from_code(10).is_err());
    }

    #[tokio::test]
    async fn write_to_a_closed_peer_is_not_started() {
        let (mut a, b) = UnixStream::pair().unwrap();
        drop(b);
        match write_frame(&mut a, b"0123456789").await {
            Err(WriteFailure::NotStarted) => {}
            Err(WriteFailure::Other(e)) => panic!("expected NotStarted, got Other({e})"),
            Ok(()) => panic!("expected NotStarted, got Ok"),
        }
    }

    /// The vault closes connections idle for 60 s.
    /// A request that never reached the wire must be retried on a new
    /// connection instead of killing the daemon.
    #[tokio::test]
    async fn a_request_that_never_left_the_daemon_is_retried_once() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("store.sock");
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        let server = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut header = [0u8; HEADER_LEN];
            s.read_exact(&mut header).await.unwrap();
            let req = RawHeader::decode(&header).unwrap();
            let mut payload = vec![0u8; req.payload_len as usize];
            s.read_exact(&mut payload).await.unwrap();
            let resp = RawHeader {
                msg_type: MSG_RESPONSE,
                opcode: req.opcode,
                request_id: req.request_id,
                payload_len: 6,
            };
            let mut frame = resp.encode().to_vec();
            frame.extend_from_slice(&[0, 0]);
            frame.extend_from_slice(&0u32.to_le_bytes());
            s.write_all(&frame).await.unwrap();
        });

        let (dead, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let client = StoreClient {
            path: sock.clone(),
            conn: Mutex::new(Conn {
                stream: dead,
                last_ok: Instant::now() - IDLE_CLOSE_GRACE - Duration::from_secs(10),
            }),
            next_id: AtomicU64::new(0),
        };
        assert!(client.data_list().await.unwrap().is_empty());
        server.await.unwrap();
    }

    /// Losing the connection while the daemon is using it stays fatal; only an
    /// idle close is retried.
    #[tokio::test]
    async fn a_connection_lost_while_in_use_is_fatal() {
        let (dead, peer) = UnixStream::pair().unwrap();
        drop(peer);
        let client = StoreClient {
            path: PathBuf::from("/nonexistent/store.sock"),
            conn: Mutex::new(Conn::new(dead)),
            next_id: AtomicU64::new(0),
        };
        let err = client.data_list().await.unwrap_err();
        assert!(matches!(err, StoreError::Connection(_)), "{err}");
        assert!(err.is_fatal());
    }
}
