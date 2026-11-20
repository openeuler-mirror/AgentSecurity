//! AF_UNIX server: accept loop, `SO_PEERCRED` gate, framing, dispatch.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;

use crate::ipc::{self, Response, Status, HEADER_LEN, MAGIC, MAX_PAYLOAD, MSG_REQUEST, VERSION};
use crate::store::Store;

pub const MAX_CONNECTIONS: usize = 16;
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const PAYLOAD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub socket: PathBuf,
    /// Only connections whose peer uid equals this value are served. `None`
    /// accepts any uid (used only when the operator explicitly opts out).
    pub allow_uid: Option<u32>,
    pub max_connections: usize,
}

pub async fn run(store: Arc<Store>, cfg: ServerConfig) -> anyhow::Result<()> {
    let listener = UnixListener::bind(&cfg.socket).map_err(|e| {
        anyhow::anyhow!(
            "bind {}: {e} (another credstore may be running; the socket is removed by systemd \
             RuntimeDirectory on stop)",
            cfg.socket.display()
        )
    })?;
    std::fs::set_permissions(&cfg.socket, std::fs::Permissions::from_mode(0o660))?;
    eprintln!(
        "credstore: listening on {} (allow_uid={:?}, data backend ready)",
        cfg.socket.display(),
        cfg.allow_uid
    );

    let semaphore = Arc::new(Semaphore::new(cfg.max_connections.max(1)));
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;

    loop {
        let permit = semaphore.clone().acquire_owned().await?;
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let store = store.clone();
                let allow_uid = cfg.allow_uid;
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(e) = serve_connection(stream, store, allow_uid).await {
                        eprintln!("credstore: connection closed: {e}");
                    }
                });
            }
            _ = sigterm.recv() => {
                eprintln!("credstore: SIGTERM, stopping accept loop");
                break;
            }
            _ = sigint.recv() => {
                eprintln!("credstore: SIGINT, stopping accept loop");
                break;
            }
        }
    }
    let _ = std::fs::remove_file(&cfg.socket);
    Ok(())
}

async fn serve_connection(
    mut stream: UnixStream,
    store: Arc<Store>,
    allow_uid: Option<u32>,
) -> anyhow::Result<()> {
    let cred = stream.peer_cred()?;
    if let Some(allow) = allow_uid {
        if cred.uid() != allow {
            // No record-existence information is returned to a rejected peer.
            return Ok(());
        }
    }
    loop {
        let mut header = [0u8; HEADER_LEN];
        match tokio::time::timeout(IDLE_TIMEOUT, stream.read_exact(&mut header)).await {
            Err(_) => return Ok(()),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(_)) => {}
        }

        let payload_len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
        let opcode = header[7];
        let request_id = u64::from_le_bytes(header[8..16].try_into().expect("8 bytes"));

        if header[0..4] != MAGIC {
            // No way to answer a peer that is not speaking this protocol.
            return Ok(());
        }
        let version = u16::from_le_bytes([header[4], header[5]]);
        if version != VERSION {
            send_error(&mut stream, opcode, request_id, Status::Unsupported).await?;
            return Ok(());
        }
        if header[6] != MSG_REQUEST {
            send_error(&mut stream, opcode, request_id, Status::InvalidArgument).await?;
            return Ok(());
        }
        if payload_len as usize > MAX_PAYLOAD {
            send_error(&mut stream, opcode, request_id, Status::TooLarge).await?;
            return Ok(());
        }
        if !known_opcode(opcode) {
            send_error(&mut stream, opcode, request_id, Status::Unsupported).await?;
            return Ok(());
        }

        let mut payload = vec![0u8; payload_len as usize];
        match tokio::time::timeout(PAYLOAD_TIMEOUT, stream.read_exact(&mut payload)).await {
            Err(_) => return Ok(()),
            Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(e)) => return Err(e.into()),
            Ok(Ok(_)) => {}
        }

        let request = match ipc::parse_request(opcode, &payload) {
            Ok(req) => req,
            Err(ipc::ParseError::InvalidArgument) => {
                send_error(&mut stream, opcode, request_id, Status::InvalidArgument).await?;
                return Ok(());
            }
            Err(ipc::ParseError::TooLarge) => {
                send_error(&mut stream, opcode, request_id, Status::TooLarge).await?;
                return Ok(());
            }
        };

        let store = store.clone();
        let response = tokio::task::spawn_blocking(move || store.execute(&request))
            .await
            .unwrap_or(Response::Empty(Status::Internal));
        let frame = response.frame(opcode, request_id);
        stream.write_all(&frame).await?;
    }
}

async fn send_error(
    stream: &mut UnixStream,
    opcode: u8,
    request_id: u64,
    status: Status,
) -> std::io::Result<()> {
    let frame = Response::Empty(status).frame(opcode, request_id);
    stream.write_all(&frame).await
}

fn known_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        ipc::OP_DATA_PUT | ipc::OP_DATA_GET | ipc::OP_DATA_DELETE | ipc::OP_DATA_LIST
    )
}
