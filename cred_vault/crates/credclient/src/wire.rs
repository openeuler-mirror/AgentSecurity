//! Management-plane client.
//!
//! One connection per command: one HTTP/1.1 request with a JSON body over the
//! daemon's AF_UNIX management socket, `Connection: close`, response read to
//! EOF. The wire shapes are restated here rather than shared with
//! `credproxyd`: the three processes share sockets, not crates.

use std::path::Path;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_RESPONSE: usize = 16 * 1024 * 1024;

/// A rejected management request, as the daemon reported it.
#[derive(Debug)]
pub struct ApiError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} ({}; HTTP {})", self.message, self.code, self.status)
    }
}

impl std::error::Error for ApiError {}

/// Sends one request and returns the decoded JSON reply (`Value::Null` for an
/// empty `204` body). A rejected request becomes an [`ApiError`] carrying the
/// daemon's code and message; stdout stays empty.
pub async fn call(
    socket: &Path,
    method: &str,
    target: &str,
    body: Option<&Value>,
) -> Result<Value> {
    let mut stream = timeout(CONNECT_TIMEOUT, UnixStream::connect(socket))
        .await
        .context("connect to credproxyd management socket timed out")?
        .with_context(|| {
            format!(
                "connect credproxyd management socket {} (is credproxyd running?)",
                socket.display()
            )
        })?;

    let payload = match body {
        Some(value) => serde_json::to_vec(value)?,
        None => Vec::new(),
    };
    let mut request = format!(
        "{method} {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Length: {}\r\n",
        payload.len()
    );
    if !payload.is_empty() {
        request.push_str("Content-Type: application/json\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;

    let mut raw = Vec::new();
    timeout(RESPONSE_TIMEOUT, stream.read_to_end(&mut raw))
        .await
        .context("management response timed out")??;
    if raw.len() > MAX_RESPONSE {
        bail!("management response exceeds {MAX_RESPONSE} bytes");
    }
    decode(&raw)
}

fn decode(raw: &[u8]) -> Result<Value> {
    let text = String::from_utf8_lossy(raw);
    let (head, body) = text
        .split_once("\r\n\r\n")
        .with_context(|| format!("management response has no header terminator: {text:?}"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next().context("management response is empty")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .with_context(|| format!("malformed status line {status_line:?}"))?
        .parse()
        .with_context(|| format!("malformed status line {status_line:?}"))?;

    if !(200..300).contains(&status) {
        let reply: Value = serde_json::from_str(body).unwrap_or(Value::Null);
        return Err(ApiError {
            status,
            code: reply
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
            message: reply
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("management request failed")
                .to_string(),
        }
        .into());
    }
    if body.trim().is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(body).context("decode management response")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_success_and_error_replies() {
        assert_eq!(
            decode(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").unwrap(),
            serde_json::json!({})
        );
        assert_eq!(
            decode(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").unwrap(),
            Value::Null
        );
        let err = decode(
            b"HTTP/1.1 409 Conflict\r\nContent-Length: 30\r\n\r\n{\"error\":\"dup\",\"code\":\"conflict\"}",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("dup"), "{err}");
        assert!(err.contains("conflict"), "{err}");
        assert!(decode(b"not a response").is_err());
    }
}
