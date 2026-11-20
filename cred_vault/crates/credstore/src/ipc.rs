//! Wire protocol between `credstore` and its client.
//!
//! Frame: 20-byte header + payload, all integers little-endian except magic.
//!
//! ```text
//! offset  size  field
//! 0       4     magic "CSIP"
//! 4       2     version = 1
//! 6       1     msg_type (0 = request, 1 = response)
//! 7       1     opcode
//! 8       8     request_id
//! 16      4     payload_len
//! ```
//!
//! Only the `data` namespace remains. Opcodes 1–4 were the credential
//! namespace and are retired; values 5–8 keep their published numbers.

use crate::record;

pub const MAGIC: [u8; 4] = *b"CSIP";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 20;
pub const MAX_PAYLOAD: usize = 8 * 1024 * 1024;

pub const MSG_REQUEST: u8 = 0;
pub const MSG_RESPONSE: u8 = 1;

pub const OP_DATA_PUT: u8 = 5;
pub const OP_DATA_GET: u8 = 6;
pub const OP_DATA_DELETE: u8 = 7;
pub const OP_DATA_LIST: u8 = 8;

/// Wire status codes. Values are a published contract; never renumber.
/// `Mismatch` is retained although the credential namespace is gone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Status {
    Ok = 0,
    NotFound = 1,
    Mismatch = 2,
    Corrupt = 3,
    AlreadyExists = 4,
    InvalidArgument = 5,
    TooLarge = 6,
    Unavailable = 7,
    Internal = 8,
    Unsupported = 9,
}

impl Status {
    pub fn code(self) -> u16 {
        self as u16
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub msg_type: u8,
    pub opcode: u8,
    pub request_id: u64,
    pub payload_len: u32,
}

impl Header {
    pub fn encode(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[0..4].copy_from_slice(&MAGIC);
        out[4..6].copy_from_slice(&VERSION.to_le_bytes());
        out[6] = self.msg_type;
        out[7] = self.opcode;
        out[8..16].copy_from_slice(&self.request_id.to_le_bytes());
        out[16..20].copy_from_slice(&self.payload_len.to_le_bytes());
        out
    }

    /// `Ok(header)` or the status to report before closing the connection.
    /// A magic mismatch is reported as `None` (close silently). Frame-level
    /// fields that the server can answer (version, size) are checked here;
    /// `msg_type`/`opcode` are checked by the caller.
    pub fn decode(buf: &[u8; HEADER_LEN]) -> Result<Header, Option<Status>> {
        if buf[0..4] != MAGIC {
            return Err(None);
        }
        let version = u16::from_le_bytes([buf[4], buf[5]]);
        if version != VERSION {
            return Err(Some(Status::Unsupported));
        }
        let msg_type = buf[6];
        let opcode = buf[7];
        let request_id = u64::from_le_bytes(buf[8..16].try_into().expect("8 bytes"));
        let payload_len = u32::from_le_bytes(buf[16..20].try_into().expect("4 bytes"));
        if payload_len as usize > MAX_PAYLOAD {
            return Err(Some(Status::TooLarge));
        }
        Ok(Header {
            msg_type,
            opcode,
            request_id,
            payload_len,
        })
    }

    /// Rejects frames the server must answer with a protocol error.
    pub fn check_request(&self) -> Result<(), Status> {
        if self.msg_type != MSG_REQUEST {
            return Err(Status::InvalidArgument);
        }
        if !matches!(
            self.opcode,
            OP_DATA_PUT | OP_DATA_GET | OP_DATA_DELETE | OP_DATA_LIST
        ) {
            return Err(Status::Unsupported);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    DataPut { name: Vec<u8>, content: Vec<u8> },
    DataGet { name: Vec<u8> },
    DataDelete { name: Vec<u8> },
    DataList,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    InvalidArgument,
    TooLarge,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// put / delete
    Empty(Status),
    Content(Status, Vec<u8>),
    Names(Status, Vec<Vec<u8>>),
}

impl Response {
    pub fn status(&self) -> Status {
        match self {
            Response::Empty(s) | Response::Content(s, _) | Response::Names(s, _) => *s,
        }
    }

    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Response::Empty(s) => out.extend_from_slice(&s.code().to_le_bytes()),
            Response::Content(s, content) => {
                out.extend_from_slice(&s.code().to_le_bytes());
                if *s == Status::Ok {
                    out.extend_from_slice(&(content.len() as u32).to_le_bytes());
                    out.extend_from_slice(content);
                }
            }
            Response::Names(s, names) => {
                out.extend_from_slice(&s.code().to_le_bytes());
                if *s == Status::Ok {
                    out.extend_from_slice(&(names.len() as u32).to_le_bytes());
                    for name in names {
                        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
                        out.extend_from_slice(name);
                    }
                }
            }
        }
        out
    }

    pub fn frame(&self, opcode: u8, request_id: u64) -> Vec<u8> {
        let payload = self.payload();
        let header = Header {
            msg_type: MSG_RESPONSE,
            opcode,
            request_id,
            payload_len: payload.len() as u32,
        };
        let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload);
        out
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.buf.len() < n {
            return Err(ParseError::InvalidArgument);
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, ParseError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn finish(self) -> Result<(), ParseError> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(ParseError::InvalidArgument)
        }
    }
}

pub fn parse_request(opcode: u8, payload: &[u8]) -> Result<Request, ParseError> {
    let mut c = Cursor::new(payload);
    let req = match opcode {
        OP_DATA_PUT => {
            let name_len = c.u16()? as usize;
            if name_len > record::DATA_NAME_MAX {
                return Err(ParseError::InvalidArgument);
            }
            let name = c.take(name_len)?.to_vec();
            let content_len = c.u32()? as usize;
            if content_len > record::DATA_CONTENT_MAX {
                return Err(ParseError::TooLarge);
            }
            let content = c.take(content_len)?.to_vec();
            Request::DataPut { name, content }
        }
        OP_DATA_GET => {
            let name_len = c.u16()? as usize;
            if name_len > record::DATA_NAME_MAX {
                return Err(ParseError::InvalidArgument);
            }
            Request::DataGet {
                name: c.take(name_len)?.to_vec(),
            }
        }
        OP_DATA_DELETE => {
            let name_len = c.u16()? as usize;
            if name_len > record::DATA_NAME_MAX {
                return Err(ParseError::InvalidArgument);
            }
            Request::DataDelete {
                name: c.take(name_len)?.to_vec(),
            }
        }
        OP_DATA_LIST => Request::DataList,
        _ => return Err(ParseError::InvalidArgument),
    };
    c.finish()?;
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = Header {
            msg_type: MSG_REQUEST,
            opcode: OP_DATA_GET,
            request_id: 42,
            payload_len: 100,
        };
        let bytes = h.encode();
        assert_eq!(Header::decode(&bytes), Ok(h));
    }

    #[test]
    fn header_rejects_bad_magic_version_type_size() {
        let bytes = [0u8; HEADER_LEN];
        assert_eq!(Header::decode(&bytes), Err(None));

        let h = Header {
            msg_type: MSG_REQUEST,
            opcode: OP_DATA_LIST,
            request_id: 1,
            payload_len: 0,
        };
        let mut bytes = h.encode();
        bytes[4..6].copy_from_slice(&2u16.to_le_bytes());
        assert_eq!(Header::decode(&bytes), Err(Some(Status::Unsupported)));

        let mut bytes = h.encode();
        bytes[6] = MSG_RESPONSE;
        let decoded = Header::decode(&bytes).expect("structurally valid");
        assert_eq!(decoded.check_request(), Err(Status::InvalidArgument));

        // Retired credential opcodes are unsupported, not silently accepted.
        let mut bytes = h.encode();
        bytes[7] = 1;
        let decoded = Header::decode(&bytes).expect("structurally valid");
        assert_eq!(decoded.check_request(), Err(Status::Unsupported));

        let mut bytes = h.encode();
        bytes[7] = 99;
        let decoded = Header::decode(&bytes).expect("structurally valid");
        assert_eq!(decoded.check_request(), Err(Status::Unsupported));

        let mut bytes = h.encode();
        bytes[16..20].copy_from_slice(&((MAX_PAYLOAD as u32) + 1).to_le_bytes());
        assert_eq!(Header::decode(&bytes), Err(Some(Status::TooLarge)));
    }

    fn data_put_payload(name: &[u8], content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(name);
        out.extend_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(content);
        out
    }

    #[test]
    fn parses_data_put() {
        let payload = data_put_payload(b"keystore.b", b"{}");
        assert_eq!(
            parse_request(OP_DATA_PUT, &payload),
            Ok(Request::DataPut {
                name: b"keystore.b".to_vec(),
                content: b"{}".to_vec(),
            })
        );
    }

    #[test]
    fn rejects_trailing_and_truncated() {
        let mut payload = data_put_payload(b"config", b"{}");
        payload.push(0);
        assert_eq!(
            parse_request(OP_DATA_PUT, &payload),
            Err(ParseError::InvalidArgument)
        );
        let payload = data_put_payload(b"config", b"{}");
        assert_eq!(
            parse_request(OP_DATA_PUT, &payload[..payload.len() - 1]),
            Err(ParseError::InvalidArgument)
        );
    }

    #[test]
    fn rejects_oversized_fields() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&((record::DATA_NAME_MAX as u16) + 1).to_le_bytes());
        assert_eq!(
            parse_request(OP_DATA_PUT, &payload),
            Err(ParseError::InvalidArgument)
        );
        let payload = data_put_payload(b"config", &vec![0; record::DATA_CONTENT_MAX + 1]);
        assert_eq!(
            parse_request(OP_DATA_PUT, &payload),
            Err(ParseError::TooLarge)
        );
    }

    #[test]
    fn list_requests_must_be_empty() {
        assert_eq!(
            parse_request(OP_DATA_LIST, b"x"),
            Err(ParseError::InvalidArgument)
        );
        assert_eq!(parse_request(OP_DATA_LIST, b""), Ok(Request::DataList));
    }

    #[test]
    fn response_frames_roundtrip_header() {
        let resp = Response::Content(Status::Ok, b"real".to_vec());
        let frame = resp.frame(OP_DATA_GET, 7);
        let header = Header::decode(frame[..HEADER_LEN].try_into().unwrap()).unwrap();
        assert_eq!(header.msg_type, MSG_RESPONSE);
        assert_eq!(header.opcode, OP_DATA_GET);
        assert_eq!(header.request_id, 7);
        assert_eq!(header.payload_len as usize, frame.len() - HEADER_LEN);
        assert_eq!(&frame[HEADER_LEN + 2..HEADER_LEN + 6], &4u32.to_le_bytes());
    }

    #[test]
    fn error_response_carries_only_status() {
        let resp = Response::Content(Status::Mismatch, Vec::new());
        assert_eq!(
            resp.payload(),
            Status::Mismatch.code().to_le_bytes().to_vec()
        );
    }
}
