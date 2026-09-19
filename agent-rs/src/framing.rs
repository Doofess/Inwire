//! Length-prefixed framing for the named pipe.
//!
//! A pipe is a byte stream, so framing is ours. The counterpart of
//! `local-agent/pipe_frame.py` and `src/services/agentFraming.ts`, held to the
//! same bytes by `scripts/agent/wire-vectors.json`.
//!
//! ```text
//!   u32  length    of the payload that follows, little-endian
//!   u8   kind      0 = JSON, 1 = binary
//!   ..   payload
//! ```
//!
//! Little-endian to match the packet records, which are little-endian because
//! every machine this runs on is.

pub const FRAME_JSON: u8 = 0;
pub const FRAME_BINARY: u8 = 1;

pub const HEADER_BYTES: usize = 5;

/// A declared length past this is refused **before anything is allocated**.
///
/// The agent is a privileged service reading from a pipe, and a five-byte
/// header must never be able to ask it for four gigabytes. 8 MB is comfortably
/// above the largest thing that legitimately crosses - a 256 kB packet batch.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, PartialEq)]
pub enum FramingError {
    /// The header declared more than `MAX_FRAME_BYTES`. Unrecoverable: the
    /// stream position is no longer trustworthy, so there is nothing to
    /// resynchronise to.
    TooLong(usize),
    /// A zero-length frame carries no kind and no payload.
    Empty,
    UnknownKind(u8),
}

impl core::fmt::Display for FramingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FramingError::TooLong(n) => {
                write!(f, "frame of {n} bytes exceeds the {MAX_FRAME_BYTES} byte ceiling")
            }
            FramingError::Empty => write!(f, "a zero-length frame declares nothing"),
            FramingError::UnknownKind(k) => write!(f, "unknown frame kind {k}"),
        }
    }
}

pub fn encode_frame(kind: u8, payload: &[u8]) -> Result<Vec<u8>, FramingError> {
    if kind != FRAME_JSON && kind != FRAME_BINARY {
        return Err(FramingError::UnknownKind(kind));
    }
    // The length covers the kind byte as well as the payload, which is what
    // makes a zero-length frame impossible to encode by construction.
    let len = payload.len() + 1;
    if len > MAX_FRAME_BYTES {
        return Err(FramingError::TooLong(len));
    }
    let mut out = Vec::with_capacity(HEADER_BYTES + payload.len());
    out.extend_from_slice(&(len as u32).to_le_bytes());
    out.push(kind);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn encode_json(text: &str) -> Result<Vec<u8>, FramingError> {
    encode_frame(FRAME_JSON, text.as_bytes())
}

/// Accumulates bytes and yields whole frames.
///
/// **Arbitrary split boundaries are the point.** A pipe read returns whatever
/// happened to be in the buffer, so a header can arrive in two pieces and a
/// payload in ten. The reader keeps what it has and yields nothing until a
/// frame is complete.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub struct Frame {
    pub kind: u8,
    pub payload: Vec<u8>,
}

impl FrameReader {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Feeds bytes in and takes whole frames out.
    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Frame>, FramingError> {
        self.buf.extend_from_slice(chunk);
        let mut out = Vec::new();
        loop {
            if self.buf.len() < HEADER_BYTES {
                return Ok(out);
            }
            let len = u32::from_le_bytes(self.buf[0..4].try_into().unwrap()) as usize;
            // Checked against the ceiling on the HEADER ALONE, before the
            // payload is waited for and before anything is reserved.
            if len > MAX_FRAME_BYTES {
                return Err(FramingError::TooLong(len));
            }
            if len == 0 {
                return Err(FramingError::Empty);
            }
            let total = 4 + len;
            if self.buf.len() < total {
                return Ok(out);
            }
            let kind = self.buf[4];
            if kind != FRAME_JSON && kind != FRAME_BINARY {
                return Err(FramingError::UnknownKind(kind));
            }
            out.push(Frame {
                kind,
                payload: self.buf[HEADER_BYTES..total].to_vec(),
            });
            self.buf.drain(0..total);
        }
    }

    /// Bytes held from an incomplete frame. Diagnostics only.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}
