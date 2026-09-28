//! The agent's binary packet format: a batch header and fixed-width records.
//!
//! The counterpart of `local-agent/packet_batch.py` and
//! `src/services/agentBinary.ts`. All three are held to the same bytes by
//! `scripts/agent/wire-vectors.json` rather than to their own copies of them -
//! see `local-agent/wire_vectors.py` for why that file exists.
//!
//! ## The record is 22 bytes
//!
//! ```text
//!   u32  seq       where this frame sits in the capture's sequence
//!   u16  iface     which adapter it came from, as a list position
//!   u32  capLen    how many bytes follow this record
//!   u32  origLen   the frame's length on the wire
//!   u64  tsNs      the driver's timestamp, epoch nanoseconds
//! ```
//!
//! **Both lengths became 32 bits in version 4** (ADR 0052). As 16 bits they
//! capped a frame at 65,535 bytes, so the capture was opened at that snaplen
//! and anything longer - an offloaded send can be - was refused with
//! `frame_too_long` and never seen. The agent now captures at dumpcap's
//! 262,144 and writes the same frames into its own pcapng, so the wire has to
//! carry what the file does. `origLen` replaced a 16-bit `extra` (wire length
//! minus capLen): at 32 bits there is nothing left to save by sending a
//! difference, and the difference had to clamp.
//!
//! **`tsNs` was an `f64` of microseconds until version 3**, and could not have
//! carried nanoseconds as one: epoch nanoseconds are past 2^53, and even epoch
//! microseconds are only 0.25 us apart in an `f64` today. So the capture's own
//! precision - which Npcap gives in nanoseconds when asked, in 100 ns steps on
//! this machine - was thrown away at the last step before the pipe. The same
//! eight bytes as an integer hold it exactly until 2554.
//!
//! **`capLen` is still refused rather than masked when it will not fit**, now
//! past 4 GB. The payload follows the record in full, so a masked length would
//! have the decoder take its next record from inside a frame - reading a
//! plausible record out of the middle of one with no error anywhere.

/// `IWP1`, little-endian on the wire like everything else here.
pub const MAGIC: [u8; 4] = *b"IWP1";

/// 4 since both lengths became 32 bits; 3 since the timestamp became integer
/// nanoseconds; 2 since the record shrank from 24 bytes to 18.
///
/// A decoder refuses a version it does not know rather than reading the old
/// layout at the new offsets, which would produce plausible frames with wrong
/// lengths instead of an error.
pub const VERSION: u8 = 4;

pub const HEADER_BYTES: usize = 8;
pub const RECORD_BYTES: usize = 22;

/// The most records one batch may declare. The count is a `u16`.
pub const MAX_BATCH_RECORDS: usize = 0xFFFF;

#[derive(Debug, PartialEq)]
pub enum WireError {
    /// A captured frame longer than the 32-bit length field can describe.
    FrameTooLong(usize),
    /// A batch with no records would say nothing.
    EmptyBatch,
    TooManyRecords(usize),
    TruncatedHeader,
    NotABatch([u8; 4]),
    UnsupportedVersion(u8),
    TruncatedRecord,
    TruncatedPayload,
    TrailingBytes,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::FrameTooLong(n) => write!(
                f,
                "a captured frame of {n} bytes cannot be framed: the record's \
                 length field is 32 bits, and masking it would desynchronise \
                 the decoder rather than truncate the frame"
            ),
            WireError::EmptyBatch => write!(f, "a batch with no records would say nothing"),
            WireError::TooManyRecords(n) => write!(f, "a batch holds at most 65535 records, not {n}"),
            WireError::TruncatedHeader => write!(f, "truncated header"),
            WireError::NotABatch(m) => write!(f, "not a packet batch: {m:?}"),
            WireError::UnsupportedVersion(v) => write!(f, "unsupported batch version {v}"),
            WireError::TruncatedRecord => write!(f, "truncated record header"),
            WireError::TruncatedPayload => write!(f, "truncated record payload"),
            WireError::TrailingBytes => write!(f, "trailing bytes after the last record"),
        }
    }
}

/// One record, ready to be concatenated into a batch.
///
/// `orig_len` is the length on the wire, never sent as less than what was
/// captured: a wire length below the frame's own bytes would be nonsense, so it
/// is raised to `capLen` instead.
pub fn encode_record(
    seq: u32,
    iface: u16,
    ts_ns: u64,
    orig_len: usize,
    data: &[u8],
) -> Result<Vec<u8>, WireError> {
    let cap_len = data.len();
    if cap_len > u32::MAX as usize {
        return Err(WireError::FrameTooLong(cap_len));
    }
    let orig_len = orig_len.max(cap_len).min(u32::MAX as usize) as u32;

    let mut out = Vec::with_capacity(RECORD_BYTES + cap_len);
    out.extend_from_slice(&seq.to_le_bytes());
    out.extend_from_slice(&iface.to_le_bytes());
    out.extend_from_slice(&(cap_len as u32).to_le_bytes());
    out.extend_from_slice(&orig_len.to_le_bytes());
    out.extend_from_slice(&ts_ns.to_le_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

/// Frames already-encoded records into one batch.
pub fn encode_batch(records: &[Vec<u8>]) -> Result<Vec<u8>, WireError> {
    if records.is_empty() {
        return Err(WireError::EmptyBatch);
    }
    if records.len() > MAX_BATCH_RECORDS {
        return Err(WireError::TooManyRecords(records.len()));
    }
    let total: usize = records.iter().map(|r| r.len()).sum();
    let mut out = Vec::with_capacity(HEADER_BYTES + total);
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.push(0); // flags, unused
    out.extend_from_slice(&(records.len() as u16).to_le_bytes());
    for r in records {
        out.extend_from_slice(r);
    }
    Ok(out)
}

#[derive(Debug, PartialEq, Clone)]
pub struct Record {
    pub seq: u32,
    pub iface: u16,
    pub ts_ns: u64,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

/// The inverse. Exists so the vectors can be asserted both ways round.
pub fn decode_batch(payload: &[u8]) -> Result<Vec<Record>, WireError> {
    if payload.len() < HEADER_BYTES {
        return Err(WireError::TruncatedHeader);
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&payload[0..4]);
    if magic != MAGIC {
        return Err(WireError::NotABatch(magic));
    }
    let version = payload[4];
    if version != VERSION {
        return Err(WireError::UnsupportedVersion(version));
    }
    let count = u16::from_le_bytes([payload[6], payload[7]]) as usize;

    let mut out = Vec::with_capacity(count);
    let mut offset = HEADER_BYTES;
    for _ in 0..count {
        if offset + RECORD_BYTES > payload.len() {
            return Err(WireError::TruncatedRecord);
        }
        let seq = u32::from_le_bytes(payload[offset..offset + 4].try_into().unwrap());
        let iface = u16::from_le_bytes([payload[offset + 4], payload[offset + 5]]);
        let cap_len = u32::from_le_bytes(payload[offset + 6..offset + 10].try_into().unwrap()) as usize;
        let orig_len = u32::from_le_bytes(payload[offset + 10..offset + 14].try_into().unwrap());
        let ts_ns = u64::from_le_bytes(payload[offset + 14..offset + 22].try_into().unwrap());
        offset += RECORD_BYTES;
        if offset + cap_len > payload.len() {
            return Err(WireError::TruncatedPayload);
        }
        out.push(Record {
            seq,
            iface,
            ts_ns,
            orig_len,
            data: payload[offset..offset + cap_len].to_vec(),
        });
        offset += cap_len;
    }
    if offset != payload.len() {
        return Err(WireError::TrailingBytes);
    }
    Ok(out)
}

impl std::error::Error for WireError {}
