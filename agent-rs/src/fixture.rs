//! Real frames for tests, read from the captures in `test/fixtures/`.
//!
//! **Real, not built.** The owner's rule for this repository is that anything
//! carrying frames replays a real capture - a frame a test author built to pass
//! proves what the author expected, and the fixtures are what the wire actually
//! sent. They are untracked (ADR 0004), so a test that wants them prints a
//! `SKIP` line and returns when they are absent, the way
//! `scripts/export/realCaptures.ts` does for the TypeScript suite.
//!
//! Classic libpcap only, which is what both general fixtures are: a 24-byte
//! file header, then a 16-byte header per record.

use std::path::PathBuf;

/// The two general captures, by the names `scripts/export/realCaptures.ts`
/// gives them.
pub const CAPTURES: [&str; 2] = [
    "inwire_capture_1788478187989.pcap",
    "bulk_capture_1788426090876.pcap",
];

/// One frame as the capture file recorded it.
#[derive(Clone, Debug)]
pub struct Frame {
    /// The capture time, in epoch microseconds.
    pub ts_us: f64,
    /// The length on the wire.
    pub wire_len: u32,
    pub data: Vec<u8>,
}

fn path(file: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("test").join("fixtures").join(file)
}

/// Every frame of `file`, or `None` - with a `SKIP` line - when it is absent.
pub fn frames(file: &str) -> Option<Vec<Frame>> {
    let Ok(bytes) = std::fs::read(path(file)) else {
        eprintln!("SKIP  {file} not present (test/fixtures/README.md)");
        return None;
    };
    Some(parse(&bytes).unwrap_or_else(|| panic!("{file} is not a classic pcap this reader knows")))
}

/// The frames of whichever general capture is present first.
pub fn any_capture() -> Option<Vec<Frame>> {
    CAPTURES.iter().find_map(|file| frames(file))
}

fn parse(bytes: &[u8]) -> Option<Vec<Frame>> {
    if bytes.len() < 24 {
        return None;
    }
    let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
    // Microsecond or nanosecond resolution, either byte order.
    let (little, nanos) = match magic {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return None,
    };
    let u32_at = |at: usize| -> u32 {
        let b = [bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]];
        if little { u32::from_le_bytes(b) } else { u32::from_be_bytes(b) }
    };
    let mut out = Vec::new();
    let mut at = 24;
    while at + 16 <= bytes.len() {
        let seconds = u32_at(at) as f64;
        let fraction = u32_at(at + 4) as f64;
        let captured = u32_at(at + 8) as usize;
        let wire_len = u32_at(at + 12);
        at += 16;
        if at + captured > bytes.len() {
            break;
        }
        let micros = if nanos { (fraction / 1000.0).floor() } else { fraction };
        out.push(Frame {
            ts_us: seconds * 1_000_000.0 + micros,
            wire_len,
            data: bytes[at..at + captured].to_vec(),
        });
        at += captured;
    }
    Some(out)
}
