//! The pcapng blocks the agent writes, laid out the way Wireshark's dumpcap
//! lays them out.
//!
//! The agent is Inwire's own dumpcap (ADR 0052): the same libpcap handle, and
//! now the same file. Four blocks, each built into a `Vec<u8>`:
//!
//! - **SHB**, once a file: the CPU, the OS and the writing program, in that
//!   order, with an unknown section length (-1) because the file is written
//!   as it grows.
//! - **IDB**, one per adapter: link type, snaplen, then the device name, the
//!   connection's name, the timestamp resolution, the capture filter, the OS
//!   and the adapter's model - **ascending option codes**, as dumpcap emits
//!   them.
//! - **EPB**, one per frame, with **no options**. dumpcap writes every packet
//!   with no comment and no flags, so a frame's block is a pure function of
//!   its interface, stamp, lengths and bytes.
//! - **ISB**, one per adapter when a file closes: a comment, the start and end
//!   of the capture, frames received, frames dropped.
//!
//! **One deliberate difference from dumpcap:** it writes the ISB's times in
//! microseconds inside a section whose interfaces declare nanoseconds, so a
//! reader applying the spec places them a thousand times too early. These are
//! in the interface's own units, as the spec says. The tests below rebuild
//! dumpcap's blocks byte for byte by passing its values straight through,
//! which is what shows the layout is the same and only the value differs.
//!
//! Pure: nothing here touches a file. `capture_file.rs` owns the writing.

/// Block types, little-endian as written.
pub const SHB: u32 = 0x0A0D_0D0A;
pub const IDB: u32 = 0x0000_0001;
pub const ISB: u32 = 0x0000_0005;
pub const EPB: u32 = 0x0000_0006;

const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

const OPT_END: u16 = 0;
const OPT_COMMENT: u16 = 1;
const SHB_HARDWARE: u16 = 2;
const SHB_OS: u16 = 3;
const SHB_USERAPPL: u16 = 4;
const IF_NAME: u16 = 2;
const IF_DESCRIPTION: u16 = 3;
const IF_SPEED: u16 = 8;
const IF_TSRESOL: u16 = 9;
const IF_FILTER: u16 = 11;
const IF_OS: u16 = 12;
const IF_HARDWARE: u16 = 15;
const ISB_STARTTIME: u16 = 2;
const ISB_ENDTIME: u16 = 3;
const ISB_IFRECV: u16 = 4;
const ISB_IFDROP: u16 = 5;

/// The file's opening block.
pub struct SectionHeader<'a> {
    pub hardware: Option<&'a str>,
    pub os: Option<&'a str>,
    pub application: &'a str,
}

/// One adapter.
pub struct InterfaceDescription<'a> {
    pub link_type: u16,
    pub snaplen: u32,
    /// The device, `\Device\NPF_{…}`.
    pub name: &'a str,
    /// Windows' name for the connection: "Ethernet".
    pub description: Option<&'a str>,
    /// Bits per second, when known. Omitted at 0, as dumpcap omits it.
    pub speed: u64,
    /// Decimal places of a second in this interface's timestamps: 9 or 6.
    /// Written only when it is not 6, which the spec makes the default.
    pub ts_resolution: u8,
    /// The libpcap capture filter, when there was one.
    pub filter: Option<&'a str>,
    pub os: Option<&'a str>,
    /// The adapter's model, as Npcap describes it.
    pub hardware: Option<&'a str>,
}

/// One adapter's counters, when a file closes.
pub struct InterfaceStatistics<'a> {
    pub interface_id: u32,
    /// The block's own timestamp, in the interface's units.
    pub timestamp: u64,
    pub comment: Option<&'a str>,
    pub start: Option<u64>,
    pub end: Option<u64>,
    /// Frames received. `None` when it could not be read, and then omitted -
    /// never written as 0.
    pub received: Option<u64>,
    /// Frames lost, by the driver and by the agent. `None` as above.
    pub dropped: Option<u64>,
}

/// Appends the SHB.
pub fn section_header(out: &mut Vec<u8>, shb: &SectionHeader) {
    let mut body = Vec::with_capacity(160);
    body.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(-1i64).to_le_bytes());
    let mut options = Options::default();
    options.text(SHB_HARDWARE, shb.hardware);
    options.text(SHB_OS, shb.os);
    options.text(SHB_USERAPPL, Some(shb.application));
    options.finish_into(&mut body);
    block(out, SHB, &body);
}

/// Appends one IDB.
pub fn interface_description(out: &mut Vec<u8>, idb: &InterfaceDescription) {
    let mut body = Vec::with_capacity(192);
    body.extend_from_slice(&idb.link_type.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&idb.snaplen.to_le_bytes());
    let mut options = Options::default();
    options.text(IF_NAME, Some(idb.name));
    options.text(IF_DESCRIPTION, idb.description);
    if idb.speed != 0 {
        options.raw(IF_SPEED, &idb.speed.to_le_bytes());
    }
    if idb.ts_resolution != 6 {
        options.raw(IF_TSRESOL, &[idb.ts_resolution]);
    }
    if let Some(filter) = idb.filter {
        // The first byte says which language the filter is in: 0, libpcap's.
        let mut value = Vec::with_capacity(filter.len() + 1);
        value.push(0);
        value.extend_from_slice(filter.as_bytes());
        options.raw(IF_FILTER, &value);
    }
    options.text(IF_OS, idb.os);
    options.text(IF_HARDWARE, idb.hardware);
    options.finish_into(&mut body);
    block(out, IDB, &body);
}

/// Appends one EPB. `timestamp` is in the interface's units.
pub fn enhanced_packet(out: &mut Vec<u8>, interface_id: u32, timestamp: u64, captured: &[u8], original_len: u32) {
    let padded = captured.len().next_multiple_of(4);
    let total = 32 + padded;
    out.reserve(total);
    out.extend_from_slice(&EPB.to_le_bytes());
    out.extend_from_slice(&(total as u32).to_le_bytes());
    out.extend_from_slice(&interface_id.to_le_bytes());
    out.extend_from_slice(&((timestamp >> 32) as u32).to_le_bytes());
    out.extend_from_slice(&(timestamp as u32).to_le_bytes());
    out.extend_from_slice(&(captured.len() as u32).to_le_bytes());
    out.extend_from_slice(&original_len.to_le_bytes());
    out.extend_from_slice(captured);
    out.resize(out.len() + (padded - captured.len()), 0);
    out.extend_from_slice(&(total as u32).to_le_bytes());
}

/// How long `enhanced_packet` makes a frame of this many captured bytes -
/// what a ring file's size limit counts.
pub fn enhanced_packet_len(captured: usize) -> usize {
    32 + captured.next_multiple_of(4)
}

/// Appends one ISB.
pub fn interface_statistics(out: &mut Vec<u8>, isb: &InterfaceStatistics) {
    let mut body = Vec::with_capacity(96);
    body.extend_from_slice(&isb.interface_id.to_le_bytes());
    body.extend_from_slice(&((isb.timestamp >> 32) as u32).to_le_bytes());
    body.extend_from_slice(&(isb.timestamp as u32).to_le_bytes());
    let mut options = Options::default();
    options.text(OPT_COMMENT, isb.comment);
    if let Some(start) = isb.start {
        options.raw(ISB_STARTTIME, &split_timestamp(start));
    }
    if let Some(end) = isb.end {
        options.raw(ISB_ENDTIME, &split_timestamp(end));
    }
    if let Some(received) = isb.received {
        options.raw(ISB_IFRECV, &received.to_le_bytes());
    }
    if let Some(dropped) = isb.dropped {
        options.raw(ISB_IFDROP, &dropped.to_le_bytes());
    }
    options.finish_into(&mut body);
    block(out, ISB, &body);
}

/// A pcapng timestamp option: the high 32 bits, then the low, each
/// little-endian - not a u64.
fn split_timestamp(value: u64) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&((value >> 32) as u32).to_le_bytes());
    bytes[4..].copy_from_slice(&(value as u32).to_le_bytes());
    bytes
}

/// type, total length, body, total length again.
fn block(out: &mut Vec<u8>, block_type: u32, body: &[u8]) {
    let total = (12 + body.len()) as u32;
    out.extend_from_slice(&block_type.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}

/// An option list: code, length, value, padding to four bytes, and an end
/// marker only when there was an option at all.
#[derive(Default)]
struct Options {
    bytes: Vec<u8>,
}

impl Options {
    fn text(&mut self, code: u16, value: Option<&str>) {
        if let Some(value) = value {
            self.raw(code, value.as_bytes());
        }
    }

    fn raw(&mut self, code: u16, value: &[u8]) {
        // An option's length is a u16; a longer string is cut rather than
        // wrapping into a length that would misframe everything after it.
        let value = &value[..value.len().min(u16::MAX as usize - 3)];
        self.bytes.extend_from_slice(&code.to_le_bytes());
        self.bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        self.bytes.extend_from_slice(value);
        self.bytes.resize(self.bytes.len().next_multiple_of(4), 0);
    }

    fn finish_into(self, body: &mut Vec<u8>) {
        if self.bytes.is_empty() {
            return;
        }
        body.extend_from_slice(&self.bytes);
        body.extend_from_slice(&OPT_END.to_le_bytes());
        body.extend_from_slice(&0u16.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    //! Held to the two captures dumpcap itself wrote, in `test/fixtures/`.
    //! Every block is parsed back into the facts it carries and rebuilt here;
    //! the rebuilt bytes must be the file's bytes. Real files only - the
    //! owner's rule - and a `SKIP` without them.
    use super::*;
    use crate::fixture;

    struct Block<'a> {
        kind: u32,
        bytes: &'a [u8],
    }

    fn blocks(file: &[u8]) -> Vec<Block<'_>> {
        let mut out = Vec::new();
        let mut at = 0;
        while at + 12 <= file.len() {
            let kind = u32::from_le_bytes(file[at..at + 4].try_into().unwrap());
            let len = u32::from_le_bytes(file[at + 4..at + 8].try_into().unwrap()) as usize;
            assert!(len >= 12 && len % 4 == 0 && at + len <= file.len(), "a torn block at {at}");
            out.push(Block { kind, bytes: &file[at..at + len] });
            at += len;
        }
        assert_eq!(at, file.len(), "trailing bytes after the last block");
        out
    }

    /// `(code, value)` for every option in a block, from `offset` into it.
    fn options(block: &[u8], offset: usize) -> Vec<(u16, Vec<u8>)> {
        let mut out = Vec::new();
        let mut at = offset;
        let end = block.len() - 4;
        while at + 4 <= end {
            let code = u16::from_le_bytes([block[at], block[at + 1]]);
            let len = u16::from_le_bytes([block[at + 2], block[at + 3]]) as usize;
            if code == OPT_END {
                break;
            }
            out.push((code, block[at + 4..at + 4 + len].to_vec()));
            at += 4 + len.next_multiple_of(4);
        }
        out
    }

    fn text(options: &[(u16, Vec<u8>)], code: u16) -> Option<String> {
        options.iter().find(|(c, _)| *c == code).map(|(_, v)| String::from_utf8(v.clone()).unwrap())
    }

    fn u64_of(options: &[(u16, Vec<u8>)], code: u16) -> Option<u64> {
        options.iter().find(|(c, _)| *c == code).map(|(_, v)| u64::from_le_bytes(v[..8].try_into().unwrap()))
    }

    fn timestamp_of(options: &[(u16, Vec<u8>)], code: u16) -> Option<u64> {
        options.iter().find(|(c, _)| *c == code).map(|(_, v)| {
            let high = u32::from_le_bytes(v[..4].try_into().unwrap()) as u64;
            let low = u32::from_le_bytes(v[4..8].try_into().unwrap()) as u64;
            (high << 32) | low
        })
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn every_block_of_a_dumpcap_file_is_rebuilt_byte_for_byte() {
        let mut checked = 0;
        for file in fixture::DUMPCAP_CAPTURES {
            let Some(bytes) = fixture::file_bytes(file) else { continue };
            let mut counts = [0usize; 4];
            for block in blocks(&bytes) {
                let mut rebuilt = Vec::new();
                match block.kind {
                    SHB => {
                        let o = options(block.bytes, 24);
                        let application = text(&o, SHB_USERAPPL).unwrap();
                        section_header(&mut rebuilt, &SectionHeader {
                            hardware: text(&o, SHB_HARDWARE).as_deref(),
                            os: text(&o, SHB_OS).as_deref(),
                            application: &application,
                        });
                        counts[0] += 1;
                    }
                    IDB => {
                        let o = options(block.bytes, 16);
                        let filter = o.iter().find(|(c, _)| *c == IF_FILTER).map(|(_, v)| {
                            assert_eq!(v[0], 0, "a filter in libpcap's syntax starts with 0");
                            String::from_utf8(v[1..].to_vec()).unwrap()
                        });
                        let name = text(&o, IF_NAME).unwrap();
                        interface_description(&mut rebuilt, &InterfaceDescription {
                            link_type: u16::from_le_bytes([block.bytes[8], block.bytes[9]]),
                            snaplen: u32_at(block.bytes, 12),
                            name: &name,
                            description: text(&o, IF_DESCRIPTION).as_deref(),
                            speed: u64_of(&o, IF_SPEED).unwrap_or(0),
                            ts_resolution: o.iter().find(|(c, _)| *c == IF_TSRESOL).map_or(6, |(_, v)| v[0]),
                            filter: filter.as_deref(),
                            os: text(&o, IF_OS).as_deref(),
                            hardware: text(&o, IF_HARDWARE).as_deref(),
                        });
                        counts[1] += 1;
                    }
                    EPB => {
                        let b = block.bytes;
                        let captured = u32_at(b, 20) as usize;
                        let timestamp = ((u32_at(b, 12) as u64) << 32) | u32_at(b, 16) as u64;
                        enhanced_packet(&mut rebuilt, u32_at(b, 8), timestamp, &b[28..28 + captured], u32_at(b, 24));
                        assert_eq!(rebuilt.len(), enhanced_packet_len(captured));
                        counts[2] += 1;
                    }
                    ISB => {
                        let b = block.bytes;
                        let o = options(b, 20);
                        interface_statistics(&mut rebuilt, &InterfaceStatistics {
                            interface_id: u32_at(b, 8),
                            timestamp: ((u32_at(b, 12) as u64) << 32) | u32_at(b, 16) as u64,
                            comment: text(&o, OPT_COMMENT).as_deref(),
                            start: timestamp_of(&o, ISB_STARTTIME),
                            end: timestamp_of(&o, ISB_ENDTIME),
                            received: u64_of(&o, ISB_IFRECV),
                            dropped: u64_of(&o, ISB_IFDROP),
                        });
                        counts[3] += 1;
                    }
                    other => panic!("{file}: a block of type {other:#x} this writer does not make"),
                }
                assert_eq!(rebuilt.as_slice(), block.bytes, "{file}: block {:#x} differs", block.kind);
            }
            eprintln!("{file}: {} SHB, {} IDB, {} EPB, {} ISB rebuilt byte for byte",
                counts[0], counts[1], counts[2], counts[3]);
            assert!(counts[0] == 1 && counts[1] >= 1 && counts[2] > 0 && counts[3] >= 1);
            checked += 1;
        }
        if checked == 0 {
            eprintln!("SKIP  no dumpcap-written fixture present");
        }
    }

    #[test]
    fn a_block_with_nothing_optional_carries_no_end_marker() {
        // What the spec requires, and what an ISB for an adapter whose
        // counters could not be read comes to.
        let mut out = Vec::new();
        interface_statistics(&mut out, &InterfaceStatistics {
            interface_id: 3, timestamp: 0, comment: None, start: None, end: None, received: None, dropped: None,
        });
        assert_eq!(out.len(), 12 + 12);
        assert_eq!(u32_at(&out, 4), 24);
        assert_eq!(u32_at(&out, 20), 24);
    }
}
