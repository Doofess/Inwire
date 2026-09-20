//! Per-adapter traffic counters, for the Interfaces panel's sparklines.
//!
//! ## Why this exists
//!
//! The app subscribes to `interface_stats` when the Interfaces panel mounts and
//! draws a rate per adapter from what comes back. The Rust agent parsed the
//! subscription and answered with a generic `state`, so the app subscribed
//! successfully and then waited for rates that never arrived - a flat graph
//! rather than an absent feature, with nothing erroring anywhere. ADR 0037
//! records it as the gap its own "not ported" list missed.
//!
//! **This is not the capture's own counters.** `capture_stats` says what the
//! capture received and lost; this says what every adapter is carrying, whether
//! or not it is being captured on. That is the panel's whole question - *is
//! traffic arriving on an adapter I am not capturing on?* - and it is the
//! documented mitigation for picking the wrong adapter, which makes it the one
//! surface that could have revealed the single-adapter truncation.
//!
//! ## `MIB_IF_ROW2`, and why not the simpler one
//!
//! `MIB_IFROW`'s octet counters are 32 bits and wrap about every 34 seconds on
//! a gigabit link. ADR 0037 calls for the 64-bit ones for that reason. A
//! wrapping subtraction would in fact be correct at a 500 ms cadence, but the
//! 64-bit row is the answer that stays correct when the cadence changes, and
//! the ADR is the decision of record.
//!
//! The cost is that `MIB_IF_ROW2` is a 1,352-byte struct whose counters sit
//! past forty other fields, so **the layout is asserted at compile time**
//! rather than trusted: a wrong offset anywhere above the counters shifts them
//! all, and the symptom would be plausible-looking numbers rather than a crash.

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::time::Instant;

#[link(name = "iphlpapi")]
extern "system" {
    fn GetIfTable2(table: *mut *mut MibIfTable2) -> u32;
    fn FreeMibTable(memory: *mut c_void);
}

const ERROR_SUCCESS: u32 = 0;

/// `GUID`. Declared rather than skipped because its alignment (4, not 8) is
/// what places every field after it.
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

/// `MIB_IF_ROW2`, in full.
///
/// Declared to the end rather than truncated at the counters: the size
/// assertion below is only meaningful against the whole struct, and that
/// assertion is the entire safety net for forty-odd offsets nobody can eyeball.
#[repr(C)]
struct MibIfRow2 {
    interface_luid: u64,
    interface_index: u32,
    interface_guid: Guid,
    alias: [u16; 257],
    description: [u16; 257],
    physical_address_length: u32,
    permanent_physical_address: [u8; 32],
    physical_address: [u8; 32],
    mtu: u32,
    if_type: u32,
    tunnel_type: u32,
    media_type: u32,
    physical_medium_type: u32,
    access_type: u32,
    direction_type: u32,
    /// Eight one-bit `BOOLEAN`s in C, which pack into one byte.
    interface_and_oper_status_flags: u8,
    oper_status: u32,
    admin_status: u32,
    media_connect_state: u32,
    network_guid: Guid,
    connection_type: u32,
    transmit_link_speed: u64,
    receive_link_speed: u64,
    in_octets: u64,
    in_ucast_pkts: u64,
    in_nucast_pkts: u64,
    in_discards: u64,
    in_errors: u64,
    in_unknown_protos: u64,
    in_ucast_octets: u64,
    in_multicast_octets: u64,
    in_broadcast_octets: u64,
    out_octets: u64,
    out_ucast_pkts: u64,
    out_nucast_pkts: u64,
    out_discards: u64,
    out_errors: u64,
    out_ucast_octets: u64,
    out_multicast_octets: u64,
    out_broadcast_octets: u64,
    out_qlen: u64,
}

/// **The safety net.** `MIB_IF_ROW2` is 1,352 bytes on x64, and every field
/// above the counters places them. If a type or an alignment here is wrong the
/// size moves and this stops compiling - which is the only way to catch it,
/// since the failure mode otherwise is numbers that look like numbers.
const _: () = assert!(std::mem::size_of::<MibIfRow2>() == 1352);

#[repr(C)]
struct MibIfTable2 {
    num_entries: u32,
    /// The table starts here. The header is a `ULONG` followed by the first
    /// row, which aligns to 8 - so the rows begin at offset 8, not 4, and the
    /// one-element array is how that padding is expressed.
    table: [MibIfRow2; 1],
}

/// One adapter's counters at one instant.
#[derive(Clone, Copy)]
struct Counters {
    packets: u64,
    bytes: u64,
}

/// The rate on one adapter, as the app's `AgentInterfaceRate`.
pub struct Rate {
    pub name: String,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
}

/// Samples the OS counters and differences them against the previous reading.
///
/// Holds its own previous sample, so the first call after a subscription
/// produces nothing - there is no interval to divide by yet, and a rate
/// invented from a single absolute reading would be the total since boot drawn
/// as a spike.
pub struct RateSampler {
    previous: HashMap<String, Counters>,
    taken_at: Option<Instant>,
}

impl RateSampler {
    pub fn new() -> Self {
        Self { previous: HashMap::new(), taken_at: None }
    }

    /// Every adapter's counters now, keyed by GUID in the braces-uppercase form
    /// `adapters::guid_of` produces.
    ///
    /// The GUID join is what ADR 0037 calls the one part of this port that gets
    /// *easier*: `\Device\NPF_{GUID}` already carries it, where the Python agent
    /// matches `psutil`'s names by longest common prefix.
    fn sample() -> HashMap<String, Counters> {
        let mut out = HashMap::new();
        let mut table: *mut MibIfTable2 = std::ptr::null_mut();
        if unsafe { GetIfTable2(&mut table) } != ERROR_SUCCESS || table.is_null() {
            return out;
        }
        unsafe {
            let n = (*table).num_entries as usize;
            let rows = (*table).table.as_ptr();
            for i in 0..n {
                let row = &*rows.add(i);
                let g = row.interface_guid;
                let guid = format!(
                    "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
                    g.data1, g.data2, g.data3,
                    g.data4[0], g.data4[1], g.data4[2], g.data4[3],
                    g.data4[4], g.data4[5], g.data4[6], g.data4[7],
                );
                out.insert(guid, Counters {
                    // In and out together: the panel draws what the adapter is
                    // carrying, not what it is receiving.
                    packets: row.in_ucast_pkts
                        .wrapping_add(row.in_nucast_pkts)
                        .wrapping_add(row.out_ucast_pkts)
                        .wrapping_add(row.out_nucast_pkts),
                    bytes: row.in_octets.wrapping_add(row.out_octets),
                });
            }
            FreeMibTable(table as *mut c_void);
        }
        out
    }

    /// The rate for each named device since the last call.
    ///
    /// `devices` are capture device names; the answer is keyed by them, because
    /// that is what the app's `interfaceRates` map is indexed by.
    pub fn rates(&mut self, devices: &[String]) -> Vec<Rate> {
        let now = Instant::now();
        let current = Self::sample();
        let elapsed = self.taken_at.map(|t| now.duration_since(t).as_secs_f64());
        let previous = std::mem::replace(&mut self.previous, current.clone());
        self.taken_at = Some(now);

        // No previous reading, or no time between them: nothing to divide by.
        let Some(elapsed) = elapsed.filter(|e| *e > 0.0) else {
            return Vec::new();
        };

        devices
            .iter()
            .filter_map(|device| {
                let guid = crate::adapters::guid_of(device)?;
                let (now_c, then_c) = (current.get(&guid)?, previous.get(&guid)?);
                // **A counter that went backwards is refused, not negated.**
                // An adapter reset, or a row that disappeared and came back,
                // would otherwise draw a spike out of a number that only fell.
                // `local-agent/interface_stats.py` refuses the same way.
                let packets = now_c.packets.checked_sub(then_c.packets)?;
                let bytes = now_c.bytes.checked_sub(then_c.bytes)?;
                Some(Rate {
                    name: device.clone(),
                    packets_per_sec: packets as f64 / elapsed,
                    bytes_per_sec: bytes as f64 / elapsed,
                })
            })
            .collect()
    }
}

impl Default for RateSampler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The struct's size is asserted at compile time; this is the runtime
    /// half - that the call works at all on this machine and answers with the
    /// adapters it has. A layout error above the counters would still compile
    /// if it happened to preserve the size, and would show here as counters
    /// that do not move.
    #[test]
    fn the_table_can_be_read_and_has_entries() {
        let sample = RateSampler::sample();
        assert!(!sample.is_empty(), "GetIfTable2 returned no adapters");
        // Every key is a braces-uppercase GUID, which is the form `guid_of`
        // produces - the join depends on the two agreeing exactly.
        for key in sample.keys() {
            assert!(key.starts_with('{') && key.ends_with('}'), "not a GUID: {key}");
            assert_eq!(key.len(), 38, "not a GUID: {key}");
            assert_eq!(key.to_uppercase(), *key, "GUIDs join uppercased: {key}");
        }
    }

    /// The first call cannot produce a rate: there is no interval yet, and a
    /// number invented from one absolute reading is the total since boot.
    #[test]
    fn the_first_sample_yields_no_rate() {
        let mut sampler = RateSampler::new();
        let devices = vec![r"\Device\NPF_{00000000-0000-0000-0000-000000000000}".to_string()];
        assert!(sampler.rates(&devices).is_empty());
    }
}
