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
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Counters {
    pub packets: u64,
    pub bytes: u64,
}

/// The rate on one adapter, as the app's `AgentInterfaceRate`.
#[derive(Clone, Debug, PartialEq)]
pub struct Rate {
    pub name: String,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
}

/// The key `\Device\NPF_Loopback` is joined under.
///
/// It carries no GUID, and the Python agent reaches the loopback pseudo-
/// interface's counters by matching the label's prefix against psutil's names.
/// That interface is the row whose type is `IF_TYPE_SOFTWARE_LOOPBACK`, so that
/// is what it is joined to here.
const LOOPBACK_KEY: &str = "loopback";

/// Which counter row a capture device's rate is read from.
fn counter_key(device: &str) -> Option<String> {
    if device.eq_ignore_ascii_case(r"\Device\NPF_Loopback") {
        return Some(LOOPBACK_KEY.to_string());
    }
    crate::adapters::guid_of(device)
}

/// Python's `round(x, 2)`: the value's exact decimal expansion rounded half to
/// even, then the nearest double to that. Formatting to two places does the
/// first half exactly and parsing does the second; `(x * 100).round() / 100`
/// would round the product's error instead of the value.
pub fn round2(x: f64) -> f64 {
    format!("{x:.2}").parse().unwrap_or(x)
}

/// Every counter row now, keyed by GUID in the braces-uppercase form
/// `adapters::guid_of` produces, plus the loopback row under its own key.
///
/// The GUID join is what ADR 0037 calls the one part of this port that gets
/// *easier*: `\Device\NPF_{GUID}` already carries it, where the Python agent
/// matches `psutil`'s names by longest common prefix.
pub fn read_counters() -> HashMap<String, Counters> {
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
            let counters = Counters {
                // In and out together: the panel draws what the adapter is
                // carrying, not what it is receiving - psutil's
                // `packets_sent + packets_recv`, each unicast plus non-unicast,
                // and `bytes_sent + bytes_recv`.
                packets: row.in_ucast_pkts
                    .wrapping_add(row.in_nucast_pkts)
                    .wrapping_add(row.out_ucast_pkts)
                    .wrapping_add(row.out_nucast_pkts),
                bytes: row.in_octets.wrapping_add(row.out_octets),
            };
            if row.if_type == crate::adapters::IF_TYPE_SOFTWARE_LOOPBACK {
                out.entry(LOOPBACK_KEY.to_string()).or_insert(counters);
            }
            out.insert(guid, counters);
        }
        FreeMibTable(table as *mut c_void);
    }
    out
}

/// One tick's rates, from two readings - `InterfaceRateSampler.sample`'s
/// arithmetic, pure.
///
/// **An entry for every device, always.** The app rebuilds its rate map from
/// each message alone, so a device missing from one tick loses its history -
/// and a flat line is the honest rendering of an adapter nothing is known
/// about. Zero, then, when there is no previous reading, no time between the
/// two, no counter row for the device, or a counter that went backwards (an
/// adapter reset, or a row that vanished and came back - reporting the negative
/// difference would draw a spike that never happened).
pub fn rates_between(
    devices: &[String],
    previous: Option<&HashMap<String, Counters>>,
    current: &HashMap<String, Counters>,
    elapsed: f64,
) -> Vec<Rate> {
    devices
        .iter()
        .map(|device| {
            let (mut packets, mut bytes) = (0.0, 0.0);
            if let (Some(key), Some(previous)) = (counter_key(device), previous) {
                if let (Some(now), Some(then)) = (current.get(&key), previous.get(&key)) {
                    if elapsed > 0.0 && now.packets >= then.packets && now.bytes >= then.bytes {
                        packets = (now.packets - then.packets) as f64 / elapsed;
                        bytes = (now.bytes - then.bytes) as f64 / elapsed;
                    }
                }
            }
            Rate {
                name: device.clone(),
                packets_per_sec: round2(packets),
                bytes_per_sec: round2(bytes),
            }
        })
        .collect()
}

/// Samples the OS counters and differences them against the previous reading.
///
/// **One per subscription, and its device list is the one it was made with** -
/// `agent.py` builds its `InterfaceRateSampler(AVAILABLE_INTERFACES)` when the
/// sampling task starts, and a sampler kept alive across a gap would report one
/// spike covering however long the panel was closed.
pub struct RateSampler {
    devices: Vec<String>,
    previous: Option<HashMap<String, Counters>>,
    taken_at: Option<Instant>,
}

impl RateSampler {
    pub fn new(devices: Vec<String>) -> Self {
        Self { devices, previous: None, taken_at: None }
    }

    /// The rate for each device since the last call - zeros on the first.
    ///
    /// Against the time that really passed, on a monotonic clock read before
    /// the counters are, as `agent.py` passes `time.monotonic()` in: a late tick
    /// reports the rate over the interval that happened.
    pub fn sample(&mut self) -> Vec<Rate> {
        let now = Instant::now();
        let current = read_counters();
        let elapsed = self.taken_at.map(|t| now.duration_since(t).as_secs_f64()).unwrap_or(0.0);
        let rates = rates_between(&self.devices, self.previous.as_ref(), &current, elapsed);
        self.previous = Some(current);
        self.taken_at = Some(now);
        rates
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
        let sample = read_counters();
        assert!(!sample.is_empty(), "GetIfTable2 returned no adapters");
        // Every key is a braces-uppercase GUID, which is the form `guid_of`
        // produces - the join depends on the two agreeing exactly - or the
        // one loopback key.
        for key in sample.keys().filter(|k| k.as_str() != LOOPBACK_KEY) {
            assert!(key.starts_with('{') && key.ends_with('}'), "not a GUID: {key}");
            assert_eq!(key.len(), 38, "not a GUID: {key}");
            assert_eq!(key.to_uppercase(), *key, "GUIDs join uppercased: {key}");
        }
        assert!(sample.contains_key(LOOPBACK_KEY), "no IF_TYPE_SOFTWARE_LOOPBACK row");
    }

    /// The first sample is zeros for every device - not nothing. There is no
    /// interval yet, and a number from one absolute reading is the total since
    /// boot; but an absent entry wipes that device's history in the app.
    #[test]
    fn the_first_sample_is_a_zero_for_every_device() {
        let devices = vec![
            r"\Device\NPF_{64455981-5CEF-4A70-8218-4E5C316C795B}".to_string(),
            r"\Device\NPF_{00000000-0000-0000-0000-000000000000}".to_string(),
            r"\Device\NPF_Loopback".to_string(),
        ];
        let rates = RateSampler::new(devices.clone()).sample();
        assert_eq!(rates.len(), devices.len());
        for (rate, device) in rates.iter().zip(&devices) {
            assert_eq!(&rate.name, device);
            assert_eq!((rate.packets_per_sec, rate.bytes_per_sec), (0.0, 0.0));
        }
    }

    /// The arithmetic, against the second sample the Python agent took on this
    /// machine for the wired adapter: 159.46 packets and 97,203.76 bytes a
    /// second - here as 7,973 packets and 4,860,188 bytes over 50 s, which is
    /// those two rates - and the two ways to a zero beside it.
    #[test]
    fn a_rate_is_the_difference_over_the_interval_rounded_to_two_places() {
        let wired = r"\Device\NPF_{64455981-5CEF-4A70-8218-4E5C316C795B}".to_string();
        let gone = r"\Device\NPF_{60B3A293-2623-4856-9CBB-CC2F7BA81A25}".to_string();
        let reset = r"\Device\NPF_{BEE4DB11-2AFA-4426-BA16-C443DE930911}".to_string();
        let key = |d: &String| counter_key(d).unwrap();
        let mut before = HashMap::new();
        before.insert(key(&wired), Counters { packets: 1_000_000, bytes: 900_000_000 });
        before.insert(key(&reset), Counters { packets: 50, bytes: 5000 });
        let mut after = HashMap::new();
        after.insert(key(&wired), Counters { packets: 1_007_973, bytes: 904_860_188 });
        // Went backwards: the adapter was reset. Unknown, so zero.
        after.insert(key(&reset), Counters { packets: 10, bytes: 1000 });
        let rates = rates_between(&[wired, gone, reset], Some(&before), &after, 50.0);
        assert_eq!((rates[0].packets_per_sec, rates[0].bytes_per_sec), (159.46, 97203.76));
        assert_eq!((rates[1].packets_per_sec, rates[1].bytes_per_sec), (0.0, 0.0));
        assert_eq!((rates[2].packets_per_sec, rates[2].bytes_per_sec), (0.0, 0.0));
        // No interval at all is no rate, not a division by zero.
        let flat = rates_between(&[r"\Device\NPF_{64455981-5CEF-4A70-8218-4E5C316C795B}".into()],
            Some(&before), &after, 0.0);
        assert_eq!(flat[0].packets_per_sec, 0.0);
    }

    /// Python's `round(x, 2)` is half-to-even on the value's exact expansion.
    /// Each expected value is what Python printed for the input.
    #[test]
    fn rounding_is_pythons() {
        assert_eq!(round2(0.125), 0.12);
        assert_eq!(round2(0.375), 0.38);
        assert_eq!(round2(2.675), 2.67);
        assert_eq!(round2(1.005), 1.0);
        assert_eq!(round2(159.4583333), 159.46);
        assert_eq!(round2(0.0), 0.0);
    }
}
