//! How this machine's adapters are configured - `adapter_config`, field for
//! field with `local-agent/adapters.py`'s Windows provider.
//!
//! ## Why it has to match rather than merely be right
//!
//! The Network panel and the capture picker were written against what the
//! Python agent sends, and three things in the app read this message as a
//! *fact* rather than as a display string: `hostFromAdapters` builds the
//! machine's own MACs and addresses from it (and with them every frame's
//! direction and the checksum verdict), the gateway MAC is compared against the
//! one the capture saw - a mismatch is how ARP spoofing looks from here - and
//! the configured resolvers are compared against the ones queried. A value this
//! agent spelled or sourced differently would not read as a difference between
//! agents; it would read as a finding about the network.
//!
//! This agent sent a `name` that was the whole picker label, a `description`
//! that was the same label again, a loopback entry the Python agent never
//! sends, and nulls for the speed, the DHCP lease, the gateway, the broadcast
//! and the privacy flag.
//!
//! ## Where each value comes from, and why there
//!
//! | field | source | why |
//! |---|---|---|
//! | the list, its order, names, MAC, addresses, resolvers | `GetAdaptersAddresses` with scapy's flags | scapy's `get_windows_if_list` is that call |
//! | `prefixLength`, `temporary` | the same call's unicast rows | `Get-NetIPAddress` reads the same table |
//! | `status`, `speedMbps`, `mtu` | `GetIfTable`, joined as psutil joins it | psutil's `net_if_stats` is that call |
//! | DHCP, lease, IPv4 gateway, gateway MAC, domain, static DNS | the registry | the only place the lease is kept |
//! | IPv6 gateway, fallback IPv4 gateway | `GetIpForwardTable2` | what `Get-NetRoute` reads |
//! | fallback gateway MAC | `GetIpNetTable2` | what `Get-NetNeighbor` reads |
//!
//! **The registry is read where the Python agent reads it, even where a Win32
//! field looks equivalent**, because it is not: on this machine the Wi-Fi
//! adapter is disconnected and the registry still holds its last lease, server
//! and gateway - `GetAdaptersAddresses`' `Dhcpv4Server` is empty for it, its
//! `LeaseLifetime` is relative rather than an epoch, and its gateway list is
//! empty. Same machine, different answer, so not the same field.
//!
//! **No PowerShell.** The Python agent spawns one (half a second, measured) to
//! read prefix lengths, suffix origins, default routes and neighbours, and
//! caches it against the address list. Every one of those is a table
//! `iphlpapi` hands over directly, so this reads them on every poll in
//! microseconds and has no cache to go stale - which is also why a changed
//! gateway MAC shows here on the next poll where the Python agent waits for
//! an address to move or for Refresh.
//!
//! **Anything a provider cannot supply is `None`, and never a guess.**

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde_json::Value;

use crate::adapters::{self, format_ipv6, WinAdapter};
use crate::protocol::{self, AdapterIpv4, AdapterIpv6, AdapterReport, AdapterSource};

// --- the pure half: `adapters.py`'s helpers, ported ---------------------------

/// Python's `str.isspace`, which is Rust's `is_whitespace` plus the four
/// information separators U+001C..U+001F. `str.strip()` and `\s` both use it.
fn py_isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `adapters.py`'s `_BIDI_MARKS`: LRM, RLM and the five embedding/override
/// controls. Windows prefixes adapter names with these on a machine set to an
/// RTL locale, and they are invisible.
const BIDI_MARKS: [char; 7] =
    ['\u{200e}', '\u{200f}', '\u{202a}', '\u{202b}', '\u{202c}', '\u{202d}', '\u{202e}'];

/// `_text`: trimmed, bidi marks stripped from the ends, trimmed again - and an
/// empty result is no value at all.
pub fn py_text(value: &str) -> Option<String> {
    let t = value.trim_matches(py_isspace);
    let t = t.trim_matches(|c| BIDI_MARKS.contains(&c));
    let t = t.trim_matches(py_isspace);
    (!t.is_empty()).then(|| t.to_string())
}

/// `_strip_zone`: an IPv6 zone index dropped, because a captured frame carries
/// `fe80::1` and the OS says `fe80::1%8`.
pub fn strip_zone(address: &str) -> Option<String> {
    let text = py_text(address)?;
    Some(match text.find('%') {
        Some(at) => text[..at].to_string(),
        None => text,
    })
}

/// `_mac`: dashes become colons, lowercase, and only the six-octet shape is a
/// MAC. `Get-NetNeighbor` writes `44-15-24-5D-CC-62`.
pub fn py_mac(text: &str) -> Option<String> {
    let text = py_text(text)?.replace('-', ":").to_lowercase();
    let octets: Vec<&str> = text.split(':').collect();
    let ok = octets.len() == 6
        && octets.iter().all(|o| o.len() == 2 && o.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then_some(text)
}

/// `_broadcast`: the IPv4 broadcast address, computed rather than reported -
/// Windows reports none, and it is arithmetic the OS declined to do. A prefix
/// past 32 is not a network, which Python's `ip_network` refuses.
pub fn broadcast(address: Ipv4Addr, prefix_length: Option<u8>) -> Option<String> {
    let prefix = prefix_length?;
    if prefix > 32 {
        return None;
    }
    // `checked_shr`, because a shift by 32 is not zero in Rust - it is
    // masked to a shift by 0 in a release build, which made a /32 broadcast
    // to everything. The test below caught exactly that.
    let host_bits = u32::MAX.checked_shr(prefix as u32).unwrap_or(0);
    Some(Ipv4Addr::from(u32::from(address) | host_bits).to_string())
}

/// `NL_SUFFIX_ORIGIN`'s `IpSuffixOriginRandom`: an RFC 4941 privacy address,
/// what `ipconfig /all` calls "Temporary". It rotates, so a capture taken
/// yesterday will not carry it.
pub const SUFFIX_ORIGIN_RANDOM: u32 = 5;

pub fn is_temporary(suffix_origin: u32) -> bool {
    suffix_origin == SUFFIX_ORIGIN_RANDOM
}

/// `v4` is inside `net/len`.
fn in_v4(v4: u32, net: [u8; 4], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    v4 & mask == u32::from(Ipv4Addr::from(net)) & mask
}

fn in_v6(v6: u128, net: [u16; 8], len: u32) -> bool {
    let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
    v6 & mask == u128::from(Ipv6Addr::from(net)) & mask
}

/// Python 3.13's `IPv4Address.is_private`, for the one path that reaches it:
/// an IPv4-mapped IPv6 address, which `ipaddress` classifies by its IPv4 half.
fn v4_is_private(v4: u32) -> bool {
    const PRIVATE: [([u8; 4], u32); 14] = [
        ([0, 0, 0, 0], 8), ([10, 0, 0, 0], 8), ([127, 0, 0, 0], 8), ([169, 254, 0, 0], 16),
        ([172, 16, 0, 0], 12), ([192, 0, 0, 0], 24), ([192, 0, 0, 170], 31),
        ([192, 0, 2, 0], 24), ([192, 168, 0, 0], 16), ([198, 18, 0, 0], 15),
        ([198, 51, 100, 0], 24), ([203, 0, 113, 0], 24), ([240, 0, 0, 0], 4),
        ([255, 255, 255, 255], 32),
    ];
    const EXCEPTIONS: [([u8; 4], u32); 2] = [([192, 0, 0, 9], 32), ([192, 0, 0, 10], 32)];
    PRIVATE.iter().any(|(n, l)| in_v4(v4, *n, *l))
        && EXCEPTIONS.iter().all(|(n, l)| !in_v4(v4, *n, *l))
}

/// `adapters.py`'s `address_scope` for an IPv6 address: `loopback`,
/// `link-local`, `ula` or `global`.
///
/// **Ported with Python's semantics rather than the RFC's**, because the app
/// groups addresses by this and the two agents must group the same address the
/// same way. `ula` there is `is_private and not is_global`, and Python 3.13's
/// `is_private` is IANA's "not globally reachable" list - so a 6to4 (`2002::/16`),
/// a documentation (`2001:db8::/32`) or a Teredo (`2001::/32`, inside
/// `2001::/23`) address is `ula` too, not only `fc00::/7`. Multicast is not in
/// that list and comes out `global`, as Python has it.
pub fn address_scope(ip: &Ipv6Addr) -> &'static str {
    if let Some(v4) = ip.to_ipv4_mapped() {
        let v4 = u32::from(v4);
        // `is_loopback` and `is_link_local` defer to the IPv4 half too.
        if in_v4(v4, [127, 0, 0, 0], 8) {
            return "loopback";
        }
        if in_v4(v4, [169, 254, 0, 0], 16) {
            return "link-local";
        }
        // `is_global` for a mapped address is the IPv4 one, which also excludes
        // 100.64.0.0/10 - so a mapped CGNAT address is neither private nor
        // global, and falls through to "global" in `address_scope`.
        let global = !in_v4(v4, [100, 64, 0, 0], 10) && !v4_is_private(v4);
        return if v4_is_private(v4) && !global { "ula" } else { "global" };
    }
    let v6 = u128::from(*ip);
    if v6 == 1 {
        return "loopback";
    }
    if in_v6(v6, [0xfe80, 0, 0, 0, 0, 0, 0, 0], 10) {
        return "link-local";
    }
    const PRIVATE: [([u16; 8], u32); 11] = [
        ([0, 0, 0, 0, 0, 0, 0, 1], 128),
        ([0, 0, 0, 0, 0, 0, 0, 0], 128),
        ([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
        ([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
        ([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
        ([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
        ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
        ([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
        ([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
        ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
        ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    ];
    const EXCEPTIONS: [([u16; 8], u32); 6] = [
        ([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
        ([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
        ([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
        ([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
        ([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
        ([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
    ];
    let private = PRIVATE.iter().any(|(n, l)| in_v6(v6, *n, *l))
        && EXCEPTIONS.iter().all(|(n, l)| !in_v6(v6, *n, *l));
    // For a non-mapped address `is_global` is exactly `not is_private`, so
    // "private and not global" is "private".
    if private { "ula" } else { "global" }
}

/// `decode_gateway_hardware`: `DhcpGatewayHardware` is a packed record per
/// gateway - 4 bytes of IPv4 address, a 32-bit little-endian hardware length,
/// then that many bytes. Walked until it runs out rather than trusting
/// `DhcpGatewayHardwareCount`, which is a separate value a half-written key
/// could disagree with. A later record for the same gateway replaces an
/// earlier one, as a Python dict does.
pub fn decode_gateway_hardware(blob: &[u8]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    let mut at = 0usize;
    while at + 8 <= blob.len() {
        let address = Ipv4Addr::new(blob[at], blob[at + 1], blob[at + 2], blob[at + 3]);
        let length =
            u32::from_le_bytes([blob[at + 4], blob[at + 5], blob[at + 6], blob[at + 7]]) as usize;
        let start = at + 8;
        if length == 0 || start + length > blob.len() {
            break;
        }
        let text = blob[start..start + length]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        if let Some(mac) = py_mac(&text) {
            out.insert(address.to_string(), mac);
        }
        at = start + length;
    }
    out
}

/// `re.split(r"[\s,]+", text)` with the empty parts dropped - how
/// `NameServer` and `DhcpNameServer` hold several resolvers in one string.
pub fn split_resolvers(text: &str) -> Vec<String> {
    text.split(|c: char| py_isspace(c) || c == ',')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

/// The first occurrence of each, in order.
pub fn dedupe_keep_first(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    items.into_iter().filter(|item| seen.insert(item.clone())).collect()
}

// --- the registry -------------------------------------------------------------

/// A registry value, as Python's `winreg` hands it back - which is the shape
/// every rule in `adapters.py` was written against.
#[derive(Clone, Debug, PartialEq)]
pub enum RegValue {
    /// `REG_SZ` / `REG_EXPAND_SZ`, cut at the first NUL.
    Str(String),
    /// `REG_MULTI_SZ`: a list, ending at the first empty string.
    Strs(Vec<String>),
    /// `REG_DWORD` / `REG_QWORD`.
    Int(u64),
    /// Anything else with bytes in it.
    Bytes(Vec<u8>),
    /// A binary value with no bytes, which `winreg` returns as `None`.
    Nothing,
}

impl RegValue {
    /// `_text(value)` - `str()` of it, cleaned. A list or a byte string is
    /// `None` here where Python would stringify its repr; no value `adapters.py`
    /// passes through `_text` is ever either type on Windows, and the one that
    /// is a list (`SubnetMask`) is read by nothing here.
    fn text(&self) -> Option<String> {
        match self {
            RegValue::Str(s) => py_text(s),
            RegValue::Int(n) => Some(n.to_string()),
            _ => None,
        }
    }

    /// `_as_list(value)`: a list as itself, anything else as a list of one.
    fn texts(&self) -> Vec<Option<String>> {
        match self {
            RegValue::Strs(list) => list.iter().map(|s| py_text(s)).collect(),
            RegValue::Nothing => Vec::new(),
            other => vec![other.text()],
        }
    }

    /// Python's truthiness, for `bool(EnableDHCP)`.
    fn truthy(&self) -> bool {
        match self {
            RegValue::Str(s) => !s.is_empty(),
            RegValue::Strs(l) => !l.is_empty(),
            RegValue::Int(n) => *n != 0,
            RegValue::Bytes(b) => !b.is_empty(),
            RegValue::Nothing => false,
        }
    }
}

/// Every value under one adapter's two TCP/IP keys, IPv6 ones prefixed `v6_` -
/// `read_registry_interface`, ported.
pub type RegValues = HashMap<String, RegValue>;

const TCPIP4_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const TCPIP6_INTERFACES: &str = r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces";

#[link(name = "advapi32")]
extern "system" {
    fn RegOpenKeyExW(key: isize, sub_key: *const u16, options: u32, sam: u32, result: *mut isize) -> i32;
    fn RegEnumValueW(
        key: isize,
        index: u32,
        name: *mut u16,
        name_len: *mut u32,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        data_len: *mut u32,
    ) -> i32;
    fn RegCloseKey(key: isize) -> i32;
}

/// `HKEY_LOCAL_MACHINE` is `(HKEY)(ULONG_PTR)((LONG)0x80000002)` - sign-extended.
const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
const KEY_READ: u32 = 0x0002_0019;
const ERROR_MORE_DATA: i32 = 234;
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
const REG_QWORD: u32 = 11;

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// One registry value's bytes as `winreg` would convert them.
fn convert(kind: u32, data: &[u8]) -> RegValue {
    let words = || -> Vec<u16> {
        data.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
    };
    match kind {
        REG_SZ | REG_EXPAND_SZ => {
            let w = words();
            let end = w.iter().position(|c| *c == 0).unwrap_or(w.len());
            RegValue::Str(String::from_utf16_lossy(&w[..end]))
        }
        REG_MULTI_SZ => RegValue::Strs(
            words()
                .split(|c| *c == 0)
                .take_while(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect(),
        ),
        REG_DWORD => {
            let mut b = [0u8; 4];
            let n = data.len().min(4);
            b[..n].copy_from_slice(&data[..n]);
            RegValue::Int(u32::from_le_bytes(b) as u64)
        }
        REG_QWORD => {
            let mut b = [0u8; 8];
            let n = data.len().min(8);
            b[..n].copy_from_slice(&data[..n]);
            RegValue::Int(u64::from_le_bytes(b))
        }
        _ if data.is_empty() => RegValue::Nothing,
        _ => RegValue::Bytes(data.to_vec()),
    }
}

/// Every value under `HKLM\{path}`, by its stored name. Enumerated rather than
/// queried one by one, so the names are compared as exactly as `adapters.py`'s
/// dict compares them. A missing key is the normal state for an adapter that
/// has never had that family configured, and is simply no values.
fn read_key(path: &str, prefix: &str, into: &mut RegValues) {
    let sub = wide(path);
    let mut key: isize = 0;
    if unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, sub.as_ptr(), 0, KEY_READ, &mut key) } != 0 {
        return;
    }
    let mut name = vec![0u16; 16_384];
    let mut data = vec![0u8; 4096];
    let mut index = 0u32;
    loop {
        let mut name_len = name.len() as u32;
        let mut data_len = data.len() as u32;
        let mut kind = 0u32;
        let rc = unsafe {
            RegEnumValueW(
                key,
                index,
                name.as_mut_ptr(),
                &mut name_len,
                std::ptr::null_mut(),
                &mut kind,
                data.as_mut_ptr(),
                &mut data_len,
            )
        };
        if rc == ERROR_MORE_DATA {
            // The same index again with room for it - a value only ever grows
            // the buffer, and `DhcpInterfaceOptions` is the one that does.
            data = vec![0u8; data_len as usize + 2];
            continue;
        }
        if rc != 0 {
            break; // ERROR_NO_MORE_ITEMS, or anything else: what was read stands
        }
        let value_name = String::from_utf16_lossy(&name[..name_len as usize]);
        into.insert(format!("{prefix}{value_name}"), convert(kind, &data[..data_len as usize]));
        index += 1;
    }
    unsafe { RegCloseKey(key) };
}

/// `read_registry_interface(guid)`.
pub fn read_registry_interface(guid: &str) -> RegValues {
    let mut values = RegValues::new();
    read_key(&format!(r"{TCPIP4_INTERFACES}\{guid}"), "", &mut values);
    read_key(&format!(r"{TCPIP6_INTERFACES}\{guid}"), "v6_", &mut values);
    values
}

// --- link statistics, as psutil reads them ------------------------------------

/// psutil's `snicstats`, the three fields `adapters.py` reads from it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct NicStat {
    pub is_up: bool,
    /// Megabits, integer-divided as psutil's C does.
    pub speed_mbps: u32,
    pub mtu: u32,
}

/// `MIB_IFROW`, in full, because psutil reads `dwSpeed` and `bDescr` from it
/// and the second is past everything else.
#[repr(C)]
struct MibIfRow {
    _name: [u16; 256],
    _index: u32,
    _if_type: u32,
    mtu: u32,
    speed: u32,
    _phys_addr_len: u32,
    _phys_addr: [u8; 8],
    admin_status: u32,
    oper_status: u32,
    _last_change: u32,
    _counters: [u32; 12],
    descr_len: u32,
    descr: [u8; 256],
}

/// 860 bytes; `descr` is the last field, so any wrong offset above it moves it.
const _: () = assert!(std::mem::size_of::<MibIfRow>() == 860);

#[link(name = "iphlpapi")]
extern "system" {
    fn GetIfTable(table: *mut u32, size: *mut u32, order: i32) -> u32;
    fn GetIpForwardTable2(family: u16, table: *mut *mut c_void) -> u32;
    fn GetIpNetTable2(family: u16, table: *mut *mut c_void) -> u32;
    fn FreeMibTable(memory: *mut c_void);
}

#[link(name = "kernel32")]
extern "system" {
    fn MultiByteToWideChar(
        code_page: u32,
        flags: u32,
        text: *const u8,
        text_len: i32,
        out: *mut u16,
        out_len: i32,
    ) -> i32;
}

/// `bDescr` is ANSI; psutil compares it against the adapter's description
/// narrowed to the same code page, which for anything the code page can hold is
/// this comparison made the other way round.
fn ansi_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    let bytes = &bytes[..end];
    if bytes.is_ascii() {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut out = vec![0u16; bytes.len() * 2 + 1];
    let n = unsafe {
        MultiByteToWideChar(0 /* CP_ACP */, 0, bytes.as_ptr(), bytes.len() as i32,
            out.as_mut_ptr(), out.len() as i32)
    };
    String::from_utf16_lossy(&out[..n.max(0) as usize])
}

/// `MIB_IF_OPER_STATUS_CONNECTED` and `_OPERATIONAL`.
const OPER_CONNECTED: u32 = 4;
const OPER_OPERATIONAL: u32 = 5;

/// psutil's `net_if_stats` on Windows, keyed by friendly name as it is.
///
/// **The join is psutil's, and it is by description, not by index**: every
/// `GetIfTable` row is matched to the first adapter in the no-flags
/// `GetAdaptersAddresses` list whose description is the row's, and a later row
/// with the same description replaces an earlier one. That list has only
/// adapters with an IP binding, which is why a WAN Miniport has no status, no
/// speed and no MTU in the Python agent's report - and so none here.
pub fn nic_stats() -> HashMap<String, NicStat> {
    let mut out = HashMap::new();
    let named = adapters::enumerate_with(0);

    let mut words: Vec<u32> = vec![0; 64 * 1024 / 4];
    let mut size = (words.len() * 4) as u32;
    let mut ok = false;
    for _ in 0..3 {
        match unsafe { GetIfTable(words.as_mut_ptr(), &mut size, 0) } {
            0 => {
                ok = true;
                break;
            }
            122 /* ERROR_INSUFFICIENT_BUFFER */ => {
                words = vec![0; (size as usize + 3) / 4];
                size = (words.len() * 4) as u32;
            }
            _ => break,
        }
    }
    if !ok {
        return out;
    }
    let count = words[0] as usize;
    let rows = unsafe { words.as_ptr().add(1) as *const MibIfRow };
    let room = (words.len() - 1) * 4 / std::mem::size_of::<MibIfRow>();
    for i in 0..count.min(room) {
        let row = unsafe { &*rows.add(i) };
        let len = (row.descr_len as usize).min(row.descr.len());
        let descr = ansi_text(&row.descr[..len]);
        let Some(adapter) = named.iter().find(|a| a.description.as_deref() == Some(descr.as_str()))
        else {
            continue;
        };
        let Some(name) = adapter.friendly_name.clone() else { continue };
        out.insert(name, NicStat {
            is_up: (row.oper_status == OPER_CONNECTED || row.oper_status == OPER_OPERATIONAL)
                && row.admin_status == 1,
            speed_mbps: row.speed / 1_000_000,
            mtu: row.mtu,
        });
    }
    out
}

// --- routes and neighbours ----------------------------------------------------

/// `SOCKADDR_INET`: a family, then either shape. `u32`s rather than bytes
/// because the union holds `ULONG`s and aligns to 4 - which is what places
/// every field after it in the two rows below.
#[repr(C)]
#[derive(Clone, Copy)]
struct SockaddrInet {
    family: u16,
    _port: u16,
    words: [u32; 6],
}

impl SockaddrInet {
    /// The address, without a zone - which is `_strip_zone`'s whole job, done
    /// by not writing one.
    fn ip(&self) -> Option<IpAddr> {
        let bytes = |from: usize, n: usize| -> Vec<u8> {
            self.words[from..from + n].iter().flat_map(|w| w.to_ne_bytes()).collect()
        };
        match self.family {
            2 => {
                let b = bytes(0, 1);
                Some(IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3])))
            }
            23 => {
                let b: [u8; 16] = bytes(1, 4).try_into().ok()?;
                Some(IpAddr::V6(Ipv6Addr::from(b)))
            }
            _ => None,
        }
    }
}

/// An address as the OS writes it - what `Get-NetRoute` and `Get-NetNeighbor`
/// print, and what scapy's `inet_ntop` printed for the adapter list.
fn ip_text(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format_ipv6(&v6.octets()),
    }
}

#[repr(C)]
struct MibIpForwardRow2 {
    _interface_luid: u64,
    interface_index: u32,
    destination: SockaddrInet,
    destination_length: u8,
    next_hop: SockaddrInet,
    _site_prefix_length: u8,
    _valid_lifetime: u32,
    _preferred_lifetime: u32,
    _metric: u32,
    _protocol: u32,
    _flags: [u8; 4],
    _age: u32,
    _origin: u32,
}

const _: () = assert!(std::mem::size_of::<MibIpForwardRow2>() == 104);

#[repr(C)]
struct MibIpnetRow2 {
    address: SockaddrInet,
    interface_index: u32,
    _interface_luid: u64,
    physical_address: [u8; 32],
    physical_address_length: u32,
    _state: u32,
    _flags: u8,
    _reachability: u32,
}

const _: () = assert!(std::mem::size_of::<MibIpnetRow2>() == 88);

/// One default route: `Get-NetRoute -DestinationPrefix '0.0.0.0/0','::/0'`.
#[derive(Clone, Debug, PartialEq)]
pub struct Route {
    pub if_index: u32,
    /// `DestinationPrefix == '::/0'`.
    pub v6: bool,
    pub next_hop: String,
}

/// One neighbour with a link-layer address: `Get-NetNeighbor | Where-Object {
/// $_.LinkLayerAddress }`.
#[derive(Clone, Debug, PartialEq)]
pub struct Neighbour {
    pub if_index: u32,
    pub address: String,
    /// `LinkLayerAddress` as `Get-NetNeighbor` writes it: dash-separated
    /// uppercase hex, which `py_mac` reads.
    pub link_layer: String,
}

/// The rows of a `MIB_*_TABLE2`: a `ULONG` count, then rows aligned to 8.
///
/// # Safety
/// `table` must be what the matching `Get*Table2` returned.
unsafe fn table_rows<'a, T>(table: *mut c_void) -> &'a [T] {
    let count = *(table as *const u32) as usize;
    std::slice::from_raw_parts((table as *const u8).add(8) as *const T, count)
}

/// Every default route, in the table's order - `Get-NetRoute`'s order.
pub fn default_routes() -> Vec<Route> {
    let mut table: *mut c_void = std::ptr::null_mut();
    if unsafe { GetIpForwardTable2(0 /* AF_UNSPEC */, &mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for row in unsafe { table_rows::<MibIpForwardRow2>(table) } {
        if row.destination_length != 0 {
            continue;
        }
        // A zero-length prefix on the unspecified address, which is the only
        // shape `Get-NetRoute` prints as `0.0.0.0/0` or `::/0`.
        let (Some(dest), Some(hop)) = (row.destination.ip(), row.next_hop.ip()) else { continue };
        if !dest.is_unspecified() {
            continue;
        }
        out.push(Route {
            if_index: row.interface_index,
            v6: dest.is_ipv6(),
            next_hop: ip_text(&hop),
        });
    }
    unsafe { FreeMibTable(table) };
    out
}

/// Every neighbour that has a link-layer address, in the table's order.
pub fn neighbours() -> Vec<Neighbour> {
    let mut table: *mut c_void = std::ptr::null_mut();
    if unsafe { GetIpNetTable2(0 /* AF_UNSPEC */, &mut table) } != 0 || table.is_null() {
        return Vec::new();
    }
    let mut out = Vec::new();
    for row in unsafe { table_rows::<MibIpnetRow2>(table) } {
        let len = (row.physical_address_length as usize).min(row.physical_address.len());
        // An empty `LinkLayerAddress` is what the `Where-Object` drops. An
        // all-zero one is not empty, and it is kept, exactly as it is there.
        if len == 0 {
            continue;
        }
        let Some(ip) = row.address.ip() else { continue };
        out.push(Neighbour {
            if_index: row.interface_index,
            address: ip_text(&ip),
            link_layer: row.physical_address[..len]
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<Vec<_>>()
                .join("-"),
        });
    }
    unsafe { FreeMibTable(table) };
    out
}

// --- one adapter, from what was read ------------------------------------------

/// The device name Npcap captures on, which is what the interface list is keyed
/// by - built from the GUID, so the join with a capture interface is exact.
pub fn device_name(guid: &str) -> String {
    format!(r"\Device\NPF_{guid}")
}

/// One adapter's report, from everything already read - `_windows_adapters`'
/// loop body. Pure, so it can be held to real values without the machine they
/// came from.
///
/// `None` for an adapter with no GUID, which `adapters.py` skips.
pub fn build_report(
    entry: &WinAdapter,
    values: &RegValues,
    stats: &HashMap<String, NicStat>,
    routes: &[Route],
    neighbours: &[Neighbour],
) -> Option<AdapterReport> {
    let guid = py_text(&entry.guid)?;
    let raw_name = entry.friendly_name.as_deref();
    let name = raw_name.and_then(py_text).unwrap_or_else(|| guid.clone());
    let index = entry.if_index;
    // By the raw name first: that is the key psutil filed it under, marks and
    // all. Looking it up by the cleaned name is how speed, MTU and link state
    // all went null on a right-to-left machine once.
    let stat = raw_name.and_then(|n| stats.get(n)).or_else(|| stats.get(&name));
    let get = |key: &str| values.get(key);

    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for address in &entry.unicast {
        let Some(text) = strip_zone(&address.text) else { continue };
        let prefix = Some(address.prefix_length);
        match address.ip {
            IpAddr::V4(v4) => ipv4.push(AdapterIpv4 {
                address: text,
                prefix_length: prefix,
                broadcast: broadcast(v4, prefix),
            }),
            IpAddr::V6(v6) => ipv6.push(AdapterIpv6 {
                address: text,
                prefix_length: prefix,
                scope: Some(address_scope(&v6)),
                temporary: Some(is_temporary(address.suffix_origin)),
            }),
        }
    }

    // The registry's IPv4 gateway first: the DHCP one, then a static one.
    let mut gateway_v4: Option<String> = None;
    for key in ["DhcpDefaultGateway", "DefaultGateway"] {
        let candidates: Vec<String> =
            get(key).map(|v| v.texts()).unwrap_or_default().into_iter().flatten().collect();
        if let Some(first) = candidates.into_iter().next() {
            gateway_v4 = Some(first);
            break;
        }
    }
    // Then the routing table: the LAST `::/0` route on this interface for IPv6
    // - `adapters.py` assigns on every one - and the FIRST IPv4 one, only if
    // the registry had none.
    let mut gateway_v6: Option<String> = None;
    for route in routes.iter().filter(|r| r.if_index == index) {
        let Some(hop) = strip_zone(&route.next_hop) else { continue };
        if hop == "0.0.0.0" || hop == "::" {
            continue;
        }
        if route.v6 {
            gateway_v6 = Some(hop);
        } else if gateway_v4.is_none() {
            gateway_v4 = Some(hop);
        }
    }

    // The registry's own answer for the MAC first - it costs nothing and is
    // already read - then the neighbour table for anything it did not cover.
    let gateway_macs = match get("DhcpGatewayHardware") {
        Some(RegValue::Bytes(blob)) => decode_gateway_hardware(blob),
        _ => HashMap::new(),
    };
    let mut gateway_mac = gateway_v4.as_ref().and_then(|g| gateway_macs.get(g).cloned());
    if gateway_mac.is_none() {
        for row in neighbours.iter().filter(|r| r.if_index == index) {
            let address = strip_zone(&row.address);
            if address.is_some() && (address == gateway_v4 || address == gateway_v6) {
                gateway_mac = py_mac(&row.link_layer);
                if gateway_mac.is_some() {
                    break;
                }
            }
        }
    }

    let mut dns = Vec::new();
    for key in ["NameServer", "DhcpNameServer", "v6_NameServer"] {
        if let Some(text) = get(key).and_then(RegValue::text) {
            dns.extend(split_resolvers(&text));
        }
    }
    dns.extend(entry.dns_servers.iter().filter_map(|s| strip_zone(s)));

    let int = |key: &str| match get(key) {
        Some(RegValue::Int(n)) => Some(*n),
        _ => None,
    };

    Some(AdapterReport {
        id: device_name(&guid),
        name,
        description: entry.description.as_deref().and_then(py_text),
        mac: entry.mac.as_deref().and_then(py_mac),
        status: stat.map(|s| if s.is_up { "up" } else { "down" }),
        // psutil reports 0 for a speed it cannot read, which is not a speed.
        speed_mbps: stat.map(|s| s.speed_mbps as u64).filter(|n| *n != 0),
        mtu: stat.map(|s| s.mtu).filter(|n| *n != 0),
        dhcp_enabled: get("EnableDHCP").map(RegValue::truthy),
        dhcp_server: get("DhcpServer").and_then(RegValue::text),
        // Epoch seconds, as the registry stores them. `adapters.py` sends the
        // raw value, which is always a DWORD on Windows; anything else is null.
        lease_obtained: int("LeaseObtainedTime"),
        lease_expires: int("LeaseTerminatesTime"),
        ipv4,
        ipv6,
        gateway_v4,
        gateway_v6,
        gateway_mac,
        dns_servers: dedupe_keep_first(dns),
        dns_suffix: get("Domain")
            .and_then(RegValue::text)
            .or_else(|| get("DhcpDomain").and_then(RegValue::text)),
        source: AdapterSource {
            adapter: Some("windows_iflist"),
            // The prefix and the privacy flag come from the same call as the
            // list, where the Python agent adds `+powershell` for its second.
            addresses: Some("windows_iflist"),
            dhcp: Some("registry"),
            gateway: Some(if gateway_macs.is_empty() { "route" } else { "registry" }),
            dns: Some("registry"),
        },
    })
}

/// `read_adapters(keep=...)`: every adapter Windows lists, in its order,
/// narrowed to the capture devices.
///
/// **Narrowed, and that is what excludes the loopback adapter.** Windows lists
/// fifty-odd adapters here - every filter binding, QoS scheduler, WAN Miniport
/// and tunnel - and sending all of them would hand the app the configuration
/// of adapters nobody is capturing on. `\Device\NPF_Loopback` carries no GUID,
/// so no adapter's `\Device\NPF_{GUID}` is ever it, and it is not reported -
/// exactly as in the Python agent.
pub fn read_adapters(keep: &[String]) -> Vec<AdapterReport> {
    let listed = adapters::enumerate();
    if listed.is_empty() {
        return Vec::new();
    }
    let stats = nic_stats();
    let routes = default_routes();
    let neighbours = neighbours();
    listed
        .iter()
        .filter_map(|entry| {
            let guid = py_text(&entry.guid)?;
            // Filtered before the registry is read, which changes nothing
            // about the answer and skips fifty registry keys nobody asked for.
            if !keep.contains(&device_name(&guid)) {
                return None;
            }
            let values = read_registry_interface(&guid);
            build_report(entry, &values, &stats, &routes, &neighbours)
        })
        .collect()
}

/// Turns successive readings into a message, or into nothing.
///
/// `adapters.py`'s `AdapterTracker`. Whole snapshots, not deltas - a machine
/// has a handful of adapters and the message is a couple of kilobytes - but the
/// same silence as the socket table's: configuration changes when a lease
/// renews or a cable moves, so the common poll has nothing to say.
#[derive(Default)]
pub struct AdapterTracker {
    previous: Option<Vec<Value>>,
}

impl AdapterTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forgets the last reading, so the next poll always sends.
    pub fn reset(&mut self) {
        self.previous = None;
    }

    /// The next message, or `None` when nothing changed.
    pub fn poll(&mut self, keep: &[String]) -> Option<Value> {
        let adapters = read_adapters(keep).iter().map(AdapterReport::to_value).collect();
        self.observe(adapters)
    }

    /// The comparison alone. By value rather than by a hash or a timestamp:
    /// the whole message is small, and the comparison is the only thing between
    /// "the lease clock ticked" and a re-render every ten seconds.
    pub fn observe(&mut self, adapters: Vec<Value>) -> Option<Value> {
        if self.previous.as_ref() == Some(&adapters) {
            return None;
        }
        self.previous = Some(adapters.clone());
        Some(protocol::adapter_config_from_values(adapters))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::UnicastAddress;

    /// `DhcpGatewayHardware` for the wired adapter on the machine this was
    /// written on, as `winreg` read it: 10.0.0.138, six bytes, then the MAC -
    /// the pairing `Get-NetNeighbor` gives, without spawning anything.
    const GATEWAY_HARDWARE: [u8; 14] =
        [0x0a, 0x00, 0x00, 0x8a, 0x06, 0x00, 0x00, 0x00, 0x44, 0x15, 0x24, 0x5d, 0xcc, 0x62];

    #[test]
    fn the_gateway_hardware_record_decodes_to_an_address_and_a_mac() {
        let decoded = decode_gateway_hardware(&GATEWAY_HARDWARE);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded.get("10.0.0.138").map(String::as_str), Some("44:15:24:5d:cc:62"));
        // A record that claims more bytes than the blob holds ends the walk
        // rather than reading past it.
        let mut torn = GATEWAY_HARDWARE.to_vec();
        torn[4] = 0x20;
        assert!(decode_gateway_hardware(&torn).is_empty());
        assert!(decode_gateway_hardware(&[]).is_empty());
    }

    /// The broadcasts `adapters.py` computed for this machine's addresses:
    /// 10.0.0.7/24 and the link-local 169.254.174.10/16 a disconnected
    /// adapter holds.
    #[test]
    fn the_broadcast_is_computed_from_address_and_prefix() {
        assert_eq!(broadcast(Ipv4Addr::new(10, 0, 0, 7), Some(24)).as_deref(), Some("10.0.0.255"));
        assert_eq!(
            broadcast(Ipv4Addr::new(169, 254, 174, 10), Some(16)).as_deref(),
            Some("169.254.255.255"),
        );
        // `ip_network(..., strict=False)` at the two edges: /32 is the address
        // itself, /0 is everything.
        assert_eq!(broadcast(Ipv4Addr::new(10, 0, 0, 7), Some(32)).as_deref(), Some("10.0.0.7"));
        assert_eq!(broadcast(Ipv4Addr::new(10, 0, 0, 7), Some(0)).as_deref(), Some("255.255.255.255"));
        // No prefix is no broadcast, and a prefix past 32 is not a network.
        assert_eq!(broadcast(Ipv4Addr::new(10, 0, 0, 7), None), None);
        assert_eq!(broadcast(Ipv4Addr::new(10, 0, 0, 7), Some(33)), None);
    }

    /// `temporary` is `SuffixOrigin == 5` and nothing else. The Ethernet
    /// adapter here held two random-suffix globals, one link-layer-derived
    /// global and a link-local, and `Get-NetIPAddress` reported 5 for exactly
    /// the two `adapters.py` marked temporary.
    #[test]
    fn only_a_random_suffix_is_temporary() {
        assert!(is_temporary(5)); // IpSuffixOriginRandom
        assert!(!is_temporary(4)); // LinkLayerAddress
        assert!(!is_temporary(3)); // Dhcp
        assert!(!is_temporary(2)); // WellKnown
        assert!(!is_temporary(1)); // Manual
    }

    /// Every expectation is what Python 3.13's `adapters.address_scope`
    /// answered for the same text on this machine - the first four are this
    /// machine's own addresses and resolvers, the rest are the table entries
    /// where Python's reading is not the RFC's.
    #[test]
    fn a_scope_is_what_python_calls_it() {
        let scope = |s: &str| address_scope(&s.parse::<Ipv6Addr>().unwrap());
        assert_eq!(scope("2a06:c701:423b:fa00:ded:f6ae:9a1c:d19a"), "global");
        assert_eq!(scope("fe80::3f65:9cc9:cb3d:8e6e"), "link-local");
        assert_eq!(scope("2a06:c701:ffff::1"), "global");
        assert_eq!(scope("fec0:0:0:ffff::1"), "global");
        assert_eq!(scope("::1"), "loopback");
        assert_eq!(scope("fd12:3456::1"), "ula");
        assert_eq!(scope("2002:c0a8:1::1"), "ula");
        assert_eq!(scope("2001:db8::1"), "ula");
        assert_eq!(scope("2001:0:4136:e378:8000:63bf:f5ff:fff8"), "ula");
        assert_eq!(scope("2001:4:112::1"), "global");
        assert_eq!(scope("ff02::1"), "global");
        assert_eq!(scope("::ffff:10.0.0.7"), "ula");
        assert_eq!(scope("::ffff:8.8.8.8"), "global");
        assert_eq!(scope("::ffff:127.0.0.1"), "loopback");
        assert_eq!(scope("::ffff:169.254.1.1"), "link-local");
        assert_eq!(scope("::ffff:100.64.0.1"), "global");
    }

    #[test]
    fn text_is_trimmed_of_space_and_bidi_marks_at_the_ends_only() {
        assert_eq!(py_text("\u{200f}\u{200f}Ethernet 2 ").as_deref(), Some("Ethernet 2"));
        assert_eq!(py_text("  "), None);
        assert_eq!(py_text(""), None);
        // Inside the name a mark is left alone, as `str.strip` leaves it.
        assert_eq!(py_text("Eth\u{200e}ernet").as_deref(), Some("Eth\u{200e}ernet"));
        assert_eq!(strip_zone("fe80::1%9").as_deref(), Some("fe80::1"));
        assert_eq!(py_mac("44-15-24-5D-CC-62").as_deref(), Some("44:15:24:5d:cc:62"));
        assert_eq!(py_mac("00-00-00-00-00-00-00-E0"), None);
        assert_eq!(py_mac(""), None);
        assert_eq!(split_resolvers("10.0.0.138 8.8.8.8,1.1.1.1"), vec!["10.0.0.138", "8.8.8.8", "1.1.1.1"]);
    }

    /// Two readings of the same resolver - the registry's and the adapter
    /// list's - are one resolver, listed where it was first seen.
    #[test]
    fn a_resolver_listed_twice_is_kept_once_where_it_first_appeared() {
        let got = dedupe_keep_first(vec![
            "10.0.0.138".into(), "10.0.0.138".into(),
            "2a06:c701:ffff::1".into(), "2a06:c701:ffff::2".into(),
        ]);
        assert_eq!(got, vec!["10.0.0.138", "2a06:c701:ffff::1", "2a06:c701:ffff::2"]);
    }

    fn v4(text: &str, prefix: u8) -> UnicastAddress {
        UnicastAddress { ip: IpAddr::V4(text.parse().unwrap()), text: text.into(), prefix_length: prefix, suffix_origin: 3 }
    }
    fn v6(text: &str, prefix: u8, suffix_origin: u32) -> UnicastAddress {
        UnicastAddress { ip: IpAddr::V6(text.parse().unwrap()), text: text.into(), prefix_length: prefix, suffix_origin }
    }

    /// The wired adapter on the machine this was written on, as each source
    /// reported it - and the report `adapters.py` built from the same sources,
    /// field for field. The lease values are one reading of a clock that moves;
    /// the point is that they travel unaltered.
    fn ethernet() -> (WinAdapter, RegValues) {
        let entry = WinAdapter {
            guid: "{64455981-5CEF-4A70-8218-4E5C316C795B}".into(),
            if_index: 12,
            if_type: 6,
            friendly_name: Some("Ethernet".into()),
            description: Some("Intel(R) Ethernet Controller (3) I225-V".into()),
            mac: Some("04:7c:16:52:db:17".into()),
            unicast: vec![
                v6("2a06:c701:423b:fa00:ded:f6ae:9a1c:d19a", 64, 4),
                v6("2a06:c701:423b:fa00:905:b5f6:7cc4:a1d0", 128, 5),
                v6("2a06:c701:423b:fa00:4cf7:82a:8f92:7df7", 128, 5),
                v6("fe80::3f65:9cc9:cb3d:8e6e", 64, 4),
                v4("10.0.0.7", 24),
            ],
            // As `GetAdaptersAddresses` listed them, duplicates and all.
            dns_servers: vec![
                "2a06:c701:ffff::1".into(), "2a06:c701:ffff::2".into(), "10.0.0.138".into(),
                "2a06:c701:ffff::1".into(), "2a06:c701:ffff::2".into(),
            ],
        };
        let mut values = RegValues::new();
        values.insert("EnableDHCP".into(), RegValue::Int(1));
        values.insert("DhcpServer".into(), RegValue::Str("10.0.0.138".into()));
        values.insert("LeaseObtainedTime".into(), RegValue::Int(1790415188));
        values.insert("LeaseTerminatesTime".into(), RegValue::Int(1790418788));
        values.insert("DhcpDefaultGateway".into(), RegValue::Strs(vec!["10.0.0.138".into()]));
        values.insert("DhcpGatewayHardware".into(), RegValue::Bytes(GATEWAY_HARDWARE.to_vec()));
        values.insert("NameServer".into(), RegValue::Str(String::new()));
        values.insert("DhcpNameServer".into(), RegValue::Str("10.0.0.138".into()));
        values.insert("Domain".into(), RegValue::Str(String::new()));
        values.insert("DhcpDomain".into(), RegValue::Str("home".into()));
        (entry, values)
    }

    #[test]
    fn the_wired_adapter_reports_what_the_python_agent_reported() {
        let (entry, values) = ethernet();
        let mut stats = HashMap::new();
        stats.insert("Ethernet".to_string(), NicStat { is_up: true, speed_mbps: 2500, mtu: 1500 });
        let routes = vec![
            Route { if_index: 12, v6: false, next_hop: "10.0.0.138".into() },
            Route { if_index: 12, v6: true, next_hop: "fe80::4615:24ff:fe5d:cc62".into() },
        ];
        let report = build_report(&entry, &values, &stats, &routes, &[]).unwrap().to_value();
        let expected: Value = serde_json::from_str(r#"{
            "id": "\\Device\\NPF_{64455981-5CEF-4A70-8218-4E5C316C795B}",
            "name": "Ethernet",
            "description": "Intel(R) Ethernet Controller (3) I225-V",
            "mac": "04:7c:16:52:db:17",
            "status": "up", "speedMbps": 2500, "mtu": 1500,
            "dhcpEnabled": true, "dhcpServer": "10.0.0.138",
            "leaseObtained": 1790415188, "leaseExpires": 1790418788,
            "ipv4": [{"address": "10.0.0.7", "prefixLength": 24, "broadcast": "10.0.0.255"}],
            "ipv6": [
                {"address": "2a06:c701:423b:fa00:ded:f6ae:9a1c:d19a", "prefixLength": 64, "scope": "global", "temporary": false},
                {"address": "2a06:c701:423b:fa00:905:b5f6:7cc4:a1d0", "prefixLength": 128, "scope": "global", "temporary": true},
                {"address": "2a06:c701:423b:fa00:4cf7:82a:8f92:7df7", "prefixLength": 128, "scope": "global", "temporary": true},
                {"address": "fe80::3f65:9cc9:cb3d:8e6e", "prefixLength": 64, "scope": "link-local", "temporary": false}
            ],
            "gatewayV4": "10.0.0.138", "gatewayV6": "fe80::4615:24ff:fe5d:cc62",
            "gatewayMac": "44:15:24:5d:cc:62",
            "dnsServers": ["10.0.0.138", "2a06:c701:ffff::1", "2a06:c701:ffff::2"],
            "dnsSuffix": "home",
            "source": {"adapter": "windows_iflist", "addresses": "windows_iflist",
                       "dhcp": "registry", "gateway": "registry", "dns": "registry"}
        }"#).unwrap();
        assert_eq!(report, expected);
    }

    /// A WAN Miniport: no IP binding, so no psutil row, no registry key, no
    /// addresses - and every one of those is `null` or empty, never a zero.
    #[test]
    fn an_adapter_nothing_knows_about_is_nulls_not_zeros() {
        let entry = WinAdapter {
            guid: "{C058D089-E644-427C-9C9A-53337892E5DB}".into(),
            if_index: 0,
            if_type: 6,
            friendly_name: Some("Local Area Connection* 3".into()),
            description: Some("WAN Miniport (Network Monitor)".into()),
            mac: None,
            unicast: Vec::new(),
            dns_servers: Vec::new(),
        };
        let report = build_report(&entry, &RegValues::new(), &HashMap::new(), &[], &[]).unwrap();
        assert_eq!(report.status, None);
        assert_eq!(report.speed_mbps, None);
        assert_eq!(report.mtu, None);
        assert_eq!(report.dhcp_enabled, None);
        assert_eq!(report.lease_obtained, None);
        assert_eq!(report.gateway_mac, None);
        assert!(report.ipv4.is_empty() && report.ipv6.is_empty() && report.dns_servers.is_empty());
        // No gateway hardware in the registry, so the gateway group names the
        // routing table - where `adapters.py` names PowerShell.
        assert_eq!(report.source.gateway, Some("route"));
    }

    /// psutil reports a speed of 0 for an adapter whose speed it cannot read -
    /// the Wi-Fi Direct virtual adapters here - which is not a speed.
    #[test]
    fn a_zero_speed_is_no_speed() {
        let (entry, values) = ethernet();
        let mut stats = HashMap::new();
        stats.insert("Ethernet".to_string(), NicStat { is_up: false, speed_mbps: 0, mtu: 1500 });
        let report = build_report(&entry, &values, &stats, &[], &[]).unwrap();
        assert_eq!(report.status, Some("down"));
        assert_eq!(report.speed_mbps, None);
        assert_eq!(report.mtu, Some(1500));
    }

    /// With no gateway hardware in the registry the MAC comes from the
    /// neighbour table - the first row on this interface for either gateway
    /// that parses as a MAC.
    #[test]
    fn the_gateway_mac_falls_back_to_the_neighbour_table() {
        let (entry, mut values) = ethernet();
        values.remove("DhcpGatewayHardware");
        let routes = vec![Route { if_index: 12, v6: true, next_hop: "fe80::4615:24ff:fe5d:cc62".into() }];
        let neighbours = vec![
            // Another interface's row for the same address is not this one's.
            Neighbour { if_index: 7, address: "10.0.0.138".into(), link_layer: "AA-AA-AA-AA-AA-AA".into() },
            Neighbour { if_index: 12, address: "10.0.0.1".into(), link_layer: "BB-BB-BB-BB-BB-BB".into() },
            Neighbour { if_index: 12, address: "10.0.0.138".into(), link_layer: "44-15-24-5D-CC-62".into() },
        ];
        let report = build_report(&entry, &values, &HashMap::new(), &routes, &neighbours).unwrap();
        assert_eq!(report.gateway_mac.as_deref(), Some("44:15:24:5d:cc:62"));
        assert_eq!(report.source.gateway, Some("route"));
    }

    /// The registry's gateway wins over the routing table's, and the table's
    /// IPv6 answer is its last `::/0` route, since `adapters.py` assigns on
    /// every one.
    #[test]
    fn gateways_come_from_the_registry_first_and_the_last_v6_route() {
        let (entry, values) = ethernet();
        let routes = vec![
            Route { if_index: 12, v6: false, next_hop: "10.0.0.1".into() },
            Route { if_index: 12, v6: true, next_hop: "fe80::1".into() },
            Route { if_index: 12, v6: true, next_hop: "::".into() },
            Route { if_index: 12, v6: true, next_hop: "fe80::2".into() },
            Route { if_index: 4, v6: true, next_hop: "fe80::3".into() },
        ];
        let report = build_report(&entry, &values, &HashMap::new(), &routes, &[]).unwrap();
        assert_eq!(report.gateway_v4.as_deref(), Some("10.0.0.138"));
        assert_eq!(report.gateway_v6.as_deref(), Some("fe80::2"));
    }

    /// `\Device\NPF_Loopback` is in the capture list and in no adapter's
    /// device name, so narrowing to the capture list is what leaves it out.
    #[test]
    fn narrowing_to_the_capture_list_leaves_the_loopback_device_out() {
        let keep = vec![
            r"\Device\NPF_{64455981-5CEF-4A70-8218-4E5C316C795B}".to_string(),
            r"\Device\NPF_Loopback".to_string(),
        ];
        let reports = read_adapters(&keep);
        assert!(reports.iter().all(|r| keep.contains(&r.id)));
        assert!(reports.iter().all(|r| r.id != r"\Device\NPF_Loopback"),
            "the loopback device has no GUID and must not be reported");
        // And an empty capture list - a machine with no Npcap - reports nothing.
        assert!(read_adapters(&[]).is_empty());
    }

    #[test]
    fn a_tracker_speaks_on_the_first_poll_and_then_only_on_change() {
        let mut tracker = AdapterTracker::new();
        let one = vec![serde_json::json!({ "id": "a", "ipv4": [], "ipv6": [], "dnsServers": [] })];
        assert!(tracker.observe(one.clone()).is_some(), "the first reading always sends");
        assert!(tracker.observe(one.clone()).is_none(), "an unchanged reading is silence");
        let two = vec![serde_json::json!({ "id": "a", "ipv4": [], "ipv6": [], "dnsServers": ["x"] })];
        assert_eq!(tracker.observe(two.clone()).unwrap()["type"], "adapter_config");
        tracker.reset();
        assert!(tracker.observe(two).is_some(), "a reset tracker always sends");
    }

    /// The registry and the two tables are real reads here, and a DWORD, a
    /// string and a list all come back in `winreg`'s shapes.
    #[test]
    fn the_registry_reads_in_winregs_shapes() {
        let adapters = adapters::enumerate();
        let Some(with_dhcp) = adapters.iter().find(|a| {
            matches!(read_registry_interface(&a.guid).get("EnableDHCP"), Some(RegValue::Int(_)))
        }) else {
            eprintln!("SKIP  no adapter here has TCP/IP parameters");
            return;
        };
        let values = read_registry_interface(&with_dhcp.guid);
        if let Some(domain) = values.get("Domain") {
            assert!(matches!(domain, RegValue::Str(_)), "Domain is a REG_SZ: {domain:?}");
        }
        if let Some(gateway) = values.get("DhcpDefaultGateway") {
            assert!(matches!(gateway, RegValue::Strs(_)), "a REG_MULTI_SZ is a list: {gateway:?}");
        }
    }
}
