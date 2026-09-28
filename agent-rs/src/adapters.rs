//! Windows' own name for an adapter, which Npcap does not carry.
//!
//! ## Why this exists
//!
//! `pcap_findalldevs` gives a device name and a *description*, and the
//! description is the hardware: `Intel(R) Ethernet Controller (3) I225-V #2`.
//! What a person calls that adapter is `Ethernet 2`, and that name lives only
//! in Windows. The Python agent gets it through scapy, whose `conf.ifaces`
//! correlates pcap's list with the Windows one; this is the same fact read
//! directly, because the Rust agent has no scapy and deliberately no crate that
//! would give it one.
//!
//! **It was found by running both agents side by side.** The comparison in
//! `scripts/agent/agent-compare.ts` picks its adapter by substring, asked for
//! `Ethernet 2`, and the Rust agent offered no such string - so the two ran on
//! different adapters until the substring was changed to the chipset. That is
//! the user-facing shape of the bug: anything selecting an adapter by the name
//! the user knows finds nothing.
//!
//! ## `iphlpapi` is linked, not loaded
//!
//! `npcap.rs` loads `wpcap.dll` by hand because it lives in a directory off the
//! default search path and may be absent entirely. `iphlpapi.dll` is a system
//! DLL present on every Windows, so it is an ordinary import - the dynamic
//! dance there buys nothing here.
//!
//! ## Failure is a degraded label, never an error
//!
//! Every path returns the pcap description rather than propagating: an agent
//! that refused to enumerate adapters because a cosmetic lookup failed would
//! trade the whole capture for a nicer string. `friendly_names` answers with an
//! empty map and `label_for` falls through to exactly the old behaviour.

use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[link(name = "iphlpapi")]
extern "system" {
    fn GetAdaptersAddresses(
        family: u32,
        flags: u32,
        reserved: *mut c_void,
        addresses: *mut IpAdapterAddresses,
        size: *mut u32,
    ) -> u32;
}

/// `IP_ADAPTER_ADDRESSES_LH`, **declared only as far as it is read**.
///
/// The real struct continues for another twenty-odd fields. Stopping at
/// `friendly_name` is safe in the one direction that matters - the buffer the
/// OS filled is always at least as long as the real struct, so every field
/// named here is within it - and it means a field added to the tail by a future
/// Windows cannot move anything this code touches. The opposite arrangement,
/// declaring the whole thing, is what has to be revisited when the tail grows.
///
/// The leading union (`ULONGLONG Alignment` over `{ULONG Length; ULONG
/// IfIndex;}`) is 8 bytes under either arm and is what forces the 8-byte
/// alignment the buffer below is allocated for.
#[repr(C)]
struct IpAdapterAddresses {
    /// The first half of the leading union's `{ULONG Length; IF_INDEX IfIndex}`.
    _length: u32,
    /// `IfIndex` - the **IPv4** interface index, 0 on an adapter with IPv4
    /// unbound. It is what scapy reports as `index` and therefore what
    /// `local-agent/adapters.py` joins routes and neighbours on, so it is the
    /// join key here too rather than the IPv6 index further down.
    if_index: u32,
    next: *mut IpAdapterAddresses,
    /// ANSI, and the join key: the adapter's GUID in braces, e.g.
    /// `{28524299-03EF-4F59-A8D2-419D761418B7}`. Npcap's device name is that
    /// same GUID behind `\Device\NPF_`.
    adapter_name: *mut c_char,
    first_unicast: *mut c_void,
    _first_anycast: *mut c_void,
    _first_multicast: *mut c_void,
    first_dns_server: *mut c_void,
    _dns_suffix: *mut u16,
    /// Wide. Windows' own hardware description - usually the same string pcap
    /// reports. Not what the label is after, and exactly what `adapter_config`
    /// sends as `description`.
    description: *mut u16,
    /// Wide. The connection name: `Ethernet 2`, `Wi-Fi`, or a localized one.
    friendly_name: *mut u16,
    /// `MAX_ADAPTER_ADDRESS_LENGTH` is 8; an Ethernet MAC uses the first 6 and
    /// `physical_address_length` says how many are real. **This is what the
    /// app's checksum verdict rests on** - with no host MAC, `directionFromMacs`
    /// answers `Unknown` for every frame and every frame this machine sent is
    /// validated against bytes the NIC had not finished writing.
    physical_address: [u8; 8],
    physical_address_length: u32,
    _flags: u32,
    _mtu: u32,
    /// `IFTYPE`. 24 is `IF_TYPE_SOFTWARE_LOOPBACK`, the one row Npcap's
    /// GUID-less `\Device\NPF_Loopback` corresponds to.
    if_type: u32,
    _oper_status: u32,
}

/// `IF_TYPE_SOFTWARE_LOOPBACK`.
pub const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

/// `SOCKET_ADDRESS`, declared as its own struct **on purpose**.
///
/// Inlining its two fields would put the next member at offset 28, where C puts
/// it at 32: the struct contains a pointer, so it aligns to 8 and occupies 16
/// bytes with four of padding. Letting the compiler apply that rule is how the
/// offsets stay right without any of them being written down.
#[repr(C)]
struct SocketAddress {
    lp_sockaddr: *mut c_void,
    _i_sockaddr_length: i32,
}

/// `IP_ADAPTER_UNICAST_ADDRESS_LH`, declared as far as the prefix length.
#[repr(C)]
struct IpAdapterUnicastAddress {
    _alignment: u64,
    next: *mut IpAdapterUnicastAddress,
    address: SocketAddress,
    _prefix_origin: u32,
    /// `NL_SUFFIX_ORIGIN`. 5 is `IpSuffixOriginRandom`: an RFC 4941 privacy
    /// address, which is the whole of what `temporary` means.
    suffix_origin: u32,
    _dad_state: u32,
    _valid_lifetime: u32,
    _preferred_lifetime: u32,
    _lease_lifetime: u32,
    on_link_prefix_length: u8,
}

/// `IP_ADAPTER_DNS_SERVER_ADDRESS_XP`. The same head as the unicast entry, and
/// nothing past the address is read.
#[repr(C)]
struct IpAdapterDnsServerAddress {
    _alignment: u64,
    next: *mut IpAdapterDnsServerAddress,
    address: SocketAddress,
}

#[repr(C)]
struct SockaddrIn {
    family: u16,
    _port: u16,
    addr: [u8; 4],
}

#[repr(C)]
struct SockaddrIn6 {
    family: u16,
    _port: u16,
    _flowinfo: u32,
    addr: [u8; 16],
}

const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

const AF_UNSPEC: u32 = 0;
const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// One enumeration serves both the labels and `adapter_config`.
///
/// The unicast and DNS lists are no longer skipped, because the adapter report
/// needs them - and fetching them once is the point: two calls with two flag
/// sets is two things to keep in step, for a handful of adapters whose address
/// lists cost microseconds to assemble.
///
/// **`INCLUDE_ALL_INTERFACES` is the one that is not an optimisation.** Without
/// it the call answers with adapters that have an IP binding, which silently
/// omits every NDIS interface that does not - here, the three `WAN Miniport`
/// entries. Npcap enumerates them, so they appeared in the list with a bare
/// description while every adapter beside them had a name. Measured, not
/// assumed: they gained their names the moment this bit was set, and nothing
/// else in the list changed.
///
/// `SKIP_FRIENDLY_NAME` (0x0020) is deliberately absent, which is worth stating
/// because setting it would empty this module's only output while leaving every
/// call here returning success.
///
/// **The two that matter are scapy's two**, `INCLUDE_PREFIX | INCLUDE_ALL_INTERFACES`,
/// because scapy's `get_windows_if_list` is what `local-agent/adapters.py` walks
/// and the adapter report has to list the same adapters in the same order. The
/// two `SKIP_` bits only drop lists neither agent reads.
const GAA_FLAGS: u32 = 0x0002 /* SKIP_ANYCAST */
    | 0x0004 /* SKIP_MULTICAST */
    | 0x0010 /* INCLUDE_PREFIX */
    | 0x0100 /* INCLUDE_ALL_INTERFACES */;

/// U+200E LEFT-TO-RIGHT MARK and U+200F RIGHT-TO-LEFT MARK.
///
/// Windows embeds these in localized adapter names, and they are invisible - so
/// a label carrying them looks identical to one that does not, compares
/// unequal, and breaks any match on the name. `local-agent/agent.py`'s
/// `_strip_rtl_marks` removes exactly these two and then trims; this is that
/// function, and the two must agree or the agents disagree about a label while
/// both look right on screen.
fn strip_rtl_marks(text: &str) -> String {
    text.chars()
        .filter(|c| *c != '\u{200e}' && *c != '\u{200f}')
        .collect::<String>()
        .trim()
        .to_string()
}

/// A NUL-terminated wide string, or `None` if the pointer is null.
///
/// Lossy because a name is being shown to a person: a lone surrogate in an
/// adapter name should cost that one character, not the whole enumeration.
unsafe fn wide_to_string(ptr: *const u16) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    Some(String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len)))
}

/// A NUL-terminated ANSI string, or `None` if the pointer is null.
unsafe fn ansi_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// The GUID inside an Npcap device name, uppercased for comparison.
///
/// `\Device\NPF_{28524299-...}` -> `{28524299-...}`. Returns `None` for
/// `\Device\NPF_Loopback`, which carries no GUID and therefore joins to no
/// Windows adapter - see `label_for`.
pub fn guid_of(device_name: &str) -> Option<String> {
    let start = device_name.find('{')?;
    let end = device_name[start..].find('}')? + start;
    Some(device_name[start..=end].to_uppercase())
}

/// One unicast address, as `GetAdaptersAddresses` lists it.
pub struct UnicastAddress {
    /// The address itself, for arithmetic - the broadcast is computed from it
    /// and the IPv6 scope is read from it.
    pub ip: IpAddr,
    /// The same address as text, written by Windows' own formatter - see
    /// `format_ipv6` for why that and not RFC 5952.
    pub text: String,
    /// `OnLinkPrefixLength`, which is what `Get-NetIPAddress` reports as
    /// `PrefixLength` - the same row of the same table.
    pub prefix_length: u8,
    /// `NL_SUFFIX_ORIGIN`; 5 is a privacy address.
    pub suffix_origin: u32,
}

/// One adapter, as `GetAdaptersAddresses` reports it **and in the order it
/// reports them**, which is the order `adapter_config` lists them in - scapy's
/// `get_windows_if_list` walks the same linked list, so the Python agent's
/// order is this order.
pub struct WinAdapter {
    /// `AdapterName` as given: the GUID in braces.
    pub guid: String,
    /// `IfIndex` - see the struct field for why the IPv4 one.
    pub if_index: u32,
    pub if_type: u32,
    /// Raw, right-to-left marks and all. `adapter_config` looks the adapter's
    /// link statistics up by this exact string before it cleans it, because
    /// that is the key they are filed under.
    pub friendly_name: Option<String>,
    pub description: Option<String>,
    /// **Only a six-byte address is a MAC**, which is scapy's `_get_mac` rule:
    /// a tunnel's 8-byte or a WAN Miniport's 0-byte address is reported as no
    /// MAC rather than as a string of the wrong shape.
    pub mac: Option<String>,
    /// Every unicast address, IPv4 and IPv6 interleaved as the OS lists them.
    pub unicast: Vec<UnicastAddress>,
    /// `FirstDnsServerAddress`, in order - what scapy calls `nameservers`.
    pub dns_servers: Vec<String>,
}

/// What the capture label needs about one adapter, keyed by GUID.
///
/// The name alone. `adapter_config` used to be built from this too, carrying a
/// MAC, addresses and resolvers with no order and nothing to pair them with; it
/// reads `enumerate` now, which keeps the order `adapters.py` sends.
pub struct AdapterFacts {
    pub friendly_name: Option<String>,
}

/// `aa:bb:cc:dd:ee:02`, or `None` unless there are exactly six bytes.
///
/// Lowercase because `hostFromAdapters` lowercases what it stores and the
/// dissector formats the frame's MACs the same way. A mismatch in case would
/// leave `host.macs` full and every lookup missing - the same symptom as
/// sending no MAC at all, which is the bug this whole message exists to fix.
pub fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 6 {
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

/// The address behind a `SOCKET_ADDRESS`, parsed and as text.
///
/// Reads the family first and picks the struct from it rather than trusting the
/// declared length: the length is what the OS says it wrote, the family is what
/// says how to read it.
unsafe fn sockaddr_to_ip(addr: &SocketAddress) -> Option<(IpAddr, String)> {
    let p = addr.lp_sockaddr;
    if p.is_null() {
        return None;
    }
    match *(p as *const u16) {
        AF_INET => {
            let v4 = &*(p as *const SockaddrIn);
            let ip = Ipv4Addr::from(v4.addr);
            Some((IpAddr::V4(ip), ip.to_string()))
        }
        AF_INET6 => {
            let v6 = &*(p as *const SockaddrIn6);
            Some((IpAddr::V6(Ipv6Addr::from(v6.addr)), format_ipv6(&v6.addr)))
        }
        _ => None,
    }
}

#[link(name = "ntdll")]
extern "system" {
    /// Writes the text and returns a pointer to its terminating NUL.
    fn RtlIpv6AddressToStringW(address: *const [u8; 16], text: *mut u16) -> *mut u16;
}

/// An IPv6 address as **Windows** writes it, which is not quite RFC 5952.
///
/// This was an RFC 5952 formatter written here, and it agreed with Windows on
/// every address with no IPv4 inside it - and disagreed on the ones with:
/// Windows writes `::ffff:10.0.0.7`, `::10.0.0.7`, `::ffff:0:10.0.0.7` and the
/// ISATAP `fe80::5efe:10.0.0.7` with a dotted quad, where the formatter wrote
/// hex. Every address the Python agent reports went through that same Windows
/// function - `socket.inet_ntop` for scapy's adapter list, psutil's
/// `RtlIpv6AddressToStringA` for the socket table - so asking the OS is the
/// only way the two agents are guaranteed to write the same string. And the
/// string is the key: a socket or an adapter address spelled differently from
/// the one it is compared against matches nothing.
pub fn format_ipv6(bytes: &[u8; 16]) -> String {
    // 46 is INET6_ADDRSTRLEN for the non-Ex call; the headroom is free.
    let mut buffer = [0u16; 64];
    let end = unsafe { RtlIpv6AddressToStringW(bytes, buffer.as_mut_ptr()) };
    let len = if end.is_null() {
        buffer.iter().position(|c| *c == 0).unwrap_or(0)
    } else {
        (end as usize - buffer.as_ptr() as usize) / 2
    };
    String::from_utf16_lossy(&buffer[..len.min(buffer.len())])
}

/// Every adapter Windows will name, in the order it names them.
///
/// Empty on any failure, which every caller degrades through: `label_for` falls
/// back to the pcap description and the adapter report has nothing to send. An
/// agent that refused to enumerate because one lookup failed would trade the
/// capture for a nicer string.
pub fn enumerate() -> Vec<WinAdapter> {
    enumerate_with(GAA_FLAGS)
}

/// The same walk with the caller's flags - `adapter_config` also needs the
/// list psutil reads, which is `GetAdaptersAddresses` with **no** flags: only
/// adapters with an IP binding, and so no WAN Miniports.
pub fn enumerate_with(flags: u32) -> Vec<WinAdapter> {
    let mut out = Vec::new();

    // 15 KB is what the docs suggest to avoid the common second call; the retry
    // is still here because the count is not ours to predict. `u64` rather than
    // `u8` because the struct leads with one and a misaligned read of it is
    // undefined - a `Vec<u8>` carries no such guarantee.
    let mut words: Vec<u64> = vec![0; 15 * 1024 / 8];
    let mut size = (words.len() * 8) as u32;

    // Two attempts, not a loop to exhaustion: the second call is made with the
    // size the OS itself asked for, so a third would mean the adapter list grew
    // between two calls microseconds apart. Giving up there yields plain
    // descriptions, which is the documented degraded answer.
    for _ in 0..2 {
        let result = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC,
                flags,
                std::ptr::null_mut(),
                words.as_mut_ptr() as *mut IpAdapterAddresses,
                &mut size,
            )
        };

        if result == ERROR_BUFFER_OVERFLOW {
            words = vec![0; (size as usize + 7) / 8];
            size = (words.len() * 8) as u32;
            continue;
        }
        if result != ERROR_SUCCESS {
            return out;
        }

        let mut adapter = words.as_ptr() as *const IpAdapterAddresses;
        while !adapter.is_null() {
            unsafe {
                let a = &*adapter;
                if let Some(guid) = ansi_to_string(a.adapter_name) {
                    let mac_len =
                        (a.physical_address_length as usize).min(a.physical_address.len());

                    let mut unicast = Vec::new();
                    let mut entry = a.first_unicast as *const IpAdapterUnicastAddress;
                    while !entry.is_null() {
                        let u = &*entry;
                        if let Some((ip, text)) = sockaddr_to_ip(&u.address) {
                            unicast.push(UnicastAddress {
                                ip,
                                text,
                                prefix_length: u.on_link_prefix_length,
                                suffix_origin: u.suffix_origin,
                            });
                        }
                        entry = u.next;
                    }

                    let mut dns_servers = Vec::new();
                    let mut dns = a.first_dns_server as *const IpAdapterDnsServerAddress;
                    while !dns.is_null() {
                        let d = &*dns;
                        if let Some((_, text)) = sockaddr_to_ip(&d.address) {
                            dns_servers.push(text);
                        }
                        dns = d.next;
                    }

                    out.push(WinAdapter {
                        guid,
                        if_index: a.if_index,
                        if_type: a.if_type,
                        friendly_name: wide_to_string(a.friendly_name),
                        description: wide_to_string(a.description),
                        mac: format_mac(&a.physical_address[..mac_len]),
                        unicast,
                        dns_servers,
                    });
                }
                adapter = a.next;
            }
        }
        return out;
    }

    out
}

/// The connection name of every adapter, as GUID -> facts, for the labels.
pub fn adapter_facts() -> HashMap<String, AdapterFacts> {
    enumerate()
        .into_iter()
        .map(|a| (a.guid.to_uppercase(), AdapterFacts { friendly_name: a.friendly_name }))
        .collect()
}

/// The label for one adapter, by the rule `agent.py`'s `build_interface_label`
/// follows - so the two agents name the same adapter the same way.
///
/// `{connection name} ({hardware description})`, each with its RTL marks
/// stripped, collapsing to whichever single part exists when they do not make a
/// distinct pair.
///
/// **`\Device\NPF_Loopback` deliberately keeps its description.** It carries no
/// GUID, so there is no adapter to join it to without matching on
/// `IF_TYPE_SOFTWARE_LOOPBACK` deep in the struct's tail - and what that would
/// win is `Loopback Pseudo-Interface 1` in place of Npcap's own
/// `Adapter for loopback traffic capture`, which is the clearer of the two.
/// This is the one label that stays different from the Python agent's, and it
/// is a choice rather than an omission.
/// Windows' own name for the connection behind a device, when it has one -
/// the first half of `label_for`'s label, on its own.
pub fn connection_name(device_name: &str, facts: &HashMap<String, AdapterFacts>) -> Option<String> {
    guid_of(device_name)
        .and_then(|guid| facts.get(&guid))
        .and_then(|f| f.friendly_name.clone())
        .map(|n| strip_rtl_marks(&n))
        .filter(|n| !n.is_empty())
}

pub fn label_for(
    device_name: &str,
    description: Option<&str>,
    facts: &HashMap<String, AdapterFacts>,
) -> String {
    let name = guid_of(device_name)
        .and_then(|guid| facts.get(&guid))
        .and_then(|f| f.friendly_name.clone())
        .map(|n| strip_rtl_marks(&n))
        .unwrap_or_default();
    let described = strip_rtl_marks(description.unwrap_or(""));

    if name.is_empty() {
        // Exactly the pre-existing behaviour: description, else the raw device
        // name, which is at least addressable.
        return if described.is_empty() { device_name.to_string() } else { described };
    }
    if described.is_empty() || described == name {
        return name;
    }
    format!("{name} ({described})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_is_lifted_out_of_an_npcap_device_name() {
        assert_eq!(
            guid_of(r"\Device\NPF_{28524299-03EF-4F59-A8D2-419D761418B7}").as_deref(),
            Some("{28524299-03EF-4F59-A8D2-419D761418B7}"),
        );
        assert_eq!(guid_of(r"\Device\NPF_Loopback"), None);
    }

    #[test]
    fn rtl_marks_go_and_the_text_is_trimmed() {
        assert_eq!(strip_rtl_marks("\u{200e}\u{200f}Ethernet 2 "), "Ethernet 2");
    }

    /// A facts entry carrying nothing but the name, which is all `label_for`
    /// reads. Written out rather than derived so a field added to `AdapterFacts`
    /// does not quietly change what this test is about.
    fn named(name: &str) -> AdapterFacts {
        AdapterFacts { friendly_name: Some(name.to_string()) }
    }

    /// A MAC has to come out in the case and separator `hostFromAdapters`
    /// stores and `directionFromMacs` compares - the whole message is useless
    /// if these disagree, and it would fail silently as "no host identity".
    #[test]
    fn a_mac_is_lowercase_and_colon_separated() {
        assert_eq!(
            format_mac(&[0xAA, 0xbb, 0x0C, 0xdd, 0xee, 0x02]).as_deref(),
            Some("aa:bb:0c:dd:ee:02"),
        );
        // Six of the eight bytes are real on Ethernet; a zero-length address is
        // "no MAC" rather than an empty string.
        assert_eq!(format_mac(&[]), None);
        // scapy's `_get_mac` answers "" for any length but six, and
        // `adapters.py`'s `_mac` turns "" into None - so an 8-byte tunnel
        // address is no MAC, not a MAC of the wrong shape.
        assert_eq!(format_mac(&[0, 0, 0, 0, 0, 0, 0, 0xe0]), None);
    }

    #[test]
    fn ipv6_text_collapses_the_longest_zero_run_once() {
        let mut a = [0u8; 16];
        a[0] = 0xfe; a[1] = 0x80; a[15] = 1;
        assert_eq!(format_ipv6(&a), "fe80::1");

        // Loopback is all zeroes but the last byte.
        let mut lo = [0u8; 16];
        lo[15] = 1;
        assert_eq!(format_ipv6(&lo), "::1");

        // Only the LONGEST run collapses, and the shorter one is written out -
        // two `::` in one address would be ambiguous to parse.
        let mut two_runs = [0u8; 16];
        two_runs[0] = 0x20; two_runs[1] = 0x01;
        two_runs[6] = 0x12; two_runs[7] = 0x34;
        two_runs[15] = 0x01;
        assert_eq!(format_ipv6(&two_runs), "2001:0:0:1234::1");

        // A run of one is written out rather than collapsed.
        let mut single = [0u8; 16];
        for (i, b) in single.iter_mut().enumerate() {
            *b = if i % 2 == 0 { 0x00 } else { 0x11 };
        }
        single[4] = 0; single[5] = 0;
        assert_eq!(format_ipv6(&single), "11:11:0:11:11:11:11:11");

        // An address with no zero groups at all keeps every one of them.
        let full = [0x20u8, 0x01, 0x0d, 0xb8, 0x11, 0x11, 0x22, 0x22,
                    0x33, 0x33, 0x44, 0x44, 0x55, 0x55, 0x66, 0x66];
        assert_eq!(format_ipv6(&full), "2001:db8:1111:2222:3333:4444:5555:6666");
    }

    /// Where Windows' formatter parts from RFC 5952, and why the OS is asked.
    ///
    /// Every expected string is what `socket.inet_ntop` printed for the same
    /// bytes on the machine this was written on - the call scapy's adapter list
    /// and psutil's socket table both go through, so it is the spelling the
    /// Python agent sends. A hand-written RFC formatter printed the hex forms.
    #[test]
    fn ipv6_text_is_windows_own_including_embedded_ipv4() {
        let v6 = |hex: &str| -> [u8; 16] {
            std::array::from_fn(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        };
        assert_eq!(format_ipv6(&v6("00000000000000000000ffff0a000007")), "::ffff:10.0.0.7");
        assert_eq!(format_ipv6(&v6("0000000000000000000000000a000007")), "::10.0.0.7");
        assert_eq!(format_ipv6(&v6("0000000000000000ffff00000a000007")), "::ffff:0:10.0.0.7");
        assert_eq!(format_ipv6(&v6("fe8000000000000000005efe0a000007")), "fe80::5efe:10.0.0.7");
        // Ties go to the first run, as RFC 5952 says too.
        assert_eq!(format_ipv6(&v6("fe800000000000000200000000000000")), "fe80::200:0:0:0");
        assert_eq!(format_ipv6(&v6("20010db8000000000001000000000001")), "2001:db8::1:0:0:1");
        assert_eq!(format_ipv6(&v6("00000000000000000000000000000000")), "::");
        // A resolver Windows configures on an adapter with none of its own,
        // as `adapters.py` reported it on this machine.
        assert_eq!(format_ipv6(&v6("fec000000000ffff0000000000000001")), "fec0:0:0:ffff::1");
    }

    /// The pairing rule, against the four shapes `agent.py` distinguishes.
    #[test]
    fn the_label_pairs_a_name_with_a_description() {
        let mut friendly = HashMap::new();
        friendly.insert("{AAAA}".to_string(), named("Ethernet 2"));
        friendly.insert("{BBBB}".to_string(), named("\u{200f}Wi-Fi"));
        friendly.insert("{CCCC}".to_string(), named("Same"));

        // Both halves present and distinct.
        assert_eq!(
            label_for(r"\Device\NPF_{AAAA}", Some("Intel I225-V"), &friendly),
            "Ethernet 2 (Intel I225-V)",
        );
        // The RTL mark must not survive into the label.
        assert_eq!(label_for(r"\Device\NPF_{BBBB}", None, &friendly), "Wi-Fi");
        // A description equal to the name is not repeated.
        assert_eq!(label_for(r"\Device\NPF_{CCCC}", Some("Same"), &friendly), "Same");
        // No friendly name: the old behaviour, unchanged.
        assert_eq!(
            label_for(r"\Device\NPF_Loopback", Some("Adapter for loopback traffic capture"), &friendly),
            "Adapter for loopback traffic capture",
        );
        // Neither: the device name, which is at least addressable.
        assert_eq!(label_for(r"\Device\NPF_Loopback", None, &friendly), r"\Device\NPF_Loopback");
    }
}
