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
    _alignment: u64,
    next: *mut IpAdapterAddresses,
    /// ANSI, and the join key: the adapter's GUID in braces, e.g.
    /// `{28524299-03EF-4F59-A8D2-419D761418B7}`. Npcap's device name is that
    /// same GUID behind `\Device\NPF_`.
    adapter_name: *mut c_char,
    first_unicast: *mut c_void,
    _first_anycast: *mut c_void,
    _first_multicast: *mut c_void,
    first_dns_server: *mut c_void,
    dns_suffix: *mut u16,
    /// Wide. Windows' own hardware description - usually the same string pcap
    /// reports, which is why it is not what this module is after.
    _description: *mut u16,
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
    mtu: u32,
    _if_type: u32,
    /// `IF_OPER_STATUS`: 1 is up, 2 is down. Anything else is a state this does
    /// not translate, and is reported as "not known" rather than as either.
    oper_status: u32,
}

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
    _suffix_origin: u32,
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
const GAA_FLAGS: u32 = 0x0002 /* SKIP_ANYCAST */
    | 0x0004 /* SKIP_MULTICAST */
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

/// One IPv4 address the OS has configured.
pub struct Ipv4Entry {
    pub address: String,
    pub prefix_length: Option<u8>,
}

/// One IPv6 address, with the scope the app renders beside it.
pub struct Ipv6Entry {
    pub address: String,
    pub prefix_length: Option<u8>,
    pub scope: Option<&'static str>,
}

/// What Windows knows about one adapter, keyed by GUID.
///
/// Every field is optional and a `None` means **not known** - never zero,
/// absent or disabled. That is `AgentAdapter`'s stated contract in
/// `src/services/agentProtocol.ts`, and it is what makes a partial
/// implementation honest rather than a lie by omission: the app validates only
/// `id` and the three lists, precisely so an agent can answer with the half it
/// can read.
pub struct AdapterFacts {
    pub friendly_name: Option<String>,
    /// Lowercase, colon-separated. **The field the checksum verdict rests on.**
    pub mac: Option<String>,
    pub status: Option<&'static str>,
    pub mtu: Option<u32>,
    pub ipv4: Vec<Ipv4Entry>,
    pub ipv6: Vec<Ipv6Entry>,
    pub dns_servers: Vec<String>,
    pub dns_suffix: Option<String>,
}

/// `aa:bb:cc:dd:ee:02`, or `None` when the adapter has no hardware address.
///
/// Lowercase because `hostFromAdapters` lowercases what it stores and the
/// dissector formats the frame's MACs the same way. A mismatch in case would
/// leave `host.macs` full and every lookup missing - the same symptom as
/// sending no MAC at all, which is the bug this whole message exists to fix.
fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"))
}

/// The address behind a `SOCKET_ADDRESS`, as text, with its family.
///
/// Reads the family first and picks the struct from it rather than trusting the
/// declared length: the length is what the OS says it wrote, the family is what
/// says how to read it.
unsafe fn sockaddr_to_string(addr: &SocketAddress) -> Option<(u16, String)> {
    let p = addr.lp_sockaddr;
    if p.is_null() {
        return None;
    }
    match *(p as *const u16) {
        AF_INET => {
            let v4 = &*(p as *const SockaddrIn);
            let a = v4.addr;
            Some((AF_INET, format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3])))
        }
        AF_INET6 => {
            let v6 = &*(p as *const SockaddrIn6);
            Some((AF_INET6, format_ipv6(&v6.addr)))
        }
        _ => None,
    }
}

/// RFC 5952 text for an IPv6 address: lowercase hex, the longest run of zero
/// groups collapsed once, and a run of one never collapsed.
pub fn format_ipv6(bytes: &[u8; 16]) -> String {
    let groups: [u16; 8] =
        std::array::from_fn(|i| ((bytes[i * 2] as u16) << 8) | bytes[i * 2 + 1] as u16);

    let (mut best_at, mut best_len, mut at, mut len) = (usize::MAX, 0usize, usize::MAX, 0usize);
    for (i, g) in groups.iter().enumerate() {
        if *g == 0 {
            if len == 0 {
                at = i;
            }
            len += 1;
            if len > best_len {
                best_at = at;
                best_len = len;
            }
        } else {
            len = 0;
        }
    }
    // A run of one is written out. `::` for a single zero group parses, and is
    // not what RFC 5952 asks anyone to print.
    if best_len < 2 {
        best_at = usize::MAX;
    }

    let mut out = String::new();
    let mut i = 0usize;
    while i < 8 {
        if i == best_at {
            // Always both colons. Writing one on the theory that the previous
            // group left the other is wrong in the middle of an address, where
            // the separator before a group is only added when the buffer does
            // not already end in one - `fe80::1` came out as `fe80:1`.
            out.push_str("::");
            i += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[i]));
        i += 1;
    }
    if out.is_empty() {
        "::".to_string()
    } else {
        out
    }
}

/// Which of the app's four IPv6 scopes an address falls in.
///
/// `None` is a real answer rather than a default: an address whose scope this
/// does not recognise is not quietly called global.
fn ipv6_scope(bytes: &[u8; 16]) -> Option<&'static str> {
    if bytes[..15].iter().all(|b| *b == 0) && bytes[15] == 1 {
        return Some("loopback");
    }
    if bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80 {
        return Some("link-local");
    }
    if (bytes[0] & 0xfe) == 0xfc {
        return Some("ula");
    }
    if bytes[0] == 0xff {
        return None; // multicast, which is none of the four
    }
    Some("global")
}

/// Everything Windows will say about every adapter, as GUID -> facts.
///
/// Empty on any failure, which every caller degrades through: `label_for` falls
/// back to the pcap description and the adapter report has nothing to send. An
/// agent that refused to enumerate because one lookup failed would trade the
/// capture for a nicer string.
pub fn adapter_facts() -> HashMap<String, AdapterFacts> {
    let mut facts = HashMap::new();

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
                GAA_FLAGS,
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
            return facts;
        }

        let mut adapter = words.as_ptr() as *const IpAdapterAddresses;
        while !adapter.is_null() {
            unsafe {
                let a = &*adapter;
                if let Some(guid) = ansi_to_string(a.adapter_name) {
                    let mac_len =
                        (a.physical_address_length as usize).min(a.physical_address.len());
                    let (mut ipv4, mut ipv6) = (Vec::new(), Vec::new());

                    let mut unicast = a.first_unicast as *const IpAdapterUnicastAddress;
                    while !unicast.is_null() {
                        let u = &*unicast;
                        if let Some((family, text)) = sockaddr_to_string(&u.address) {
                            let prefix = Some(u.on_link_prefix_length);
                            if family == AF_INET {
                                ipv4.push(Ipv4Entry { address: text, prefix_length: prefix });
                            } else {
                                let v6 = &*(u.address.lp_sockaddr as *const SockaddrIn6);
                                ipv6.push(Ipv6Entry {
                                    address: text,
                                    prefix_length: prefix,
                                    scope: ipv6_scope(&v6.addr),
                                });
                            }
                        }
                        unicast = u.next;
                    }

                    let mut dns_servers = Vec::new();
                    let mut dns = a.first_dns_server as *const IpAdapterDnsServerAddress;
                    while !dns.is_null() {
                        let d = &*dns;
                        if let Some((_, text)) = sockaddr_to_string(&d.address) {
                            dns_servers.push(text);
                        }
                        dns = d.next;
                    }

                    facts.insert(
                        guid.to_uppercase(),
                        AdapterFacts {
                            friendly_name: wide_to_string(a.friendly_name),
                            mac: format_mac(&a.physical_address[..mac_len]),
                            // 1 is up, 2 is down. Every other IF_OPER_STATUS is
                            // a state this does not translate, and saying
                            // nothing beats rounding it to either.
                            status: match a.oper_status {
                                1 => Some("up"),
                                2 => Some("down"),
                                _ => None,
                            },
                            mtu: if a.mtu == 0 || a.mtu == u32::MAX { None } else { Some(a.mtu) },
                            ipv4,
                            ipv6,
                            dns_servers,
                            dns_suffix: wide_to_string(a.dns_suffix).filter(|s| !s.is_empty()),
                        },
                    );
                }
                adapter = a.next;
            }
        }
        return facts;
    }

    facts
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
        AdapterFacts {
            friendly_name: Some(name.to_string()),
            mac: None,
            status: None,
            mtu: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            dns_servers: Vec::new(),
            dns_suffix: None,
        }
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

    #[test]
    fn a_scope_is_named_or_withheld_but_never_guessed() {
        let mut ll = [0u8; 16];
        ll[0] = 0xfe; ll[1] = 0x80;
        assert_eq!(ipv6_scope(&ll), Some("link-local"));

        let mut ula = [0u8; 16];
        ula[0] = 0xfd;
        assert_eq!(ipv6_scope(&ula), Some("ula"));

        let mut lo = [0u8; 16];
        lo[15] = 1;
        assert_eq!(ipv6_scope(&lo), Some("loopback"));

        let mut global = [0u8; 16];
        global[0] = 0x20; global[1] = 0x01;
        assert_eq!(ipv6_scope(&global), Some("global"));

        // Multicast is none of the four, and is withheld rather than called
        // global - `null` is a value the app renders.
        let mut mcast = [0u8; 16];
        mcast[0] = 0xff; mcast[1] = 0x02;
        assert_eq!(ipv6_scope(&mcast), None);
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
