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
    _first_unicast: *mut c_void,
    _first_anycast: *mut c_void,
    _first_multicast: *mut c_void,
    _first_dns_server: *mut c_void,
    _dns_suffix: *mut u16,
    /// Wide. Windows' own hardware description - usually the same string pcap
    /// reports, which is why it is not what this module is after.
    _description: *mut u16,
    /// Wide. The connection name: `Ethernet 2`, `Wi-Fi`, or a localized one.
    friendly_name: *mut u16,
}

const AF_UNSPEC: u32 = 0;
const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

/// Everything but the adapter identity. The address lists are the expensive
/// part of this call and nothing here reads one.
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
const GAA_FLAGS: u32 = 0x0001 /* SKIP_UNICAST */
    | 0x0002 /* SKIP_ANYCAST */
    | 0x0004 /* SKIP_MULTICAST */
    | 0x0008 /* SKIP_DNS_SERVER */
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
fn guid_of(device_name: &str) -> Option<String> {
    let start = device_name.find('{')?;
    let end = device_name[start..].find('}')? + start;
    Some(device_name[start..=end].to_uppercase())
}

/// Every adapter Windows knows, as GUID -> connection name.
///
/// Empty on any failure, which `label_for` reads as "no friendly name" and
/// answers with the description alone.
pub fn friendly_names() -> HashMap<String, String> {
    let mut names = HashMap::new();

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
            return names;
        }

        let mut adapter = words.as_ptr() as *const IpAdapterAddresses;
        while !adapter.is_null() {
            unsafe {
                if let (Some(guid), Some(friendly)) = (
                    ansi_to_string((*adapter).adapter_name),
                    wide_to_string((*adapter).friendly_name),
                ) {
                    names.insert(guid.to_uppercase(), friendly);
                }
                adapter = (*adapter).next;
            }
        }
        return names;
    }

    names
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
    friendly: &HashMap<String, String>,
) -> String {
    let name = guid_of(device_name)
        .and_then(|guid| friendly.get(&guid).cloned())
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

    /// The pairing rule, against the four shapes `agent.py` distinguishes.
    #[test]
    fn the_label_pairs_a_name_with_a_description() {
        let mut friendly = HashMap::new();
        friendly.insert("{AAAA}".to_string(), "Ethernet 2".to_string());
        friendly.insert("{BBBB}".to_string(), "\u{200f}Wi-Fi".to_string());
        friendly.insert("{CCCC}".to_string(), "Same".to_string());

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
