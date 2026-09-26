//! What the Npcap driver's device object admits, as an SDDL string.
//!
//! The port of `local-agent/npcap_access.py`, and its header is the reason:
//! Npcap's installer has a checkbox - *"Restrict Npcap driver's access to
//! Administrators only"* - that is **not ticked by default**, and unticked, the
//! capture devices are open to every local account. The app recommends ticking
//! it (ADR 0033), and a recommendation has to know whether it has been taken.
//!
//! ## The agent reports the string and decides nothing
//!
//! ADR 0010's rule. `hello.npcapAccess` carries the DACL as SDDL and
//! `src/services/npcapAccess.ts` turns it into an answer - which it gives
//! **priority over the registry**, because `AdminOnly` under
//! `HKLM\SOFTWARE\Npcap` is what the installer recorded while the DACL is what
//! the kernel enforces, and the two disagree whenever the value is edited
//! without the driver being restarted.
//!
//! This agent sent `null` there until now. The app read that as "not known"
//! and fell back to the registry - so on a machine whose registry says
//! admin-only over a device that still grants `WD`, it said "administrators
//! only". That is the confidently wrong answer in the one direction that
//! matters, and ADR 0037's note that a null here is "never wrongly permissive"
//! was mistaken about it.
//!
//! ## Why `\\.\NPCAP`
//!
//! `GetNamedSecurityInfo` with `SE_FILE_OBJECT` resolves a Win32 path; the NT
//! object path `\Device\NPCAP` fails. The control device carries the same
//! descriptor as the per-adapter ones and is always there when the driver is.
//! Reading a DACL needs only `READ_CONTROL`, which every shape of this
//! descriptor grants to somebody who can run the app - so it works unelevated,
//! which is also what makes it testable here.
//!
//! **Nothing here fails loudly.** No driver, a call that fails, a descriptor
//! that will not convert - all answer `None`, which the app renders as
//! "unknown" and never as either verdict. An error escaping would take down the
//! `hello` that carries it.

#![cfg(windows)]

use std::ffi::c_void;

/// The control device. Per-adapter devices are `\\.\npcap\{GUID}` and carry the
/// same descriptor, so asking the one that is always there is enough.
pub const NPCAP_DEVICE: &str = r"\\.\NPCAP";

const SE_FILE_OBJECT: u32 = 1;
const DACL_SECURITY_INFORMATION: u32 = 0x0000_0004;
const SDDL_REVISION_1: u32 = 1;
const ERROR_SUCCESS: u32 = 0;

#[link(name = "advapi32")]
extern "system" {
    fn GetNamedSecurityInfoW(
        object_name: *const u16,
        object_type: u32,
        security_info: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor: *const c_void,
        revision: u32,
        security_info: u32,
        string: *mut *mut u16,
        length: *mut u32,
    ) -> i32;
    #[cfg(test)]
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        length: *mut u32,
    ) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

/// The Npcap device's DACL as SDDL, or `None` if it could not be read.
///
/// Read per connection by the caller, like the Python agent: Npcap can be
/// reinstalled under a running service - it is what the Update Center does -
/// and a cached answer would outlive the reinstall that changed it.
pub fn read_driver_sddl() -> Option<String> {
    read_sddl(NPCAP_DEVICE)
}

/// Any object's DACL as SDDL, by Win32 path.
pub fn read_sddl(path: &str) -> Option<String> {
    let name = wide(path);
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    let mut dacl: *mut c_void = std::ptr::null_mut();
    let rc = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if rc != ERROR_SUCCESS || descriptor.is_null() {
        return None;
    }
    // `dacl` points INTO `descriptor`, so only the descriptor is freed.
    let text = unsafe { dacl_as_sddl(descriptor) };
    unsafe { LocalFree(descriptor) };
    text
}

/// The DACL half of a security descriptor, as the string `pywin32`'s
/// `ConvertSecurityDescriptorToStringSecurityDescriptor(sd, SDDL_REVISION_1,
/// DACL_SECURITY_INFORMATION)` returns - which is what `npcap_access.py` sends.
///
/// # Safety
/// `descriptor` must be a valid security descriptor.
unsafe fn dacl_as_sddl(descriptor: *const c_void) -> Option<String> {
    let mut string: *mut u16 = std::ptr::null_mut();
    let mut length: u32 = 0;
    let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
        descriptor,
        SDDL_REVISION_1,
        DACL_SECURITY_INFORMATION,
        &mut string,
        &mut length,
    );
    if ok == 0 || string.is_null() {
        return None;
    }
    // `length` counts the terminating NUL; reading to the NUL rather than
    // trusting it keeps a count that ever excluded it from dropping a bracket.
    let mut len = 0usize;
    while *string.add(len) != 0 {
        len += 1;
    }
    let text = String::from_utf16_lossy(std::slice::from_raw_parts(string, len));
    LocalFree(string as *mut c_void);
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `local-agent/npcap_access.py` read from `\\.\NPCAP` on the machine
    /// this was written on - an install with the restriction NOT ticked, which
    /// is Npcap's default: SYSTEM and Administrators with full access, and
    /// Everyone (`WD`) with read, write and execute. `npcapAccess.ts` answers
    /// `all-users` for exactly this string.
    const CAPTURED: &str = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x12019f;;;WD)";

    /// The formatting half, against the captured string: parsed by Windows into
    /// a descriptor and written back out by the same call this module makes.
    /// A wrong revision, a wrong information mask (an owner or a group leaking
    /// in as `O:`/`G:`) or a truncated length would all change the string.
    #[test]
    fn a_descriptor_is_written_back_as_the_python_agent_wrote_it() {
        let text = wide(CAPTURED);
        let mut descriptor: *mut c_void = std::ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        assert!(ok != 0 && !descriptor.is_null(), "Windows refused the captured SDDL");
        let round_trip = unsafe { dacl_as_sddl(descriptor) };
        unsafe { LocalFree(descriptor) };
        assert_eq!(round_trip.as_deref(), Some(CAPTURED));
    }

    /// An object that does not exist answers `None`, which is the state of a
    /// machine with no driver - the one the Update Center exists to fix. Never
    /// an error, and never an empty string the app would try to parse.
    #[test]
    fn no_device_is_none_rather_than_an_error() {
        assert_eq!(read_sddl(r"\\.\INWIRE_NO_SUCH_DEVICE_3F1D"), None);
    }

    /// The live read, on a machine that has the driver. Skips rather than
    /// fails where there is none, because that is a legal machine.
    #[test]
    fn the_installed_driver_answers_with_a_dacl() {
        match read_driver_sddl() {
            None => eprintln!("SKIP  no Npcap driver on this machine"),
            Some(sddl) => {
                assert!(sddl.starts_with("D:"), "not a DACL: {sddl}");
                assert!(!sddl.contains("O:") && !sddl.contains("G:"),
                    "only the DACL was asked for: {sddl}");
            }
        }
    }
}
