//! The agent's own log, and the half of it a client can subscribe to.
//!
//! The port of `local-agent/logging_setup.py` and `local-agent/agent_log.py`.
//! The first of those states the stakes and they are unchanged here: *"Once the
//! agent runs as a service there is no console, so a file is the only
//! diagnostic channel that exists for either the user or a maintainer. This is
//! not optional polish - it is the entire observability story."*
//!
//! **The Rust agent shipped without any of it**, and `service.rs` says what
//! that cost in as many words: *"Nothing is attached to stderr under the SCM."*
//! So every `eprintln!` in this crate went nowhere on the machines it was
//! written for, and the one that matters most - a frame the wire format could
//! not describe - vanished with no trace at all. The Python agent's
//! `log.warning` reaches a rotating file the app can subscribe to, which is the
//! gap this closes.
//!
//! ## The format is Python's, exactly
//!
//! `"%(asctime)s %(levelname)-7s %(message)s"`, so a line reads
//!
//! ```text
//! 2026-09-20 22:14:02,123 INFO    client connected (1 total)
//! ```
//!
//! That is not nostalgia. `local-agent/agent_log.py`'s `parse_log_line` splits
//! a backlog line back into `{time, level, message}` for the app, the level
//! field is left-justified to **seven** characters followed by one literal
//! space, and the parser strips exactly that computed width rather than a
//! greedy `\s+` - because the agent logs deliberately indented lines and a
//! greedy match would eat their indentation. A Rust agent writing a different
//! shape would produce a backlog the app renders as one unparsed blob.
//!
//! ## Subscribers are polled, not called
//!
//! A live sink invoked from inside `log!` would be re-entrant: sending to a
//! client can fail, and a failure worth logging would call `log!` again from
//! inside the lock it is holding. So new entries land in a bounded ring here
//! and the runtime's own thread drains it - which also means a burst of
//! logging costs one message rather than one per line.

#![cfg(windows)]

use std::collections::VecDeque;
use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde_json::{json, Value};

/// An agent running for months must not be able to fill a disk.
const MAX_BYTES: u64 = 1_000_000;
const BACKUP_COUNT: u32 = 3;

/// The `-7` in Python's `"%(levelname)-7s"`. The app's parser strips exactly
/// this width, so it is a wire constant rather than a formatting preference.
const LEVEL_FIELD_WIDTH: usize = 7;

/// How many recent lines a new subscriber is given, and the cap on the bytes
/// read back to find them. Both are `agent_log.py`'s.
const BACKLOG_LINES: usize = 200;
const BACKLOG_BYTES: u64 = 65536;

/// How many entries wait here for the runtime's thread to pick them up.
///
/// Bounded, and the oldest are dropped rather than the newest: a subscriber
/// that has fallen behind wants to know what just happened. The file is the
/// record, and nothing here is the only copy of a line.
const RING: usize = 512;

#[link(name = "kernel32")]
extern "system" {
    fn GetLocalTime(time: *mut SystemTime);
}

#[repr(C)]
#[derive(Default)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

struct Sink {
    path: Option<PathBuf>,
    to_stderr: bool,
    /// New lines waiting for the runtime to forward them, with the sequence
    /// number of the oldest still held.
    pending: VecDeque<String>,
    first_pending: u64,
    next: u64,
}

static SINK: Mutex<Option<Sink>> = Mutex::new(None);

/// Opens the log in `directory` and decides whether lines also go to stderr.
///
/// **An agent that cannot write its log must still run.** An unwritable
/// directory degrades to stderr-or-nothing rather than refusing to capture,
/// which is `logging_setup.py`'s rule and the reason `path` is an `Option`.
///
/// `to_stderr` is false under the SCM, where stderr reaches nobody, and true
/// for `inwire-agent debug`.
///
/// `harden` is true under the SCM only. The service rotates this folder as
/// SYSTEM with `remove_file` and `rename`, so a user who owned it, or could
/// plant entries in it, could aim SYSTEM's delete or rename anywhere. With
/// `harden` the folder is created, then given `LOG_DIR_SDDL` (owner
/// Administrators, protected DACL), then anything planted under a log name is
/// removed: a link, or a file another account owns. A folder that is already a
/// junction is refused rather than followed, and a folder that cannot be
/// secured is not written to at all - nor is one where a log name is still held
/// by a link, a directory, a file with other names or another account's file
/// after clearing. Every open of a log file declines to follow a reparse point.
/// A hand run is not the service and cannot set the owner, so it passes false.
pub fn init(directory: &Path, to_stderr: bool, harden: bool) {
    let mut unsecured: Option<io::Error> = None;
    if harden {
        match fs::create_dir_all(directory).and_then(|()| harden_directory(directory, LOG_DIR_SDDL)) {
            Ok(()) => {
                // Unreadable, only SYSTEM and Administrators are trusted.
                let own = process_user_sid().unwrap_or_default();
                clear_planted_links(directory, &own);
                // An entry that could not be removed is run past, not trusted:
                // no file log, exactly as for a folder that is a junction.
                if !log_names_are_safe(directory, &own) {
                    unsecured = Some(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "a log file name is held by a link, a directory, a file with other names \
                         or another account's file",
                    ));
                }
            }
            Err(error) => unsecured = Some(error),
        }
    }
    // **Probed here, not on the first line**, which is what `logging_setup.py`
    // does by constructing its handler inside the same `try`. The realistic
    // failure is not an unwritable directory: `%ProgramData%\Inwire` grants
    // `Users` write, so a directory is created happily, while `agent.log`
    // itself belongs to SYSTEM and Administrators - so an agent run by hand,
    // unelevated, beside an installed service can create nothing and append to
    // nothing. Finding that out once and saying so beats discovering it per
    // line and saying nothing.
    let path = if unsecured.is_some() {
        None
    } else {
        fs::create_dir_all(directory)
            .and_then(|()| {
                let path = directory.join("agent.log");
                open_append(&path)?;
                Ok(path)
            })
            .map_err(|error| {
                if to_stderr {
                    eprintln!("[agent] WARNING: cannot write a log in {directory:?}: {error}");
                    eprintln!("[agent] lines go to stderr and to subscribers, and nothing is kept");
                }
            })
            .ok()
    };
    *SINK.lock().unwrap() = Some(Sink {
        path,
        to_stderr,
        pending: VecDeque::new(),
        first_pending: 0,
        next: 0,
    });
    if let Some(error) = unsecured {
        write(
            "WARNING",
            &format!(
                "agent log folder {directory:?} could not be secured ({error}) - logging to subscribers only"
            ),
        );
    }
}

/// The service's descriptor for its log folder: owned by Administrators,
/// protected (nothing inherited from ProgramData), SYSTEM and Administrators
/// full control, and `Users` read-and-execute only. Inheritable, so the log
/// files take it too.
pub const LOG_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)";

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const SDDL_REVISION_1: u32 = 1;
const SE_FILE_OBJECT: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const FILE_SHARE_READ: u32 = 0x1;
const FILE_SHARE_WRITE: u32 = 0x2;
const FILE_SHARE_DELETE: u32 = 0x4;
const OPEN_EXISTING: u32 = 3;
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

#[repr(C)]
struct FileTime {
    low: u32,
    high: u32,
}

/// `BY_HANDLE_FILE_INFORMATION`.
#[repr(C)]
struct ByHandleFileInformation {
    file_attributes: u32,
    creation_time: FileTime,
    last_access_time: FileTime,
    last_write_time: FileTime,
    volume_serial_number: u32,
    file_size_high: u32,
    file_size_low: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        flags: u32,
        template: *mut c_void,
    ) -> *mut c_void;
    fn GetFileInformationByHandle(file: *mut c_void, information: *mut ByHandleFileInformation) -> i32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn GetCurrentProcess() -> *mut c_void;
}

#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorOwner(descriptor: *mut c_void, owner: *mut *mut c_void, defaulted: *mut i32) -> i32;
    fn GetSecurityDescriptorDacl(
        descriptor: *mut c_void,
        present: *mut i32,
        dacl: *mut *mut c_void,
        defaulted: *mut i32,
    ) -> i32;
    fn SetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
    fn GetSecurityInfo(
        handle: *mut c_void,
        object_type: u32,
        information: u32,
        owner: *mut *mut c_void,
        group: *mut *mut c_void,
        dacl: *mut *mut c_void,
        sacl: *mut *mut c_void,
        descriptor: *mut *mut c_void,
    ) -> u32;
    fn ConvertSidToStringSidW(sid: *mut c_void, text: *mut *mut u16) -> i32;
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        information: *mut c_void,
        length: u32,
        returned: *mut u32,
    ) -> i32;
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// Gives `dir` the owner and DACL of `sddl`, protected, and propagates them to
/// what is already inside.
///
/// **A reparse point is refused**, not followed: re-ACLing a junction's target
/// would be done as SYSTEM. The owner is applied only when `sddl` names one.
///
/// **The folder is opened once and the check and the change both use that
/// handle.** A user who owns a pre-existing folder can replace it between a
/// check made on its path and a change made on its path (an oplock says when),
/// so neither names the path twice. The handle is opened with every share flag
/// and explicit rights: `SetSecurityInfo` propagates inheritable entries to what
/// is already inside, but not through a handle opened exclusively or with
/// `MAXIMUM_ALLOWED`.
pub fn harden_directory(dir: &Path, sddl: &str) -> io::Result<()> {
    harden_directory_with(dir, sddl, || {})
}

/// `harden_directory`, with a hook that runs between the check and the change -
/// the only gap a swap could use. Tests put the swap there.
fn harden_directory_with(dir: &Path, sddl: &str, between_check_and_apply: impl FnOnce()) -> io::Result<()> {
    let sddl_wide = wide(std::ffi::OsStr::new(sddl));
    let mut descriptor: *mut c_void = std::ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_wide.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        let mut owner: *mut c_void = std::ptr::null_mut();
        let mut dacl: *mut c_void = std::ptr::null_mut();
        let (mut defaulted, mut present) = (0i32, 0i32);
        if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // A NULL DACL, set, grants everyone full control: no DACL is refused
        // rather than applied.
        if present == 0 || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{sddl:?} has no DACL, and applying none would grant everyone full control"),
            ));
        }
        let mut information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        let mut access = READ_CONTROL | WRITE_DAC;
        if !owner.is_null() {
            information |= OWNER_SECURITY_INFORMATION;
            access |= WRITE_OWNER;
        }

        let name = wide(dir.as_os_str());
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                std::ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // Closed when this goes out of scope, on every path below.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let raw = handle.as_raw_handle();

        let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(raw, &mut info) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{dir:?} is a reparse point and is not followed"),
            ));
        }
        if info.file_attributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("{dir:?} is not a directory"),
            ));
        }

        between_check_and_apply();

        let status = unsafe {
            SetSecurityInfo(
                raw,
                SE_FILE_OBJECT,
                information,
                owner,
                std::ptr::null_mut(),
                dacl,
                std::ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    })();
    unsafe { LocalFree(descriptor) };
    result
}

/// `agent.log` and its rotated names, which are the only entries the agent
/// opens, renames or deletes in its folder.
fn log_names(dir: &Path) -> Vec<PathBuf> {
    let live = dir.join("agent.log");
    let mut names = vec![live.clone()];
    names.extend((1..=BACKUP_COUNT).map(|n| live.with_extension(format!("log.{n}"))));
    names
}

/// How many names the file at `path` has, read without following a reparse
/// point. A log file has one; a hard link planted by a user has two or more.
fn link_count(path: &Path) -> io::Result<u32> {
    // Only `FILE_READ_ATTRIBUTES`, so this succeeds on a file the account may
    // not read, and every share flag so it cannot make a user's own open fail.
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    let file = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut info: ByHandleFileInformation = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info.number_of_links)
}

/// A SID as `S-1-...` text.
fn sid_text(sid: *mut c_void) -> io::Result<String> {
    let mut text: *mut u16 = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0;
    while unsafe { *text.add(length) } != 0 {
        length += 1;
    }
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { LocalFree(text.cast()) };
    Ok(sid)
}

/// The account this process runs as: SYSTEM under the SCM.
fn process_user_sid() -> io::Result<String> {
    const TOKEN_QUERY: u32 = 0x8;
    const TOKEN_USER: u32 = 1;
    let mut raw = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut needed = 0u32;
    unsafe { GetTokenInformation(token.as_raw_handle(), TOKEN_USER, std::ptr::null_mut(), 0, &mut needed) };
    // `u64`s so the buffer is aligned for the `SID_AND_ATTRIBUTES` at its head.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8).max(2)];
    let size = (buffer.len() * 8) as u32;
    if unsafe { GetTokenInformation(token.as_raw_handle(), TOKEN_USER, buffer.as_mut_ptr().cast(), size, &mut needed) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // `TOKEN_USER` is one `SID_AND_ATTRIBUTES`, whose first field is the SID.
    sid_text(unsafe { *buffer.as_ptr().cast::<*mut c_void>() })
}

/// The owner of the file at `path`, read without following a reparse point.
fn owner_sid(path: &Path) -> io::Result<String> {
    const FILE_READ_ATTRIBUTES: u32 = 0x80;
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let mut owner = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let sid = sid_text(owner);
    unsafe { LocalFree(descriptor) };
    sid
}

/// Whether a log file owned by `owner` is the agent's: SYSTEM's,
/// Administrators' (what a file SYSTEM creates is owned by), or the account
/// this process runs as.
fn trusted_owner(owner: &str, own: &str) -> bool {
    owner == "S-1-5-18" || owner == "S-1-5-32-544" || owner == own
}

/// `trusted_owner` for the file at `path`. An owner that cannot be read is not
/// trusted.
fn owned_by_the_agent(path: &Path, own: &str) -> bool {
    owner_sid(path).map_or(false, |owner| trusted_owner(&owner, own))
}

/// Whether `meta` describes something other than a plain file: a symlink, a
/// junction or any other reparse point, or a directory.
fn is_link_or_directory(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink() || meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Removes what a user planted under a log name: a symlink, junction or
/// directory, a regular file with more than one name, or a file another
/// account owns.
///
/// Rotation renames and deletes these names as SYSTEM, and every append opens
/// one; a link under one is how that is aimed elsewhere. Only the entry goes,
/// never what it points at: `remove_dir` on a junction removes the junction, and
/// removing one name of a hard link leaves the file and its other names alone.
///
/// **A file a user created before the folder was first hardened** takes the
/// hardened DACL, but the user stays its owner, and an owner can always
/// rewrite a DACL: grant themselves write and forge the agent's lines. So a
/// log name `own` (the agent's account) or SYSTEM or Administrators does not
/// own goes too. The folder's `FILE_DELETE_CHILD` lets SYSTEM delete it
/// whatever its own DACL says.
///
/// Errors are ignored here because `log_names_are_safe` is what decides what to
/// do about an entry that stayed.
fn clear_planted_links(dir: &Path, own: &str) {
    for name in log_names(dir) {
        let Ok(meta) = fs::symlink_metadata(&name) else { continue };
        if is_link_or_directory(&meta) {
            let _ = fs::remove_dir(&name).or_else(|_| fs::remove_file(&name));
        } else if link_count(&name).map_or(false, |links| links > 1) || !owned_by_the_agent(&name, own) {
            let _ = fs::remove_file(&name);
        }
    }
}

/// True when every log name is absent or a plain regular file with one name,
/// owned by the agent's account, SYSTEM or Administrators.
///
/// Checked after `clear_planted_links`: an entry that is still a reparse point,
/// a directory, a multi-link file or another account's file is one a user
/// could remove-proof (a symlink held open without `FILE_SHARE_DELETE`, a
/// directory with something inside), and the agent then writes no file log at
/// all rather than rotate into it. A name whose state cannot be read counts as
/// unsafe.
fn log_names_are_safe(dir: &Path, own: &str) -> bool {
    log_names(dir).iter().all(|name| match fs::symlink_metadata(name) {
        Err(error) => error.kind() == io::ErrorKind::NotFound,
        Ok(meta) => {
            !is_link_or_directory(&meta)
                && meta.is_file()
                && link_count(name).map_or(false, |links| links == 1)
                && owned_by_the_agent(name, own)
        }
    })
}

/// Opens a log file for appending without following a reparse point, so a
/// symlink that clearing could not remove, or that appeared afterwards, is
/// opened itself and never what it points at.
fn open_append(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// `%ProgramData%\Inwire`, which is where the Python agent keeps its own.
///
/// Populated before anybody logs in, which a LocalSystem service starting at
/// boot needs. Under the SCM `init` gives it `LOG_DIR_SDDL`; the installer
/// only creates it.
pub fn directory() -> PathBuf {
    let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
    PathBuf::from(base).join("Inwire")
}

/// `2026-09-20 22:14:02,123` - Python's `asctime`, comma and all.
fn stamp() -> String {
    let mut now = SystemTime::default();
    unsafe { GetLocalTime(&mut now) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02},{:03}",
        now.year, now.month, now.day, now.hour, now.minute, now.second, now.milliseconds
    )
}

/// Writes one line, at `level`.
///
/// Prefer the `log_info!` / `log_warn!` macros, which is what the rest of the
/// crate calls: the point of going through them is that a caller never has to
/// remember the level field's width.
pub fn write(level: &str, message: &str) {
    // `{:width$}` is left-justified for strings, which is what `-7s` means -
    // and a level longer than the field (CRITICAL) overflows rather than being
    // truncated, again matching Python, whose parser handles both.
    let line = format!("{} {:LEVEL_FIELD_WIDTH$} {}", stamp(), level, message);

    let mut held = SINK.lock().unwrap();
    let Some(sink) = held.as_mut() else {
        // Before `init`, which is `--version` and the argument parser. stderr
        // is the only destination there is, and it is a real console.
        eprintln!("{line}");
        return;
    };
    if sink.to_stderr {
        eprintln!("{line}");
    }
    if let Some(path) = sink.path.clone() {
        // A write that fails is dropped in silence and deliberately: the
        // alternative is logging about being unable to log.
        let _ = append(&path, &line);
    }
    sink.next += 1;
    sink.pending.push_back(line);
    while sink.pending.len() > RING {
        sink.pending.pop_front();
        sink.first_pending += 1;
    }
}

/// Appends a line, rotating first when the file has reached its cap.
fn append(path: &Path, line: &str) -> std::io::Result<()> {
    if fs::symlink_metadata(path).map(|m| m.len()).unwrap_or(0) >= MAX_BYTES {
        rotate(path);
    }
    let mut file = open_append(path)?;
    writeln!(file, "{line}")
}

/// `agent.log.3` goes, `.2` becomes `.3`, and so on down to the live file.
///
/// Highest first, which is the whole of it: renaming upwards from `.1` would
/// overwrite `.2` with `.1` and leave the older ones unreachable.
fn rotate(path: &Path) {
    let numbered = |n: u32| path.with_extension(format!("log.{n}"));
    let _ = fs::remove_file(numbered(BACKUP_COUNT));
    for n in (1..BACKUP_COUNT).rev() {
        let _ = fs::rename(numbered(n), numbered(n + 1));
    }
    let _ = fs::rename(path, numbered(1));
}

/// One raw line of the log, as the protocol's `AgentLogEntry`.
///
/// **A line that does not parse keeps its text**, with null time and level -
/// a traceback continuation, most often, or anything a previous version of the
/// agent wrote. Dropping it would hide exactly the lines somebody subscribed
/// to read.
pub fn parse_line(raw: &str) -> Value {
    let unparsed = || json!({ "time": Value::Null, "level": Value::Null, "message": raw });
    // "YYYY-MM-DD HH:MM:SS,mmm " is 24 characters including the space.
    if raw.len() < 24 {
        return unparsed();
    }
    // `get` rather than `split_at`, which **panics** on an index that is not a
    // character boundary - and a line beginning with a multi-byte character is
    // exactly what a rotated file full of adapter names in another script
    // contains. A panic here would take down the thread reading the backlog.
    let (Some(time), Some(rest)) = (raw.get(..23), raw.get(23..)) else {
        return unparsed();
    };
    let mut chars = time.chars();
    let shaped = time.len() == 23
        && chars.clone().nth(4) == Some('-')
        && chars.clone().nth(7) == Some('-')
        && chars.clone().nth(10) == Some(' ')
        && chars.clone().nth(13) == Some(':')
        && chars.clone().nth(16) == Some(':')
        && chars.nth(19) == Some(',');
    if !shaped || !rest.starts_with(' ') {
        return unparsed();
    }
    let after_time = &rest[1..];
    let level: String = after_time.chars().take_while(|c| c.is_ascii_uppercase()).collect();
    if level.is_empty() {
        return unparsed();
    }
    // **The computed width, never a greedy run of spaces.** The level is
    // padded to seven and followed by one literal space; a `\s+` would also
    // swallow a message's own indentation, and the agent indents on purpose.
    let skip = level.len().max(LEVEL_FIELD_WIDTH) + 1;
    let message = after_time.get(skip..).unwrap_or("");
    json!({ "time": time, "level": level, "message": message })
}

/// The recent end of the log file, oldest first.
///
/// Read from the end, because rotation lets the file reach 1 MB and a
/// subscriber wants the last couple of hundred lines rather than all of it.
/// An unreadable or absent file answers with nothing, which is what a fresh
/// install looks like and is not an error.
pub fn backlog() -> Vec<Value> {
    let path = {
        let held = SINK.lock().unwrap();
        match held.as_ref().and_then(|s| s.path.clone()) {
            Some(path) => path,
            None => return Vec::new(),
        }
    };
    // Not `File::open`, which would follow a link on the log's name.
    let Ok(mut file) = OpenOptions::new().read(true).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&path) else {
        return Vec::new();
    };
    let Ok(size) = file.metadata().map(|m| m.len()) else { return Vec::new() };
    let from = size.saturating_sub(BACKLOG_BYTES);
    if file.seek(SeekFrom::Start(from)).is_err() {
        return Vec::new();
    }
    let mut buffer = String::new();
    // Lossy rather than strict: a file truncated mid-character by the seek
    // above is the ordinary case, not a corrupt log.
    let mut bytes = Vec::new();
    if file.read_to_end(&mut bytes).is_err() {
        return Vec::new();
    }
    buffer.push_str(&String::from_utf8_lossy(&bytes));

    let mut lines: Vec<&str> = buffer.lines().collect();
    // The first line is a fragment whenever the seek landed mid-line, which is
    // every time the file is larger than the window.
    if from > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    let start = lines.len().saturating_sub(BACKLOG_LINES);
    lines[start..].iter().map(|line| parse_line(line)).collect()
}

/// Entries written since `seen`, and the sequence to ask with next time.
///
/// The runtime polls this rather than being called back, for the re-entrancy
/// reason in this module's header. A caller that has fallen further behind
/// than the ring is long gets what the ring still holds - the file is the
/// record, and the app is reading a live tail rather than an audit trail.
pub fn since(seen: u64) -> (Vec<Value>, u64) {
    let held = SINK.lock().unwrap();
    let Some(sink) = held.as_ref() else { return (Vec::new(), 0) };
    if seen >= sink.next {
        return (Vec::new(), sink.next);
    }
    let skip = seen.saturating_sub(sink.first_pending) as usize;
    let lines = sink
        .pending
        .iter()
        .skip(skip.min(sink.pending.len()))
        .map(|line| parse_line(line))
        .collect();
    (lines, sink.next)
}

/// The sequence a subscriber starts from: everything already written is in the
/// backlog, so only what comes after it should arrive as a live line.
pub fn watermark() -> u64 {
    SINK.lock().unwrap().as_ref().map(|s| s.next).unwrap_or(0)
}

/// `{ type: 'log', lines: [...] }`, which carries both the backlog sent on
/// subscribe and each live line after it - one handler in the app rather than
/// two message types differing only in how many entries they hold.
pub fn log_message(lines: Vec<Value>) -> Value {
    json!({ "type": "log", "lines": lines })
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::agent_log::write("INFO", &format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::agent_log::write("WARNING", &format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::agent_log::write("ERROR", &format!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the app's parser expects, both ways round.
    #[test]
    fn a_line_parses_back_into_its_three_parts() {
        let entry = parse_line("2026-09-20 22:14:02,123 INFO    client connected (1 total)");
        assert_eq!(entry["time"], "2026-09-20 22:14:02,123");
        assert_eq!(entry["level"], "INFO");
        assert_eq!(entry["message"], "client connected (1 total)");
    }

    /// **The indentation survives**, which is what the computed width buys and
    /// a greedy `\s+` would have eaten. The agent indents its per-interface
    /// startup lines on purpose.
    #[test]
    fn a_messages_own_indentation_is_not_stripped() {
        let entry = parse_line("2026-09-20 22:14:02,123 INFO      Ethernet 2");
        assert_eq!(entry["message"], "  Ethernet 2");
    }

    /// A level that overflows the seven-character field is followed by one
    /// space, not padded out to seven.
    #[test]
    fn an_overflowing_level_still_leaves_exactly_one_space() {
        let entry = parse_line("2026-09-20 22:14:02,123 CRITICAL the driver is gone");
        assert_eq!(entry["level"], "CRITICAL");
        assert_eq!(entry["message"], "the driver is gone");
    }

    /// A line whose first 23 bytes are not 23 characters must not panic the
    /// thread reading the backlog. Windows adapter names arrive in the local
    /// script - this machine's read "חיבור מקומי* 8" - and every message that
    /// names one reaches the log.
    #[test]
    fn a_multibyte_line_is_refused_rather_than_split_mid_character() {
        let entry = parse_line("  חיבור מקומי* 8 could not be opened");
        assert!(entry["time"].is_null());
        assert!(entry["message"].as_str().unwrap().contains("could not be opened"));
    }

    /// A line this cannot read keeps its text rather than being dropped - a
    /// traceback continuation is the common case, and it is exactly what
    /// somebody subscribed to see.
    #[test]
    fn an_unparsable_line_keeps_its_message() {
        let entry = parse_line("  File \"agent.py\", line 12, in main");
        assert!(entry["time"].is_null());
        assert!(entry["level"].is_null());
        assert_eq!(entry["message"], "  File \"agent.py\", line 12, in main");
    }

    /// What `write` produces is what `parse_line` reads, which is the only
    /// thing holding the formatter and the parser to one format.
    #[test]
    fn the_formatter_and_the_parser_agree() {
        let line = format!("{} {:LEVEL_FIELD_WIDTH$} {}", stamp(), "WARNING", "a message");
        let entry = parse_line(&line);
        assert_eq!(entry["level"], "WARNING");
        assert_eq!(entry["message"], "a message");
        let short = format!("{} {:LEVEL_FIELD_WIDTH$} {}", stamp(), "INFO", "a message");
        assert_eq!(parse_line(&short)["message"], "a message");
    }

    // --- the log folder's ACL, and links planted in it ---

    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[link(name = "advapi32")]
    extern "system" {
        fn GetNamedSecurityInfoW(
            name: *const u16,
            object_type: u32,
            information: u32,
            owner: *mut *mut std::ffi::c_void,
            group: *mut *mut std::ffi::c_void,
            dacl: *mut *mut std::ffi::c_void,
            sacl: *mut *mut std::ffi::c_void,
            descriptor: *mut *mut std::ffi::c_void,
        ) -> u32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor: *const std::ffi::c_void,
            revision: u32,
            information: u32,
            string: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(memory: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    /// A path under the temp folder that nothing has created yet.
    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "inwire-agent-log-{label}-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn temp(label: &str) -> PathBuf {
        let path = temp_path(label);
        fs::create_dir_all(&path).unwrap();
        path
    }

    /// `cmd /c mklink /J`, which needs no privilege.
    fn mklink_junction(link: &Path, target: &Path) {
        let output = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(output.status.success(), "mklink /J failed: {output:?}");
    }

    /// The directory's DACL as SDDL text, read back from the filesystem.
    fn read_dacl_sddl(dir: &Path) -> String {
        let name: Vec<u16> = dir.as_os_str().encode_wide().chain(Some(0)).collect();
        let mut descriptor = std::ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                name.as_ptr(),
                1, // SE_FILE_OBJECT
                4, // DACL_SECURITY_INFORMATION
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0, "GetNamedSecurityInfoW");
        let mut text: *mut u16 = std::ptr::null_mut();
        let mut length = 0u32;
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, 1, 4, &mut text, &mut length)
        };
        assert_ne!(ok, 0, "ConvertSecurityDescriptorToStringSecurityDescriptorW");
        let sddl = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length as usize) });
        unsafe {
            LocalFree(text.cast());
            LocalFree(descriptor);
        }
        sddl.trim_end_matches('\0').to_string()
    }

    #[test]
    fn the_service_descriptor_is_admin_only() {
        assert_eq!(LOG_DIR_SDDL, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)");
    }

    #[test]
    fn hardening_protects_the_dacl() {
        // No `O:` - an unelevated test cannot set the owner to Administrators.
        let dir = temp("harden");
        harden_directory(&dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)").unwrap();
        let sddl = read_dacl_sddl(&dir);
        let _ = fs::remove_dir(&dir);
        assert!(sddl.starts_with("D:P"), "{sddl}");
        assert!(!sddl.contains(";ID;"), "nothing inherited survives: {sddl}");
    }

    #[test]
    fn a_reparse_point_is_refused() {
        let target = temp("target");
        let link = temp_path("junction");
        mklink_junction(&link, &target);
        let before = read_dacl_sddl(&target);
        let refused = harden_directory(&link, "D:P(A;OICI;FA;;;SY)");
        let after = read_dacl_sddl(&target);
        let _ = fs::remove_dir(&link);
        let _ = fs::remove_dir(&target);
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(after, before, "the junction's target was not re-ACLed");
    }

    /// **The check and the change are one object.** A user who owns the
    /// pre-existing folder can swap it for a junction between a path-based
    /// reparse check and the `SetNamedSecurityInfoW` that follows it, and SYSTEM
    /// would then re-ACL the junction's target. The swap is made in the hook,
    /// where it would be made by hand: the folder is renamed away and a junction
    /// takes its name.
    #[test]
    fn a_folder_swapped_for_a_junction_after_the_check_is_not_followed() {
        let dir = temp("race");
        let moved = temp_path("race-moved");
        let target = temp("race-target");
        let before = read_dacl_sddl(&target);
        let result = harden_directory_with(&dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", || {
            fs::rename(&dir, &moved).unwrap();
            mklink_junction(&dir, &target);
        });
        let after = read_dacl_sddl(&target);
        let swapped_in = read_dacl_sddl(&dir);
        let checked = read_dacl_sddl(&moved);
        let _ = fs::remove_dir(&dir);
        let _ = fs::remove_dir(&moved);
        let _ = fs::remove_dir(&target);
        result.unwrap();
        assert_eq!(after, before, "the junction's target was re-ACLed");
        // Measured: on this Windows `SetNamedSecurityInfoW` does not follow a
        // junction at the final component, it re-ACLs the junction itself - so
        // the target above survives even the path-based code. What fails there
        // is the object: the change must land on the folder that passed the
        // check, not on whatever the name has come to mean.
        assert!(checked.starts_with("D:P"), "the checked folder was hardened: {checked}");
        assert!(!swapped_in.starts_with("D:P"), "the swapped-in junction was changed: {swapped_in}");
    }

    /// Opening a handle instead of naming a path must not lose the propagation
    /// to what is already inside, which is how an old log file gets the new
    /// descriptor.
    #[test]
    fn an_existing_child_inherits_the_hardened_descriptor() {
        let dir = temp("children");
        let child = dir.join("agent.log");
        fs::write(&child, b"x").unwrap();
        let before = read_dacl_sddl(&child);
        harden_directory(&dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)").unwrap();
        let after = read_dacl_sddl(&child);
        let _ = fs::remove_file(&child);
        let _ = fs::remove_dir(&dir);
        assert_ne!(after, before);
        assert!(after.contains("(A;ID;FA;;;SY)"), "{after}");
        assert_eq!(after.matches("(A;").count(), 2, "only the hardened entries: {after}");
    }

    /// **A descriptor with no DACL is refused, not applied.** `SetSecurityInfo`
    /// given a NULL DACL sets one, which grants everyone full control - the
    /// opposite of hardening. `LOG_DIR_SDDL` always has one; this holds the
    /// function to that for any descriptor it is given.
    #[test]
    fn a_descriptor_without_a_dacl_is_refused() {
        for sddl in ["D:NO_ACCESS_CONTROL", "G:SY"] {
            let dir = temp("null-dacl");
            let before = read_dacl_sddl(&dir);
            let refused = harden_directory(&dir, sddl);
            let after = read_dacl_sddl(&dir);
            let _ = fs::remove_dir(&dir);
            assert_eq!(refused.map_err(|e| e.kind()), Err(io::ErrorKind::InvalidInput), "{sddl}");
            assert_eq!(after, before, "{sddl} changed the folder");
        }
    }

    #[test]
    fn a_file_is_refused_as_a_log_folder() {
        let dir = temp("not-a-folder");
        let file = dir.join("file");
        fs::write(&file, b"x").unwrap();
        let refused = harden_directory(&file, "D:P(A;OICI;FA;;;SY)");
        let _ = fs::remove_file(&file);
        let _ = fs::remove_dir(&dir);
        assert_eq!(refused.unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn planted_links_are_cleared() {
        let dir = temp("planted");
        let target = temp("planted-target");
        fs::write(target.join("keep"), b"x").unwrap();
        mklink_junction(&dir.join("agent.log.3"), &target);
        clear_planted_links(&dir, &me());
        let gone = !dir.join("agent.log.3").exists();
        let kept = target.join("keep").exists();
        let _ = fs::remove_file(target.join("keep"));
        let _ = fs::remove_dir(&target);
        let _ = fs::remove_dir(&dir);
        assert!(gone);
        assert!(kept, "the link went, not what it pointed at");
    }

    /// Before the folder was first hardened any user could create entries in
    /// it. A hard link under a log name makes rotation's `rename` and the next
    /// append act on a file the user chose, and unlike a symlink it has no
    /// reparse tag to find. Removing a hard link's name deletes only that name.
    #[test]
    fn a_planted_hard_link_is_removed_and_its_target_is_intact() {
        let dir = temp("hardlink");
        let outside = temp("hardlink-outside");
        let target = outside.join("victim");
        fs::write(&target, b"precious").unwrap();
        fs::hard_link(&target, dir.join("agent.log.2")).unwrap();
        let unsafe_before = !log_names_are_safe(&dir, &me());
        clear_planted_links(&dir, &me());
        let gone = !dir.join("agent.log.2").exists();
        let intact = fs::read(&target).ok();
        let safe_after = log_names_are_safe(&dir, &me());
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir(&outside);
        let _ = fs::remove_dir(&dir);
        assert!(unsafe_before, "a multi-link file is not a plain log file");
        assert!(gone);
        assert_eq!(intact.as_deref(), Some(&b"precious"[..]));
        assert!(safe_after);
    }

    /// A non-empty directory cannot be removed by `remove_dir`, and an entry
    /// that stays is one SYSTEM would still rotate into. The caller must see
    /// that and run with no file log, as it does for a junction folder.
    #[test]
    fn a_name_that_cannot_be_cleared_makes_the_folder_unsafe() {
        let dir = temp("stuck");
        let stuck = dir.join("agent.log.2");
        fs::create_dir_all(&stuck).unwrap();
        fs::write(stuck.join("inside"), b"x").unwrap();
        let before = log_names_are_safe(&dir, &me());
        clear_planted_links(&dir, &me());
        let after = log_names_are_safe(&dir, &me());
        let _ = fs::remove_file(stuck.join("inside"));
        let _ = fs::remove_dir(&stuck);
        let _ = fs::remove_dir(&dir);
        assert!(!before);
        assert!(!after, "the directory is still there");
    }

    #[test]
    fn plain_log_files_and_absent_names_are_safe() {
        let dir = temp("plain");
        assert!(log_names_are_safe(&dir, &me()), "an empty folder");
        fs::write(dir.join("agent.log"), b"x").unwrap();
        fs::write(dir.join("agent.log.1"), b"x").unwrap();
        let safe = log_names_are_safe(&dir, &me());
        let _ = fs::remove_file(dir.join("agent.log"));
        let _ = fs::remove_file(dir.join("agent.log.1"));
        let _ = fs::remove_dir(&dir);
        assert!(safe);
    }

    /// The account the tests run as, which owns every file they create.
    fn me() -> String {
        process_user_sid().expect("the test's own SID")
    }

    #[test]
    fn the_agents_own_files_are_trusted_and_anyone_elses_are_not() {
        let own = "S-1-5-21-1-2-3-1001";
        assert!(trusted_owner("S-1-5-18", own), "SYSTEM");
        assert!(trusted_owner("S-1-5-32-544", own), "Administrators, which own what SYSTEM creates");
        assert!(trusted_owner(own, own), "the agent's own account");
        assert!(!trusted_owner("S-1-5-21-1-2-3-1002", own), "another user");
        assert!(!trusted_owner(own, "S-1-5-18"), "a user's file, to an agent running as SYSTEM");
        assert!(me().starts_with("S-1-5-"), "{}", me());
    }

    /// **A log file another account owns is planted, and goes.** Before the
    /// folder was first hardened any user could create `agent.log`; hardening
    /// gives it the folder's DACL but leaves the user its owner, and an owner
    /// can rewrite the DACL and forge lines. Played here by running as if the
    /// agent were SYSTEM: the files this test makes are then another account's.
    #[test]
    fn a_log_file_another_account_owns_is_removed() {
        let dir = temp("owned");
        fs::write(dir.join("agent.log"), b"forged").unwrap();
        fs::write(dir.join("agent.log.1"), b"forged").unwrap();
        let read_back = owner_sid(&dir.join("agent.log")).ok();
        let unsafe_before = !log_names_are_safe(&dir, "S-1-5-18");
        clear_planted_links(&dir, "S-1-5-18");
        let gone = !dir.join("agent.log").exists() && !dir.join("agent.log.1").exists();
        let safe_after = log_names_are_safe(&dir, "S-1-5-18");
        let _ = fs::remove_file(dir.join("agent.log"));
        let _ = fs::remove_file(dir.join("agent.log.1"));
        let _ = fs::remove_dir(&dir);
        assert_eq!(read_back, Some(me()), "the owner is read back as the account that made the file");
        assert!(unsafe_before, "another account's file is not the agent's log");
        assert!(gone, "both planted names were removed");
        assert!(safe_after);
    }

    /// The case clearing cannot win: a user-owned file converted to a symlink
    /// after the folder was checked. Appending opens the link itself, never
    /// what it points at. Creating a symlink needs Developer Mode or the
    /// privilege, so this skips on an account that has neither.
    #[test]
    fn appending_never_follows_a_symlink_on_a_log_name() {
        let dir = temp("symlink");
        let outside = temp("symlink-outside");
        let target = outside.join("victim");
        fs::write(&target, b"precious").unwrap();
        let log = dir.join("agent.log");
        let cleanup = || {
            let _ = fs::remove_file(&log);
            let _ = fs::remove_file(&target);
            let _ = fs::remove_dir(&outside);
            let _ = fs::remove_dir(&dir);
        };
        if std::os::windows::fs::symlink_file(&target, &log).is_err() {
            eprintln!("skipped: this account cannot create a symlink");
            cleanup();
            return;
        }
        let unsafe_before = !log_names_are_safe(&dir, &me());
        let _ = append(&log, "2026-09-20 22:14:02,123 INFO    appended through a link");
        let intact = fs::read(&target).ok();
        cleanup();
        assert!(unsafe_before, "a symlink is not a plain log file");
        assert_eq!(intact.as_deref(), Some(&b"precious"[..]), "the link's target was written");
    }

    /// Hardening runs before `clear_planted_links`, and `SetNamedSecurityInfoW`
    /// propagates to children - so a junction planted under any other name is
    /// already inside when it does. Measured: the propagation does not follow
    /// it. This pins that, rather than a property of `harden_directory` itself.
    #[test]
    fn propagation_does_not_follow_a_junction_inside() {
        let dir = temp("inside-parent");
        let target = temp("inside-target");
        mklink_junction(&dir.join("elsewhere"), &target);
        let before = read_dacl_sddl(&target);
        harden_directory(&dir, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)").unwrap();
        let after = read_dacl_sddl(&target);
        let _ = fs::remove_dir(dir.join("elsewhere"));
        let _ = fs::remove_dir(&target);
        let _ = fs::remove_dir(&dir);
        assert_eq!(after, before, "propagation re-ACLed a child junction's target");
    }
}
