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
/// Administrators, protected DACL), then any link planted under a log name is
/// removed. A folder that is already a junction is refused rather than
/// followed, and a folder that cannot be secured is not written to at all. A
/// hand run is not the service and cannot set the owner, so it passes false.
pub fn init(directory: &Path, to_stderr: bool, harden: bool) {
    let mut unsecured: Option<io::Error> = None;
    if harden {
        match fs::create_dir_all(directory).and_then(|()| harden_directory(directory, LOG_DIR_SDDL)) {
            Ok(()) => clear_planted_links(directory),
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
                OpenOptions::new().create(true).append(true).open(&path)?;
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

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const INVALID_FILE_ATTRIBUTES: u32 = 0xFFFF_FFFF;
const SDDL_REVISION_1: u32 = 1;
const SE_FILE_OBJECT: u32 = 1;
const OWNER_SECURITY_INFORMATION: u32 = 0x1;
const DACL_SECURITY_INFORMATION: u32 = 0x4;
const PROTECTED_DACL_SECURITY_INFORMATION: u32 = 0x8000_0000;

#[link(name = "kernel32")]
extern "system" {
    fn GetFileAttributesW(name: *const u16) -> u32;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
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
    fn SetNamedSecurityInfoW(
        name: *const u16,
        object_type: u32,
        information: u32,
        owner: *mut c_void,
        group: *mut c_void,
        dacl: *mut c_void,
        sacl: *mut c_void,
    ) -> u32;
}

fn wide(text: &std::ffi::OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

/// Gives `dir` the owner and DACL of `sddl`, protected, and propagates them to
/// what is already inside.
///
/// **A reparse point is refused**, not followed: `SetNamedSecurityInfoW` would
/// re-ACL whatever a junction points at, as SYSTEM. The owner is applied only
/// when `sddl` names one.
pub fn harden_directory(dir: &Path, sddl: &str) -> io::Result<()> {
    let name = wide(dir.as_os_str());
    let attributes = unsafe { GetFileAttributesW(name.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES {
        return Err(io::Error::last_os_error());
    }
    if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{dir:?} is a reparse point and is not followed"),
        ));
    }

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
        let mut information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        if !owner.is_null() {
            information |= OWNER_SECURITY_INFORMATION;
        }
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
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

/// Removes a symlink, junction or directory sitting where a log file belongs.
///
/// Rotation renames and deletes these names as SYSTEM; a junction under one is
/// how that is aimed elsewhere. Only the entry goes, never what it points at:
/// `remove_dir` on a junction removes the junction. Errors are ignored - an
/// entry that cannot be removed also cannot be rotated into.
fn clear_planted_links(dir: &Path) {
    let live = dir.join("agent.log");
    let mut names = vec![live.clone()];
    names.extend((1..=BACKUP_COUNT).map(|n| live.with_extension(format!("log.{n}"))));
    for name in names {
        let Ok(meta) = fs::symlink_metadata(&name) else { continue };
        if meta.file_type().is_symlink() || meta.is_dir() {
            let _ = fs::remove_dir(&name).or_else(|_| fs::remove_file(&name));
        }
    }
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
    if fs::metadata(path).map(|m| m.len()).unwrap_or(0) >= MAX_BYTES {
        rotate(path);
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
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
    let Ok(mut file) = File::open(&path) else { return Vec::new() };
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

    #[test]
    fn planted_links_are_cleared() {
        let dir = temp("planted");
        let target = temp("planted-target");
        fs::write(target.join("keep"), b"x").unwrap();
        mklink_junction(&dir.join("agent.log.3"), &target);
        clear_planted_links(&dir);
        let gone = !dir.join("agent.log.3").exists();
        let kept = target.join("keep").exists();
        let _ = fs::remove_file(target.join("keep"));
        let _ = fs::remove_dir(&target);
        let _ = fs::remove_dir(&dir);
        assert!(gone);
        assert!(kept, "the link went, not what it pointed at");
    }
}
