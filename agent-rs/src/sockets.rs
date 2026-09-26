//! Which process owns which local socket.
//!
//! The port of `local-agent/sockets.py`, whose opening paragraph is the reason
//! this exists at all: *"A frame says 10.0.0.4:54321 talked to
//! 142.250.185.14:443; the operating system knows that 54321 belongs to
//! chrome.exe, and nothing on the wire does."* ADR 0009 - enrich only from the
//! captured machine, never from a third party.
//!
//! ## Three decisions carried over rather than re-taken
//!
//! **Keyed by the LOCAL endpoint, not by a five-tuple.** That is forced rather
//! than chosen: `GetExtendedUdpTable` has no remote column at all, so every UDP
//! socket would report an empty remote address. The local endpoint is what the
//! OS actually owns and the only key that works for both transports.
//!
//! **Deltas, not snapshots.** The full table is ~890 sockets and ~52 KB of
//! JSON, and it changes by one or two a second - so a delta is roughly two
//! hundred times cheaper. `full` marks the snapshot that opens a subscription,
//! and says to discard whatever was held rather than merge into it.
//!
//! **A pid of 0 is kept, not dropped.** A socket the OS will not attribute is
//! not the same fact as no socket, and collapsing the two would let a frame
//! fall through to a stale entry for a reused port.
//!
//! ## What is not cached, and why
//!
//! `describe_process` in the Python agent says it plainly: caching a name by
//! pid alone is wrong, because pids are reused and the cache would eventually
//! name a socket after the process that used to hold that number - *"the single
//! most misleading thing this module could do"*. The snapshot below is taken
//! fresh on every poll for the same reason.

#![cfg(windows)]

use std::collections::HashMap;
use std::ffi::c_void;

use serde_json::{json, Value};

use crate::adapters::format_ipv6;

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        af: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
    fn GetExtendedUdpTable(
        table: *mut c_void,
        size: *mut u32,
        order: i32,
        af: u32,
        class: u32,
        reserved: u32,
    ) -> u32;
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, process: u32) -> *mut c_void;
    fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry32W) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
    fn QueryFullProcessImageNameW(
        process: *mut c_void,
        flags: u32,
        buffer: *mut u16,
        size: *mut u32,
    ) -> i32;
}

const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
/// `TCP_TABLE_OWNER_PID_ALL`. Every state, not just the listeners: a capture is
/// mostly established connections.
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;
const TH32CS_SNAPPROCESS: u32 = 0x0000_0002;
/// `PROCESS_QUERY_LIMITED_INFORMATION`, which is what
/// `QueryFullProcessImageNameW` documents and is granted for processes that
/// refuse `PROCESS_QUERY_INFORMATION`.
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const INVALID_HANDLE_VALUE: isize = -1;

#[repr(C)]
#[derive(Clone, Copy)]
struct MibTcpRowOwnerPid {
    state: u32,
    local_addr: u32,
    /// **Network byte order in the low 16 bits**, which is what the whole
    /// DWORD-for-a-port shape is about - the high half is not the port.
    local_port: u32,
    remote_addr: u32,
    remote_port: u32,
    owning_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MibTcp6RowOwnerPid {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    remote_addr: [u8; 16],
    remote_scope_id: u32,
    remote_port: u32,
    state: u32,
    owning_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MibUdpRowOwnerPid {
    local_addr: u32,
    local_port: u32,
    owning_pid: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MibUdp6RowOwnerPid {
    local_addr: [u8; 16],
    local_scope_id: u32,
    local_port: u32,
    owning_pid: u32,
}

/// `PROCESSENTRY32W`.
///
/// **568 bytes on x64, and the size is asserted** for the same reason
/// `if_table.rs` asserts its own: `th32DefaultHeapID` is a `ULONG_PTR`, so it
/// aligns to 8 and pads the three `DWORD`s above it out to 16 - get that wrong
/// and `szExeFile` reads from the wrong offset, which is mojibake rather than a
/// crash.
#[repr(C)]
struct ProcessEntry32W {
    size: u32,
    usage: u32,
    process_id: u32,
    default_heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_process_id: u32,
    pri_class_base: i32,
    flags: u32,
    exe_file: [u16; 260],
}

const _: () = assert!(std::mem::size_of::<ProcessEntry32W>() == 568);

/// One socket's key: the transport, the local address, the local port.
pub type SocketKey = (&'static str, String, u16);

/// Everything the OS says about the local sockets right now.
///
/// A socket with no local address is skipped: every key here has to be one a
/// captured frame could match, and no frame carries an empty address.
fn read_socket_table() -> HashMap<SocketKey, u32> {
    let mut table = HashMap::new();
    read_tcp(AF_INET, &mut table);
    read_tcp(AF_INET6, &mut table);
    read_udp(AF_INET, &mut table);
    read_udp(AF_INET6, &mut table);
    table
}

/// The port out of one of these DWORDs.
///
/// The value is in network byte order in the **low two bytes**; the high two
/// are not part of it. Reading the whole DWORD gives a number in the millions,
/// which would key every socket under a port no frame can carry.
fn port_of(raw: u32) -> u16 {
    u16::from_be_bytes([(raw & 0xff) as u8, ((raw >> 8) & 0xff) as u8])
}

/// Records one socket unless its endpoint is already in the table.
///
/// **First writer wins**, which is `sockets.py`'s `table.setdefault(key, pid)`.
/// Several rows share one local endpoint - every connection accepted on a
/// server port, and the `TIME_WAIT` rows those leave behind, which the kernel
/// attributes to pid 0. `insert` let the last row read decide, so a port a
/// process still owned could be keyed to "no process" by a connection that had
/// already closed. The test below counts how often that choice matters here.
///
/// "First" is table order: TCP before UDP, IPv4 before IPv6, and each table as
/// the kernel lists it. psutil returns its rows through a `set`, so the Python
/// agent's first is hash order - the same rule, applied to an order nobody can
/// predict.
fn keep_first(table: &mut HashMap<SocketKey, u32>, key: SocketKey, pid: u32) {
    table.entry(key).or_insert(pid);
}

fn format_ipv4(raw: u32) -> String {
    let b = raw.to_ne_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Calls one of the two table functions until the buffer is big enough.
///
/// The size is asked for and then asked for again, because sockets open
/// between the two calls: a fixed number of retries rather than a loop that
/// could spin on a machine opening sockets faster than this can allocate.
fn fetch(
    call: unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, u32, u32) -> u32,
    af: u32,
    class: u32,
) -> Option<Vec<u8>> {
    let mut size: u32 = 0;
    for _ in 0..4 {
        let rc = unsafe { call(std::ptr::null_mut(), &mut size, 0, af, class, 0) };
        if rc != ERROR_INSUFFICIENT_BUFFER && rc != ERROR_SUCCESS {
            return None;
        }
        if size == 0 {
            return None;
        }
        let mut buffer = vec![0u8; size as usize];
        let rc = unsafe { call(buffer.as_mut_ptr() as *mut c_void, &mut size, 0, af, class, 0) };
        if rc == ERROR_SUCCESS {
            return Some(buffer);
        }
        if rc != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
    }
    None
}

/// The rows of a `MIB_*TABLE_OWNER_PID`, which is a `DWORD` count and then an
/// array. The array starts at the row type's own alignment, not at offset 4.
///
/// # Safety
/// `buffer` must be what the matching `GetExtended*Table` wrote.
unsafe fn rows<T: Copy>(buffer: &[u8]) -> Vec<T> {
    if buffer.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_ne_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    let start = std::mem::align_of::<T>().max(4);
    let size = std::mem::size_of::<T>();
    if buffer.len() < start + count * size {
        return Vec::new();
    }
    let first = buffer.as_ptr().add(start) as *const T;
    (0..count).map(|i| *first.add(i)).collect()
}

fn read_tcp(af: u32, table: &mut HashMap<SocketKey, u32>) {
    let Some(buffer) = fetch(GetExtendedTcpTable, af, TCP_TABLE_OWNER_PID_ALL) else {
        return;
    };
    if af == AF_INET {
        for row in unsafe { rows::<MibTcpRowOwnerPid>(&buffer) } {
            keep_first(table, ("tcp", format_ipv4(row.local_addr), port_of(row.local_port)), row.owning_pid);
        }
    } else {
        for row in unsafe { rows::<MibTcp6RowOwnerPid>(&buffer) } {
            // No zone index is appended, which is `normalize_address`'s job in
            // the Python agent read the other way round: a captured frame
            // carries the address alone, so an address with `%eth0` on it would
            // never compare equal to one.
            keep_first(
                table,
                ("tcp", format_ipv6(&row.local_addr), port_of(row.local_port)),
                row.owning_pid,
            );
        }
    }
}

fn read_udp(af: u32, table: &mut HashMap<SocketKey, u32>) {
    let Some(buffer) = fetch(GetExtendedUdpTable, af, UDP_TABLE_OWNER_PID) else {
        return;
    };
    if af == AF_INET {
        for row in unsafe { rows::<MibUdpRowOwnerPid>(&buffer) } {
            keep_first(table, ("udp", format_ipv4(row.local_addr), port_of(row.local_port)), row.owning_pid);
        }
    } else {
        for row in unsafe { rows::<MibUdp6RowOwnerPid>(&buffer) } {
            keep_first(
                table,
                ("udp", format_ipv6(&row.local_addr), port_of(row.local_port)),
                row.owning_pid,
            );
        }
    }
}

/// Every running process's image name, by pid.
///
/// A toolhelp snapshot rather than `OpenProcess` per pid, and that is what
/// matches the Python agent's behaviour rather than merely being cheaper:
/// `psutil`'s `name()` succeeds for processes whose `exe()` is refused, and
/// this snapshot is the same kind of source - the kernel's own process list,
/// which needs no handle to the process.
fn process_names() -> HashMap<u32, String> {
    let mut out = HashMap::new();
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot.is_null() || snapshot as isize == INVALID_HANDLE_VALUE {
        return out;
    }
    // SAFETY: `entry.size` is set before the first call, which is what the API
    // requires and what it uses to decide the structure version.
    unsafe {
        let mut entry: ProcessEntry32W = std::mem::zeroed();
        entry.size = std::mem::size_of::<ProcessEntry32W>() as u32;
        let mut more = Process32FirstW(snapshot, &mut entry);
        while more != 0 {
            let end = entry.exe_file.iter().position(|c| *c == 0).unwrap_or(entry.exe_file.len());
            out.insert(entry.process_id, String::from_utf16_lossy(&entry.exe_file[..end]));
            more = Process32NextW(snapshot, &mut entry);
        }
        CloseHandle(snapshot);
    }
    out
}

/// A process's full image path, or an empty string.
///
/// **Empty is not an error.** The Python agent says so in as many words: *"a
/// service can deny its own path while freely giving its name. The name alone
/// is still worth having."*
fn process_path(pid: u32) -> String {
    if pid == 0 {
        return String::new();
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return String::new();
    }
    let mut buffer = [0u16; 512];
    let mut size = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut size) };
    unsafe { CloseHandle(handle) };
    if ok == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&buffer[..size as usize])
}

/// Turns successive readings into add/gone deltas.
///
/// Holds the previous reading, so the first poll after `reset` reports the
/// whole table as additions and every poll after it reports only what moved.
pub struct SocketTracker {
    previous: Option<HashMap<SocketKey, u32>>,
}

impl SocketTracker {
    pub fn new() -> Self {
        Self { previous: None }
    }

    /// Forgets the previous reading, so the next poll is a full snapshot.
    ///
    /// Called when a client subscribes: it has no table of its own yet, and a
    /// delta against a table it never received would leave it permanently short
    /// of every socket that existed before it arrived.
    pub fn reset(&mut self) {
        self.previous = None;
    }

    /// The next `socket_table` message, or `None` when nothing changed.
    ///
    /// An unchanged second is the common case on an idle machine, and an empty
    /// delta every second is a message that says nothing.
    pub fn poll(&mut self) -> Option<Value> {
        let current = read_socket_table();
        let full = self.previous.is_none();
        let previous = self.previous.take().unwrap_or_default();

        let added: Vec<(&SocketKey, u32)> = current
            .iter()
            .filter(|(key, pid)| previous.get(*key) != Some(pid))
            .map(|(key, pid)| (key, *pid))
            .collect();
        let gone: Vec<&SocketKey> =
            previous.keys().filter(|key| !current.contains_key(*key)).collect();

        if !full && added.is_empty() && gone.is_empty() {
            self.previous = Some(current);
            return None;
        }

        // Only the pids this message's additions refer to, and re-sent even
        // when an earlier message already named them - which costs a few dozen
        // bytes on a delta that averages two sockets and lets the app treat
        // each message on its own.
        let mut wanted: Vec<u32> = added.iter().map(|(_, pid)| *pid).filter(|p| *p != 0).collect();
        wanted.sort_unstable();
        wanted.dedup();
        let names = if wanted.is_empty() { HashMap::new() } else { process_names() };
        let mut procs = serde_json::Map::new();
        for pid in wanted {
            // Absent rather than invented. A pid with no name is a protected
            // process, or one that exited between the table read and this call.
            let Some(name) = names.get(&pid) else { continue };
            procs.insert(pid.to_string(), json!({ "name": name, "exe": process_path(pid) }));
        }

        let message = socket_table(
            full,
            &added.iter().map(|(key, pid)| ((*key).clone(), *pid)).collect::<Vec<_>>(),
            &gone.into_iter().cloned().collect::<Vec<_>>(),
            procs,
        );
        self.previous = Some(current);
        Some(message)
    }
}

/// The message itself, built from data rather than read from the machine.
///
/// Separated from `poll` so the shape can be produced without a socket table -
/// which is what `examples/control_vectors.rs` needs, and the app's parser is
/// the only thing that can prove the shape is right. `procs` keyed by the pid
/// **as a string** is the part most worth pinning: JSON object keys are
/// strings, the app reads them back with `Number(...)`, and a numeric key would
/// serialise the same way here and be a different type in a hand-written
/// fixture.
pub fn socket_table(
    full: bool,
    added: &[(SocketKey, u32)],
    gone: &[SocketKey],
    procs: serde_json::Map<String, Value>,
) -> Value {
    json!({
        "type": "socket_table",
        "full": full,
        "procs": Value::Object(procs),
        "add": added
            .iter()
            .map(|((proto, address, port), pid)| json!([proto, address, port, pid]))
            .collect::<Vec<_>>(),
        "gone": gone
            .iter()
            .map(|(proto, address, port)| json!([proto, address, port]))
            .collect::<Vec<_>>(),
    })
}

impl Default for SocketTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A port lives in the low two bytes of its DWORD, in network order.
    /// Reading the whole thing gives a number in the millions and keys every
    /// socket under a port no frame can carry.
    #[test]
    fn a_port_comes_out_of_the_low_half_in_network_order() {
        // 443 on the wire is 0x01bb, which lands as 0x01, 0xbb - so the DWORD
        // reads 0xbb01 little-endian, with whatever the kernel left above it.
        assert_eq!(port_of(0x0000_bb01), 443);
        assert_eq!(port_of(0xdead_bb01), 443);
        assert_eq!(port_of(0x0000_5000), 80);
    }

    /// `sockets.py`'s `setdefault`: the first row for an endpoint decides.
    /// `127.0.0.1:28338` is an endpoint this machine held three TCP rows for -
    /// two established connections and the listener, all one process - when
    /// this was written; the second pid is what a `TIME_WAIT` row carries.
    #[test]
    fn a_shared_endpoint_keeps_the_first_rows_pid() {
        let mut table = HashMap::new();
        let key: SocketKey = ("tcp", "127.0.0.1".into(), 28338);
        keep_first(&mut table, key.clone(), 34664);
        keep_first(&mut table, key.clone(), 0);
        keep_first(&mut table, key.clone(), 34664);
        assert_eq!(table.get(&key), Some(&34664));
        assert_eq!(table.len(), 1);
    }

    /// The runtime half of the layout assertion above: the call works on this
    /// machine and the table it returns is not empty.
    #[test]
    fn this_machine_has_sockets_and_they_are_keyed_by_a_real_address() {
        let table = read_socket_table();
        assert!(!table.is_empty(), "GetExtendedTcpTable returned nothing");
        for ((proto, address, _port), _pid) in &table {
            assert!(*proto == "tcp" || *proto == "udp", "unknown transport {proto}");
            assert!(!address.is_empty(), "a socket with no local address was kept");
            // No zone index: a captured frame carries the address alone.
            assert!(!address.contains('%'), "a zone index reached the table: {address}");
        }
    }

    /// The snapshot names this process, which is the one pid the test knows
    /// the answer for. A wrong `szExeFile` offset shows up here as mojibake or
    /// an empty string rather than as a crash.
    #[test]
    fn the_process_snapshot_names_this_process() {
        let names = process_names();
        let me = std::process::id();
        let name = names.get(&me).expect("the snapshot did not include this process");
        assert!(name.to_lowercase().ends_with(".exe"), "not an image name: {name}");
    }

    /// The first poll is a full snapshot with every socket in `add`; a poll
    /// straight after it is a delta, and on a quiet machine usually nothing.
    #[test]
    fn the_first_poll_is_full_and_the_next_is_a_delta() {
        let mut tracker = SocketTracker::new();
        let first = tracker.poll().expect("the first poll always reports");
        assert_eq!(first["full"], true);
        assert!(!first["add"].as_array().unwrap().is_empty());
        assert!(first["gone"].as_array().unwrap().is_empty(), "nothing can have gone yet");

        match tracker.poll() {
            None => {}
            Some(second) => {
                assert_eq!(second["full"], false);
                let added = second["add"].as_array().unwrap().len();
                let went = second["gone"].as_array().unwrap().len();
                assert!(added + went > 0, "a delta that says nothing should be None");
            }
        }
    }
}
