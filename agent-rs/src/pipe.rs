//! The named pipe the app connects to.
//!
//! The port of `local-agent/pipe_server.py`. Two facts from that file are not
//! preferences and are repeated here because getting either wrong produces a
//! working handshake and a broken capture.
//!
//! ## The descriptor IS the authentication
//!
//! ```text
//! D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
//! ```
//!
//! `D:P` is protected, so nothing is inherited. `SY` and `BA` get full access.
//! **`IU` - the interactive user - is the whole point**: the service runs as
//! LocalSystem and the app deliberately does not, and the default DACL on a
//! pipe a LocalSystem service creates admits SYSTEM and administrators only, so
//! without that ACE the app could never reach the service that exists to serve
//! it. ADR 0029.
//!
//! Deliberately absent: `WD` (everyone), `AN` (anonymous), `NU` (network). A
//! named pipe answers over SMB as `\\host\pipe\name` unless the descriptor says
//! otherwise, and `PIPE_REJECT_REMOTE_CLIENTS` says it a second time.
//!
//! Because the kernel decides, a pipe client is never asked for a token. There
//! is no pairing token on Windows and there must not be one.
//!
//! ## Overlapped, and this is not an optimisation
//!
//! A handle opened without `FILE_FLAG_OVERLAPPED` is **synchronous**, and
//! Windows serialises every operation on one: while the reader sits in
//! `ReadFile` waiting for the client's next command, a `WriteFile` from the
//! writer thread does not fail and does not block visibly - it waits its turn
//! behind a read that may not complete for minutes.
//!
//! Driven against the real client, `hello` and the first reply arrived and
//! everything after them did not. Which is the worst shape a bug can have: it
//! works on the handshake, which is what anyone tests, and stops on the
//! traffic, which is what the pipe is for.
//!
//! So every instance is `FILE_FLAG_OVERLAPPED` and **every operation carries
//! its own `OVERLAPPED` with its own event**. Its own, not a shared one: two
//! concurrent operations signalling one event is the same bug in a different
//! hat.

use std::ffi::{c_void, OsStr};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::Arc;

use crate::framing::{Frame, FrameReader, FramingError};
use crate::outbound::{Closed, Item, Outbound};

type Handle = *mut c_void;

#[repr(C)]
struct SecurityAttributes {
    n_length: u32,
    lp_security_descriptor: *mut c_void,
    b_inherit_handle: i32,
}

#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    h_event: Handle,
}

impl Default for Overlapped {
    fn default() -> Self {
        Self {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            h_event: ptr::null_mut(),
        }
    }
}

#[link(name = "kernel32")]
extern "system" {
    fn CreateNamedPipeW(
        name: *const u16,
        open_mode: u32,
        pipe_mode: u32,
        max_instances: u32,
        out_buffer_size: u32,
        in_buffer_size: u32,
        default_timeout: u32,
        security_attributes: *mut SecurityAttributes,
    ) -> Handle;
    fn ConnectNamedPipe(pipe: Handle, overlapped: *mut Overlapped) -> i32;
    fn DisconnectNamedPipe(pipe: Handle) -> i32;
    fn ReadFile(h: Handle, buf: *mut u8, len: u32, read: *mut u32, ov: *mut Overlapped) -> i32;
    fn WriteFile(h: Handle, buf: *const u8, len: u32, written: *mut u32, ov: *mut Overlapped) -> i32;
    fn GetOverlappedResult(h: Handle, ov: *mut Overlapped, count: *mut u32, wait: i32) -> i32;
    fn CreateEventW(attrs: *mut c_void, manual: i32, initial: i32, name: *const u16) -> Handle;
    fn CloseHandle(h: Handle) -> i32;
    fn CancelIoEx(h: Handle, ov: *mut Overlapped) -> i32;
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *mut c_void,
        disposition: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
    fn GetLastError() -> u32;
}

#[link(name = "advapi32")]
extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl: *const u16,
        revision: u32,
        descriptor: *mut *mut c_void,
        size: *mut u32,
    ) -> i32;
    fn ImpersonateNamedPipeClient(pipe: Handle) -> i32;
    fn RevertToSelf() -> i32;
    fn OpenThreadToken(thread: Handle, access: u32, open_as_self: i32, token: *mut Handle) -> i32;
    fn DuplicateTokenEx(
        existing: Handle,
        access: u32,
        attributes: *mut c_void,
        level: u32,
        token_type: u32,
        token: *mut Handle,
    ) -> i32;
    fn SetThreadToken(thread: *mut Handle, token: Handle) -> i32;
}

#[link(name = "kernel32")]
extern "system" {
    fn GetCurrentThread() -> Handle;
}

const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_IMPERSONATE: u32 = 0x0004;
const TOKEN_QUERY: u32 = 0x0008;
/// `SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation`: the service may act
/// as the client on this machine, and only on this machine.
const SECURITY_IMPERSONATION: u32 = 2;
/// `TOKEN_TYPE::TokenImpersonation`.
const TOKEN_IMPERSONATION: u32 = 2;

const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// Fails `CreateNamedPipe` when the name already exists (ADR 0068).
const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
const PIPE_TYPE_BYTE: u32 = 0x0000_0000;
const PIPE_READMODE_BYTE: u32 = 0x0000_0000;
const PIPE_WAIT: u32 = 0x0000_0000;
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
const SDDL_REVISION_1: u32 = 1;

const GENERIC_READ: u32 = 0x8000_0000;
const OPEN_EXISTING: u32 = 3;
const INVALID_HANDLE: isize = -1;

const ERROR_IO_PENDING: u32 = 997;
const ERROR_PIPE_CONNECTED: u32 = 535;

const INFINITE: i32 = 1;

/// Where the app looks. One instance per connected client.
pub const PIPE_NAME: &str = r"\\.\pipe\inwire-agent";

/// The descriptor. See the module note - this is the authentication.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

/// More than one, because the ownership model still means something: a second
/// Windows user logged into the same machine runs their own copy of the app
/// against the one machine-wide service, and `capture_busy` arbitrates.
pub const MAX_INSTANCES: u32 = 8;

/// How long an acceptor waits before asking for an instance again after the
/// system refused one (ADR 0068). A user who takes a slot costs the agent a
/// second of that slot, not its life.
pub const INSTANCE_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// Read buffer. A batch is capped at 256 kB and a control message is smaller.
pub const READ_CHUNK: usize = 64 * 1024;

pub const MAX_OUTBOUND_FRAMES: usize = 4096;
pub const MAX_OUTBOUND_BYTES: usize = 32 * 1024 * 1024;

fn wide(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(std::iter::once(0)).collect()
}

/// A security descriptor built from SDDL, freed on drop.
struct Descriptor(*mut c_void);

impl Descriptor {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let text = wide(sddl);
        let mut sd: *mut c_void = ptr::null_mut();
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Descriptor(sd))
    }
}

impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0) };
            self.0 = ptr::null_mut();
        }
    }
}

/// An event handle, closed on drop. One per operation, never shared.
struct Event(Handle);

impl Event {
    fn manual_reset() -> io::Result<Self> {
        let h = unsafe { CreateEventW(ptr::null_mut(), 1, 0, ptr::null()) };
        if h.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Event(h))
    }
}

impl Drop for Event {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

/// One pipe instance, closed on drop.
pub struct PipeInstance {
    handle: Handle,
}

// The handle is moved to a serving thread and used from there.
unsafe impl Send for PipeInstance {}

// **`Sync` here and deliberately NOT on `Capture`, and the difference is the
// whole reason this handle is overlapped.**
//
// A reader thread in `ReadFile` and a writer thread in `WriteFile`, on one
// overlapped handle, each carrying its own `OVERLAPPED` with its own event, is
// the documented and intended use - it is what `FILE_FLAG_OVERLAPPED` is for.
// The kernel keeps the two operations apart; what it cannot do is keep two
// operations that share one event apart, which is why the events are per
// operation rather than per handle.
//
// `npcap::Capture` is the opposite case and says so: `pcap_next_ex` on one
// handle from two threads is documented-undefined, so that type is `Send` and
// not `Sync`, and the compiler refuses the arrangement the Python agent
// performs once a second.
unsafe impl Sync for PipeInstance {}

impl Drop for PipeInstance {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                DisconnectNamedPipe(self.handle);
                CloseHandle(self.handle);
            }
            self.handle = ptr::null_mut();
        }
    }
}

/// Creates a pipe instance carrying the descriptor.
///
/// Threads rather than an IOCP runtime, and not by preference: a proactor
/// creates its own pipe instances with the creating process's **default** DACL,
/// which for a LocalSystem service is exactly the descriptor that locks the app
/// out. Passing our own means creating the instances ourselves, and once we are
/// doing that the threads are the simpler half.
///
/// **`first` is for the very first instance of the name** (ADR 0068). It adds
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`, which makes the call fail when any process
/// has already created the name - so the agent never serves a pipe that
/// someone else made, and whose descriptor they chose.
pub fn create_instance(
    name: &str,
    sddl: &str,
    max_instances: u32,
    first: bool,
) -> io::Result<PipeInstance> {
    let descriptor = Descriptor::from_sddl(sddl)?;
    let mut attrs = SecurityAttributes {
        n_length: std::mem::size_of::<SecurityAttributes>() as u32,
        lp_security_descriptor: descriptor.0,
        b_inherit_handle: 0,
    };
    let wide_name = wide(name);
    let handle = unsafe {
        CreateNamedPipeW(
            wide_name.as_ptr(),
            PIPE_ACCESS_DUPLEX
                | FILE_FLAG_OVERLAPPED
                | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 },
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            max_instances,
            READ_CHUNK as u32,
            READ_CHUNK as u32,
            0,
            &mut attrs,
        )
    };
    if handle as isize == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(PipeInstance { handle })
}

/// Waits for a client. Returns when one has connected.
pub fn accept(instance: &PipeInstance) -> io::Result<()> {
    let event = Event::manual_reset()?;
    let mut ov = Overlapped {
        h_event: event.0,
        ..Default::default()
    };
    let ok = unsafe { ConnectNamedPipe(instance.handle, &mut ov) };
    if ok != 0 {
        return Ok(());
    }
    match unsafe { GetLastError() } {
        // A client that connected between CreateNamedPipe and ConnectNamedPipe.
        // Not an error and not a race to retry: it is already connected.
        ERROR_PIPE_CONNECTED => Ok(()),
        ERROR_IO_PENDING => {
            let mut transferred = 0u32;
            let ok =
                unsafe { GetOverlappedResult(instance.handle, &mut ov, &mut transferred, INFINITE) };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        _ => Err(io::Error::last_os_error()),
    }
}

/// Reads until the client goes, handing whole frames to `on_frame`.
///
/// Its own `OVERLAPPED` and its own event, for the life of the loop. The writer
/// has its own; sharing one is the bug the module note describes.
pub fn read_loop<F>(instance: &PipeInstance, mut on_frame: F) -> io::Result<()>
where
    F: FnMut(Frame) -> io::Result<()>,
{
    let event = Event::manual_reset()?;
    let mut reader = FrameReader::new();
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let mut ov = Overlapped {
            h_event: event.0,
            ..Default::default()
        };
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                instance.handle,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut read,
                &mut ov,
            )
        };
        if ok == 0 {
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => {
                    let done = unsafe {
                        GetOverlappedResult(instance.handle, &mut ov, &mut read, INFINITE)
                    };
                    if done == 0 {
                        // The client went. Not an error worth raising: it is
                        // how every connection ends.
                        return Ok(());
                    }
                }
                _ => return Ok(()),
            }
        }
        if read == 0 {
            return Ok(());
        }
        match reader.push(&buf[..read as usize]) {
            Ok(frames) => {
                for f in frames {
                    on_frame(f)?;
                }
            }
            Err(e) => {
                // Unrecoverable by construction: the stream position is no
                // longer known, so there is nothing to resynchronise to.
                // `InvalidData` so the caller can log it as `pipe_server.py`
                // does - "pipe framing error, dropping the client" - rather
                // than as one more way a connection ends.
                return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()));
            }
        }
    }
}

/// Drains the queue onto the pipe until shutdown.
///
/// **Each write is waited to completion before the next begins.** Two
/// outstanding writes on one handle have no defined order, and a packet batch
/// delivered out of order is a capture that lies about the wire. Measured
/// against the real client, that costs nothing worth having: 4,000 batches of
/// 64 kB - 262 MB - in 539 ms, or 487 MB/s.
pub fn write_loop(instance: &PipeInstance, outbound: &Outbound) -> io::Result<()> {
    let event = Event::manual_reset()?;
    loop {
        let frame = match outbound.pop() {
            Item::Shutdown => return Ok(()),
            // The record count is the queue's business, for its shed counter.
            // Once a frame is being written it has not been lost, so the writer
            // has no use for it.
            Item::Frame(f, _) => f,
        };
        let mut ov = Overlapped {
            h_event: event.0,
            ..Default::default()
        };
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                instance.handle,
                frame.as_ptr(),
                frame.len() as u32,
                &mut written,
                &mut ov,
            )
        };
        if ok == 0 {
            match unsafe { GetLastError() } {
                ERROR_IO_PENDING => {
                    let done = unsafe {
                        GetOverlappedResult(instance.handle, &mut ov, &mut written, INFINITE)
                    };
                    if done == 0 {
                        outbound.shutdown();
                        return Ok(());
                    }
                }
                _ => {
                    outbound.shutdown();
                    return Ok(());
                }
            }
        }
    }
}

/// Stops a blocked read or write so a thread can leave.
pub fn cancel_io(instance: &PipeInstance) {
    unsafe { CancelIoEx(instance.handle, ptr::null_mut()) };
}

/// Ends a connected client's session from outside the thread serving it.
///
/// **What a service stop with a client connected needs, and `poke` cannot
/// give.** The serving thread sits in `GetOverlappedResult(INFINITE)` on a
/// `ReadFile` for a command the app may not send for hours, and `run` joins
/// that thread on the way out - so an SCM stop with Inwire open never finished.
/// `CancelIoEx` completes the pending read with `ERROR_OPERATION_ABORTED`;
/// `DisconnectNamedPipe` then closes the client's end, so a read issued after
/// the cancel - the race a cancel alone loses, a thread between two reads -
/// fails at once with `ERROR_PIPE_NOT_CONNECTED` instead of blocking. Either
/// way `read_loop` returns and the thread unwinds through its own cleanup.
///
/// Safe on a handle another thread is using: the caller holds an `Arc` to the
/// instance, so the handle cannot be closed underneath this, and both calls are
/// documented for use against I/O issued by other threads.
pub fn disconnect(instance: &PipeInstance) {
    unsafe {
        CancelIoEx(instance.handle, ptr::null_mut());
        DisconnectNamedPipe(instance.handle);
    }
}

/// Connects to the pipe and immediately drops it, to release one acceptor.
///
/// **What this is for.** An accept thread is blocked inside `ConnectNamedPipe`
/// waiting for a client that is never coming, because the agent is shutting
/// down. Nothing it can see changes: a flag it is not reading, a socket it does
/// not have. One real connection is what returns it to a loop where it can
/// check whether a stop was asked for.
///
/// `CancelIoEx` from another thread would also do it and is **not** used here:
/// the acceptor owns its instance handle and is about to hand it to `serve`, so
/// cancelling from outside would race a handle that is legitimately being used.
/// A connection is the in-band answer and needs no shared handle at all.
///
/// Failure is ignored by every caller, and must be: the common reason for it is
/// that the acceptor already went away, which is the outcome being asked for.
pub fn poke(name: &str) -> io::Result<()> {
    let wide = wide(name);
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    };
    if handle as isize == INVALID_HANDLE {
        return Err(io::Error::last_os_error());
    }
    unsafe { CloseHandle(handle) };
    Ok(())
}

/// The identity of the client at the other end of a pipe, to act as.
///
/// **The agent never writes a file with its own rights** (ADR 0052). It runs as
/// LocalSystem, which can write anywhere, and the capture files go where a
/// client says - so a client that could name a folder and have SYSTEM write
/// there would be a privilege escalation any local account could use. Every
/// file the agent creates or deletes for a capture is done *as the client that
/// started it*: `ImpersonateNamedPipeClient`, then a duplicate of that thread
/// token kept for the capture's writer thread, which puts it on around each
/// file operation (`act`). The kernel then checks the client's rights, and a
/// client can make the service write only where it could have written itself.
///
/// Impersonation level only - the token works on this machine and cannot be
/// carried to another. Closed on drop.
pub struct ClientToken(Handle);

// A token handle is an ordinary kernel handle: usable from any thread, and the
// writer thread is the one that uses it.
unsafe impl Send for ClientToken {}
unsafe impl Sync for ClientToken {}

impl Drop for ClientToken {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// Puts the calling thread back in the service's own identity when dropped,
/// however the work in between ended.
struct Revert;

impl Drop for Revert {
    fn drop(&mut self) {
        unsafe {
            RevertToSelf();
        }
    }
}

/// The identity of `instance`'s client, for acting as it later.
///
/// Must be called on a thread that has read from the pipe - the kernel refuses
/// impersonation before the client has sent anything - which the read loop
/// has, by the time a command asks for it. The calling thread is back in its
/// own identity when this returns, whatever happened.
pub fn client_token(instance: &PipeInstance) -> io::Result<ClientToken> {
    if unsafe { ImpersonateNamedPipeClient(instance.handle) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _revert = Revert;
    let mut thread_token: Handle = ptr::null_mut();
    // Opened "as self": the access check on the thread's own token object is
    // the service's, so a client with an unusual DACL on its token cannot make
    // this fail.
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_DUPLICATE | TOKEN_QUERY, 1, &mut thread_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut duplicate: Handle = ptr::null_mut();
    let ok = unsafe {
        DuplicateTokenEx(
            thread_token,
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            ptr::null_mut(),
            SECURITY_IMPERSONATION,
            TOKEN_IMPERSONATION,
            &mut duplicate,
        )
    };
    let error = io::Error::last_os_error();
    unsafe {
        CloseHandle(thread_token);
    }
    if ok == 0 {
        return Err(error);
    }
    Ok(ClientToken(duplicate))
}

impl ClientToken {
    /// Runs `work` as the client, and is back in the service's own identity
    /// afterwards - on the way out of a panic too.
    pub fn act<T>(&self, work: impl FnOnce() -> T) -> io::Result<T> {
        if unsafe { SetThreadToken(ptr::null_mut(), self.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let _revert = Revert;
        Ok(work())
    }
}

/// One connected client, as the rest of the agent sees it.
pub struct Connection {
    pub outbound: Arc<Outbound>,
}

impl Connection {
    pub fn new() -> Self {
        Self {
            outbound: Arc::new(Outbound::new(MAX_OUTBOUND_FRAMES, MAX_OUTBOUND_BYTES)),
        }
    }

    /// Queues one frame. `Err` once the writer has given up.
    ///
    /// `records` is how many captured packets `payload` carries, so the shed
    /// counter can be in packets rather than in queued items - see
    /// `Outbound::push`. A control message passes 0.
    pub fn send(&self, kind: u8, payload: &[u8], records: u64) -> Result<(), SendError> {
        let framed = crate::framing::encode_frame(kind, payload).map_err(SendError::Framing)?;
        self.outbound.push(framed, records).map_err(SendError::Gone)
    }

    /// **The kernel checked the descriptor before this handle existed.**
    ///
    /// So a pipe client is never asked for a pairing token - the question is
    /// skipped rather than answered. There is no token on Windows and there
    /// must not be one.
    pub fn kernel_authenticated(&self) -> bool {
        true
    }
}

impl Default for Connection {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum SendError {
    Framing(FramingError),
    Gone(Closed),
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SendError::Framing(e) => write!(f, "{e}"),
            SendError::Gone(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SendError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A pipe name nothing else uses - never the production one.
    fn unique_pipe_name(tag: &str) -> String {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        format!(
            r"\\.\pipe\inwire-pipe-test-{}-{tag}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )
    }

    /// ADR 0068: the first instance of the name is created with
    /// `FILE_FLAG_FIRST_PIPE_INSTANCE`, which fails when anyone else made the
    /// name first. Later instances of our own name must still be created.
    #[test]
    fn a_second_first_instance_is_refused() {
        let name = unique_pipe_name("first");
        let _a = create_instance(&name, PIPE_SDDL, 2, true).unwrap();
        assert!(create_instance(&name, PIPE_SDDL, 2, true).is_err());
        assert!(create_instance(&name, PIPE_SDDL, 2, false).is_ok());
    }
}
