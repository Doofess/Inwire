//! Npcap, loaded at run time and wrapped in something safe to hold.
//!
//! The counterpart of the libpcap FFI scattered through `local-agent/agent.py` -
//! `pcap_handle`, `set_kernel_buffer`, `read_frame`, `read_pcap_stats` - which
//! that file's own grouping comments already mark as a module that wants
//! extracting. Here it is one.
//!
//! ## Why it is loaded by absolute path
//!
//! **`wpcap.dll` lives in `System32\Npcap\` and that directory is NOT on the
//! default DLL search path.** A plain `LoadLibrary("wpcap.dll")` finds either
//! nothing or, worse, a different `wpcap.dll` that something else dropped
//! somewhere earlier in the search order - which for a LocalSystem service is a
//! DLL-planting hole rather than a missing-file error. So the path is absolute
//! and built from the system directory the OS reports, and `LOAD_WITH_ALTERED_SEARCH_PATH`
//! makes the DLL's own dependencies resolve from beside it.
//!
//! ## Why there are no dependencies
//!
//! `windows` and `libloading` would each do this. CLAUDE.md's dependency rule
//! asks what a shipped dependency buys over the platform API it replaces, and
//! for three kernel32 entry points the answer is nothing - so they are declared
//! here and the crate's dependency list stays empty.
//!
//! ## The pieces that are easy to get wrong
//!
//! - **`pcap_pkthdr` is 16 bytes on Windows, not 24.** `struct timeval` there is
//!   two 32-bit `long`s, where on 64-bit Unix it is two 64-bit ones. Get this
//!   wrong and `caplen` is read out of the middle of the timestamp: the frames
//!   look plausible and every length is nonsense.
//! - **`pcap_setbuff` is Npcap's, not libpcap's.** The portable call is
//!   `pcap_set_buffer_size`, which must precede `pcap_activate`; this one works
//!   on an already-activated handle, which is what lets the buffer be raised
//!   after the handle is open.
//! - **A snaplen above 65535 is unrepresentable downstream.** The wire record's
//!   captured-length field is 16 bits, so the capture is opened at 65535 and a
//!   frame that cannot be encoded is made impossible here rather than refused
//!   later.

use std::ffi::{c_char, c_int, c_uchar, c_uint, c_void, CStr, CString};
use std::io;
use std::ptr;

// --- the three kernel32 entry points, declared rather than depended on -------

type Hmodule = *mut c_void;
type Farproc = *const c_void;

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(name: *const u16, file: *mut c_void, flags: u32) -> Hmodule;
    fn GetProcAddress(module: Hmodule, name: *const c_char) -> Farproc;
    fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
}

/// Resolve the DLL's own imports from its own directory, not from ours.
const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;

/// libpcap's error buffer size. Every call that takes one expects this much.
const PCAP_ERRBUF_SIZE: usize = 256;

/// The capture is opened at this and no higher: the wire record's captured
/// length is a `u16`. See the module note.
pub const SNAPLEN: c_int = 65535;

// --- the structs, laid out as the DLL sees them ------------------------------

/// Two 32-bit `long`s on Windows. This is the layout that matters.
#[repr(C)]
#[derive(Clone, Copy)]
struct Timeval {
    tv_sec: i32,
    tv_usec: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct PcapPktHdr {
    ts: Timeval,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct PcapIf {
    next: *mut PcapIf,
    name: *mut c_char,
    description: *mut c_char,
    addresses: *mut c_void,
    flags: c_uint,
}

/// Deliberately oversized. The portable struct is three `u_int`s and Npcap's
/// build has carried a fourth; the DLL writes what it writes, and reading only
/// the first three out of a roomy buffer is correct under either layout while a
/// tight one would be a stack overwrite under the larger.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct PcapStat {
    ps_recv: c_uint,
    ps_drop: c_uint,
    ps_ifdrop: c_uint,
    _spare: [c_uint; 5],
}

type PcapT = c_void;

type FnOpenLive = unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> *mut PcapT;
type FnClose = unsafe extern "C" fn(*mut PcapT);
type FnNextEx = unsafe extern "C" fn(*mut PcapT, *mut *mut PcapPktHdr, *mut *const c_uchar) -> c_int;
type FnStats = unsafe extern "C" fn(*mut PcapT, *mut PcapStat) -> c_int;
type FnGetErr = unsafe extern "C" fn(*mut PcapT) -> *mut c_char;
type FnFindAllDevs = unsafe extern "C" fn(*mut *mut PcapIf, *mut c_char) -> c_int;
type FnFreeAllDevs = unsafe extern "C" fn(*mut PcapIf);
type FnSetBuff = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
type FnSetMinToCopy = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
type FnDatalink = unsafe extern "C" fn(*mut PcapT) -> c_int;
#[cfg(test)]
type FnOpenOffline = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT;

/// The loaded library and its entry points.
pub struct Npcap {
    open_live: FnOpenLive,
    close: FnClose,
    next_ex: FnNextEx,
    stats: FnStats,
    geterr: FnGetErr,
    findalldevs: FnFindAllDevs,
    freealldevs: FnFreeAllDevs,
    /// `None` on a libpcap that is not Npcap. The buffer then stays at the
    /// driver's default, which is a degraded capture rather than a failed one -
    /// so this is an `Option` and not an error.
    setbuff: Option<FnSetBuff>,
    /// Npcap's too, and absent for the same reason - see `set_min_to_copy`.
    setmintocopy: Option<FnSetMinToCopy>,
    datalink: FnDatalink,
    /// `pcap_open_offline`, for the tests alone: it is how `runtime.rs`'s tests
    /// drive the real sniffer, pump and reaper with the real frames of
    /// `test/fixtures/*.pcap`, read through Npcap exactly as a live adapter's
    /// are - including `pcap_next_ex`'s -2 at the end of the file, which is an
    /// adapter "failing" the same way a removed one does.
    #[cfg(test)]
    open_offline: FnOpenOffline,
}

#[derive(Debug)]
pub struct Device {
    pub name: String,
    pub description: Option<String>,
}

fn last_os_error(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

impl Npcap {
    /// Loads `wpcap.dll` from the system's Npcap directory.
    pub fn load() -> io::Result<Self> {
        let mut dir = [0u16; 260];
        let n = unsafe { GetSystemDirectoryW(dir.as_mut_ptr(), dir.len() as u32) };
        if n == 0 || n as usize >= dir.len() {
            return Err(last_os_error("GetSystemDirectory"));
        }
        let mut path: Vec<u16> = dir[..n as usize].to_vec();
        path.extend(r"\Npcap\wpcap.dll".encode_utf16());
        path.push(0);

        let module = unsafe {
            LoadLibraryExW(path.as_ptr(), ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH)
        };
        if module.is_null() {
            // Taken first: nothing below may disturb the thread's last error.
            let error = io::Error::last_os_error();
            // Short, because it is quoted inside the runtime's own sentence -
            // "Npcap's packet driver is not available (...). Packet capture
            // will not work. Install Npcap from ..." - once per connection
            // until Npcap is installed.
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "could not load {}: {}",
                    String::from_utf16_lossy(&path[..path.len() - 1]),
                    error
                ),
            ));
        }

        // SAFETY: each cast matches the signature libpcap documents for that
        // symbol, and the names are literals rather than anything constructed.
        unsafe fn sym(module: Hmodule, name: &str) -> io::Result<Farproc> {
            let c = CString::new(name).expect("symbol names have no interior nul");
            let p = GetProcAddress(module, c.as_ptr());
            if p.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("wpcap.dll exports no {name}"),
                ));
            }
            Ok(p)
        }

        unsafe {
            Ok(Npcap {
                open_live: std::mem::transmute::<Farproc, FnOpenLive>(sym(module, "pcap_open_live")?),
                close: std::mem::transmute::<Farproc, FnClose>(sym(module, "pcap_close")?),
                next_ex: std::mem::transmute::<Farproc, FnNextEx>(sym(module, "pcap_next_ex")?),
                stats: std::mem::transmute::<Farproc, FnStats>(sym(module, "pcap_stats")?),
                geterr: std::mem::transmute::<Farproc, FnGetErr>(sym(module, "pcap_geterr")?),
                findalldevs: std::mem::transmute::<Farproc, FnFindAllDevs>(
                    sym(module, "pcap_findalldevs")?,
                ),
                freealldevs: std::mem::transmute::<Farproc, FnFreeAllDevs>(
                    sym(module, "pcap_freealldevs")?,
                ),
                setbuff: sym(module, "pcap_setbuff")
                    .ok()
                    .map(|p| std::mem::transmute::<Farproc, FnSetBuff>(p)),
                setmintocopy: sym(module, "pcap_setmintocopy")
                    .ok()
                    .map(|p| std::mem::transmute::<Farproc, FnSetMinToCopy>(p)),
                datalink: std::mem::transmute::<Farproc, FnDatalink>(sym(module, "pcap_datalink")?),
                #[cfg(test)]
                open_offline: std::mem::transmute::<Farproc, FnOpenOffline>(
                    sym(module, "pcap_open_offline")?,
                ),
            })
        }
    }

    /// Every capture device the driver reports.
    pub fn devices(&self) -> io::Result<Vec<Device>> {
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        let mut head: *mut PcapIf = ptr::null_mut();
        let rc = unsafe { (self.findalldevs)(&mut head, errbuf.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::other(unsafe { cstr(errbuf.as_ptr()) }));
        }
        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: the list is the one the DLL just built and is walked only
            // until it is freed below.
            let dev = unsafe { &*cur };
            out.push(Device {
                name: unsafe { cstr(dev.name) },
                description: if dev.description.is_null() {
                    None
                } else {
                    Some(unsafe { cstr(dev.description) })
                },
            });
            cur = dev.next;
        }
        unsafe { (self.freealldevs)(head) };
        Ok(out)
    }

    /// Opens one device for capture.
    ///
    /// `to_ms` is 100 deliberately: the read returns on its own timeout, which
    /// is how a stop is honoured promptly on an adapter with no traffic.
    /// Opens a capture file as if it were an adapter. Tests only - see the
    /// `open_offline` field.
    #[cfg(test)]
    pub fn open_file(&self, path: &std::path::Path) -> io::Result<Capture<'_>> {
        let name = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| io::Error::other("a path cannot contain a nul"))?;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        let handle = unsafe { (self.open_offline)(name.as_ptr(), errbuf.as_mut_ptr()) };
        if handle.is_null() {
            return Err(io::Error::other(unsafe { cstr(errbuf.as_ptr()) }));
        }
        Ok(Capture { npcap: self, handle })
    }

    pub fn open(&self, device: &str, promiscuous: bool) -> io::Result<Capture<'_>> {
        let name = CString::new(device)
            .map_err(|_| io::Error::other("a device name cannot contain a nul"))?;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        let handle = unsafe {
            (self.open_live)(
                name.as_ptr(),
                SNAPLEN,
                if promiscuous { 1 } else { 0 },
                100,
                errbuf.as_mut_ptr(),
            )
        };
        if handle.is_null() {
            return Err(io::Error::other(unsafe { cstr(errbuf.as_ptr()) }));
        }
        Ok(Capture { npcap: self, handle })
    }
}

/// # Safety
/// `p` must point at a NUL-terminated string the caller keeps alive.
unsafe fn cstr(p: *const c_char) -> String {
    if p.is_null() {
        return String::new();
    }
    CStr::from_ptr(p).to_string_lossy().into_owned()
}

/// What one `pcap_next_ex` returned.
pub enum Read<'a> {
    /// A frame, its capture time in microseconds, and its length on the wire.
    Frame {
        data: &'a [u8],
        ts_us: f64,
        wire_len: u32,
    },
    /// The `to_ms` timeout expired with no frame. **Not an error**: it is how a
    /// silent adapter lets the loop re-test its stop flag.
    Timeout,
}

/// An open capture handle.
///
/// Borrowed from the `Npcap` that produced it, so the library cannot be dropped
/// while a handle into it is alive - which is the use-after-free the Python
/// agent has an open window for at every stop, expressed as a lifetime instead
/// of as a rule somebody has to keep.
pub struct Capture<'a> {
    npcap: &'a Npcap,
    handle: *mut PcapT,
}

impl Capture<'_> {
    /// Raises the driver's kernel buffer.
    ///
    /// Npcap's default on Windows is 1 MB, which at a ~1,100-byte mean frame is
    /// about 950 frames - tens of milliseconds of slack on a busy adapter, and
    /// a real capture once lost 302,448 frames to it.
    ///
    /// Returns `Ok(false)` when the library has no `pcap_setbuff`, because a
    /// capture at the default buffer is degraded rather than broken and saying
    /// so is more useful than refusing to start.
    pub fn set_kernel_buffer(&self, bytes: c_int) -> io::Result<bool> {
        let Some(setbuff) = self.npcap.setbuff else {
            return Ok(false);
        };
        if unsafe { setbuff(self.handle, bytes) } != 0 {
            return Err(io::Error::other(self.error()));
        }
        Ok(true)
    }

    /// The `LINKTYPE_*` value of the frames this handle delivers.
    ///
    /// **Neither agent asked, and the app therefore assumed Ethernet.** That
    /// is right for every adapter on this machine but one: Npcap's loopback
    /// device is `DLT_NULL`, a 4-byte address family followed by the IP
    /// header, and read as Ethernet its bytes 12-13 land on the IP header's
    /// TTL and protocol - which is why a loopback capture showed a stream of
    /// ethertypes `0x8006` and `0x8011`. 0x80 is the Windows default TTL; 0x06
    /// and 0x11 are TCP and UDP.
    ///
    /// libpcap answers from the open handle and cannot be asked about a device
    /// it has not opened, which is why this is read at enumeration and cached -
    /// see `runtime::datalink_of`.
    pub fn datalink(&self) -> c_int {
        unsafe { (self.npcap.datalink)(self.handle) }
    }

    /// Asks the driver to hand frames over as soon as it has any.
    ///
    /// **Latency, not content.** Npcap's default `mintocopy` is 16 KB: the
    /// driver holds captured frames in its kernel buffer until that much has
    /// accumulated or `to_ms` expires, so on a quiet adapter a frame waits up
    /// to the 100 ms timeout before the agent sees it. Nothing is lost - it is
    /// the time between a packet arriving and a row appearing.
    ///
    /// Zero is what scapy asks for on this platform
    /// (`scapy/arch/libpcap.py`), so the Python agent has always had it and
    /// this port did not: the symbol was never resolved.
    ///
    /// **It is not free and the trade is deliberate.** A copy per frame rather
    /// than per 16 KB is more user/kernel transitions, which is the wrong side
    /// of the trade at rate - but at rate the buffer fills in well under
    /// `to_ms` anyway, so the setting stops mattering exactly where its cost
    /// would. The latency it buys is at the low rates where a person is
    /// watching individual frames arrive.
    ///
    /// `Ok(false)` on a libpcap that does not export it, for the same reason
    /// `set_kernel_buffer` answers that way.
    pub fn set_min_to_copy(&self, bytes: c_int) -> io::Result<bool> {
        let Some(setmintocopy) = self.npcap.setmintocopy else {
            return Ok(false);
        };
        if unsafe { setmintocopy(self.handle, bytes) } != 0 {
            return Err(io::Error::other(self.error()));
        }
        Ok(true)
    }

    /// One frame, or a timeout.
    ///
    /// **A timeout and a failure are different answers.** Collapsing them is
    /// what made the Python loop spin a core at 100% for ever when an adapter
    /// was removed mid-capture: `pcap_next_ex` returns 0 for the timeout but -1
    /// for an error, immediately and repeatedly, and the caller just continued.
    pub fn next(&mut self) -> io::Result<Read<'_>> {
        let mut header: *mut PcapPktHdr = ptr::null_mut();
        let mut data: *const c_uchar = ptr::null();
        let rc = unsafe { (self.npcap.next_ex)(self.handle, &mut header, &mut data) };
        match rc {
            0 => Ok(Read::Timeout),
            1 => {
                if header.is_null() || data.is_null() {
                    return Err(io::Error::other(
                        "pcap_next_ex reported a frame but handed back no pointer",
                    ));
                }
                // SAFETY: rc == 1 means the DLL filled both pointers, and the
                // buffer they describe is valid until the next call - which the
                // returned lifetime ties to `&mut self`.
                let h = unsafe { *header };
                let caplen = h.caplen as usize;
                Ok(Read::Frame {
                    data: unsafe { std::slice::from_raw_parts(data, caplen) },
                    // The driver's own clock, as seconds and microseconds.
                    ts_us: h.ts.tv_sec as f64 * 1_000_000.0 + h.ts.tv_usec as f64,
                    wire_len: h.len,
                })
            }
            // The end of a capture file. Named rather than described by
            // `pcap_geterr`, which reports whatever the handle last failed at
            // - on a file, the `pcap_setmintocopy` the open refused - and so
            // says something true about the wrong call. A live adapter never
            // answers -2; the tests' fixture captures do.
            -2 => Err(io::Error::other(
                "pcap_next_ex failed (-2): the end of the capture file",
            )),
            _ => Err(io::Error::other(format!(
                "pcap_next_ex failed ({rc}): {}",
                self.error()
            ))),
        }
    }

    /// `(received, dropped)` as the driver counts them, or `None` when the call
    /// failed.
    ///
    /// **`None`, never `(0, 0)`.** A counter that could not be read and a
    /// counter that says nothing was lost are different facts, and the app
    /// renders the first as "unknown" rather than as reassurance.
    pub fn stats(&self) -> Option<(u32, u32)> {
        let mut s = PcapStat::default();
        if unsafe { (self.npcap.stats)(self.handle, &mut s) } != 0 {
            return None;
        }
        // The interface's own drops are summed in: both are frames the agent
        // never saw, which is the one quantity nothing downstream can infer.
        Some((s.ps_recv, s.ps_drop.saturating_add(s.ps_ifdrop)))
    }

    fn error(&self) -> String {
        let text = unsafe { cstr((self.npcap.geterr)(self.handle)) };
        if text.is_empty() {
            "no message".to_string()
        } else {
            text
        }
    }
}

impl Drop for Capture<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe { (self.npcap.close)(self.handle) };
            self.handle = ptr::null_mut();
        }
    }
}

// The handle is used from one sniffer thread at a time, and `Capture` owns it.
// `Send` is what lets that thread be spawned; `Sync` is deliberately NOT
// implemented, because two threads calling `pcap_next_ex` on one handle is
// exactly the documented-undefined use the Python agent performs once a second.
unsafe impl Send for Capture<'_> {}
unsafe impl Send for Npcap {}
unsafe impl Sync for Npcap {}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The two optional symbols are optional in the type and present here.**
    ///
    /// Both are Npcap's rather than libpcap's, so the loader treats a missing
    /// one as a degraded capture instead of a failure - which means a typo in
    /// either name would cost the setting and report nothing. `set_min_to_copy`
    /// in particular buys latency and no content, so its absence has no symptom
    /// at all beyond frames arriving up to `to_ms` late.
    ///
    /// **Skips where Npcap is not installed** - a GitHub `windows-latest`
    /// runner, or a fresh machine the Update Center has not reached - because
    /// that is a legal machine and the agent serves it (runtime.rs). It skips
    /// on the *file* being absent, not on the load failing: a `wpcap.dll` that
    /// is present and will not load, or lacks a required export, is exactly
    /// what this test exists to catch.
    #[test]
    fn npcaps_own_symbols_resolve_on_this_machine() {
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let dll = std::path::Path::new(&system).join(r"System32\Npcap\wpcap.dll");
        if !dll.exists() {
            eprintln!("SKIP  Npcap is not installed on this machine ({} is absent)", dll.display());
            return;
        }
        let npcap = Npcap::load().expect("wpcap.dll is installed and loads");
        assert!(npcap.setbuff.is_some(), "wpcap.dll exports no pcap_setbuff");
        assert!(
            npcap.setmintocopy.is_some(),
            "wpcap.dll exports no pcap_setmintocopy"
        );
    }
}
