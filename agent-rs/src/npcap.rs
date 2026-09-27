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
//!   captured-length field is 16 bits, so the capture is opened at 65535 at
//!   most and a frame that cannot be encoded is made impossible here rather
//!   than refused later. A client may ask for less (`OpenOptions::snaplen`).
//! - **`pcap_create` and `pcap_activate`, not `pcap_open_live`.** The snaplen
//!   and the timestamp precision can only be set between the two, and
//!   `pcap_open_live` is both at once with no room between them. It is how
//!   the capture gets nanoseconds: asked for before activation, Npcap stamps
//!   in them, and the `tv_usec` field of every header then holds nanoseconds -
//!   which is why a `Capture` remembers the precision it was given rather than
//!   the one it asked for.

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

/// `pcap_compile`'s netmask when it is not known, which only matters to the
/// `ip broadcast` primitive - and that one then refuses to compile rather than
/// matching the wrong addresses.
const PCAP_NETMASK_UNKNOWN: u32 = 0xffff_ffff;

/// `pcap_set_tstamp_precision`'s nanosecond answer; 0 is microseconds.
const PCAP_TSTAMP_PRECISION_NANO: c_int = 1;

/// `pcap_activate`'s plain failure, whose text is `pcap_geterr`'s. Every other
/// negative status has its own name in `pcap_statustostr`.
const PCAP_ERROR: c_int = -1;

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

/// A compiled filter. Owned by whoever compiled it, and freed with
/// `pcap_freecode` once `pcap_setfilter` has taken its copy.
#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

type PcapT = c_void;

type FnCreate = unsafe extern "C" fn(*const c_char, *mut c_char) -> *mut PcapT;
type FnSetInt = unsafe extern "C" fn(*mut PcapT, c_int) -> c_int;
type FnActivate = unsafe extern "C" fn(*mut PcapT) -> c_int;
type FnGetInt = unsafe extern "C" fn(*mut PcapT) -> c_int;
type FnStatusToStr = unsafe extern "C" fn(c_int) -> *const c_char;
type FnCompile =
    unsafe extern "C" fn(*mut PcapT, *mut BpfProgram, *const c_char, c_int, u32) -> c_int;
type FnSetFilter = unsafe extern "C" fn(*mut PcapT, *mut BpfProgram) -> c_int;
type FnFreeCode = unsafe extern "C" fn(*mut BpfProgram);
type FnOpenDead = unsafe extern "C" fn(c_int, c_int) -> *mut PcapT;
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
type FnOpenOffline = unsafe extern "C" fn(*const c_char, c_int, *mut c_char) -> *mut PcapT;

/// The loaded library and its entry points.
pub struct Npcap {
    create: FnCreate,
    set_snaplen: FnSetInt,
    set_promisc: FnSetInt,
    set_timeout: FnSetInt,
    activate: FnActivate,
    statustostr: FnStatusToStr,
    /// Both `None` on a libpcap older than 1.5, where a capture is in
    /// microseconds and says so (`Capture::nanoseconds`).
    set_tstamp_precision: Option<FnSetInt>,
    get_tstamp_precision: Option<FnGetInt>,
    compile: FnCompile,
    setfilter: FnSetFilter,
    freecode: FnFreeCode,
    open_dead: FnOpenDead,
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
    /// `pcap_open_offline_with_tstamp_precision`, for the tests alone: it is
    /// how `runtime.rs`'s tests drive the real sniffer, pump and reaper with
    /// the real frames of `test/fixtures/*.pcap`, read through Npcap exactly as
    /// a live adapter's are - in nanoseconds, as a live one is - including
    /// `pcap_next_ex`'s -2 at the end of the file, which is an adapter
    /// "failing" the same way a removed one does.
    #[cfg(test)]
    open_offline: FnOpenOffline,
}

/// How to open an adapter.
#[derive(Clone, Copy, Debug)]
pub struct OpenOptions {
    pub promiscuous: bool,
    /// The most of each frame to keep. At most `SNAPLEN`.
    pub snaplen: u16,
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
                create: std::mem::transmute::<Farproc, FnCreate>(sym(module, "pcap_create")?),
                set_snaplen: std::mem::transmute::<Farproc, FnSetInt>(sym(module, "pcap_set_snaplen")?),
                set_promisc: std::mem::transmute::<Farproc, FnSetInt>(sym(module, "pcap_set_promisc")?),
                set_timeout: std::mem::transmute::<Farproc, FnSetInt>(sym(module, "pcap_set_timeout")?),
                activate: std::mem::transmute::<Farproc, FnActivate>(sym(module, "pcap_activate")?),
                statustostr: std::mem::transmute::<Farproc, FnStatusToStr>(
                    sym(module, "pcap_statustostr")?,
                ),
                set_tstamp_precision: sym(module, "pcap_set_tstamp_precision")
                    .ok()
                    .map(|p| std::mem::transmute::<Farproc, FnSetInt>(p)),
                get_tstamp_precision: sym(module, "pcap_get_tstamp_precision")
                    .ok()
                    .map(|p| std::mem::transmute::<Farproc, FnGetInt>(p)),
                compile: std::mem::transmute::<Farproc, FnCompile>(sym(module, "pcap_compile")?),
                setfilter: std::mem::transmute::<Farproc, FnSetFilter>(sym(module, "pcap_setfilter")?),
                freecode: std::mem::transmute::<Farproc, FnFreeCode>(sym(module, "pcap_freecode")?),
                open_dead: std::mem::transmute::<Farproc, FnOpenDead>(sym(module, "pcap_open_dead")?),
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
                    sym(module, "pcap_open_offline_with_tstamp_precision")?,
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

    /// Opens a capture file as if it were an adapter, in nanoseconds. Tests
    /// only - see the `open_offline` field.
    #[cfg(test)]
    pub fn open_file(&self, path: &std::path::Path) -> io::Result<Capture<'_>> {
        let name = CString::new(path.to_string_lossy().as_bytes())
            .map_err(|_| io::Error::other("a path cannot contain a nul"))?;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        let handle = unsafe {
            (self.open_offline)(name.as_ptr(), PCAP_TSTAMP_PRECISION_NANO, errbuf.as_mut_ptr())
        };
        if handle.is_null() {
            return Err(io::Error::other(unsafe { cstr(errbuf.as_ptr()) }));
        }
        Ok(Capture { npcap: self, handle, nanoseconds: true, keep: SNAPLEN as usize })
    }

    /// Opens one device for capture.
    ///
    /// `to_ms` is 100 deliberately: the read returns on its own timeout, which
    /// is how a stop is honoured promptly on an adapter with no traffic.
    ///
    /// **Nanoseconds are asked for and not required.** A driver that refuses
    /// them captures in microseconds, and the handle says which it got - a
    /// precision is a fact about the frames, and the frames are no less worth
    /// having for being stamped more coarsely.
    pub fn open(&self, device: &str, options: OpenOptions) -> io::Result<Capture<'_>> {
        let name = CString::new(device)
            .map_err(|_| io::Error::other("a device name cannot contain a nul"))?;
        let mut errbuf = [0 as c_char; PCAP_ERRBUF_SIZE];
        let handle = unsafe { (self.create)(name.as_ptr(), errbuf.as_mut_ptr()) };
        if handle.is_null() {
            return Err(io::Error::other(unsafe { cstr(errbuf.as_ptr()) }));
        }
        // Owned from here, so every early return below closes it.
        let mut capture = Capture { npcap: self, handle, nanoseconds: false, keep: SNAPLEN as usize };
        let snaplen = c_int::from(options.snaplen).clamp(1, SNAPLEN);
        capture.keep_at_most(options.snaplen);
        unsafe {
            (self.set_snaplen)(handle, snaplen);
            (self.set_promisc)(handle, c_int::from(options.promiscuous));
            (self.set_timeout)(handle, 100);
            if let Some(set_precision) = self.set_tstamp_precision {
                // Refused with PCAP_ERROR_TSTAMP_PRECISION_NOTSUP by a driver
                // that stamps in microseconds only; asked below which it was.
                set_precision(handle, PCAP_TSTAMP_PRECISION_NANO);
            }
        }
        let status = unsafe { (self.activate)(handle) };
        // A positive status is a warning - promiscuous mode not supported, a
        // timestamp type refused - and the handle is live.
        if status < 0 {
            let text = capture.error();
            let reason = if status == PCAP_ERROR || text != "no message" {
                text
            } else {
                unsafe { cstr((self.statustostr)(status)) }
            };
            return Err(io::Error::other(reason));
        }
        capture.nanoseconds = self
            .get_tstamp_precision
            .map(|get| unsafe { get(handle) } == PCAP_TSTAMP_PRECISION_NANO)
            .unwrap_or(false);
        Ok(capture)
    }

    /// Whether `filter` compiles for an adapter of `link_type`, and libpcap's
    /// own sentence when it does not.
    ///
    /// A filter is compiled against a link type, not a device: `ether host`
    /// means nothing on Npcap's loopback adapter, which is `DLT_NULL`. So this
    /// asks a dead handle of that type, which opens nothing and needs no
    /// privilege - it is the question a filter box asks while somebody types.
    pub fn check_filter(&self, link_type: i32, filter: &str) -> Result<(), String> {
        let handle = unsafe { (self.open_dead)(link_type, SNAPLEN) };
        if handle.is_null() {
            return Err(format!("libpcap cannot compile for link type {link_type}"));
        }
        let dead = Capture { npcap: self, handle, nanoseconds: false, keep: 0 };
        dead.compile(filter).map(|mut program| unsafe { (self.freecode)(&mut program) })
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
    /// A frame, its capture time in epoch nanoseconds, and its length on the
    /// wire.
    Frame {
        data: &'a [u8],
        ts_ns: u64,
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
    /// What the driver stamps in, as it answered after activation.
    nanoseconds: bool,
    /// The most of any frame `next` hands out - see `keep_at_most`.
    keep: usize,
}

impl Capture<'_> {
    /// Whether this handle's timestamps are nanoseconds rather than
    /// microseconds - the precision the frames actually carry, which is 9
    /// decimals or 6 in the app's time column.
    pub fn nanoseconds(&self) -> bool {
        self.nanoseconds
    }

    /// Hands out at most `snaplen` bytes of any frame, whatever the driver
    /// delivered, and reports the rest in the wire length as the driver does.
    ///
    /// **The driver already truncates at the snaplen it was opened with**, so
    /// on a live adapter this never cuts anything. It is here so the snaplen a
    /// capture asked for is a property of what this handle hands out rather
    /// than a promise about every driver - and so it holds on a capture file,
    /// which a snaplen given to libpcap does not touch, which is how the tests
    /// read real frames through it.
    pub fn keep_at_most(&mut self, snaplen: u16) {
        self.keep = usize::from(snaplen.max(1));
    }

    /// Compiles `filter` for this handle, or says why not in libpcap's words.
    fn compile(&self, filter: &str) -> Result<BpfProgram, String> {
        let text =
            CString::new(filter).map_err(|_| "a capture filter cannot contain a nul".to_string())?;
        let mut program = BpfProgram { bf_len: 0, bf_insns: ptr::null_mut() };
        let rc = unsafe {
            (self.npcap.compile)(self.handle, &mut program, text.as_ptr(), 1, PCAP_NETMASK_UNKNOWN)
        };
        if rc != 0 {
            return Err(self.error());
        }
        Ok(program)
    }

    /// Has the driver drop every frame `filter` does not match, before it is
    /// copied anywhere.
    ///
    /// **In the kernel, which is the point.** A frame the filter refuses never
    /// reaches the ring, so it cannot fill it: this is the one lever that makes
    /// a burst of traffic nobody asked for cost nothing, where every other
    /// stage only decides who pays.
    pub fn set_filter(&self, filter: &str) -> Result<(), String> {
        let mut program = self.compile(filter)?;
        let rc = unsafe { (self.npcap.setfilter)(self.handle, &mut program) };
        // libpcap keeps its own copy; ours is freed whether or not it took.
        unsafe { (self.npcap.freecode)(&mut program) };
        if rc != 0 {
            return Err(self.error());
        }
        Ok(())
    }

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
                let caplen = (h.caplen as usize).min(self.keep);
                // The driver's own clock, as seconds and a fraction whose unit
                // is the precision the handle was activated with. The seconds
                // are an `i32` on Windows and read as unsigned, which carries
                // them to 2106 rather than to 2038.
                let fraction = u64::from(h.ts.tv_usec as u32);
                let ts_ns = u64::from(h.ts.tv_sec as u32) * 1_000_000_000
                    + if self.nanoseconds { fraction } else { fraction * 1_000 };
                Ok(Read::Frame {
                    data: unsafe { std::slice::from_raw_parts(data, caplen) },
                    ts_ns,
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
        // Optional in the type for an old libpcap, and required here: without
        // them every capture on this machine is quietly microseconds.
        assert!(npcap.set_tstamp_precision.is_some(), "wpcap.dll exports no pcap_set_tstamp_precision");
        assert!(npcap.get_tstamp_precision.is_some(), "wpcap.dll exports no pcap_get_tstamp_precision");
    }

    /// **A filter is checked against a link type, in libpcap's own words.**
    /// `ether host` compiles for Ethernet and not for Npcap's loopback, which
    /// is `DLT_NULL` - the reason the check takes a link type at all.
    #[test]
    fn a_capture_filter_compiles_or_says_why() {
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        if !std::path::Path::new(&system).join(r"System32\Npcap\wpcap.dll").exists() {
            eprintln!("SKIP  Npcap is not installed on this machine");
            return;
        }
        let npcap = Npcap::load().expect("wpcap.dll is installed and loads");
        assert_eq!(npcap.check_filter(1, "tcp port 443 or udp port 53"), Ok(()));
        assert_eq!(npcap.check_filter(1, "ether host 00:11:22:33:44:55"), Ok(()));
        let loopback = npcap.check_filter(0, "ether host 00:11:22:33:44:55");
        assert!(loopback.is_err(), "ether host compiled for DLT_NULL");
        let typo = npcap.check_filter(1, "tcp prot 443").unwrap_err();
        assert!(typo.contains("syntax error"), "libpcap's reason is kept: {typo}");
    }
}
