//! The capture's own pcapng: which file each frame goes in, and the thread
//! that writes them (ADR 0052).
//!
//! Two halves, split where the testing is:
//!
//! - **`Sequencer`** decides, frame by frame, which file a frame belongs to
//!   and whether the capture has reached an autostop limit. Pure, and called
//!   under the same lock that hands the frame its sequence number - so the
//!   file and the live stream to the app can never disagree about which
//!   frames exist, or which file holds one.
//! - **`Writer`** is a thread that follows those decisions: a file opens with
//!   the SHB and every IDB, frames are appended as EPBs, and a file closes with
//!   an ISB per interface. A ring deletes its oldest file once it holds more
//!   than it keeps. Every file operation is made **as the client** that
//!   started the capture (`pipe::ClientToken`), never with the service's own
//!   rights.
//!
//! **The writer never sheds for the app's sake.** The live queue to the app
//! drops its oldest frames when the pipe is slow; the file must not lose a
//! frame because a window was busy. The writer's queue has a byte budget of
//! its own, and a frame that finds it full - the disk, not the app, falling
//! behind - is counted against its interface and reported in the ISB's
//! `isb_ifdrop` and in `capture_stats.droppedWriter`, never silently.

use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::pcapng;
use crate::protocol::{Autostop, Ring};

/// Why the agent stopped a capture itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopReason {
    Packets,
    Bytes,
    Seconds,
    Files,
}

impl StopReason {
    pub fn as_str(self) -> &'static str {
        match self {
            StopReason::Packets => "packets",
            StopReason::Bytes => "bytes",
            StopReason::Seconds => "seconds",
            StopReason::Files => "files",
        }
    }
}

/// What the sequencer says about one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// Write it, into this file (1-based, Wireshark's `_00001`). `first` when
    /// it is the file's first frame, which is when the owner is told where the
    /// file begins (`protocol::capture_boundary`).
    Write { file: u32, first: bool },
    /// The capture has met a limit. This frame and every one after it are
    /// neither written nor sent.
    Stop(StopReason),
}

/// Which file each frame goes in, and when the capture stops.
///
/// **Sizes count what the files hold**: each file starts at its SHB and IDBs
/// (`header_bytes`), and a frame adds its whole EPB. A file rotates on the
/// frame that finds it at or past a limit - dumpcap's rule, so a file ends up
/// at least its size and at most one frame over. Duration is measured on the
/// frames' own capture times: the boundary is then a fact about the capture,
/// the same however late the frames were read. Autostop by seconds is the
/// wall clock's, and is the runtime's to call (`stop_now`), because a silent
/// link must still stop.
#[derive(Debug)]
pub struct Sequencer {
    ring: Ring,
    stop: Autostop,
    header_bytes: u64,
    file: u32,
    file_bytes: u64,
    file_frames: u64,
    file_first_ns: Option<u64>,
    total_frames: u64,
    total_bytes: u64,
    stopped: Option<StopReason>,
}

impl Sequencer {
    pub fn new(ring: Ring, stop: Autostop, header_bytes: u64) -> Self {
        Self {
            ring,
            stop,
            header_bytes,
            file: 1,
            file_bytes: header_bytes,
            file_frames: 0,
            file_first_ns: None,
            total_frames: 0,
            total_bytes: header_bytes,
            stopped: None,
        }
    }

    /// Where a frame of `epb_len` bytes, stamped `ts_ns`, goes.
    pub fn admit(&mut self, epb_len: u64, ts_ns: u64) -> Admit {
        if let Some(reason) = self.stopped {
            return Admit::Stop(reason);
        }
        if self.stop.packets.is_some_and(|limit| self.total_frames >= limit) {
            return self.halt(StopReason::Packets);
        }
        if self.stop.bytes.is_some_and(|limit| self.total_bytes >= limit) {
            return self.halt(StopReason::Bytes);
        }
        if self.file_frames > 0 && self.full(ts_ns) {
            if self.stop.files.is_some_and(|limit| self.file >= limit) {
                return self.halt(StopReason::Files);
            }
            self.file += 1;
            self.file_bytes = self.header_bytes;
            self.file_frames = 0;
            self.file_first_ns = None;
            self.total_bytes += self.header_bytes;
        }
        self.file_frames += 1;
        self.file_bytes += epb_len;
        self.total_frames += 1;
        self.total_bytes += epb_len;
        self.file_first_ns.get_or_insert(ts_ns);
        Admit::Write { file: self.file, first: self.file_frames == 1 }
    }

    /// Stops the capture for a reason decided outside - the wall clock.
    pub fn stop_now(&mut self, reason: StopReason) {
        self.stopped.get_or_insert(reason);
    }

    pub fn stopped(&self) -> Option<StopReason> {
        self.stopped
    }

    fn halt(&mut self, reason: StopReason) -> Admit {
        self.stopped = Some(reason);
        Admit::Stop(reason)
    }

    /// Whether the current file has reached a limit, so this frame starts
    /// the next one.
    fn full(&self, ts_ns: u64) -> bool {
        self.ring.file_bytes.is_some_and(|limit| self.file_bytes >= limit)
            || self.ring.file_packets.is_some_and(|limit| self.file_frames >= limit)
            || self.ring.file_seconds.is_some_and(|seconds| {
                self.file_first_ns
                    .is_some_and(|first| ts_ns.saturating_sub(first) >= seconds.saturating_mul(1_000_000_000))
            })
    }
}

/// One frame, on its way to the file.
pub struct FrameJob {
    pub seq: u64,
    pub file: u32,
    /// The frame's interface as an IDB index: its position among the
    /// capture's adapters, not its id in the interface list.
    pub interface: u32,
    pub ts_ns: u64,
    pub wire_len: u32,
    pub data: Vec<u8>,
}

/// The most the writer may have waiting before a frame is refused, which is
/// the disk falling behind. Generous: a frame costs its bytes and nothing else
/// here, and 64 MB is more than a second at gigabit.
pub const WRITER_BUDGET_BYTES: usize = 64 << 20;

/// The writer's queue: never sheds what it holds, refuses what will not fit.
pub struct WriterQueue {
    state: Mutex<QueueState>,
    ready: Condvar,
    budget: usize,
}

struct QueueState {
    jobs: VecDeque<FrameJob>,
    bytes: usize,
    closed: bool,
}

impl WriterQueue {
    pub fn new(budget: usize) -> Self {
        Self {
            state: Mutex::new(QueueState { jobs: VecDeque::new(), bytes: 0, closed: false }),
            ready: Condvar::new(),
            budget,
        }
    }

    /// Queues a frame, or answers `false` when there is no room for it.
    pub fn push(&self, job: FrameJob) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.closed || state.bytes + job.data.len() > self.budget {
            return false;
        }
        state.bytes += job.data.len();
        state.jobs.push_back(job);
        self.ready.notify_one();
        true
    }

    /// No more frames: the writer finishes what it has and closes the file.
    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
        self.ready.notify_all();
    }

    /// Everything waiting, blocking until there is some or `timeout` passes.
    /// `None` once closed and empty.
    fn take(&self, timeout: Duration) -> Option<Vec<FrameJob>> {
        let mut state = self.state.lock().unwrap();
        if state.jobs.is_empty() && !state.closed {
            state = self.ready.wait_timeout(state, timeout).unwrap().0;
        }
        if state.jobs.is_empty() {
            return if state.closed { None } else { Some(Vec::new()) };
        }
        state.bytes = 0;
        Some(state.jobs.drain(..).collect())
    }
}

/// One of the capture's adapters, as its IDB describes it.
pub struct FileInterface {
    pub name: String,
    pub connection: Option<String>,
    pub hardware: Option<String>,
    pub link_type: u16,
    /// 9 when the driver stamps nanoseconds, 6 when microseconds.
    pub ts_resolution: u8,
}

/// A file, as the app is told about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileReport {
    pub index: u32,
    pub name: String,
    pub first_seq: Option<u64>,
    pub last_seq: Option<u64>,
    pub frames: u64,
    pub bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FileEvent {
    Opened(FileReport),
    Closed(FileReport),
    Deleted(FileReport),
    /// A file could not be created or written (a ring file that cannot be
    /// deleted is logged and left, not this). The capture stops -
    /// a capture writing nowhere is not one its owner asked for.
    Failed(String),
}

/// An interface's counters at the moment a file closes: frames received, and
/// frames the driver dropped - `None` when the driver could not say.
pub type Counters = dyn Fn(usize) -> (u64, Option<u64>) + Send + Sync;

/// Everything the writer thread needs, fixed for the capture.
pub struct WriterSetup {
    /// `<root>\<captureId>\pcapng`.
    pub dir: PathBuf,
    pub ring: Ring,
    /// Who the files are written as. `None` only in tests, which write as
    /// themselves.
    pub token: Option<crate::pipe::ClientToken>,
    pub interfaces: Vec<FileInterface>,
    /// The SHB and IDBs every file opens with (`file_header`) - built once, so
    /// the sequencer's sizes and the files' bytes are the same bytes.
    pub header: Vec<u8>,
    /// The capture's start, epoch nanoseconds, for every ISB's `isb_starttime`.
    pub started_ns: u64,
    pub counters: Arc<Counters>,
    pub events: Box<dyn Fn(FileEvent) + Send>,
}

/// The SHB and IDBs every file of this capture opens with.
pub fn file_header(interfaces: &[FileInterface], snaplen: u32, filter: Option<&str>) -> Vec<u8> {
    let os = os_description();
    let hardware = cpu_description();
    let application = format!("Inwire {}", crate::VERSION);
    let mut out = Vec::with_capacity(512);
    pcapng::section_header(&mut out, &pcapng::SectionHeader {
        hardware: hardware.as_deref(),
        os: os.as_deref(),
        application: &application,
    });
    for interface in interfaces {
        pcapng::interface_description(&mut out, &pcapng::InterfaceDescription {
            link_type: interface.link_type,
            snaplen,
            name: &interface.name,
            description: interface.connection.as_deref(),
            speed: 0,
            ts_resolution: interface.ts_resolution,
            filter,
            os: os.as_deref(),
            hardware: interface.hardware.as_deref(),
        });
    }
    out
}

/// The running writer.
pub struct Writer {
    queue: Arc<WriterQueue>,
    /// Frames refused because the queue was full, per interface.
    dropped: Arc<Vec<AtomicU64>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Writer {
    /// Starts the thread. The first file is created at once, so a capture
    /// that sees nothing still leaves a file saying so.
    pub fn start(setup: WriterSetup) -> Writer {
        let queue = Arc::new(WriterQueue::new(WRITER_BUDGET_BYTES));
        let dropped: Arc<Vec<AtomicU64>> =
            Arc::new(setup.interfaces.iter().map(|_| AtomicU64::new(0)).collect());
        let (q, d) = (Arc::clone(&queue), Arc::clone(&dropped));
        let thread = thread::spawn(move || run(setup, &q, &d));
        Writer { queue, dropped, thread: Some(thread) }
    }

    /// Hands a frame over, or counts it as dropped by the writer.
    pub fn push(&self, job: FrameJob) {
        let interface = job.interface as usize;
        if !self.queue.push(job) {
            if let Some(counter) = self.dropped.get(interface) {
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Frames the writer refused, across every interface.
    pub fn dropped(&self) -> u64 {
        self.dropped.iter().map(|d| d.load(Ordering::Relaxed)).sum()
    }

    /// Writes what is waiting, closes the file, and returns once it has.
    pub fn finish(mut self) {
        self.queue.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        self.queue.close();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A file being written.
struct OpenFile {
    report: FileReport,
    path: PathBuf,
    out: BufWriter<File>,
}

/// The thread's whole life: open file 1, follow the frames, close the last.
fn run(setup: WriterSetup, queue: &WriterQueue, dropped: &[AtomicU64]) {
    let header = &setup.header;
    let mut on_disk: VecDeque<(FileReport, PathBuf)> = VecDeque::new();
    let fail = |error: String| (setup.events)(FileEvent::Failed(error));

    let mut current = match open(&setup, 1, header) {
        Ok(file) => file,
        Err(error) => return fail(error),
    };
    (setup.events)(FileEvent::Opened(current.report.clone()));
    let mut last_flush = Instant::now();
    let mut scratch = Vec::with_capacity(2048);

    while let Some(jobs) = queue.take(Duration::from_millis(250)) {
        for job in jobs {
            if job.file != current.report.index {
                if let Err(error) = close(&setup, &mut current, dropped) {
                    return fail(error);
                }
                on_disk.push_back((current.report.clone(), current.path.clone()));
                (setup.events)(FileEvent::Closed(current.report.clone()));
                current = match open(&setup, job.file, header) {
                    Ok(file) => file,
                    Err(error) => return fail(error),
                };
                (setup.events)(FileEvent::Opened(current.report.clone()));
                // The newest `keep`, counting the one just opened.
                if let Some(keep) = setup.ring.keep {
                    while on_disk.len() + 1 > keep as usize {
                        let Some((oldest, path)) = on_disk.pop_front() else { break };
                        // **A file that cannot be deleted does not end the
                        // capture** (open in Wireshark without delete sharing,
                        // say): dumpcap logs it and carries on. It was popped
                        // from `on_disk`, so it is not tried again, and no
                        // `Deleted` is sent for it - the app files a segment by
                        // that event, so the file keeps its segment.
                        if let Err(error) = as_client(&setup, || fs::remove_file(&path)) {
                            crate::log_warn!(
                                "could not delete {}: {error} - it stays on disk and the ring carries on",
                                oldest.name
                            );
                            continue;
                        }
                        (setup.events)(FileEvent::Deleted(oldest));
                    }
                }
            }
            let interface = &setup.interfaces[job.interface as usize];
            let timestamp = in_units(job.ts_ns, interface.ts_resolution);
            scratch.clear();
            pcapng::enhanced_packet(&mut scratch, job.interface, timestamp, &job.data, job.wire_len);
            if let Err(error) = current.out.write_all(&scratch) {
                return fail(format!("could not write {}: {error}", current.report.name));
            }
            let report = &mut current.report;
            report.first_seq.get_or_insert(job.seq);
            report.last_seq = Some(job.seq);
            report.frames += 1;
            report.bytes += scratch.len() as u64;
        }
        // Flushed once a second, so a file being written is a file that can
        // be read - by the app's Save, or by Wireshark opening it live.
        if last_flush.elapsed() >= Duration::from_secs(1) {
            last_flush = Instant::now();
            if let Err(error) = current.out.flush() {
                return fail(format!("could not write {}: {error}", current.report.name));
            }
        }
    }
    if let Err(error) = close(&setup, &mut current, dropped) {
        return fail(error);
    }
    (setup.events)(FileEvent::Closed(current.report.clone()));
}

/// Runs a file operation as the client, or as ourselves when there is none.
fn as_client<T>(setup: &WriterSetup, work: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    match &setup.token {
        Some(token) => token.act(work)?,
        None => work(),
    }
}

fn file_name(ring: &Ring, index: u32) -> String {
    if ring.rotates() {
        format!("capture_{index:05}_{}.pcapng", local_stamp())
    } else {
        "capture.pcapng".to_string()
    }
}

/// `capture.pcapng`, or `capture-2.pcapng` and on when that name is taken.
fn candidate(name: &str, attempt: u32) -> String {
    match (attempt, name.rsplit_once('.')) {
        (1, _) | (_, None) => name.to_string(),
        (n, Some((stem, extension))) => format!("{stem}-{n}.{extension}"),
    }
}

fn open(setup: &WriterSetup, index: u32, header: &[u8]) -> Result<OpenFile, String> {
    let wanted = file_name(&setup.ring, index);
    // **`create_new`: a capture never writes over a file it did not make.** A
    // name already taken is the capture resuming - the app's reconnect names
    // the same capture again after the agent restarted - so the next free name
    // is taken rather than the start refused.
    let mut attempt = 1;
    let (name, path, file) = loop {
        let name = candidate(&wanted, attempt);
        let path = setup.dir.join(&name);
        let opened = as_client(setup, || {
            fs::create_dir_all(&setup.dir)?;
            File::options().write(true).create_new(true).open(&path)
        });
        match opened {
            Ok(file) => break (name, path, file),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists && attempt < 100 => attempt += 1,
            Err(error) => return Err(format!("could not create {}: {error}", show(&path))),
        }
    };
    let mut out = BufWriter::with_capacity(1 << 20, file);
    out.write_all(header).map_err(|error| format!("could not write {name}: {error}"))?;
    Ok(OpenFile {
        report: FileReport { index, name, first_seq: None, last_seq: None, frames: 0, bytes: header.len() as u64 },
        path,
        out,
    })
}

/// Ends a file with an ISB per interface, and flushes it.
///
/// The counters are the capture's since it began - what dumpcap's ISB
/// carries, "Counters provided by dumpcap" at the close - so every file of a
/// ring says how the capture stood when that file ended.
fn close(setup: &WriterSetup, file: &mut OpenFile, dropped: &[AtomicU64]) -> Result<(), String> {
    let now = crate::session::wall_clock_ns();
    let mut tail = Vec::with_capacity(128 * setup.interfaces.len());
    for (i, interface) in setup.interfaces.iter().enumerate() {
        let (received, kernel_dropped) = (setup.counters)(i);
        let writer_dropped = dropped.get(i).map_or(0, |d| d.load(Ordering::Relaxed));
        let units = interface.ts_resolution;
        pcapng::interface_statistics(&mut tail, &pcapng::InterfaceStatistics {
            interface_id: i as u32,
            timestamp: in_units(now, units),
            comment: Some("Counters provided by Inwire"),
            start: Some(in_units(setup.started_ns, units)),
            end: Some(in_units(now, units)),
            received: Some(received),
            // Unknown stays unknown: a driver that could not say is not a
            // driver that dropped nothing.
            dropped: kernel_dropped.map(|k| k + writer_dropped),
        });
    }
    file.report.bytes += tail.len() as u64;
    file.out
        .write_all(&tail)
        .and_then(|()| file.out.flush())
        .map_err(|error| format!("could not write {}: {error}", file.report.name))
}

/// Epoch nanoseconds in an interface's units.
fn in_units(ts_ns: u64, resolution: u8) -> u64 {
    if resolution >= 9 {
        ts_ns
    } else {
        ts_ns / 1_000
    }
}

fn show(path: &Path) -> String {
    path.display().to_string()
}

// --- the section's facts, as dumpcap states them -----------------------------

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

#[link(name = "kernel32")]
extern "system" {
    fn GetLocalTime(time: *mut SystemTime);
}

#[link(name = "advapi32")]
extern "system" {
    fn RegGetValueW(
        key: isize,
        sub_key: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut u8,
        size: *mut u32,
    ) -> i32;
}

const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
const RRF_RT_REG_SZ: u32 = 0x0000_0002;

/// `YYYYMMDDhhmmss` in local time, for a ring file's name - Wireshark's.
fn local_stamp() -> String {
    let mut t = SystemTime::default();
    unsafe { GetLocalTime(&mut t) };
    format!("{:04}{:02}{:02}{:02}{:02}{:02}", t.year, t.month, t.day, t.hour, t.minute, t.second)
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn registry_string(sub_key: &str, value: &str) -> Option<String> {
    let (key, name) = (wide(sub_key), wide(value));
    let mut buffer = vec![0u16; 256];
    let mut size = (buffer.len() * 2) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast(),
            &mut size,
        )
    };
    if status != 0 {
        return None;
    }
    let len = (size as usize / 2).saturating_sub(1);
    Some(String::from_utf16_lossy(&buffer[..len.min(buffer.len())]))
}

/// The OS as dumpcap words it: `64-bit Windows 11 (25H2), build 26200`.
///
/// The registry's `ProductName` still says "Windows 10" on Windows 11, so the
/// major version is read from the build, as Wireshark does: 22000 and above
/// is 11.
pub fn os_description() -> Option<String> {
    const KEY: &str = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
    let build = registry_string(KEY, "CurrentBuildNumber")?;
    let number: u32 = build.trim().parse().ok()?;
    let major = if number >= 22_000 { 11 } else { 10 };
    let bits = if cfg!(target_pointer_width = "64") { "64-bit" } else { "32-bit" };
    Some(match registry_string(KEY, "DisplayVersion") {
        Some(release) => format!("{bits} Windows {major} ({release}), build {number}"),
        None => format!("{bits} Windows {major}, build {number}"),
    })
}

/// The CPU as dumpcap words it: the processor's brand string, and
/// "(with SSE4.2)" when it has that - which `pcap`'s CRC work cares about and
/// Wireshark has always said.
pub fn cpu_description() -> Option<String> {
    #[cfg(target_arch = "x86_64")]
    {
        use std::arch::x86_64::__cpuid;
        let highest = __cpuid(0x8000_0000).eax;
        if highest < 0x8000_0004 {
            return None;
        }
        let mut bytes = Vec::with_capacity(48);
        for leaf in 0x8000_0002u32..=0x8000_0004 {
            let r = __cpuid(leaf);
            for word in [r.eax, r.ebx, r.ecx, r.edx] {
                bytes.extend_from_slice(&word.to_le_bytes());
            }
        }
        let brand = String::from_utf8_lossy(&bytes).trim_matches(char::from(0)).trim().to_string();
        let sse42 = __cpuid(1).ecx & (1 << 20) != 0;
        Some(if sse42 { format!("{brand} (with SSE4.2)") } else { brand })
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ring(bytes: Option<u64>, seconds: Option<u64>, packets: Option<u64>, keep: Option<u32>) -> Ring {
        Ring { file_bytes: bytes, file_seconds: seconds, file_packets: packets, keep }
    }

    #[test]
    fn one_file_holds_everything_when_nothing_rotates() {
        let mut s = Sequencer::new(Ring::default(), Autostop::default(), 400);
        for i in 0..10_000u64 {
            assert_eq!(s.admit(1_532, i), Admit::Write { file: 1, first: i == 0 });
        }
    }

    #[test]
    fn a_file_rotates_on_the_frame_that_finds_it_full() {
        // 400 bytes of headers, 100-byte frames, 1,000-byte files: 400 + 6 *
        // 100 = 1,000, so the seventh frame opens file 2 and the file is
        // never more than one frame over.
        let mut s = Sequencer::new(ring(Some(1_000), None, None, None), Autostop::default(), 400);
        let files: Vec<u32> = (0..14).map(|i| match s.admit(100, i) {
            Admit::Write { file, .. } => file,
            other => panic!("{other:?}"),
        }).collect();
        assert_eq!(files, [1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 3, 3]);
    }

    #[test]
    fn a_file_rotates_by_packets_and_by_capture_time() {
        let mut by_packets = Sequencer::new(ring(None, None, Some(3), None), Autostop::default(), 0);
        let files: Vec<u32> = (0..7).map(|i| match by_packets.admit(64, i) {
            Admit::Write { file, .. } => file,
            other => panic!("{other:?}"),
        }).collect();
        assert_eq!(files, [1, 1, 1, 2, 2, 2, 3]);

        // Two seconds a file, on the frames' own stamps.
        let mut by_time = Sequencer::new(ring(None, Some(2), None, None), Autostop::default(), 0);
        let stamps = [0u64, 1_000_000_000, 1_999_999_999, 2_000_000_000, 3_500_000_000, 4_000_000_001];
        let files: Vec<u32> = stamps.iter().map(|&t| match by_time.admit(64, t) {
            Admit::Write { file, .. } => file,
            other => panic!("{other:?}"),
        }).collect();
        assert_eq!(files, [1, 1, 1, 2, 2, 3]);
    }

    #[test]
    fn autostop_is_exact_and_final() {
        let stop = Autostop { packets: Some(5), ..Autostop::default() };
        let mut s = Sequencer::new(Ring::default(), stop, 0);
        for i in 0..5 {
            assert_eq!(s.admit(64, i), Admit::Write { file: 1, first: i == 0 });
        }
        assert_eq!(s.admit(64, 5), Admit::Stop(StopReason::Packets));
        assert_eq!(s.admit(64, 6), Admit::Stop(StopReason::Packets), "a stop stays a stop");

        // Files: the frame that would open the fourth file stops instead.
        let stop = Autostop { files: Some(3), ..Autostop::default() };
        let mut s = Sequencer::new(ring(None, None, Some(2), None), stop, 0);
        let answers: Vec<Admit> = (0..7).map(|i| s.admit(64, i)).collect();
        assert_eq!(answers[4], Admit::Write { file: 3, first: true });
        assert_eq!(answers[5], Admit::Write { file: 3, first: false });
        assert_eq!(answers[6], Admit::Stop(StopReason::Files));

        // Bytes: across every file, headers included.
        let stop = Autostop { bytes: Some(1_000), ..Autostop::default() };
        let mut s = Sequencer::new(Ring::default(), stop, 400);
        let written = (0..20).take_while(|&i| s.admit(100, i) != Admit::Stop(StopReason::Bytes)).count();
        assert_eq!(written, 6);

        // The wall clock's, from outside.
        let mut s = Sequencer::new(Ring::default(), Autostop::default(), 0);
        s.stop_now(StopReason::Seconds);
        assert_eq!(s.admit(64, 0), Admit::Stop(StopReason::Seconds));
    }

    #[test]
    fn the_writer_refuses_what_will_not_fit_and_never_sheds() {
        let q = WriterQueue::new(1_000);
        let job = |seq: u64, len: usize| FrameJob { seq, file: 1, interface: 0, ts_ns: 0, wire_len: len as u32, data: vec![0; len] };
        assert!(q.push(job(0, 600)));
        assert!(!q.push(job(1, 600)), "over budget is refused, not made room for");
        assert!(q.push(job(2, 400)));
        let taken = q.take(Duration::from_millis(1)).unwrap();
        assert_eq!(taken.iter().map(|j| j.seq).collect::<Vec<_>>(), [0, 2], "what was accepted is kept, in order");
        q.close();
        assert!(q.take(Duration::from_millis(1)).is_none());
    }

    /// dumpcap logs a ring file it cannot delete (open in Wireshark without
    /// delete sharing, say) and carries on; ending a capture over it lost the
    /// rest of the capture to a file somebody was reading. The stuck file stays
    /// on disk, is never reported `Deleted` (the app files a segment by that
    /// event, so it keeps its segment), and the ring goes on rotating.
    #[test]
    fn a_ring_file_that_cannot_be_deleted_is_left_and_the_capture_carries_on() {
        use std::os::windows::fs::OpenOptionsExt;
        use std::sync::Mutex;

        let dir = std::env::temp_dir().join(format!("inwire-ring-stuck-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let interfaces = vec![FileInterface {
            name: "test".into(),
            connection: None,
            hardware: None,
            link_type: 1,
            ts_resolution: 9,
        }];
        let events: Arc<Mutex<Vec<FileEvent>>> = Arc::default();
        let sink = Arc::clone(&events);
        let header = file_header(&interfaces, 65_535, None);
        let writer = Writer::start(WriterSetup {
            dir: dir.clone(),
            ring: ring(None, None, Some(1), Some(2)),
            token: None,
            interfaces,
            header,
            started_ns: 0,
            counters: Arc::new(|_| (0, Some(0))),
            events: Box::new(move |event| sink.lock().unwrap().push(event)),
        });
        let job = |seq: u64, file: u32| FrameJob {
            seq, file, interface: 0, ts_ns: seq, wire_len: 60, data: vec![0; 60],
        };
        let opened = |index: u32| {
            events.lock().unwrap().iter().find_map(|event| match event {
                FileEvent::Opened(report) if report.index == index => Some(report.name.clone()),
                _ => None,
            })
        };
        let wait_for = |index: u32| {
            for _ in 0..200 {
                if let Some(name) = opened(index) {
                    return name;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            panic!("file {index} was never opened: {:?}", events.lock().unwrap());
        };

        writer.push(job(0, 1));
        writer.push(job(1, 2));
        // File 1 is closed once file 2 is open, and only then can it be held
        // the way Wireshark holds one: readable, with no delete sharing.
        let stuck_name = wait_for(1);
        let _ = wait_for(2);
        let held = loop {
            match File::options().read(true).share_mode(0).open(dir.join(&stuck_name)) {
                Ok(file) => break file,
                Err(_) => std::thread::sleep(Duration::from_millis(25)),
            }
        };
        // Two more rotations: the first tries to delete file 1 and cannot, the
        // second deletes file 2 as usual.
        writer.push(job(2, 3));
        writer.push(job(3, 4));
        writer.finish();

        let seen = events.lock().unwrap().clone();
        let deleted: Vec<u32> = seen.iter().filter_map(|e| match e {
            FileEvent::Deleted(report) => Some(report.index),
            _ => None,
        }).collect();
        let opened_indexes: Vec<u32> = seen.iter().filter_map(|e| match e {
            FileEvent::Opened(report) => Some(report.index),
            _ => None,
        }).collect();
        let failed: Vec<&FileEvent> = seen.iter().filter(|e| matches!(e, FileEvent::Failed(_))).collect();
        let stuck_exists = dir.join(&stuck_name).exists();
        drop(held);
        let _ = fs::remove_dir_all(&dir);

        assert!(failed.is_empty(), "the writer did not fail: {failed:?}");
        assert_eq!(opened_indexes, [1, 2, 3, 4], "the capture carried on through both rotations");
        assert_eq!(deleted, [2], "only the file that could be deleted was reported deleted");
        assert!(stuck_exists, "the file that could not be deleted is still on disk");
    }

    #[test]
    fn a_name_already_taken_is_followed_by_the_next_free_one() {
        assert_eq!(candidate("capture.pcapng", 1), "capture.pcapng");
        assert_eq!(candidate("capture.pcapng", 2), "capture-2.pcapng");
        assert_eq!(candidate("capture_00001_20260928120000.pcapng", 3), "capture_00001_20260928120000-3.pcapng");
    }

    #[test]
    fn the_section_says_what_dumpcap_says() {
        let os = os_description().expect("the build number is readable");
        assert!(os.starts_with("64-bit Windows "), "{os}");
        assert!(os.contains(", build "), "{os}");
        if let Some(cpu) = cpu_description() {
            assert!(!cpu.is_empty() && !cpu.contains('\0'), "{cpu:?}");
        }
        assert_eq!(local_stamp().len(), 14);
        eprintln!("shb_os: {os}
shb_hardware: {:?}", cpu_description());
    }
}
