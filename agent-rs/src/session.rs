//! The queue between the sniffer threads and the pump, and how a batch is cut.
//!
//! The port of `AgentServer.queue_packet`, `_drain_packets` and `_packet_pump`
//! from `local-agent/agent.py` - three methods on a 780-line class, which the
//! file's own grouping comments already mark as a `CaptureSession` wanting to
//! exist.
//!
//! ## The throttle this is shaped to make unrepresentable
//!
//! A drain stops on **either** bound: 512 records or 256 kB. The Python pump
//! then decided whether the queue had run dry by re-testing the RECORD count:
//!
//! ```python
//! if len(batch) < MAX_BATCH_RECORDS:
//!     await asyncio.sleep(PACKET_BATCH_INTERVAL_SECONDS)   # 10 ms
//! ```
//!
//! At the 1,101-byte mean frame this repo measured, 256 kB is about 233 records
//! - under 512 - so **every batch on real traffic was read as an empty queue**
//! and the pump slept 10 ms with up to 32 MB backed up behind it. Measured on
//! the machine this was found on: 14,959 f/s and 16.5 MB/s, against a link that
//! was delivering more. Small-frame floods reach 512 records first and were
//! never affected, which is why every synthetic test passed and only real
//! captures lost frames.
//!
//! So `drain` returns **why it stopped**, not a count for somebody to re-derive
//! the answer from. `Drain::More` and `Drain::Drained` are different values, and
//! the sleep is reachable from exactly one of them.
//!
//! ## Shedding is oldest-first and counted
//!
//! Bounded by a frame count AND a byte budget, because a frame is 60 bytes to
//! 64 kB and a count says nothing about memory. Oldest first, because the
//! premise is a live view of traffic rather than a recording - a premise worth
//! revisiting once frames are persisted on arrival, and recorded here so that
//! revisit is a decision rather than a discovery.

use std::collections::VecDeque;
use std::sync::Mutex;

/// Frames held for the pump before the oldest are shed.
pub const MAX_QUEUED_PACKETS: usize = 30_000;
/// ...and the byte budget beside it, for the reason above.
pub const MAX_QUEUED_BYTES: usize = 32 * 1024 * 1024;

/// One batch holds at most this many records...
pub const MAX_BATCH_RECORDS: usize = 512;
/// ...or this many bytes, whichever comes first.
pub const MAX_BATCH_BYTES: usize = 256 * 1024;

/// How long the pump waits when the queue is genuinely empty.
pub const BATCH_INTERVAL_MS: u64 = 10;

/// Why a drain stopped. **Not a count**: see the module note.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Drain {
    /// The queue ran dry. This is the only state the pump may sleep on.
    Drained,
    /// A bound was hit and frames remain. Go straight round again.
    More,
}

#[derive(Default)]
struct Inner {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
    dropped: u64,
}

/// Encoded records waiting to be batched.
pub struct FrameQueue {
    inner: Mutex<Inner>,
    max_frames: usize,
    max_bytes: usize,
}

impl FrameQueue {
    pub fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            max_frames,
            max_bytes,
        }
    }

    /// The default bounds.
    pub fn with_defaults() -> Self {
        Self::new(MAX_QUEUED_PACKETS, MAX_QUEUED_BYTES)
    }

    /// Called from a sniffer thread, once per frame.
    ///
    /// Records are encoded on the sniffer thread deliberately: it keeps the
    /// pump looking at finished bytes rather than at live driver buffers, and
    /// it is what lets the queue drop, reorder and re-batch records freely.
    pub fn push(&self, record: Vec<u8>) {
        self.push_counting(record);
    }

    /// `push`, answering how many of the oldest frames it shed to make room.
    ///
    /// Almost always 0. The sniffer uses the figure to keep the process-wide
    /// drop count that `shed_warning` reads - `agent.py`'s `_dropped_sends`,
    /// which is the process's and not the capture's, and which its sparse
    /// "the client is not keeping up" line is keyed to (agent.py:1767).
    pub fn push_counting(&self, record: Vec<u8>) -> u64 {
        let mut q = self.inner.lock().expect("frame queue mutex");
        q.bytes += record.len();
        q.frames.push_back(record);
        let mut shed = 0;
        while q.frames.len() > self.max_frames || q.bytes > self.max_bytes {
            match q.frames.pop_front() {
                Some(old) => {
                    q.bytes -= old.len();
                    q.dropped += 1;
                    shed += 1;
                }
                None => break,
            }
        }
        shed
    }

    /// Takes at most one batch, and says whether more is waiting.
    ///
    /// `more` is computed under the same lock as the pops, so it cannot be a
    /// stale answer about a queue a sniffer thread has since appended to.
    pub fn drain(&self) -> (Vec<Vec<u8>>, Drain) {
        let mut q = self.inner.lock().expect("frame queue mutex");
        let mut batch = Vec::new();
        let mut size = 0usize;
        while !q.frames.is_empty() && batch.len() < MAX_BATCH_RECORDS && size < MAX_BATCH_BYTES {
            let record = q.frames.pop_front().expect("non-empty");
            q.bytes -= record.len();
            size += record.len();
            batch.push(record);
        }
        let state = if q.frames.is_empty() {
            Drain::Drained
        } else {
            Drain::More
        };
        (batch, state)
    }

    /// Frames shed because the pump could not keep up. Reported as
    /// `capture_stats.droppedAgent`.
    pub fn dropped(&self) -> u64 {
        self.inner.lock().expect("frame queue mutex").dropped
    }

    /// `(frames, bytes)` currently held. The reading that tells "the pump is
    /// behind" from "the client is behind" when read beside the pipe's depth.
    pub fn depth(&self) -> (usize, usize) {
        let q = self.inner.lock().expect("frame queue mutex");
        (q.frames.len(), q.bytes)
    }

    /// Emptied on stop **without counting**: those frames were never going to
    /// be delivered and were not lost to pressure, so counting them would
    /// report a drop the user did not suffer.
    pub fn discard(&self) {
        let mut q = self.inner.lock().expect("frame queue mutex");
        q.frames.clear();
        q.bytes = 0;
    }
}

impl Default for FrameQueue {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// When a frame was captured, in epoch nanoseconds.
///
/// The driver's own stamp, except when the driver reported **none** - a stamp
/// of exactly zero - which `agent.py`'s `capture_time_ns` answers with the wall
/// clock (agent.py:715-716), and for its stated reason: "a frame with no time at
/// all would break the browser's relative-time column outright, which is a
/// worse outcome than one slightly-late timestamp." Only exact zero: a stamp
/// that is merely old is a fact about the frame, not a missing one.
pub fn capture_time_ns(ts_ns: u64, now_ns: impl FnOnce() -> u64) -> u64 {
    if ts_ns == 0 {
        now_ns()
    } else {
        ts_ns
    }
}

/// The wall clock in epoch nanoseconds, for `capture_time_ns`'s fallback.
pub fn wall_clock_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0)
}

/// The log line owed after the `count`th frame this process has captured.
///
/// `agent.py`'s `sniff_callback` (agent.py:1934-1943), whose counter is the
/// process's and never reset: the first frame says the capture works, and then
/// one line per 10,000 - "at 100 this single line was 82% of the log file",
/// which churned the rotation fast enough to discard real history.
pub fn captured_milestone(count: u64) -> Option<String> {
    if count == 1 {
        Some("first packet captured - capture is working".to_string())
    } else if count > 0 && count % 10_000 == 0 {
        Some(format!("{count} packets captured so far"))
    } else {
        None
    }
}

/// The process-lifetime counts `agent.py`'s two sparse log lines are keyed to:
/// `_captured_count` and `_dropped_sends`, neither of which is ever reset.
pub struct ProcessCounts {
    captured: std::sync::atomic::AtomicU64,
    shed: std::sync::atomic::AtomicU64,
}

impl Default for ProcessCounts {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcessCounts {
    pub const fn new() -> Self {
        Self {
            captured: std::sync::atomic::AtomicU64::new(0),
            shed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// One more frame captured: the milestone line owed, if any.
    pub fn captured(&self) -> Option<String> {
        use std::sync::atomic::Ordering;
        captured_milestone(self.captured.fetch_add(1, Ordering::Relaxed) + 1)
    }

    /// `n` more frames shed by one push: the warning owed, if any.
    ///
    /// Only the total **after** the push is tested, because that is what
    /// `agent.py` tests - `dropped` is read once, after its eviction loop - so a
    /// push that sheds two frames across a boundary says nothing for it, there
    /// as here.
    pub fn shed(&self, n: u64) -> Option<String> {
        use std::sync::atomic::Ordering;
        if n == 0 {
            return None;
        }
        shed_warning(self.shed.fetch_add(n, Ordering::Relaxed) + n)
    }
}

/// The warning owed when this process's shed total reaches `total`.
///
/// `agent.py`'s `queue_packet` (agent.py:1767-1776): at 1, 100, 1000 and every
/// 10,000 after, and nowhere else, because the drop path is the hot path when it
/// runs at all and a line per drop would recreate the flood one level up. The
/// full figure reaches the app every second in `capture_stats` regardless.
pub fn shed_warning(total: u64) -> Option<String> {
    if matches!(total, 1 | 100 | 1000) || (total > 0 && total % 10_000 == 0) {
        Some(format!(
            "dropped {total} packet(s): the client is not keeping up with this interface"
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod batch_bound_tests {
    /// **Two different constants share the name `MAX_BATCH_RECORDS`**, and only
    /// their ordering keeps a whole batch from being discarded in silence.
    ///
    /// This one (512) bounds a drain; `wire::MAX_BATCH_RECORDS` (0xFFFF) is
    /// what the format's u16 count can describe. `encode_batch` refuses above
    /// the latter, and `runtime.rs`'s pump answers that refusal with
    /// `else { continue }` - no counter, no message, not even the `eprintln!`
    /// the single-frame path gets. Roughly 512 already-sequenced frames would
    /// vanish per batch.
    ///
    /// It is unreachable today only because 512 < 65535. Nothing enforced that,
    /// and the shared name invites the edit that breaks it: raising this one in
    /// the belief that it IS the format limit. Now it cannot compile.
    #[test]
    fn the_drain_bound_stays_inside_what_the_format_can_describe() {
        assert!(
            super::MAX_BATCH_RECORDS <= crate::wire::MAX_BATCH_RECORDS,
            "a drain of {} records cannot be encoded into a batch bounded at {}",
            super::MAX_BATCH_RECORDS,
            crate::wire::MAX_BATCH_RECORDS,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// About the mean frame this repo measured on a real capture.
    const MEAN: usize = 1100;

    fn record(n: usize) -> Vec<u8> {
        vec![0u8; n]
    }

    #[test]
    fn a_batch_stops_on_the_record_bound_and_says_more_is_left() {
        let q = FrameQueue::with_defaults();
        for _ in 0..MAX_BATCH_RECORDS + 10 {
            q.push(record(60));
        }
        let (batch, state) = q.drain();
        assert_eq!(batch.len(), MAX_BATCH_RECORDS);
        assert_eq!(state, Drain::More);
        assert_eq!(q.depth().0, 10);
    }

    /// **The regression that cost 95% of delivery, at the size that hid it.**
    ///
    /// Small frames reach 512 records first, so every synthetic test passed.
    /// Real ones reach 256 kB at about 233 records - under the record bound -
    /// and the old pump read that as an empty queue.
    #[test]
    fn a_batch_of_real_sized_frames_stops_on_bytes_and_still_says_more() {
        let q = FrameQueue::with_defaults();
        for _ in 0..600 {
            q.push(record(MEAN));
        }
        let (batch, state) = q.drain();
        assert!(
            batch.len() < MAX_BATCH_RECORDS,
            "a real-sized batch is cut by the byte bound, below the record bound"
        );
        assert!(q.depth().0 > 0, "and the queue is still backed up");
        assert_eq!(
            state,
            Drain::More,
            "which the record count alone cannot tell you - this is the bug"
        );
    }

    #[test]
    fn draining_while_more_clears_the_queue_and_loses_nothing() {
        let q = FrameQueue::with_defaults();
        let total = 5_000;
        for _ in 0..total {
            q.push(record(MEAN));
        }
        let mut delivered = 0;
        loop {
            let (batch, state) = q.drain();
            delivered += batch.len();
            if state == Drain::Drained {
                break;
            }
        }
        assert_eq!(delivered, total);
        assert_eq!(q.depth(), (0, 0));
        assert_eq!(q.dropped(), 0, "nothing was shed: the queue was never over its bounds");
    }

    #[test]
    fn an_empty_queue_is_the_only_state_the_pump_may_sleep_on() {
        let q = FrameQueue::with_defaults();
        let (batch, state) = q.drain();
        assert!(batch.is_empty());
        assert_eq!(state, Drain::Drained);
    }

    #[test]
    fn the_queue_sheds_oldest_first_and_counts_it() {
        let q = FrameQueue::new(3, 1_000_000);
        for i in 0..5u8 {
            q.push(vec![i; 10]);
        }
        assert_eq!(q.depth().0, 3);
        assert_eq!(q.dropped(), 2);
        let (batch, _) = q.drain();
        assert_eq!(batch[0][0], 2, "the two oldest went, not the two newest");
    }

    #[test]
    fn the_byte_budget_bites_where_a_count_bound_cannot() {
        // Few frames, each enormous: the case that makes a count bound a
        // gigabyte of memory in a LocalSystem service.
        let q = FrameQueue::new(30_000, 100_000);
        for _ in 0..10 {
            q.push(record(64 * 1024));
        }
        assert!(q.dropped() > 0);
        assert!(q.depth().1 <= 100_000);
    }

    #[test]
    fn a_stop_empties_without_counting_a_drop() {
        let q = FrameQueue::with_defaults();
        for _ in 0..100 {
            q.push(record(MEAN));
        }
        q.discard();
        assert_eq!(q.depth(), (0, 0));
        assert_eq!(
            q.dropped(),
            0,
            "a stopped capture's queued frames were not lost to pressure"
        );
    }
}

/// What the capture driver is asked to hold before it starts dropping frames.
///
/// Npcap's default on Windows is 1 MB; dumpcap's `-B` default is 2 MiB on every
/// platform, so the base below is sixteen times what Wireshark asks for.
pub const KERNEL_BUFFER_BASE_BYTES: usize = 32 * 1024 * 1024;

/// **Npcap splits that buffer per processor, and a burst does not.**
///
/// From Npcap's own maintainer (nmap/npcap#30, mirrored in npcap.com's API
/// guide): the adapter buffer "is split into a number of independent segments
/// according to the number of processors on the system. When a packet is
/// received by the driver, it is put into the buffer segment corresponding to
/// the driver thread's current processor. If there is not enough room in that
/// segment, the packet is dropped."
///
/// So a flat 32 MB is 32/N MB of usable slack against a burst that lands on one
/// core - 2 MB on a sixteen-core machine, which is dumpcap's *default* and the
/// opposite of what asking for sixteen times it was meant to buy.
pub const KERNEL_BUFFER_PER_CORE_BYTES: usize = 4 * 1024 * 1024;

/// Capped because this is **non-paged kernel memory**. A 64-core machine must
/// not be asked for a gigabyte of it on the strength of a capture starting.
pub const KERNEL_BUFFER_MAX_BYTES: usize = 256 * 1024 * 1024;

/// How much to ask the driver for, given this machine's core count.
///
/// `None` - or a nonsensical zero - falls back to the flat base rather than to
/// one core. Not knowing how many processors a machine has is not knowing it
/// has one, and falling to one would ask for the least on the machine that
/// needs the most. The Python agent's `kernel_buffer_bytes` is the same
/// function, and `local-agent/test_protocol.py` holds it to the same shape.
pub fn kernel_buffer_bytes(cores: Option<usize>) -> usize {
    match cores {
        Some(n) if n >= 1 => (n * KERNEL_BUFFER_PER_CORE_BYTES)
            .clamp(KERNEL_BUFFER_BASE_BYTES, KERNEL_BUFFER_MAX_BYTES),
        _ => KERNEL_BUFFER_BASE_BYTES,
    }
}

/// This machine's core count, or `None` when the platform will not say.
pub fn available_cores() -> Option<usize> {
    std::thread::available_parallelism().ok().map(|n| n.get())
}

#[cfg(test)]
mod kernel_buffer_tests {
    use super::*;

    #[test]
    fn never_shrinks_below_the_base() {
        for cores in [1usize, 2, 4, 8, 16, 32, 64, 128] {
            assert!(kernel_buffer_bytes(Some(cores)) >= KERNEL_BUFFER_BASE_BYTES);
        }
    }

    #[test]
    fn grows_with_the_core_count() {
        assert!(kernel_buffer_bytes(Some(64)) > kernel_buffer_bytes(Some(8)));
    }

    #[test]
    fn is_capped_because_it_is_non_paged() {
        assert_eq!(kernel_buffer_bytes(Some(4096)), KERNEL_BUFFER_MAX_BYTES);
    }

    /// The `null != 0` rule. Falling to one core would ask for the least on the
    /// machine that needs the most.
    #[test]
    fn unknown_falls_back_to_the_base_not_to_one_core() {
        assert_eq!(kernel_buffer_bytes(None), KERNEL_BUFFER_BASE_BYTES);
        assert_eq!(kernel_buffer_bytes(Some(0)), KERNEL_BUFFER_BASE_BYTES);
    }

    /// dumpcap asks for 2 MiB by default, on every platform. Asserted so an
    /// edit that flattens this has to argue with the comparison.
    #[test]
    fn every_machine_beats_dumpcaps_default() {
        for cores in [Some(1usize), Some(8), Some(64), Some(0), None] {
            assert!(kernel_buffer_bytes(cores) > 2 * 1024 * 1024);
        }
    }
}

/// The sniffer's per-frame accounting, driven by the frames of a real capture.
///
/// **Real frames, not built ones**: every test here replays
/// `test/fixtures/*.pcap` through the same calls the runtime's sniffer makes -
/// `capture_time_ns`, `wire::encode_record`, `FrameQueue::push_counting` and
/// `ProcessCounts` - and holds the result to `agent.py`. The fixtures are
/// untracked (ADR 0004), so each test prints `SKIP` and passes when they are
/// absent rather than failing on a machine that never had them.
#[cfg(all(test, windows))]
mod frame_accounting_tests {
    use super::*;
    use crate::fixture;
    use crate::wire;

    /// agent.py:715-719 - the driver's stamp is carried exactly, and a stamp of
    /// zero is replaced by the wall clock rather than sent as 1970.
    #[test]
    fn a_frame_keeps_its_driver_stamp_and_a_missing_one_gets_the_wall_clock() {
        let Some(frames) = fixture::any_capture() else { return };
        let frame = &frames[0];
        assert!(frame.ts_ns > 1_000_000_000_000_000_000, "the fixture's own stamp is a real epoch time");

        let stamped = capture_time_ns(frame.ts_ns, || panic!("a stamped frame never asks the clock"));
        let record = wire::encode_record(0, 0, stamped, frame.wire_len as usize, &frame.data).unwrap();
        let decoded = wire::decode_batch(&wire::encode_batch(&[record]).unwrap()).unwrap();
        assert_eq!(decoded[0].ts_ns, frame.ts_ns);
        assert_eq!(decoded[0].data, frame.data, "the bytes go through untouched");

        // The same real frame, as a driver that stamped nothing would hand it
        // over.
        let before = wall_clock_ns();
        let unstamped = capture_time_ns(0, wall_clock_ns);
        let after = wall_clock_ns();
        assert!(before <= unstamped && unstamped <= after, "{before} <= {unstamped} <= {after}");
        let record = wire::encode_record(1, 0, unstamped, frame.wire_len as usize, &frame.data).unwrap();
        let decoded = wire::decode_batch(&wire::encode_batch(&[record]).unwrap()).unwrap();
        assert_eq!(decoded[0].ts_ns, unstamped);
        assert_eq!(decoded[0].orig_len, frame.wire_len);
    }

    /// agent.py:1934-1943 and 1767-1776, replayed: a whole real capture pushed
    /// into a queue nobody drains, the way a stalled pump would leave it.
    ///
    /// The log owes exactly: the first frame, every 10,000th, and a shed warning
    /// at 1, 100, 1000 and 10,000 - and nothing else, however many frames go
    /// through. The byte budget is set wide so the count bound is the one that
    /// bites and every push sheds exactly one frame, which is what makes the
    /// crossings exact rather than dependent on frame sizes.
    #[test]
    fn a_real_capture_owes_the_log_its_first_frame_and_sparse_milestones() {
        let Some(frames) = fixture::any_capture() else { return };
        let counts = ProcessCounts::new();
        let queue = FrameQueue::new(1_000, usize::MAX / 2);
        let (mut milestones, mut warnings) = (Vec::new(), Vec::new());

        for (n, frame) in frames.iter().enumerate() {
            if let Some(line) = counts.captured() {
                milestones.push((n + 1, line));
            }
            let ts = capture_time_ns(frame.ts_ns, wall_clock_ns);
            let record = wire::encode_record(n as u32, 0, ts, frame.wire_len as usize, &frame.data)
                .expect("a captured frame encodes");
            if let Some(line) = counts.shed(queue.push_counting(record)) {
                warnings.push(line);
            }
        }

        assert_eq!(milestones[0], (1, "first packet captured - capture is working".to_string()));
        let tens: Vec<usize> = milestones[1..].iter().map(|(n, _)| *n).collect();
        let expected: Vec<usize> = (1..=frames.len() / 10_000).map(|k| k * 10_000).collect();
        assert_eq!(tens, expected, "one line per 10,000 frames of a {}-frame capture", frames.len());
        if let Some((_, line)) = milestones.get(1) {
            assert_eq!(line, "10000 packets captured so far");
        }

        let shed = frames.len().saturating_sub(1_000) as u64;
        assert_eq!(queue.dropped(), shed, "every frame past the bound was shed, oldest first");
        let expected: Vec<String> = [1u64, 100, 1000, 10_000, 20_000, 30_000]
            .into_iter()
            .filter(|n| *n <= shed)
            .map(|n| format!("dropped {n} packet(s): the client is not keeping up with this interface"))
            .collect();
        assert_eq!(warnings, expected);
    }
}
