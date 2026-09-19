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
        let mut q = self.inner.lock().expect("frame queue mutex");
        q.bytes += record.len();
        q.frames.push_back(record);
        while q.frames.len() > self.max_frames || q.bytes > self.max_bytes {
            match q.frames.pop_front() {
                Some(old) => {
                    q.bytes -= old.len();
                    q.dropped += 1;
                }
                None => break,
            }
        }
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
