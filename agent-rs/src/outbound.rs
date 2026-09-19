//! Frames waiting for the writer thread, bounded by count AND bytes.
//!
//! The port of `local-agent/pipe_server.py`'s `_Outbound`, which replaced a
//! `queue.Queue` that could only express the count bound. Three things were
//! wrong there and each hid the others; all three are decisions here rather
//! than repairs.
//!
//! **Full means shed the oldest, not drop the client.** Closing on a full queue
//! sounds like making a slow reader pay for itself. It is not: the client
//! leaving is what stops the capture, so the protection against a slow reader
//! terminated the thing it was protecting - and took with it the only
//! connection that could have reported the loss.
//!
//! **Bounded by bytes as well as frames.** The items are whole packet batches of
//! up to 256 kB, so a 4,096-frame bound is up to a gigabyte held inside a
//! LocalSystem service. The sniffer queue on the other end of the pump records
//! adding a byte budget for exactly this reason, and the pipe cited it while
//! repeating the mistake.
//!
//! **Counted.** Frames vanished here with no counter, no per-drop log line and
//! nothing in `capture_stats`, so the app's loss figure was silently short.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};

/// What a writer thread was handed.
pub enum Item {
    /// The bytes, and **how many captured packets they carry**. See `push`.
    Frame(Vec<u8>, u64),
    /// Wakes the writer so it can exit. Never shed: the thread is blocked
    /// waiting for it, and dropping it would leave that thread parked until the
    /// handle closed underneath it.
    Shutdown,
}

struct State {
    items: VecDeque<Item>,
    bytes: usize,
    dropped: u64,
    closed: bool,
}

pub struct Outbound {
    state: Mutex<State>,
    ready: Condvar,
    max_frames: usize,
    max_bytes: usize,
}

impl Outbound {
    pub fn new(max_frames: usize, max_bytes: usize) -> Self {
        Self {
            state: Mutex::new(State {
                items: VecDeque::new(),
                bytes: 0,
                dropped: 0,
                closed: false,
            }),
            ready: Condvar::new(),
            max_frames,
            max_bytes,
        }
    }

    /// Queues a frame, shedding the oldest if either bound is exceeded.
    ///
    /// `records` is **how many captured packets this frame carries** - up to
    /// 512 for a batch, none for a control message.
    ///
    /// **The counter is in packets and counting items was a real bug.** The
    /// app adds `droppedPipe` straight into a frames-lost total beside
    /// `droppedAgent` and `droppedKernel`, which are packets, so a shed batch
    /// of twelve frames reported as one understated the loss by the batch size.
    /// Caught by asserting conservation end to end rather than by reading it:
    /// 37,793 shed batches accounted for 398,000 missing packets.
    ///
    /// `Err` when the connection is closed, so a caller learns its frame went
    /// nowhere. The Python original returned silently here while `send` tested
    /// a *different* flag, which meant every send after the writer gave up
    /// reported success and discarded its frame.
    pub fn push(&self, frame: Vec<u8>, records: u64) -> Result<(), Closed> {
        let mut s = self.state.lock().expect("outbound mutex");
        if s.closed {
            return Err(Closed);
        }
        s.bytes += frame.len();
        s.items.push_back(Item::Frame(frame, records));
        // `> 1` so the frame just queued is never the one shed: a queue that
        // evicted its own newest arrival would deliver nothing at all once a
        // single frame exceeded the budget.
        while (s.items.len() > self.max_frames || s.bytes > self.max_bytes) && s.items.len() > 1 {
            match s.items.front() {
                Some(Item::Shutdown) | None => break,
                Some(Item::Frame(..)) => {}
            }
            if let Some(Item::Frame(old, records)) = s.items.pop_front() {
                s.bytes -= old.len();
                // In packets, not in items. See the note on `push`.
                s.dropped += records;
            }
        }
        self.ready.notify_one();
        Ok(())
    }

    /// Blocks until there is something to write.
    pub fn pop(&self) -> Item {
        let mut s = self.state.lock().expect("outbound mutex");
        loop {
            if let Some(item) = s.items.pop_front() {
                if let Item::Frame(f, _) = &item {
                    s.bytes -= f.len();
                }
                return item;
            }
            s = self.ready.wait(s).expect("outbound condvar");
        }
    }

    /// Marks the connection closed and wakes the writer.
    pub fn shutdown(&self) {
        let mut s = self.state.lock().expect("outbound mutex");
        s.closed = true;
        s.items.push_back(Item::Shutdown);
        self.ready.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().expect("outbound mutex").closed
    }

    /// Frames shed because the reader could not keep up. Reported to the app as
    /// `capture_stats.droppedPipe`.
    pub fn dropped(&self) -> u64 {
        self.state.lock().expect("outbound mutex").dropped
    }

    /// Diagnostics: the reading that tells "the pump is behind" from "the
    /// client is behind", which look identical from outside and want opposite
    /// fixes.
    pub fn depth(&self) -> (usize, usize) {
        let s = self.state.lock().expect("outbound mutex");
        (s.items.len(), s.bytes)
    }
}

#[derive(Debug, PartialEq)]
pub struct Closed;

impl core::fmt::Display for Closed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "the pipe client has gone")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(n: usize, byte: u8) -> Vec<u8> {
        vec![byte; n]
    }

    #[test]
    fn sheds_the_oldest_and_counts_it() {
        let q = Outbound::new(3, 10_000);
        for i in 0..3 {
            q.push(frame(10, i), 12).unwrap();
        }
        assert_eq!(q.depth().0, 3);
        assert_eq!(q.dropped(), 0);
        q.push(frame(10, 9), 12).unwrap();
        assert_eq!(q.depth().0, 3, "past the bound the queue does not grow");
        // **Packets, not items.** A shed batch loses every packet in it, and
        // the app sums this with counters that are in packets.
        assert_eq!(q.dropped(), 12);
        match q.pop() {
            Item::Frame(f, _) => assert_eq!(f[0], 1, "the oldest is the one shed"),
            Item::Shutdown => panic!("not a shutdown"),
        }
    }

    #[test]
    fn a_byte_budget_bites_before_a_generous_count_bound() {
        // The case a count bound cannot express: few items, each enormous.
        let q = Outbound::new(4096, 1000);
        for _ in 0..5 {
            q.push(frame(400, 0), 7).unwrap();
        }
        assert!(q.dropped() > 0);
        assert_eq!(q.dropped() % 7, 0, "every packet in every shed batch is counted");
        assert!(q.depth().1 <= 1000, "the queue stays inside its budget");
    }

    #[test]
    fn a_frame_larger_than_the_whole_budget_is_still_delivered() {
        // A queue that evicts its own newest arrival delivers nothing at all.
        let q = Outbound::new(4096, 100);
        q.push(frame(500, 7), 3).unwrap();
        assert_eq!(q.depth().0, 1);
    }

    #[test]
    fn shedding_a_control_message_loses_no_packets() {
        // Zero is the honest weight for a message that carries no capture, and
        // it is what keeps a busy control channel from inflating the figure.
        let q = Outbound::new(1, 10_000);
        q.push(b"{}".to_vec(), 0).unwrap();
        q.push(b"{}".to_vec(), 0).unwrap();
        assert_eq!(q.dropped(), 0);
    }

    #[test]
    fn the_stop_signal_is_never_shed() {
        let q = Outbound::new(1, 10);
        q.shutdown();
        // Closed, so pushes are refused rather than shedding the signal.
        assert_eq!(q.push(frame(50, 0), 1), Err(Closed));
        assert!(matches!(q.pop(), Item::Shutdown));
    }

    #[test]
    fn a_closed_queue_refuses_rather_than_swallowing() {
        let q = Outbound::new(8, 1000);
        q.push(frame(4, 0), 1).unwrap();
        q.shutdown();
        assert_eq!(
            q.push(frame(4, 0), 1),
            Err(Closed),
            "a send after the writer gave up must fail, not report success"
        );
    }
}

impl std::error::Error for Closed {}
