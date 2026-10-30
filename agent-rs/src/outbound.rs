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
//!
//! **Only a packet batch is sheddable.** A control message - `capture_boundary`,
//! `capture_stopped`, an error - carries no packets, so shedding one lost
//! nothing the counter could see and the app was told nothing. Shedding takes
//! the oldest *sheddable* item wherever it sits. Control messages are held
//! instead against their own byte cap: a client that lets that much queue is
//! not reading at all, and its connection ends (see `push`).

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

/// What the queue holds: an `Item`, and whether the frame may be shed.
enum Queued {
    Frame { bytes: Vec<u8>, records: u64, sheddable: bool },
    Shutdown,
}

struct State {
    items: VecDeque<Queued>,
    bytes: usize,
    /// Bytes of unsheddable frames queued - what the control cap bounds.
    control_bytes: usize,
    dropped: u64,
    closed: bool,
    /// The control cap ended this connection, as opposed to a normal close.
    overflowed: bool,
}

pub struct Outbound {
    state: Mutex<State>,
    ready: Condvar,
    max_frames: usize,
    max_bytes: usize,
    max_control_bytes: usize,
}

impl Outbound {
    pub fn new(max_frames: usize, max_bytes: usize, max_control_bytes: usize) -> Self {
        Self {
            state: Mutex::new(State {
                items: VecDeque::new(),
                bytes: 0,
                control_bytes: 0,
                dropped: 0,
                closed: false,
                overflowed: false,
            }),
            ready: Condvar::new(),
            max_frames,
            max_bytes,
            max_control_bytes,
        }
    }

    /// Queues a frame, shedding the oldest *sheddable* one if either bound is
    /// exceeded.
    ///
    /// `sheddable` is true for a packet batch and false for a control message.
    /// An unsheddable frame is never removed to make room. If the unsheddable
    /// bytes queued pass `max_control_bytes` the client is not reading at all:
    /// the queue is emptied, `Shutdown` is queued, it is marked closed and this
    /// returns `Err(Closed)`, so the connection ends through the normal path.
    /// The batches discarded with it are counted.
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
    pub fn push(&self, frame: Vec<u8>, records: u64, sheddable: bool) -> Result<(), Closed> {
        let mut s = self.state.lock().expect("outbound mutex");
        if s.closed {
            return Err(Closed);
        }
        if !sheddable {
            s.control_bytes += frame.len();
            if s.control_bytes > self.max_control_bytes {
                // Nothing here will be read. Whatever batches were waiting are
                // lost with the connection, and counted like any other loss.
                let mut lost = 0;
                for queued in s.items.drain(..) {
                    if let Queued::Frame { records, sheddable: true, .. } = queued {
                        lost += records;
                    }
                }
                s.dropped += lost;
                s.bytes = 0;
                s.control_bytes = 0;
                s.closed = true;
                s.overflowed = true;
                s.items.push_back(Queued::Shutdown);
                self.ready.notify_all();
                return Err(Closed);
            }
        }
        s.bytes += frame.len();
        s.items.push_back(Queued::Frame { bytes: frame, records, sheddable });
        // The frame just queued is never the one shed (`take(last)`): a queue
        // that evicted its own newest arrival would deliver nothing at all once
        // a single frame exceeded the budget. Unsheddable items and `Shutdown`
        // are skipped, so a control message is never what makes room.
        while s.items.len() > self.max_frames || s.bytes > self.max_bytes {
            let last = s.items.len() - 1;
            let victim = s
                .items
                .iter()
                .take(last)
                .position(|q| matches!(q, Queued::Frame { sheddable: true, .. }));
            let Some(at) = victim else { break };
            if let Some(Queued::Frame { bytes, records, .. }) = s.items.remove(at) {
                s.bytes -= bytes.len();
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
            if let Some(queued) = s.items.pop_front() {
                return match queued {
                    Queued::Frame { bytes, records, sheddable } => {
                        s.bytes -= bytes.len();
                        if !sheddable {
                            s.control_bytes -= bytes.len();
                        }
                        Item::Frame(bytes, records)
                    }
                    Queued::Shutdown => Item::Shutdown,
                };
            }
            s = self.ready.wait(s).expect("outbound condvar");
        }
    }

    /// Marks the connection closed and wakes the writer.
    pub fn shutdown(&self) {
        let mut s = self.state.lock().expect("outbound mutex");
        s.closed = true;
        s.items.push_back(Queued::Shutdown);
        self.ready.notify_all();
    }

    pub fn is_closed(&self) -> bool {
        self.state.lock().expect("outbound mutex").closed
    }

    /// Whether the control cap, rather than a normal close, ended the queue.
    /// The writer reads it to end the whole session, not only itself.
    pub fn overflowed(&self) -> bool {
        self.state.lock().expect("outbound mutex").overflowed
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

    /// Everything queued, in order, up to a `Shutdown` if there is one.
    fn drain(q: &Outbound) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while q.depth().0 > 0 {
            match q.pop() {
                Item::Frame(f, _) => out.push(f),
                Item::Shutdown => break,
            }
        }
        out
    }

    #[test]
    fn sheds_the_oldest_and_counts_it() {
        let q = Outbound::new(3, 10_000, usize::MAX);
        for i in 0..3 {
            q.push(frame(10, i), 12, true).unwrap();
        }
        assert_eq!(q.depth().0, 3);
        assert_eq!(q.dropped(), 0);
        q.push(frame(10, 9), 12, true).unwrap();
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
        let q = Outbound::new(4096, 1000, usize::MAX);
        for _ in 0..5 {
            q.push(frame(400, 0), 7, true).unwrap();
        }
        assert!(q.dropped() > 0);
        assert_eq!(q.dropped() % 7, 0, "every packet in every shed batch is counted");
        assert!(q.depth().1 <= 1000, "the queue stays inside its budget");
    }

    #[test]
    fn a_frame_larger_than_the_whole_budget_is_still_delivered() {
        // A queue that evicts its own newest arrival delivers nothing at all.
        let q = Outbound::new(4096, 100, usize::MAX);
        q.push(frame(500, 7), 3, true).unwrap();
        assert_eq!(q.depth().0, 1);
    }

    /// **A control message is never shed.** It used to be the oldest item that
    /// went, of any kind, so a `capture_boundary`, a `capture_stopped` or an
    /// error could vanish under backpressure - uncounted, because a control
    /// message carries `records = 0`.
    #[test]
    fn a_control_message_is_never_shed() {
        let q = Outbound::new(3, usize::MAX, usize::MAX);
        q.push(vec![1], 10, true).unwrap();
        q.push(b"ctl".to_vec(), 0, false).unwrap();
        q.push(vec![2], 10, true).unwrap();
        q.push(vec![3], 10, true).unwrap(); // over by one: [1] goes, "ctl" stays
        assert_eq!(drain(&q), vec![b"ctl".to_vec(), vec![2], vec![3]]);
        assert_eq!(q.dropped(), 10);
    }

    /// The case the shedding rule exists for: the control message is the OLDEST
    /// item, which is what the old front-popping loop removed first.
    #[test]
    fn the_oldest_item_being_a_control_message_does_not_make_it_the_one_shed() {
        let q = Outbound::new(3, usize::MAX, usize::MAX);
        q.push(b"ctl".to_vec(), 0, false).unwrap();
        for i in 1..=3u8 {
            q.push(vec![i], 4, true).unwrap();
        }
        assert_eq!(drain(&q), vec![b"ctl".to_vec(), vec![2], vec![3]]);
        assert_eq!(q.dropped(), 4);
    }

    /// A control message queued behind a full budget of batches arrives, in
    /// order, after the batches ahead of it that survived.
    #[test]
    fn a_control_message_behind_a_full_budget_arrives_in_order() {
        let q = Outbound::new(3, usize::MAX, usize::MAX);
        for i in 0..3u8 {
            q.push(vec![i], 5, true).unwrap();
        }
        q.push(b"ctl".to_vec(), 0, false).unwrap();
        q.push(b"ctl2".to_vec(), 0, false).unwrap();
        assert_eq!(drain(&q), vec![vec![2], b"ctl".to_vec(), b"ctl2".to_vec()]);
        assert_eq!(q.dropped(), 10, "two batches went to make room, in packets");
    }

    /// The control messages themselves are not bounded by the frame budget, so
    /// a client that reads nothing at all is cut off by their own byte cap.
    #[test]
    fn a_control_backlog_past_its_cap_ends_the_connection() {
        let q = Outbound::new(4096, usize::MAX, 8);
        q.push(vec![0; 6], 0, false).unwrap();
        assert!(q.push(vec![0; 6], 0, false).is_err());
        assert!(q.overflowed());
        assert!(q.is_closed());
        assert!(matches!(q.pop(), Item::Shutdown));
        assert_eq!(q.push(vec![0; 1], 0, false), Err(Closed), "and nothing more is taken");
    }

    #[test]
    fn a_control_cap_overflow_counts_the_batches_it_discards() {
        let q = Outbound::new(4096, usize::MAX, 4);
        q.push(vec![9; 10], 7, true).unwrap();
        assert!(q.push(vec![0; 6], 0, false).is_err());
        assert_eq!(q.dropped(), 7, "conservation: what was queued and never sent is counted");
    }

    #[test]
    fn a_control_message_leaving_the_queue_frees_its_cap() {
        let q = Outbound::new(4096, usize::MAX, 8);
        for _ in 0..10 {
            q.push(vec![0; 6], 0, false).unwrap();
            assert!(matches!(q.pop(), Item::Frame(..)));
        }
        assert!(!q.overflowed(), "a client that keeps reading never trips the cap");
    }

    #[test]
    fn the_stop_signal_is_never_shed() {
        let q = Outbound::new(1, 10, usize::MAX);
        q.shutdown();
        // Closed, so pushes are refused rather than shedding the signal.
        assert_eq!(q.push(frame(50, 0), 1, true), Err(Closed));
        assert!(matches!(q.pop(), Item::Shutdown));
    }

    #[test]
    fn a_closed_queue_refuses_rather_than_swallowing() {
        let q = Outbound::new(8, 1000, usize::MAX);
        q.push(frame(4, 0), 1, true).unwrap();
        q.shutdown();
        assert_eq!(
            q.push(frame(4, 0), 1, true),
            Err(Closed),
            "a send after the writer gave up must fail, not report success"
        );
    }
}

impl std::error::Error for Closed {}
