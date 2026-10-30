//! The agent, as something that can be started and stopped rather than run.
//!
//! `examples/agent_serve.rs` proved every piece of this against the app's own
//! client, and it serves **one** connection and returns. That is the right shape
//! for a harness and the wrong one for a service: a real agent accepts several
//! clients, arbitrates a capture between them, and has to come back from a
//! client going away without losing the pipe name.
//!
//! ## What is shared and what is per connection
//!
//! Per connection: a `Connection` with its own outbound queue, its own writer
//! thread, and a read loop on its own pipe instance. Shared: the interface list,
//! the capture session, and who owns it.
//!
//! **Packets go to the owner and to nobody else.** That is the Python agent's
//! `_send_to_owner` rule and it is not an optimisation - a second window
//! watching the same capture would otherwise receive frames it never asked for
//! and cannot account for, and the sequence numbers it saw would not be its own.
//! Control messages broadcast; frames do not.
//!
//! ## Why a thread per pipe instance
//!
//! A named pipe server hands out one instance per client and the instances are
//! independent handles. `MAX_INSTANCES` of them are created up front, each with
//! a thread that accepts, serves, and goes back to accepting - so a client
//! disconnecting frees its instance rather than the server. Threads rather than
//! an async runtime because the whole agent is four long-lived loops, and the
//! only reason the Python one needed an event loop was that it had a WebSocket
//! library attached to it.

#![cfg(windows)]

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::adapters;
use crate::agent_log;
use crate::capture_file::{self, Admit, FileEvent, FileInterface, FileReport, FrameJob, Sequencer, StopReason, Writer, WriterSetup};
use crate::control::{self, Control, Driver, Env, Lazy, Level, RestartSupport};
use crate::framing::{FRAME_BINARY, FRAME_JSON};
use crate::host_feeds::{self, HostFeeds, Outlet};
use crate::npcap_access;
use crate::npcap::{self, Capture, Npcap, OpenOptions, Read};
use crate::pcapng;
use crate::pipe::{self, ClientToken, Connection, PipeInstance};
use crate::protocol::{self, CaptureOptions, CaptureState, Command, Interface, InterfaceStats};
use crate::restart;
use crate::session::{
    available_cores, capture_time_ns, kernel_buffer_bytes, wall_clock_ns, Drain, FrameQueue,
    ProcessCounts, BATCH_INTERVAL_MS,
};
use crate::sockets;
use crate::wire;

/// How often the idle watchdog looks. Matches the Python agent's
/// `ORPHAN_CHECK_SECONDS`, and for the same reason: polling is the right shape
/// for a guarantee that must not depend on an event arriving.
pub const IDLE_CHECK: Duration = Duration::from_secs(2);

/// Consecutive idle ticks before the agent stops itself.
///
/// Two rather than one, to absorb `AgentPipeLink.recycle()` - the app closes the
/// pipe and reopens it immediately after a driver install, and a tick landing in
/// that gap would stop the service the app is mid-way through reconnecting to.
/// ADR 0035.
pub const IDLE_EXIT_TICKS: u32 = 2;

/// How long to wait for a first client before exiting on idleness.
///
/// The service is demand-start: the app asks the SCM for it and connects a
/// moment later. Stopping in that window is a service that kills itself before
/// the thing that started it arrives.
pub const FIRST_CLIENT_GRACE: Duration = Duration::from_secs(30);

/// How often `capture_stats` goes out while capturing.
pub const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// How often `interface_stats` goes out to whoever subscribed - 500 ms, from
/// `host_feeds`, which owns that subscription's whole lifecycle.
///
/// **Deliberately not `STATS_INTERVAL`.** That one is 1 s and only ticks while
/// a capture is running; these rates have to move on an idle adapter, which is
/// the entire point of the panel.
pub const INTERFACE_STATS_INTERVAL: Duration = host_feeds::INTERFACE_STATS_INTERVAL;

/// How often the socket table is re-read for whoever subscribed.
///
/// One second, matching `local-agent/agent.py`'s
/// `SOCKET_TABLE_INTERVAL_SECONDS`. The table is ~890 sockets and changes by
/// one or two a second, so this is the rate at which a delta is worth sending
/// at all - and reading it costs a few milliseconds, which is why it has a
/// thread rather than sharing one with anything on a shorter tick.
pub const SOCKET_TABLE_INTERVAL: Duration = Duration::from_secs(1);

/// How often new log lines are forwarded to whoever subscribed.
///
/// A quarter second: a log viewer wants to feel live, and the cost of a tick
/// with nothing to send is one lock and one comparison.
pub const LOG_FORWARD_INTERVAL: Duration = Duration::from_millis(250);

/// How long a stop waits for the pipe threads before leaving them to the
/// process exit.
///
/// A bound rather than a join, because a join is what used to make an SCM stop
/// with Inwire open never finish: the thread serving a connected client sat in
/// a read for a command that might not come for hours. `pipe::disconnect` ends
/// those sessions now, and this is the backstop if one still does not - the
/// service must reach `STOPPED` whatever a client is doing.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);

/// Frames captured and frames shed, over the life of the process - the counts
/// `agent.py`'s sparse log lines are keyed to (`_captured_count` and
/// `_dropped_sends`, agent.py:1918 and 1075, neither of which is ever reset).
static COUNTS: ProcessCounts = ProcessCounts::new();

/// Capture threads alive in this process - every sniffer and every pump.
///
/// It is how a test sees the one thing a dead capture must do that nothing on
/// the wire shows: that its threads are gone. A capture taken out of the
/// lifecycle but never halted keeps a sniffer reading an adapter, promiscuous,
/// for the life of the process, while every client is told it is idle
/// (`runtime_tests.rs`).
static CAPTURE_THREADS: AtomicUsize = AtomicUsize::new(0);

/// Counts one capture thread for as long as it lives. Taken before the spawn and
/// moved in, so a thread is counted from the moment it can exist.
struct Alive;

impl Alive {
    fn new() -> Self {
        CAPTURE_THREADS.fetch_add(1, Ordering::SeqCst);
        Alive
    }
}

impl Drop for Alive {
    fn drop(&mut self) {
        CAPTURE_THREADS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Where the runtime gets Npcap, its device list and its capture handles.
///
/// `Hardware::NPCAP` everywhere but the tests, which replace one part at a
/// time: the load, to stand in for a machine where Npcap arrives after the
/// agent started; the list and the open, to drive the real sniffer, pump and
/// reaper with the real frames of a fixture capture, read through Npcap's own
/// `pcap_open_offline`.
#[derive(Clone, Copy)]
struct Hardware {
    load: fn() -> io::Result<Npcap>,
    devices: fn(&Npcap) -> io::Result<Vec<Interface>>,
    open: fn(&'static Npcap, &Interface, &CaptureOptions) -> io::Result<Capture<'static>>,
}

impl Hardware {
    const NPCAP: Hardware = Hardware {
        load: Npcap::load,
        devices: read_interfaces,
        open: open_adapter,
    };
}

/// Opens an adapter for capture, promiscuous - what every real capture does -
/// at the snaplen its `start_capture` asked for. The filter is applied by the
/// caller, to whichever handle this returns, so it is the same code on a live
/// adapter and on the fixture a test opens in its place.
fn open_adapter(
    npcap: &'static Npcap,
    iface: &Interface,
    options: &CaptureOptions,
) -> io::Result<Capture<'static>> {
    npcap.open(&iface.name, OpenOptions { promiscuous: true, snaplen: options.snaplen })
}

/// Signals a stop from any thread, and lets one thread wait for it.
///
/// A `Condvar` rather than a channel because there are several senders - the
/// SCM's control handler, the idle watchdog, a fatal capture error - and one
/// waiter, and because `wait_timeout` is what lets the waiter also be the thing
/// that gives up.
#[derive(Default)]
pub struct Shutdown {
    flag: Mutex<Option<String>>,
    signal: Condvar,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Asks for a stop. The **first** reason wins: a stop that cascades into
    /// other failures should be reported as what started it.
    pub fn request(&self, reason: &str) {
        let mut held = self.flag.lock().unwrap();
        if held.is_none() {
            *held = Some(reason.to_string());
            self.signal.notify_all();
        }
    }

    pub fn requested(&self) -> bool {
        self.flag.lock().unwrap().is_some()
    }

    /// Blocks until a stop is asked for, and answers with the reason.
    pub fn wait(&self) -> String {
        let mut held = self.flag.lock().unwrap();
        while held.is_none() {
            held = self.signal.wait(held).unwrap();
        }
        held.clone().unwrap_or_else(|| "stopped".into())
    }
}

/// Everything shared between connections.
struct Shared {
    /// Npcap's `wpcap.dll`, loaded by the first attempt that succeeds and
    /// retried on every connection until one does.
    ///
    /// **This was `Npcap::load()?` at start-up**, so a machine without Npcap
    /// had no agent at all: the service exited, the pipe went unanswered, and
    /// the app read that as the agent being broken rather than the driver being
    /// absent - on exactly the machine whose Update Center exists to install
    /// it. `agent.py` serves the pipe with an empty interface list instead
    /// (agent.py:2024-2028, 2349-2360), and so does this. And because the load
    /// is retried, Npcap installed *under* a running service is found by the
    /// next connection - which is what the Update Center's pipe recycle is -
    /// with nobody restarting the service.
    npcap: Lazy<Npcap>,
    /// How Npcap is loaded, listed and opened - see `Hardware`.
    hardware: Hardware,
    interfaces: Mutex<Vec<Interface>>,
    /// Connected clients by id, so the pump can find the owner's.
    clients: Mutex<HashMap<String, Arc<Connection>>>,
    /// Who owns the capture, what it reads from, and what every client is told
    /// when that changes - decided in `control.rs`, where each rule is tested
    /// against the `agent.py` lines it ports. This file supplies the clients
    /// and the threads.
    control: Control<CaptureHandles>,
    /// Whether `restart_agent` can be honoured, read from the SCM at start-up.
    restart: RestartSupport,
    /// `interface_stats` and `adapter_config`: who subscribed, and the loops
    /// that serve them - see `host_feeds.rs`, which holds both to `agent.py`'s
    /// lifecycle. Facts about the machine, not about anybody's capture, so they
    /// go to every subscriber rather than to the owner alone.
    host: Arc<HostFeeds>,
    /// Clients that asked for `socket_table`, by id.
    ///
    /// Apart from the rate feed rather than merged with it: the two have
    /// different cadences and different costs, and a client can want process
    /// attribution without the Interfaces panel open or the other way round.
    socket_watchers: Mutex<std::collections::HashSet<String>>,
    /// The shared reading the per-second deltas are differenced against.
    ///
    /// One for the whole agent, because the table is a fact about the machine
    /// rather than about anybody's subscription - a second tracker would read
    /// the same table again and difference it against a different previous.
    /// A client that subscribes gets a full snapshot of its own from a
    /// throwaway tracker, so it never needs this one to restart.
    sockets: Mutex<sockets::SocketTracker>,
    /// Clients that asked for `log`, and the log sequence each has been sent
    /// up to.
    ///
    /// A position per client rather than one shared cursor: a second window
    /// subscribing must not make the first one skip the lines the newcomer got
    /// in its backlog, and a client that subscribes an hour late starts from
    /// its own backlog rather than from wherever the other one had reached.
    log_watchers: Mutex<HashMap<String, u64>>,
    /// Each client's capture root, from its `set_capture_root` - sent by the
    /// app's main process, which knows where its captures live. A
    /// `start_capture` names only a capture id under it (ADR 0052).
    capture_roots: Mutex<HashMap<String, String>>,
    /// A `start_capture`'s file output, between the read loop that resolved it
    /// - and took the client's identity to write it as - and the `start` that
    /// uses it. Whatever the start did not take is discarded after it.
    pending_output: Mutex<HashMap<String, PendingOutput>>,
    shutdown: Arc<Shutdown>,
}

/// Where a capture's files go, and who they are written as.
struct PendingOutput {
    dir: std::path::PathBuf,
    /// `None` only in the capture harness, which has no pipe to take one from
    /// and writes as itself.
    token: Option<ClientToken>,
}

/// A running capture's own pcapng (ADR 0052): the sequencer every frame passes
/// through, and the thread that writes what it decides.
struct Output {
    /// Held while a frame takes its sequence number and is handed to the
    /// writer, so the file's order is the sequence's.
    sequencer: Mutex<Sequencer>,
    writer: Writer,
    /// Who hears about the files - the capture's owner, which a second window
    /// can become.
    owner: Arc<Mutex<String>>,
    autostop_seconds: Option<u64>,
    started: Instant,
    /// Whether the capture's end has already been asked for, so a limit met by
    /// several threads at once ends it once.
    ending: AtomicBool,
}

/// One selected adapter, inside a running capture.
///
/// **Per adapter rather than per capture**, which is the shape the wire format
/// has always had: `capture_stats` carries an *array* of these and the record's
/// `iface` field names one. Whether the adapter is still reading is
/// `control.rs`'s to know - it is the one place that decides when the last of
/// them has gone, and what happens then.
struct CaptureInterface {
    /// This adapter's index in the interface list, which is what goes in every
    /// record's `iface` field and in its `capture_stats` entry.
    iface: usize,
    /// Frames the driver handed to *this* adapter's sniffer.
    ///
    /// Per adapter, where `seq` is per capture - the same split
    /// `local-agent/agent.py`'s `CaptureCounters` makes, and for the same
    /// reason: the sequence number orders the capture as a whole, while
    /// "received" is what the app shows per row of the Interfaces list.
    received: Arc<AtomicU64>,
    /// `pcap_stats` for this adapter's handle: (recv, dropped), read by its
    /// sniffer when the pump asks.
    kernel: Arc<KernelStats>,
}

/// How long the pump waits for the sniffers to answer a `pcap_stats` request.
///
/// A sniffer answers between two reads: microseconds later on a busy adapter,
/// and at most one `to_ms` (100 ms) later on a silent one, where it sits in
/// `pcap_next_ex`'s timeout. Past this the figures go out with the last reading
/// rather than holding `capture_stats` back.
pub const KERNEL_ANSWER_WAIT: Duration = Duration::from_millis(250);

/// The driver's counters for one adapter, read on the thread that owns its
/// handle, **when the pump asks** rather than on a timer of the sniffer's own.
///
/// **This was a timer, and the figure it produced lagged.** The sniffer took a
/// `pcap_stats` every half second and the pump sent whatever the last one was,
/// beside a `received` it read live - so `kernelReceived` described a moment up
/// to a tick before `received` did, and on a real Ethernet capture at ~12,000
/// frames a second it trailed by a whole second's worth: 16,687 against 29,191,
/// then 29,312 against 41,020. The driver counts a frame before the agent can
/// have received it, so the right answer is never below `received`, and
/// `agent.py` - which reads `pcap_stats` when it sends, after taking its own
/// counters (agent.py:1581-1582) - never showed one below it.
///
/// A `Capture` is `Send` and not `Sync` (npcap.rs), so the pump cannot read the
/// handle itself. It asks instead, and the sniffer answers between two frames:
/// one atomic load per frame when nobody is asking.
pub(crate) struct KernelStats {
    /// How many readings have been asked for.
    asked: AtomicU64,
    /// The last request answered, and the reading that answered it.
    answer: Mutex<(u64, Option<(u32, u32)>)>,
}

/// Answered, for every request past and future: what a sniffer that has
/// stopped leaves behind, so nothing waits on it.
const ANSWERED_FOR_GOOD: u64 = u64::MAX;

impl KernelStats {
    pub(crate) fn new() -> Self {
        Self { asked: AtomicU64::new(0), answer: Mutex::new((0, None)) }
    }

    /// Asks for a reading, and answers the number to wait on.
    pub(crate) fn ask(&self) -> u64 {
        self.asked.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// The sniffer's half: the request it should answer now, if any is newer
    /// than the last one it answered.
    pub(crate) fn pending(&self, answered: u64) -> Option<u64> {
        let asked = self.asked.load(Ordering::SeqCst);
        (asked > answered).then_some(asked)
    }

    /// Records a reading taken **after** request `request` was made. A reading
    /// that could not be taken keeps the previous one: the counter is
    /// cumulative, so an older figure is late rather than wrong, and `None`
    /// would read as "the driver cannot say" for a handle that said a moment
    /// ago.
    pub(crate) fn answer(&self, request: u64, reading: Option<(u32, u32)>) {
        let mut held = self.answer.lock().unwrap();
        held.0 = held.0.max(request);
        if reading.is_some() {
            held.1 = reading;
        }
    }

    /// The reading that answered `request` - `None` until one has.
    pub(crate) fn answer_to(&self, request: u64) -> Option<Option<(u32, u32)>> {
        let held = self.answer.lock().unwrap();
        (held.0 >= request).then_some(held.1)
    }

    /// The last reading, however old - for the final figures, taken after the
    /// sniffer's last word.
    pub(crate) fn latest(&self) -> Option<(u32, u32)> {
        self.answer.lock().unwrap().1
    }
}

/// One `capture_stats` in the making: the capture's own counters, snapshotted,
/// and the driver readings asked for after them.
///
/// **In `agent.py`'s order** - its counters first, then the driver's
/// (agent.py:1581-1582) - so every adapter's `kernelReceived` is read after its
/// `received` and, the driver having counted every frame the agent has,
/// cannot be below it.
struct StatsTick {
    asked_at: Instant,
    seq_high: u64,
    dropped_agent: u64,
    received: Vec<u64>,
    requests: Vec<u64>,
}

impl StatsTick {
    fn begin(roster: &[Arc<CaptureInterface>], seq_high: u64, dropped_agent: u64) -> Self {
        let received = roster.iter().map(|per| per.received.load(Ordering::SeqCst)).collect();
        let requests = roster.iter().map(|per| per.kernel.ask()).collect();
        Self { asked_at: Instant::now(), seq_high, dropped_agent, received, requests }
    }

    /// The per-adapter figures once every sniffer has answered - or, past
    /// `KERNEL_ANSWER_WAIT`, with the last reading of any that has not.
    fn ready(&self, roster: &[Arc<CaptureInterface>]) -> Option<Vec<InterfaceStats>> {
        let answers: Vec<Option<Option<(u32, u32)>>> = roster
            .iter()
            .zip(&self.requests)
            .map(|(per, request)| per.kernel.answer_to(*request))
            .collect();
        if answers.iter().any(Option::is_none) && self.asked_at.elapsed() < KERNEL_ANSWER_WAIT {
            return None;
        }
        Some(
            roster
                .iter()
                .zip(answers)
                .zip(&self.received)
                .map(|((per, answer), received)| InterfaceStats {
                    iface: per.iface,
                    received: *received,
                    kernel: answer.unwrap_or_else(|| per.kernel.latest()),
                })
                .collect(),
        )
    }
}

/// Whether a figure the driver reported is behind what the agent received -
/// which a reading taken after the agent's own count cannot be, unless the
/// reading is stale. The live check for the lag above; `u32` because that is
/// what `pcap_stat` counts in, and past it the driver's figure has wrapped.
fn kernel_behind(stats: &InterfaceStats) -> bool {
    match stats.kernel {
        Some((kernel_received, _)) => {
            stats.received <= u64::from(u32::MAX) && u64::from(kernel_received) < stats.received
        }
        None => false,
    }
}

/// What a running capture owns, so stopping it is one place.
struct CaptureHandles {
    running: Arc<AtomicBool>,
    queue: Arc<FrameQueue>,
    seq: Arc<AtomicU64>,
    /// One entry per selected adapter that opened, in selection order.
    interfaces: Arc<Vec<Arc<CaptureInterface>>>,
    /// Whose pipe `droppedPipe` is measured against, and what that pipe had
    /// already shed when it became the owner's.
    ///
    /// **`droppedPipe` is the one counter that outlives its capture.** It sits
    /// on the `Connection`, and the app holds one across many start/stop
    /// cycles - so sending the raw total made capture #2 report capture #1's
    /// shed packets as its own, and the app adds it straight into per-capture
    /// loss. `local-agent/agent.py` rebases it for the same reason: *"a number
    /// that accumulated across every capture since the service started would
    /// be read as belonging to the one on screen."*
    ///
    /// Keyed by the owner because ownership can move under a running capture -
    /// a second window's Start once the owner's pipe has gone (agent.py:1232) -
    /// and the new owner's pipe has a history of its own.
    pipe_base: Arc<Mutex<(String, u64)>>,
    /// What the sniffer queue had shed when this capture's figures began -
    /// normally 0, and moved by a `start_capture` that arrives while already
    /// capturing, which begins the figures again (agent.py:1434).
    dropped_base: Arc<AtomicU64>,
    /// One per adapter, stopped first.
    sniffers: Vec<thread::JoinHandle<()>>,
    /// Stopped once every sniffer has, so nothing a sniffer read is behind it.
    pump: Option<thread::JoinHandle<()>>,
    pump_running: Arc<AtomicBool>,
    /// The capture's files, when it writes them. Finished last.
    output: Option<Arc<Output>>,
}

impl CaptureHandles {
    /// `droppedAgent`: shed by the sniffer queue since the figures began.
    fn dropped_agent(&self) -> u64 {
        dropped_since(&self.queue, &self.dropped_base)
    }
}

fn dropped_since(queue: &FrameQueue, base: &AtomicU64) -> u64 {
    queue.dropped().saturating_sub(base.load(Ordering::SeqCst))
}

/// The roster as `capture_stats`' per-interface array.
///
/// Read in roster order, which is selection order, so the array is stable
/// across every tick of one capture - the app indexes its Interfaces rows by
/// `iface` rather than by position, but a list that reordered itself between
/// ticks would be a difference nobody could account for.
fn interface_stats(roster: &[Arc<CaptureInterface>]) -> Vec<InterfaceStats> {
    roster
        .iter()
        .map(|per| InterfaceStats {
            iface: per.iface,
            received: per.received.load(Ordering::Relaxed),
            kernel: per.kernel.latest(),
        })
        .collect()
}

impl Shared {
    fn broadcast(&self, value: &Value) {
        let text = value.to_string();
        for connection in self.clients.lock().unwrap().values() {
            // A client that has gone is not an error here - its own read loop
            // is already tearing it down and will deregister it.
            let _ = connection.send(FRAME_JSON, text.as_bytes(), 0);
        }
    }

    fn send_to(&self, client: &str, value: &Value) {
        if let Some(connection) = self.clients.lock().unwrap().get(client) {
            let _ = connection.send(FRAME_JSON, value.to_string().as_bytes(), 0);
        }
    }

    /// Whether a capture is running - which is **not** the same question as
    /// whether a capture handle exists, and was answered as if it were: a
    /// capture whose reader had died kept its handle, so the agent reported
    /// `sniffing` for the rest of the session. `control.rs` removes a capture
    /// the moment its last adapter goes, so the two now agree by construction.
    fn capture_state(&self) -> CaptureState {
        self.control.capture_state()
    }

    /// The owning client's id, for `hello` and `state` - `None` exactly when
    /// nothing is being captured.
    fn owner_id(&self) -> Option<String> {
        self.control.owner()
    }
}

/// The clients, as `control.rs` sees them.
impl Env for Shared {
    fn send_to(&self, client: &str, message: &Value) {
        Shared::send_to(self, client, message);
    }

    fn broadcast(&self, message: &Value) {
        Shared::broadcast(self, message);
    }

    fn is_connected(&self, client: &str) -> bool {
        self.clients.lock().unwrap().contains_key(client)
    }

    fn connected(&self) -> usize {
        self.clients.lock().unwrap().len()
    }

    fn interfaces(&self) -> Vec<Interface> {
        self.interfaces.lock().unwrap().clone()
    }

    fn log(&self, level: Level, text: &str) {
        agent_log::write(level.as_str(), text);
    }

    /// agent.py:1369 - a moment's delay, so the handler returns and the log
    /// line reaches a subscriber before the pipe drops.
    fn schedule_restart(&self) {
        thread::spawn(|| {
            thread::sleep(restart::RESTART_DELAY);
            restart::exit_for_restart();
        });
    }
}

/// `droppedPipe` for `owner`: what its pipe has shed since it became the owner.
/// `None` - "unknown", never 0 - once the owner has no pipe.
fn dropped_pipe(shared: &Shared, base: &Mutex<(String, u64)>, owner: &str) -> Option<u64> {
    let connection = shared.clients.lock().unwrap().get(owner).cloned()?;
    let now = connection.outbound.dropped();
    let mut held = base.lock().unwrap();
    if held.0 != owner {
        *held = (owner.to_string(), now);
    }
    Some(now.saturating_sub(held.1))
}

/// Stops a capture's threads in order, and answers what the writer refused.
///
/// **Sniffers, then the pump, then the writer**, each joined before the next
/// is stopped: every frame a sniffer read is then in the queues before either
/// consumer is told there will be no more, and the file closes - its ISBs
/// written - with nothing still on the way to it. **The workers are joined
/// before a single counter is read**, so every figure read afterwards is final
/// rather than a snapshot taken while threads were still moving it. The cost
/// is up to one `to_ms` (100 ms), on a path that is already stopping.
///
/// The live queue is left as it is: `stop` delivers what is in it, `reap`
/// throws it away.
fn halt(handles: &mut CaptureHandles) -> Option<u64> {
    handles.running.store(false, Ordering::SeqCst);
    for sniffer in std::mem::take(&mut handles.sniffers) {
        let _ = sniffer.join();
    }
    handles.pump_running.store(false, Ordering::SeqCst);
    if let Some(pump) = handles.pump.take() {
        let _ = pump.join();
    }
    // Read before the writer finishes: nothing pushes to it any more.
    let dropped = handles.output.as_ref().map(|o| o.writer.dropped());
    // The last reference: dropping it finishes the writer, which writes what
    // it holds and closes the file with its ISBs.
    handles.output.take();
    dropped
}

/// Sends what the live queue still holds to `owner`, and answers how many
/// frames could not be.
///
/// **Delivered, not discarded.** A stop used to throw these away and report
/// them as `queuedAtStop`: frames captured and never shown. The capture's file
/// has every one of them now, and the list should too - a stop that dropped
/// its tail would leave the file and the list disagreeing about how the
/// capture ended.
fn deliver_rest(shared: &Shared, queue: &FrameQueue, owner: &str) -> usize {
    let connection = shared.clients.lock().unwrap().get(owner).cloned();
    if let Some(connection) = connection {
        loop {
            let (batch, _) = queue.drain();
            if batch.is_empty() {
                break;
            }
            let Ok(payload) = wire::encode_batch(&batch) else { break };
            if connection.send(FRAME_BINARY, &payload, batch.len() as u64).is_err() {
                break;
            }
        }
    }
    let (left, _) = queue.depth();
    queue.discard();
    left
}

/// Stops a capture that ended itself - its last adapter died, or its owner's
/// pipe refused a batch - on a thread of its own, because the thread that
/// noticed is one of those the stop has to join.
///
/// This is what was missing: the capture used to be marked dead and left
/// standing, so its pump went on sending `capture_stats`, its owner kept it,
/// and the next `start_capture` was ignored because a handle still existed.
fn reap(mut handles: CaptureHandles) {
    thread::spawn(move || {
        halt(&mut handles);
        handles.queue.discard();
    });
}

/// Ends the capture itself, once, on a thread of its own - the thread that
/// met the limit is one the stop joins.
fn end_capture(shared: &Arc<Shared>, generation: u64, why: Value, to_everyone: bool) {
    let shared = Arc::clone(shared);
    thread::spawn(move || {
        shared.control.end_itself(&*shared, &Live { shared: &shared }, generation, &why, to_everyone);
    });
}

/// An autostop limit was met: the capture ends, and its owner is told which.
fn autostop(shared: &Arc<Shared>, output: &Output, generation: u64, reason: StopReason) {
    if !output.ending.swap(true, Ordering::SeqCst) {
        crate::log_info!("autostop: {} limit reached - stopping the capture", reason.as_str());
        end_capture(shared, generation, protocol::capture_stopped(reason.as_str()), false);
    }
}

/// A file as `capture_file` reports it.
fn file_message(report: &FileReport, state: &str) -> Value {
    protocol::capture_file(
        report.index,
        &report.name,
        state,
        report.first_seq,
        report.last_seq,
        report.frames,
        report.bytes,
    )
}

/// `control::Driver` over Npcap and this file's threads.
struct Live<'a> {
    shared: &'a Arc<Shared>,
}

impl Driver for Live<'_> {
    type Handle = Capture<'static>;
    type Running = CaptureHandles;

    /// Opens one adapter, promiscuous, and raises its kernel buffer.
    ///
    /// **Neither buffer call can fail the open any more.** Both were `?` here,
    /// so an adapter whose driver refused `pcap_setbuff` could not be captured
    /// on at all - where `agent.py` notes that "a smaller buffer drops more
    /// frames, it does not stop a capture" (agent.py:835-838) and says which
    /// it got in the log (agent.py:2113-2115), which is what this does.
    fn open(&self, iface: &Interface, options: &CaptureOptions) -> Result<Capture<'static>, String> {
        let npcap = self
            .shared
            .npcap
            .get()
            .ok_or_else(|| "Npcap is not installed".to_string())?;
        let mut capture =
            (self.shared.hardware.open)(npcap, iface, options).map_err(|error| error.to_string())?;
        capture.keep_at_most(options.snaplen);
        // Before a single frame is read, and a failure fails this adapter:
        // compiled against ITS link type, a filter can be fine on Ethernet and
        // meaningless on the loopback, and a capture that went on unfiltered
        // would deliver exactly what its owner asked not to see.
        if let Some(filter) = &options.filter {
            capture
                .set_filter(filter)
                .map_err(|error| format!("the capture filter does not apply here: {error}"))?;
        }
        // Sized per core: Npcap splits the buffer into one segment per
        // processor and drops when the segment for the receiving core is full,
        // so a flat figure is that figure divided by the core count. See
        // `session::kernel_buffer_bytes`. Per handle, not per capture: the
        // budget is the driver's per-adapter ring.
        let bytes = kernel_buffer_bytes(available_cores());
        if matches!(capture.set_kernel_buffer(bytes as i32), Ok(true)) {
            crate::log_info!("{}: capture buffer {} MB", iface.label, bytes / (1024 * 1024));
        } else {
            crate::log_info!("{}: capture buffer driver default (could not be set)", iface.label);
        }
        // Hand frames over as they arrive rather than at Npcap's 16 KB default,
        // which is what scapy asks for and therefore what the Python agent has
        // always had. Latency, not content: at the default a frame is shown up
        // to `to_ms` later, and nothing is lost - so a refusal is ignored, as
        // scapy ignores it.
        let _ = capture.set_min_to_copy(0);
        Ok(capture)
    }

    fn start(
        &self,
        generation: u64,
        owner: &str,
        opened: Vec<(Interface, Capture<'static>)>,
        options: &CaptureOptions,
    ) -> CaptureHandles {
        start_capture(self.shared, generation, owner, opened, options)
    }

    /// agent.py:1432-1436: a `start_capture` while already capturing begins
    /// this capture's figures again - `seq` from 0, `received` per adapter,
    /// the agent's and the pipe's drops rebased - while the threads keep
    /// reading. The app keys nothing on `seq` being unbroken: it is only the
    /// tie-break when two frames share a capture time (`orderingWindow.ts`),
    /// and a stored frame's identity is the id the Worker gives it.
    fn rebase(&self, handles: &CaptureHandles, owner: &str) {
        if let Some(output) = &handles.output {
            *output.owner.lock().unwrap() = owner.to_string();
        }
        handles.seq.store(0, Ordering::SeqCst);
        for per in handles.interfaces.iter() {
            per.received.store(0, Ordering::SeqCst);
        }
        handles.dropped_base.store(handles.queue.dropped(), Ordering::SeqCst);
        let shed = self
            .shared
            .clients
            .lock()
            .unwrap()
            .get(owner)
            .map(|c| c.outbound.dropped())
            .unwrap_or(0);
        *handles.pipe_base.lock().unwrap() = (owner.to_string(), shed);
    }

    /// Stops, and answers the final figures.
    ///
    /// **Built after the join and before anything else**, so the last figures
    /// the app ever sees are final rather than up to a second stale - a burst in
    /// that last second is invisible otherwise, which is exactly when somebody
    /// looks.
    fn stop(&self, mut handles: CaptureHandles, owner: &str) -> Option<Value> {
        let dropped_writer = halt(&mut handles);
        let queued = deliver_rest(self.shared, &handles.queue, owner);
        // **The owner's pipe drops, not `None`.** Passing None here made the
        // LAST message the app ever sees report `droppedPipe` as unknown, for a
        // stage that had been reported every second up to that point - found
        // by driving this with the app's own client, which asserts that every
        // stage the agent can measure is one it actually reports.
        let dropped_pipe = dropped_pipe(self.shared, &handles.pipe_base, owner);
        let mut stats = protocol::capture_stats(
            STATS_INTERVAL.as_millis() as u32,
            handles.seq.load(Ordering::Relaxed),
            handles.dropped_agent(),
            dropped_pipe,
            &interface_stats(&handles.interfaces),
        );
        // `queuedAtStop` is what the stop could not deliver - 0 unless the
        // owner's pipe went while it was sending. Those frames were captured
        // and not lost to pressure: counting them as a drop would report a
        // loss nobody suffered, and leaving them out makes the figures fail to
        // add up, which is how somebody concludes the counters are wrong.
        if let Some(object) = stats.as_object_mut() {
            object.insert("queuedAtStop".into(), serde_json::json!(queued));
            if let Some(dropped) = dropped_writer {
                object.insert("droppedWriter".into(), serde_json::json!(dropped));
            }
        }
        Some(stats)
    }
}

/// Re-reads the adapter list - loading Npcap first if it never has - and logs
/// what moved.
///
/// Per connection, which is what lets a reconnect find adapters after a driver
/// install (`AgentPipeLink.recycle`), and Npcap itself after the Update Center
/// installs it under a running service. The read happens before the list's
/// lock is taken: a new device costs a `pcap_open_live` to learn its link type.
fn refresh_interfaces(shared: &Shared) {
    let read = match load_npcap(shared) {
        Some(npcap) => (shared.hardware.devices)(npcap).map_err(|error| error.to_string()),
        // agent.py:2024-2028: no driver is an empty list, not a failed read -
        // a failed read keeps the previous list, and there is nothing true
        // about a list Npcap would have produced.
        None => Ok(Vec::new()),
    };
    let log = |level: Level, text: &str| agent_log::write(level.as_str(), text);
    let mut held = shared.interfaces.lock().unwrap();
    let fresh = control::refresh_interfaces(&log, &held, read);
    *held = fresh;
}

/// Npcap, if it is installed - trying again when it was not last time.
fn load_npcap(shared: &Shared) -> Option<&'static Npcap> {
    match shared
        .npcap
        .get_or_load(|| (shared.hardware.load)().map_err(|error| error.to_string()))
    {
        Ok((npcap, failed_before)) => {
            if failed_before > 0 {
                crate::log_info!(
                    "Npcap's packet driver is available now - adapters can be listed and captured on"
                );
            }
            Some(npcap)
        }
        Err(error) => {
            // agent.py:2024-2027, written on every attempt as that is: each is
            // a connection that found nothing to capture on.
            crate::log_error!(
                "Npcap's packet driver is not available ({error}). Packet capture will not work. \
                 Install Npcap from https://npcap.com/#download"
            );
            None
        }
    }
}

/// Reads the adapters Npcap can capture on.
///
/// The label pairs Windows' connection name with Npcap's hardware description
/// (`Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)`), which is what
/// the Python agent shows and what a person recognises. Read once for the whole
/// list rather than per device: it is one `GetAdaptersAddresses` either way and
/// a per-device call would make the enumeration quadratic in adapters.
fn read_interfaces(npcap: &Npcap) -> io::Result<Vec<Interface>> {
    let friendly = adapters::adapter_facts();
    Ok(npcap
        .devices()?
        .into_iter()
        .enumerate()
        .map(|(index, device)| {
            let probe = probe(npcap, &device.name);
            Interface {
                id: index,
                label: adapters::label_for(&device.name, device.description.as_deref(), &friendly),
                link_type: probe.link_type,
                ts_precision: probe.ts_precision,
                connection: adapters::connection_name(&device.name, &friendly),
                hardware: device.description.clone(),
                name: device.name,
            }
        })
        .collect())
}

/// What `pcap_datalink` says about a device, remembered for the process.
///
/// **libpcap will only answer about a handle it has open**, so asking costs a
/// `pcap_open_live` and a `pcap_close` per device - and the interface list is
/// re-read on *every* connection, which would put that cost on the critical
/// path of opening Inwire. Demand start is the whole reason the agent's cold
/// start matters (ADR 0035), so the answer is cached by device name for the
/// life of the process.
///
/// **Caching is safe because a device's link type is a property of what the
/// device IS.** An Ethernet adapter does not become a loopback one; a device
/// that appears later is not in the map and is asked about then. What can
/// change under a running service is the SET of devices, and that is re-read
/// per connection exactly as before.
///
/// Opened **non-promiscuous** and closed immediately: this is a question, not
/// a capture, and putting an adapter into promiscuous mode to ask it would be
/// a visible side effect of listing the adapters.
///
/// `None` rather than a guess when the open fails - a device in use by
/// something that will not share it, or one the driver has just removed. The
/// app's own fallback is Ethernet, so a `1` written here would be
/// indistinguishable from having asked and been told.
///
/// **The timestamp precision comes from the same open**, and is cached for the
/// same reason: it is what the driver answers when asked for nanoseconds, which
/// is a property of the driver rather than of any one capture - and the capture
/// asks the same question the same way (`Npcap::open`).
fn probe(npcap: &Npcap, device: &str) -> Probe {
    static CACHE: Mutex<Option<HashMap<String, Probe>>> = Mutex::new(None);
    let mut held = CACHE.lock().unwrap();
    let cache = held.get_or_insert_with(HashMap::new);
    if let Some(known) = cache.get(device) {
        return *known;
    }
    let question = OpenOptions { promiscuous: false, snaplen: npcap::SNAPLEN as u32 };
    let answer = match npcap.open(device, question) {
        Ok(handle) => Probe {
            link_type: Some(handle.datalink()),
            ts_precision: Some(if handle.nanoseconds() { 9 } else { 6 }),
        },
        Err(_) => Probe { link_type: None, ts_precision: None },
    };
    cache.insert(device.to_string(), answer);
    answer
}

/// What opening a device once says about it. See `probe`.
#[derive(Clone, Copy)]
struct Probe {
    link_type: Option<i32>,
    ts_precision: Option<u8>,
}

/// The answer to `check_capture_filter`: whether `filter` compiles for every
/// link type among `names`, and libpcap's reason when it does not.
///
/// **Per link type, not per adapter**, because that is all a compile depends
/// on - so a selection of Ethernet and Wi-Fi is one compile, and Ethernet with
/// the loopback is two. An adapter whose link type is unknown is checked as
/// Ethernet, which is what the app will read its frames as. With no adapters
/// named, Ethernet alone: the question is then about the filter's spelling.
///
/// **A hostname in a filter is resolved by libpcap while it compiles**, here
/// and again when the capture starts - `host example.com` costs a DNS lookup
/// from this service, exactly as it does in Wireshark's filter box. A cost of
/// what was typed, and visible in the capture it narrows.
fn check_capture_filter(shared: &Shared, filter: &str, names: &[String]) -> Value {
    if filter.trim().is_empty() {
        return protocol::capture_filter_check(filter, None);
    }
    let Some(npcap) = shared.npcap.get() else {
        return protocol::capture_filter_check(filter, Some("Npcap is not installed, so a capture filter cannot be checked"));
    };
    let interfaces = shared.interfaces.lock().unwrap().clone();
    let mut kinds: Vec<(i32, Option<String>)> = Vec::new();
    for name in names {
        let Some(iface) = interfaces.iter().find(|i| &i.name == name) else { continue };
        let link_type = iface.link_type.unwrap_or(1);
        if !kinds.iter().any(|(known, _)| *known == link_type) {
            kinds.push((link_type, Some(iface.label.clone())));
        }
    }
    if kinds.is_empty() {
        kinds.push((1, None));
    }
    let named = kinds.len() > 1;
    for (link_type, label) in &kinds {
        if let Err(reason) = npcap.check_filter(*link_type, filter) {
            // Named only when the selection mixes link types: then the reason
            // is about one adapter and not the others.
            let reason = match label {
                Some(label) if named => format!("{label}: {reason}"),
                _ => reason,
            };
            return protocol::capture_filter_check(filter, Some(&reason));
        }
    }
    protocol::capture_filter_check(filter, None)
}

/// What the machine feeds (`host_feeds.rs`) need from the agent: somewhere to
/// send, the capture list to narrow the adapter report to and sample, and
/// whether to stop.
impl Outlet for Shared {
    fn send_to(&self, client: &str, message: &Value) {
        Shared::send_to(self, client, message);
    }

    fn capture_devices(&self) -> Vec<String> {
        self.interfaces.lock().unwrap().iter().map(|i| i.name.clone()).collect()
    }

    fn stopping(&self) -> bool {
        self.shutdown.requested()
    }
}

/// This agent as the feeds' outlet.
fn outlet(shared: &Arc<Shared>) -> Arc<dyn Outlet> {
    Arc::clone(shared) as Arc<dyn Outlet>
}

/// Starts reading every adapter in `opened`, for `owner`.
///
/// **Every one of them.** This once took a single device, and its caller passed
/// `chosen.first()` - so a selection of two adapters captured one and said
/// nothing. The handles arrive already open, one adapter at a time
/// (`Live::open`), so an adapter that refuses is reported on its own and the
/// rest still capture - `control.rs` decides that, as `agent.py` does.
///
/// One `FrameQueue` and one pump serve every adapter, because the queue is the
/// capture's shared budget and the batch is the capture's: a pump per adapter
/// would split the ordering window N ways and make the app's 100 ms flush
/// reassemble what this side had just taken apart. The sniffers are one thread
/// per adapter, which is what `local-agent/agent.py` does and is forced here
/// anyway - a `Capture` is `Send` and not `Sync`, so a handle belongs to
/// exactly one thread for its whole life.
fn start_capture(
    shared: &Arc<Shared>,
    generation: u64,
    owner: &str,
    opened: Vec<(Interface, Capture<'static>)>,
    options: &CaptureOptions,
) -> CaptureHandles {
    let running = Arc::new(AtomicBool::new(true));
    let pump_running = Arc::new(AtomicBool::new(true));
    let queue = Arc::new(FrameQueue::with_defaults());
    let seq = Arc::new(AtomicU64::new(0));
    let roster: Arc<Vec<Arc<CaptureInterface>>> = Arc::new(
        opened
            .iter()
            .map(|(iface, _)| {
                Arc::new(CaptureInterface {
                    iface: iface.id,
                    received: Arc::new(AtomicU64::new(0)),
                    kernel: Arc::new(KernelStats::new()),
                })
            })
            .collect(),
    );
    // Read before the first frame can be shed, so the subtraction can never go
    // negative.
    let base = shared
        .clients
        .lock()
        .unwrap()
        .get(owner)
        .map(|c| c.outbound.dropped())
        .unwrap_or(0);
    let pipe_base = Arc::new(Mutex::new((owner.to_string(), base)));
    let dropped_base = Arc::new(AtomicU64::new(0));
    let output = start_output(shared, generation, owner, &opened, &roster, options);
    let mut sniffers = Vec::new();

    // A sniffer per adapter. Encodes on its own thread, so the pump sees
    // finished bytes rather than live driver buffers - which is also what keeps
    // a libpcap handle from ever crossing to another thread.
    //
    // **The sequence number is taken from one counter across every adapter**,
    // and `received` is counted per adapter. That is `CaptureCounters`' split in
    // `agent.py`, and it is what the wire format asks for: `seq` orders the
    // capture, `iface` says where a frame came from, and `capture_stats` reports
    // "received" per interface.
    for (position, ((interface, mut capture), per)) in opened.into_iter().zip(roster.iter()).enumerate() {
        let iface = interface.id;
        let out = output.clone();
        let (run, q, sq, shutdown) = (
            Arc::clone(&running),
            Arc::clone(&queue),
            Arc::clone(&seq),
            Arc::clone(&shared.shutdown),
        );
        let (rx, kn) = (Arc::clone(&per.received), Arc::clone(&per.kernel));
        let sh = Arc::clone(shared);
        let alive = Alive::new();
        sniffers.push(thread::spawn(move || {
            let _alive = alive;
            let mut answered = 0u64;
            while run.load(Ordering::SeqCst) && !shutdown.requested() {
                match capture.next() {
                    Ok(Read::Timeout) => {}
                    Ok(Read::Frame { data, ts_ns, wire_len }) => {
                        rx.fetch_add(1, Ordering::Relaxed);
                        // agent.py:1934-1943: the first frame this process
                        // captures says the capture works, then one line per
                        // 10,000.
                        if let Some(line) = COUNTS.captured() {
                            crate::log_info!("{line}");
                        }
                        // agent.py:715-716: a driver that stamped nothing gets
                        // the wall clock rather than a frame at 1970.
                        let ts_ns = capture_time_ns(ts_ns, wall_clock_ns);
                        let n = match &out {
                            None => sq.fetch_add(1, Ordering::Relaxed),
                            // **The sequence number and the file are decided
                            // under one lock**, and the frame is in the
                            // writer's queue before the lock is let go - so
                            // the file's order is the sequence's across every
                            // adapter, and a frame is in the file exactly when
                            // it is in the stream.
                            Some(o) => {
                                let mut sequencer = o.sequencer.lock().unwrap();
                                match sequencer.admit(pcapng::enhanced_packet_len(data.len()) as u64, ts_ns) {
                                    Admit::Write { file, first } => {
                                        let n = sq.fetch_add(1, Ordering::Relaxed);
                                        // Still under the lock, and before
                                        // this frame is in the live queue: the
                                        // owner hears where the file begins
                                        // ahead of any frame in it.
                                        if first {
                                            let owner = o.owner.lock().unwrap().clone();
                                            sh.send_to(&owner, &protocol::capture_boundary(file, n));
                                        }
                                        o.writer.push(FrameJob {
                                            seq: n,
                                            file,
                                            interface: position as u32,
                                            ts_ns,
                                            wire_len,
                                            data: data.to_vec(),
                                        });
                                        n
                                    }
                                    // **The capture has met its limit, so this
                                    // sniffer stops reading.** Reading on would
                                    // only discard frames - and could reach an
                                    // adapter's end first, whose report would
                                    // end the capture as a failure and throw
                                    // away what the owner is still owed.
                                    Admit::Stop(reason) => {
                                        drop(sequencer);
                                        autostop(&sh, o, generation, reason);
                                        break;
                                    }
                                }
                            }
                        };
                        match wire::encode_record(n as u32, iface as u16, ts_ns, wire_len as usize, data) {
                            Ok(record) => {
                                let shed = q.push_counting(record);
                                if shed > 0 {
                                    // agent.py:1767-1776, sparsely.
                                    if let Some(line) = COUNTS.shed(shed) {
                                        crate::log_warn!("{line}");
                                    }
                                }
                            }
                            // Unreachable: the encoder refuses only a frame past
                            // 4 GB, and the snaplen caps one at 262,144 bytes.
                            // Logged rather than silent if that ever changes.
                            Err(error) => {
                                crate::log_warn!("dropping a frame: {error}");
                            }
                        }
                    }
                    Err(error) => {
                        // A removed adapter lands here - an unplugged USB NIC,
                        // a driver reset, a Wi-Fi adapter torn down by a roam.
                        // Stopping this thread is right; the Python agent used
                        // to `continue` on this and spin a core at 100% for
                        // ever. Every client is told, and when this was the
                        // last adapter still reading the capture is stopped -
                        // by another thread, since stopping joins this one.
                        kn.answer(ANSWERED_FOR_GOOD, capture.stats());
                        if let Some((dead, _owner)) =
                            sh.control.adapter_failed(&*sh, generation, iface, &error.to_string())
                        {
                            reap(dead);
                        }
                        return;
                    }
                }
                // **`pcap_stats` when the pump asks, not per frame and not on a
                // timer.** Per frame was one FFI call and one mutex for every
                // packet, on the thread whose only job is draining the driver's
                // buffer before it overflows - spending stage-1 drops to
                // measure them. A timer of this thread's own made the figure
                // the pump sent up to a tick older than the `received` beside
                // it - see `KernelStats`. Asked, it is one atomic load a frame,
                // and the reading is taken after the pump's snapshot. It
                // cannot leave this thread: a libpcap handle belongs to the one
                // thread that reads it.
                if let Some(request) = kn.pending(answered) {
                    answered = request;
                    kn.answer(request, capture.stats());
                }
            }
            // The last word. A stop joins the workers before it reads these
            // counters, so this is what the final `capture_stats` carries - the
            // figure somebody looks at when the numbers do not add up - and it
            // answers every request for good, so a pump waiting on an adapter
            // that has stopped does not wait out `KERNEL_ANSWER_WAIT`.
            kn.answer(ANSWERED_FOR_GOOD, capture.stats());
        }));
    }

    // The pump. **It sleeps on `Drained` and on nothing else**, which is the
    // whole point of `drain` reporting why it stopped - the Python agent slept
    // on a full queue and capped itself at 16.5 MB/s.
    let pump = {
        let (run, q, sq, shared) = (
            Arc::clone(&pump_running),
            Arc::clone(&queue),
            Arc::clone(&seq),
            Arc::clone(shared),
        );
        let (all, base) = (Arc::clone(&roster), Arc::clone(&pipe_base));
        let shed_base = Arc::clone(&dropped_base);
        let out = output.clone();
        let alive = Alive::new();
        thread::spawn(move || {
            let _alive = alive;
            let mut last_stats = Instant::now();
            let mut tick: Option<StatsTick> = None;
            let mut warned_behind = false;
            while run.load(Ordering::SeqCst) && !shared.shutdown.requested() {
                // Whose capture this is **now**. Another window can take over a
                // running capture once its owner's pipe has gone (agent.py:1232),
                // and a capture that has been stopped or replaced has no owner
                // at all - which is this thread's signal to leave.
                let Some(owner) = shared.control.owner_of(generation) else { return };
                // The wall-clock autostop: a capture on a silent link still
                // stops, which a limit counted in frames never would.
                if let Some(o) = &out {
                    if o.autostop_seconds.is_some_and(|s| o.started.elapsed() >= Duration::from_secs(s)) {
                        o.sequencer.lock().unwrap().stop_now(StopReason::Seconds);
                        autostop(&shared, o, generation, StopReason::Seconds);
                    }
                }
                let target = shared.clients.lock().unwrap().get(&owner).cloned();
                let Some(connection) = target else {
                    // The owner's pipe is being torn down. Its disconnect stops
                    // this capture, or another window claims it; either way the
                    // frames wait in the bounded queue rather than going nowhere.
                    thread::sleep(Duration::from_millis(BATCH_INTERVAL_MS));
                    continue;
                };
                let (batch, state) = q.drain();
                if !batch.is_empty() {
                    let Ok(payload) = wire::encode_batch(&batch) else { continue };
                    // Frames go to the owner alone. A second window would
                    // otherwise see sequence numbers that are not its own.
                    if connection.send(FRAME_BINARY, &payload, batch.len() as u64).is_err() {
                        match shared.control.owner_gone(&*shared, generation, &owner) {
                            // The owner's pipe has gone, so there is nowhere
                            // left to deliver on any adapter: the capture is
                            // over, and is stopped on another thread because
                            // stopping joins this one.
                            Some((dead, _)) => {
                                reap(dead);
                                return;
                            }
                            // Not that pipe's capture any more: another window
                            // took it over once the owner's pipe had gone
                            // (agent.py:1232), or it was stopped or replaced.
                            // The top of the loop decides which. Returning here
                            // left a taken-over capture with no pump - running,
                            // and delivering to nobody.
                            None => continue,
                        }
                    }
                }
                // Once a tick: the counters now, the driver's readings asked
                // for after them, and the message sent when they have come back
                // - a few loop turns later, never holding the batches up.
                if tick.is_none() && last_stats.elapsed() >= STATS_INTERVAL {
                    last_stats = Instant::now();
                    tick = Some(StatsTick::begin(
                        &all,
                        sq.load(Ordering::SeqCst),
                        dropped_since(&q, &shed_base),
                    ));
                }
                if let Some(entries) = tick.as_ref().and_then(|t| t.ready(&all)) {
                    let pending = tick.take().expect("ready came from it");
                    // The runtime check for the lag `KernelStats` fixed, once a
                    // capture: a driver figure below the agent's own count means
                    // a reading older than the count it sits beside.
                    if !warned_behind {
                        if let Some(behind) = entries.iter().find(|e| kernel_behind(e)) {
                            warned_behind = true;
                            crate::log_warn!(
                                "capture_stats: interface {}'s driver count ({}) is behind the frames received ({}) - a stale pcap_stats reading",
                                behind.iface,
                                behind.kernel.map_or(0, |k| k.0),
                                behind.received
                            );
                        }
                    }
                    let mut stats = protocol::capture_stats(
                        STATS_INTERVAL.as_millis() as u32,
                        pending.seq_high,
                        pending.dropped_agent,
                        dropped_pipe(&shared, &base, &owner),
                        &entries,
                    );
                    // Frames the file refused because the disk fell behind.
                    // Present only for a capture that writes a file.
                    if let (Some(o), Some(object)) = (&out, stats.as_object_mut()) {
                        object.insert("droppedWriter".into(), serde_json::json!(o.writer.dropped()));
                    }
                    let _ = connection.send(FRAME_JSON, stats.to_string().as_bytes(), 0);
                }
                if state == Drain::Drained {
                    thread::sleep(Duration::from_millis(BATCH_INTERVAL_MS));
                }
            }
        })
    };

    CaptureHandles {
        running,
        queue,
        seq,
        interfaces: roster,
        pipe_base,
        dropped_base,
        sniffers,
        pump: Some(pump),
        pump_running,
        output,
    }
}

/// The capture's own pcapng, when its `start_capture` asked for one and the
/// read loop resolved where and as whom (`PendingOutput`).
///
/// One IDB per adapter, in the order they opened - the order the sniffers'
/// `position` indexes, which is what every EPB's interface id is.
fn start_output(
    shared: &Arc<Shared>,
    generation: u64,
    owner: &str,
    opened: &[(Interface, Capture<'static>)],
    roster: &Arc<Vec<Arc<CaptureInterface>>>,
    options: &CaptureOptions,
) -> Option<Arc<Output>> {
    let file = options.file.as_ref()?;
    let pending = shared.pending_output.lock().unwrap().remove(owner)?;
    let interfaces: Vec<FileInterface> = opened
        .iter()
        .map(|(interface, capture)| FileInterface {
            name: interface.name.clone(),
            connection: interface.connection.clone(),
            hardware: interface.hardware.clone(),
            link_type: interface.link_type.and_then(|t| u16::try_from(t).ok()).unwrap_or(1),
            ts_resolution: if capture.nanoseconds() { 9 } else { 6 },
        })
        .collect();
    let header = capture_file::file_header(&interfaces, options.snaplen, options.filter.as_deref());
    let sequencer = Sequencer::new(file.ring, file.autostop, header.len() as u64);
    let owner_cell = Arc::new(Mutex::new(owner.to_string()));

    let counters_roster = Arc::clone(roster);
    let counters = Arc::new(move |i: usize| {
        let per = &counters_roster[i];
        (per.received.load(Ordering::Relaxed), per.kernel.latest().map(|(_, dropped)| u64::from(dropped)))
    });
    // Weak: the writer lives inside the capture, which lives inside `Shared`.
    let (weak, who) = (Arc::downgrade(shared), Arc::clone(&owner_cell));
    let events = Box::new(move |event: FileEvent| {
        let Some(shared) = weak.upgrade() else { return };
        let owner = who.lock().unwrap().clone();
        match event {
            FileEvent::Opened(report) => shared.send_to(&owner, &file_message(&report, "open")),
            FileEvent::Closed(report) => shared.send_to(&owner, &file_message(&report, "closed")),
            FileEvent::Deleted(report) => shared.send_to(&owner, &file_message(&report, "deleted")),
            FileEvent::Failed(reason) => {
                crate::log_warn!("capture file: {reason} - stopping the capture");
                end_capture(
                    &shared,
                    generation,
                    protocol::error("capture_failed", &format!("The capture stopped: {reason}")),
                    true,
                );
            }
        }
    });
    crate::log_info!("capture files: {}", pending.dir.display());
    let writer = Writer::start(WriterSetup {
        dir: pending.dir,
        ring: file.ring,
        token: pending.token,
        interfaces,
        header,
        started_ns: wall_clock_ns(),
        counters,
        events,
    });
    Some(Arc::new(Output {
        sequencer: Mutex::new(sequencer),
        writer,
        owner: owner_cell,
        autostop_seconds: file.autostop.seconds,
        started: Instant::now(),
        ending: AtomicBool::new(false),
    }))
}

/// Serves one connected client until its pipe closes.
fn serve(shared: Arc<Shared>, instance: Arc<PipeInstance>, client: String) -> io::Result<()> {
    let connection = Arc::new(Connection::new());
    let total = {
        let mut clients = shared.clients.lock().unwrap();
        clients.insert(client.clone(), Arc::clone(&connection));
        clients.len()
    };
    // agent.py:1095's line, exactly.
    crate::log_info!("client connected ({total} total)");

    let writer_instance = Arc::clone(&instance);
    let outbound = Arc::clone(&connection.outbound);
    let writer = thread::spawn(move || {
        let _ = pipe::write_loop(&writer_instance, &outbound);
    });

    // The interface list is re-read per connection, which is what makes a
    // reconnect re-enumerate after a driver install - see `AgentPipeLink.recycle`
    // - and it loads Npcap itself if that has never worked before.
    refresh_interfaces(&shared);
    let interfaces = shared.interfaces.lock().unwrap().clone();
    let _ = connection.send(
        FRAME_JSON,
        protocol::hello(
            crate::VERSION,
            shared.capture_state(),
            &interfaces,
            &client,
            shared.owner_id().as_deref(),
            // The Npcap device's DACL as SDDL - a fact, never a verdict - read
            // per connection like `agent.py:1132` reads it: Npcap can be
            // reinstalled under a running service, and a reconnect is exactly
            // what the Update Center triggers afterwards. `npcapAccess.ts`
            // gives it priority over the registry's `AdminOnly`, which can be
            // edited without the driver being restarted; `null` here made the
            // app answer from the registry alone. See `npcap_access.rs`.
            npcap_access::read_driver_sddl().as_deref(),
        )
        .to_string()
        .as_bytes(),
        0,
    );

    let result = pipe::read_loop(&instance, |frame| {
        if frame.kind != FRAME_JSON {
            // Binary from the client is not part of the protocol. Ignored rather
            // than treated as a framing failure: the stream position is still
            // known, so there is nothing to resynchronise. pipe_server.py:535.
            crate::log_warn!("pipe client sent a binary frame - ignoring");
            return Ok(());
        }
        let text = String::from_utf8_lossy(&frame.payload).to_string();
        let command = match protocol::parse_command(&text) {
            Ok(command) => command,
            // Silence for what is not a JSON object, a named reply for an
            // unknown type, and a malformed selection refused only after the
            // ownership gate - all agent.py's, and all in `control.rs`.
            Err(error) => {
                shared.control.parse_failed(&*shared, &client, &error);
                return Ok(());
            }
        };

        // Where this client's captures live - main's to say, once per pipe.
        if let Command::SetCaptureRoot(dir) = &command {
            shared.capture_roots.lock().unwrap().insert(client.clone(), dir.clone());
            return Ok(());
        }
        // **A capture's files are written as the client that started it**
        // (ADR 0052), so its identity is taken here, on the thread that read
        // its command - the only one the kernel will let impersonate it.
        if let Command::StartCapture(CaptureOptions { file: Some(file), .. }) = &command {
            let root = shared.capture_roots.lock().unwrap().get(&client).cloned();
            let Some(root) = root else {
                shared.send_to(&client, &protocol::error(
                    "invalid_capture_options",
                    "start_capture's captureId needs a set_capture_root first: the agent does not know where this client's captures live.",
                ));
                return Ok(());
            };
            match pipe::client_token(&instance) {
                Ok(token) => {
                    let dir = std::path::Path::new(&root).join(&file.capture_id).join("pcapng");
                    shared.pending_output.lock().unwrap().insert(client.clone(), PendingOutput { dir, token: Some(token) });
                }
                Err(error) => {
                    shared.send_to(&client, &protocol::error(
                        "capture_failed",
                        &format!("The capture's files cannot be written as this client: {error}"),
                    ));
                    return Ok(());
                }
            }
        }

        // Start, stop and re-point are the lifecycle's, including who may send
        // them: a capture belongs to the client that started it, and Fast User
        // Switching is real, so the agent is the only thing that can arbitrate.
        let handled = shared.control.command(&*shared, &Live { shared: &shared }, &client, &command);
        // A start that did not happen - busy, or joining a running capture -
        // leaves its output unused, and its identity is let go here.
        shared.pending_output.lock().unwrap().remove(&client);
        if handled {
            return Ok(());
        }

        match command {
            // The machine's own facts. Each answers the way `agent.py` does -
            // including `unsubscribe_adapters`, which answers nothing.
            Command::SubscribeInterfaceStats => {
                shared.host.subscribe_interface_stats(&outlet(&shared), &client);
            }
            Command::UnsubscribeInterfaceStats => {
                shared.host.unsubscribe_interface_stats(&client);
            }
            Command::SubscribeAdapters => {
                shared.host.subscribe_adapters(&outlet(&shared), &client);
            }
            Command::RefreshAdapters => {
                shared.host.refresh_adapters(&outlet(&shared), &client);
            }
            Command::UnsubscribeAdapters => {
                shared.host.unsubscribe_adapters(&client);
            }
            Command::SubscribeLogs => {
                // **The backlog first, then live lines from here on.** The
                // watermark is taken before the backlog is read rather than
                // after, so a line written in between is sent twice rather
                // than not at all - a duplicate in a log viewer is visible
                // and harmless, a hole is neither.
                let from = agent_log::watermark();
                shared.log_watchers.lock().unwrap().insert(client.clone(), from);
                shared.send_to(&client, &agent_log::log_message(agent_log::backlog()));
            }
            Command::UnsubscribeLogs => {
                shared.log_watchers.lock().unwrap().remove(&client);
            }
            Command::SubscribeSockets => {
                shared.socket_watchers.lock().unwrap().insert(client.clone());
                // **This client's own full snapshot, now.** The shared ticker
                // sends deltas, and a delta against a table this client never
                // received would leave it permanently short of every socket
                // that existed before it subscribed - the same reason
                // `subscribe_logs` hands over a backlog. A throwaway tracker
                // rather than the shared one, so a second window subscribing
                // does not make the first one's next delta a full resend.
                //
                // Re-sending an add the next delta also carries is harmless:
                // `flowAnnotations.ts` applies each message idempotently.
                if let Some(snapshot) = sockets::SocketTracker::new().poll() {
                    shared.send_to(&client, &snapshot);
                }
            }
            Command::UnsubscribeSockets => {
                let mut watchers = shared.socket_watchers.lock().unwrap();
                watchers.remove(&client);
                if watchers.is_empty() {
                    // The next subscriber gets a snapshot of its own anyway,
                    // but the shared tracker must not carry a table read
                    // minutes ago into the first delta after it - every socket
                    // that came and went in between would arrive as one
                    // impossible burst.
                    shared.sockets.lock().unwrap().reset();
                }
            }
            Command::CheckCaptureFilter { filter, interfaces } => {
                shared.send_to(&client, &check_capture_filter(&shared, &filter, &interfaces));
            }
            Command::RestartAgent => {
                // Refused unless this process is the SCM's and a restart policy
                // will bring it back - see `restart.rs`.
                shared.control.restart_agent(&*shared, &shared.restart, &client);
            }
            _ => {
                // Nothing reaches here today: the three capture commands were
                // taken by `control.command` above, and every other command has
                // an arm. Kept as an answer rather than a panic for a command
                // added to the enum before it is handled - silence is the shape
                // the app cannot diagnose.
                let interfaces = shared.interfaces.lock().unwrap().clone();
                shared.send_to(&client, &protocol::state(
                    shared.capture_state(),
                    &interfaces,
                    shared.owner_id().as_deref(),
                ));
            }
        }
        Ok(())
    });

    // pipe_server.py:539 - the one way a connection ends that is the agent's
    // decision rather than the client's, so it is said.
    if let Err(error) = &result {
        if error.kind() == io::ErrorKind::InvalidData {
            crate::log_warn!("pipe framing error, dropping the client: {error}");
        }
    }

    // The client has gone. Deregister first, so nothing tries to send to it
    // while the capture is being torn down.
    let left = {
        let mut clients = shared.clients.lock().unwrap();
        clients.remove(&client);
        clients.len()
    };
    // agent.py:1164's line, exactly.
    crate::log_info!("client disconnected ({left} remaining)");
    // Out of both machine feeds, stopping each loop this client was the last
    // subscriber to - `handle_disconnect`, so a closed window leaves nothing
    // sampling.
    shared.host.client_gone(&client);
    shared.log_watchers.lock().unwrap().remove(&client);
    shared.capture_roots.lock().unwrap().remove(&client);
    {
        let mut watchers = shared.socket_watchers.lock().unwrap();
        watchers.remove(&client);
        // Same reason as `unsubscribe_sockets`: a stale previous reading would
        // make the next delta a burst of everything that moved while nobody
        // was listening.
        if watchers.is_empty() {
            shared.sockets.lock().unwrap().reset();
        }
    }
    // The owner leaving ends its capture; the last client leaving ends any.
    shared.control.disconnected(&*shared, &Live { shared: &shared }, &client);
    connection.outbound.shutdown();
    pipe::cancel_io(&instance);
    let _ = writer.join();
    result
}

/// Runs the agent until `shutdown` is asked for.
///
/// The Npcap handle is leaked deliberately: the library stays loaded for the
/// life of the process - a service never unloads it - and this is what lets a
/// `Capture` borrowed from it move into a sniffer thread without an `Arc`
/// indirection on the hot path. The lifetime is honest rather than erased,
/// because the library really does outlive every handle.
pub fn run(shutdown: Arc<Shutdown>) -> io::Result<()> {
    run_on(shutdown, &pipe_name())
}

/// Where this agent listens.
///
/// `INWIRE_AGENT_PIPE` overrides it, and that is not a debugging nicety - it is
/// the only way this runtime can be driven at all on a development machine. The
/// installed service owns the production name, and a second server on one name
/// is not a state worth debugging. `electron/main.ts` reads the same variable
/// from the other end, so one export points both halves at a private pipe.
pub fn pipe_name() -> String {
    std::env::var("INWIRE_AGENT_PIPE")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| pipe::PIPE_NAME.to_string())
}

/// The body, with the pipe name given rather than read from the environment.
pub fn run_on(shutdown: Arc<Shutdown>, name: &str) -> io::Result<()> {
    run_with(shutdown, name, Hardware::NPCAP)
}

/// The line logged when the very first `CreateNamedPipe` is refused (ADR 0068).
fn name_taken_message(name: &str, error: &io::Error) -> String {
    format!(
        "{name} already exists - another process created it first, so the agent will not serve it: {error}"
    )
}

/// The instance an acceptor serves next (ADR 0068).
///
/// `first` is the one made before the threads started, used once by slot 0.
/// Every other instance comes from `create`. A refusal is **not** a reason to
/// stop the agent - any user can take a slot - so it is logged once per failing
/// streak and retried every `retry` until it works or a stop is asked for.
/// `None` means a stop was asked for.
fn next_instance(
    first: &mut Option<pipe::PipeInstance>,
    failing: &mut bool,
    shutdown: &Shutdown,
    retry: Duration,
    mut create: impl FnMut() -> io::Result<pipe::PipeInstance>,
) -> Option<pipe::PipeInstance> {
    if let Some(instance) = first.take() {
        return Some(instance);
    }
    loop {
        if shutdown.requested() {
            return None;
        }
        match create() {
            Ok(instance) => {
                *failing = false;
                return Some(instance);
            }
            Err(error) => {
                if !*failing {
                    *failing = true;
                    crate::log_warn!("could not create a pipe instance, retrying: {error}");
                }
                // In short slices, so a stop is not held up by the retry wait.
                let until = Instant::now() + retry;
                while Instant::now() < until && !shutdown.requested() {
                    thread::sleep(retry.min(Duration::from_millis(50)));
                }
            }
        }
    }
}

/// `run_on`, with how Npcap is loaded given - which is what lets a test stand
/// in for a machine where Npcap is installed after the agent started.
fn run_with(shutdown: Arc<Shutdown>, name: &str, hardware: Hardware) -> io::Result<()> {
    // agent.py:2325 - the first line of every run, service or `debug`, so a
    // log read later says which build wrote what follows it.
    crate::log_info!("Inwire agent {} starting", crate::VERSION);
    // agent.py:2346 - asks the SCM whether a restart could come back, and
    // re-asserts the restart-on-failure policy when this is the service.
    let restart = restart::probe();

    let shared = new_shared(&shutdown, hardware, restart);

    // agent.py:2348-2360: the list is read now, and an empty one is not fatal -
    // the service can beat Npcap's own start at boot, or run on a machine where
    // Npcap is not installed yet, and either heals on the next connection.
    refresh_interfaces(&shared);
    if shared.interfaces.lock().unwrap().is_empty() {
        crate::log_warn!(
            "no capturable network interfaces found at startup - starting anyway. \
             If this persists, Npcap may not be installed: https://npcap.com/#download"
        );
    }

    // One accept thread per instance. A client disconnecting frees its instance
    // rather than the server, so the pipe name stays served throughout.
    //
    // `live` holds the instances that have a client, so a stop can end those
    // sessions from outside - see `pipe::disconnect` and the foot of this
    // function.
    let live: Arc<Mutex<HashMap<u32, Arc<PipeInstance>>>> = Arc::new(Mutex::new(HashMap::new()));
    //
    // **The first instance is made here, before any thread**, with
    // `FILE_FLAG_FIRST_PIPE_INSTANCE` (ADR 0068): if another process created the
    // name first, the agent refuses it rather than serving a pipe whose
    // descriptor someone else chose. Slot 0 then serves that instance.
    let first_instance =
        match pipe::create_instance(name, pipe::PIPE_SDDL, pipe::MAX_INSTANCES, true) {
            Ok(instance) => instance,
            Err(error) => {
                crate::log_error!("{}", name_taken_message(name, &error));
                shutdown.request("the pipe name is already in use");
                crate::log_info!("shutting down: {}", shutdown.wait());
                return Ok(());
            }
        };
    let mut first_instance = Some(first_instance);
    let mut acceptors = Vec::new();
    for slot in 0..pipe::MAX_INSTANCES {
        let shared = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        let name = name.to_string();
        let live = Arc::clone(&live);
        let mut first = if slot == 0 { first_instance.take() } else { None };
        acceptors.push(thread::spawn(move || {
            let mut serial = 0u64;
            let mut failing = false;
            while !shutdown.requested() {
                let create = || {
                    pipe::create_instance(&name, pipe::PIPE_SDDL, pipe::MAX_INSTANCES, false)
                };
                let Some(instance) =
                    next_instance(&mut first, &mut failing, &shutdown, pipe::INSTANCE_RETRY, create)
                else {
                    return;
                };
                let instance = Arc::new(instance);
                if pipe::accept(&instance).is_err() {
                    continue;
                }
                if shutdown.requested() {
                    return;
                }
                serial += 1;
                let client = format!("rs-{slot}-{serial}");
                live.lock().unwrap().insert(slot, Arc::clone(&instance));
                let _ = serve(Arc::clone(&shared), instance, client);
                live.lock().unwrap().remove(&slot);
            }
        }));
    }
    // pipe_server.py:350's line.
    crate::log_info!("listening on {name}");

    // No rate sampler here any more: `interface_stats` runs one loop per
    // subscription, started by the first subscriber and ended by the last -
    // `host_feeds.rs`.

    // The log forwarder. **Polled rather than called back**, for the reason
    // `agent_log`'s header gives: a sink invoked from inside `log!` would be
    // re-entrant, because sending to a client can fail and a failure worth
    // logging would call `log!` again from inside the lock it is holding.
    //
    // It also means a burst of logging costs one message rather than one per
    // line, which matters because the noisiest thing the agent writes is a
    // capture failing - the moment a subscriber is most likely watching.
    {
        let shared = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            while !shutdown.requested() {
                thread::sleep(LOG_FORWARD_INTERVAL);
                let watchers: Vec<(String, u64)> = shared
                    .log_watchers
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(client, from)| (client.clone(), *from))
                    .collect();
                for (client, from) in watchers {
                    let (lines, next) = agent_log::since(from);
                    if lines.is_empty() {
                        continue;
                    }
                    shared.send_to(&client, &agent_log::log_message(lines));
                    // Only if the client is still subscribed: an unsubscribe
                    // that landed while this was building the message must not
                    // be undone by writing the position back.
                    if let Some(held) = shared.log_watchers.lock().unwrap().get_mut(&client) {
                        *held = next;
                    }
                }
            }
        });
    }

    // The socket-table poller. Its own thread rather than a second job on the
    // sampler's, because reading the table is a few milliseconds of blocking
    // work against the sampler's one `GetIfTable2` - sharing a thread would
    // make the sparkline stutter whenever attribution was on.
    //
    // **A failure here never takes a capture down.** The packet list is the
    // product; a missing process name is a missing annotation, which is the
    // same line `local-agent/agent.py`'s `_socket_loop` draws.
    {
        let shared = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            while !shutdown.requested() {
                thread::sleep(SOCKET_TABLE_INTERVAL);
                let watchers: Vec<String> =
                    shared.socket_watchers.lock().unwrap().iter().cloned().collect();
                if watchers.is_empty() {
                    continue;
                }
                // `None` means nothing opened or closed this second, which on
                // an idle machine is most seconds - and an empty delta every
                // second is a message that says nothing.
                let Some(delta) = shared.sockets.lock().unwrap().poll() else {
                    continue;
                };
                for watcher in watchers {
                    shared.send_to(&watcher, &delta);
                }
            }
        });
    }

    // The idle watchdog, which is the whole of ADR 0035 on this side: the agent
    // stops ITSELF when the app has gone, rather than the app stopping it.
    {
        let shared = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            let started = Instant::now();
            let mut seen_a_client = false;
            let mut idle_ticks = 0u32;
            while !shutdown.requested() {
                thread::sleep(IDLE_CHECK);
                let connected = !shared.clients.lock().unwrap().is_empty();
                if connected {
                    seen_a_client = true;
                    idle_ticks = 0;
                    continue;
                }
                // A capture running with nobody watching is stopped
                // unconditionally, whether or not the process is about to exit.
                // The guarantee does not depend on the exit path being taken.
                shared.control.stop_orphaned(&*shared, &Live { shared: &shared });
                if !seen_a_client && started.elapsed() < FIRST_CLIENT_GRACE {
                    continue;
                }
                idle_ticks += 1;
                if idle_ticks >= IDLE_EXIT_TICKS {
                    shutdown.request(if seen_a_client {
                        "no clients connected"
                    } else {
                        "no client connected within the startup grace period"
                    });
                    return;
                }
            }
        });
    }

    let reason = shutdown.wait();
    crate::log_info!("shutting down: {reason}");
    shared.control.shutdown(&Live { shared: &shared });

    // Release every pipe thread. An idle acceptor is blocked in `accept`, and a
    // connection of our own is what returns it (`poke`); one serving a client
    // is blocked in a read for that client's next command, and **used to be
    // joined as it was** - so an SCM stop with Inwire open waited on the app,
    // and the SCM on this. `pipe::disconnect` ends those sessions from outside.
    //
    // Repeated rather than done once, because a thread can be between two
    // blocking calls when either lands; and bounded, because the service has
    // to reach STOPPED whatever a client is doing.
    let started = Instant::now();
    loop {
        for instance in live.lock().unwrap().values() {
            pipe::disconnect(instance);
        }
        for _ in 0..pipe::MAX_INSTANCES {
            let _ = pipe::poke(name);
        }
        if acceptors.iter().all(|acceptor| acceptor.is_finished()) {
            break;
        }
        if started.elapsed() >= SHUTDOWN_GRACE {
            let waiting = acceptors.iter().filter(|a| !a.is_finished()).count();
            crate::log_warn!(
                "{waiting} pipe thread(s) had not stopped after {} ms - leaving them to the process exit",
                SHUTDOWN_GRACE.as_millis()
            );
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    for acceptor in acceptors {
        if acceptor.is_finished() {
            let _ = acceptor.join();
        }
    }
    Ok(())
}

/// Everything shared between connections, as a run begins - one constructor,
/// so a test builds exactly what `run_with` builds.
fn new_shared(shutdown: &Arc<Shutdown>, hardware: Hardware, restart: RestartSupport) -> Arc<Shared> {
    Arc::new(Shared {
        npcap: Lazy::new(),
        hardware,
        interfaces: Mutex::new(Vec::new()),
        clients: Mutex::new(HashMap::new()),
        control: Control::new(),
        restart,
        host: HostFeeds::new(host_feeds::Sources::machine()),
        socket_watchers: Mutex::new(std::collections::HashSet::new()),
        sockets: Mutex::new(sockets::SocketTracker::new()),
        log_watchers: Mutex::new(HashMap::new()),
        capture_roots: Mutex::new(HashMap::new()),
        pending_output: Mutex::new(HashMap::new()),
        shutdown: Arc::clone(shutdown),
    })
}

// The lifecycle end to end over a real pipe: Npcap arriving under a running
// agent, and a stop with a client connected. In a file of its own so the tests
// do not sit in the middle of what other work edits here.
#[cfg(test)]
#[path = "runtime_tests.rs"]
mod lifecycle_tests;
