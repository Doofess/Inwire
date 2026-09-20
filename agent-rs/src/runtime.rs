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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::adapters;
use crate::agent_log;
use crate::framing::{FRAME_BINARY, FRAME_JSON};
use crate::if_table;
use crate::npcap::{Npcap, Read};
use crate::pipe::{self, Connection, PipeInstance};
use crate::protocol::{self, CaptureState, Command, Interface, InterfaceStats, ParseError};
use crate::session::{
    available_cores, kernel_buffer_bytes, Drain, FrameQueue, BATCH_INTERVAL_MS,
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

/// How often `interface_stats` goes out to whoever subscribed.
///
/// 500 ms, matching `local-agent/agent.py`'s
/// `INTERFACE_STATS_INTERVAL_SECONDS`, because the app sizes its history window
/// from the `intervalMs` the message carries and the two agents drawing
/// differently-scaled graphs would be a difference nobody could see the cause
/// of.
///
/// **Deliberately not `STATS_INTERVAL`.** That one is 1 s and only ticks while
/// a capture is running; these rates have to move on an idle adapter, which is
/// the entire point of the panel.
pub const INTERFACE_STATS_INTERVAL: Duration = Duration::from_millis(500);

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
    npcap: &'static Npcap,
    interfaces: Mutex<Vec<Interface>>,
    /// Connected clients by id, so the pump can find the owner's.
    clients: Mutex<HashMap<String, Arc<Connection>>>,
    /// Whose capture this is, or none.
    owner: Mutex<Option<String>>,
    /// The device NAMES the client chose - `\Device\NPF_{GUID}` - never list
    /// positions, and **all of them**.
    ///
    /// **Honoured rather than ignored, which it was for one run.** The runtime
    /// used to capture on `interfaces.first()` whatever the client asked for -
    /// so it opened *an* adapter, reported `sniffing` quite truthfully, and
    /// delivered nothing, because the frames were on a different one. Driving
    /// it with the app's own client is what found that; nothing in the unit
    /// tests could, because they never pick an adapter.
    ///
    /// **Then it took `chosen.first()`, which was the same failure one layer
    /// up.** The comment defending that said "the app only ever sends one",
    /// which is true of the mouse and false of the program: `App.tsx` forwards
    /// a restored `meta.selectedInterfaces` verbatim and `useAgentConnection`
    /// resyncs it on reconnect, so a session restored from a two-adapter
    /// capture asked for two and was given one - with no error, no log, and a
    /// status bar reading "2 adapters" over frames from one. Every *other*
    /// selection fault here already had a code (`empty_interfaces`,
    /// `bad_message`, `no_interfaces`); only this one was accepted and
    /// silently truncated.
    ///
    /// Empty until a client says, and there is deliberately no fallback - see
    /// `Command::StartCapture`.
    selected: Mutex<Vec<String>>,
    capture: Mutex<Option<CaptureHandles>>,
    /// Clients that asked for `interface_stats`, by id.
    ///
    /// A set rather than a flag: several windows can watch the rates at once,
    /// and unlike frames there is no reason to send them to one client alone -
    /// these are facts about the machine, not about anybody's capture.
    rate_watchers: Mutex<std::collections::HashSet<String>>,
    /// Clients that asked for `socket_table`, by id.
    ///
    /// Beside `rate_watchers` rather than merged with it: the two have
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
    shutdown: Arc<Shutdown>,
}

/// One selected adapter, inside a running capture.
///
/// **Per adapter rather than per capture**, which is the shape the wire format
/// has always had: `capture_stats` carries an *array* of these and the record's
/// `iface` field names one. The runtime held a single set and captured a single
/// adapter, so the array had one entry by construction.
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
    /// `pcap_stats` for this adapter's handle: (recv, dropped).
    kernel: Arc<Mutex<Option<(u32, u32)>>>,
    /// Why this adapter's sniffer stopped, when it stopped by itself.
    ///
    /// **A worker cannot tear its own capture down.** `stop_capture` joins the
    /// workers, so a worker calling it would wait for itself. So a dying worker
    /// records the reason here instead, and everything that reads the capture's
    /// state reads this too - which is what stops a dead capture reporting
    /// `sniffing` for the rest of the session.
    fault: Mutex<Option<String>>,
}

/// What a running capture owns, so stopping it is one place.
struct CaptureHandles {
    running: Arc<AtomicBool>,
    queue: Arc<FrameQueue>,
    seq: Arc<AtomicU64>,
    /// One entry per selected adapter, in the order they were selected.
    ///
    /// An `Arc` around the whole roster as well as around each entry, because
    /// every worker needs to answer *"am I the last one still alive?"* and the
    /// answer is a property of the set rather than of any member.
    interfaces: Arc<Vec<Arc<CaptureInterface>>>,
    /// Frames the driver handed over and the wire format could not describe -
    /// a fifth loss stage, beside the kernel, the sniffer queue and the pipe.
    /// Its own counter rather than folded into `droppedAgent`: a frame shed
    /// under pressure and a frame too long to encode want opposite responses,
    /// and this file has a comment about exactly that conflation elsewhere.
    oversize: Arc<AtomicU64>,
    /// What the owner's pipe had already shed when this capture started.
    ///
    /// **`droppedPipe` is the one counter that outlives its capture.** It sits
    /// on the `Connection`, and the app holds one across many start/stop
    /// cycles - so sending the raw total made capture #2 report capture #1's
    /// shed packets as its own, and the app adds it straight into per-capture
    /// loss. Every other stage here is already per-capture: the `FrameQueue` is
    /// built inside `start_capture` and the driver's counters reset with the
    /// handle. Without this the stages disagreed about what "this capture"
    /// means inside one agent.
    ///
    /// `local-agent/agent.py` rebases it for the same reason, and says so: *"a
    /// number that accumulated across every capture since the service started
    /// would be read as belonging to the one on screen."*
    dropped_pipe_base: u64,
    workers: Vec<thread::JoinHandle<()>>,
}

/// Whether one selected adapter is still reading.
///
/// A free function rather than a method so it reads as a predicate at the three
/// call sites that ask the roster the same question.
fn alive(per: &Arc<CaptureInterface>) -> bool {
    per.fault.lock().unwrap().is_none()
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
            kernel: *per.kernel.lock().unwrap(),
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
    /// whether a capture handle exists.
    ///
    /// This used to answer `is_some()`, and a capture whose reader had died
    /// kept the handle, so the agent reported `sniffing` for the rest of the
    /// session: no frames, no error, and a status bar reading "Capturing"
    /// against an empty list. That is the state
    /// `local-agent/agent.py`'s `report_capture_failure` was written to end,
    /// and porting the read loop without it brought it back.
    /// With several adapters selected, one still reading is still a capture -
    /// the same line `local-agent/agent.py`'s `mark_failed` draws.
    fn capture_state(&self) -> CaptureState {
        let held = self.capture.lock().unwrap();
        match held.as_ref() {
            Some(handles) if handles.interfaces.iter().any(alive) => CaptureState::Sniffing,
            _ => CaptureState::Idle,
        }
    }

    /// Records why a capture died and tells the owner, once.
    ///
    /// Called from inside a worker, so it must not touch `stop_capture` - see
    /// `CaptureHandles::fault`. The handles are reaped by whatever stops the
    /// capture next: the client's own `stop_capture`, its disconnect, or the
    /// shutdown path. Until then `capture_state` already reads `idle`, so
    /// nothing downstream believes a capture is running.
    ///
    /// **The first reason wins.** A failing read usually makes the next write
    /// fail too, and the second message would describe the consequence rather
    /// than the cause.
    fn fail_capture(
        &self,
        roster: &[Arc<CaptureInterface>],
        per: &Arc<CaptureInterface>,
        reason: String,
    ) {
        {
            let mut held = per.fault.lock().unwrap();
            if held.is_some() {
                return;
            }
            *held = Some(reason.clone());
        }
        crate::log_warn!("capture stopped on interface {}: {reason}", per.iface);
        let owner = self.owner.lock().unwrap().clone();
        if let Some(owner) = owner {
            self.send_to(&owner, &protocol::capture_failed(per.iface, &reason));
        }
        // **Idle only once the last adapter has gone.** With several selected,
        // one dying is a loss of part of the capture rather than the end of
        // it - `local-agent/agent.py`'s `mark_failed` draws the line in the
        // same place and stops only when "every selected interface failed".
        // Reporting idle on the first would take the surviving adapters'
        // frames off the screen while they were still arriving, and the app
        // has the `iface` in the message to say which one went.
        if roster.iter().any(alive) {
            return;
        }
        let interfaces = self.interfaces.lock().unwrap().clone();
        self.broadcast(&protocol::state(CaptureState::Idle, &interfaces, None));
    }

    /// The owner's pipe has gone, which ends the capture on every adapter.
    ///
    /// **Not an adapter fault.** Nothing is wrong with any of them; there is
    /// simply nowhere left to send what they capture, so every one is marked
    /// and the sniffers stop filling a queue nobody will drain. The message
    /// names the adapter whose pump noticed, which is the first - one fault
    /// described once, rather than N copies of one sentence.
    fn fail_transport(&self, roster: &[Arc<CaptureInterface>], reason: String) {
        for per in roster.iter().skip(1) {
            let mut held = per.fault.lock().unwrap();
            if held.is_none() {
                *held = Some(reason.clone());
            }
        }
        if let Some(first) = roster.first() {
            self.fail_capture(roster, first, reason);
        }
    }

    /// Stops the capture if one is running, and answers its final figures.
    ///
    /// **The stats are built before the queue is discarded.** Without that the
    /// last figures the app ever sees are up to a second stale, and a burst in
    /// that last second is invisible - which is exactly when somebody looks.
    fn stop_capture(&self) -> Option<Value> {
        let handles = self.capture.lock().unwrap().take()?;
        handles.running.store(false, Ordering::SeqCst);

        // **The workers are joined before a single counter is read**, and the
        // queue is not discarded until after. Every figure below is then final
        // rather than a snapshot taken while threads were still moving it: a
        // sniffer could previously push after `depth()` was read, and the
        // driver's own counters are now sampled on a timer rather than per
        // frame, so the last sample belongs to the sniffer's exit.
        //
        // The cost is up to one `to_ms` - the sniffers are blocked in
        // `pcap_next_ex` with a 100 ms timeout - on a path that is already
        // stopping. The join was always here; only its position moved.
        for worker in handles.workers {
            let _ = worker.join();
        }

        let (queued, _) = handles.queue.depth();
        // **The owner's pipe drops, not `None`.** Passing None here made the
        // LAST message the app ever sees report `droppedPipe` as unknown, for a
        // stage that had been reported every second up to that point - so the
        // final figures were the only ones with a hole in them, which is
        // precisely where somebody looks when the numbers do not add up. Found
        // by driving this with the app's own client, which asserts that every
        // stage the agent can measure is one it actually reports.
        let dropped_pipe = self
            .owner
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|owner| self.clients.lock().unwrap().get(owner).cloned())
            // Rebased, so the figure describes THIS capture - see
            // `CaptureHandles::dropped_pipe_base`.
            .map(|connection| {
                connection.outbound.dropped().saturating_sub(handles.dropped_pipe_base)
            });
        let mut stats = protocol::capture_stats(
            STATS_INTERVAL.as_millis() as u32,
            handles.seq.load(Ordering::Relaxed),
            handles.queue.dropped(),
            dropped_pipe,
            handles.oversize.load(Ordering::Relaxed),
            &interface_stats(&handles.interfaces),
        );
        // `queuedAtStop` is what the discard is about to throw away. Those frames
        // were captured and never delivered, and they were not lost to pressure -
        // counting them as a drop would report a loss nobody suffered, and
        // leaving them out makes the figures fail to add up, which is how
        // somebody concludes the counters are wrong.
        if let Some(object) = stats.as_object_mut() {
            object.insert("queuedAtStop".into(), serde_json::json!(queued));
        }

        handles.queue.discard();
        *self.owner.lock().unwrap() = None;
        Some(stats)
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
        .map(|(index, device)| Interface {
            id: index,
            label: adapters::label_for(&device.name, device.description.as_deref(), &friendly),
            link_type: datalink_of(npcap, &device.name),
            name: device.name,
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
fn datalink_of(npcap: &Npcap, device: &str) -> Option<i32> {
    static CACHE: Mutex<Option<HashMap<String, Option<i32>>>> = Mutex::new(None);
    let mut held = CACHE.lock().unwrap();
    let cache = held.get_or_insert_with(HashMap::new);
    if let Some(known) = cache.get(device) {
        return *known;
    }
    let answer = npcap.open(device, false).ok().map(|handle| handle.datalink());
    cache.insert(device.to_string(), answer);
    answer
}

/// The adapter report, joined to the capture devices the app knows.
///
/// Keyed by the capture device name rather than by the GUID, because that is
/// what the app joins on - `isValidAdapterList` refuses an entry without one.
/// An adapter Windows knows but Npcap cannot capture on is left out: it could
/// never be attached to an interface, and the app has nowhere to put it.
///
/// `\Device\NPF_Loopback` carries no GUID and so joins to no Windows adapter.
/// It is still reported, with nulls, because its presence is the fact the panel
/// needs - and because a MAC it does not have cannot be missed.
fn adapter_reports(shared: &Arc<Shared>) -> Vec<protocol::AdapterReport> {
    let facts = adapters::adapter_facts();
    let interfaces = shared.interfaces.lock().unwrap().clone();
    interfaces
        .iter()
        .map(|iface| {
            let entry = adapters::guid_of(&iface.name).and_then(|guid| facts.get(&guid));
            protocol::AdapterReport {
                id: iface.name.clone(),
                name: iface.label.clone(),
                description: Some(iface.label.clone()),
                mac: entry.and_then(|f| f.mac.clone()),
                status: entry.and_then(|f| f.status),
                mtu: entry.and_then(|f| f.mtu),
                ipv4: entry
                    .map(|f| f.ipv4.iter().map(|a| (a.address.clone(), a.prefix_length)).collect())
                    .unwrap_or_default(),
                ipv6: entry
                    .map(|f| {
                        f.ipv6.iter().map(|a| (a.address.clone(), a.prefix_length, a.scope)).collect()
                    })
                    .unwrap_or_default(),
                dns_servers: entry.map(|f| f.dns_servers.clone()).unwrap_or_default(),
                dns_suffix: entry.and_then(|f| f.dns_suffix.clone()),
            }
        })
        .collect()
}

/// Starts a capture on every adapter in `chosen`, owned by `client`.
///
/// **Every one of them, which is the change.** This took a single `device` and
/// a single `iface`, and the caller passed it `chosen.first()` - so a selection
/// of two adapters captured one and said nothing. See `Shared::selected`.
///
/// One `FrameQueue` and one pump serve every adapter, because the queue is the
/// capture's shared budget and the batch is the capture's: a pump per adapter
/// would split the ordering window N ways and make the app's 100 ms flush
/// reassemble what this side had just taken apart. The sniffers are one thread
/// per adapter, which is what `local-agent/agent.py` does and is forced here
/// anyway - a `Capture` is `Send` and not `Sync`, so a handle belongs to
/// exactly one thread for its whole life.
///
/// **All the handles are opened before any thread starts.** Opening inside the
/// spawn loop would leave a capture half-running when adapter #2 refused, with
/// #1's sniffer already delivering frames under a call that returned an error.
fn start_capture(shared: &Arc<Shared>, client: &str, chosen: &[Interface]) -> io::Result<()> {
    let mut opened = Vec::new();
    for interface in chosen {
        let capture = shared.npcap.open(&interface.name, true)?;
        // Sized per core: Npcap splits the buffer into one segment per processor
        // and drops when the segment for the receiving core is full, so a flat
        // figure is that figure divided by the core count. See
        // `session::kernel_buffer_bytes`.
        //
        // Per handle, not per capture: the budget is the driver's per-adapter
        // ring, so two adapters is two of these rather than one split in half.
        capture.set_kernel_buffer(kernel_buffer_bytes(available_cores()) as i32)?;
        // Hand frames over as they arrive rather than at Npcap's 16 KB default,
        // which is what scapy asks for and therefore what the Python agent has
        // always had. Not an error when the library does not export it: a
        // capture at the default `mintocopy` is slower to show a frame, not
        // wrong about one.
        capture.set_min_to_copy(0)?;
        opened.push((interface.id, capture));
    }

    let running = Arc::new(AtomicBool::new(true));
    let queue = Arc::new(FrameQueue::with_defaults());
    let seq = Arc::new(AtomicU64::new(0));
    let oversize = Arc::new(AtomicU64::new(0));
    let roster: Arc<Vec<Arc<CaptureInterface>>> = Arc::new(
        opened
            .iter()
            .map(|(iface, _)| {
                Arc::new(CaptureInterface {
                    iface: *iface,
                    received: Arc::new(AtomicU64::new(0)),
                    kernel: Arc::new(Mutex::new(None)),
                    fault: Mutex::new(None),
                })
            })
            .collect(),
    );
    // Read before the first frame can be shed, so the subtraction below can
    // never go negative.
    let dropped_pipe_base = shared
        .clients
        .lock()
        .unwrap()
        .get(client)
        .map(|c| c.outbound.dropped())
        .unwrap_or(0);
    let mut workers = Vec::new();

    // A sniffer per adapter. Encodes on its own thread, so the pump sees
    // finished bytes rather than live driver buffers - which is also what keeps
    // a libpcap handle from ever crossing to another thread.
    //
    // **The sequence number is taken from one counter across every adapter**,
    // and `received` is counted per adapter. That is `CaptureCounters`' split in
    // `agent.py`, and it is what the wire format asks for: `seq` orders the
    // capture, `iface` says where a frame came from, and `capture_stats` reports
    // "received" per interface.
    for ((iface, mut capture), per) in opened.into_iter().zip(roster.iter()) {
        let (run, q, sq, shutdown) = (
            Arc::clone(&running),
            Arc::clone(&queue),
            Arc::clone(&seq),
            Arc::clone(&shared.shutdown),
        );
        let (rx, kn, me) = (Arc::clone(&per.received), Arc::clone(&per.kernel), Arc::clone(per));
        let (ov, sh, owner_id, all) = (
            Arc::clone(&oversize),
            Arc::clone(shared),
            client.to_string(),
            Arc::clone(&roster),
        );
        workers.push(thread::spawn(move || {
            let mut kernel_sampled = Instant::now();
            while run.load(Ordering::SeqCst) && !shutdown.requested() {
                match capture.next() {
                    Ok(Read::Timeout) => {}
                    Ok(Read::Frame { data, ts_us, wire_len }) => {
                        rx.fetch_add(1, Ordering::Relaxed);
                        // **Checked before a sequence number is taken.** The
                        // encoder refuses a frame past 0xFFFF - rightly, since
                        // a masked length desynchronises the decoder - but
                        // taking the number first left a hole in the sequence
                        // for a frame that was never sent, on top of counting
                        // it as received and in no drop counter at all.
                        if data.len() > 0xFFFF {
                            let seen = ov.fetch_add(1, Ordering::Relaxed);
                            if seen == 0 {
                                sh.send_to(&owner_id, &protocol::frame_too_long(iface, data.len()));
                            }
                            continue;
                        }
                        let n = sq.fetch_add(1, Ordering::Relaxed);
                        match wire::encode_record(n as u32, iface as u16, ts_us, wire_len as usize, data) {
                            Ok(record) => q.push(record),
                            // Unreachable while the length check above is the
                            // encoder's only failure, and counted rather than
                            // printed so it cannot become invisible if that
                            // ever stops being true.
                            Err(error) => {
                                ov.fetch_add(1, Ordering::Relaxed);
                                crate::log_warn!("dropping a frame: {error}");
                            }
                        }
                    }
                    Err(error) => {
                        // A removed adapter lands here - an unplugged USB NIC,
                        // a driver reset, a Wi-Fi adapter torn down by a roam.
                        // Stopping is right; the Python agent used to
                        // `continue` on this and spin a core at 100% for ever.
                        // Saying so is what was missing: without it the app
                        // keeps "Capturing" on screen against an empty list.
                        //
                        // **This thread returns and `running` is left alone.**
                        // The flag is the whole capture's, and one adapter
                        // being pulled is not a reason to stop reading the
                        // others - `fail_capture` reports idle only when the
                        // last of them has gone.
                        sh.fail_capture(&all, &me, error.to_string());
                        return;
                    }
                }
                // **`pcap_stats` on a timer, not per frame.** This was one FFI
                // call and one mutex acquisition for every packet, on the
                // thread whose only job is draining the driver's buffer before
                // it overflows - so it spent stage-1 drops in order to measure
                // stage-1 drops. Nothing reads the figure more than once a
                // second. `local-agent/agent.py` polls it off the sniffer
                // thread entirely; here it cannot leave this thread, because a
                // libpcap handle belongs to the one thread that reads it.
                //
                // Half of `STATS_INTERVAL`, so the figure the pump sends is
                // never more than half a tick old.
                if kernel_sampled.elapsed() >= STATS_INTERVAL / 2 {
                    kernel_sampled = Instant::now();
                    if let Some(stats) = capture.stats() {
                        *kn.lock().unwrap() = Some(stats);
                    }
                }
            }
            // The last word, whatever the timer was about to do. `stop_capture`
            // joins the workers before it reads these counters, so this is what
            // the final `capture_stats` carries - and the final drop figure is
            // the one somebody looks at when the numbers do not add up.
            if let Some(stats) = capture.stats() {
                *kn.lock().unwrap() = Some(stats);
            }
        }));
    }

    // The pump. **It sleeps on `Drained` and on nothing else**, which is the
    // whole point of `drain` reporting why it stopped - the Python agent slept
    // on a full queue and capped itself at 16.5 MB/s.
    {
        let (run, q, sq, owner, shared) = (
            Arc::clone(&running),
            Arc::clone(&queue),
            Arc::clone(&seq),
            client.to_string(),
            Arc::clone(shared),
        );
        let (all, ov, base) = (Arc::clone(&roster), Arc::clone(&oversize), dropped_pipe_base);
        workers.push(thread::spawn(move || {
            let mut last_stats = Instant::now();
            while run.load(Ordering::SeqCst) && !shared.shutdown.requested() {
                let (batch, state) = q.drain();
                if !batch.is_empty() {
                    let Ok(payload) = wire::encode_batch(&batch) else { continue };
                    let target = shared.clients.lock().unwrap().get(&owner).cloned();
                    match target {
                        // Frames go to the owner alone. A second window would
                        // otherwise see sequence numbers that are not its own.
                        Some(connection) => {
                            if let Err(error) =
                                connection.send(FRAME_BINARY, &payload, batch.len() as u64)
                            {
                                // The owner's pipe has gone. The sniffers are
                                // still filling a queue nobody will drain, so
                                // this is a stop rather than a return - and it
                                // is the whole capture's, on every adapter,
                                // because none of them has anywhere to send to.
                                run.store(false, Ordering::SeqCst);
                                shared.fail_transport(&all, error.to_string());
                                return;
                            }
                        }
                        // The owner has gone. The disconnect path stops the
                        // capture; returning here just stops feeding a queue
                        // nobody will drain.
                        None => return,
                    }
                }
                if last_stats.elapsed() >= STATS_INTERVAL {
                    last_stats = Instant::now();
                    let dropped_pipe = shared
                        .clients
                        .lock()
                        .unwrap()
                        .get(&owner)
                        .map(|c| c.outbound.dropped().saturating_sub(base));
                    let stats = protocol::capture_stats(
                        STATS_INTERVAL.as_millis() as u32,
                        sq.load(Ordering::Relaxed),
                        q.dropped(),
                        dropped_pipe,
                        ov.load(Ordering::Relaxed),
                        &interface_stats(&all),
                    );
                    shared.send_to(&owner, &stats);
                }
                if state == Drain::Drained {
                    thread::sleep(Duration::from_millis(BATCH_INTERVAL_MS));
                }
            }
        }));
    }

    *shared.capture.lock().unwrap() = Some(CaptureHandles {
        running,
        queue,
        seq,
        interfaces: roster,
        oversize,
        dropped_pipe_base,
        workers,
    });
    *shared.owner.lock().unwrap() = Some(client.to_string());
    Ok(())
}

/// Serves one connected client until its pipe closes.
fn serve(shared: Arc<Shared>, instance: Arc<PipeInstance>, client: String) -> io::Result<()> {
    let connection = Arc::new(Connection::new());
    let total = {
        let mut clients = shared.clients.lock().unwrap();
        clients.insert(client.clone(), Arc::clone(&connection));
        clients.len()
    };
    crate::log_info!("client {client} connected ({total} total)");

    let writer_instance = Arc::clone(&instance);
    let outbound = Arc::clone(&connection.outbound);
    let writer = thread::spawn(move || {
        let _ = pipe::write_loop(&writer_instance, &outbound);
    });

    // The interface list is re-read per connection, which is what makes a
    // reconnect re-enumerate after a driver install - see `AgentPipeLink.recycle`.
    if let Ok(fresh) = read_interfaces(shared.npcap) {
        *shared.interfaces.lock().unwrap() = fresh;
    }
    let interfaces = shared.interfaces.lock().unwrap().clone();
    let _ = connection.send(
        FRAME_JSON,
        protocol::hello(
            crate::VERSION,
            shared.capture_state(),
            &interfaces,
            &client,
            shared.owner.lock().unwrap().clone().as_deref(),
            // **Not ported yet, and `None` is the safe answer.** The Python
            // agent reads the DACL on the Npcap device object
            // (`npcap_access.py`) and sends the SDDL string, never a verdict.
            // `npcapAccess.ts` gives that DACL priority over the registry
            // precisely because the registry can be edited without the driver
            // being restarted - so omitting it falls back to the registry,
            // which is the weaker answer but never the wrongly-permissive one.
            // Sending a stale or invented descriptor would be the direction
            // that must not happen.
            None,
        )
        .to_string()
        .as_bytes(),
        0,
    );

    let result = pipe::read_loop(&instance, |frame| {
        if frame.kind != FRAME_JSON {
            // Binary from the client is not part of the protocol. Ignored rather
            // than treated as a framing failure: the stream position is still
            // known, so there is nothing to resynchronise.
            crate::log_warn!("ignoring a binary frame from {client}");
            return Ok(());
        }
        let text = String::from_utf8_lossy(&frame.payload).to_string();
        let command = match protocol::parse_command(&text) {
            Ok(command) => command,
            Err(ParseError::Unknown(what)) => {
                shared.send_to(&client, &protocol::error(
                    "unknown_command",
                    &format!("This agent does not understand '{what}'."),
                ));
                return Ok(());
            }
            Err(ParseError::EmptyInterfaces) => {
                shared.send_to(&client, &protocol::error(
                    "empty_interfaces",
                    "A capture needs at least one adapter.",
                ));
                return Ok(());
            }
            Err(error) => {
                shared.send_to(&client, &protocol::error("bad_message", &format!("{error:?}")));
                return Ok(());
            }
        };

        // A capture belongs to the client that started it. Fast User Switching
        // is real and the agent is the only thing that can arbitrate.
        let held = shared.owner.lock().unwrap().clone();
        if !protocol::may_run(&command, &client, held.as_deref()) {
            shared.send_to(&client, &protocol::error(
                "capture_busy",
                "Another client is capturing on this machine.",
            ));
            return Ok(());
        }

        match command {
            Command::SetInterfaces(chosen) => {
                // The app sends device NAMES - `\Device\NPF_{GUID}` - which is
                // what `agentProtocol.ts` declares and what `agent.py` spawns a
                // sniffer per. This used to read them as indices, so the app's
                // message did not parse at all.
                //
                // **All of them.** This took `chosen.first()` on the argument
                // that "the app only ever sends one", which is true of the
                // mouse and false of the program - see `Shared::selected`.
                //
                // Stored rather than validated here, because the list this
                // would be checked against is re-read per connection and the
                // adapter could go between the two messages anyway.
                // `start_capture` resolves every name and refuses the whole
                // selection if any of them is gone, which is one answer at the
                // moment it matters instead of two that can disagree.
                crate::log_info!("set_interfaces: {} interface(s) selected", chosen.len());
                *shared.selected.lock().unwrap() = chosen;
                let interfaces = shared.interfaces.lock().unwrap().clone();
                shared.send_to(&client, &protocol::state(
                    shared.capture_state(),
                    &interfaces,
                    shared.owner.lock().unwrap().clone().as_deref(),
                ));
            }
            Command::StartCapture => {
                if shared.capture.lock().unwrap().is_some() {
                    return Ok(());
                }
                let interfaces = shared.interfaces.lock().unwrap().clone();
                let wanted = shared.selected.lock().unwrap().clone();

                // **No fallback to "whatever is first", and that absence is the
                // fix.** This used to end `.or_else(|| interfaces.first())`, so
                // a selection that did not arrive - which is what happened for
                // every real capture, because the names did not parse - became
                // a capture on adapter 0. On this machine adapter 0 is a dead
                // `WAN Miniport`: the agent opened it, reported `sniffing`
                // perfectly truthfully, and delivered nothing for ever.
                //
                // A guess is the one answer this must not give. The app always
                // sends `set_interfaces` before `start_capture` - including on
                // reconnect - and says so in `App.tsx`: "starting always names
                // exactly one adapter, so there is no way to begin capturing
                // without having said where from". So an absent or unknown
                // selection is a real fault, and saying so puts a sentence in
                // front of somebody instead of an empty packet list.
                if wanted.is_empty() {
                    shared.send_to(&client, &protocol::error(
                        "no_interfaces",
                        "No adapter has been chosen. Send set_interfaces before start_capture.",
                    ));
                    return Ok(());
                }
                // **Every name resolved, and the whole selection refused if any
                // of them cannot be.** Capturing on the ones that are left
                // would be the silent truncation this fixed, arriving by
                // another door: the app would show two adapters, one would
                // deliver, and the only sign would be a row whose counters
                // never moved.
                let mut chosen = Vec::with_capacity(wanted.len());
                for name in &wanted {
                    let Some(found) = interfaces.iter().find(|i| &i.name == name).cloned() else {
                        shared.send_to(&client, &protocol::error(
                            "no_interfaces",
                            &format!("No capture adapter named '{name}'. It may have been removed."),
                        ));
                        return Ok(());
                    };
                    chosen.push(found);
                }
                crate::log_info!("start_capture requested on {} interface(s)", chosen.len());
                if let Err(error) = start_capture(&shared, &client, &chosen) {
                    shared.send_to(&client, &protocol::error(
                        "capture_failed",
                        &format!("Could not start capturing: {error}"),
                    ));
                    return Ok(());
                }
                shared.broadcast(&protocol::state(
                    CaptureState::Sniffing,
                    &interfaces,
                    Some(&client),
                ));
            }
            Command::StopCapture => {
                crate::log_info!("stop_capture requested");
                if let Some(final_stats) = shared.stop_capture() {
                    shared.send_to(&client, &final_stats);
                }
                let interfaces = shared.interfaces.lock().unwrap().clone();
                shared.broadcast(&protocol::state(CaptureState::Idle, &interfaces, None));
            }
            Command::SubscribeInterfaceStats => {
                shared.rate_watchers.lock().unwrap().insert(client.clone());
            }
            Command::UnsubscribeInterfaceStats => {
                shared.rate_watchers.lock().unwrap().remove(&client);
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
            Command::SubscribeAdapters | Command::RefreshAdapters => {
                // A whole snapshot, not a delta, and sent on subscribe rather
                // than on a timer: a machine has a handful of adapters and the
                // message is a couple of kilobytes. The app subscribes from
                // `hello`, so this is what fills `host.macs` and with it every
                // frame's direction.
                shared.send_to(&client, &protocol::adapter_config(&adapter_reports(&shared)));
            }
            _ => {
                // Subscriptions this agent does not serve yet. Answered rather
                // than ignored: silence is the shape the app cannot diagnose.
                let interfaces = shared.interfaces.lock().unwrap().clone();
                shared.send_to(&client, &protocol::state(
                    shared.capture_state(),
                    &interfaces,
                    shared.owner.lock().unwrap().clone().as_deref(),
                ));
            }
        }
        Ok(())
    });

    // The client has gone. Deregister first, so nothing tries to send to it
    // while the capture is being torn down.
    let left = {
        let mut clients = shared.clients.lock().unwrap();
        clients.remove(&client);
        clients.len()
    };
    crate::log_info!("client {client} disconnected ({left} left)");
    shared.rate_watchers.lock().unwrap().remove(&client);
    shared.log_watchers.lock().unwrap().remove(&client);
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
    if shared.owner.lock().unwrap().as_deref() == Some(client.as_str()) {
        shared.stop_capture();
        let interfaces = shared.interfaces.lock().unwrap().clone();
        shared.broadcast(&protocol::state(CaptureState::Idle, &interfaces, None));
    }
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
    let npcap: &'static Npcap = Box::leak(Box::new(Npcap::load()?));
    let interfaces = read_interfaces(npcap).unwrap_or_default();

    let shared = Arc::new(Shared {
        npcap,
        interfaces: Mutex::new(interfaces),
        clients: Mutex::new(HashMap::new()),
        owner: Mutex::new(None),
        selected: Mutex::new(Vec::new()),
        capture: Mutex::new(None),
        rate_watchers: Mutex::new(std::collections::HashSet::new()),
        socket_watchers: Mutex::new(std::collections::HashSet::new()),
        sockets: Mutex::new(sockets::SocketTracker::new()),
        log_watchers: Mutex::new(HashMap::new()),
        shutdown: Arc::clone(&shutdown),
    });

    // One accept thread per instance. A client disconnecting frees its instance
    // rather than the server, so the pipe name stays served throughout.
    let mut acceptors = Vec::new();
    for slot in 0..pipe::MAX_INSTANCES {
        let shared = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        let name = name.to_string();
        acceptors.push(thread::spawn(move || {
            let mut serial = 0u64;
            while !shutdown.requested() {
                let instance =
                    match pipe::create_instance(&name, pipe::PIPE_SDDL, pipe::MAX_INSTANCES) {
                        Ok(instance) => Arc::new(instance),
                        Err(error) => {
                            // The one failure that must not be retried in a tight
                            // loop: if the name cannot be created at all, the
                            // agent has nothing to offer and says so once.
                            crate::log_error!("could not create a pipe instance: {error}");
                            shutdown.request("the pipe could not be served");
                            return;
                        }
                    };
                if pipe::accept(&instance).is_err() {
                    continue;
                }
                if shutdown.requested() {
                    return;
                }
                serial += 1;
                let client = format!("rs-{slot}-{serial}");
                let _ = serve(Arc::clone(&shared), instance, client);
            }
        }));
    }

    // The rate sampler. One thread for the whole agent rather than one per
    // subscriber: the OS counters are read once however many windows are
    // watching, and a second reader would difference the same table against a
    // different previous sample.
    {
        let shared = Arc::clone(&shared);
        let shutdown = Arc::clone(&shutdown);
        thread::spawn(move || {
            let mut sampler = if_table::RateSampler::new();
            while !shutdown.requested() {
                thread::sleep(INTERFACE_STATS_INTERVAL);
                let watchers: Vec<String> =
                    shared.rate_watchers.lock().unwrap().iter().cloned().collect();
                if watchers.is_empty() {
                    continue;
                }
                let devices: Vec<String> = shared
                    .interfaces
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|i| i.name.clone())
                    .collect();
                let rates = sampler.rates(&devices);
                // The first tick after a subscription has no interval behind it
                // and yields nothing. Sending an empty list would draw a zero
                // that was never measured.
                if rates.is_empty() {
                    continue;
                }
                let message = protocol::interface_stats(
                    INTERFACE_STATS_INTERVAL.as_millis() as u32,
                    &rates,
                );
                for watcher in watchers {
                    shared.send_to(&watcher, &message);
                }
            }
        });
    }

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
                if shared.capture.lock().unwrap().is_some() {
                    shared.stop_capture();
                }
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
    shared.stop_capture();
    // The acceptors are blocked in `accept`; a connection of our own is what
    // releases them, and each checks `requested()` immediately after.
    for _ in 0..pipe::MAX_INSTANCES {
        let _ = pipe::poke(name);
    }
    for acceptor in acceptors {
        let _ = acceptor.join();
    }
    Ok(())
}
