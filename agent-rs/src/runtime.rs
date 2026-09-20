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
use crate::framing::{FRAME_BINARY, FRAME_JSON};
use crate::npcap::{Npcap, Read};
use crate::pipe::{self, Connection, PipeInstance};
use crate::protocol::{self, CaptureState, Command, Interface, InterfaceStats, ParseError};
use crate::session::{
    available_cores, kernel_buffer_bytes, Drain, FrameQueue, BATCH_INTERVAL_MS,
};
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
    /// Which adapter the client chose, by its index in `interfaces`.
    ///
    /// **Honoured rather than ignored, which it was for one run.** The runtime
    /// used to capture on `interfaces.first()` whatever the client asked for -
    /// so it opened *an* adapter, reported `sniffing` quite truthfully, and
    /// delivered nothing, because the frames were on a different one. Driving
    /// it with the app's own client is what found that; nothing in the unit
    /// tests could, because they never pick an adapter.
    ///
    /// `None` until a client says. Capture then falls back to the first, which
    /// is what the app's own default does on a fresh connection.
    /// The device NAME the app asked for, never a list position.
    selected: Mutex<Option<String>>,
    capture: Mutex<Option<CaptureHandles>>,
    shutdown: Arc<Shutdown>,
}

/// What a running capture owns, so stopping it is one place.
struct CaptureHandles {
    running: Arc<AtomicBool>,
    queue: Arc<FrameQueue>,
    seq: Arc<AtomicU64>,
    received: Arc<AtomicU64>,
    kernel: Arc<Mutex<Option<(u32, u32)>>>,
    iface: usize,
    workers: Vec<thread::JoinHandle<()>>,
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

    fn capture_state(&self) -> CaptureState {
        if self.capture.lock().unwrap().is_some() {
            CaptureState::Sniffing
        } else {
            CaptureState::Idle
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
            .map(|connection| connection.outbound.dropped());
        let mut stats = protocol::capture_stats(
            STATS_INTERVAL.as_millis() as u32,
            handles.seq.load(Ordering::Relaxed),
            handles.queue.dropped(),
            dropped_pipe,
            &[InterfaceStats {
                iface: handles.iface,
                received: handles.received.load(Ordering::Relaxed),
                kernel: *handles.kernel.lock().unwrap(),
            }],
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
        for worker in handles.workers {
            let _ = worker.join();
        }
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
            name: device.name,
        })
        .collect())
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

/// Starts a capture on one adapter, owned by `client`.
fn start_capture(shared: &Arc<Shared>, client: &str, device: &str, iface: usize) -> io::Result<()> {
    let mut capture = shared.npcap.open(device, true)?;
    // Sized per core: Npcap splits the buffer into one segment per processor and
    // drops when the segment for the receiving core is full, so a flat figure is
    // that figure divided by the core count. See `session::kernel_buffer_bytes`.
    capture.set_kernel_buffer(kernel_buffer_bytes(available_cores()) as i32)?;

    let running = Arc::new(AtomicBool::new(true));
    let queue = Arc::new(FrameQueue::with_defaults());
    let seq = Arc::new(AtomicU64::new(0));
    let received = Arc::new(AtomicU64::new(0));
    let kernel = Arc::new(Mutex::new(None::<(u32, u32)>));
    let mut workers = Vec::new();

    // The sniffer. Encodes on this thread, so the pump sees finished bytes
    // rather than live driver buffers - which is also what keeps a libpcap
    // handle from ever crossing to another thread.
    {
        let (run, q, sq, rx, kn, shutdown) = (
            Arc::clone(&running),
            Arc::clone(&queue),
            Arc::clone(&seq),
            Arc::clone(&received),
            Arc::clone(&kernel),
            Arc::clone(&shared.shutdown),
        );
        workers.push(thread::spawn(move || {
            while run.load(Ordering::SeqCst) && !shutdown.requested() {
                match capture.next() {
                    Ok(Read::Timeout) => {}
                    Ok(Read::Frame { data, ts_us, wire_len }) => {
                        let n = sq.fetch_add(1, Ordering::Relaxed);
                        rx.fetch_add(1, Ordering::Relaxed);
                        match wire::encode_record(n as u32, iface as u16, ts_us, wire_len as usize, data) {
                            Ok(record) => q.push(record),
                            // Refused rather than masked: a masked length
                            // desynchronises the decoder and costs a whole batch.
                            Err(error) => eprintln!("dropping a frame: {error}"),
                        }
                    }
                    Err(error) => {
                        // A removed adapter lands here. Stopping is right; the
                        // Python agent used to `continue` on this and spin a
                        // core at 100% for ever.
                        eprintln!("capture failed: {error}");
                        run.store(false, Ordering::SeqCst);
                        return;
                    }
                }
                if let Some(stats) = capture.stats() {
                    *kn.lock().unwrap() = Some(stats);
                }
            }
        }));
    }

    // The pump. **It sleeps on `Drained` and on nothing else**, which is the
    // whole point of `drain` reporting why it stopped - the Python agent slept
    // on a full queue and capped itself at 16.5 MB/s.
    {
        let (run, q, sq, rx, kn, owner, shared) = (
            Arc::clone(&running),
            Arc::clone(&queue),
            Arc::clone(&seq),
            Arc::clone(&received),
            Arc::clone(&kernel),
            client.to_string(),
            Arc::clone(shared),
        );
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
                            if connection
                                .send(FRAME_BINARY, &payload, batch.len() as u64)
                                .is_err()
                            {
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
                        .map(|c| c.outbound.dropped());
                    let stats = protocol::capture_stats(
                        STATS_INTERVAL.as_millis() as u32,
                        sq.load(Ordering::Relaxed),
                        q.dropped(),
                        dropped_pipe,
                        &[InterfaceStats {
                            iface,
                            received: rx.load(Ordering::Relaxed),
                            kernel: *kn.lock().unwrap(),
                        }],
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
        received,
        kernel,
        iface,
        workers,
    });
    *shared.owner.lock().unwrap() = Some(client.to_string());
    Ok(())
}

/// Serves one connected client until its pipe closes.
fn serve(shared: Arc<Shared>, instance: Arc<PipeInstance>, client: String) -> io::Result<()> {
    let connection = Arc::new(Connection::new());
    shared
        .clients
        .lock()
        .unwrap()
        .insert(client.clone(), Arc::clone(&connection));

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
            eprintln!("ignoring a binary frame from {client}");
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
                // One adapter: capture is single-interface here, and taking the
                // first of several is a smaller lie than pretending to merge
                // them - the app only ever sends one.
                *shared.selected.lock().unwrap() = chosen.first().cloned();
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
                let Some(wanted) = wanted else {
                    shared.send_to(&client, &protocol::error(
                        "no_interfaces",
                        "No adapter has been chosen. Send set_interfaces before start_capture.",
                    ));
                    return Ok(());
                };
                let Some(chosen) = interfaces.iter().find(|i| i.name == wanted).cloned() else {
                    shared.send_to(&client, &protocol::error(
                        "no_interfaces",
                        &format!("No capture adapter named '{wanted}'. It may have been removed."),
                    ));
                    return Ok(());
                };
                if let Err(error) = start_capture(&shared, &client, &chosen.name, chosen.id) {
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
                if let Some(final_stats) = shared.stop_capture() {
                    shared.send_to(&client, &final_stats);
                }
                let interfaces = shared.interfaces.lock().unwrap().clone();
                shared.broadcast(&protocol::state(CaptureState::Idle, &interfaces, None));
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
    shared.clients.lock().unwrap().remove(&client);
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
        selected: Mutex::new(None),
        capture: Mutex::new(None),
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
                            eprintln!("could not create a pipe instance: {error}");
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
    eprintln!("shutting down: {reason}");
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
