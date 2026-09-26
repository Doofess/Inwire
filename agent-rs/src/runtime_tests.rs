//! The runtime end to end.
//!
//! `control.rs` tests every lifecycle decision against fakes. These drive the
//! real runtime for what a fake cannot show, in two harnesses:
//!
//! - **Over a real named pipe** with the production descriptor and the app's
//!   framing: that a machine without Npcap is served, and finds Npcap once it
//!   arrives, without the agent restarting; and that a stop with a client
//!   connected finishes. No frames cross the pipe in these.
//! - **Over the real capture threads** - `start_capture`'s sniffers and pump,
//!   `reap`, `halt` - fed the **real frames** of `test/fixtures/*.pcap`, read
//!   through Npcap's own `pcap_open_offline` exactly as a live adapter's are,
//!   with the clients as real `Connection`s whose outbound queues the test
//!   drains the way the pipe's writer would. This is the wiring for a capture
//!   that ends itself, which no test reached: the review found `reap` could be
//!   emptied, and the pump could stop calling `owner_gone`, with every test
//!   still passing.
//!
//! Everything that needs something this machine may not have - Npcap, the
//! fixtures, an account the pipe's descriptor admits - says `SKIP` and passes,
//! because a GitHub `windows-latest` runner has none of the first two and is a
//! legal place to run this.

use super::*;

use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::windows::io::AsRawHandle;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::mpsc;

use serde_json::json;

use crate::fixture;
use crate::framing::FrameReader;
use crate::outbound::Item;

#[link(name = "kernel32")]
extern "system" {
    fn PeekNamedPipe(
        pipe: *mut std::ffi::c_void,
        buffer: *mut u8,
        size: u32,
        read: *mut u32,
        available: *mut u32,
        left: *mut u32,
    ) -> i32;
}

/// Waits for `condition`, polling, for at most `within`.
fn eventually(within: Duration, condition: impl Fn() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if condition() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

// --- the pipe harness ---------------------------------------------------------

/// A pipe name nothing else uses - never the production one, which belongs to
/// the installed service.
fn private_pipe(tag: &str) -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!(
        r"\\.\pipe\inwire-rs-test-{}-{tag}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )
}

/// A client speaking the app's framing.
///
/// **It reads only what `PeekNamedPipe` says has arrived.** The handle is a
/// synchronous one, and a read blocked on it would hold the handle against the
/// next write - `pipe.rs`'s module note, seen from the client's side.
struct Client {
    pipe: File,
}

impl Client {
    /// Connects, waiting for the server to come up. `None` - after a `SKIP` -
    /// when the descriptor refuses this account: it admits the interactive
    /// user, SYSTEM and administrators, and a CI runner's service account can
    /// be none of the three. That is the descriptor working, not a failure.
    fn connect(name: &str) -> Option<Client> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match OpenOptions::new().read(true).write(true).open(name) {
                Ok(pipe) => return Some(Client { pipe }),
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    eprintln!(
                        "SKIP  the pipe's descriptor does not admit this account ({error}) - \
                         it is neither interactive nor an administrator"
                    );
                    return None;
                }
                Err(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
                Err(error) => panic!("could not connect to {name}: {error}"),
            }
        }
    }

    /// Bytes waiting, or `None` once the agent has closed its end.
    fn available(&self) -> Option<u32> {
        let mut available = 0u32;
        let ok = unsafe {
            PeekNamedPipe(
                self.pipe.as_raw_handle() as _,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut available,
                std::ptr::null_mut(),
            )
        };
        (ok != 0).then_some(available)
    }

    fn wait_for(&self, bytes: usize, deadline: Instant) -> bool {
        loop {
            match self.available() {
                Some(n) if n as usize >= bytes => return true,
                None => return false,
                _ => {}
            }
            if Instant::now() >= deadline {
                return false;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// The next control message, or `None` if none arrived in time or the pipe
    /// closed. Binary frames are skipped: nothing here captures.
    fn next_within(&mut self, within: Duration) -> Option<Value> {
        let deadline = Instant::now() + within;
        loop {
            if !self.wait_for(5, deadline) {
                return None;
            }
            let mut header = [0u8; 5];
            self.pipe.read_exact(&mut header).ok()?;
            let length = (u32::from_le_bytes(header[..4].try_into().unwrap()) as usize).saturating_sub(1);
            if !self.wait_for(length, deadline) {
                return None;
            }
            let mut payload = vec![0u8; length];
            self.pipe.read_exact(&mut payload).ok()?;
            if header[4] == FRAME_JSON {
                return serde_json::from_slice(&payload).ok();
            }
        }
    }

    fn next(&mut self) -> Value {
        self.next_within(Duration::from_secs(10)).expect("a message from the agent")
    }

    fn send(&mut self, text: &str) {
        let frame = crate::framing::encode_json(text).expect("a small frame");
        self.pipe.write_all(&frame).expect("the pipe takes a command");
    }
}

fn serve_in_background(
    name: &str,
    hardware: Hardware,
) -> (Arc<Shutdown>, thread::JoinHandle<io::Result<()>>) {
    let shutdown = Arc::new(Shutdown::new());
    let server = {
        let (shutdown, name) = (Arc::clone(&shutdown), name.to_string());
        thread::spawn(move || run_with(shutdown, &name, hardware))
    };
    (shutdown, server)
}

/// Asks for a stop the way the SCM's handler does, and answers how long the
/// runtime took to return.
fn stop(shutdown: Arc<Shutdown>, server: thread::JoinHandle<io::Result<()>>) -> Duration {
    let asked = Instant::now();
    shutdown.request("the service control manager asked");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(server.join());
    });
    match rx.recv_timeout(SHUTDOWN_GRACE * 5) {
        Ok(result) => result
            .expect("the runtime did not panic")
            .expect("the runtime returned cleanly"),
        Err(_) => panic!("the runtime had not returned {:?} after the stop was asked for", SHUTDOWN_GRACE * 5),
    }
    asked.elapsed()
}

static NPCAP_ARRIVED: AtomicBool = AtomicBool::new(false);

/// Npcap as a machine sees it before the Update Center has installed it - until
/// the test says it has.
fn npcap_installed_later() -> io::Result<Npcap> {
    if NPCAP_ARRIVED.load(Ordering::SeqCst) {
        Npcap::load()
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "could not load wpcap.dll: The specified module could not be found. (os error 126)",
        ))
    }
}

/// **Must-fix 1.** The runtime used to `Npcap::load()?` at start-up, so without
/// Npcap there was no pipe at all. `agent.py` serves it with an empty interface
/// list (agent.py:2024-2028, 2349-2360); and because the load is retried per
/// connection, Npcap installed under the running agent is found by the next
/// connection with nothing restarted.
///
/// On the way, the refusals that need no adapter are checked over the real
/// pipe against `agent.py`'s texts: a start with nothing to capture on,
/// `restart_agent` from a process that is not the service (agent.py:1354-1364),
/// text that is not a command (ignored, agent.py:1186-1191) and an unknown
/// command (named, agent.py:1374-1378).
#[test]
fn a_machine_without_npcap_is_served_and_finds_it_once_installed() {
    let name = private_pipe("late-npcap");
    let (shutdown, server) = serve_in_background(
        &name,
        Hardware { load: npcap_installed_later, ..Hardware::NPCAP },
    );

    let Some(mut first) = Client::connect(&name) else {
        stop(shutdown, server);
        return;
    };
    let hello = first.next();
    assert_eq!(hello["type"], "hello");
    assert_eq!(hello["interfaces"], json!([]), "no Npcap is no adapters, not no agent");
    assert_eq!(hello["state"], "idle");

    first.send(r#"{"type":"start_capture"}"#);
    assert_eq!(first.next(), control::no_interfaces());
    let state = first.next();
    assert_eq!((state["type"].as_str(), state["state"].as_str()), (Some("state"), Some("idle")));
    assert!(state["owner"].is_null());

    first.send(r#"{"type":"restart_agent"}"#);
    assert_eq!(
        first.next(),
        json!({ "type": "error", "code": "restart_unavailable", "message": restart::NOT_THE_SERVICE }),
        "a test process is not the service, so exiting would be a stop nothing undoes"
    );

    first.send("not json at all");
    first.send("[1, 2]");
    first.send(r#"{"type":"teleport"}"#);
    assert_eq!(
        first.next()["message"],
        format!("This agent ({}) does not understand 'teleport'.", crate::VERSION),
        "the two lines before it were ignored, and this is the next message"
    );
    drop(first);

    // The Update Center installs Npcap under the running agent, then recycles
    // the pipe.
    NPCAP_ARRIVED.store(true, Ordering::SeqCst);
    if Npcap::load().is_err() {
        eprintln!("SKIP  Npcap is not installed on this machine, so there is nothing to arrive");
        stop(shutdown, server);
        return;
    }
    let mut second = Client::connect(&name).expect("admitted a moment ago");
    let hello = second.next();
    assert_eq!(hello["type"], "hello");
    assert!(
        !hello["interfaces"].as_array().unwrap().is_empty(),
        "the next connection lists the adapters, and nothing was restarted"
    );
    drop(second);
    stop(shutdown, server);
}

/// **Must-fix 9.** A stop with a client connected used to join the thread
/// serving that client, which sat in a read for the app's next command - so an
/// SCM stop with Inwire open never finished, and the SCM's own wait ran out.
/// `pipe::disconnect` ends the session from outside now.
///
/// **The bound is the backstop, not a stopwatch.** The stop measures ~20 ms
/// here, but a CI runner can be slow by an order of magnitude, and a timing
/// test that fails on a busy machine teaches people to ignore it. What the
/// assertion has to tell apart is the fix from its absence, and without
/// `pipe::disconnect` a connected client pins its thread until `SHUTDOWN_GRACE`
/// runs out - so anything under it is the sessions having ended, however
/// slowly. (Verified by removing the disconnect: the stop then takes 3.0 s.)
///
/// This is the path the SCM's `Stop` takes (`service.rs` requests the same
/// `Shutdown`); the service itself cannot be driven without elevation.
#[test]
fn a_stop_with_a_client_connected_finishes_promptly() {
    let name = private_pipe("stop");
    let (shutdown, server) = serve_in_background(&name, Hardware::NPCAP);

    let Some(mut client) = Client::connect(&name) else {
        stop(shutdown, server);
        return;
    };
    assert_eq!(client.next()["type"], "hello");
    // Connected, and silent: the serving thread is blocked in its read.
    let took = stop(shutdown, server);
    eprintln!("stop with a client connected took {} ms", took.as_millis());
    assert!(
        took < SHUTDOWN_GRACE,
        "took {took:?} - the backstop ended it, so the client's session was not"
    );
    assert!(
        client.next_within(Duration::from_secs(1)).is_none(),
        "and the client's pipe is closed rather than left hanging"
    );
}

// --- the capture harness --------------------------------------------------------

/// The capture tests share `CAPTURE_THREADS`, which is the process's; one at a
/// time, or one test's threads would be counted in another's.
static CAPTURING: Mutex<()> = Mutex::new(());

/// The device name the fixture capture is listed under.
const FIXTURE_DEVICE: &str = "fixture:inwire";
const FIXTURE_LABEL: &str = "the inwire fixture";

fn fixture_file() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join("fixtures")
        .join(fixture::CAPTURES[0]);
    path.exists().then_some(path)
}

/// The device list the capture tests see: the fixture capture as adapter 0,
/// and this machine's real loopback adapter - by the name Npcap gives it - as
/// adapter 1, when Npcap has one.
fn fixture_devices(npcap: &Npcap) -> io::Result<Vec<Interface>> {
    let mut list = vec![Interface {
        id: 0,
        name: FIXTURE_DEVICE.into(),
        label: FIXTURE_LABEL.into(),
        link_type: Some(1),
    }];
    if let Some(loopback) =
        npcap.devices()?.into_iter().find(|d| d.name.to_ascii_lowercase().contains("loopback"))
    {
        list.push(Interface {
            id: 1,
            name: loopback.name,
            label: "Adapter for loopback traffic capture".into(),
            link_type: None,
        });
    }
    Ok(list)
}

/// The fixture through `pcap_open_offline`; anything else as a live adapter.
///
/// **The loopback adapter is opened for what it does with no traffic**: its
/// sniffer sits in `pcap_next_ex`'s timeout, looping for as long as its
/// capture runs and not a moment longer. That makes it the witness for whether
/// a dead capture's threads were stopped - it never ends on its own. What it
/// captures, if the machine happens to send anything over loopback, is
/// counted and dropped with the rest, never looked at.
fn fixture_open(npcap: &'static Npcap, iface: &Interface) -> io::Result<Capture<'static>> {
    if iface.name == FIXTURE_DEVICE {
        npcap.open_file(&fixture_file().expect("checked before the capture started"))
    } else {
        npcap.open(&iface.name, true)
    }
}

/// Everything a drained connection received, decoded the way the app decodes
/// it.
#[derive(Default)]
struct Received {
    control: Vec<Value>,
    frames: Vec<crate::wire::Record>,
}

/// The real runtime minus the pipe: `Shared` as `run_with` builds it, over the
/// fixture hardware, with clients registered as real `Connection`s.
struct Rig {
    shared: Arc<Shared>,
    frames: Vec<fixture::Frame>,
    has_loopback: bool,
    baseline: usize,
    _serial: std::sync::MutexGuard<'static, ()>,
}

impl Rig {
    /// `None`, after a `SKIP`, where this machine lacks Npcap or the fixture.
    fn new() -> Option<Rig> {
        let serial = CAPTURING.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if fixture_file().is_none() {
            eprintln!("SKIP  {} not present (test/fixtures/README.md)", fixture::CAPTURES[0]);
            return None;
        }
        if Npcap::load().is_err() {
            eprintln!("SKIP  Npcap is not installed on this machine");
            return None;
        }
        let frames = fixture::frames(fixture::CAPTURES[0])?;
        let hardware = Hardware { devices: fixture_devices, open: fixture_open, ..Hardware::NPCAP };
        let shared = new_shared(
            &Arc::new(Shutdown::new()),
            hardware,
            RestartSupport { allowed: false, reason: restart::NOT_THE_SERVICE.into() },
        );
        refresh_interfaces(&shared);
        let has_loopback = shared.interfaces.lock().unwrap().len() > 1;
        Some(Rig {
            shared,
            frames,
            has_loopback,
            baseline: CAPTURE_THREADS.load(Ordering::SeqCst),
            _serial: serial,
        })
    }

    /// Registers `client` and drains its queue the way the pipe's writer
    /// would, decoding what arrives.
    fn connect(&self, client: &str) -> (Arc<Connection>, Arc<Mutex<Received>>) {
        let connection = Arc::new(Connection::new());
        self.shared.clients.lock().unwrap().insert(client.into(), Arc::clone(&connection));
        let received = Arc::new(Mutex::new(Received::default()));
        let (queue, into) = (Arc::clone(&connection.outbound), Arc::clone(&received));
        thread::spawn(move || {
            while let Item::Frame(bytes, _) = queue.pop() {
                for frame in FrameReader::new().push(&bytes).expect("the agent frames what it sends") {
                    let mut held = into.lock().unwrap();
                    if frame.kind == FRAME_JSON {
                        held.control.push(serde_json::from_slice(&frame.payload).unwrap());
                    } else {
                        held.frames.extend(crate::wire::decode_batch(&frame.payload).unwrap());
                    }
                }
            }
        });
        (connection, received)
    }

    /// A client whose pipe refuses everything - the writer has given up on it,
    /// and the client is still in the table.
    fn connect_refusing(&self, client: &str) -> Arc<Connection> {
        let connection = Arc::new(Connection::new());
        connection.outbound.shutdown();
        self.shared.clients.lock().unwrap().insert(client.into(), Arc::clone(&connection));
        connection
    }

    fn command(&self, client: &str, command: Command) {
        assert!(self.shared.control.command(&*self.shared, &Live { shared: &self.shared }, client, &command));
    }

    fn threads(&self) -> usize {
        CAPTURE_THREADS.load(Ordering::SeqCst).saturating_sub(self.baseline)
    }
}

impl Drop for Rig {
    /// Whatever a failed assertion left running is stopped, so it cannot be
    /// counted by the next test.
    fn drop(&mut self) {
        self.shared.control.shutdown(&Live { shared: &self.shared });
        for connection in self.shared.clients.lock().unwrap().values() {
            connection.outbound.shutdown();
        }
    }
}

fn idle() -> (String, Value) {
    ("idle".to_string(), Value::Null)
}

fn states(received: &Mutex<Received>) -> Vec<(String, Value)> {
    received
        .lock()
        .unwrap()
        .control
        .iter()
        .filter(|m| m["type"] == "state")
        .map(|m| (m["state"].as_str().unwrap().to_string(), m["owner"].clone()))
        .collect()
}

/// **The last adapter dying ends the capture, over the real threads.** A real
/// capture file ends with `pcap_next_ex` answering -2, which is how a removed
/// adapter answers too (-1): the sniffer reports it, it was the only adapter,
/// so the capture is stopped, every client is told `capture_failed` and then
/// `idle` with no owner, and its threads end (agent.py:1490-1516).
///
/// On the way it holds the frame path to the fixture: every frame the owner
/// was delivered is the capture file's own - bytes, wire length and driver
/// timestamp - in order, under a sequence that starts at 0 and has no hole.
#[test]
fn the_last_adapter_dying_stops_the_capture_and_its_threads() {
    let Some(rig) = Rig::new() else { return };
    let (_owner, delivered) = rig.connect("owner");
    let (_watcher, watched) = rig.connect("watcher");

    rig.command("owner", Command::SetInterfaces(vec![FIXTURE_DEVICE.into()]));
    rig.command("owner", Command::StartCapture);

    assert!(
        eventually(Duration::from_secs(10), || rig.shared.control.capture_state() == CaptureState::Idle),
        "the capture outlived its only adapter"
    );
    assert!(
        eventually(Duration::from_secs(5), || rig.threads() == 0),
        "{} capture thread(s) outlived the capture",
        rig.threads()
    );
    assert_eq!(rig.shared.control.owner(), None);

    // The selection's own answer, the start's, and the end's.
    let told = [idle(), ("sniffing".to_string(), json!("owner")), idle()];
    assert!(
        eventually(Duration::from_secs(5), || states(&watched) == told),
        "the watcher was told {:?}",
        states(&watched)
    );
    let failed: Vec<Value> = watched
        .lock()
        .unwrap()
        .control
        .iter()
        .filter(|m| m["code"] == "capture_failed")
        .cloned()
        .collect();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["iface"], 0);
    let message = failed[0]["message"].as_str().unwrap();
    assert!(
        message.starts_with(&format!("Could not capture on {FIXTURE_LABEL}: pcap_next_ex failed (-2)")),
        "{message}"
    );

    assert!(
        eventually(Duration::from_secs(5), || !delivered.lock().unwrap().frames.is_empty()),
        "the pump delivered nothing before the capture ended"
    );
    let got = delivered.lock().unwrap();
    for (n, record) in got.frames.iter().enumerate() {
        let original = &rig.frames[record.seq as usize];
        assert_eq!(record.seq as usize, n, "a hole or a reordering in the sequence");
        assert_eq!(record.iface, 0);
        assert_eq!(record.data, original.data, "frame {n}'s bytes");
        assert_eq!(record.orig_len, original.wire_len, "frame {n}'s wire length");
        assert_eq!(record.ts_us, original.ts_us, "frame {n}'s timestamp");
    }
    eprintln!(
        "delivered {} of the fixture's {} frames before it ended",
        got.frames.len(),
        rig.frames.len()
    );
}

/// **The owner's pipe refusing a batch ends the capture - every adapter of it.**
/// The pump is the only thread that can notice, so it must hand the capture to
/// `owner_gone`, and the capture it gets back must be *stopped*, because its
/// sniffers are still reading. The loopback adapter is the witness: it never
/// ends on its own, so it is still counted in `CAPTURE_THREADS` for exactly as
/// long as the dead capture was left standing.
///
/// Each half fails on its own mutation: a pump that stops without calling
/// `owner_gone` leaves the capture `sniffing` for ever; a `reap` that does not
/// halt leaves the loopback sniffer reading for the life of the process.
#[test]
fn the_owners_pipe_refusing_a_batch_stops_the_capture_and_every_sniffer() {
    let Some(rig) = Rig::new() else { return };
    if !rig.has_loopback {
        eprintln!("SKIP  Npcap here has no loopback adapter to witness the threads with");
        return;
    }
    let loopback = rig.shared.interfaces.lock().unwrap()[1].name.clone();
    let _owner = rig.connect_refusing("owner");
    let (_watcher, watched) = rig.connect("watcher");

    rig.command("owner", Command::SetInterfaces(vec![FIXTURE_DEVICE.into(), loopback]));
    rig.command("owner", Command::StartCapture);

    assert!(
        eventually(Duration::from_secs(10), || rig.shared.control.capture_state() == CaptureState::Idle),
        "the owner's pipe refused a batch and the capture kept running"
    );
    assert!(
        eventually(Duration::from_secs(5), || rig.threads() == 0),
        "{} capture thread(s) still running after the capture ended - it was never halted",
        rig.threads()
    );
    let told = [idle(), ("sniffing".to_string(), json!("owner")), idle()];
    assert!(
        eventually(Duration::from_secs(5), || states(&watched) == told),
        "the watcher was told {:?}",
        states(&watched)
    );
    // Nothing is wrong with either adapter, and nobody is told otherwise.
    let blamed: Vec<Value> = watched
        .lock()
        .unwrap()
        .control
        .iter()
        .filter(|m| m["code"] == "capture_failed" && m["iface"] == 1)
        .cloned()
        .collect();
    assert!(blamed.is_empty(), "{blamed:?}");
}

// --- the driver's counters, read when the pump asks ------------------------------

fn roster_of(n: usize) -> Vec<Arc<CaptureInterface>> {
    (0..n)
        .map(|iface| {
            Arc::new(CaptureInterface {
                iface,
                received: Arc::new(AtomicU64::new(0)),
                kernel: Arc::new(KernelStats::new()),
            })
        })
        .collect()
}

/// **`kernelReceived` is read after `received`, so it cannot trail it.** A
/// sniffer stand-in counts frames as fast as it can and answers the pump's
/// requests with what the driver would say - every frame it has handed over and
/// a few it has not reached yet - and every tick the pump builds must carry a
/// driver figure at or above its own count.
///
/// The timer this replaced sent whatever reading the sniffer had last taken
/// beside a `received` read live, which on a real 12,000 frame-a-second capture
/// trailed by a second's worth. Answering the ready check with `latest()`
/// instead of the answer to this tick's request - the timer's behaviour - fails
/// this at once.
#[test]
fn a_ticks_driver_figure_is_read_after_its_own_count() {
    let roster = roster_of(1);
    let per = Arc::clone(&roster[0]);
    let stop = Arc::new(AtomicBool::new(false));
    let sniffer = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let (mut handed_over, mut answered) = (0u64, 0u64);
            while !stop.load(Ordering::SeqCst) {
                handed_over += 1;
                per.received.store(handed_over, Ordering::SeqCst);
                if let Some(request) = per.kernel.pending(answered) {
                    answered = request;
                    // The driver has counted everything handed over, and the
                    // frames still in its buffer.
                    per.kernel.answer(request, Some(((handed_over + 7) as u32, 0)));
                }
                // An idle stretch now and then, as a real adapter has.
                if handed_over % 50_000 == 0 {
                    thread::sleep(Duration::from_millis(1));
                }
            }
            per.kernel.answer(ANSWERED_FOR_GOOD, None);
        })
    };
    for tick in 0..200 {
        let pending = StatsTick::begin(&roster, 0, 0, 0);
        let entries = loop {
            if let Some(entries) = pending.ready(&roster) {
                break entries;
            }
            thread::yield_now();
        };
        assert!(entries[0].kernel.is_some(), "tick {tick} carried no reading");
        assert!(!kernel_behind(&entries[0]), "tick {tick}: {:?}", entries[0]);
        thread::sleep(Duration::from_micros(200));
    }
    stop.store(true, Ordering::SeqCst);
    sniffer.join().unwrap();
}

/// An adapter whose sniffer has stopped - its adapter died, or the capture is
/// ending - answers every request for good, so the pump does not wait on it;
/// one that is merely slow is waited for only `KERNEL_ANSWER_WAIT`, and then
/// reported with the last reading it gave rather than holding the figures back.
#[test]
fn a_stopped_sniffer_is_not_waited_on_and_a_slow_one_not_for_long() {
    let roster = roster_of(2);
    roster[0].kernel.answer(ANSWERED_FOR_GOOD, Some((10, 1)));
    roster[1].kernel.answer(0, Some((5, 0)));
    roster[1].received.store(3, Ordering::SeqCst);

    let pending = StatsTick::begin(&roster, 0, 0, 0);
    assert!(pending.ready(&roster).is_none(), "adapter 1 has not answered yet");
    let waited = Instant::now();
    let entries = loop {
        if let Some(entries) = pending.ready(&roster) {
            break entries;
        }
        thread::sleep(Duration::from_millis(5));
    };
    assert!(waited.elapsed() >= KERNEL_ANSWER_WAIT - Duration::from_millis(20));
    assert_eq!(entries[0].kernel, Some((10, 1)), "the stopped adapter's final reading");
    assert_eq!(entries[1].kernel, Some((5, 0)), "the slow adapter's last reading, not null");
    assert_eq!(entries[1].received, 3);

    // Answered, the tick is ready at once.
    let next = StatsTick::begin(&roster, 0, 0, 0);
    roster[1].kernel.answer(roster[1].kernel.pending(0).unwrap(), Some((9, 0)));
    assert_eq!(next.ready(&roster).unwrap()[1].kernel, Some((9, 0)));
}

/// The live check's arithmetic: behind is below the agent's own count, and a
/// count past what `pcap_stat`'s `u32` can hold is not compared at all.
#[test]
fn behind_means_below_the_agents_own_count() {
    let entry = |received: u64, kernel: Option<(u32, u32)>| InterfaceStats { iface: 0, received, kernel };
    assert!(kernel_behind(&entry(100, Some((99, 0)))));
    assert!(!kernel_behind(&entry(100, Some((100, 0)))));
    assert!(!kernel_behind(&entry(100, None)), "unreadable is not behind");
    assert!(!kernel_behind(&entry(u64::from(u32::MAX) + 5, Some((3, 0)))), "wrapped, not behind");
}
