//! The capture's lifecycle, as decisions rather than as threads.
//!
//! The port of the half of `local-agent/agent.py`'s `AgentServer` that decides
//! things: who owns the capture (`owned_by_other`, agent.py:1393-1406), what
//! `start_capture`, `stop_capture` and `set_interfaces` do (`_handle_message`,
//! agent.py:1222-1263 and the broadcast at 1385), what happens when an adapter
//! cannot be opened or dies under a running capture (`report_capture_failure`
//! and `mark_failed`, agent.py:1490-1516 and 690-699), what a disconnect ends
//! (`handle_disconnect`, agent.py:1139-1183), and what `restart_agent` may do
//! (agent.py:1353-1370).
//!
//! ## Why it is its own module
//!
//! `runtime.rs` carried all of this inline, in a closure over a live Npcap and a
//! live pipe, and had no tests at all - so every divergence the parity audit
//! found was one nothing could have caught. Here the two boundaries are traits:
//! [`Env`] is the connected clients (and the log), [`Driver`] is Npcap and the
//! threads that read it. The runtime implements both over the real things; the
//! tests below implement them with fakes that carry no frames, and each
//! behaviour is asserted against the `agent.py` lines it ports.
//!
//! ## Two locks, and why there are two
//!
//! `agent.py` gets serialisation for free: one event loop runs every handler to
//! completion. Here each client has its own thread, so **`commands`** plays the
//! loop's part - the three capture commands, a disconnect and the watchdog run
//! one at a time, which is what makes `set_interfaces`' stop-then-start one
//! step that another client's `start_capture` cannot land in the middle of.
//!
//! **`state`** is held only briefly and never across a join. It has to be
//! separate, because stopping a capture joins its sniffer threads, and a
//! sniffer reporting its own adapter's death takes `state` - if the joiner held
//! it, each would wait for the other for ever. So a sniffer never touches
//! `commands`, a join never holds `state`, and a sniffer's report carries the
//! capture's **generation** so that a report arriving after its capture was
//! replaced is recognised as stale rather than applied to the replacement.
//!
//! ## One invariant the Python agent does not keep
//!
//! **A capture has an owner exactly when it is running.** `agent.py` leaves
//! `capture_owner` set when every adapter has failed (`_stop_capture_and_
//! broadcast` stops but does not clear it), so the idle `state` it broadcasts
//! names an owner - and the app greys out Start in every *other* window
//! (`captureOwnedElsewhere` in `App.tsx`) for a capture that no longer exists.
//! Here the owner lives inside the running capture and cannot outlive it.

#![cfg(windows)]

use std::collections::HashSet;
use std::sync::Mutex;

use serde_json::Value;

use crate::protocol::{self, CaptureState, Command, Interface, ParseError};

/// A log line's level, spelled the way `agent_log` writes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warning => "WARNING",
            Level::Error => "ERROR",
        }
    }
}

/// The connected clients, as the lifecycle needs them.
///
/// The runtime's `Shared` is the real one. The tests' is a recorder, which is
/// what lets every message and every log line be asserted exactly.
pub trait Env {
    /// One client, and nobody else.
    fn send_to(&self, client: &str, message: &Value);
    /// Every connected client - `agent.py`'s `send_control`.
    fn broadcast(&self, message: &Value);
    /// Whether this client's pipe is still in the table.
    fn is_connected(&self, client: &str) -> bool;
    /// How many clients are connected.
    fn connected(&self) -> usize;
    /// The interface list as it stands, which every `state` carries.
    fn interfaces(&self) -> Vec<Interface>;
    fn log(&self, level: Level, text: &str);
    /// Ends the process a moment from now so the SCM starts a new one - see
    /// `restart::exit_for_restart`. Only ever called when that is known to work.
    fn schedule_restart(&self);
}

/// The capture engine: Npcap, and the threads that read it.
pub trait Driver {
    /// One adapter, open and not yet being read.
    type Handle;
    /// A running capture - its sniffers, its pump, its queue.
    type Running;
    /// Opens one adapter for capture. `Err` is the reason, as the sentence the
    /// app will show after "Could not capture on {label}: ".
    fn open(&self, iface: &Interface) -> Result<Self::Handle, String>;
    /// Starts reading every opened adapter, for `owner`. `generation` travels
    /// with every report a sniffer makes back, so a late one can be told from
    /// a current one.
    ///
    /// **Called with the lifecycle's state lock held**, so the capture is never
    /// visible half-installed - which means it must not call back into
    /// `Control` itself. Threads it spawns may, and simply wait their turn.
    fn start(
        &self,
        generation: u64,
        owner: &str,
        opened: Vec<(Interface, Self::Handle)>,
    ) -> Self::Running;
    /// Stops and joins, and answers the final figures for `owner`, if any.
    fn stop(&self, running: Self::Running, owner: &str) -> Option<Value>;
    /// Begins a running capture's figures again, for `owner`, without
    /// stopping it - what `start_capture` does to a capture already running
    /// (agent.py:1432-1436).
    fn rebase(&self, running: &Self::Running, owner: &str);
}

// --- the texts, which are agent.py's ------------------------------------------

/// agent.py:1226.
pub const CAPTURE_BUSY: &str =
    "Another Inwire window started this capture. Stop it there, or close that window.";
/// agent.py:1246.
pub const INVALID_INTERFACES: &str = "set_interfaces needs a list of interface names.";
/// agent.py:1256.
pub const EMPTY_INTERFACES: &str = "At least one interface must be selected.";
/// There is no adapter to start on at all. **Not a message `agent.py` sends**:
/// it starts "sniffing" on an empty selection instead (agent.py:656-663 with a
/// default taken from an empty list at 2364), which is the silent
/// capture-of-nothing its own `empty_interfaces` check exists to refuse.
pub const NO_INTERFACES: &str = "There is no network adapter to capture on. \
Npcap may not be installed: https://npcap.com/#download";
/// The reason given for a selected device the interface list does not have.
pub const NOT_LISTED: &str = "no capture adapter by that name - it may have been removed";
/// ...and for several of them at once, which are reported together.
pub const NOT_LISTED_MANY: &str =
    "none of them is a capture adapter on this machine - they may have been removed";

/// How much of a client-supplied name reaches a log line. A device name is
/// about fifty characters (`\Device\NPF_{GUID}`); a longer one is not a device
/// name, and the log keeps enough of it to recognise.
pub const LOG_NAME_CHARS: usize = 120;

pub fn capture_busy() -> Value {
    protocol::error("capture_busy", CAPTURE_BUSY)
}

/// agent.py:1374-1378. The version is in the sentence because the common cause
/// is a newer app talking to an older agent, and the sentence is all the user
/// sees.
pub fn unknown_command(version: &str, what: &str) -> Value {
    protocol::error(
        "unknown_command",
        &format!("This agent ({version}) does not understand '{what}'."),
    )
}

pub fn invalid_interfaces() -> Value {
    protocol::error("invalid_interfaces", INVALID_INTERFACES)
}

/// A selection past `protocol::MAX_SELECTED_INTERFACES` names, or with a name
/// past `protocol::MAX_INTERFACE_NAME_CHARS`. Not a limit `agent.py` has; the
/// same code as its other malformed-selection answer, with a sentence that says
/// which bound.
pub fn selection_too_large() -> Value {
    protocol::error(
        "invalid_interfaces",
        &format!(
            "set_interfaces names at most {} interfaces, each at most {} characters long.",
            protocol::MAX_SELECTED_INTERFACES,
            protocol::MAX_INTERFACE_NAME_CHARS
        ),
    )
}

pub fn empty_interfaces() -> Value {
    protocol::error("empty_interfaces", EMPTY_INTERFACES)
}

pub fn no_interfaces() -> Value {
    protocol::error("no_interfaces", NO_INTERFACES)
}

pub fn restart_unavailable(reason: &str) -> Value {
    protocol::error("restart_unavailable", reason)
}

/// Python's `repr()` of a string, for the log lines `agent.py` writes with
/// `%r` - `capture failed on interface 'Ethernet 2' (...)`. Single quotes unless
/// the text has one and no double quote, backslashes doubled.
pub fn py_repr(text: &str) -> String {
    let quote = if text.contains('\'') && !text.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(text.len() + 2);
    out.push(quote);
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            // C0, DEL and C1, and the Unicode line and paragraph separators -
            // Python's repr escapes every one of these, and each would
            // otherwise break a log line in two.
            c => match breaks_a_line(c) {
                Some(escape) => out.push_str(&escape),
                None => out.push(c),
            },
        }
    }
    out.push(quote);
    out
}

// --- the state ----------------------------------------------------------------

/// One adapter inside a running capture.
struct Member {
    iface: usize,
    name: String,
    label: String,
    /// `agent.py`'s `failed_interfaces`: this adapter stopped, the capture may
    /// not have.
    failed: bool,
}

/// A running capture, and the only place its owner is recorded.
struct Active<R> {
    generation: u64,
    owner: String,
    members: Vec<Member>,
    running: R,
}

struct State<R> {
    /// The device names the last `set_interfaces` carried - `\Device\NPF_{GUID}`,
    /// never list positions, and **all of them** - or `None` if no client has
    /// sent one since the process started.
    ///
    /// `None` starts on **every** adapter, which is `agent.py`'s default: its
    /// `SnifferController` is built from the whole list (agent.py:2364). The
    /// list is today's rather than start-up's, so an agent that started before
    /// Npcap was installed does not default to nothing.
    ///
    /// Every entry is honoured. This runtime once read the names as indices
    /// (so the app's message did not parse and adapter 0 was captured), and
    /// then took `chosen.first()` on the argument that "the app only ever sends
    /// one" - true of the mouse and false of the program: `App.tsx` forwards a
    /// restored `meta.selectedInterfaces` verbatim and `useAgentConnection`
    /// resyncs it on reconnect, so a two-adapter session captured one adapter
    /// under a status bar reading "2 adapters".
    selected: Option<Vec<String>>,
    capture: Option<Active<R>>,
    generation: u64,
}

/// The lifecycle. One per agent.
pub struct Control<R> {
    commands: Mutex<()>,
    state: Mutex<State<R>>,
}

impl<R> Default for Control<R> {
    fn default() -> Self {
        Self::new()
    }
}

/// The idle `state`, which has no owner by construction.
fn idle(env: &(impl Env + ?Sized)) -> Value {
    protocol::state(CaptureState::Idle, &env.interfaces(), None)
}

/// At most `LOG_NAME_CHARS` of `text`, marked when cut.
fn bounded(text: &str) -> String {
    match text.char_indices().nth(LOG_NAME_CHARS) {
        None => text.to_string(),
        Some((at, _)) => format!("{}...", &text[..at]),
    }
}

/// A client-supplied name as a log line may carry it: bounded, and with every
/// character that could end the line - or begin a forged one - escaped the way
/// `py_repr` escapes it. The log is one line per event, and the app reads it
/// back line by line (`agent_log::parse_line`), so a name carrying `\r\n` and a
/// timestamp would otherwise write a line the agent never wrote.
///
/// **Only those characters.** Backslashes are left alone, so a real device
/// name - `\Device\NPF_{GUID}` - reads in the log exactly as `agent.py`'s
/// `%s` writes it.
pub fn log_safe(text: &str) -> String {
    let mut out = String::new();
    for c in bounded(text).chars() {
        match breaks_a_line(c) {
            Some(escape) => out.push_str(&escape),
            None => out.push(c),
        }
    }
    out
}

/// How Python's repr writes `c`, when `c` is one of the characters that would
/// break a log line - C0, DEL, C1, and the Unicode line and paragraph
/// separators - and `None` for everything else.
fn breaks_a_line(c: char) -> Option<String> {
    match c {
        '\n' => Some("\\n".into()),
        '\r' => Some("\\r".into()),
        '\t' => Some("\\t".into()),
        c if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) => {
            Some(format!("\\x{:02x}", c as u32))
        }
        '\u{2028}' | '\u{2029}' => Some(format!("\\u{:04x}", c as u32)),
        _ => None,
    }
}

/// agent.py:2109 and 2201 for the log, 1496-1501 for the message.
///
/// `name` and `label` can be the client's own text - an unknown device name is
/// its own label - so the log line takes both through `py_repr`/`log_safe`,
/// bounded. The broadcast carries them as JSON, which escapes on its own, and
/// `protocol::parse_command` has already bounded their length.
fn report_failure(
    env: &(impl Env + ?Sized),
    iface: Option<usize>,
    name: &str,
    label: &str,
    reason: &str,
) {
    env.log(
        Level::Warning,
        &format!(
            "capture failed on interface {} ({}): {reason}",
            py_repr(&bounded(label)),
            log_safe(name)
        ),
    );
    env.broadcast(&protocol::capture_failed(iface, label, reason));
}

/// Selected devices the interface list does not have, reported **together**.
///
/// One is reported as `agent.py` reports any adapter - a line and a message of
/// its own. Several are one line and one message: a selection is bounded, but
/// a warning and a message to every client per unknown name is still a storm
/// out of one command, and the names say nothing a count does not.
fn report_unlisted(env: &(impl Env + ?Sized), names: &[&str]) {
    match names {
        [] => {}
        [one] => report_failure(env, None, one, one, NOT_LISTED),
        many => {
            let shown: Vec<String> = many.iter().take(3).map(|n| py_repr(&bounded(n))).collect();
            let more = if many.len() > 3 {
                format!(" and {} more", many.len() - 3)
            } else {
                String::new()
            };
            env.log(
                Level::Warning,
                &format!(
                    "capture failed on {} selected interfaces: {NOT_LISTED_MANY} ({}{more})",
                    many.len(),
                    shown.join(", ")
                ),
            );
            let label = format!("{} selected adapters", many.len());
            env.broadcast(&protocol::capture_failed(None, &label, NOT_LISTED_MANY));
        }
    }
}

impl<R> Control<R> {
    pub fn new() -> Self {
        Self {
            commands: Mutex::new(()),
            state: Mutex::new(State { selected: None, capture: None, generation: 0 }),
        }
    }

    /// What `hello` and `state` say. Running means at least one adapter is
    /// still reading - a capture whose last adapter died is removed on the spot,
    /// so there is no "sniffing on nothing" to report.
    pub fn capture_state(&self) -> CaptureState {
        if self.state.lock().unwrap().capture.is_some() {
            CaptureState::Sniffing
        } else {
            CaptureState::Idle
        }
    }

    /// Who owns the running capture, by the id their `hello` carried.
    pub fn owner(&self) -> Option<String> {
        self.state.lock().unwrap().capture.as_ref().map(|a| a.owner.clone())
    }

    /// The owner of capture `generation`, or `None` once that capture has been
    /// stopped or replaced - which is the pump's signal to leave.
    pub fn owner_of(&self, generation: u64) -> Option<String> {
        self.state
            .lock()
            .unwrap()
            .capture
            .as_ref()
            .filter(|a| a.generation == generation)
            .map(|a| a.owner.clone())
    }

    /// The stored selection, for tests and diagnostics.
    pub fn selected(&self) -> Option<Vec<String>> {
        self.state.lock().unwrap().selected.clone()
    }

    /// `agent.py`'s `owned_by_other` (agent.py:1393-1406): somebody else's
    /// capture is **running** and **their pipe is still connected**. An owner
    /// whose connection has gone holds nothing - "a stale owner would lock the
    /// agent out of capturing at all, which is a worse failure than two tabs
    /// racing."
    fn busy(env: &(impl Env + ?Sized), st: &State<R>, client: &str) -> bool {
        match st.capture.as_ref() {
            Some(active) if active.owner != client => env.is_connected(&active.owner),
            _ => false,
        }
    }

    /// The three commands that change the capture. `false` for any other,
    /// which the runtime answers itself.
    pub fn command<D: Driver<Running = R>>(
        &self,
        env: &(impl Env + ?Sized),
        driver: &D,
        client: &str,
        command: &Command,
    ) -> bool {
        match command {
            Command::StartCapture => self.start(env, driver, client),
            Command::StopCapture => self.stop(env, driver, client),
            Command::SetInterfaces(names) => self.set_interfaces(env, driver, client, names),
            _ => return false,
        }
        true
    }

    /// agent.py:1230-1233, then 1385.
    fn start<D: Driver<Running = R>>(&self, env: &(impl Env + ?Sized), driver: &D, client: &str) {
        let _serial = self.commands.lock().unwrap();
        let wanted = {
            let mut st = self.state.lock().unwrap();
            if Self::busy(env, &st, client) {
                env.send_to(client, &capture_busy());
                return;
            }
            let interfaces = env.interfaces();
            let wanted = st
                .selected
                .clone()
                .unwrap_or_else(|| interfaces.iter().map(|i| i.name.clone()).collect());
            env.log(
                Level::Info,
                &format!("start_capture requested on {} interface(s)", wanted.len()),
            );
            if let Some(active) = st.capture.as_mut() {
                // **Already running: the asker becomes the owner and nothing
                // restarts.** `agent.py` sets `capture_owner = ws` and its
                // `start_threads` returns early when already sniffing
                // (agent.py:1232, 657-658), then broadcasts. Reachable by the
                // owner pressing Start twice, or by another window once the
                // owner's pipe has gone - `busy` already said it holds nothing.
                //
                // The figures begin again, as `agent.py`'s `start_capture`
                // resets them before `start_threads` returns early
                // (agent.py:1432-1436) - so a window that takes over a capture
                // is not handed its predecessor's counts as its own.
                active.owner = client.to_string();
                driver.rebase(&active.running, client);
                env.broadcast(&protocol::state(CaptureState::Sniffing, &interfaces, Some(client)));
                return;
            }
            wanted
        };
        self.open_and_start(env, driver, client, &wanted);
    }

    /// Opens what it can of `wanted`, starts on whatever opened, and says so.
    ///
    /// **Per adapter, and the ones that open keep capturing.** `agent.py` runs
    /// one sniffer thread per name; each that cannot open its adapter reports
    /// `capture_failed` to every client and marks itself failed, and only when
    /// all of them have does the capture stop (agent.py:2106-2111, 1490-1516).
    /// This refused the whole selection if any one adapter would not open,
    /// which turned one unplugged dongle into no capture at all.
    ///
    /// **What differs is the order, deliberately.** `agent.py` broadcasts
    /// `sniffing` before its threads have tried to open anything, so a selection
    /// that fails entirely tells every client "sniffing" and then "idle". The
    /// opens happen here first, so no client is ever told a capture is running
    /// that never ran.
    fn open_and_start<D: Driver<Running = R>>(
        &self,
        env: &(impl Env + ?Sized),
        driver: &D,
        owner: &str,
        wanted: &[String],
    ) {
        let interfaces = env.interfaces();
        if wanted.is_empty() {
            env.log(
                Level::Warning,
                "no capturable network interfaces - nothing to capture on. \
                 If this persists, Npcap may not be installed: https://npcap.com/#download",
            );
            env.send_to(owner, &no_interfaces());
            env.broadcast(&idle(env));
            return;
        }

        let mut opened = Vec::new();
        let mut members = Vec::new();
        let mut unlisted = Vec::new();
        let mut seen = HashSet::new();
        for name in wanted {
            // The same device twice would be two handles on one adapter and
            // every frame delivered twice. The app never sends that, and a
            // duplicate is dropped rather than obeyed.
            if !seen.insert(name.as_str()) {
                continue;
            }
            // **A name the list does not have is never opened.** `agent.py`
            // hands any string straight to libpcap; Npcap's `pcap_open_live`
            // also accepts `rpcap://` sources, and a LocalSystem service
            // dialling whatever a client names is not a door worth leaving
            // open for a fault that only a stale selection produces.
            let Some(iface) = interfaces.iter().find(|i| &i.name == name) else {
                unlisted.push(name.as_str());
                continue;
            };
            match driver.open(iface) {
                Ok(handle) => {
                    members.push(Member {
                        iface: iface.id,
                        name: iface.name.clone(),
                        label: iface.label.clone(),
                        failed: false,
                    });
                    opened.push((iface.clone(), handle));
                }
                Err(reason) => report_failure(env, Some(iface.id), &iface.name, &iface.label, &reason),
            }
        }
        report_unlisted(env, &unlisted);

        if opened.is_empty() {
            // agent.py:1502-1503, then `_stop_capture_and_broadcast`.
            env.log(Level::Warning, "every selected interface failed - capture stopped");
            env.broadcast(&idle(env));
            return;
        }

        let mut st = self.state.lock().unwrap();
        st.generation += 1;
        let generation = st.generation;
        let running = driver.start(generation, owner, opened);
        st.capture = Some(Active { generation, owner: owner.to_string(), members, running });
        env.broadcast(&protocol::state(CaptureState::Sniffing, &interfaces, Some(owner)));
    }

    /// agent.py:1234-1237, then 1385.
    ///
    /// The final figures go to the client that stopped it, which the Python
    /// agent does not send at all: without them the last `capture_stats` the
    /// app sees is up to a second stale, and a burst in that second is
    /// invisible exactly when somebody looks.
    fn stop<D: Driver<Running = R>>(&self, env: &(impl Env + ?Sized), driver: &D, client: &str) {
        let _serial = self.commands.lock().unwrap();
        let taken = {
            let mut st = self.state.lock().unwrap();
            if Self::busy(env, &st, client) {
                env.send_to(client, &capture_busy());
                return;
            }
            env.log(Level::Info, "stop_capture requested");
            st.capture.take()
        };
        if let Some(active) = taken {
            if let Some(stats) = driver.stop(active.running, &active.owner) {
                env.send_to(client, &stats);
            }
        }
        env.broadcast(&idle(env));
    }

    /// agent.py:1238-1263, then 1385.
    ///
    /// **A running capture follows the change**: it is stopped and started
    /// again on the new set, and every client is told the result. The app
    /// relies on that - `handleToggleInterface` in `App.tsx` sends
    /// `set_interfaces` mid-capture and expects to keep capturing, on the new
    /// set. This used to store the names and answer the sender alone, so the
    /// capture carried on reading the old adapters while the app showed the
    /// new ones.
    fn set_interfaces<D: Driver<Running = R>>(
        &self,
        env: &(impl Env + ?Sized),
        driver: &D,
        client: &str,
        names: &[String],
    ) {
        let _serial = self.commands.lock().unwrap();
        let restart = {
            let mut st = self.state.lock().unwrap();
            if Self::busy(env, &st, client) {
                env.send_to(client, &capture_busy());
                return;
            }
            env.log(Level::Info, &format!("set_interfaces: {} interface(s) selected", names.len()));
            st.selected = Some(names.to_vec());
            st.capture.take()
        };
        match restart {
            None => env.broadcast(&idle(env)),
            Some(active) => {
                // `stop_capture()` then `start_capture()`, as agent.py:1262-1263
                // does. No final figures: the capture carries on, and Python
                // sends none here either. The owner is the asker - `busy`
                // passed, so it either was already or its pipe has gone.
                let _ = driver.stop(active.running, &active.owner);
                self.open_and_start(env, driver, client, names);
            }
        }
    }

    /// Everything that can go wrong before a `Command` exists.
    ///
    /// agent.py:1186-1191 ignores what is not a JSON object; 1371-1379 names an
    /// unknown `type` back; 1239-1258 refuses a malformed selection - **after**
    /// the ownership gate at 1222, so a second window sending garbage while
    /// another owns the capture is told `capture_busy`, not how to spell a list.
    pub fn parse_failed(&self, env: &(impl Env + ?Sized), client: &str, error: &ParseError) {
        match error {
            ParseError::NotJson | ParseError::NotObject => {}
            ParseError::NoType => env.send_to(client, &unknown_command(crate::VERSION, "None")),
            ParseError::Unknown(what) => env.send_to(client, &unknown_command(crate::VERSION, what)),
            ParseError::BadInterfaces
            | ParseError::EmptyInterfaces
            | ParseError::SelectionTooLarge => {
                let _serial = self.commands.lock().unwrap();
                let st = self.state.lock().unwrap();
                if Self::busy(env, &st, client) {
                    env.send_to(client, &capture_busy());
                } else if *error == ParseError::EmptyInterfaces {
                    env.send_to(client, &empty_interfaces());
                } else if *error == ParseError::SelectionTooLarge {
                    env.send_to(client, &selection_too_large());
                } else {
                    env.send_to(client, &invalid_interfaces());
                }
            }
        }
    }

    /// A client's pipe has closed. The runtime has already removed it from the
    /// client table, so `env.connected()` counts the ones that remain.
    ///
    /// agent.py:1166-1183: the owner leaving stops its capture even with other
    /// windows open - "inheriting a capture nobody present requested is the
    /// always-on background capture this agent is designed not to do" - and
    /// the last client leaving stops whatever is running.
    pub fn disconnected<D: Driver<Running = R>>(
        &self,
        env: &(impl Env + ?Sized),
        driver: &D,
        client: &str,
    ) {
        let _serial = self.commands.lock().unwrap();
        let (taken, owner_left) = {
            let mut st = self.state.lock().unwrap();
            match st.capture.as_ref() {
                Some(active) if active.owner == client => {
                    env.log(
                        Level::Info,
                        "the client that started this capture disconnected - stopping",
                    );
                    (st.capture.take(), true)
                }
                Some(_) if env.connected() == 0 => {
                    env.log(Level::Info, "last client disconnected - stopping capture");
                    (st.capture.take(), false)
                }
                _ => (None, false),
            }
        };
        if let Some(active) = taken {
            let _ = driver.stop(active.running, &active.owner);
        }
        if owner_left {
            env.broadcast(&idle(env));
        }
    }

    /// A sniffer's adapter could not be read. Called from that sniffer's own
    /// thread, which is why it takes no `commands` lock and joins nothing.
    ///
    /// agent.py:1490-1516: `capture_failed` to every client, and when every
    /// adapter of the capture has failed, the capture is **stopped** - not
    /// merely reported idle, which is what this did before: the pump kept
    /// sending `capture_stats`, the owner kept the capture, and the next
    /// `start_capture` was ignored because a handle still existed.
    ///
    /// Answers the dead capture when this report was the last straw. The caller
    /// must hand it to another thread to stop, because stopping joins the
    /// sniffers and the caller is one of them.
    pub fn adapter_failed(
        &self,
        env: &(impl Env + ?Sized),
        generation: u64,
        iface: usize,
        reason: &str,
    ) -> Option<(R, String)> {
        let mut st = self.state.lock().unwrap();
        // A report from a capture that has since been stopped or replaced.
        let active = st.capture.as_mut().filter(|a| a.generation == generation)?;
        // The first reason wins: a failing read usually makes the next one fail
        // too, and the second report would describe the consequence.
        let member = active.members.iter_mut().find(|m| m.iface == iface && !m.failed)?;
        member.failed = true;
        let (name, label) = (member.name.clone(), member.label.clone());
        report_failure(env, Some(iface), &name, &label, reason);
        if active.members.iter().any(|m| !m.failed) {
            return None;
        }
        env.log(Level::Warning, "every selected interface failed - capture stopped");
        let dead = st.capture.take()?;
        env.broadcast(&idle(env));
        Some((dead.running, dead.owner))
    }

    /// The owner's pipe refused a batch: there is nowhere left to deliver.
    ///
    /// `agent.py`'s `_send_to_owner` clears the owner and leaves the sniffers
    /// running (agent.py:1425-1428), so with another window connected the
    /// capture carries on invisibly until that window closes too. Stopped here
    /// instead. `owner` must still be the owner - a capture another window has
    /// since taken over is not this pipe's to end.
    pub fn owner_gone(
        &self,
        env: &(impl Env + ?Sized),
        generation: u64,
        owner: &str,
    ) -> Option<(R, String)> {
        let mut st = self.state.lock().unwrap();
        st.capture.as_ref().filter(|a| a.generation == generation && a.owner == owner)?;
        env.log(Level::Info, "the client that started this capture disconnected - stopping");
        let dead = st.capture.take()?;
        env.broadcast(&idle(env));
        Some((dead.running, dead.owner))
    }

    /// The watchdog's half: a capture running with nobody connected is stopped,
    /// whatever else is true. agent.py:2287-2289.
    pub fn stop_orphaned<D: Driver<Running = R>>(&self, env: &(impl Env + ?Sized), driver: &D) {
        let _serial = self.commands.lock().unwrap();
        let taken = {
            let mut st = self.state.lock().unwrap();
            if st.capture.is_some() && env.connected() == 0 {
                env.log(Level::Warning, "capture was running with no clients connected - stopping it");
                st.capture.take()
            } else {
                None
            }
        };
        if let Some(active) = taken {
            let _ = driver.stop(active.running, &active.owner);
        }
    }

    /// Stops whatever is running, for the process exiting. agent.py:2399-2404.
    pub fn shutdown<D: Driver<Running = R>>(&self, driver: &D) {
        let _serial = self.commands.lock().unwrap();
        let taken = self.state.lock().unwrap().capture.take();
        if let Some(active) = taken {
            let _ = driver.stop(active.running, &active.owner);
        }
    }
}

/// Whether `restart_agent` can be honoured, decided once at startup.
#[derive(Clone, Debug, PartialEq)]
pub struct RestartSupport {
    pub allowed: bool,
    /// The sentence sent back when it cannot be. Empty when it can.
    pub reason: String,
}

/// agent.py:1353-1370.
///
/// **Refusing is the whole safety property**: this command is implemented by
/// exiting, and where nothing would start the agent again that is a stop the
/// user cannot undo from the app. Answers only the asker and broadcasts no
/// `state` - restarting changes nothing about what the agent is doing until
/// the process is gone.
pub fn restart_agent(env: &(impl Env + ?Sized), support: &RestartSupport, client: &str) {
    if !support.allowed {
        env.log(Level::Warning, &format!("restart_agent refused - {}", support.reason));
        env.send_to(client, &restart_unavailable(&support.reason));
        return;
    }
    env.log(Level::Info, "restart_agent requested by a client");
    env.schedule_restart();
}

/// The interface list after a re-read, and the log lines that say what moved.
///
/// agent.py:2074-2098. A failed read keeps the previous list - "emptying it
/// because one call threw while a driver was reloading would take the picker
/// away from a client that is using it". A list that did not change says
/// nothing, so a reconnect on a quiet machine costs no log lines.
pub fn refresh_interfaces(
    log: &dyn Fn(Level, &str),
    previous: &[Interface],
    read: Result<Vec<Interface>, String>,
) -> Vec<Interface> {
    let fresh = match read {
        Ok(list) => list,
        Err(error) => {
            log(
                Level::Warning,
                &format!("could not re-enumerate network interfaces ({error}); keeping the previous list"),
            );
            return previous.to_vec();
        }
    };
    let pairs = |list: &[Interface]| -> Vec<(String, String)> {
        list.iter().map(|i| (i.name.clone(), i.label.clone())).collect()
    };
    if pairs(&fresh) == pairs(previous) {
        return fresh;
    }
    log(Level::Info, &format!("detected {} network interface(s)", fresh.len()));
    for iface in &fresh {
        if !previous.iter().any(|p| p.name == iface.name) {
            log(Level::Info, &format!("  interface available: {} -> {}", iface.label, iface.name));
        }
    }
    for gone in previous {
        if !fresh.iter().any(|i| i.name == gone.name) {
            log(Level::Info, &format!("  interface gone: {} -> {}", gone.label, gone.name));
        }
    }
    fresh
}

/// Something loaded on first success and kept for the life of the process -
/// Npcap's `wpcap.dll`.
///
/// **Retried on every ask until it works**, which is must-fix 1 of the parity
/// audit. The runtime used to load Npcap once at start-up with `?`, so a
/// machine without it had no agent at all - not an agent reporting no adapters,
/// which is what `agent.py` serves (agent.py:2024-2028, 2349-2360), but a
/// service that exited and a pipe nobody answered. And a machine where Npcap is
/// installed *after* the service started - by the app's own Update Center,
/// which then recycles the pipe - needs the next connection to find it without
/// anybody restarting the service.
///
/// Leaked on success, deliberately: the DLL stays loaded for the life of the
/// process, and a `&'static` is what lets a capture handle borrowed from it
/// move into a sniffer thread.
pub struct Lazy<T: 'static> {
    slot: Mutex<Option<&'static T>>,
    failures: Mutex<u32>,
}

impl<T: 'static> Default for Lazy<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: 'static> Lazy<T> {
    pub const fn new() -> Self {
        Self { slot: Mutex::new(None), failures: Mutex::new(0) }
    }

    /// The value, if a load has ever succeeded.
    pub fn get(&self) -> Option<&'static T> {
        *self.slot.lock().unwrap()
    }

    /// The value, loading it now if no attempt has succeeded yet.
    ///
    /// `Ok((value, failed_before))`, where `failed_before` is how many earlier
    /// attempts failed **if this call is the one that loaded it**, and 0
    /// otherwise - so the caller can say "available now" exactly once, and only
    /// when it had said "not available" first.
    pub fn get_or_load(
        &self,
        load: impl FnOnce() -> Result<T, String>,
    ) -> Result<(&'static T, u32), String> {
        let mut slot = self.slot.lock().unwrap();
        if let Some(value) = *slot {
            return Ok((value, 0));
        }
        match load() {
            Ok(value) => {
                let value: &'static T = Box::leak(Box::new(value));
                *slot = Some(value);
                let failed = std::mem::take(&mut *self.failures.lock().unwrap());
                Ok((value, failed))
            }
            Err(error) => {
                *self.failures.lock().unwrap() += 1;
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! Every test here drives the lifecycle through fakes of the two
    //! boundaries and holds the result to the `agent.py` lines it ports. No
    //! frames cross either fake - these are decisions about adapters and
    //! clients, and the frame path is tested with real captures in
    //! `session.rs` and `runtime.rs`.

    use super::*;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // --- the fakes ---------------------------------------------------------

    /// Who a message went to: one client, or everyone.
    #[derive(Clone, Debug, PartialEq)]
    enum To {
        One(String),
        All,
    }

    #[derive(Default)]
    struct FakeEnv {
        clients: Mutex<Vec<String>>,
        interfaces: Mutex<Vec<Interface>>,
        sent: Mutex<Vec<(To, Value)>>,
        logs: Mutex<Vec<(Level, String)>>,
        restarts: AtomicUsize,
    }

    impl FakeEnv {
        fn with(clients: &[&str], interfaces: Vec<Interface>) -> Self {
            let env = FakeEnv::default();
            *env.clients.lock().unwrap() = clients.iter().map(|c| c.to_string()).collect();
            *env.interfaces.lock().unwrap() = interfaces;
            env
        }
        fn drop_client(&self, client: &str) {
            self.clients.lock().unwrap().retain(|c| c != client);
        }
        fn take(&self) -> Vec<(To, Value)> {
            std::mem::take(&mut *self.sent.lock().unwrap())
        }
        fn take_logs(&self) -> Vec<(Level, String)> {
            std::mem::take(&mut *self.logs.lock().unwrap())
        }
    }

    impl Env for FakeEnv {
        fn send_to(&self, client: &str, message: &Value) {
            self.sent.lock().unwrap().push((To::One(client.into()), message.clone()));
        }
        fn broadcast(&self, message: &Value) {
            self.sent.lock().unwrap().push((To::All, message.clone()));
        }
        fn is_connected(&self, client: &str) -> bool {
            self.clients.lock().unwrap().iter().any(|c| c == client)
        }
        fn connected(&self) -> usize {
            self.clients.lock().unwrap().len()
        }
        fn interfaces(&self) -> Vec<Interface> {
            self.interfaces.lock().unwrap().clone()
        }
        fn log(&self, level: Level, text: &str) {
            self.logs.lock().unwrap().push((level, text.to_string()));
        }
        fn schedule_restart(&self) {
            self.restarts.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// A running fake capture: which generation, and which devices it read.
    #[derive(Debug, PartialEq)]
    struct FakeRunning {
        generation: u64,
        names: Vec<String>,
    }

    /// Opens every adapter except those given a refusal, and records what it
    /// was asked to do.
    #[derive(Default)]
    struct FakeDriver {
        refuse: HashMap<String, String>,
        opened: Mutex<Vec<String>>,
        started: Mutex<Vec<(u64, Vec<String>)>>,
        stopped: Mutex<Vec<(FakeRunning, String)>>,
        rebased: Mutex<Vec<(u64, String)>>,
    }

    impl FakeDriver {
        fn refusing(pairs: &[(&str, &str)]) -> Self {
            FakeDriver {
                refuse: pairs.iter().map(|(n, r)| (n.to_string(), r.to_string())).collect(),
                ..Default::default()
            }
        }
    }

    impl Driver for FakeDriver {
        type Handle = String;
        type Running = FakeRunning;
        fn open(&self, iface: &Interface) -> Result<String, String> {
            self.opened.lock().unwrap().push(iface.name.clone());
            match self.refuse.get(&iface.name) {
                Some(reason) => Err(reason.clone()),
                None => Ok(iface.name.clone()),
            }
        }
        fn start(&self, generation: u64, _owner: &str, opened: Vec<(Interface, String)>) -> FakeRunning {
            let names: Vec<String> = opened.into_iter().map(|(_, h)| h).collect();
            self.started.lock().unwrap().push((generation, names.clone()));
            FakeRunning { generation, names }
        }
        fn stop(&self, running: FakeRunning, owner: &str) -> Option<Value> {
            let generation = running.generation;
            self.stopped.lock().unwrap().push((running, owner.to_string()));
            Some(json!({ "type": "capture_stats", "final": true, "generation": generation }))
        }
        fn rebase(&self, running: &FakeRunning, owner: &str) {
            self.rebased.lock().unwrap().push((running.generation, owner.to_string()));
        }
    }

    fn iface(id: usize, name: &str, label: &str) -> Interface {
        Interface { id, name: name.into(), label: label.into(), link_type: Some(1) }
    }

    /// Three adapters, named the way Npcap names them and labelled the way the
    /// interface list labels them.
    fn three() -> Vec<Interface> {
        vec![
            iface(0, r"\Device\NPF_{A}", "Ethernet 2 (Intel(R) I225-V)"),
            iface(1, r"\Device\NPF_{B}", "Wi-Fi (Intel(R) Wi-Fi 6E AX211)"),
            iface(2, r"\Device\NPF_Loopback", "Adapter for loopback traffic capture"),
        ]
    }

    const A: &str = r"\Device\NPF_{A}";
    const B: &str = r"\Device\NPF_{B}";
    const LO: &str = r"\Device\NPF_Loopback";

    fn set(names: &[&str]) -> Command {
        Command::SetInterfaces(names.iter().map(|n| n.to_string()).collect())
    }

    fn states(sent: &[(To, Value)]) -> Vec<(To, String, Value)> {
        sent.iter()
            .filter(|(_, m)| m["type"] == "state")
            .map(|(to, m)| (to.clone(), m["state"].as_str().unwrap().to_string(), m["owner"].clone()))
            .collect()
    }

    fn errors(sent: &[(To, Value)]) -> Vec<(To, Value)> {
        sent.iter().filter(|(_, m)| m["type"] == "error").cloned().collect()
    }

    // --- start_capture -------------------------------------------------------

    /// agent.py:2364 builds the controller's selection from EVERY adapter, and
    /// agent.py:661 spawns a sniffer per selected name - so a `start_capture`
    /// with no `set_interfaces` before it captures on all of them. This used to
    /// refuse with `no_interfaces`.
    #[test]
    fn start_with_no_selection_captures_on_every_adapter() {
        let env = FakeEnv::with(&["a"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        assert!(control.command(&env, &driver, "a", &Command::StartCapture));

        assert_eq!(*driver.started.lock().unwrap(), vec![(1, vec![A.into(), B.into(), LO.into()])]);
        let sent = env.take();
        // agent.py:1385 - the resulting state, to every client, naming the owner.
        assert_eq!(states(&sent), vec![(To::All, "sniffing".into(), json!("a"))]);
        assert!(errors(&sent).is_empty());
        assert_eq!(control.capture_state(), CaptureState::Sniffing);
        assert_eq!(control.owner().as_deref(), Some("a"));
        // agent.py:1231's line, counting the selection.
        assert!(env.take_logs().contains(&(Level::Info, "start_capture requested on 3 interface(s)".into())));
    }

    /// agent.py:2106-2111 then 1496-1501: an adapter that will not open is
    /// reported to EVERY client, as `capture_failed` with the adapter's id and
    /// "Could not capture on {label}: {reason}" - and the ones that did open
    /// keep capturing, because `mark_failed` stops the capture only when every
    /// selected interface has failed (agent.py:690-699).
    #[test]
    fn an_adapter_that_will_not_open_is_reported_to_everyone_and_the_rest_capture() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::refusing(&[(B, "Error opening adapter: The device is not ready.")]);
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[A, B]));
        env.take();
        env.take_logs();
        control.command(&env, &driver, "a", &Command::StartCapture);

        let sent = env.take();
        assert_eq!(
            errors(&sent),
            vec![(To::All, json!({
                "type": "error",
                "code": "capture_failed",
                "iface": 1,
                "message": "Could not capture on Wi-Fi (Intel(R) Wi-Fi 6E AX211): \
                            Error opening adapter: The device is not ready.",
            }))],
            "to every client, with the adapter's id and its label"
        );
        assert_eq!(*driver.started.lock().unwrap(), vec![(1, vec![A.to_string()])]);
        assert_eq!(states(&sent), vec![(To::All, "sniffing".into(), json!("a"))]);
        // agent.py:2109, with the label as %r.
        assert!(env.take_logs().contains(&(
            Level::Warning,
            format!(
                "capture failed on interface 'Wi-Fi (Intel(R) Wi-Fi 6E AX211)' ({B}): \
                 Error opening adapter: The device is not ready."
            )
        )));
    }

    /// agent.py:1502-1516: when every selected adapter has failed, the capture
    /// is stopped and every client is told `idle`. Here the owner is cleared
    /// with it (see the module note), so the idle state names nobody, and a
    /// new start is taken rather than ignored.
    #[test]
    fn a_selection_where_nothing_opens_ends_idle_with_no_owner() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::refusing(&[(A, "no such device"), (B, "access denied")]);
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[A, B]));
        env.take();
        env.take_logs();
        control.command(&env, &driver, "a", &Command::StartCapture);

        let sent = env.take();
        let failed: Vec<Value> = errors(&sent).into_iter().map(|(to, m)| {
            assert_eq!(to, To::All);
            json!([m["code"], m["iface"]])
        }).collect();
        assert_eq!(failed, vec![json!(["capture_failed", 0]), json!(["capture_failed", 1])]);
        assert_eq!(
            states(&sent),
            vec![(To::All, "idle".into(), Value::Null)],
            "never 'sniffing' for a capture that never ran, and no owner on an idle state"
        );
        assert!(driver.started.lock().unwrap().is_empty());
        assert_eq!(control.capture_state(), CaptureState::Idle);
        assert!(env.take_logs().contains(&(
            Level::Warning,
            "every selected interface failed - capture stopped".into()
        )));

        // Another window may start now: nothing is running (agent.py:1406).
        control.command(&env, &FakeDriver::default(), "b", &set(&[LO]));
        control.command(&env, &FakeDriver::default(), "b", &Command::StartCapture);
        assert_eq!(control.owner().as_deref(), Some("b"));
    }

    /// A selected device the interface list does not have is reported, per
    /// adapter, and never handed to Npcap. The `iface` is omitted rather than
    /// agent.py's 0 (agent.py:2213), which would name a different adapter.
    #[test]
    fn a_device_the_list_does_not_have_is_reported_without_an_id_and_never_opened() {
        let env = FakeEnv::with(&["a"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[r"\Device\NPF_{GONE}", A]));
        env.take();
        control.command(&env, &driver, "a", &Command::StartCapture);

        let sent = env.take();
        let (to, message) = errors(&sent).remove(0);
        assert_eq!(to, To::All);
        assert!(message.get("iface").is_none(), "no id is the honest answer: {message}");
        assert_eq!(
            message["message"],
            format!(r"Could not capture on \Device\NPF_{{GONE}}: {NOT_LISTED}")
        );
        assert_eq!(*driver.opened.lock().unwrap(), vec![A.to_string()], "only listed devices are opened");
        assert_eq!(states(&sent), vec![(To::All, "sniffing".into(), json!("a"))]);
    }

    /// No adapters at all - the state a machine without Npcap is in. agent.py
    /// would report `sniffing` on nothing (its default selection is the empty
    /// list it enumerated, agent.py:2364, and 656-663 start "zero threads");
    /// this refuses, tells the asker why, and every client that it is idle.
    #[test]
    fn with_no_adapters_a_start_is_refused_and_everyone_told_idle() {
        let env = FakeEnv::with(&["a", "b"], vec![]);
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &Command::StartCapture);

        let sent = env.take();
        assert_eq!(errors(&sent), vec![(To::One("a".into()), no_interfaces())]);
        assert_eq!(states(&sent), vec![(To::All, "idle".into(), Value::Null)]);
        assert!(driver.started.lock().unwrap().is_empty());
    }

    /// agent.py:1232 and 657-658: a start while sniffing makes the asker the
    /// owner and restarts nothing, then broadcasts (1385) - and begins the
    /// capture's figures again, as agent.py:1432-1436 does before its
    /// `start_threads` returns early.
    #[test]
    fn a_start_while_sniffing_restarts_nothing_and_rebroadcasts() {
        let env = FakeEnv::with(&["a"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[A]));
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();
        control.command(&env, &driver, "a", &Command::StartCapture);

        assert_eq!(driver.started.lock().unwrap().len(), 1, "not restarted");
        assert!(driver.stopped.lock().unwrap().is_empty());
        assert_eq!(states(&env.take()), vec![(To::All, "sniffing".into(), json!("a"))]);
        assert_eq!(*driver.rebased.lock().unwrap(), vec![(1, "a".to_string())], "the figures begin again");
    }

    // --- ownership -----------------------------------------------------------

    /// agent.py:1222-1228 with 1393-1406: another window's commands are refused
    /// while the owner is connected and its capture is running - with Python's
    /// sentence, to the asker only, and no state broadcast.
    #[test]
    fn capture_busy_while_the_owner_is_connected_and_capturing() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();

        for command in [Command::StartCapture, Command::StopCapture, set(&[LO])] {
            control.command(&env, &driver, "b", &command);
            assert_eq!(
                env.take(),
                vec![(To::One("b".into()), json!({
                    "type": "error",
                    "code": "capture_busy",
                    "message": "Another Inwire window started this capture. Stop it there, or close that window.",
                }))],
                "{command:?}"
            );
        }
        assert_eq!(control.owner().as_deref(), Some("a"), "nothing moved");
        assert_eq!(control.selected(), None, "b's selection was not taken");
        // Subscriptions are never gated and are not this module's.
        assert!(!control.command(&env, &driver, "b", &Command::SubscribeLogs));
    }

    /// agent.py:1403-1405: "an owner whose socket is gone holds nothing". The
    /// next window's start takes over the running capture (agent.py:1232).
    #[test]
    fn an_owner_whose_pipe_has_gone_holds_nothing() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.drop_client("a");
        env.take();

        control.command(&env, &driver, "b", &Command::StartCapture);
        let sent = env.take();
        assert!(errors(&sent).is_empty(), "no capture_busy for a stale owner");
        assert_eq!(states(&sent), vec![(To::All, "sniffing".into(), json!("b"))]);
        assert_eq!(control.owner().as_deref(), Some("b"));
        assert_eq!(
            *driver.rebased.lock().unwrap(),
            vec![(1, "b".to_string())],
            "b is not handed a's figures as its own"
        );
    }

    /// agent.py:1406 - ownership only bites while a capture is running. After
    /// the owner's capture died, another window is not told it is busy.
    #[test]
    fn a_dead_capture_is_not_busy() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[A]));
        control.command(&env, &driver, "a", &Command::StartCapture);
        let dead = control.adapter_failed(&env, 1, 0, "pcap_next_ex failed (-1): device removed");
        assert!(dead.is_some());
        env.take();

        control.command(&env, &driver, "b", &Command::StartCapture);
        assert!(errors(&env.take()).is_empty());
        assert_eq!(control.owner().as_deref(), Some("b"));
    }

    // --- set_interfaces ------------------------------------------------------

    /// agent.py:1259-1263 then 1385: set_interfaces while sniffing stops the
    /// capture and starts it on the new set, and every client is told. The app
    /// depends on this (`handleToggleInterface`, App.tsx).
    #[test]
    fn set_interfaces_while_sniffing_restarts_on_the_new_set_and_tells_everyone() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[A]));
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();
        env.take_logs();

        control.command(&env, &driver, "a", &set(&[B, LO]));

        let stopped = driver.stopped.lock().unwrap();
        assert_eq!(stopped.len(), 1);
        assert_eq!(stopped[0].0, FakeRunning { generation: 1, names: vec![A.into()] });
        assert_eq!(
            *driver.started.lock().unwrap(),
            vec![(1, vec![A.to_string()]), (2, vec![B.to_string(), LO.to_string()])]
        );
        let sent = env.take();
        assert_eq!(states(&sent), vec![(To::All, "sniffing".into(), json!("a"))]);
        assert!(
            !sent.iter().any(|(_, m)| m["type"] == "capture_stats"),
            "a restart sends no final figures - agent.py sends none, and the capture carries on"
        );
        assert_eq!(control.selected(), Some(vec![B.to_string(), LO.to_string()]));
        assert_eq!(
            env.take_logs(),
            vec![(Level::Info, "set_interfaces: 2 interface(s) selected".into())]
        );
    }

    /// A restart onto adapters that all refuse ends idle, like a start would.
    #[test]
    fn set_interfaces_onto_adapters_that_all_fail_ends_idle() {
        let env = FakeEnv::with(&["a"], three());
        let driver = FakeDriver::refusing(&[(B, "access denied")]);
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[A]));
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();
        control.command(&env, &driver, "a", &set(&[B]));

        let sent = env.take();
        assert_eq!(errors(&sent).len(), 1);
        assert_eq!(states(&sent), vec![(To::All, "idle".into(), Value::Null)]);
        assert_eq!(control.capture_state(), CaptureState::Idle);
    }

    /// agent.py:1385 again: set_interfaces while idle stores the selection and
    /// broadcasts the (idle) state to every client. This used to answer the
    /// sender alone.
    #[test]
    fn set_interfaces_while_idle_is_broadcast() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[B]));
        assert_eq!(states(&env.take()), vec![(To::All, "idle".into(), Value::Null)]);
        assert!(driver.opened.lock().unwrap().is_empty(), "idle stays idle");
        control.command(&env, &driver, "a", &Command::StartCapture);
        assert_eq!(*driver.started.lock().unwrap(), vec![(1, vec![B.to_string()])]);
    }

    /// agent.py:1239-1258 - the two refusals, with Python's sentences, to the
    /// sender only and with no state broadcast (test_protocol.py asserts
    /// "...and broadcasts no state"). And agent.py:1222 runs first: a window
    /// that does not own a running capture is told `capture_busy` instead.
    #[test]
    fn a_malformed_selection_is_refused_after_the_ownership_gate() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();

        let bad = protocol::parse_command(r#"{"type":"set_interfaces","interfaces":"eth1"}"#).unwrap_err();
        control.parse_failed(&env, "a", &bad);
        assert_eq!(env.take(), vec![(To::One("a".into()), json!({
            "type": "error", "code": "invalid_interfaces",
            "message": "set_interfaces needs a list of interface names.",
        }))]);

        let numbers = protocol::parse_command(r#"{"type":"set_interfaces","interfaces":[0]}"#).unwrap_err();
        control.parse_failed(&env, "a", &numbers);
        assert_eq!(env.take()[0].1["code"], "invalid_interfaces");

        let empty = protocol::parse_command(r#"{"type":"set_interfaces","interfaces":[]}"#).unwrap_err();
        control.parse_failed(&env, "a", &empty);
        assert_eq!(env.take(), vec![(To::One("a".into()), json!({
            "type": "error", "code": "empty_interfaces",
            "message": "At least one interface must be selected.",
        }))]);

        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();
        control.parse_failed(&env, "b", &empty);
        assert_eq!(env.take(), vec![(To::One("b".into()), capture_busy())]);
    }

    // --- stop_capture and disconnects ----------------------------------------

    /// agent.py:1234-1237 then 1385: stop, and every client is told idle with
    /// no owner. The final figures go to the stopper.
    #[test]
    fn stop_capture_stops_and_everyone_is_told_idle() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();
        env.take_logs();
        control.command(&env, &driver, "a", &Command::StopCapture);

        let sent = env.take();
        assert_eq!(sent[0].0, To::One("a".into()));
        assert_eq!(sent[0].1["type"], "capture_stats");
        assert_eq!(states(&sent), vec![(To::All, "idle".into(), Value::Null)]);
        assert_eq!(driver.stopped.lock().unwrap().len(), 1);
        assert_eq!(env.take_logs(), vec![(Level::Info, "stop_capture requested".into())]);
        assert_eq!(control.owner(), None);

        // Stopping an idle agent still answers with the state (agent.py:1385).
        control.command(&env, &driver, "b", &Command::StopCapture);
        assert_eq!(states(&env.take()), vec![(To::All, "idle".into(), Value::Null)]);
    }

    /// agent.py:1170-1175: the owner leaving stops its capture even with other
    /// windows open, and they are told.
    #[test]
    fn the_owner_leaving_stops_the_capture() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();
        env.take_logs();

        env.drop_client("a");
        control.disconnected(&env, &driver, "a");
        assert_eq!(driver.stopped.lock().unwrap().len(), 1);
        assert_eq!(states(&env.take()), vec![(To::All, "idle".into(), Value::Null)]);
        assert_eq!(
            env.take_logs(),
            vec![(Level::Info, "the client that started this capture disconnected - stopping".into())]
        );
    }

    /// agent.py:1176-1183 and the watchdog at 2287-2289: a window that does not
    /// own the capture leaving changes nothing while others remain, and nothing
    /// runs once nobody is connected.
    #[test]
    fn nothing_captures_with_nobody_connected() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();

        env.drop_client("b");
        control.disconnected(&env, &driver, "b");
        assert!(driver.stopped.lock().unwrap().is_empty(), "b never owned it");
        assert!(env.take().is_empty());

        // The owner's pipe vanishes without its disconnect running - the case
        // the watchdog exists for.
        env.drop_client("a");
        env.take_logs();
        control.stop_orphaned(&env, &driver);
        assert_eq!(driver.stopped.lock().unwrap().len(), 1);
        assert_eq!(
            env.take_logs(),
            vec![(Level::Warning, "capture was running with no clients connected - stopping it".into())]
        );
    }

    // --- adapters dying under a running capture ------------------------------

    /// agent.py:1490-1516 for a read failure: each adapter's death is reported
    /// to everyone once, the rest keep capturing, and the last one's death
    /// stops the capture, clears the owner and hands the dead capture back to
    /// be reaped. A report from a replaced capture is ignored.
    #[test]
    fn adapters_dying_mid_capture_are_reported_and_the_last_ends_it() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &set(&[A, B]));
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();

        assert!(control.adapter_failed(&env, 1, 1, "pcap_next_ex failed (-1): device removed").is_none());
        let sent = env.take();
        assert_eq!(sent, vec![(To::All, json!({
            "type": "error", "code": "capture_failed", "iface": 1,
            "message": "Could not capture on Wi-Fi (Intel(R) Wi-Fi 6E AX211): pcap_next_ex failed (-1): device removed",
        }))]);
        assert_eq!(control.capture_state(), CaptureState::Sniffing, "A still reads");

        assert!(control.adapter_failed(&env, 1, 1, "again").is_none(), "the first reason wins");
        assert!(control.adapter_failed(&env, 7, 0, "stale").is_none(), "another capture's report");
        assert!(env.take().is_empty());

        let (dead, owner) = control.adapter_failed(&env, 1, 0, "adapter reset").expect("the last one");
        assert_eq!(dead, FakeRunning { generation: 1, names: vec![A.into(), B.into()] });
        assert_eq!(owner, "a");
        let sent = env.take();
        assert_eq!(errors(&sent).len(), 1);
        assert_eq!(states(&sent), vec![(To::All, "idle".into(), Value::Null)]);
        assert_eq!(control.owner(), None);
        assert_eq!(control.owner_of(1), None, "the pump's signal to leave");

        // A start is taken, not ignored because a handle lingers.
        control.command(&env, &driver, "a", &Command::StartCapture);
        assert_eq!(driver.started.lock().unwrap().len(), 2);
    }

    /// The owner's pipe refusing a batch ends that owner's capture - and only
    /// that owner's: a capture another window has since taken is not ended.
    #[test]
    fn the_owners_pipe_refusing_a_batch_ends_its_capture() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        control.command(&env, &driver, "a", &Command::StartCapture);
        env.take();

        assert!(control.owner_gone(&env, 1, "b").is_none(), "not b's capture");
        assert!(control.owner_gone(&env, 1, "a").is_some());
        assert_eq!(states(&env.take()), vec![(To::All, "idle".into(), Value::Null)]);
    }

    // --- parsing and restart -------------------------------------------------

    /// agent.py:1186-1191 ignores text that is not a JSON object; 1371-1379
    /// names an unknown type back with the version in the sentence, and a
    /// missing type is Python's `None`.
    #[test]
    fn what_is_not_a_command_is_ignored_or_named() {
        let env = FakeEnv::with(&["a"], three());
        let control: Control<FakeRunning> = Control::new();
        for text in ["{not json", "[1,2]", "5", "\"start_capture\""] {
            control.parse_failed(&env, "a", &protocol::parse_command(text).unwrap_err());
        }
        assert!(env.take().is_empty(), "silently, as agent.py does");

        control.parse_failed(&env, "a", &protocol::parse_command(r#"{"type":"teleport"}"#).unwrap_err());
        control.parse_failed(&env, "a", &protocol::parse_command("{}").unwrap_err());
        // `authenticate` is agent.py's pairing-token handshake, which must not
        // come back on Windows (CLAUDE.md banner, ADR 0029).
        control.parse_failed(&env, "a", &protocol::parse_command(r#"{"type":"authenticate"}"#).unwrap_err());
        let messages: Vec<Value> = env.take().into_iter().map(|(_, m)| m["message"].clone()).collect();
        let v = crate::VERSION;
        assert_eq!(messages, vec![
            json!(format!("This agent ({v}) does not understand 'teleport'.")),
            json!(format!("This agent ({v}) does not understand 'None'.")),
            json!(format!("This agent ({v}) does not understand 'authenticate'.")),
        ]);
    }

    /// agent.py:1354-1370: refused with the reason when it cannot come back,
    /// and otherwise scheduled - neither broadcasts a state.
    #[test]
    fn restart_is_refused_unless_it_can_come_back() {
        let env = FakeEnv::with(&["a", "b"], three());
        let refused = RestartSupport {
            allowed: false,
            reason: "Restart is unavailable: this agent is not running as the Inwire service.".into(),
        };
        restart_agent(&env, &refused, "a");
        assert_eq!(env.take(), vec![(To::One("a".into()), json!({
            "type": "error", "code": "restart_unavailable",
            "message": "Restart is unavailable: this agent is not running as the Inwire service.",
        }))]);
        assert_eq!(env.take_logs(), vec![(
            Level::Warning,
            "restart_agent refused - Restart is unavailable: this agent is not running as the Inwire service.".into()
        )]);
        assert_eq!(env.restarts.load(Ordering::SeqCst), 0);

        restart_agent(&env, &RestartSupport { allowed: true, reason: String::new() }, "a");
        assert!(env.take().is_empty());
        assert_eq!(env.take_logs(), vec![(Level::Info, "restart_agent requested by a client".into())]);
        assert_eq!(env.restarts.load(Ordering::SeqCst), 1);
    }

    // --- the interface list, and Npcap arriving late ---------------------------

    /// agent.py:2082-2098: what changed is logged, with the two-space indent the
    /// log parser preserves; an unchanged list says nothing; a failed read
    /// keeps what was there (2074-2080).
    #[test]
    fn a_re_read_interface_list_says_what_moved() {
        let logs = Mutex::new(Vec::new());
        let log = |level: Level, text: &str| logs.lock().unwrap().push((level, text.to_string()));

        let first = refresh_interfaces(&log, &[], Ok(three()[..2].to_vec()));
        let second = refresh_interfaces(&log, &first, Ok(vec![three()[1].clone(), three()[2].clone()]));
        assert_eq!(second.len(), 2);
        let unchanged = refresh_interfaces(&log, &second, Ok(second.clone()));
        let kept = refresh_interfaces(&log, &unchanged, Err("PacketGetAdapterNames failed".into()));
        assert_eq!(kept, unchanged);

        assert_eq!(*logs.lock().unwrap(), vec![
            (Level::Info, "detected 2 network interface(s)".to_string()),
            (Level::Info, format!("  interface available: Ethernet 2 (Intel(R) I225-V) -> {A}")),
            (Level::Info, format!("  interface available: Wi-Fi (Intel(R) Wi-Fi 6E AX211) -> {B}")),
            (Level::Info, "detected 2 network interface(s)".to_string()),
            (Level::Info, format!("  interface available: Adapter for loopback traffic capture -> {LO}")),
            (Level::Info, format!("  interface gone: Ethernet 2 (Intel(R) I225-V) -> {A}")),
            (Level::Warning, "could not re-enumerate network interfaces (PacketGetAdapterNames failed); keeping the previous list".to_string()),
        ]);
    }

    /// Must-fix 1: a load that fails is tried again on the next ask, and the
    /// first success is kept for the life of the process - so Npcap installed
    /// after the service started is found by the next connection.
    #[test]
    fn a_failed_load_is_retried_and_a_success_is_kept() {
        let lazy: Lazy<String> = Lazy::new();
        assert_eq!(lazy.get_or_load(|| Err("wpcap.dll not found".into())), Err("wpcap.dll not found".into()));
        assert_eq!(lazy.get_or_load(|| Err("wpcap.dll not found".into())), Err("wpcap.dll not found".into()));
        assert!(lazy.get().is_none());

        let (value, failed_before) = lazy.get_or_load(|| Ok("npcap".to_string())).unwrap();
        assert_eq!((value.as_str(), failed_before), ("npcap", 2), "loaded now, after two failures");
        let (again, failed_before) =
            lazy.get_or_load(|| panic!("a loaded library is never loaded twice")).unwrap();
        assert_eq!((again.as_str(), failed_before), ("npcap", 0));
        assert!(std::ptr::eq(value, again));
    }

    #[test]
    fn repr_matches_pythons_for_the_labels_windows_produces() {
        assert_eq!(py_repr("Ethernet 2"), "'Ethernet 2'");
        assert_eq!(py_repr("Bob's Wi-Fi"), "\"Bob's Wi-Fi\"");
        assert_eq!(py_repr(r"\Device\NPF_{A}"), r"'\\Device\\NPF_{A}'");
        assert_eq!(py_repr("it's \"x\""), r#"'it\'s "x"'"#);
        // What Python's repr escapes that would break a line: C0, C1, and the
        // Unicode line and paragraph separators.
        assert_eq!(py_repr("a\u{85}b\u{2028}c\u{7f}"), r"'a\x85b\u2028c\x7f'");
    }

    /// **A selected name cannot write a log line of its own.** The log is one
    /// event per line and the app reads it back line by line, so a device name
    /// carrying CR/LF and a timestamp would otherwise forge an entry - from a
    /// client, into a privileged service's log. The name is escaped and
    /// bounded; the broadcast carries it as JSON, which escapes on its own.
    #[test]
    fn a_selected_name_cannot_forge_a_log_line() {
        let forged = "\\Device\\NPF_{X}\r\n2026-09-26 13:00:00,000 ERROR   agent compromised";
        let env = FakeEnv::with(&["a"], three());
        let control = Control::new();
        control.command(&env, &FakeDriver::default(), "a", &set(&[forged, A]));
        env.take_logs();
        control.command(&env, &FakeDriver::default(), "a", &Command::StartCapture);

        let logs = env.take_logs();
        let line = &logs.iter().find(|(level, _)| *level == Level::Warning).expect("reported").1;
        assert!(!line.contains('\r') && !line.contains('\n'), "{line:?}");
        assert!(line.contains(r"\r\n2026-09-26"), "escaped, not dropped: {line}");

        let long = "N".repeat(protocol::MAX_INTERFACE_NAME_CHARS);
        assert_eq!(log_safe(&long).chars().count(), LOG_NAME_CHARS + 3, "bounded, and marked as cut");
        assert!(log_safe(&long).ends_with("..."));
        assert_eq!(log_safe(r"\Device\NPF_{A}"), r"\Device\NPF_{A}", "a real name reads as agent.py's %s writes it");
    }

    /// **Many unknown names are one report, not a storm.** One unknown device
    /// is reported as agent.py reports any adapter; several are one warning and
    /// one `capture_failed` to every client, however many there were - a
    /// selection of 64 stale names was 64 warnings and 64 broadcasts.
    #[test]
    fn many_unknown_names_are_reported_once() {
        let env = FakeEnv::with(&["a", "b"], three());
        let driver = FakeDriver::default();
        let control = Control::new();
        let stale: Vec<String> =
            (0..protocol::MAX_SELECTED_INTERFACES - 1).map(|n| format!(r"\Device\NPF_{{GONE-{n}}}")).collect();
        let mut selection: Vec<&str> = stale.iter().map(String::as_str).collect();
        selection.push(A);
        control.command(&env, &driver, "a", &set(&selection));
        env.take();
        env.take_logs();
        control.command(&env, &driver, "a", &Command::StartCapture);

        let sent = env.take();
        let failed = errors(&sent);
        assert_eq!(failed.len(), 1, "one report for {} unknown names", stale.len());
        assert_eq!(failed[0].0, To::All);
        assert!(failed[0].1.get("iface").is_none());
        assert_eq!(
            failed[0].1["message"],
            format!("Could not capture on {} selected adapters: {NOT_LISTED_MANY}", stale.len())
        );
        let warnings: Vec<String> = env.take_logs().into_iter()
            .filter(|(level, _)| *level == Level::Warning).map(|(_, line)| line).collect();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].starts_with(&format!("capture failed on {} selected interfaces: ", stale.len())));
        assert!(warnings[0].ends_with(&format!(" and {} more)", stale.len() - 3)), "{}", warnings[0]);
        // The adapter that exists still captures.
        assert_eq!(*driver.started.lock().unwrap(), vec![(1, vec![A.to_string()])]);
        assert_eq!(states(&sent), vec![(To::All, "sniffing".into(), json!("a"))]);
    }

    /// Past the bound, the selection is refused with a sentence that says which
    /// bound, under `agent.py`'s code for a malformed selection.
    #[test]
    fn a_selection_past_the_bound_is_refused_with_the_bound() {
        let env = FakeEnv::with(&["a"], three());
        let control: Control<FakeRunning> = Control::new();
        control.parse_failed(&env, "a", &ParseError::SelectionTooLarge);
        assert_eq!(env.take(), vec![(To::One("a".into()), json!({
            "type": "error", "code": "invalid_interfaces",
            "message": "set_interfaces names at most 64 interfaces, each at most 256 characters long.",
        }))]);
    }
}
