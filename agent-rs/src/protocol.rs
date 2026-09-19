//! The control messages, and the rules about who may send which.
//!
//! The port of the message-building and dispatch halves of
//! `local-agent/agent.py`. The app's side is `src/services/agentProtocol.ts`,
//! whose parser refuses anything it does not recognise - so a shape invented
//! here does not fail loudly, it is dropped silently by a validator doing its
//! job. `scripts/agent/control-vectors.json` holds the shapes for that reason.
//!
//! ## The agent states facts and the app decides
//!
//! ADR 0010 for frames, and it holds for everything else too: `npcapAccess`
//! travels as the **SDDL string**, not as "admin only" or "open"; the driver's
//! counters travel as numbers, not as "healthy"; an interface list is names and
//! labels, not a recommendation. Every verdict in this system is computed in
//! TypeScript where it can be asserted as a pure function, and none is computed
//! here where it would need a running service to test.
//!
//! ## Ownership is the one rule with teeth
//!
//! A capture belongs to the connection that started it. A second client may
//! watch the state and read the logs, and may not start, stop or re-point the
//! capture - it gets `capture_busy`. Without that, a second Windows user's app
//! silently re-points the first user's capture at a different adapter.

use serde_json::{json, Map, Value};

/// A connected client, as the protocol sees it.
pub type ClientId = String;

/// One capture interface, as `hello` and `state` list it.
///
/// `id` is the **list position**, and that is what a packet record's `iface`
/// field means. It is not a stable identifier and must not be treated as one:
/// the list is re-enumerated on every connection, which is what fixes the race
/// against Npcap finishing its own start-up.
#[derive(Clone, Debug, PartialEq)]
pub struct Interface {
    pub id: usize,
    pub name: String,
    pub label: String,
}

impl Interface {
    fn to_value(&self) -> Value {
        json!({ "id": self.id, "name": self.name, "label": self.label })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureState {
    Idle,
    Sniffing,
}

impl CaptureState {
    pub fn as_str(self) -> &'static str {
        match self {
            CaptureState::Idle => "idle",
            CaptureState::Sniffing => "sniffing",
        }
    }
}

fn interfaces_value(interfaces: &[Interface]) -> Value {
    Value::Array(interfaces.iter().map(Interface::to_value).collect())
}

/// The first message on every connection.
///
/// **`npcapAccess` is the SDDL string or null.** Read per connection, because
/// Npcap can be reinstalled under a running service and a cached answer would
/// outlive the reinstall that changed it. Null means unreadable, which is a
/// third answer the app renders as "unknown" rather than rounding to either.
#[allow(clippy::too_many_arguments)]
pub fn hello(
    version: &str,
    state: CaptureState,
    interfaces: &[Interface],
    client_id: &str,
    owner: Option<&str>,
    npcap_access: Option<&str>,
) -> Value {
    json!({
        "type": "hello",
        "version": version,
        "state": state.as_str(),
        "interfaces": interfaces_value(interfaces),
        "clientId": client_id,
        "owner": owner,
        // **Always false, and present rather than omitted.** The pipe's
        // descriptor is the authentication (ADR 0029); there is no pairing
        // token on Windows and there must not be one. The field stays so an
        // older app that reads it sees the answer it expects.
        "authRequired": false,
        "npcapAccess": npcap_access,
    })
}

/// Broadcast whenever the capture's state or the interface list changes.
pub fn state(state: CaptureState, interfaces: &[Interface], owner: Option<&str>) -> Value {
    json!({
        "type": "state",
        "state": state.as_str(),
        "interfaces": interfaces_value(interfaces),
        "owner": owner,
    })
}

/// Per-interface counters for one `capture_stats`.
#[derive(Clone, Copy, Debug)]
pub struct InterfaceStats {
    pub iface: usize,
    pub received: u64,
    /// `None` when the driver's counters could not be read. **Never 0.**
    pub kernel: Option<(u32, u32)>,
}

/// The message that makes loss visible.
///
/// Before it existed the agent logged 260,000 dropped frames in one afternoon
/// and the app showed a clean, complete-looking list.
///
/// Three absences are modelled and none is rounded to zero: a driver counter
/// that could not be read, and a pipe counter this transport cannot report.
pub fn capture_stats(
    interval_ms: u32,
    seq_high: u64,
    dropped_agent: u64,
    dropped_pipe: Option<u64>,
    interfaces: &[InterfaceStats],
) -> Value {
    let entries: Vec<Value> = interfaces
        .iter()
        .map(|s| {
            json!({
                "iface": s.iface,
                "received": s.received,
                "kernelReceived": s.kernel.map(|(r, _)| r),
                "droppedKernel": s.kernel.map(|(_, d)| d),
            })
        })
        .collect();
    let mut message = Map::new();
    message.insert("type".into(), json!("capture_stats"));
    message.insert("intervalMs".into(), json!(interval_ms));
    message.insert("seqHigh".into(), json!(seq_high));
    message.insert("droppedAgent".into(), json!(dropped_agent));
    // **Omitted, not null, when there is nothing to report.** The app reads an
    // absent field as unknown; a present null would have to be handled as a
    // third case by a validator that already has one.
    if let Some(n) = dropped_pipe {
        message.insert("droppedPipe".into(), json!(n));
    }
    message.insert("interfaces".into(), Value::Array(entries));
    Value::Object(message)
}

pub fn error(code: &str, message: &str) -> Value {
    json!({ "type": "error", "code": code, "message": message })
}

// --- what the client may send ------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum Command {
    StartCapture,
    StopCapture,
    SetInterfaces(Vec<usize>),
    SubscribeLogs,
    UnsubscribeLogs,
    SubscribeInterfaceStats,
    UnsubscribeInterfaceStats,
    SubscribeSockets,
    UnsubscribeSockets,
    SubscribeAdapters,
    UnsubscribeAdapters,
    RefreshAdapters,
    RestartAgent,
}

#[derive(Debug, PartialEq)]
pub enum ParseError {
    NotJson,
    NoType,
    /// Named, so the reply can say which command it did not know - which is how
    /// a version mismatch reports itself as a sentence rather than as silence.
    Unknown(String),
    /// `set_interfaces` with something that is not a list of indices.
    BadInterfaces,
    /// `set_interfaces` with an empty list. A capture on no adapter is a capture
    /// that silently returns nothing, so it is refused rather than accepted.
    EmptyInterfaces,
}

pub fn parse_command(text: &str) -> Result<Command, ParseError> {
    let value: Value = serde_json::from_str(text).map_err(|_| ParseError::NotJson)?;
    let kind = value.get("type").and_then(Value::as_str).ok_or(ParseError::NoType)?;
    match kind {
        "start_capture" => Ok(Command::StartCapture),
        "stop_capture" => Ok(Command::StopCapture),
        "set_interfaces" => {
            let list = value.get("interfaces").and_then(Value::as_array);
            let Some(list) = list else {
                return Err(ParseError::BadInterfaces);
            };
            if list.is_empty() {
                return Err(ParseError::EmptyInterfaces);
            }
            let mut out = Vec::with_capacity(list.len());
            for entry in list {
                // A float or a negative is not an index. Refused rather than
                // rounded: `as usize` on -1 is 18 quintillion.
                let n = entry.as_u64().ok_or(ParseError::BadInterfaces)?;
                out.push(n as usize);
            }
            Ok(Command::SetInterfaces(out))
        }
        "subscribe_logs" => Ok(Command::SubscribeLogs),
        "unsubscribe_logs" => Ok(Command::UnsubscribeLogs),
        "subscribe_interface_stats" => Ok(Command::SubscribeInterfaceStats),
        "unsubscribe_interface_stats" => Ok(Command::UnsubscribeInterfaceStats),
        "subscribe_sockets" => Ok(Command::SubscribeSockets),
        "unsubscribe_sockets" => Ok(Command::UnsubscribeSockets),
        "subscribe_adapters" => Ok(Command::SubscribeAdapters),
        "unsubscribe_adapters" => Ok(Command::UnsubscribeAdapters),
        "refresh_adapters" => Ok(Command::RefreshAdapters),
        "restart_agent" => Ok(Command::RestartAgent),
        other => Err(ParseError::Unknown(other.to_string())),
    }
}

/// Does this command change the capture, and therefore need ownership?
///
/// A pure function so the rule can be asserted without a service. The three
/// that qualify are exactly the three that can make another client's capture
/// stop, restart, or point somewhere else.
pub fn needs_ownership(command: &Command) -> bool {
    matches!(
        command,
        Command::StartCapture | Command::StopCapture | Command::SetInterfaces(_)
    )
}

/// Whether `client` may run `command` given who owns the capture.
///
/// `owner: None` means nobody has started one, so the first to ask becomes the
/// owner. Subscriptions are always allowed: a second client watching the state,
/// the logs or the adapter list costs the first nothing.
pub fn may_run(command: &Command, client: &str, owner: Option<&str>) -> bool {
    if !needs_ownership(command) {
        return true;
    }
    match owner {
        None => true,
        Some(o) => o == client,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ifaces() -> Vec<Interface> {
        vec![
            Interface { id: 0, name: r"\Device\NPF_{A}".into(), label: "Ethernet".into() },
            Interface { id: 1, name: r"\Device\NPF_{B}".into(), label: "Wi-Fi".into() },
        ]
    }

    #[test]
    fn hello_states_facts_and_never_asks_for_a_token() {
        let h = hello("1.0.0", CaptureState::Idle, &ifaces(), "rs-1", None, Some("D:NO_ACCESS_CONTROL"));
        assert_eq!(h["type"], "hello");
        assert_eq!(h["state"], "idle");
        assert_eq!(h["authRequired"], false, "the pipe's ACL is the authentication");
        // The SDDL travels, not a verdict about it.
        assert_eq!(h["npcapAccess"], "D:NO_ACCESS_CONTROL");
        assert_eq!(h["interfaces"][1]["label"], "Wi-Fi");
        assert_eq!(h["interfaces"][1]["id"], 1);
        assert!(h["owner"].is_null());
    }

    #[test]
    fn an_unreadable_driver_counter_is_null_and_never_zero() {
        let stats = capture_stats(
            1000,
            42,
            3,
            None,
            &[
                InterfaceStats { iface: 0, received: 10, kernel: Some((12, 2)) },
                InterfaceStats { iface: 1, received: 5, kernel: None },
            ],
        );
        assert_eq!(stats["interfaces"][0]["droppedKernel"], 2);
        assert!(
            stats["interfaces"][1]["droppedKernel"].is_null(),
            "unreadable is null, because 0 would read as 'nothing was lost'"
        );
        assert!(
            stats.get("droppedPipe").is_none(),
            "a counter with nothing to report is omitted, not sent as 0"
        );
        assert_eq!(capture_stats(1000, 0, 0, Some(7), &[])["droppedPipe"], 7);
        assert_eq!(capture_stats(1000, 0, 0, Some(0), &[])["droppedPipe"], 0);
    }

    #[test]
    fn commands_parse_and_unknown_ones_are_named() {
        assert_eq!(parse_command(r#"{"type":"start_capture"}"#), Ok(Command::StartCapture));
        assert_eq!(
            parse_command(r#"{"type":"set_interfaces","interfaces":[0,2]}"#),
            Ok(Command::SetInterfaces(vec![0, 2]))
        );
        assert_eq!(parse_command("{not json"), Err(ParseError::NotJson));
        assert_eq!(parse_command("{}"), Err(ParseError::NoType));
        assert_eq!(
            parse_command(r#"{"type":"fly"}"#),
            Err(ParseError::Unknown("fly".into())),
            "named, so the reply can say which command it did not know"
        );
    }

    #[test]
    fn a_capture_on_no_adapter_is_refused_rather_than_started() {
        assert_eq!(
            parse_command(r#"{"type":"set_interfaces","interfaces":[]}"#),
            Err(ParseError::EmptyInterfaces)
        );
        assert_eq!(
            parse_command(r#"{"type":"set_interfaces","interfaces":"eth0"}"#),
            Err(ParseError::BadInterfaces)
        );
        // `as usize` on -1 is 18 quintillion, so a negative is refused rather
        // than cast.
        assert_eq!(
            parse_command(r#"{"type":"set_interfaces","interfaces":[-1]}"#),
            Err(ParseError::BadInterfaces)
        );
        assert_eq!(
            parse_command(r#"{"type":"set_interfaces","interfaces":[1.5]}"#),
            Err(ParseError::BadInterfaces)
        );
    }

    #[test]
    fn ownership_gates_exactly_the_three_that_can_disturb_another_client() {
        let start = Command::StartCapture;
        let logs = Command::SubscribeLogs;

        // Nobody owns it: the first to ask may have it.
        assert!(may_run(&start, "a", None));
        // The owner may.
        assert!(may_run(&start, "a", Some("a")));
        // Somebody else may not - without this, a second Windows user's app
        // silently re-points the first user's capture.
        assert!(!may_run(&start, "b", Some("a")));
        assert!(!may_run(&Command::StopCapture, "b", Some("a")));
        assert!(!may_run(&Command::SetInterfaces(vec![0]), "b", Some("a")));

        // Watching costs the owner nothing and is never gated.
        assert!(may_run(&logs, "b", Some("a")));
        assert!(may_run(&Command::SubscribeAdapters, "b", Some("a")));
        assert!(may_run(&Command::RefreshAdapters, "b", Some("a")));
    }
}
