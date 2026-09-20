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

/// The adapter report: how this machine was *told* to behave.
///
/// **The app cannot decide a frame's direction without this**, and the cost of
/// that is not a missing column. `hostFromAdapters` builds `host.macs` from
/// here alone for a live capture; with it empty `directionFromMacs` answers
/// `Unknown` for every frame, and the checksum verdict then validates every
/// frame this machine sent against bytes the NIC had not finished writing -
/// 30.3% of one measured capture painted `Broken`. See
/// `scripts/dissect/checksum-verdict.ts`, which holds the app's half.
///
/// **`id` is the capture device name, not the GUID.** It is the join key to the
/// interface list (`\Device\NPF_{GUID}` on Windows), and `isValidAdapterList`
/// in `src/services/agentProtocol.ts` rejects an entry without one - an adapter
/// that cannot be attached to a capture interface has nowhere to go.
///
/// Every other field may be null, and null means **not known** rather than
/// zero, absent or disabled. That is the contract `AgentAdapter` states, and it
/// is why this can report what `GetAdaptersAddresses` gives and stay honest
/// about the DHCP lease fields it does not read.
pub fn adapter_config(adapters: &[AdapterReport]) -> Value {
    json!({
        "type": "adapter_config",
        "adapters": adapters.iter().map(AdapterReport::to_value).collect::<Vec<_>>(),
    })
}

/// One adapter, already joined to the capture device it belongs to.
pub struct AdapterReport {
    /// The capture device name - the join key.
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub mac: Option<String>,
    pub status: Option<&'static str>,
    pub mtu: Option<u32>,
    pub ipv4: Vec<(String, Option<u8>)>,
    pub ipv6: Vec<(String, Option<u8>, Option<&'static str>)>,
    pub dns_servers: Vec<String>,
    pub dns_suffix: Option<String>,
}

impl AdapterReport {
    fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mac": self.mac,
            "status": self.status,
            // Read from GetIfTable2 with the interface counters rather than
            // here: TransmitLinkSpeed sits past ZoneIndices[16] in the adapter
            // struct, and guessing at that offset to fill a cosmetic field is a
            // worse trade than saying "not known".
            "speedMbps": Value::Null,
            "mtu": self.mtu,
            // Not read. The lease fields need the DHCP client's own view, which
            // GetAdaptersAddresses carries in a tail this does not declare.
            "dhcpEnabled": Value::Null,
            "dhcpServer": Value::Null,
            "leaseObtained": Value::Null,
            "leaseExpires": Value::Null,
            "ipv4": self.ipv4.iter().map(|(address, prefix)| json!({
                "address": address,
                "prefixLength": prefix,
                "broadcast": Value::Null,
            })).collect::<Vec<_>>(),
            "ipv6": self.ipv6.iter().map(|(address, prefix, scope)| json!({
                "address": address,
                "prefixLength": prefix,
                "scope": scope,
                // Whether an address is an RFC 4941 privacy address needs the
                // suffix origin, which is a field past what is declared. Three
                // states matter here and `null` is the honest third.
                "temporary": Value::Null,
            })).collect::<Vec<_>>(),
            "gatewayV4": Value::Null,
            "gatewayV6": Value::Null,
            "gatewayMac": Value::Null,
            "dnsServers": self.dns_servers,
            "dnsSuffix": self.dns_suffix,
            // Which provider answered for each group, so a value on screen can
            // be traced. One provider here, and naming it is what lets the app
            // tell this agent's answer from the Python one's.
            "source": { "adapters": "GetAdaptersAddresses" },
        })
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
    /// The adapters to capture on, as the device NAMES the app was given in
    /// `hello` - `\Device\NPF_{GUID}` - and never as indices into that list.
    /// `src/services/agentProtocol.ts` declares `interfaces: string[]`, and
    /// `local-agent/agent.py` spawns one sniffer per entry by name.
    SetInterfaces(Vec<String>),
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
    /// `set_interfaces` with something that is not a list of device names.
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
                // Names, not numbers. A number is refused rather than coerced:
                // `0` would stringify to "0", match no device, and then be
                // selected silently - which is the shape of the bug this
                // replaced, where an unparseable selection became a capture on
                // whatever adapter happened to be first.
                let name = entry.as_str().ok_or(ParseError::BadInterfaces)?;
                out.push(name.to_string());
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

    /// **`set_interfaces` carries device NAMES, and this agent read indices.**
    ///
    /// `AgentCommand` in `src/services/agentProtocol.ts` declares
    /// `interfaces: string[]`, and `local-agent/agent.py` spawns one sniffer
    /// per entry as a name. This implementation demanded `as_u64`, so the app's
    /// message failed to parse, the selection stayed unset, and `start_capture`
    /// fell back to adapter 0 - a dead `WAN Miniport` on the machine this was
    /// found on. The agent reported `sniffing` perfectly truthfully and
    /// delivered nothing.
    ///
    /// The test that used to live here asserted `[0,2]` parsed to indices. It
    /// was written against this implementation rather than against the
    /// protocol, so it passed for as long as the bug existed - which is the
    /// whole argument for checking both ends against one shared description
    /// rather than each end against itself. `scripts/agent/command-vectors.json`
    /// is that description for the inbound direction, and `command_vectors.rs`
    /// is this end reading it.
    #[test]
    fn set_interfaces_carries_device_names_not_indices() {
        assert_eq!(
            parse_command(r#"{"type":"set_interfaces","interfaces":["\\Device\\NPF_{A}"]}"#),
            Ok(Command::SetInterfaces(vec![r"\Device\NPF_{A}".to_string()]))
        );
        // A number is not a name. Refused rather than coerced: `0` would
        // stringify to "0", which matches no device and would be selected
        // silently.
        assert_eq!(
            parse_command(r#"{"type":"set_interfaces","interfaces":[0,2]}"#),
            Err(ParseError::BadInterfaces)
        );
    }

    #[test]
    fn commands_parse_and_unknown_ones_are_named() {
        assert_eq!(parse_command(r#"{"type":"start_capture"}"#), Ok(Command::StartCapture));
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
        assert!(!may_run(&Command::SetInterfaces(vec!["x".into()]), "b", Some("a")));

        // Watching costs the owner nothing and is never gated.
        assert!(may_run(&logs, "b", Some("a")));
        assert!(may_run(&Command::SubscribeAdapters, "b", Some("a")));
        assert!(may_run(&Command::RefreshAdapters, "b", Some("a")));
    }
}

/// The app's own commands, parsed from the shared fixture.
///
/// **This is the check that was missing.** `control-vectors.json` holds what
/// the agent emits and `scripts/agent/control-vectors.ts` holds the app's
/// parser to it; nothing held THIS end to what the app sends. So
/// `set_interfaces` could be read as a list of indices here, be encoded as a
/// list of indices by the interop harness, and be asserted as a list of indices
/// by a unit test - three agreeing witnesses, none of them the app - while
/// every real capture opened the wrong adapter.
///
/// Reading the fixture rather than restating it is the whole point: the bytes
/// are produced by `encodeAgentCommand`, and if they change without this
/// parser changing, this fails.
#[cfg(test)]
mod command_vectors {
    use super::*;

    const VECTORS: &str = include_str!("../../scripts/agent/command-vectors.json");

    #[test]
    fn every_command_the_app_sends_is_understood() {
        let doc: Value = serde_json::from_str(VECTORS).expect("the fixture is JSON");
        let commands = doc["commands"].as_array().expect("commands is an array");
        assert!(!commands.is_empty(), "an empty fixture would pass vacuously");

        for entry in commands {
            let text = entry.as_str().expect("each vector is an encoded string");
            let parsed = parse_command(text);
            assert!(
                parsed.is_ok(),
                "the app sends {text} and this agent answered {parsed:?} - \
                 a command the agent cannot parse is one the app gets no effect from",
            );
        }
    }

    /// Named on its own, because a diff of thirteen strings does not say
    /// "adapter selection is broken" and this does.
    #[test]
    fn set_interfaces_from_the_app_is_a_device_name() {
        let doc: Value = serde_json::from_str(VECTORS).unwrap();
        let text = doc["commands"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .find(|c| c.contains("set_interfaces"))
            .expect("the fixture covers set_interfaces");

        match parse_command(text) {
            Ok(Command::SetInterfaces(names)) => {
                assert_eq!(names, vec![r"\Device\NPF_{A}".to_string()],
                    "the backslashes must survive, and the entry is a NAME");
            }
            other => panic!("the app's set_interfaces parsed as {other:?}"),
        }
    }
}
