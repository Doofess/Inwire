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
    /// This adapter's `LINKTYPE_*` value, when it could be read.
    ///
    /// **Neither agent used to say, so the app assumed Ethernet** - which is
    /// right for every adapter here but Npcap's loopback device, and that one
    /// is `DLT_NULL`. Read as Ethernet it produced fabricated MAC addresses
    /// with vendors attached to them, a direction decided from those MACs, and
    /// no transport layer at all.
    ///
    /// `None` when the device could not be opened to ask. Omitted from the
    /// JSON rather than sent as 1, because the app's fallback is Ethernet
    /// anyway and a guess written into the field would be indistinguishable
    /// from having asked. `AgentInterface.linkType` is optional for the same
    /// reason, and an agent that predates the field is a legal one.
    pub link_type: Option<i32>,
}

impl Interface {
    fn to_value(&self) -> Value {
        let mut value = json!({ "id": self.id, "name": self.name, "label": self.label });
        if let (Some(link_type), Some(object)) = (self.link_type, value.as_object_mut()) {
            object.insert("linkType".into(), json!(link_type));
        }
        value
    }
}

/// Per-adapter traffic rates, for the Interfaces panel's sparklines.
///
/// **Not `capture_stats`.** That one says what the capture received and lost;
/// this says what every adapter is carrying whether or not it is being captured
/// on, which is the panel's question - *is traffic arriving on an adapter I am
/// not capturing on?*
///
/// `intervalMs` is the agent's own cadence, which the app uses to size its
/// history window rather than assuming one. `src/services/agentProtocol.ts`
/// validates `name`, `packetsPerSec` and `bytesPerSec` per entry.
///
/// Beware the false friend next door: `struct InterfaceStats` in this file is
/// the `capture_stats` drop counter and has nothing to do with this.
pub fn interface_stats(interval_ms: u32, rates: &[crate::if_table::Rate]) -> Value {
    json!({
        "type": "interface_stats",
        "intervalMs": interval_ms,
        "interfaces": rates.iter().map(|r| json!({
            "name": r.name,
            "packetsPerSec": r.packets_per_sec,
            "bytesPerSec": r.bytes_per_sec,
        })).collect::<Vec<_>>(),
    })
}

/// An adapter that could not be opened, or stopped delivering under a capture.
///
/// `local-agent/agent.py`'s `report_capture_failure` (agent.py:1490-1501),
/// ported **with its text**: `"Could not capture on {label}: {reason}"`, where
/// the label is the one the interface list carries - the sentence a person
/// reads in the status bar, so it names the adapter they picked rather than a
/// list position. This said `"Capture stopped on interface 2: ..."` until the
/// parity audit; a number means nothing on screen.
///
/// `iface` is the adapter's id in the interface list, and it is **omitted**
/// rather than guessed when the selection named a device that is not in the
/// list at all. `agent.py` sends `iface: 0` there (`INTERFACE_IDS.get(name,
/// 0)`, agent.py:2213), which names a *different* adapter; `AgentErrorMessage`
/// declares the field optional, so absent is the honest shape.
///
/// Broadcast to every client, not only the owner - `send_control`, which is
/// what `agent.py` uses - because a second window showing "Capturing" is as
/// wrong as the first.
pub fn capture_failed(iface: Option<usize>, label: &str, reason: &str) -> Value {
    let mut message = Map::new();
    message.insert("type".into(), json!("error"));
    message.insert("code".into(), json!("capture_failed"));
    if let Some(iface) = iface {
        message.insert("iface".into(), json!(iface));
    }
    message.insert("message".into(), json!(format!("Could not capture on {label}: {reason}")));
    Value::Object(message)
}

/// A frame the driver delivered and the wire format cannot describe.
///
/// Sent as well as counted, because a counter the app does not render is a
/// loss nobody sees - and this file's own header is about exactly that: *"the
/// agent logged 260,000 dropped frames in one afternoon and the app showed a
/// clean, complete-looking list."* One message per capture, not one per frame.
pub fn frame_too_long(iface: usize, bytes: usize) -> Value {
    json!({
        "type": "error",
        "code": "frame_too_long",
        "iface": iface,
        "message": format!(
            "A {bytes}-byte frame cannot be framed - the record's length field is 16 bits. \
             Receive offload is coalescing past 64 KB; further frames of this size are counted \
             but not reported again."
        ),
    })
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
/// zero, absent or disabled. That is the contract `AgentAdapter` states.
///
/// **Field for field with `local-agent/adapters.py`'s Windows provider**, which
/// is what the app was written against: the same keys, the same sources for
/// each value where the value is a fact only one source holds (the DHCP lease
/// lives in the registry, and nowhere else says what it was), and the same
/// order. `crate::adapter_config` is where each is read and says why.
pub fn adapter_config(adapters: &[AdapterReport]) -> Value {
    adapter_config_from_values(adapters.iter().map(AdapterReport::to_value).collect())
}

/// The same message around adapters already turned into JSON - which is what
/// the change tracker holds, since it compares by value.
pub fn adapter_config_from_values(adapters: Vec<Value>) -> Value {
    json!({ "type": "adapter_config", "adapters": adapters })
}

/// One IPv4 address, as `AgentAdapterIpv4`.
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterIpv4 {
    pub address: String,
    pub prefix_length: Option<u8>,
    /// Computed from the address and prefix - Windows reports none.
    pub broadcast: Option<String>,
}

/// One IPv6 address, as `AgentAdapterIpv6`.
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterIpv6 {
    pub address: String,
    pub prefix_length: Option<u8>,
    pub scope: Option<&'static str>,
    /// `true` only when the OS said so. Never null on Windows: an address
    /// nothing marked is one nothing marked, which is `false`. Null is macOS's
    /// honest third answer and not one this agent gives.
    pub temporary: Option<bool>,
}

/// Which provider answered for each group, so a value on screen can be traced
/// back to where it came from - the app shows it as "From ..." beside the row.
///
/// The vocabulary is `adapters.py`'s, and every value this agent sends is one
/// the Python agent can send too: `windows_iflist` for what
/// `GetAdaptersAddresses` answered, `registry` for the TCP/IP parameters key,
/// and `route` - the macOS provider's name - where the Python agent says
/// `powershell`, because this agent reads the same routing and neighbour
/// tables `Get-NetRoute` and `Get-NetNeighbor` do, without the PowerShell.
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterSource {
    pub adapter: Option<&'static str>,
    pub addresses: Option<&'static str>,
    pub dhcp: Option<&'static str>,
    pub gateway: Option<&'static str>,
    pub dns: Option<&'static str>,
}

/// One adapter, already joined to the capture device it belongs to.
#[derive(Clone, Debug, PartialEq)]
pub struct AdapterReport {
    /// The capture device name - the join key.
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub mac: Option<String>,
    pub status: Option<&'static str>,
    pub speed_mbps: Option<u64>,
    pub mtu: Option<u32>,
    pub dhcp_enabled: Option<bool>,
    pub dhcp_server: Option<String>,
    /// Epoch seconds, as the registry stores them. Formatting a time belongs to
    /// whoever knows the reader's locale.
    pub lease_obtained: Option<u64>,
    pub lease_expires: Option<u64>,
    pub ipv4: Vec<AdapterIpv4>,
    pub ipv6: Vec<AdapterIpv6>,
    pub gateway_v4: Option<String>,
    pub gateway_v6: Option<String>,
    pub gateway_mac: Option<String>,
    pub dns_servers: Vec<String>,
    pub dns_suffix: Option<String>,
    pub source: AdapterSource,
}

impl AdapterReport {
    pub fn to_value(&self) -> Value {
        json!({
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "mac": self.mac,
            "status": self.status,
            "speedMbps": self.speed_mbps,
            "mtu": self.mtu,
            "dhcpEnabled": self.dhcp_enabled,
            "dhcpServer": self.dhcp_server,
            "leaseObtained": self.lease_obtained,
            "leaseExpires": self.lease_expires,
            "ipv4": self.ipv4.iter().map(|a| json!({
                "address": a.address,
                "prefixLength": a.prefix_length,
                "broadcast": a.broadcast,
            })).collect::<Vec<_>>(),
            "ipv6": self.ipv6.iter().map(|a| json!({
                "address": a.address,
                "prefixLength": a.prefix_length,
                "scope": a.scope,
                "temporary": a.temporary,
            })).collect::<Vec<_>>(),
            "gatewayV4": self.gateway_v4,
            "gatewayV6": self.gateway_v6,
            "gatewayMac": self.gateway_mac,
            "dnsServers": self.dns_servers,
            "dnsSuffix": self.dns_suffix,
            "source": {
                "adapter": self.source.adapter,
                "addresses": self.source.addresses,
                "dhcp": self.source.dhcp,
                "gateway": self.source.gateway,
                "dns": self.source.dns,
            },
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
        // **No `authRequired`, and its absence is the point.** The pipe's
        // descriptor is the authentication (ADR 0029): there is no pairing
        // token on Windows, and CLAUDE.md's banner lists the field among the
        // things that must not come back. It was sent here as `false` "so an
        // older app sees the answer it expects", but no app reads it - the
        // parser accepts a hello with or without it, and
        // `scripts/agent-protocol/message-parsing.ts` holds it to both - so
        // all it did was keep the word on the wire. The Python agent still
        // sends it, for the macOS and Linux WebSocket, where the token is real.
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
    // Frames the driver delivered that the wire format could not describe.
    // Its own figure rather than folded into `dropped_agent`: a frame shed
    // under pressure and a frame too long to encode want opposite responses.
    dropped_oversize: u64,
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
    // Omitted when zero, which is the ordinary case, so the field's presence
    // is itself the signal that receive offload is coalescing past 64 KB.
    if dropped_oversize > 0 {
        message.insert("droppedOversize".into(), json!(dropped_oversize));
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

/// Why a client's frame did not become a `Command`.
///
/// **Two of these are answered with silence and the rest with a sentence**, and
/// the split is `agent.py`'s (agent.py:1186-1191 and 1371-1379): text that is not
/// JSON, or JSON that is not an object, is dropped without a word - there is no
/// command in it to name - while an object whose `type` this build does not know
/// is told so, because a newer app talking to an older agent must not wait for
/// an answer that never comes.
#[derive(Debug, PartialEq)]
pub enum ParseError {
    /// Not JSON at all. Ignored.
    NotJson,
    /// JSON, but not an object - `[1]`, `5`, `"start_capture"`. Ignored, as
    /// `agent.py`'s `isinstance(message, dict)` does.
    NotObject,
    /// An object with no `type`, or `type: null`. Answered as an unknown
    /// command named `None`, which is exactly what `agent.py` says -
    /// `message.get("type")` is `None` there and the reply formats it.
    NoType,
    /// Named, so the reply can say which command it did not know - which is how
    /// a version mismatch reports itself as a sentence rather than as silence.
    /// A `type` that is not a string is carried as Python's `str()` of it
    /// (`5`, `True`), because that is what `agent.py` puts in the reply.
    Unknown(String),
    /// `set_interfaces` with something that is not a list of device names.
    BadInterfaces,
    /// `set_interfaces` with an empty list. A capture on no adapter is a capture
    /// that silently returns nothing, so it is refused rather than accepted.
    EmptyInterfaces,
    /// `set_interfaces` naming more than `MAX_SELECTED_INTERFACES` devices, or
    /// one whose name is longer than `MAX_INTERFACE_NAME_CHARS`.
    SelectionTooLarge,
}

/// The most devices one `set_interfaces` may name.
///
/// **Not a limit `agent.py` has**, and set far above any real selection. This
/// machine lists 9 capture devices, and it is not a small one: six WAN
/// Miniports, two Wi-Fi Direct adapters and a Bluetooth PAN beside the
/// Ethernet, Wi-Fi and loopback anyone would name. A Hyper-V or Docker host adds
/// a vEthernet per virtual switch and a VPN client one more each, which is how
/// a busy workstation reaches a few dozen. Past 64 a list is not a selection:
/// the app only ever sends names from the list it was given, and nothing a
/// client can gain from a longer one is worth a privileged service parsing,
/// resolving and reporting on it.
pub const MAX_SELECTED_INTERFACES: usize = 64;

/// The longest device name a selection may carry. Npcap's are about fifty
/// characters - `\Device\NPF_{` + a GUID + `}` - and a name travels into log
/// lines and into a `capture_failed` sent to every client, so it is bounded
/// here, once, rather than wherever it is repeated.
pub const MAX_INTERFACE_NAME_CHARS: usize = 256;

/// Python's `str()` of a JSON value that was not a string where a command name
/// belongs, so the `unknown_command` sentence reads as `agent.py`'s does.
fn python_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        Value::String(text) => text.clone(),
        // Numbers print the same in both; a list or an object is approximated
        // by its JSON, which differs from Python's repr only in spacing.
        other => other.to_string(),
    }
}

pub fn parse_command(text: &str) -> Result<Command, ParseError> {
    let value: Value = serde_json::from_str(text).map_err(|_| ParseError::NotJson)?;
    if !value.is_object() {
        return Err(ParseError::NotObject);
    }
    let kind = match value.get("type") {
        None | Some(Value::Null) => return Err(ParseError::NoType),
        Some(Value::String(kind)) => kind.as_str(),
        Some(other) => return Err(ParseError::Unknown(python_str(other))),
    };
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
            let mut out = Vec::with_capacity(list.len().min(MAX_SELECTED_INTERFACES));
            for entry in list {
                // Names, not numbers. A number is refused rather than coerced:
                // `0` would stringify to "0", match no device, and then be
                // selected silently - which is the shape of the bug this
                // replaced, where an unparseable selection became a capture on
                // whatever adapter happened to be first.
                let name = entry.as_str().ok_or(ParseError::BadInterfaces)?;
                out.push(name);
            }
            // After the shape, so a list of numbers is still told what
            // `agent.py` tells it (agent.py:1240-1247).
            if out.len() > MAX_SELECTED_INTERFACES
                || out.iter().any(|name| name.chars().count() > MAX_INTERFACE_NAME_CHARS)
            {
                return Err(ParseError::SelectionTooLarge);
            }
            Ok(Command::SetInterfaces(out.into_iter().map(str::to_string).collect()))
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
///
/// **The static half of the rule only.** The runtime's gate is
/// `control::Control`'s `busy`, which adds the two conditions `agent.py`'s
/// `owned_by_other` has and this cannot see: the owner's capture must be
/// *running*, and its pipe must still be *connected* (agent.py:1393-1406). An
/// owner whose capture died or whose window closed holds nothing. This stays
/// for `examples/agent_serve.rs`, which has one client and no such cases.
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
            // One with a link type and one without, because absent and present
            // are different messages: `linkType` is omitted rather than sent
            // as 1, and the test below holds the pair apart.
            Interface {
                id: 0,
                name: r"\Device\NPF_{A}".into(),
                label: "Ethernet".into(),
                link_type: Some(1),
            },
            Interface {
                id: 1,
                name: r"\Device\NPF_{B}".into(),
                label: "Wi-Fi".into(),
                link_type: None,
            },
        ]
    }

    #[test]
    fn an_unknown_link_type_is_omitted_rather_than_guessed() {
        let h = hello("1.0.0", CaptureState::Idle, &ifaces(), "rs-1", None, None);
        let list = h["interfaces"].as_array().expect("interfaces is a list");
        assert_eq!(list[0]["linkType"], 1);
        assert!(
            list[1].get("linkType").is_none(),
            "an adapter that could not be asked must not claim Ethernet",
        );
    }

    #[test]
    fn hello_states_facts_and_never_asks_for_a_token() {
        let h = hello("1.0.0", CaptureState::Idle, &ifaces(), "rs-1", None, Some("D:NO_ACCESS_CONTROL"));
        assert_eq!(h["type"], "hello");
        assert_eq!(h["state"], "idle");
        // The pipe's ACL is the authentication, so there is nothing to ask for
        // and no field to ask with (CLAUDE.md banner, ADR 0029).
        let keys: Vec<&String> = h.as_object().unwrap().keys().collect();
        assert!(
            !keys.iter().any(|k| k.to_ascii_lowercase().starts_with("auth")),
            "a hello names no authentication: {keys:?}"
        );
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
            0,
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
        assert_eq!(capture_stats(1000, 0, 0, Some(7), 0, &[])["droppedPipe"], 7);
        assert_eq!(capture_stats(1000, 0, 0, Some(0), 0, &[])["droppedPipe"], 0);

        // The oversize stage follows the same rule as the pipe one: omitted
        // when there is nothing to report, so its presence is the signal.
        assert!(
            capture_stats(1000, 0, 0, None, 0, &[]).get("droppedOversize").is_none(),
            "a stage with nothing to report is omitted, not sent as 0"
        );
        assert_eq!(capture_stats(1000, 0, 0, None, 5, &[])["droppedOversize"], 5);
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
        assert_eq!(parse_command(r#"{"type":null}"#), Err(ParseError::NoType));
        // agent.py:1190 - JSON that is not an object carries no command.
        assert_eq!(parse_command("[1,2]"), Err(ParseError::NotObject));
        assert_eq!(parse_command(r#""start_capture""#), Err(ParseError::NotObject));
        // agent.py:1377 formats a non-string type with str(), so 5 is '5'.
        assert_eq!(parse_command(r#"{"type":5}"#), Err(ParseError::Unknown("5".into())));
        assert_eq!(parse_command(r#"{"type":true}"#), Err(ParseError::Unknown("True".into())));
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

    /// A selection is bounded in count and in name length, and the bound is the
    /// last thing checked - a list of numbers is still told it is not a list of
    /// names, which is `agent.py`'s answer.
    #[test]
    fn a_selection_is_bounded_in_count_and_in_name_length() {
        let names = |n: usize, len: usize| -> String {
            let one = format!("\"{}\"", "N".repeat(len));
            format!(r#"{{"type":"set_interfaces","interfaces":[{}]}}"#, vec![one; n].join(","))
        };
        assert!(matches!(
            parse_command(&names(MAX_SELECTED_INTERFACES, MAX_INTERFACE_NAME_CHARS)),
            Ok(Command::SetInterfaces(list)) if list.len() == MAX_SELECTED_INTERFACES
        ));
        assert_eq!(
            parse_command(&names(MAX_SELECTED_INTERFACES + 1, 50)),
            Err(ParseError::SelectionTooLarge)
        );
        assert_eq!(
            parse_command(&names(1, MAX_INTERFACE_NAME_CHARS + 1)),
            Err(ParseError::SelectionTooLarge)
        );
        let numbers = format!(
            r#"{{"type":"set_interfaces","interfaces":[{}]}}"#,
            vec!["0"; MAX_SELECTED_INTERFACES + 1].join(",")
        );
        assert_eq!(parse_command(&numbers), Err(ParseError::BadInterfaces));
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
