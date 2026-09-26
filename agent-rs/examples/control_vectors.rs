//! Emits every control message the Rust agent can send, as JSON.
//!
//!     cargo run --manifest-path agent-rs/Cargo.toml --example control_vectors \
//!       > scripts/agent/control-vectors.json
//!
//! The app's parser (`src/services/agentProtocol.ts`) **refuses what it does not
//! recognise**, which is correct and is also why a wrong shape here would not
//! fail loudly: it would be dropped by a validator doing its job, and the
//! symptom would be an app that connects and then shows nothing.
//!
//! So the shapes are written out and `scripts/agent/control-vectors.ts` feeds
//! every one of them through that parser on every `npm run check` - which gives
//! the TypeScript suite real coverage of the Rust agent's output without
//! needing cargo installed to get it.
//!
//! Regenerating is deliberately a redirect somebody types, for the reason the
//! wire vectors are: a fixture that rewrites itself on every run cannot catch
//! the change it exists to catch.

use inwire_agent::control;
use inwire_agent::agent_log;
use inwire_agent::protocol::{
    self, AdapterIpv4, AdapterIpv6, AdapterReport, AdapterSource, CaptureState, Interface,
    InterfaceStats,
};
use inwire_agent::sockets;
use serde_json::{json, Value};

fn main() {
    let interfaces = vec![
        Interface {
            id: 0,
            name: r"\Device\NPF_{28524299-03EF-4F59-A8D2-419D761418B7}".into(),
            label: "Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)".into(),
            link_type: Some(1),
        },
        Interface {
            id: 1,
            name: r"\Device\NPF_Loopback".into(),
            // DLT_NULL, which is what this device really is - the one adapter
            // on a Windows machine that is not Ethernet, and the reason the
            // field exists. The fixture carries the interesting value rather
            // than a second 1.
            label: "Adapter for loopback traffic capture".into(),
            link_type: Some(0),
        },
    ];

    let mut cases: Vec<Value> = Vec::new();
    let mut add = |note: &str, message: Value| {
        cases.push(json!({ "note": note, "message": message }));
    };

    add(
        "hello, idle, nobody owns the capture, the driver's DACL was readable",
        protocol::hello(
            "1.0.0",
            CaptureState::Idle,
            &interfaces,
            "rs-1",
            None,
            Some("D:P(A;;FA;;;SY)(A;;FA;;;BA)"),
        ),
    );
    add(
        "hello while another client is capturing - the app greys Start rather than hijacking",
        protocol::hello("1.0.0", CaptureState::Sniffing, &interfaces, "rs-2", Some("rs-1"), None),
    );
    add(
        "hello with no interfaces at all, which is what a machine with no Npcap looks like",
        protocol::hello("1.0.0", CaptureState::Idle, &[], "rs-3", None, None),
    );
    add(
        "state: capture started",
        protocol::state(CaptureState::Sniffing, &interfaces, Some("rs-1")),
    );
    add(
        "state: capture stopped and the owner released it",
        protocol::state(CaptureState::Idle, &interfaces, None),
    );
    add(
        "interface_stats: the rates the Interfaces panel draws",
        protocol::interface_stats(500, &[
            inwire_agent::if_table::Rate {
                name: r"\Device\NPF_{28524299-03EF-4F59-A8D2-419D761418B7}".to_string(),
                packets_per_sec: 12.0,
                bytes_per_sec: 1536.0,
            },
            // An adapter carrying nothing still reports, so the panel draws a
            // flat line rather than leaving a row blank.
            inwire_agent::if_table::Rate {
                name: r"\Device\NPF_{AFD92574-A48F-4DB3-B2DD-AC064979FDC7}".to_string(),
                packets_per_sec: 0.0,
                bytes_per_sec: 0.0,
            },
        ]),
    );
    add(
        "an adapter that stopped delivering under a capture, named by its label",
        protocol::capture_failed(
            Some(0),
            "Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)",
            "pcap_next_ex failed (-1): device removed",
        ),
    );
    add(
        "a selected device the interface list does not have - no id, rather than a wrong one",
        protocol::capture_failed(
            None,
            r"\Device\NPF_{00000000-0000-0000-0000-000000000000}",
            inwire_agent::control::NOT_LISTED,
        ),
    );
    add(
        "a frame the wire format cannot describe - receive offload past 64 KB",
        protocol::frame_too_long(0, 71_680),
    );
    add(
        "capture_stats carrying the oversize stage",
        protocol::capture_stats(
            1000,
            4096,
            12,
            Some(3),
            7,
            &[InterfaceStats { iface: 0, received: 4000, kernel: Some((4100, 100)) }],
        ),
    );
    add(
        "capture_stats with every counter readable",
        protocol::capture_stats(
            1000,
            4096,
            12,
            Some(3),
            0,
            &[InterfaceStats { iface: 0, received: 4000, kernel: Some((4100, 100)) }],
        ),
    );
    add(
        "capture_stats where one interface's driver counters could not be read - null, never 0",
        protocol::capture_stats(
            1000,
            10,
            0,
            Some(0),
            0,
            &[
                InterfaceStats { iface: 0, received: 10, kernel: Some((10, 0)) },
                InterfaceStats { iface: 1, received: 5, kernel: None },
            ],
        ),
    );
    add(
        "capture_stats from a transport that cannot report pipe drops - the field is absent",
        protocol::capture_stats(
            1000,
            10,
            0,
            None,
            0,
            &[InterfaceStats { iface: 0, received: 10, kernel: Some((10, 0)) }],
        ),
    );
    add(
        "socket_table: the snapshot that opens a subscription",
        sockets::socket_table(
            true,
            &[
                (("tcp", "10.0.0.4".into(), 54321), 4242),
                // A pid of 0 is a socket the OS will not attribute, and it is
                // kept rather than dropped: an unattributed socket is not the
                // same fact as no socket, and collapsing the two would let a
                // frame fall through to a stale entry for a reused port.
                (("udp", "0.0.0.0".into(), 5353), 0),
                // No zone index. `fe80::1%eth0` would never compare equal to
                // the address a captured frame carries.
                (("tcp", "fe80::1".into(), 443), 4242),
            ],
            &[],
            // Keyed by the pid AS A STRING, because JSON object keys are, and
            // the app reads them back with `Number(...)`. The second pid is
            // named with no path: a service can deny its own executable while
            // freely giving its name, and the name alone is worth having.
            serde_json::from_value(json!({
                "4242": { "name": "chrome.exe", "exe": r"C:\Program Files\Chrome\chrome.exe" },
                "8": { "name": "System", "exe": "" },
            }))
            .expect("an object"),
        ),
    );
    add(
        "socket_table: a delta, which is what every message after the first is",
        sockets::socket_table(
            false,
            &[(("tcp", "10.0.0.4".into(), 54400), 4242)],
            &[("tcp", "10.0.0.4".into(), 54321)],
            serde_json::from_value(json!({
                "4242": { "name": "chrome.exe", "exe": r"C:\Program Files\Chrome\chrome.exe" },
            }))
            .expect("an object"),
        ),
    );
    add(
        "socket_table: a delta that only closes sockets carries no processes",
        sockets::socket_table(
            false,
            &[],
            &[("udp", "0.0.0.0".into(), 5353)],
            serde_json::Map::new(),
        ),
    );
    // Three adapters as this agent reported them on the machine the port was
    // compared on, field for field equal to `local-agent/adapters.py`'s report
    // for the same adapters at the same moment: the wired one with a lease, a
    // gateway and two privacy addresses; a disconnected virtual one that only
    // has what Windows invents; and a WAN Miniport nothing knows anything about.
    add(
        "adapter_config: a wired adapter, a disconnected virtual one and a WAN Miniport",
        protocol::adapter_config(&[wired_adapter(), wifi_direct_adapter(), wan_miniport()]),
    );
    add(
        "adapter_config with no adapters - a machine with no Npcap has no capture list to narrow to",
        protocol::adapter_config(&[]),
    );
    // Lines from this machine's own `agent.log`, parsed as the backlog is. The
    // second keeps the two spaces the agent indents it with - the parser strips
    // the level's computed width and nothing more.
    add(
        "log: a backlog of real lines, one of them indented on purpose",
        agent_log::log_message(vec![
            agent_log::parse_line(
                "2026-09-22 10:01:23,743 ERROR   packet capture requires elevated privileges. \
                 Right-click and choose 'Run as administrator'.",
            ),
            agent_log::parse_line(
                r"2026-09-26 11:30:16,833 INFO      interface available: Ethernet (Intel(R) Ethernet Controller (3) I225-V) -> \Device\NPF_{64455981-5CEF-4A70-8218-4E5C316C795B}",
            ),
            agent_log::parse_line("2026-09-26 11:49:06,073 INFO    start_capture requested on 1 interface(s)"),
        ]),
    );
    add(
        "log: one live line",
        agent_log::log_message(vec![agent_log::parse_line(
            "2026-09-26 11:49:06,260 INFO    first packet captured - capture is working",
        )]),
    );
    add(
        "log: the backlog of an agent that has written nothing yet",
        agent_log::log_message(Vec::new()),
    );
    add(
        "error: a second client tried to start a capture somebody else owns",
        control::capture_busy(),
    );
    add(
        "error: a command this build does not know, named so the app can say which",
        control::unknown_command(inwire_agent::VERSION, "fly"),
    );
    add(
        "error: set_interfaces with something that is not a list of names",
        control::invalid_interfaces(),
    );
    add(
        "error: set_interfaces with an empty list",
        control::empty_interfaces(),
    );
    add(
        "error: start_capture with no adapter to capture on - a machine without Npcap",
        control::no_interfaces(),
    );
    add(
        "error: restart_agent from a process that is not the Inwire service",
        control::restart_unavailable(inwire_agent::restart::NOT_THE_SERVICE),
    );

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "note": "Control messages the Rust agent emits. Generated by \
                     `cargo run --example control_vectors`. Checked against the app's \
                     own parser by scripts/agent/control-vectors.ts.",
            "cases": cases,
        }))
        .expect("the vectors serialise")
    );
}

fn v6(address: &str, prefix: u8, scope: &'static str, temporary: bool) -> AdapterIpv6 {
    AdapterIpv6 {
        address: address.into(),
        prefix_length: Some(prefix),
        scope: Some(scope),
        temporary: Some(temporary),
    }
}

/// `Ethernet`, up at 2.5 Gb/s, on a DHCP lease with its gateway's MAC in the
/// registry. `mac` is what `hostFromAdapters` builds the host's identity from.
fn wired_adapter() -> AdapterReport {
    AdapterReport {
        id: r"\Device\NPF_{64455981-5CEF-4A70-8218-4E5C316C795B}".into(),
        name: "Ethernet".into(),
        description: Some("Intel(R) Ethernet Controller (3) I225-V".into()),
        mac: Some("04:7c:16:52:db:17".into()),
        status: Some("up"),
        speed_mbps: Some(2500),
        mtu: Some(1500),
        dhcp_enabled: Some(true),
        dhcp_server: Some("10.0.0.138".into()),
        lease_obtained: Some(1790416988),
        lease_expires: Some(1790420588),
        ipv4: vec![AdapterIpv4 {
            address: "10.0.0.7".into(),
            prefix_length: Some(24),
            broadcast: Some("10.0.0.255".into()),
        }],
        ipv6: vec![
            v6("2a06:c701:423b:fa00:ded:f6ae:9a1c:d19a", 64, "global", false),
            v6("2a06:c701:423b:fa00:905:b5f6:7cc4:a1d0", 128, "global", true),
            v6("2a06:c701:423b:fa00:4cf7:82a:8f92:7df7", 128, "global", true),
            v6("fe80::3f65:9cc9:cb3d:8e6e", 64, "link-local", false),
        ],
        gateway_v4: Some("10.0.0.138".into()),
        gateway_v6: Some("fe80::4615:24ff:fe5d:cc62".into()),
        gateway_mac: Some("44:15:24:5d:cc:62".into()),
        dns_servers: vec!["10.0.0.138".into(), "2a06:c701:ffff::1".into(), "2a06:c701:ffff::2".into()],
        dns_suffix: Some("home".into()),
        source: AdapterSource {
            adapter: Some("windows_iflist"),
            addresses: Some("windows_iflist"),
            dhcp: Some("registry"),
            gateway: Some("registry"),
            dns: Some("registry"),
        },
    }
}

/// A Wi-Fi Direct virtual adapter, down: no speed psutil could read, only the
/// addresses Windows assigns itself, and the site-local resolvers it configures
/// on an adapter that has none.
fn wifi_direct_adapter() -> AdapterReport {
    AdapterReport {
        id: r"\Device\NPF_{BEE4DB11-2AFA-4426-BA16-C443DE930911}".into(),
        name: "Local Area Connection* 8".into(),
        description: Some("Microsoft Wi-Fi Direct Virtual Adapter".into()),
        mac: Some("b0:3c:dc:d1:89:8c".into()),
        status: Some("down"),
        speed_mbps: None,
        mtu: Some(1500),
        dhcp_enabled: Some(true),
        dhcp_server: None,
        lease_obtained: None,
        lease_expires: None,
        ipv4: vec![AdapterIpv4 {
            address: "169.254.174.10".into(),
            prefix_length: Some(16),
            broadcast: Some("169.254.255.255".into()),
        }],
        ipv6: vec![v6("fe80::b56f:39b7:6f12:fb47", 64, "link-local", false)],
        gateway_v4: None,
        gateway_v6: None,
        gateway_mac: None,
        dns_servers: vec!["fec0:0:0:ffff::1".into(), "fec0:0:0:ffff::2".into(), "fec0:0:0:ffff::3".into()],
        dns_suffix: None,
        source: AdapterSource {
            adapter: Some("windows_iflist"),
            addresses: Some("windows_iflist"),
            dhcp: Some("registry"),
            gateway: Some("route"),
            dns: Some("registry"),
        },
    }
}

/// `WAN Miniport (Network Monitor)`: no IP binding, so no link statistics, no
/// TCP/IP key and no addresses - nulls and empty lists, never zeros.
fn wan_miniport() -> AdapterReport {
    AdapterReport {
        id: r"\Device\NPF_{C058D089-E644-427C-9C9A-53337892E5DB}".into(),
        name: "Local Area Connection* 3".into(),
        description: Some("WAN Miniport (Network Monitor)".into()),
        mac: None,
        status: None,
        speed_mbps: None,
        mtu: None,
        dhcp_enabled: None,
        dhcp_server: None,
        lease_obtained: None,
        lease_expires: None,
        ipv4: Vec::new(),
        ipv6: Vec::new(),
        gateway_v4: None,
        gateway_v6: None,
        gateway_mac: None,
        dns_servers: Vec::new(),
        dns_suffix: None,
        source: AdapterSource {
            adapter: Some("windows_iflist"),
            addresses: Some("windows_iflist"),
            dhcp: Some("registry"),
            gateway: Some("route"),
            dns: Some("registry"),
        },
    }
}
