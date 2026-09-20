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

use inwire_agent::protocol::{self, CaptureState, Interface, InterfaceStats};
use serde_json::{json, Value};

fn main() {
    let interfaces = vec![
        Interface {
            id: 0,
            name: r"\Device\NPF_{28524299-03EF-4F59-A8D2-419D761418B7}".into(),
            label: "Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)".into(),
        },
        Interface {
            id: 1,
            name: r"\Device\NPF_Loopback".into(),
            label: "Adapter for loopback traffic capture".into(),
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
        "a capture that stopped on its own, with the reason",
        protocol::capture_failed(2, "pcap_next_ex failed (-1): device removed"),
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
        "error: a second client tried to start a capture somebody else owns",
        protocol::error("capture_busy", "Another client is capturing on this machine."),
    );
    add(
        "error: a command this build does not know, named so the app can say which",
        protocol::error("unknown_command", "This agent does not understand 'fly'."),
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
