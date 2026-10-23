# Scope

Inwire is a desktop network analyzer. Its current foundation is local packet
capture and analysis; its direction is to connect that evidence with monitoring
across a network. This file governs product decisions and issue triage.
[README.md](README.md) describes the app available today,
[CLAUDE.md](CLAUDE.md) routes engineering work, and
[architecture decisions](docs/decisions/README.md) record accepted designs.

## Product direction

Help someone move from a network symptom to the evidence that explains it:
which link is overloaded, which hosts or applications are responsible, and what
the available packets, flow exports or counters actually show.

The packet analyzer is the working foundation. Network-wide monitoring extends
it with flow collection, link counters, utilisation, alerting, history and
reports. These additions must preserve the connection to their source evidence.
A filter over the open capture can help investigate a monitored host; it must
never imply that the capture contains the packets behind an exported flow.

## Implemented foundation

The Windows desktop app captures through the Rust agent and Npcap, dissects
traffic locally, and provides display filters, decryption, stream inspection,
statistics, a routing map, network diagnostics, exports and analysis reports.
Capture filters, snaplen, multiple adapters, ring files, autostop and scheduling
are implemented. The internet speed test uses Cloudflare through its own
unprivileged engine ([ADR 0054](docs/decisions/0054-an-internet-speed-test-against-cloudflare.md)).

The dissector set covers the common families of a real network: name and
address services, TLS and QUIC, HTTP/1-3, SSH, IPsec, WireGuard and OpenVPN,
Windows networking (SMB, DCE/RPC, NTLMSSP, LDAP, RDP), VoIP (SIP and RTP),
tunnels and mirrors (GRE, ERSPAN, TZSP) and flow-export protocols. NetFlow
v5/v9, IPFIX and sFlow datagrams can be inspected inside a capture.

**Network monitoring (NetFlow v5, v9 and IPFIX)** is implemented
([ADRs 0058-0066](docs/decisions/README.md)). Inwire collects from one exporter
over IPv4 and UDP: a specific local address and port, started explicitly while
the app is open. An unprivileged utilityProcess owns the socket and the history; a
sandboxed Worker decodes the datagrams; the capture agent has no listener and no
extra privilege ([ADR 0058](docs/decisions/0058-monitoring-intake-and-lifetime.md)).
A standalone journal is the authority and minute rollups are derived caches.
History lives apart from captures, survives capture replacement, and by default stops at a
storage limit rather than silently expiring data
([ADR 0059](docs/decisions/0059-monitoring-evidence-journal-and-rollups.md)).
The user chooses where history is kept, and adopts or discards it there; the
folder's own files are never touched
([ADR 0061](docs/decisions/0061-monitoring-dataset-location-adoption-discard.md)).
Raw-evidence retention is off unless the user turns it on; what expires keeps
its minute totals in a sealed archive and is shown as "Evidence expired", never
as a gap
([ADR 0062](docs/decisions/0062-monitoring-segments-retention-archive.md)).
A range can be exported as a `.iwmon` evidence bundle of its raw records
([ADR 0063](docs/decisions/0063-monitoring-evidence-bundle.md)).
v9 and IPFIX templates are kept per source ID or observation domain, and carry
across a restart only within their lifetime. A data set that arrives before its
template is kept and counted, never decoded later. Counters are shown as the
exporter reported them, with a sampled estimate labelled as one, and a
bidirectional record stays two directions
([ADR 0064](docs/decisions/0064-monitoring-v9-ipfix-collection.md)).
The Monitoring sheet opens from the Network sidebar and the command palette,
leaves the five capture views alone, and does not stop collection when closed. A
talker can apply a filter to the open capture, labelled as that operation
([ADR 0060](docs/decisions/0060-monitoring-workspace-sheet.md)). The
measurements behind these choices are in
the monitoring measurement reports for
[v5](docs/monitoring-v5-measurements.md) and
[v9 and IPFIX](docs/monitoring-v9-ipfix-measurements.md).

Windows has the desktop app. macOS and Linux retain the Python capture agent;
desktop apps for those platforms remain future work.

Dissection is compared with Wireshark/tshark on real captures. This is a measured
reference, not a claim of complete Wireshark parity.
[ADR 0021](docs/decisions/0021-where-the-parity-chase-stops.md) records where the
parity chase stops.

## Later directions

These areas are in scope, but need their own design and evidence before work
begins. They are not commitments.

- Additional exporters and formats: multiple sources, IPv6 exporters, IPFIX
  over TCP or SCTP, sFlow flow samples and interface-counter samples.
- SNMP polling for devices that cannot export counters, per-link utilisation,
  overload detection and alerting.
- Per-process bandwidth analysis from local traffic and the agent's socket table.
- Baselines and monitoring reports.
- macOS and Linux desktop apps with appropriate local permission and transport
  designs.

[The monitoring research](docs/ideas/network-monitoring-and-speed-test.md)
holds the broader build order and market context. Accepted ADRs take precedence
where they refine that research; only implemented code belongs in the current
feature list.

## Product invariants

These apply to current and future work. A request that breaks one is out of scope.

1. **Local and offline by default.** No account, backend or telemetry. Network
   access needs a user action or consent, covering request volume as well as
   permission. Monitoring data stays local unless exported. Optional online
   behaviour must be stated clearly.
2. **A desktop app.** Windows today, with macOS and Linux desktop apps in scope.
   No hosted app, browser build or phone layout
   ([ADR 0027](docs/decisions/0027-the-app-is-a-desktop-app.md)).
3. **One small privileged agent.** It captures, writes pcapng and streams bytes;
   it dissects nothing. Collectors, pollers and test engines run unprivileged in
   the app, never as listeners inside the LocalSystem service
   ([ADR 0033](docs/decisions/0033-the-agent-stays-a-separate-service.md)).
4. **Source evidence is authoritative.** A capture's bytes and a monitoring
   journal answer different questions. Derived numbers must have a path to
   inspectable source data; gaps and unavailable measurements must not appear
   as zeros.
5. **Measured, not asserted.** Performance ceilings, dependency choices and
   architecture changes need evidence. New privileges, outbound destinations
   and native modules require justification.
6. **The user owns the data.** Stored captures are removed only through a user
   decision, including an explicitly configured ring. Monitoring retention has
   its own stated policy. Personal capture fixtures are never committed
   ([ADR 0004](docs/decisions/0004-fixtures-and-privacy.md)).

## Open decisions

- **Bundling dumpcap** can reopen with a burst-throughput comparison against
  the native agent and a GPL distribution plan. The native agent already has
  pcapng writing, ring files and autostop.
- **Other speed-test providers** need a separate design. Cloudflare is built;
  M-Lab would require separate consent because it publishes client addresses.
  Ookla, fast.com and nPerf cannot be embedded under the researched terms.

## Rejected directions

Each rejection has a reason and decision reference under [.out-of-scope/](.out-of-scope/):

- [Accounts, backend and telemetry](.out-of-scope/account-backend-telemetry.md).
- [Browser builds, hosting and phone layouts](.out-of-scope/browser-build-or-hosted-app.md).
- [Capture inside Electron or privileged listeners in the agent](.out-of-scope/in-process-capture.md).
- [Windows pairing credentials and WebSocket transport](.out-of-scope/pairing-token-on-windows.md).
- [Silent or mirrored Npcap installers](.out-of-scope/npcap-silent-or-mirrored.md).
- [Packaging shortcuts](.out-of-scope/packaging-shortcuts.md).

## Issue and pull-request bar

A change must meet all three conditions:

1. **Observed, or placed.** A bug gives reproduction steps, actual behaviour and
   expected behaviour. A feature names its place in the direction above or
   argues for an addition. Include a safe reproducer where possible.
2. **Holds the invariants.** It breaks none of the product constraints and
   matches no rejected direction.
3. **Fits the sequence.** It follows the accepted research order,
   or provides evidence that a different order is cheaper or more valuable.

Size and popularity do not replace these conditions. A request for something
already implemented gets a pointer to the existing feature. An unjudgeable
request gets one round of questions and `needs-info`; with no reply in 14 days
it is closed. A rejected enhancement records the rejection and closes as not
planned. See [CONTRIBUTING.md](CONTRIBUTING.md) for the working process.
