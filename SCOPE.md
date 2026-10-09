# Scope

What Inwire is, what it is becoming, and the bar an issue or pull request has to clear. `/triage` judges every incoming request against this file and against the rejected concepts in [`.out-of-scope/`](./.out-of-scope/). Engineering invariants (what the code must keep doing) live in `CLAUDE.md`; decisions and their reasoning live in `docs/decisions/`.

## What Inwire is

A desktop network analyzer that starts where Wireshark stops.

The foundation is Wireshark-class packet capture and dissection, done locally: a small privileged capture agent, dissection in the app, display filters, colour rules, expert analysis, pcap and pcapng in and out. That part is a modernisation of Wireshark and is measured against it (`scripts/parity/`, ADR 0021 says where the parity chase stops).

The product is what gets built on top of it: **monitoring anything on the network, not one capture device**.

- Bandwidth, utilisation and overloads per link, per direction, with alerting.
- Traffic across the whole network from flow exports (NetFlow v5/v9, IPFIX, sFlow flow samples) and sFlow counter samples, then SNMP counters for devices that cannot export.
- This machine's bandwidth by process, from the local capture and the agent's socket table.
- An internet speed test whose packets land in the same views.
- Top talkers, applications and conversations, baselines, retention, reports.
- The pivot no flow tool has: from any number (a talker, an overload, a slow test) to the packets that explain it. Clicking a talker opens a display filter over the capture; a discards alert jumps to a 1 ms I/O graph.

`docs/ideas/network-monitoring-and-speed-test.md` holds the market research and the build order. Nothing in it is built until it has an ADR.

## Product invariants

These hold across every feature, current or future. A request that breaks one is out of scope however good the feature.

1. **Local and offline by default.** No account, no backend, no telemetry. No outbound connection the user did not ask for, and consent covers how many requests as well as whether (ADR 0009, `OUTBOUND_HOSTS`). Monitoring data stays on this machine unless the user exports it.
2. **A desktop app, not a web app** (ADR 0027). Windows today, macOS and Linux as the agent gains a desktop app to talk to. Nothing hosted, no browser build, no phone layout.
3. **The agent is the only privileged component, and it dissects nothing** (ADRs 0010, 0033). It captures, writes pcapng and streams bytes. Collectors, pollers and test engines run unprivileged in the app, never as sockets inside the LocalSystem service.
4. **The capture is the ground truth.** Monitoring views are derived from packets, flows and counters the user can inspect. A number without a path back to its source is a defect.
5. **Measured, not asserted.** Performance ceilings, dependency choices and architecture changes come with numbers (ADR 0041, the dependency rule in `CLAUDE.md` §10).
6. **The user owns their data.** A stored capture is discarded only when the user asks (ADR 0012). Fixture captures with personal traffic are never committed (ADR 0004).

## The bar

An issue or pull request stays open only if it clears all three parts.

1. **Observed, or placed.** A bug describes what you ran, what happened and what you expected, with a capture or steps that reproduce it. A feature request names where it sits in the list above or argues for a new line in it. "It would be nice if" clears neither.
2. **Holds the invariants.** It breaks none of the six product invariants, and matches nothing in [`.out-of-scope/`](./.out-of-scope/).
3. **Fits the sequence.** Monitoring features follow the build order in the ideas document unless the request shows why a later item is cheaper or more valuable now. Features that need a new privileged capability, a new outbound host or a new native module come with the measurement that justifies it.

Size is irrelevant: a one-line fix and a new subsystem face the same bar. Reactions and +1 comments do not count towards it.

## In scope by area

- **Dissection and parity**: protocols where Wireshark is the reference. New dissectors are measured against tshark two-pass output on real captures. Where parity deliberately stops is recorded in ADR 0021 and is not a defect.
- **Capture**: the Rust agent on Windows, the Python agent elsewhere until those platforms get a desktop app. Ring buffers, autostop, capture filters, snaplen, nanosecond stamps: in. Capture engines maintained elsewhere: see **Undecided**.
- **Monitoring**: flow collection, counter samples, utilisation, overload rules, per-process bandwidth, speed test, retention, baselines, reports. In, in the order the ideas document gives.
- **Platform**: macOS and Linux desktop apps when the agent on those platforms has an app to talk to. Windows facts are written as Windows facts, not as the product.
- **Exports and reports**: pcap, pcapng, CSV, PDF, flows in reports. Export is the whole capture, streamed (ADR 0046).

## Out of scope

Each rejected concept is one file in [`.out-of-scope/`](./.out-of-scope/), with the reason and the decision it rests on. Read them before filing. Current entries:

- [`account-backend-telemetry.md`](./.out-of-scope/account-backend-telemetry.md): accounts, cloud sync, sharing services, usage telemetry.
- [`browser-build-or-hosted-app.md`](./.out-of-scope/browser-build-or-hosted-app.md): a web build, a hosted version, a service worker, a phone layout.
- [`in-process-capture.md`](./.out-of-scope/in-process-capture.md): capturing from inside Electron, or a privileged socket in the agent.
- [`pairing-token-on-windows.md`](./.out-of-scope/pairing-token-on-windows.md): tokens, origin allowlists and the WebSocket port on Windows.
- [`npcap-silent-or-mirrored.md`](./.out-of-scope/npcap-silent-or-mirrored.md): silent Npcap installs and bundled Npcap copies.
- [`packaging-shortcuts.md`](./.out-of-scope/packaging-shortcuts.md): MSIX, Electron Forge, V8 startup snapshots.

## Undecided

Open, not rejected. Filing one of these is welcome if it brings a measurement or a design, not a vote.

- **Bundling dumpcap** as the capture engine. Shelved twice by the owner; the native agent now has the pcapng writer, ring and autostop that motivated it. Reopens only with a burst-throughput comparison against the native agent and a GPL distribution plan.
- **Who owns the flow collector's UDP port**: passive capture through the agent's filter, or an unprivileged socket in a `utilityProcess`. Never the agent. First measurement: ICMP port-unreachable behaviour.
- **Speed test servers**: Cloudflare endpoints measured by our own engine; M-Lab only as a separate opt-in because it publishes client addresses. Ookla, fast.com and nPerf cannot be embedded.

## Process

Labels: `needs-triage`, `needs-info`, `ready-for-agent`, `ready-for-human`, `wontfix`. An issue that cannot be judged against the bar gets one round of questions and `needs-info`; with no reply in 14 days it is closed. A rejected enhancement gets a new `.out-of-scope/` file and closes as not planned. A request for something already built is closed with a pointer to where it lives and gets no `.out-of-scope/` file.

Discussion and questions go to GitHub Discussions. Issues are for tracking changes.
