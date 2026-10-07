<img src="logo/inwire-layers-256.png" width="76" align="right" alt="">

# Inwire

A Windows desktop network packet analyzer. Capture happens in a small agent —
one Rust executable — that ships inside the same installer and runs as a
LocalSystem service;
everything else — dissection, decryption, display filters, colour rules, expert
analysis, statistics, pcap/pcapng import and export — happens locally in
TypeScript, inside an Electron app. No account, no backend, no telemetry, no
server of any kind in this repository, and no packet leaves the machine.

It is **not a web app**: no browser build, nothing hosted, and the renderer is
served to Electron from a custom `app://inwire` scheme. macOS and Linux have the
capture agent — one tarball, built from these sources — but no desktop app yet.

[![CI](https://github.com/Doofess/Inwire/actions/workflows/ci.yml/badge.svg)](https://github.com/Doofess/Inwire/actions/workflows/ci.yml)

## How it works

![Five processes, one direction of flow: the kernel driver hands frames to a
privileged Rust service, which pushes them over a named pipe to the Electron
main process, which forwards the bytes untouched to a Worker that dissects them.
The React UI only ever sees dissected rows, and hands every frame to a separate
store process that owns the files on disk.](docs/images/processes.svg)

The agent is the only privileged component and deliberately small: it sniffs,
batches and streams raw bytes. It **dissects nothing** — a record carries no
protocol, no addresses and no ports, because the app reads the bytes itself — and
it starts idle, sniffing only once a client asks and stopping when the last one
disconnects. Imported `.pcap` and `.pcapng` files take the same dissection path,
so a packet from a file and one off the wire are the same object by the time
anything renders it.

The pipe is also what decides who may talk to the agent, and the operating system
makes that decision: its security descriptor grants the interactive user read and
write, SYSTEM and administrators everything, and nobody else anything — not the
network, not anonymous callers. Nothing to pair, no secret to paste, no port open.

Once a frame is inside, it crosses exactly one process boundary as bytes and is
never carried across another as a tree:

![From the wire to a row on screen, in nine hops. The first three are the
adapter, the driver and the agent; the rest are the pipe, the main process, the
Worker that dissects, the capture store that writes to disk, and the flush that
puts a row on screen.](docs/images/frame-path.svg)

**[How Inwire works, illustrated →](docs/how-inwire-works.html)** — twelve pages
on the same subject: what happens on every launch, where the capture lives, who
may touch what, and the map from concept to file.

## Features

- **Live capture** from any adapter, with throughput sparklines in the picker so
  you can see which one is carrying traffic before you commit.
- **85 dissected layers** — Ethernet/VLAN/802.1ad/LLC, 802.1X (EAPOL and EAP), Linux cooked capture, IPv4/IPv6
  with fragment reassembly, TCP/UDP, DNS, TLS, DTLS, SSH, QUIC, HTTP/1.1 through HTTP/3,
  DHCP, CLDAP (the domain-controller locator), NAT-PMP/PCP, WireGuard, OpenVPN, IPsec (IKE, ESP, NAT-T), LDAP, SMB2, Kerberos, RDP (TPKT, X.224 and the security negotiation), SIP, SNMP, RADIUS, BGP, OSPF and the rest, plus GRE
  and VXLAN dissected *through*, and an HTTP body read on into JSON, XML or text (WS-Discovery's SOAP too). The list is `LAYERS` in
  `src/services/dissect/fieldRegistry.ts`, which also feeds the filter's names,
  the autocomplete and the column catalogue.
- **Decryption from a key log.** `Settings → Decryption` takes the
  `SSLKEYLOGFILE` a browser writes and opens TLS 1.2, TLS 1.3 and QUIC, HTTP/2
  and HTTP/3 included, with full HPACK and QPACK dynamic tables. Key material
  stays in memory: never on disk, and in an export only if you deliberately turn
  on the Decryption Secrets Block.
- **Which way each frame went.** A capture taken *on* an endpoint knows which of
  a frame's two MACs is yours; Wireshark cannot answer that at all. Direction is
  a column, a filter (`frame.direction == out`), a per-direction split in the
  conversation table, and a real `epb_flags` field in a pcapng export.
- **Which process opened the socket.** From the machine's own socket table: an
  outbound frame renders as `<address>\chrome.exe`, `inwire.process.name` is
  filterable and columnable, and it lands in each pcapng packet's comment.
- **Display filters with a real grammar** — comparison, membership, nesting,
  `contains`/`matches` — on Wireshark's own field names, every one checked
  against `tshark -G fields` in CI, and answered over the **whole** capture
  rather than only the part still in memory.
- **Expert information** in eight categories named after what to conclude
  (Broken, Reset, Security, Loss, CaptureGap, FlowControl, Unverifiable, Note),
  each a colour rule at the head of the first-match-wins chain that paints the
  packet list. The chain is shipped rather than configurable, deliberately:
  colouring is the one part of this UI whose job is to be opinionated about
  which frames matter, and the parity harness compares the rule each frame
  matched against tshark's answer for the same frame.
- **Follow Stream** for TCP, UDP and QUIC, with a **ladder view** drawing the
  conversation as two lanes and time running down.
- **Statistics** — conversations, endpoints, protocol hierarchy, devices, expert
  info, processes, resolved addresses — where every row applies the filter that
  selects its own frames.
- **A Network report** (`Settings → Network`) putting what the OS says beside what
  the capture shows (gateway, resolvers, DHCP lease, IPv6 router, LLDP neighbour)
  and flagging where they disagree. It sits in Settings rather than being a view,
  because it describes the machine and nothing in it changes when a packet arrives.
- **A routing map**, one of the five views: every arc on it is a conversation in
  the buffer, and it redraws as packets arrive. Pins are real geometry standing on
  the globe rather than icons pasted over it.
- **Charts inside Statistics**: a throughput plot and a packet-size distribution,
  each with its own metric, interval and overlay filter — the overlay draws a
  second series without touching the display filter the packet list is using.
- **Passive name resolution.** Every name comes out of the capture — DNS and mDNS
  answers, TLS and QUIC server names, DHCP, LLDP — and is a rendering choice
  only, so filters and exports still see addresses.
- **Export the whole capture**, not just what is in memory — every frame on
  disk, or every frame the display filter selects — to pcapng, pcap, CSV, JSON
  or Excel, streamed to disk so the file can be larger than the app's memory.
  pcapng carries what pcap cannot: per-adapter provenance, nanosecond
  timestamps, the names the capture taught us, and what the capture missed.
  Every format except classic pcap records where the capture came from and what
  it dropped; CSV, JSON and Excel carry every dissected field under its
  Wireshark name, and Excel rows keep the packet list's colours.
- **A PDF analysis report**: traffic over time, the protocol hierarchy, top
  endpoints and conversations, expert findings and a written summary of what
  stands out — statistics, not a packet list.
- **Anonymise** on export: addresses prefix-preserving so the file is still a
  network, MACs keeping their OUI, everything above the transport header zeroed.
- **Two themes**, Day and Night, plus System — which is a rule for choosing
  between them rather than a third palette. Packet row colours are derived per
  theme and held to contrast and separation floors in CI.
- **The capture lives on disk**, in `%LOCALAPPDATA%\Inwire\captures`, one
  directory per capture — bounded by the disk rather than by memory, surviving a
  restart or a crash with at most the trailing chunk lost and nothing before it,
  and deleted only when you ask.

## Installing

One installer, `Inwire-Setup.exe`. It installs the app, installs the capture
agent beside it, and registers that agent as the `InwireAgent` LocalSystem
service. Nothing per-user is provisioned, and the app itself never elevates.

**There is no download yet, and that is deliberate rather than an oversight.**
The installer, the app and the agent are Authenticode-signed. But the
certificate is one only the maintainer's own PC trusts, so on your machine it is
an unknown publisher, and SmartScreen would warn everyone who ran it. Teaching
people to click through that warning, for a tool that installs a kernel driver
and a LocalSystem service, is exactly the habit this project should not be
building. A download waits on a publicly trusted certificate
(`docs/decisions/0047-windows-ships-the-rust-agent-signed-on-this-pc.md`). Until
then, build it from source with the steps below. [Releases](../../releases)
carries the notes for each version, and will carry the binary once it can be
signed for everyone.

**Npcap is not bundled.** The capture driver is a prerequisite the app manages
rather than a payload the installer ships. Inwire's Update Center
(`Settings → Updates`) reads whether the driver is present and which version it
is, and on request downloads Npcap's official installer from npcap.com, verifies
its SHA-256 and its exact size, and runs it behind a UAC prompt. **Npcap's own
wizard appears**, licence and all, and the person installing accepts it; there is
no silent install, because the silent flag is Npcap's OEM feature and the free
licence does not grant it (`docs/decisions/0032-the-update-center.md`). A first
launch with no driver lands on a banner linking to the tab that fixes it. That
same row reports the driver's **access mode**: Npcap's *"Restrict Npcap driver's
access to Administrators only"* is unticked by default, leaving this machine's
traffic readable by every local account. Inwire captures through the agent, so
the restriction costs its users nothing — the row recommends it and offers the
reinstall that applies it, naming the checkbox, because ticking it is the one
step Inwire cannot do for you.

Updates to Inwire itself are checked and applied from the same panel, one UAC
prompt per update. **Automatic checking is off by default and opt-in**: an update
check is an outbound request, and in a packet analyzer an unbidden request shows
up in the user's own capture. *Coming:* the feed's host does not resolve yet,
and the installer is signed only for the maintainer's PC, so the Inwire row
reads "Not checked" today. The Npcap row works now.

The agent's rotating log is `%ProgramData%\Inwire\agent.log` — a service has no
console, so that file is the only place to look, and the app surfaces it under
`Settings → Driver Info` beside what the driver dropped, what the agent dropped
and what the packet buffer pushed out. Uninstalling stops and removes the
service and deletes that log; it leaves Npcap alone, since other tools may be
using it, and it does not touch stored captures.

## Building from source

**Prerequisites:** Node.js 24+, [rustup](https://rustup.rs) with the
`stable-x86_64-pc-windows-gnu` toolchain for the Windows agent, Python 3.10+
for the macOS/Linux agent and its tests, and
[Npcap](https://npcap.com/#download) for live capture. Packaging additionally
needs Inno Setup 6.3 or newer (7 works).

```
npm install
npm run dev         # Vite + Electron, for iterating on the UI
npm run start:app   # build, then launch Electron against app:// - no packaging
npm run build       # Vite into dist/, then esbuild main + preload + store
npm run pack        # electron-builder --dir into release/win-unpacked/
```

Under `npm run dev` the renderer comes from a dev server, where the `app://`
handler, the MIME table, the 404 rule and the CSP all behave differently, so
`npm run start:app` is the cheapest thing that exercises them for real. The agent
and the installer are built separately, in that order:

```
npm run build:agent                         # the Rust agent, then its resources
iscc installer/setup.iss                    # an unsigned installer; needs both builds
npm run dist:signed                         # or all three, signed, refusing any unsigned file

pip install -r local-agent/requirements.txt # or run the Python agent,
python local-agent/agent.py                 # as Administrator
```

`npm run dist:signed` needs a code-signing certificate configured on the
machine. `scripts/sign/` creates one that only that machine trusts, and no
certificate or thumbprint is ever committed. Build outputs are not tracked;
rebuild them rather than committing binaries. `local-agent/CLAUDE.md` holds the
release checklist and the Python agent's packaging mechanics.
`agent-rs/rust-toolchain.toml` says why the Rust build uses the GNU toolchain,
and why the toolchain is named on the command line.

## Development

```
npm run lint    # tsc --noEmit over both TypeScript programs
npm run check   # lint, then every assertion script  <- the gate
```

`npm run check` is the one that matters. There is no unit-test runner here:
correctness is enforced by assertion scripts under `scripts/`, discovered by
directory walk so that a new one cannot be forgotten out of a hand-maintained
list. They run under plain `tsx` — no Electron, no browser — which keeps the
suite runnable on Linux in CI and fast enough for every commit. They cover the
dissectors, the filter grammar, the colour rules, the on-disk capture format and
its recovery, the capture store's protocol, the agent's framing and binary
records, the Update Center, rendering, preferences and the theme contract; one of
them drives the **real app** under Playwright against a stub agent, because three
of the worst bugs in the desktop migration were invisible to everything else.

`npm run lint` does more than its name suggests: both programs run `strict`,
`noUnusedLocals`, `noUnusedParameters` and `noFallthroughCasesInSwitch`, so an
unused import or an unread local fails the build.

**Dissection is measured, not asserted.** Two real captures are decoded and
diffed against tshark column by column — Protocol, Source, Destination, Time,
Length, Info and the matched colouring rule — each column held to a floor that
only ever rises. They are personal and untracked, so that gate skips without
them; `test/fixtures/README.md` says what they are and `docs/decisions/` why it
is shaped this way.

```
npx tsx scripts/parity/parity-check.ts
python local-agent/test_protocol.py
```

The second of those is the Python agent's own suite. The Rust agent's is
`cargo test` in `agent-rs/`. The agent's version is the product's, held in every
place it appears by `scripts/agent/version.ts`, and a reset is refused, because
that version is an ordering rather than a label. Both agents' suites run on
every push and pull request, the Rust one on Windows. The parity check needs the
untracked captures, so it runs by hand.

## Layout

```
src/
  components/    UI, grouped by surface (packet-list, packet-details, network...)
  services/      dissection, filtering, colour rules, the capture format and
                 theming - no Electron and no node:*, by assertion
  workers/       the pipeline Worker - ordering window, trackers, dissection;
                 the renderer's main thread never parses an agent message
  types/         packet.ts is the single source of truth for the domain model
  lib/           hooks and small utilities
electron/        main, the sandboxed preload, the pipe client, the agent
                 supervisor, the Update Center, and store/ - its utilityProcess
dist-electron/   built main, preload and store, as .cjs (not tracked)
scripts/         assertion scripts, run as a set by `npm run check`
docs/decisions/  numbered architecture decisions, with the measurements behind them
docs/ideas/      notes on things that are not built, each banner-marked as such
docs/specs/      historic specifications; read the banner at the top of each first
docs/verification.md  what only a person can check, and what each failure looks like
docs/how-inwire-works.html  the illustrated explainer, twelve pages
test/fixtures/   the parity captures and the acceptance floors (not tracked)
local-agent/     the Python capture agent - what macOS and Linux run, and the
                 baseline the Windows agent is compared against - and its tests
agent-rs/        the same agent in Rust, which is what the Windows installer
                 ships (docs/decisions/0037-the-agent-is-rust-on-windows.md)
scripts/sign/    code signing: one script signs everything, and no certificate
                 is committed
installer/       the unified Inno Setup installer
logo/            the brand mark's sources; every icon is generated from
                 src/lib/brandMark.ts rather than committed as art
```

## Notes

- **The app used to be called NetView**, and in the tree that name survives only
  where it must: `legacy_config_dir()`, the installer's `Legacy*` defines,
  `LEGACY_KEY_PREFIX` and `LEGACY_DB_NAME` each recognise what an *old* install
  left behind, and every one of them would stop working the moment it said
  `Inwire`. Links to the old repository name still resolve — GitHub redirects a
  renamed repository indefinitely — but nothing here points at it.
- There is no role model. `Capabilities` in `src/types/packet.ts` is a flat set
  of six permissions, stated once in `App.tsx` and threaded to the components;
  the gates reading it are live, and are where a real model would plug in.

## License

MIT — see [LICENSE](LICENSE).
