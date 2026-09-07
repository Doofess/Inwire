# Inwire

A real-time network packet analyzer that runs in the browser.

Capture happens in a small local agent with the privileges it requires;
everything else — dissection, decryption, filtering, colour rules, expert
analysis, PCAP import and export — runs client-side in TypeScript. No packet
ever leaves the machine, and there is no backend to stand up.

![CI](https://github.com/Doofess/NetView/actions/workflows/ci.yml/badge.svg)

## How it works

```
┌─────────────────────┐   ws://localhost:8999    ┌──────────────────────────┐
│  local-agent        │  ───────────────────────▶│  browser (React + Vite)  │
│  Python + Scapy     │   batched binary frames  │                          │
│  runs elevated      │                          │  dissection, filtering,  │
│  idle until asked   │◀───────────────────────  │  colour rules, charts,   │
└─────────────────────┘   JSON control messages  │  PCAP import + export    │
                                                 └──────────────────────────┘
```

The agent is the only privileged component, and it is deliberately small: it
sniffs, batches, and streams. It starts **idle** and sniffs only once a client
asks it to, stopping again when the last client disconnects. It dissects
nothing — captured frames travel as raw bytes and the browser reads them.

Imported `.pcap` and `.pcapng` files travel the same dissection path as live
frames, so a packet from a file and a packet off the wire are the same object by
the time anything renders it.

## Features

- **Live capture** from any adapter, with per-adapter throughput sparklines in
  the picker so you can see which one is carrying traffic before you commit.
- **47 protocols dissected**, from Ethernet/VLAN/LLC and Linux cooked capture up
  through IPv4/IPv6 with fragment reassembly, TCP/UDP, and DNS, TLS, QUIC,
  HTTP/1.1, HTTP/2, HTTP/3, DHCP, LDAP, SIP, SNMP, RADIUS, OSPF and the rest —
  plus GRE, which is dissected *through*, so a tunnelled packet reports what is
  inside it rather than the tunnel.
  The list
  is `LAYERS` in `src/services/dissect/fieldRegistry.ts`, which is also where the
  filter's names, the autocomplete and the column catalogue come from.
- **Decryption from a key log.** Point Settings → Decryption at the
  `SSLKEYLOGFILE` a browser writes and TLS 1.2, TLS 1.3 and QUIC open up,
  including HTTP/2 and HTTP/3 with full HPACK and QPACK dynamic tables. The key
  material stays in memory: never in the stored session, and never in an export
  unless you deliberately turn on the Decryption Secrets Block.
- **Which way each frame went.** A capture taken *on* an endpoint knows which of
  a frame's two MACs is yours; Wireshark cannot answer that at all. Direction is
  a column, a filter (`frame.direction == out`), a per-direction split in the
  conversation table, and a real `epb_flags` field in a pcapng export.
- **Which process opened the socket.** The agent reports the machine's socket
  table, so an outbound frame renders as `<address>\chrome.exe`, and
  `inwire.process.name` is filterable, columnable, and written into each pcapng
  packet's comment. A Processes tab counts by pid, because a browser's renderers
  are separate programs.
- **Display filters with a real grammar** — comparison, membership, nesting,
  `contains`/`matches` — using Wireshark's own field names, every one of them
  checked against `tshark -G fields` in CI.
- **Expert information** in eight categories named after what to conclude
  (Broken, Reset, Security, Loss, CaptureGap, FlowControl, Unverifiable, Note),
  each one a colour rule at the head of a reorderable, first-match-wins chain.
- **Follow Stream** for TCP, UDP and QUIC, with a **ladder view** that draws the
  conversation as two lanes with time running down — the shape a packet list
  cannot show.
- **Statistics**: conversations, endpoints, protocol hierarchy, devices, expert
  info, processes and resolved addresses. Every row applies the filter that
  selects its own frames.
- **A Network panel** putting what the OS says beside what the capture shows —
  gateway, resolvers, DHCP lease, IPv6 router, LLDP neighbour — and highlighting
  where they disagree.
- **A widget dashboard**: protocol mix, traffic timeline, packet sizes,
  conversation matrix and a geographic map of remote endpoints. It collapses to
  an icon rail and expands any widget to full screen.
- **Passive name resolution.** Every name comes out of the capture itself — DNS
  and mDNS answers, TLS and QUIC server names, DHCP, LLDP. Nothing is looked up,
  and resolution is a rendering choice only, so filters and exports still see
  addresses.
- **Custom dissectors** defined in the UI, no rebuild required.
- **Export to pcap and pcapng**, plus PDF and CSV reports. pcapng carries what
  pcap cannot: per-adapter provenance, nanosecond timestamps, the names the
  capture taught us, and what the capture missed.
- **Anonymise** on export: addresses are prefix-preserving so the file is still a
  network, MACs keep their OUI so the printer still looks unlike the phone, and
  everything above the transport header is zeroed.
- **Four themes** (Day, Paper, Graphite, Midnight). Packet row colours are
  derived per theme, and each is checked against contrast and separation floors
  in CI.
- **Session survives a refresh.** Frames stream to IndexedDB as they arrive and
  are restored on the way back in. A stored capture is discarded when you ask and
  not before.

## Quick start

**Prerequisites:** Node.js 24+, and Python 3.10+ if you want live capture.

```bash
npm install
npm run dev            # http://localhost:3000
```

That gets you the full UI, PCAP import, and every analysis feature. For live
traffic you also need the agent.

### Live capture

Raw packet capture requires elevation on every operating system, which is why
this is a separate process rather than something the page does.

```bash
pip install -r local-agent/requirements.txt
python local-agent/agent.py          # as Administrator / root
```

On Windows this development path needs [Npcap](https://npcap.com/#download)
installed. The packaged installer handles that for you; running from source does
not.

The agent listens on `ws://localhost:8999` behind **two** controls that do
different jobs. Its `Origin` allowlist, in `%ProgramData%\Inwire\config.json`, is
checked during the handshake and keeps an ordinary web page out — but it stops
nothing that can set a header, which is any process on the machine. So the agent
also holds a **pairing token** in that same file, written by the installer and
readable only by an administrator, and refuses every command with
`auth_required` until a connection has authenticated. That token has to be
pasted into the app once, and the reason is the point of it: the browser cannot
read `%ProgramData%`, which is exactly what separates it from another program
running as you. Both are re-read per connection, so changing either needs no
restart.

One capture has one owner: the connection that started it is the only one that
can stop it, so a second window can tell "capture is running" from "capture is
running and I can stop it".

Logs go to `%ProgramData%\Inwire\agent.log`. When the agent runs as a service
there is no console, so that file is the only place to look — the app surfaces it
under Settings → Driver Info, along with what the driver dropped, what the agent
dropped, and what the packet buffer pushed out.

### Distribution

On **Windows** the agent ships as a service — installed once, then invisible: no
console, no tray icon, no UAC prompt on boot. PyInstaller and Inno Setup build
steps live in `local-agent/`.

On **macOS and Linux** it is one tarball, built from the real sources by
`npx tsx scripts/agent/package-unix.ts --build`, carrying its own `install.sh`
(root-owned virtualenv, systemd unit or LaunchDaemon, pairing token, and an
`uninstall` verb).

Build outputs are not tracked; rebuild them rather than committing binaries.

## Development

```bash
npm run dev       # dev server on port 3000
npm run lint      # tsc --noEmit
npm run check     # tsc --noEmit + every assertion script  ← the gate
npm run build     # production bundle
npm run start     # serve the built bundle via Express
```

`npm run check` is the one that matters. There is no unit-test runner here;
correctness is enforced by assertion scripts under `scripts/`, discovered by
directory walk so that a new one cannot be forgotten out of a hand-maintained
list. They cover the protocol dissectors, the filter grammar, the colour-rule
engine, packet-list and detail rendering, session handling, preferences, and the
theme contract — token completeness, contrast ratios, how far apart two row fills
may be, and drift between the CSS variables and the TypeScript palettes.

`npm run lint` does more than its name suggests: `tsconfig.json` runs `strict`,
`noUnusedLocals` and `noUnusedParameters`, so an unread local or a prop a
component declares and ignores fails the build.

**Dissection is measured, not asserted.** Two real captures are decoded and
diffed against tshark column by column — Protocol, Source, Destination, Time,
Length, Info and the matched colouring rule — and each column is held to a floor
that only ever rises. The captures are personal and untracked; see
`test/fixtures/README.md` for what they are, and `docs/decisions/` for why the
gate is shaped this way.

The agent has its own suite:

```bash
python local-agent/test_protocol.py
```

which also enforces that the agent's version matches in all three places it
appears (`agent.py`, `src/services/agentProtocol.ts`, `installer/setup.iss`).
Any change to the agent's wire protocol must bump it.

Both suites run on every push and pull request.

## Layout

```
src/
  components/    UI, grouped by surface (packet-list, packet-details, network…)
  services/      dissection, filtering, colour rules, session, theming — pure,
                 client-side, no backend calls except geo/DNS lookups
  workers/       the capture pipeline: socket, ordering window, trackers,
                 dissection — the main thread never parses an agent message
  types/         packet.ts is the single source of truth for the domain model
  lib/           hooks and small utilities
scripts/         assertion scripts, run as a set by `npm run check`
docs/decisions/  numbered architecture decisions, with the measurements behind them
test/fixtures/   the parity captures and the acceptance floors
local-agent/     Python capture agent, its tests, and the Windows installer
```

## Notes

- The repository is still named `NetView` on GitHub, which is what the app was
  called; every URL here points at that name until it is renamed there. Inside
  the tree the old name survives only where it has to — `legacy_config_dir()`,
  the installer's `Legacy*` defines, `LEGACY_KEY_PREFIX`, `LEGACY_DB_NAME` and
  the two PDF markers all exist to recognise what an *old* install left behind,
  and would stop working the moment they said `Inwire`.
- `security_spec.md` describes Firestore rules and a threat model for a Firebase
  backend that is **not implemented**. Read it as a spec for not-yet-built auth
  and sharing, not as a description of this code.
- There is no role model. `Capabilities` in `src/types/packet.ts` is a flat set
  of permissions stated once in `App.tsx` and threaded to the components; the
  seventeen gates that read it are live, and are where a real model would plug
  in.

## License

MIT — see [LICENSE](LICENSE).
