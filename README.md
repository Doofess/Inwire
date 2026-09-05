# Inwire

A real-time network packet analyzer that runs in the browser.

Capture happens in a small local agent with the privileges it requires;
everything else — dissection, filtering, colour rules, anomaly detection, PCAP
import and export — runs client-side in TypeScript. No packet ever leaves the
machine, and there is no backend to stand up.

![CI](https://github.com/Doofess/Inwire/actions/workflows/ci.yml/badge.svg)

## How it works

```
┌─────────────────────┐   ws://localhost:8999    ┌──────────────────────────┐
│  local-agent        │  ───────────────────────▶│  browser (React + Vite)  │
│  Python + Scapy     │   typed JSON frames      │                          │
│  runs elevated      │                          │  dissection, filtering,  │
│  idle until asked   │◀───────────────────────  │  colour rules, charts,   │
└─────────────────────┘   start / stop / config  │  PCAP import + export    │
                                                  └──────────────────────────┘
```

The agent is the only privileged component, and it is deliberately small: it
sniffs, serialises, and streams. It starts **idle** and sniffs only once a
client asks it to, stopping again when the last client disconnects.

Imported `.pcap` files travel the same dissection path as live frames, so a
packet from a file and a packet off the wire are the same object by the time
anything renders it.

## Features

- **Live capture** from any adapter, with per-adapter throughput sparklines in
  the picker so you can see which one is carrying traffic before you commit.
- **Deep protocol dissection** — Ethernet/VLAN, ARP, IPv4/IPv6, TCP, UDP, ICMP,
  DNS, TLS, QUIC (including decrypted initial packets), LLDP, IGMP and IEEE 1905,
  presented as an expandable tree with sub-byte fields rendered in binary.
- **Display filters** with a real grammar — comparison, membership, nesting —
  plus saved presets.
- **Colour rules**, editable, applied in order, with the matching rule name
  exposed for filtering.
- **A widget dashboard**: protocol mix, live I/O graph, traffic timeline,
  conversation matrix, anomaly alerts and a geographic map of remote endpoints.
  It collapses to an icon rail and expands any widget to full screen.
- **Stream reassembly** for TCP, plus ICMP echo and QUIC flow tracking.
- **Custom dissectors** defined in the UI, no rebuild required.
- **PCAP import and export**, plus PDF and CSV reports.
- **Four themes** (Day, Paper, Graphite, Midnight) or follow the OS setting.
  Packet row colours are derived per theme, and each is checked against
  contrast and separation floors in CI.
- **Session survives a refresh.** Frames stream to IndexedDB as they arrive and
  are restored on the way back in; a real close deletes them, because leaving
  raw packet bytes on disk is not something an analyzer should do once you are
  finished.

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
installed. The packaged installer handles that for you; running from source
does not.

The agent listens on `ws://localhost:8999` and authenticates browsers by
**origin**, not by a token: a connection whose `Origin` header is not listed in
`%ProgramData%\Inwire\config.json` is rejected during the handshake. Defaults
cover `localhost:3000` and `localhost:4173`. The file is re-read per connection,
so adding an origin needs no restart.

Logs go to `%ProgramData%\Inwire\agent.log`. When the agent runs as a Windows
service there is no console, so that file is the only place to look.

### Windows distribution

The agent ships as a Windows service — installed once, then invisible: no
console, no tray icon, no UAC prompt on boot. PyInstaller and Inno Setup build
steps live in `local-agent/`. Build outputs are not tracked; rebuild them rather
than committing binaries.

## Development

```bash
npm run dev       # dev server on port 3000
npm run check     # tsc --noEmit + every assertion script  ← the gate
npm run build     # production bundle
npm run start     # serve the built bundle via Express
```

`npm run check` is the one that matters. There is no unit-test runner here;
correctness is enforced by assertion scripts under `scripts/`, discovered by
directory walk so that a new one cannot be forgotten out of a hand-maintained
list. They cover the protocol dissectors, the filter grammar, the colour-rule
engine, packet-list and detail rendering, session handling, preferences, and the
theme contract — token completeness, contrast ratios, how far apart two row
fills may be, and drift between the CSS variables and the TypeScript palettes.

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
  components/    UI, grouped by surface (packet-list, packet-details, analytics…)
  services/      dissection, filtering, colour rules, session, theming — pure,
                 client-side, no backend calls except geo/DNS lookups
  types/         packet.ts is the single source of truth for the domain model
  lib/           hooks and small utilities
scripts/         assertion scripts, run as a set by `npm run check`
local-agent/     Python capture agent, its tests, and the Windows installer
```

## Notes

- `security_spec.md` describes Firestore rules and a threat model for a Firebase
  backend that is **not currently implemented**. Read it as a spec for
  not-yet-built auth and sharing, not as a description of this code.
- Role-based access control is defined in `src/services/rbacService.ts` for four
  roles, but the app currently hardcodes the admin permission set. Components
  already gate on the permissions object, so restoring real roles is a matter of
  feeding one in.

## License

MIT — see [LICENSE](LICENSE).
