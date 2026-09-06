# Inwire — Network Decoding & Agent Specification, v3

**What this is.** A validated, re-ordered replacement for the v2 specification
(`inwire-network-decoding-spec-v2.md`), written to be handed to Claude Code one phase at
a time. Validated on 2026-09-04 against the tree at commit `ed511e3` plus uncommitted
work, the two fixture captures, and the agent service installed on the author's PC.
Start with Part B (the review gate) before any phase in Part C.

**How v3 differs from v2.** v2 was written against a reading of the code that is
several weeks stale, and its acceptance numbers were counted by hand. Every claim in it
was checked against the current tree and against **tshark 4.6.8** (installed at
`C:\Program Files\Wireshark\tshark.exe`) on the two real captures it names. Where v2 and
tshark disagree, tshark wins. The app's own output was then diffed column-by-column
against tshark on both captures, so each phase below is ordered by *measured* gap rather
than by protocol layer. A new Phase 0 puts a senior-developer review gate in front of the
work, because the two most expensive decisions (packet data model, worker boundary) sit
in v2 at step 14, after thirteen steps that would have to be redone.

---

## Part A — What was validated

### A.1 v2 claims vs reality

| v2 | Claim | Verdict | Evidence |
|---|---|---|---|
| A | Agent stamps packets with `time.time()` at ms | **Stale.** Agent ≥2.3.0 uses libpcap's `pkt.time` as fractional ms | `agent.py:348-360`; only 30 of 12,858 fixture frames are ms-truncated |
| B | ClientHello now spans 2 segments; reassembly finds 12 not 9 | **Wrong on its own fixture.** tshark finds 9 TCP ClientHellos with reassembly on *or* off; 0 span a segment. "12" is the SYN count | `tshark -Y "tls.handshake.type==1 && tcp"` = 9; `tcp.reassembled_in` = 0 |
| B' | TLS reassembly is mandatory | **Still true, for a different reason.** 2,186 Application-Data records span segments in `bulk`; the app labels the segment holding the record *header*, Wireshark labels the one where the record *completes*. Result: Protocol 59 %, Info 57 % match on that capture | gap diff below |
| C | ECH ext 0xfe0d; outer SNI may be a decoy | Confirmed. 34 of 43 ClientHellos carry it (all QUIC/h3, i.e. Chrome GREASE) | tshark |
| D | DoH bootstrap queries present | Confirmed (`cloudflare-dns.com` SNI and A/AAAA/HTTPS queries) | tshark |
| E | Checksum false-positives on offloaded outbound frames | Confirmed; 315 frames >1514 B, 200 of them tshark itself marks malformed | `-z io,phs` |
| F | WebCrypto has no AES-ECB → AES-CTR trick | **Moot.** App already ships synchronous pure-JS AES/HKDF/SHA-256 with RFC 9001 vectors and decrypts QUIC Initials (v1 and v2 salts) | `src/services/crypto/*`, `dissectors/quicCrypto.ts:24-78`, `scripts/parity/crypto-vectors.ts` |
| G | Binary batched transport | Valid, not done. One JSON text frame per packet, base64 raw | `agent.py:667-671` |
| H | CLAUDE.md says 4,000-frame buffer | **Stale.** 50,000 default, user-selectable 10k/25k/50k. **Real bug:** pcap/pcapng *import* is hard-capped at 10,000 frames, so a full export cannot be re-imported | `pcapParser.ts:218,303`; `interfacePrefs.ts:192` |
| I | pcapng NRB | Valid, not done. There is no pcapng *writer* at all (reader exists) | `pcapParser.ts:78-128` |
| J | TCP analysis table | Valid; app already has stream index, relative seq, WS, keep-alive, retrans, OoO, lost, ACKed-unseen. Missing dup-ACK, zero-window, window-update/full, spurious/fast, RTT | `tcpStreamTracker.ts` |
| K | Randomised MAC | Valid, not done | `macVendors.ts` |
| L | SSLKEYLOGFILE | Valid end-state | — |
| 0.3 | Agent drops non-IP frames | **Stale.** No BPF filter; ARP/STP/LLDP/1905 forwarded and dissected (105/41/1/85 all match tshark) | `agent.py:906-919` |
| 0.5 | Replace `wait_closed` with a command loop | **Done** (typed protocol, origin check). Gap: `state` is not broadcast on start/stop/set_interfaces | `agent.py:510-531` |
| 1.9 | 3,744 QUIC rows | **Over-counted.** tshark: 3,088 QUIC + 656 UDP/443 it declines to call QUIC. App matches tshark 2,560/2,560 in the first 10k | `-z io,phs` |
| 1.11 | LLDP/STP/IGMP | **Done and tested** (`scripts/lldp`, `scripts/igmp`) | — |

### A.2 Measured baseline (app vs tshark, first 10,000 frames — the import cap)

| Column | `inwire` (12,858) | `bulk` (14,782) | Dominant cause |
|---|---|---|---|
| Protocol | 95.9 % | **58.9 %** | TLS record boundary across segments; TLS version never read from `supported_versions` (TLSv1 / 1.2 / 1.3 mislabels: 342 rows) |
| Info | 90.7 % | **56.6 %** | same; plus spurious `[TCP ACKed unseen segment]` on SYN-ACKs, TCP option order, DNS multi-answer Info, mDNS `"QM" question`, RA `from <mac>`, DHCP absent |
| Source / Destination | 99.9 / 99.97 % | 100 % | 55-entry OUI table (`Intel_1c:2c:b2`), `IEEE-1905.1-Control` group name |
| Time / Length | 100 % | 100 % | — |
| Parse rate (Node, one thread) | 6.2 k pkt/s | 7.5 k pkt/s | 50k restore ≈ 8 s on the main thread |

411 ICMP "mismatches" were a harness artefact: tshark needs `-2` (two-pass) to print
`(reply in N)`. The app is right. 477 rows of ground truth change under `-2`.

### A.3 Is there data loss between agent and app? — **Yes, at four points, three of them silent**

1. **Kernel/driver drops** (Npcap ring buffer) when Python's per-packet callback lags —
   never measured; `pcap_stats` is not read anywhere (`interface_stats.py` uses psutil
   NIC counters, which count wire traffic, not capture).
2. **Agent send queue**: above `MAX_PENDING_SENDS = 400` packets are dropped and only
   logged. The installed agent's log shows **≥260,000 packets dropped** on 3 Sep
   ("the client is not keeping up") and the app never showed it.
3. **Browser buffer**: oldest frames trimmed past the cap, auto-pause at 99 % — the one
   visible mechanism.
4. **Ordering, not loss**: multi-interface threads interleave; 11 negative deltas in the
   `inwire` fixture; nothing sorts by time.

The transport is also not optimal: one text frame per packet, base64 (+33 %), a full
synchronous dissection inside the WebSocket `onmessage` on the main thread. Phase 2 and
Phase 11 fix the loss reporting first and the throughput second — in that order, because
a fast pipe that still drops silently is worse than a slow one that says so.

### A.4 Corrected acceptance oracle

Acceptance is **parity with tshark 4.6.8 (`-2`) on the two fixtures**, per column, with
thresholds per phase — not v2's hand counts. Fixed reference counts (from tshark):

| Metric | `bulk` | `inwire` |
|---|---|---|
| Frames | 14,782 | 12,858 |
| TCP ClientHello (with SNI) | 3 | **9** |
| QUIC ClientHello (SNI) | — | 34 (26 distinct names overall) |
| QUIC frames | 86 | **3,088** |
| TCP retrans / dup-ACK / OoO / lost / RST | — | 70 / 17 / 33 / 111 / 11 |
| Conversations (IP + IPv6) | 38 | 145 |
| Negative time deltas | 1 | 11 |

---

## Part B — Phase 0: Senior-developer review gate (new)

**Status: done 2026-09-04.** Decisions recorded in `docs/decisions/0001`-`0006`; the review's two amendments to the execution order (Phase 2 split into 2a/2b, a Phase 1b before Phase 4) are in `docs/decisions/README.md`.

**Purpose.** Decide the four things every later phase depends on, *before* dissector
work multiplies the cost of changing them. Output: one ADR each under
`docs/decisions/`, plus a re-ordered task list if the review disagrees with Part C.
Time-box: one session. The reviewer reads Part A, the three inventories below
(`pcapParser.ts` 1,945 lines; `filterEngine.ts`; `tcpStreamTracker.ts`; `agent.py`),
and answers:

1. **Packet data model.** Today every frame carries a full `layers[]` tree, a flat
   `fields` bag, `rawBytes`, `info` — built eagerly in `onmessage`. Two-phase dissection
   (summary on arrival, tree on demand) changes every dissector's return type.
   *Recommendation:* introduce `dissectSummary(bytes) → {columns, fields, analysis}` and
   `dissectTree(bytes, summary) → layers[]` as the contract **now**, migrate existing
   dissectors to it in Phase 4/5 as they are touched, and never add a new dissector on
   the old shape.
2. **Field registry.** The tree (`ProtocolField.name`) and the filter namespace
   (`Packet.fields`, `KNOWN_FIELD_NAMES`) are unconnected lists maintained by hand;
   "apply as filter/column" is impossible until a field carries its filter name.
   *Recommendation:* `ProtocolField.abbrev` (e.g. `tcp.flags.syn`) becomes required for
   any field a dissector publishes into `fields`; one registry module generates
   `KNOWN_FIELD_NAMES`, autocomplete, and column definitions; an assertion script fails
   on a field published without an abbrev.
3. **Worker boundary.** Dissection is synchronous by design (hand-rolled crypto exists
   *because* WebCrypto is async). *Recommendation:* keep dissection synchronous, move
   the whole pipeline (decode → summary → trackers → filter) into one Worker in
   Phase 11, posting column rows + typed-array deltas; the sync crypto is a strength
   here, not something to replace with WebCrypto.
4. **Fixtures and privacy.** The two captures contain this machine's SNI/DNS history and
   rotating IPv6 addresses; `origin` is `github.com/Doofess/NetView`, visibility
   unknown. *Recommendation:* fixtures and ground-truth `.psv` stay **untracked**
   (`test/fixtures/` gitignored, SHA-256 recorded in a README); only aggregate
   acceptance counts (`test/fixtures/acceptance.json`, no names/addresses) are
   committed; parity runs locally, `npm run check` asserts the counts file is current.
   Revisit once Phase 12's anonymiser exists.

Also settle: sequence-number/`iface` wire format (Phase 2) and pcapng writer scope
(Phase 12) so the agent and browser changes land once.

**Recurring gate.** At the end of each phase the same reviewer role spends ≤30 min on:
parity delta vs previous phase, new assertion script present, `CLAUDE.md` updated, no
dissector added on the old shape, no field without abbrev, `npm run check` green.

---

## Part C — Phases (execution order)

Each phase is one or more Claude Code tasks. Every phase ends with `npm run check`
green (assertion scripts are auto-discovered under `scripts/`), the parity script run on
both fixtures, and a `CLAUDE.md` update. Files named are the ones that must change.

### Phase 1 — Harness, fixtures, import cap

**Status: done 2026-09-04.** Import cap removed (caller-supplied, exact total reported); two-pass ground truth with `tcp.reassembled_in`; `parity-check.ts` rewritten with per-column floors in `test/fixtures/acceptance.json`; `scripts/import/capture-cap.ts` and `scripts/parity/acceptance.ts` added (suite 36 → 38). Baseline under two-pass: inwire Protocol 96.3 % / Info 86.5 %, bulk 60.4 % / 25.9 % (reassembled-PDU rows now labelled by tshark). Enforced counts: frames, quicRows, tcpRst on both; tcpClientHelloSni on inwire.

*Why first:* everything after is measured by it, and the current harness is pinned to a
115-frame `tmp.pcapng` with single-pass ground truth.

- Remove the 10,000-frame import ceiling in both extractors (`pcapParser.ts:218,303`);
  replace with the buffer-cap preference and a "N frames not loaded" notice.
- `scripts/parity/regen-ground-truth.sh`: add `-2`; add `-e tcp.reassembled_in`
  `-e tcp.segment` to the field list so "[TCP segment of a reassembled PDU]" rows are
  distinguishable from the "SSL / empty Info" case the two-pass trick exists for.
- `scripts/parity/parity-check.ts`: accept a fixture *set*, report per-column match %
  and mismatch buckets by tshark protocol (as `gap.mts` did during validation), compare
  colouring-rule names via `ColorRulesEngine.getMatchedRuleName`, and fail when any
  column drops below the thresholds in `acceptance.json`.
- `test/fixtures/README.md` (paths, SHA-256, regen commands); `.gitignore` entry.
- Fix `formatTimeColumn.ts:27` hardcoded 6-digit precision (ignores `tsPrecision`).

**Accept when:** both fixtures parse in full; baseline numbers in A.2 reproduce; check
suite 36 → 37+.

### Phase 1b — Dissection contract and registry (added by the Phase 0 review)

**Status: done 2026-09-04.** `src/services/dissect/types.ts` (`DissectInput`, `DissectSummary`, `DissectContext`, `LINKTYPE`), `src/services/dissect/fieldRegistry.ts` (52 fields, `LAYERS`), `ProtocolField.abbrev`, the filter engine's known names derived from the registry, and `scripts/dissect/registry.ts` (suite 38 -> 39). No behaviour change; parity unchanged.

### Phase 2 — Agent: honesty, lifecycle, platform, installer

*Answers "is it really idle / does every interaction work / versioning / icon /
uninstaller". Every finding below was verified in source and against the service
running on this PC.*

**Status: 2a done 2026-09-04 (protocol 3.1.0).** `state` broadcast on every command (asserted per command in `test_protocol.py`); `capture_stats` once a second with `pcap_stats` kernel drops and the agent's own, shown as a header chip and in Driver Info; `seq`/`iface`/`tsUs`/`origLen` on packets and `id` on interfaces (frames now attributed to the right adapter); `capture_failed`/`invalid_interfaces`/`unknown_command` errors and an agent-side stop when every adapter fails; send bound under a lock; sniff loop re-entered every 0.5 s so stop is honoured on a quiet adapter; `--version`; installer icon, TAB fix, `[UninstallDelete]` for logs, `VersionInfoVersion`; `test_interface_stats.py` in CI; `verify_protocol.py` extended. Rebuilt and published `public/downloads/Inwire-Agent-Setup.exe` (3.1.0). **Not yet done on this PC:** installing it and running `verify_protocol.py` need an elevated prompt. 2b (ownership, token, macOS/Linux, lazy scapy) is pending.

**2.1 What is true today**

- **Idle: genuinely idle.** With no tab open only the WebSocket listener and a 2 s
  orphan-capture watchdog run; no sniffer thread, no psutil sampling, no capture handle,
  no log polling. Measured on the installed service (up 5.5 days): CPU 0.0 s over a
  10 s window, ~0.06 % lifetime; **~90 MB RSS permanently** because all of scapy is
  imported eagerly (`agent.py:43-44`, `inwire_agent.spec:29-33`). Capture stops when
  the last connection closes (`agent.py:497-499`, tested).
- **Installed reality:** this PC runs **`NetViewAgent` 2.6.0** from
  `C:\Program Files\NetView Agent\` with `%ProgramData%\NetView`; no Inwire service
  exists. `public/downloads/Inwire-Agent-Setup.exe` is the 2.6.0 "NetView Agent" build
  renamed (`ProductVersion 2.6.0`). Today's user experience: install → agent says
  2.6.0 → "Update" pill → Download fetches the same 2.6.0 file. **An update loop.**
- **`state` is never sent** (regression from commit `4083f2e`): the only broadcast sits
  after the interface-stats loop (`agent.py:625`) and is unreachable on the normal
  cancel path; the fall-through `else: return` at `agent.py:575-576` is the leftover.
  Driver Info's "Capture: …" row is frozen at connect time, hot-plugged adapters never
  reach an open tab, and `verify_protocol.py` (8 `state` assertions) fails.
- **macOS and Linux do not work at all.** `bootstrap_macos.command` and
  `bootstrap_linux.sh` embed a pre-protocol copy of the agent: no `type` field, no
  `hello`, `await ws.wait_closed()` instead of a command loop, sniffs every interface
  from launch, no origin check, BPF `ip or ip6`. The app parses zero packets and shows
  the "Update" pill forever. The copies in `public/downloads/` are older still (ISO
  timestamps, no raw bytes). Also `pip --user` as the user, then run as root.
- **Installer:** `SetupIconFile` set and `icon.ico` valid, `[UninstallRun]` stops and
  removes the service, uninstaller registered — but **`UninstallDisplayIcon` missing**
  (blank icon in Add/Remove, confirmed), **no `[UninstallDelete]`** (config + ~4 MB
  logs survive), **`setup.iss:194` has a literal TAB in `{sys}\taskkill.exe`** so a
  wedged legacy agent is never force-killed on upgrade, no `VersionInfoVersion`
  (setup exe FileVersion 0.0.0.0), Npcap 1.79 pinned with no hash, unsigned.
- **Interactions:** all 8 commands and 6 messages have handlers on both sides. Gaps:
  no ack for any command; a capture that fails to open an adapter is only logged
  (`agent.py:918-919`) — the app shows "capturing" with zero packets; `error.code` is
  never read by the app; malformed `set_interfaces` silently ignored; unknown commands
  silently dropped.
- **Multi-tab:** one global sniffer; packets fan out to every connection; a second tab
  sending its remembered `set_interfaces` on `hello` restarts the sniffer on *its*
  adapter; Stop in one tab stops the other silently (and with `state` dead, no
  correction).
- **Security:** bound to loopback only (verified); `config.json` read-only to
  non-admins (verified); log contains no packet data (verified). But the origin check
  is a client-supplied header: **any local process, unprivileged, can connect with
  `Origin: http://localhost:3000` and stream every frame from a LocalSystem service.**
- **Tests:** `test_protocol.py` is thorough and in CI; `verify_protocol.py` and
  `test_interface_stats.py` are in nobody's run list.

**2.2 Work**

1. Move the `state` broadcast back to the end of `_handle_message`; delete the vestigial
   `else: return`; add a `test_protocol.py` case asserting start/stop/set_interfaces
   each broadcast `state`. Put `verify_protocol.py` back into the documented loop.
2. Loss reporting: read `pcap_stats` per interface (scapy's `L2listen` socket exposes
   the pcap handle; fall back to callback counts) and send
   `{"type":"capture_stats", iface, received, dropped_kernel, dropped_agent}` once per
   second while capturing; the app shows a persistent "N dropped" chip beside the packet
   counter and an expert note at the gap. Guard `_pending_sends` with a lock.
3. `seq` (one locked counter) and `iface` index on every packet; stable interface ids
   in `hello`. Report adapter open failure as `error{code:"capture_failed"}`; app reads
   `error.code`; agent answers unknown commands with `error{code:"unknown_command"}`.
4. Multi-tab: capture ownership — `set_interfaces`/`stop_capture` from a non-owner get
   `error{code:"capture_busy"}` unless the owner is gone; packets only to connections
   that sent `start_capture` (or subscribed). Decision recorded in Phase 0.
5. Auth: per-install random token written to `config.json` by the installer (admin-only
   read), passed as a WebSocket subprotocol; app obtains it via the `inwire://` handler
   or a one-time paste in Driver Info. Origin check stays as defence in depth. **Phase 0
   decides whether this ships in 2 or 11**; recommendation: 2, it is small.
6. Installer: `UninstallDisplayIcon={app}\{#MyAppExeName}`; fix the TAB; `[UninstallDelete]`
   for logs, uninstaller *asks* about config; `VersionInfoVersion`; SHA-256 for the Npcap
   download; `Permissions:` on the `[Dirs]` entry; `--version` flag; version bump to
   3.1.0 (protocol changed) in all three places; rebuild and republish all three
   downloads; document the release step in `local-agent/CLAUDE.md`.
7. macOS/Linux: stop embedding a copy. Ship the real `agent.py` + modules as a tarball
   the scripts download/extract, install deps for root (`sudo pip` or a venv owned by
   root), and provide persistence + stop: a LaunchDaemon plist on macOS, a systemd unit
   on Linux, each with an `uninstall` verb. Add a CI job that runs `test_protocol.py`
   on ubuntu and macos runners. Until this lands, the app should say "Windows only"
   rather than offer a broken download; `platformDetect` unknown → Windows, iOS → no
   download.
8. Memory: lazy-import scapy layers (`conf.load_layers`), import psutil on first use.

**Accept when:** `verify_protocol.py` passes against the rebuilt service; a 1-minute
capture during a large download shows `dropped_agent` in the UI when the log reports
drops; two tabs cannot change each other's adapter; a `curl` with a spoofed Origin and
no token is rejected; uninstall leaves no service, process, registry entry or logs;
Add/Remove shows the Inwire icon and 3.1.0; the macOS script produces packets in the
app on a Mac (or the download is hidden until it does).

**Status: 1, 2, 3 and 6 done with the phase; 4, 5, 7 and 8 done 2026-09-04 (agent 3.3.0).**

- **Capture ownership (4).** The connection that sends `start_capture` owns it.
  `stop_capture` and `set_interfaces` from anyone else are answered with
  `error{capture_busy}` and change nothing, packets and `capture_stats` go to
  the owner alone, and the owner leaving stops the capture rather than leaving
  it running for tabs that never asked for it. `hello` hands each connection a
  `clientId` and `state` carries an `owner`, which is what lets a second window
  tell "capture is running" from "capture is running and I can stop it" - it
  disables its own Start/Stop and says why, instead of offering a button whose
  only outcome is an error.

  This is the fix for a bug that was worse than it looked: a second tab sent
  its *remembered* `set_interfaces` on connect, so opening one moved a running
  capture to that tab's adapter without either user doing anything.

- **A pairing token (5).** The origin check is a header the client writes: it
  keeps an ordinary web page out of the agent and stops nothing that can set a
  header, which is any local process - and what it would be reaching is a
  LocalSystem service streaming every frame on the wire. `config.json` now
  carries a token the installer generates, and an agent that has one answers
  every command with `error{auth_required}` until a connection sends
  `authenticate`. Compared with `hmac.compare_digest`, because both ends are on
  one machine and the usual argument that timing attacks are impractical is the
  argument that does not apply locally.

  Announced in `hello` rather than enforced in the handshake: a refused
  handshake reaches a browser as an opaque WebSocket error, which is exactly
  what "the agent is not running" looks like, and the app has to be able to
  tell those apart to ask for the token. The one paste is the security
  property, not a gap in it - the browser cannot read `%ProgramData%`, which is
  why the token is kept there.

- **macOS and Linux (7).** The two bootstrap scripts each embedded a copy of
  `agent.py` that stopped being updated around 2.1 and went on being
  downloaded: no `hello`, no typed messages, no origin check, sniffing every
  interface from launch. The app parsed zero packets and showed the "Update"
  pill for ever. They are gone. In their place is one tarball built from the
  real sources (`scripts/agent/package-unix.ts`), carrying its own `install.sh`
  - a root-owned virtualenv rather than `pip --user` as the invoking user
  followed by running as root, a systemd unit or a LaunchDaemon, a generated
  pairing token, and an `uninstall` verb. An assertion fails if a module the
  agent imports is missing from the archive, which is the old failure written
  down. CI runs the protocol tests on macOS as well as Linux, checks that the
  installer parses, and imports the agent on both.

  `platformDetect` now answers `ios` and `android` and offers no download for
  either, and no longer falls back to the Linux script for a platform it does
  not recognise.

- **Memory (8).** Scapy is a capture driver here and nothing else - the browser
  has dissected since 3.2.0 - so `conf.load_layers` is cut to `l2`, `inet` and
  `inet6` before `scapy.all` is imported, and the protocol classes the agent
  still imported with no reader left are gone. Measured: 65.6 MB and 0.33 s of
  import become 39.9 MB and 0.17 s; the agent module as a whole goes from about
  89 MB resident to 63 MB, for a service that spends nearly all its life idle.
  `psutil` was left eager after measuring it at roughly nothing.

Verified live, on a real agent process over a real socket
(`scripts/` has the unit tests; the control path was driven end to end): an
unpaired connection cannot capture, a wrong token is refused and the right one
accepted, a disallowed origin is still refused during the handshake, and of two
paired connections only the one that started the capture can stop it or move
it.

**Verified against a real installed service, 2026-09-04.** Built
(`pyinstaller` + `iscc`), installed, exercised, uninstalled and reinstalled on
this machine. Everything in the acceptance list above now has a result:

- `verify_protocol.py`: **30 checks, all passing** against the live 3.3.0
  service - state after every command, `capture_stats` while sniffing, the
  error codes, the log subscription, and both origin rejections.
- A **1-minute capture under load**: 147,595 frames delivered, **0 agent
  drops**, and the driver's own counter read for the first time.
- A **1-minute capture at rate** (loopback, four senders): **5,872 frames/s
  average and 6,295/s peak with 0 agent drops** - Phase 11's criterion - while
  the driver reported **21,006,015 dropped**. That number is the whole point of
  Phase 2: the capture was 1.6% complete and the app says so, where before it
  would have shown a clean-looking list of 352,408 frames.
- **Uninstall**: no service, no process, no install directory, nothing
  listening on 8999, no registry entry, no logs. `config.json` is left behind
  deliberately - it holds an edited allowlist and a token somebody has pasted
  into a browser - and a reinstall picks the same token back up, which was
  checked by pairing with it afterwards.
- Add/Remove Programs shows **"Inwire Agent version 3.3.0"** with the agent's
  icon; both were spec gaps (`VersionInfoVersion` absent, `UninstallDisplayIcon`
  missing).
- The app itself: paired through Settings -> Driver Info and capturing live at
  3.3.0, over the binary transport.

**Two bugs that only a live run could have found.**

1. **The driver's drop counter had never worked.** `read_pcap_stats` reached
   for the libpcap handle at `sock.ins.pcap`; current scapy keeps it at
   `sock.pcap_fd.pcap`. The lookup failed, the function returned None - which
   it is *documented* to do when a handle is unavailable - and the app
   faithfully rendered "unknown" on every capture since the feature shipped.
   The failure was indistinguishable from the thing it was designed to report
   honestly, which is what made it survive. Both attribute names are tried now,
   and the loopback run above is what proves it: 21 million drops where there
   had only ever been a dash.

2. **`config.json` was readable by `BUILTIN\Users`.** `%ProgramData%` grants
   that by default and a file created there inherits it, so the pairing token -
   whose entire job is to distinguish the user's browser from another process
   running as the user - would have been readable by every one of those
   processes. Verified with `Get-Acl` on a real install before the fix. The
   agent now restricts the file to SYSTEM and administrators on every run
   (`icacls /inheritance:r`, `chmod 600` on Unix), so installs that predate it
   are fixed on upgrade rather than left open.

**One deliberate change of behaviour while doing this.** An upgrade that finds
a config with no token now adds one, where the first draft left the file
untouched. "Never overwrite" is right for a token somebody has already pasted
into a browser and for an edited allowlist; it is wrong for a missing token,
because it would have left every install that predates the feature
unauthenticated for ever. Existing keys are preserved; only the missing one is
filled in.

`verify_protocol.py` needed a fix of its own before it could run at all: it
called `json.loads` on every message, and since 3.2.0 captured frames arrive as
binary. The first frame captured during a run killed it with a
`UnicodeDecodeError` - a verification tool failing in the way that looks most
like the thing it is verifying being broken.

### Phase 3 — Time and ordering

**Status: done 2026-09-04.** `Packet.timestamp` (ms) replaced by `Packet.tsUs` (epoch microseconds, plus `tsNanos` for nanosecond files); every reader updated, stored sessions from older builds still load (`storedFrameTsUs`). Live frames now wait in `src/services/dissect/orderingWindow.ts` (100 ms hold, ordered by `(tsUs, seq)`) and are dissected by the flush in capture order, so the trackers see the wire order. The pcap writer derives microseconds exactly and writes frames sorted by capture time. **Deviation:** import does *not* sort - Wireshark shows a file in file order and the parity harness compares row-for-row, so sorting on import would renumber frames relative to the file; ordering is applied at ingest (live) and at export instead. `scripts/dissect/ordering-window.ts` added (suite 40).

- `Packet.timestamp` becomes microseconds (`number` is exact to 2^53 µs); keep
  `tsNanos: bigint` for ns captures; live path sets `tsPrecision = 6`.
- Ingest orders by `(ts, seq)` with a 100 ms insertion window; import stable-sorts.
- pcap writer derives `tsUsec` from µs, not `ms % 1000`.

**Accept when:** re-export of `inwire` has 0 negative deltas; Time column parity stays
100 %.

### Phase 4 — TLS over TCP: reassembly, negotiated version, a real TLS layer

**Status: done 2026-09-04.** `src/services/dissectors/tls.ts` rewritten on the summary/tree split: a per-direction record cursor in `TcpStreamTracker` (sequence-number based, so a lost segment inside a record does not lose the record), Wireshark's resync rules (a known direction accepts any valid content-type byte as a header; "Ignored Unknown Record"), the frame that *completes* a record carries the TLS label while earlier segments get "[TCP PDU reassembled in N]" via `InfoPatch`; negotiated version per conversation with the ClientHello re-labelled once the ServerHello settles it; a full TLS layer (records, hellos with every extension named, key-share sizes, ECH heuristic, alerts, TLS 1.2 certificates via `x509.ts`); JA3/JA3S/JA4 (`crypto/md5.ts` added). tshark's JA3/JA3S/JA4 are now ground-truth columns. Measured: **bulk Protocol 60.4 → 96.1 %, Info 25.9 → 92.6 %; inwire Protocol 96.3 → 99.0 %, Info 86.5 → 89.8 %**; all 9 TCP ClientHello JA3/JA4 match tshark exactly. What remains on bulk is TCP-analysis classification (Out-Of-Order vs Retransmission, Window Update) and its effect on reassembly - Phase 5. `scripts/tls/dissect.ts` added (suite 41).

*Largest measured win (bulk 59 % → ≥99 % Protocol).*

- Per-direction record cursor in `TcpStreamTracker`: carry bytes-remaining-in-record
  across segments; label the frame where a record **completes**; mark earlier segments
  `[TCP segment of a reassembled PDU]` (Protocol `TCP`). Buffer only handshake records
  for parsing (cap 64 KB per direction); Application Data needs the cursor, not the bytes.
- Per-conversation negotiated version: ClientHello → handshake version; ServerHello
  `supported_versions` → 1.3; all later records on that stream inherit it.
- New `dissectors/tls.ts` output = a `ProtocolLayer` with fields and abbrevs
  (`tls.record.*`, `tls.handshake.*`): ClientHello ciphers (named, GREASE stripped),
  extensions by name incl. `supported_groups` (`X25519MLKEM768 (0x11ec)`), `key_share`
  sizes, ALPN, `supported_versions`, ECH (`0xfe0d`) with the v2 heuristic for real vs
  GREASE; ServerHello selected cipher/group/version; TLS 1.2 Certificate leaf CN/SAN/
  issuer/validity; alerts; `[Certificate: encrypted (TLS 1.3)]`.
- JA3, JA3S, JA4 (core only — licence note kept from v2) as generated fields.

**Accept when:** `bulk` Protocol ≥ 99 %, Info ≥ 97 %; `inwire` TLS rows ≥ 99 %;
9 TCP ClientHellos each with SNI + ALPN + JA4; assertion script with byte-level vectors
for the two hellos.

### Phase 5 — TCP analysis completion and bugs

**Status: done 2026-09-04.** `src/services/dissect/tcpAnalysis.ts` reimplements Wireshark 4.6's `tcp_analyze_sequence_number` check for check (source read, not recalled): zero window / probe / probe ACK, lost segment, keep-alive and its ACK, window update and window full, duplicate ACK with the original frame number, ACKed unseen segment with the contiguous-run rule, spurious / fast (dup-ACK and SACK based) / plain retransmission vs out-of-order by the peer's last-ACK timer and iRTT, initial RTT, ACK RTT with partial ACKs, bytes in flight, reused ports; the SYN/FIN sequence accounting bug is gone with it. Tags print in Wireshark's (prepend) order; options print in wire order; TCP and UDP checksums are computed with the offload policy (`Unverified` for zero, truncated or over-MTU segments) and published as `*.checksum.status`. Measured on the tag vocabulary: **1 disagreeing frame on inwire and 4 on bulk** out of every TCP row; Info 89.8 → 94.2 % (inwire) and 92.6 → 94.3 % (bulk); colour-rule parity 95.5 → 99.9 % and 98.9 → 99.98 %. Enforced counts on inwire now include retransmission (70), outOfOrder (33), lostSegment (111). `scripts/tcp/analysis.ts` added (suite 42).

- **Bug:** SYN/FIN consume one sequence number; `checkSequence` ignores it, producing
  `[TCP ACKed unseen segment]` on SYN-ACKs and `[Previous segment not captured]` on the
  handshake ACK.
- **Bug:** options in Info must follow wire order (`MSS=1344 SACK_PERM WS=128`).
- Add dup-ACK (#n), zero window, window update/full, zero-window probe/ACK, spurious and
  fast retransmission, reused ports, RTT (SYN↔SYN-ACK and TS option), `[Bytes in
  flight]`; out-of-order vs retransmission by Wireshark's timing rule.
- TCP checksum computed, with the offload policy from v2 §1.3 (`Unverified` for
  outbound >1514 or zero); publish `tcp.checksum.status` so the shipped colour rule can
  ever match. Same status field for IP/UDP/ICMP.
- Publish `tcp.seq`, `tcp.ack`, `tcp.options.*`, `tcp.analysis.*` as fields.

**Accept when:** `inwire` retrans/dup-ACK/OoO/lost/RST = 70/17/33/111/11 (±2 for
timing-rule differences, each listed); TCP Info parity ≥ 99 % on both fixtures.

### Phase 6 — L2/L3 completeness

**Status: partly done 2026-09-04.** Done: the IPv6 extension-header chain (`dissectors/ipv6Ext.ts` - Hop-by-Hop, Destination Options, Routing, Fragment with the non-first-fragment stop, AH's 4-byte length rule, ESP, No Next Header, Router Alert options), which fixes the MLDv2 frames that were reported as `IPv6 Hop-by-Hop`; DHCP and DHCPv6 (`dissectors/dhcp.ts`, hostname / vendor class / parameter list / client id, Wireshark's padded Info); ICMPv4 and ICMPv6 error type and code names; the echo Info padding; mDNS `"QM"/"QU" question` and full answer lists with SRV priority/weight/port; the OUI table regenerated from IEEE's registry (40,083 entries, short names derived by this project's own rule - `scripts/gen-oui.ts`) plus the IEEE 1905.1 control group address. **Both address columns are now exact on both fixtures (100 %).** Info: 94.2 → 98.5 % (inwire), 94.3 → 94.7 % (bulk). `scripts/ipv6/extensions.ts` added (suite 43).

**Status: done 2026-09-04 (second half).** The remainder, in the order it mattered:

- **Link type is read, not assumed** (`src/services/dissectors/linkLayer.ts`). The
  pcap header's `network` field and the pcapng IDB's `LinkType` were parsed and then
  ignored: every frame was decoded as Ethernet II with the network header at offset
  14. Ethernet, raw IP, BSD loopback and Linux cooked v1/v2 are now each read for
  what they are. `scripts/link/layer.ts` wraps one IPv4/TCP datagram in all five and
  requires the same packet out of each - a test that only checked "SLL parses" would
  pass on an implementation reading the wrong offset, because the bytes it read would
  still be *some* addresses. A pcapng file's link type is per interface, not per file,
  because `tcpdump -i any` produces exactly that.
- **802.3 / LLC / SNAP.** A type/length field at or below 1500 is a length, and what
  follows is an LLC header. Every STP BPDU on the wire is one, and this repo's own
  fixture has 105: they dissected only because the STP dissector reached past a header
  nothing described, so the tree jumped from Ethernet straight to Spanning Tree and
  `frameProtocols` never said `llc`. It now reads `eth -> llc -> stp`, bytes 12-13 are
  labelled a Length rather than "Type: 0x0026 (Unknown)", and SNAP's inner ethertype is
  followed so IPv4 over 802.3 dispatches normally.
- **IPv4 options** (`src/services/dissectors/ipv4.ts`). `ip.hdr_len` was used to find
  the transport header and the bytes in between were never looked at. Router Alert,
  Record Route and the source routes (with the pointer separating filled slots from
  empty ones), Timestamp and Stream Identifier are read; anything else is listed with
  its bytes rather than dropped. **7 option nodes on `inwire`** - the spec's acceptance
  number - all IGMPv3 Router Alerts.
- **DSCP and ECN are named**, as IPv6 has named them since the first half: `0xb8
  (DSCP: EF PHB, ECN: Not-ECT)` rather than 46 and 0.
- **TTL carries the distance it implies** - `[Inferred initial TTL]` and `[Hops away]`,
  both `generated`, because it is a guess from the small set of initial values stacks
  actually use.
- **IP fragments, reassembled** (`src/services/l3Tracker.ts`). This was wrong, not
  missing: a non-first fragment carries application data where a transport header would
  be and it was being read as one, so the second fragment of a UDP datagram was reported
  with two invented port numbers and a length taken out of the payload. The fragments
  are now stitched back together and the transport dissector runs **once, on the whole
  datagram, in the frame that completed it** - which is where Wireshark shows it, and
  why every earlier fragment reads `Fragmented IP protocol (proto=UDP 17, off=..., ID=...)`
  and gets `[Reassembled in N]` through the same `InfoPatch` path TLS reassembly uses.
  The completing frame carries a `[N Reassembled IPv4 fragments (M bytes)]` row listing
  each contributor and linking to its frame.

  Three properties the assertions hold it to. **A hole is never filled in**: a datagram
  missing a fragment is reported as incomplete rather than handed to the transport
  dissector with the gap zero-filled, which would produce a confident reading of bytes
  nobody sent. **Overlaps resolve first-arrival-wins and are reported** - overlapping
  fragments are the classic evasion, where a sender arranges for a firewall and the host
  behind it to reassemble different datagrams from the same frames. And **out-of-order
  arrival works**: a trailing fragment routinely arrives first, and the frame that fills
  the last hole is the one that carries the dissection.

  The strongest check is the equivalence one: the same datagram split 2, 3, 4 and 5 ways
  must dissect to exactly what it dissects to when it arrives whole - protocol, ports,
  Info, layer stack and fields. Reassembly that produced a *different* reading would be
  worse than not reassembling at all.

  A layer built from a reassembled datagram carries **no byte ranges**, because it
  describes bytes that are not in this frame's hex dump - the rule TLS reassembly across
  segments already follows.

  **IPv6 fragments** go through the same tracker, keyed the way RFC 8200 §4.5 keys them:
  source, destination and the Fragment header's 32-bit identification, with the payload
  protocol deliberately excluded - the Fragment header sits above whatever the payload
  turns out to be, which is why IPv6 moved fragmentation out of the fixed header at all.
  Two differences from IPv4 that the assertions pin down: an **atomic fragment** (offset
  0, More Fragments clear) is not fragmented and is processed where it stands, per RFC
  6946; and the **fragmentable part may itself begin with extension headers**, so the
  reassembled buffer is walked again before the transport dissector sees it - a
  Destination Options header that arrived split across two frames ends up in the tree of
  the frame that completed the datagram, with its filter token in the chain.
- **ARP duplicate-address detection.** One address answered by two MACs is invisible in
  either frame alone. Only a claim counts - a request's target fields are a question -
  and the change is reported once rather than on every frame after it.
- **NTP, STUN and DNS over TCP** (`src/services/dissectors/udpApps.ts`). STUN is
  dispatched **by content**: it is how a WebRTC call finds itself, it runs on whichever
  port ICE gave it, and RFC 5389's magic cookie exists precisely so it can be found
  there. XOR-MAPPED-ADDRESS is unmasked. DNS over TCP differs from the datagram form by
  a two-byte length prefix and nothing else, so all of Phase 7's dissector applies - it
  was simply never reached, because the dispatch only looked at UDP.
- **The offload note.** A frame past the 1514-byte MTU was never on the wire in that
  shape; saying so is what stops its zero checksum reading as damage.

Neither fixture contains a fragment, a STUN exchange, an NTP poll or a DNS query over
TCP, so the parity harness cannot see any of this - which is why
`scripts/ipv4/options-and-fragments.ts` builds each case byte by byte and decodes it
through the real `decodeRawEthernetPacket`. Parity is unchanged on every column
(suite 51 -> 55 across this phase and Phase 11).

Phase 6 is complete.

- Honour pcap/pcapng **linktype** (Ethernet, Linux SLL/SLL2, raw IP, loopback);
  today it is read and ignored, so any non-Ethernet capture misparses.
- LLC header layer (DSAP/SSAP/Control) and SNAP dispatch; named EtherTypes per v2.
- IPv4 options (Router Alert, RR, TS, unknown as type/len/hex); DSCP/ECN names on v4
  (already on v6); TTL inferred-initial/hops; fragment tracking (reassembly optional).
- IPv6 extension-header chain walk (the 5 MLDv2 frames), multicast group names,
  temporary-address flag.
- OUI table: regenerate from IEEE (`scripts/gen-oui.ts` exists) — ship the full MA-L as
  a lazy-loaded JSON; locally-administered and multicast bit labels.
- UDP dispatch by content as well as port; DHCP/DHCPv6, NTP, STUN, DNS-over-TCP.
- Offload note `[Frame exceeds MTU; segmentation by NIC]`; ICMPv4 error types with
  inner header; RA `from <mac>`; ARP duplicate-IP conflict.

**Accept when:** `inwire` IPv6 Hop-by-Hop rows show `ICMPv6 MLDv2 Report`; 7 IPv4
option nodes; 2 DHCP rows; Source/Destination parity 100 %.

### Phase 7 — DNS family

**Status: done 2026-09-04.** The message is parsed once (`dissectors/dnsRecords.ts`) and rendered twice - Info line and tree - so a record can no longer be readable in the list and absent from the details pane. Added: Answers / Authoritative nameservers / Additional records sections, EDNS(0) (payload size, DO bit, options incl. Client Subnet and cookies), SVCB and HTTPS rdata with `alpn`/`ipv4hint`/`ipv6hint`/`ech` (the `ech` parameter is what will tell Phase 4's ECH heuristic that an outer SNI is a decoy), SOA/SRV/CAA/TXT rdata, TTLs in Wireshark's wording, and query/response pairing (`dnsTracker.ts`) giving `[Request In]`, `[Time]` and a `[Response In]` patched back onto the query frame, plus an NXDOMAIN expert note and an unanswered-query sweep. `resolved` (name to addresses) is returned per frame, ready for Phase 10's passive name map. Info parity: 98.5 → 98.8 % (inwire), 94.7 % (bulk). `scripts/dns/records.ts` added (suite 44).

**Deviation:** the mDNS pairing key is the question name alone, not the client address - on a shared bus the answer comes from whichever host owns the name, never from the host that asked.

Answer/Authority/Additional tree nodes; OPT/EDNS (size, DO, ECS, cookie); HTTPS/SVCB
rdata (alpn, port, hints, `ech`); mDNS Info parity (`"QM" question`, full answer
list); query↔response pairing `[Response In]`/`[Time]` (reuse the ICMP tracker
pattern and the retro-patch path in `pcapParser.ts:341` / `App.tsx:1181`); NXDOMAIN and
unanswered notes; NBNS name decoding; DoH/DoT capture-level notice.

**Accept when:** DNS/MDNS/LLMNR Info parity ≥ 99 %; 67 HTTPS queries with decoded
rdata on responses; 4 NXDOMAIN notes; every response has `[Request In]`.

### Phase 8 — QUIC: CRYPTO reassembly -> SNI/ALPN, tree, parity

**Status: done 2026-09-04.** CRYPTO frames are collected out of decrypted Initial packets and reassembled per direction in `QuicFlowTracker` into a sparse buffer, parsed only when contiguous from zero and complete to the declared length; the same hello parser as TLS-over-TCP then yields SNI, ALPN, the extensions and a JA4 with the `q` transport prefix, plus JA3S from the server's Initial. A TLS layer is added to the QUIC frame. **All 34 QUIC ClientHello server names are now recovered (0 before), and JA3, JA3S and JA4 are exact on both fixtures** (JA3 20.9 → 100 %, JA3S 15.9 → 100 %, JA4 20.9 → 100 %); `quicClientHelloSni` is an enforced count. Also fixed here: an out-of-order segment is now dissected against a cloned record cursor (Wireshark reassembles it) while a retransmission still is not (Wireshark shows the plain TCP line) - worth 0.5 % of inwire's Protocol column and, got backwards, 8 % of bulk's.

**Deviation:** the Info column does not name the QUIC server name, because tshark's does not either. The name is a field (`tls.handshake.extensions_server_name`), which is what Phase 10's passive resolution reads.

Collect CRYPTO frames by offset per `(5-tuple, DCID)` across Initials (PQ hellos span
two), hand to Phase 4's ClientHello parser (JA4 `q` prefix); Retry re-keying; short
header DCID in Info; server-Initial PKN; a QUIC `ProtocolLayer` with `quic.*` fields;
`HTTP3` label once ALPN=h3.

**Accept when:** 34 QUIC ClientHellos with SNI; QUIC Info parity ≥ 99 %; 3,088 QUIC
rows.

### Phase 9 — Filter engine and field registry

**Status: done 2026-09-04.** The language now lives in `src/services/filter/`:
`lexer.ts` (one pass, one `word` token for names and unquoted values so a CIDR, an
IPv6 prefix, a MAC and `3..5` all survive intact), `parser.ts` (recursive descent to an
AST), `fields.ts` (every name resolved through the registry; the engine's own aliases
are the only hand-written names and each is a `Packet` property no dissector writes) and
`compile.ts` (field readers, literals and regexes resolved once, returning a closure).
`filterEngine.ts` is now a facade.

**`==` is equality.** It used to mean "equal *or* contains", so `ip.src == 10.0.0.1`
also matched `110.0.0.10` and every preset written with `==` asked a wider question than
it looked like. Substring and pattern matching are spelled out: `contains`
(case-sensitive, as in Wireshark), `icontains`, `matches`/`~`. `!=` is the negation of
`==` over every occurrence of a field, and an absent field never matches under any
operator. Also added: `xor`, byte slices (`eth[0:2]`), `0x` literals everywhere,
worded operators, and syntax errors that name the character they gave up at.

Two real bugs fell out of the parity run rather than the test suite. A bareword layer
test consulted `Packet.protocol` when the frame's own layer list did not carry the
token - and `protocol` defaults to `TCP` for any frame that never reached a transport
decoder, so ARP, IGMP and broadcast Ethernet frames were all matching `tcp` (391 frames
mis-coloured). And `frameProtocols` had no token for DNS, DHCP, LLDP, IGMP or QUIC,
because those layers' display names fell through `PROTOCOL_NAME_MAP` to
`domain_name_system`; both are fixed, and colour-rule parity **rose to 99.99 % (inwire)
and 99.98 % (bulk)**.

An unknown name is no longer a substring search. `dcerpc` in a shipped colour rule used
to paint any frame whose Info happened to contain those letters; a name this build
cannot produce now matches nothing. The validator separates a typo (`tpc.port`, an
error) from a protocol Inwire recognises and does not decode (`ospf.msg`, a warning, so
Wireshark's default rules keep their filters and light up when the dissector lands).
The filter *bar* keeps a free-text search for a lone unrecognised word, because typing a
hostname there is a habit worth keeping; `compileFilter`, which colour rules use, does
not.

`ip.checksum`/`ip.checksum.status` are now published (with the same offload policy as
the transport checksums), which is what the shipped Checksum Errors rule needed. Tree
rows for the addresses, TTL, ports, sequence and ack numbers, every TCP flag bit and the
window now carry their `abbrev`, so the rows people reach for first can actually become
a filter; `scripts/dissect/registry.ts` decodes a synthetic frame and fails if any of
them loses it again.

UI: right-click a tree row for Apply/Prepare as Filter (Selected / Not / …and / …or),
Apply as Column, Copy Value / Field Name / as Filter; the pane header names the hovered
row's field; the filter bar's autocomplete is back, generated from the registry rather
than the twenty-odd hand-typed examples that were removed for drifting; a column added
from the tree is drawn between Length and Info and removed from the column menu.
`scripts/filter/engine.ts` added (suite 45 → 46); a 50,000-frame pass measures **5 ms**
against the phase's 50 ms budget.

Replace the regex re-parse (`filterEngine.ts:217`) with tokenizer → AST → compiled
predicate over `fields`; **fix `==` meaning substring** (`compareStrings:542`), keep
`contains`/`matches` explicit; generate `KNOWN_FIELD_NAMES`, autocomplete and column
catalogue from the registry (Phase 0 decision 2); tree right-click: Apply/Prepare as
filter (selected / not / and / or), Apply as column, Copy value/field name; status-bar
field name on hover. Assertion script for the engine itself (none exists).

**Accept when:** every shipped colour rule and preset compiles against the registry or
is removed; `tcp.flags.syn == 1 && !tcp.analysis.flags` and
`tls.handshake.extensions_server_name contains "google"` work; 50k-frame filter ≤ 50 ms.

### Phase 10 — Enrichment and views

**Status: done 2026-09-04, with one deviation.**

**Passive name resolution** (`services/nameResolution.ts`). Every name comes out of the
capture itself - DNS and mDNS answer sets, TLS and QUIC server names, DHCP hostnames and
leases, LLDP system names, and ARP to carry a known MAC's name onto the address it is
using. Nothing is looked up, so it works on an imported file from a network that no
longer exists and cannot tell a resolver which addresses were captured. Sources are
ranked, because they disagree: a host naming itself over DHCP outranks a DNS answer,
which outranks an SNI - one CDN address serves thousands of names, so an SNI says very
little about the address. A **real ECH ClientHello's outer name is deliberately not
learned**: `cloudflare-ech.com` is genuinely carried and genuinely wrong, which is the
worst combination. On the fixtures this learns 115 names (inwire) and 14 (bulk) with
no network access, and **the 3,395-frame IPv6 conversation resolves to `claude.ai`** -
the acceptance criterion. Resolution is a *rendering* choice throughout: `Packet.source`
stays the address on every path, so filters, exports and the parity harness are
untouched. Defaults ON, unlike Wireshark, whose default guards against reverse-DNS
traffic this cannot generate. `services/portServices.ts` does the same for ports.

**Statistics** (`services/statistics.ts`, `components/statistics/`). Conversations,
endpoints, protocol hierarchy, devices, expert information and resolved addresses, on
six tabs, with Ethernet/IPv4/IPv6/TCP/UDP sub-tabs where they apply. **`inwire` shows
145 conversations (88 IPv4 + 57 IPv6)** and bulk 38, both matching Part A.4. Every row
is a filter: clicking one applies the display filter that selects exactly its frames, and
the filters come from the statistics module rather than being spelled out in the dialog,
so a row and its filter cannot disagree. The hierarchy is built from `frameProtocols` and
counts a frame at every level it passed, which exposed a real ordering bug - `quic` was
appended to the end of the chain, so on the 68 frames carrying both it read as a child of
the TLS it actually contains. Transport tokens are inserted beside their transport layer
now, and the IPv6 extension headers get their proper dotted tokens instead of
`ipv6_hop-by-hop_options`.

**Expert information** (`services/expertInfo.ts`). The two severity vocabularies are one:
`ExpertSeverity` (`chat/note/warn/error`) is the enum, `AnomalyInfo`'s four levels map
onto it, and the same palette paints the detail tree, the packet list's new severity dot
and the Expert Information tab. Identical findings collapse to one row with a count and
the frames behind it. `inwire.expert.severity` is published at dissection as the worst
finding in a frame, which is what lets a colour rule and a display filter ask about
expert info at all - neither can walk a tree.

**Colouring rules.** There was no editor; `canChangeColorRules` gated nothing. There is
one now (Settings → Colouring Rules): reorder, enable, edit, add, delete, reset, with
each row previewed by the same `resolveRuleColors` the packet list uses and each filter
validated *strictly* (a colour rule has no free-text fallback). The chain is stored and
validated on load. Three bands were added - **Expert Warnings, TLS Handshake, QUIC** -
kept in `INWIRE_EXTRA_RULES` and inserted where first-match-wins puts them to work.
`WIRESHARK_DEFAULT_RULES` stays exactly Wireshark's twenty and is what the parity harness
compares against, so that column still measures the engine against Wireshark's own
decisions. QUIC now gets its own band on 24 % of `inwire` instead of reading as plain UDP.
Expert Warnings ships **disabled**, like Checksum Errors and for the same reason: measured
on the fixtures it would paint 14 % and 22 % of the list, almost all of it "Bad checksum"
on locally-originated traffic where NIC offload means the checksum was never filled in.

**Follow Stream** (`services/followStream.ts`). Selection is by five-tuple rather than by
the TCP tracker's index, which is what makes it work for UDP and QUIC at all - they have
no index, so the option was simply not offered on them before. Direction is decided by
the well-known port first and arrival order second, so a capture that started mid-stream
is not labelled backwards. `raw` was rendering the ASCII view; it is the payload as one
unbroken hex string now, which is the thing that gets pasted into a decoder.

**I/O graph.** The traffic timeline gained a bucket **interval** (100 ms / 1 s / 10 s /
1 min - it was hardcoded to one second, which hides a microburst and drowns an hour) and
a **filter-defined overlay series** drawn against the same axis as the total, so the
answer reads as a proportion. **Deviation:** one overlay, not Wireshark's arbitrary
number of series. Generalising the D3 draw to N series is most of a rewrite of that
component for a feature whose common case is "how much of this is X"; the option model
now has a `text` kind, so adding more series is a widening rather than a redesign.

`scripts/statistics/tables.ts`, `scripts/names/resolution.ts`, `scripts/expert/log.ts`,
`scripts/color-rules/library.ts` and `scripts/stream/follow.ts` added (suite 46 → 51).
Parity unchanged on every column.

Passive name resolution map (dns/mdns/sni/quic-sni/dhcp/lldp; skip ECH outer names)
with a Resolved Addresses view and a View → Name Resolution toggle; port→service table;
5-tuple conversations, endpoints, protocol hierarchy (from `frameProtocols`) as
sortable tables with click-to-filter and Follow Stream; **Expert Information** — unify
`AnomalyInfo` and `expertInfo` severities into one enum, aggregate by severity/group,
list with jump, severity dot column; colour preset repair (remove rules referencing
fields no dissector will ever publish, add QUIC / TLS handshake / Expert Warning bands)
and restore a rules editor (there is none; `canChangeColorRules` gates nothing); device
inventory; Follow Stream: real `raw` mode, direction from tracker, UDP/QUIC streams;
I/O graph filter-defined series and interval.

**Accept when:** `inwire` shows 145 conversations with the top four from v2 §2.4; the
TCP/43594 and the 3,395-frame IPv6 conversations show hostnames with no external lookup.

### Phase 11 — Transport and performance

Binary batched WebSocket frames (v2 §0.4 layout, plus `iface` and both lengths), JSON
kept for control; Worker pipeline per Phase 0 decision 3; two-phase dissection
completed for all dissectors; typed-array frame store with configurable cap and
"N frames dropped (buffer full)"; drop counters from Phase 2 shown end-to-end.

**Accept when:** 1-minute capture at ≥5k pkt/s with 0 agent drops and main-thread long
tasks < 50 ms; 100k-frame buffer usable.

**Status: done (2026-09-04).** The measurement came first and changed the design.
`scripts/perf/clone-cost.ts` on the `inwire` fixture: dissecting a frame costs
178 us, cloning the whole `Packet` across the worker boundary costs **57 us**
(32% of it), cloning it without `layers` costs **5.1 us**, and without the bytes
as well 4.0 us. Resident, a frame is 1.2 kB of bytes and 10.6 kB with its
protocol tree - so a 100,000-frame buffer was **1.06 GB** and is now ~180 MB.
The tree was the whole cost on both counts and the bytes were nearly free, which
is the opposite of what ADR 0003 assumed; ADR 0007 records the correction.

- **Binary batched frames.** `local-agent/packet_batch.py` and
  `src/services/agentBinary.ts`, asserted against fixed vectors at both ends
  (`test_protocol.py`, `scripts/agent/binary.ts`). Agent 3.2.0. A record carries
  the bytes, the wire length, the capture time, the adapter and the sequence
  number, and nothing else - the metadata the JSON message sent was overwritten
  before it was ever displayed. 23.7 MB -> 15.4 MB and 12,858 messages -> 26 on
  the fixture (`scripts/perf/wire-size.ts`).
- **The agent no longer schedules a coroutine per frame.** Sniffer threads
  append encoded records to a bounded deque; one pump drains it in batches. The
  bound now drops the *oldest* frames rather than the newest, which is what a
  live view of traffic actually wants.
- **`src/workers/pipeline.worker.ts`** owns the socket, the ordering window, the
  trackers and dissection. The main thread never parses an agent message, never
  base64-decodes, never advances a tracker and never dissects.
- **The tree is dissected on demand**, from the recently-dissected cache or by
  replaying that frame's conversation through fresh trackers
  (`services/pipeline/replay.ts`). `scripts/pipeline/replay.ts` holds it to exact
  equality with the eager tree on real TCP, TLS, QUIC, DNS and non-stream frames.
  A replay that cannot start at the conversation's beginning says so in the tree.
- **`Packet.expert`** carries the frame's findings as a flat list, because Expert
  Information aggregates over the whole buffer and can no longer walk trees.
- **100k buffer** offered in Settings; frames pushed out of it are counted and
  shown in the drop chip beside the agent's and the driver's, worded apart
  because they are a different kind of loss.

Deviations: ADR 0003's typed-array column store was **not** built - it exists to
make the packet list cheap to render, and the list already renders from a
windowed slice; the measurement says the boundary was never the problem it was
proposed to solve. Import and session restore still dissect on the main thread,
now producing the same tree-less frames the pipeline does; moving them into the
Worker buys responsiveness during a load, not throughput, and is not what this
phase's acceptance measures.

### Phase 12 — Export and privacy

pcapng writer (SHB, one IDB per interface with `if_tsresol`, EPB with interface id,
NRB from the resolution map, ISB from capture stats), `.pcap` kept; frames sorted by
`(ts, seq)`; **Anonymise on export** (prefix-preserving IPs, vendor-preserving MACs,
strip above L4); gate `IspStatsModal`'s `ipapi.co` call behind the same name-resolution
consent as GeoJS/DoH (today it is the one ungated outbound call).

**Status: done 2026-09-04.**

- **The ungated call is gated.** `IspStatsModal` fetched `ipapi.co/json/` the moment it
  opened. Nothing from the capture was sent - the request's own source address is the
  disclosure: ipapi.co learns this machine's public IP and answers with its ISP, city
  and coordinates. It is behind the same switch as GeoJS and the DoH resolver now, and
  the panel *asks* rather than showing an empty box, because a switch buried in Settings
  is a worse consent moment than the one the user is already looking at. The switch's
  own description was rewritten to name both services, since consent text that omits one
  of them is not consent.
- **pcapng writer** (`src/services/pcapngWriter.ts`), covering what classic pcap cannot
  express: **which adapter each frame came from** (one IDB per adapter; a multi-adapter
  capture used to come out as one undifferentiated stream), **timestamps finer than a
  microsecond** (`if_tsresol` is per interface, so a nanosecond capture survives a round
  trip), **the names the capture taught us** (an NRB built from the passive resolution
  map - the file then carries its own resolution and a reader gets the same names
  without a lookup), and **what the capture missed** (an ISB with the driver's and the
  agent's drop counts; a file that does not say it is incomplete reads as complete).

  Verified against tshark rather than only against this repo's reader - a writer fed to
  its own reader proves the two agree, which is also what a matched pair of bugs looks
  like. `capinfos` on a real 1,068-frame export reports the adapter as
  `Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)` and **16 resolved addresses**
  in the file. `scripts/export/pcapng.ts` asserts the bytes - block types, the trailing
  length that lets a reader walk the file backwards, option codes, padding - against the
  format.
- **Anonymise on export** (`src/services/anonymise.ts`). What makes an anonymised
  capture *useful* rather than merely safe is that the structure survives, so: addresses
  are **prefix-preserving** (Crypto-PAn over the AES this app already ships for QUIC), so
  subnets, routing boundaries and "these twelve hosts are on the same /24" all survive;
  **MACs keep their OUI**, because the vendor half is what tells the printer from the
  phone from the access point; and everything above the transport header is **zeroed**,
  not scrambled, because no reversible transform of payload is worth defending. The key
  is random per export, so two exports of one capture cannot be lined up against each
  other.

  Measured on a real 1,068-frame capture: 39 addresses and 9 MACs rewritten, 89 KB of
  payload dropped from 608 frames. tshark on the result shows the LAN's
  10.0.0.2/.4/.5/.138 as 200.201.231.224/.225/.227/.229 - **still one /24** - with
  224.0.0.251 and 239.255.255.250 untouched (rewriting them would turn mDNS into traffic
  to a host that does not exist and hide nothing, since they are the same on every
  network), OUIs `04:7c:16` / `44:15:24` / `70:15:fb` intact with every unit half
  changed, payloads all-zero, **zero checksum errors** (the IPv4 header checksum is
  recomputed, or the whole file would read as damaged), and **no NRB** - an anonymised
  file must not carry a table mapping the addresses it just rewrote back to host names.

Frames were already sorted by capture time on export; the pcapng writer sorts the same
way and for the same reason.

### Phase 13 — End-state

SSLKEYLOGFILE import (TLS 1.2/1.3 key schedule, AES-GCM via existing sync AES;
ChaCha20-Poly1305 in JS), pcapng DSB import/export, HTTP/2 and HTTP/3 frames.

**Status: done 2026-09-04.**

- **The crypto the key schedules need.** AES generalised to 192- and 256-bit
  keys (`TLS_AES_256_GCM_SHA384` is the second most common TLS 1.3 suite and
  every AES-256 suite in 1.2); SHA-384/512 and their HMACs, because TLS 1.3
  picks its hash per cipher suite and deriving with the wrong one produces keys
  that fail silently; ChaCha20-Poly1305, which is what a phone or an ARM server
  negotiates; the TLS 1.2 PRF, which is not HKDF and shares nothing with it.
  GHASH was rewritten over 32-bit words on the way - 11 MB/s to 87 MB/s - since
  it stopped being a handful of calls per QUIC handshake and became every byte
  of every decrypted record.

  Every primitive is held to its RFC's own vectors, and the *combination* is
  held to Node's crypto: `scripts/tls/decrypt.ts` encrypts records with
  `createCipheriv` and asks the dissector to read them back, so a mistake in
  the nonce, the AAD or the key schedule shows up as a record that will not
  open. It caught one on the first run - in the test, not the dissector: the
  test shifted a sequence number with `>>`, which JavaScript takes mod 32.

- **The key log** (`services/tls/keyLog.ts`), joined to connections by the
  client random - the one value that is unique per connection and in the clear
  in every ClientHello, TLS and QUIC alike. Held in memory only and never
  persisted; `docs/decisions/0008` records why, and why decryption runs in the
  summary pass rather than on demand.

- **TLS 1.2 and 1.3 record decryption**, with the per-direction epoch and
  sequence numbering neither protocol puts on the wire. Nothing is guessed: the
  AEAD tag decides, so the decoder can try the current epoch and then the next
  one from zero and be sure a wrong guess cannot render. A suite this build
  will not decrypt (CBC, CCM) says so with the reason instead of failing
  silently. TLS 1.3's encrypted handshake opens too, so a 1.3 connection's
  certificates are shown rather than the `[Certificate: encrypted]` note that
  used to stand in for them.

- **HTTP/1.1, HTTP/2 and HTTP/3.** There was no HTTP dissector at all: a frame
  on port 80 was labelled `HTTP` from the port number over a payload nothing
  read. Now HTTP/1.1 is read in the clear and inside TLS, with the body framing
  followed (Content-Length, chunked, the HEAD rule, and Transfer-Encoding
  winning over Content-Length - the disagreement that *is* request smuggling)
  because that is what says where the next message starts. HTTP/2 comes with a
  complete HPACK decoder, dynamic table and all; HTTP/3 with QPACK's static
  table and the QUIC stream reassembly under it. `http`, `http2` and `http3`
  are real filter tokens now rather than three entries in the list of names
  this build cannot produce.

  The HPACK Huffman table is written as its 257 code *lengths* and the codes
  derived, because the lengths must satisfy Kraft's equality exactly - which no
  transcription error survives, and a table of hand-copied codes gives no such
  check.

- **QUIC beyond the Initial packets.** Handshake and 1-RTT packets decrypt from
  the same key log, with header protection in both of its constructions (AES-ECB
  on a ciphertext sample, ChaCha20 keystream) and a packet-number space of
  their own. That is what makes HTTP/3 reachable at all: a QUIC packet is
  protected header and all, so unlike TLS over TCP there is no visible framing
  to fall back on.

- **pcapng Decryption Secrets Blocks**, read and written. A file that carries
  its own secrets decrypts with nothing loaded and nothing asked of the user;
  writing one is off by default and says how many connections would travel in
  the clear with it.

Verified against a real capture rather than only against fixtures: a genuine
TLS 1.3 + HTTP/2 session with `www.cloudflare.com`, recorded with its key log.
Every one of the 160 frames tshark labels HTTP2 is labelled HTTP2 here, and all
189 of its DATA frames are found. Wireshark opens our exported pcapng and
decrypts it with no key log of its own. Cost: 1,051 frames in 173 ms without a
key log and 305 ms with one, for 1.3 MB of plaintext.

One bug found by that comparison and worth recording, because it was invisible
from the unit tests: a frame that only *continues* a TLS record produces no TLS
result, and fell through to the new cleartext-HTTP path, which handed
ciphertext to the same HTTP/2 decoder the plaintext goes to. HTTP/2 frame
boundaries stopped lining up a few kilobytes into a download - which looks
exactly like a framing bug and is not one.

---

## Part D — Verification

1. `npm run check` after every phase (36 scripts today; each phase adds ≥1).
2. `npx tsx scripts/parity/parity-check.ts` on both fixtures; per-column thresholds in
   `test/fixtures/acceptance.json` must not regress.
3. Live: agent installed from the rebuilt 3.0.0 installer; capture on this PC at
   ≥2k pkt/s (a large download) with the drop chip visible; close the only tab → agent
   `state` idle, 0 connections on port 8999, process RSS/CPU flat.
4. Browser: import each fixture in full, confirm Protocol/Info against tshark for a
   spot list of frame numbers recorded in the README.
5. Uninstall on Windows → no service, no process, no registry entry; reinstall →
   version visible in Driver Info.
