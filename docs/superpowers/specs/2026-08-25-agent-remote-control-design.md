# Agent Remote Control, Phase 1: command protocol, pairing, versioning, interface selection

## Context

The user supplied `C:\Users\Rotem\Desktop\agent-remote-control.md`, a plan
describing four goals for the local capture agent: persistent background
auto-start, remote start/stop control from the webapp, network-interface
selection, and version-mismatch detection. Reading it against the actual
code surfaced two things the plan didn't account for:

1. **"Start/Stop Capture" doesn't actually control the agent today.**
   `agent.py`'s `start_sniffer()` calls scapy's blocking `sniff()`
   unconditionally the moment the process launches, on every interface,
   with no stop mechanism. The webapp's Start/Stop buttons only gate
   whether `App.tsx`'s `ws.onmessage` (`App.tsx:184-273`) records incoming
   packets into React state (`App.tsx:185`) - the agent keeps sniffing
   regardless. This phase is what actually closes that gap, not merely an
   enhancement.
2. **`local-agent/installer/setup.iss` already exists** (Inno Setup,
   uninstaller, Start Menu entry, `netview://` URI handler) but isn't wired
   to anything - the "Download Driver" button serves the raw PyInstaller
   exe directly (`getAgentDownloadForCurrentOS`, `platformDetect.ts`), not
   this installer. The original plan's "update setup.iss for the registry
   run key" assumed it was already the live distribution path.

The four goals were also two combined security changes disguised as one
feature: adding a remote command channel, *and* removing the two things
that currently bound its risk (manual launch, visible console) by making
the agent auto-start hidden in the background. Discussed with the user and
split into two sub-projects. **This spec covers only the first.**

**In scope for this phase:**
1. A typed WebSocket command protocol (`start_capture`, `stop_capture`,
   `set_interfaces`) that actually starts/stops scapy's sniffer threads
2. A pairing/token handshake so the command channel isn't wide open to any
   page that can reach `localhost:8999`
3. Version handshake and a webapp-side mismatch indicator
4. Interface selection UI, living in the AppMenu drawer

**Explicitly out of scope for this phase** (sub-project 2, deferred):
- Hidden/no-console build (`console=False` in `netview_agent.spec`)
- Auto-start on login (`HKCU\...\Run` registry key)
- Wiring `setup.iss` up as the actual distribution path
- Any token-persistence-across-restarts strategy - this phase's token is
  regenerated fresh per manual launch and printed to the (still visible)
  console, which is only an adequate delivery mechanism *because* the
  console is visible. A hidden background agent needs a different pairing
  story, designed when that sub-project is scoped.

## Protocol

Every message over the existing `ws://localhost:8999` gets an explicit
`type` field. Today `ws.onmessage` assumes every message is a raw packet;
that assumption breaks the moment a second message shape exists, so this
is a clean break rather than a compat shim - the version handshake is
itself what catches an old agent talking to a new webapp or vice versa, so
there's no need to keep supporting untyped legacy messages.

**Agent → client, sent immediately on every new connection, before
anything else:**
```json
{"type": "hello", "version": "1.1.0", "state": "idle", "authRequired": true,
 "interfaces": [{"name": "\\Device\\NPF_{...}", "label": "Wi-Fi (Intel AX211)"}]}
```

**Client → agent:**
```json
{"type": "auth", "token": "XXXX-XXXX"}
{"type": "start_capture"}
{"type": "stop_capture"}
{"type": "set_interfaces", "interfaces": ["\\Device\\NPF_{...}", ...]}
```

**Agent → client, in response to state changes:**
```json
{"type": "state", "state": "idle" | "sniffing", "interfaces": [...]}
{"type": "error", "message": "..."}
```

**Packets** keep their current field shape but gain `"type": "packet"`, so
`App.tsx`'s handler can switch on `data.type` instead of assuming.

## Pairing

On each agent launch (console still visible in this phase - see Context),
generate a random token (`secrets.token_urlsafe`, formatted for readable
copy-paste, e.g. `XXXX-XXXX`) and print `Pairing code: XXXX-XXXX`
prominently to that console before the WebSocket server starts accepting
capture-related messages.

The agent gates **sniffing itself**, not just commands, behind a
successfully authenticated connection - this is a real improvement over
today's behavior (sniffs unconditionally the instant the process exists),
not just a formality. An unauthenticated connection still receives
`hello` (so the webapp can show "agent found, not yet paired") but any
`start_capture`/`stop_capture`/`set_interfaces` sent before a matching
`auth` message gets an `{"type":"error",...}` response and is ignored.

Frontend: on a `hello` with `authRequired: true` and no token in
`localStorage`, show a small inline prompt near the existing
Agent-status pill (`Header.tsx:149-181`) - not a full modal takeover -
asking the user to type the code shown in the agent's console window. The
accepted token is stored in `localStorage` (no other keying needed; it's
already inherently per-machine) and replayed as the first message on
every future reconnect, including the automatic 3-second retry loop
already in `App.tsx`.

This is deliberately not full auth infrastructure. It closes the gap a
naive trust-the-first-connection approach would leave open (a malicious
tab racing to be first) without adding real friction, given the console
printing the code is right there during manual launch. It is *not*
designed to survive the agent running hidden with no console - that's the
harder problem correctly left to sub-project 2.

## Agent architecture (`local-agent/agent.py`)

- Add `sniffer_stop_event = threading.Event()` alongside the existing
  `AgentServer` instance.
- `sniff_on_interface` changes from an unconditional blocking call to:
  ```python
  sniff(prn=sniff_callback, store=False, iface=iface_name,
        stop_filter=lambda pkt: sniffer_stop_event.is_set())
  ```
  scapy polls `stop_filter` after every captured packet, which is what
  makes the stop responsive without killing the thread. Interfaces with no
  traffic technically won't check the event until scapy's own read
  timeout — acceptable for this phase; a hard-timeout `sniff(timeout=1,
  ...)` wrapped in a loop is the fix if that latency turns out to matter
  in testing, not designed further here.
- Replace the current `start_sniffer()` (spawns threads once at process
  startup, joins forever) with command-driven start/stop: `start_capture`
  clears the stop event and spawns the sniffer threads for whichever
  interfaces are currently selected (default: all, matching today's
  behavior, until `set_interfaces` narrows it); `stop_capture` sets the
  event and the threads exit on their next packet or read-timeout.
- `set_interfaces` while `state == "sniffing"` stops the current threads
  and starts new ones for the new interface set, rather than silently
  no-op'ing until the next manual start - "change interfaces" should read
  as an immediate reconfiguration, not a deferred one.
- `list_interfaces()` (`agent.py:171-191`) is reused as-is for the
  `interfaces` field in `hello`.
- Token check: a plain module-level string generated in `main()` before
  `websockets.serve` starts; compared on `auth` messages with plain `==`
  (no timing-attack hardening needed - the threat model here is
  browser-reachable localhost ports, not a network attacker who can
  usefully exploit microsecond timing differences over a websocket).

## Frontend architecture

- `sendAgentCommand(type, payload?)` - a small helper near the existing
  `ws` ref in `App.tsx`'s agent-connection `useEffect`, serializing
  `{type, ...payload}` and calling `ws.send`. Needs the `ws` reference
  lifted out of the effect's local closure into a ref so it's callable
  from event handlers outside that effect (Start/Stop buttons, the new
  interface-selection UI) - currently `ws` is a plain local variable that
  only the effect itself can reach.
- `ws.onmessage` gains a `switch (data.type)` before the existing packet
  handling: `"hello"` populates `agentVersion`/`agentInterfaces`/
  `pairingRequired` state and shows the pairing prompt if needed;
  `"state"` updates a new `agentCaptureState` (idle/sniffing) separate
  from the existing `agentStatus` (connection-level: connecting/
  connected/error/disconnected) - these are orthogonal axes, not the same
  state renamed; `"error"` surfaces to console/toast; `"packet"` (or
  legacy untyped, dropped per the clean-break decision above) goes
  through the existing decode path unchanged.
- Start/Stop Capture buttons (`Header.tsx`, `FloatingToolbar.tsx`,
  `AppMenu.tsx`) call `sendAgentCommand('start_capture' | 'stop_capture')`
  in addition to their existing `setIsCapturing` local state - the local
  state still drives whether the browser *records* packets (unchanged),
  the new command additionally drives whether the agent *produces* any.
- **Version check**: a hardcoded `REQUIRED_AGENT_VERSION` constant
  compared against `hello.version`. On mismatch, the Agent-status pill
  (`Header.tsx:149-181`) gets a fourth visual state - amber "Agent
  Outdated" alongside the existing connected/connecting/error/disconnected
  - and the AppMenu's "Download Driver" item gets a small badge, reusing
  the pill's existing color-by-state pattern rather than inventing a new
  one.
- **Interface selection** lives in the AppMenu drawer (Views group,
  alongside Statistics/Custom Dissectors/Settings), not a new Header
  dropdown - consistent with this session's direction of moving actions
  out of the header rather than adding to it. A `Command.Item` opens a
  small checklist of `agentInterfaces` (from the `hello`/`state` payload)
  with checkboxes, calling `sendAgentCommand('set_interfaces', {interfaces:
  [...]})` on change.
- **Pairing prompt**: an inline banner, not a modal - appears near the
  Agent-status pill when `authRequired && !hasStoredToken`, with a single
  text input and a "Connect" button that stores the token and immediately
  sends the `auth` message.

## Files touched

| File | Change |
|---|---|
| `local-agent/agent.py` | Command protocol, pairing token, `threading.Event`-based sniffer control, `hello`/`state`/`error` messages |
| `src/App.tsx` | `sendAgentCommand`, typed `onmessage` dispatch, `agentCaptureState`/`agentVersion`/`agentInterfaces`/pairing state, `REQUIRED_AGENT_VERSION` |
| `src/components/common/Header.tsx` | Agent-status pill gains "outdated" state; pairing-prompt banner |
| `src/components/common/AppMenu.tsx` | New "Capture Interfaces" entry (Views group); Download Driver item gains update badge |
| `src/components/common/FloatingToolbar.tsx` | Start/Stop buttons also call `sendAgentCommand` |

`local-agent/netview_agent.spec`, `local-agent/bootstrap_windows.py`, and
`local-agent/installer/setup.iss` are **not** touched in this phase - all
three are sub-project 2's concern (hidden console, auto-start, real
installer wiring).

## Verification

- Unit-level: run the agent manually (`python local-agent/agent.py`),
  confirm the pairing code prints, confirm `hello` arrives before any
  packet data, confirm `start_capture`/`stop_capture` actually starts and
  stops scapy's capture (observable via the console's existing "N packets
  captured so far" logging) rather than only toggling the browser's local
  recording state as today.
- Confirm an unauthenticated `start_capture` sent before `auth` is
  rejected with an `error` message and does not start sniffing.
- Confirm `set_interfaces` sent while `state == "sniffing"` takes effect
  immediately (new interface's traffic appears, old interface's stops)
  rather than requiring a manual stop/start.
- Frontend: reload with no stored token, confirm the pairing banner
  appears and a correct code unblocks capture; confirm an incorrect code
  is rejected; confirm the stored token survives a page reload and the
  automatic reconnect loop.
- Manually lower `REQUIRED_AGENT_VERSION` below the agent's reported
  version (and above it) to exercise both directions of the mismatch
  indicator.
- `npm run lint` (`tsc --noEmit`) after the frontend changes.
