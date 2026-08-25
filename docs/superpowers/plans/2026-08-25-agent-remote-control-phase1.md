# Agent Remote Control, Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the local capture agent idle-by-default and remotely controllable over its existing WebSocket - the webapp's Start/Stop Capture buttons actually start and stop scapy sniffing (they currently don't), the connection is gated behind a printed pairing code instead of being wide open, the agent reports its version so the webapp can flag an outdated build, and the user can pick which network interface(s) to capture on from the AppMenu.

**Architecture:** The WebSocket protocol at `ws://localhost:8999` gains a `type` field on every message (`hello`, `auth`, `start_capture`, `stop_capture`, `set_interfaces`, `state`, `error`, `packet`). On the agent side, a `SnifferController` class separates *what should be sniffing* (pure state, unit-testable with a fake thread-spawn function) from *actually spawning scapy threads* (only verifiable by running the real agent). On the frontend, `src/services/agentProtocol.ts` is a new pure module (message parsing, version comparison, token storage) that `App.tsx` wires into the existing WebSocket `useEffect`.

**Tech Stack:** Python 3 (`scapy`, `websockets`) for the agent; React 19 + TypeScript on the frontend. No test framework exists in this repo on either side (confirmed: no `pytest` installed, not in `local-agent/requirements.txt`; CLAUDE.md confirms no frontend test runner is configured). This plan follows the repo's own established pattern instead - `scripts/parity/crypto-vectors.ts` is a plain assertion script run via `npx tsx`, with a `check(name, actual, expected)` helper and a failure counter. Every task below tests pure logic the same way (a runnable assertion script, Python or `tsx`), and verifies wiring/UI/real-thread behavior manually against a running agent and browser, per the spec's own Verification section.

**Spec:** `docs/superpowers/specs/2026-08-25-agent-remote-control-design.md`

## Global Constraints

- Every message over `ws://localhost:8999` must carry an explicit `type` field - this is a clean break from the old untyped packet stream (per spec: "there's no need to keep supporting untyped legacy messages").
- The agent must not start sniffing at process launch - it starts idle and only sniffs after `start_capture` is both authenticated and explicitly sent.
- `start_capture`/`stop_capture`/`set_interfaces` sent before a successful `auth` message must be rejected with `{"type":"error",...}` and must not affect sniffer state.
- No new third-party dependencies (no pytest, no vitest/jest) - use this repo's existing plain-assertion-script convention (`scripts/parity/`) for anything genuinely unit-testable.
- `local-agent/netview_agent.spec`, `local-agent/bootstrap_windows.py`, and `local-agent/installer/setup.iss` are out of scope for this phase - do not touch them.

---

## Task 1: Pairing token and hello-message pure logic

**Files:**
- Modify: `local-agent/agent.py` (add near the top, after `make_id`/`has_admin_privileges`, before `packet_to_dict` - i.e. after line 56)
- Test: `local-agent/test_protocol.py` (new)

**Interfaces:**
- Produces: `generate_pairing_token() -> str`, `build_hello_message(version: str, state: str, interfaces: list[tuple[str,str]], auth_required: bool) -> dict`

- [ ] **Step 1: Write the failing test**

Create `local-agent/test_protocol.py`:

```python
#!/usr/bin/env python3
"""
Plain-assertion tests for agent.py's pure protocol logic (no pytest in this
repo - see scripts/parity/crypto-vectors.ts for the equivalent frontend
convention this mirrors).

Run:  python local-agent/test_protocol.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent

failures = 0


def check(name, actual, expected):
    global failures
    ok = actual == expected
    if not ok:
        failures += 1
    print(f"{'PASS' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"        expected {expected!r}")
        print(f"        actual   {actual!r}")


def check_true(name, condition):
    check(name, bool(condition), True)


# --- generate_pairing_token ---
token = agent.generate_pairing_token()
check_true("pairing token matches XXXX-XXXX shape", re.fullmatch(r"[0-9A-F]{4}-[0-9A-F]{4}", token))
check_true("pairing tokens are not constant across calls", agent.generate_pairing_token() != agent.generate_pairing_token())

# --- build_hello_message ---
hello = agent.build_hello_message(
    version="1.1.0",
    state="idle",
    interfaces=[("\\Device\\NPF_{ABC}", "Wi-Fi")],
    auth_required=True,
)
check("hello type", hello["type"], "hello")
check("hello version", hello["version"], "1.1.0")
check("hello state", hello["state"], "idle")
check("hello authRequired", hello["authRequired"], True)
check("hello interfaces", hello["interfaces"], [{"name": "\\Device\\NPF_{ABC}", "label": "Wi-Fi"}])

hello_no_ifaces = agent.build_hello_message(version="1.1.0", state="sniffing", interfaces=[], auth_required=False)
check("hello with empty interfaces", hello_no_ifaces["interfaces"], [])
check("hello sniffing state", hello_no_ifaces["state"], "sniffing")

print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python local-agent/test_protocol.py`
Expected: `AttributeError: module 'agent' has no attribute 'generate_pairing_token'`

- [ ] **Step 3: Write minimal implementation**

In `local-agent/agent.py`, insert after `has_admin_privileges` (after line 56, before `def packet_to_dict(pkt):`):

```python
def generate_pairing_token() -> str:
    """A short, easy-to-type code printed to the agent's console and typed
    once into NetView to pair. Not persisted - the agent regenerates it on
    every launch, matching this phase's "still manually launched, console
    visible" scope (see spec)."""
    import secrets
    raw = secrets.token_hex(4).upper()
    return f"{raw[:4]}-{raw[4:]}"


def build_hello_message(version: str, state: str, interfaces, auth_required: bool) -> dict:
    """The first message sent on every new connection, before anything else."""
    return {
        "type": "hello",
        "version": version,
        "state": state,
        "authRequired": auth_required,
        "interfaces": [{"name": name, "label": label} for name, label in interfaces],
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python local-agent/test_protocol.py`
Expected: `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent.py local-agent/test_protocol.py
git commit -m "agent: add pairing token generation and hello message"
```

---

## Task 2: Auth gate pure logic

**Files:**
- Modify: `local-agent/agent.py` (insert directly after Task 1's additions)
- Test: `local-agent/test_protocol.py` (append)

**Interfaces:**
- Consumes: nothing from Task 1's functions directly
- Produces: `class ConnectionAuth` (constructor `ConnectionAuth(expected_token: str)`, method `try_authenticate(message: dict) -> bool`, attribute `authenticated: bool`), `GATED_COMMAND_TYPES: set[str]`, `is_command_allowed(auth: ConnectionAuth, message: dict) -> bool`

- [ ] **Step 1: Write the failing test**

Append to `local-agent/test_protocol.py` (before the final `print()` / `sys.exit` block - move that block to the very end after adding this):

```python
# --- ConnectionAuth / is_command_allowed ---
auth = agent.ConnectionAuth(expected_token="AAAA-BBBB")
check("starts unauthenticated", auth.authenticated, False)
check("wrong token rejected", auth.try_authenticate({"type": "auth", "token": "WRONG"}), False)
check("still unauthenticated after wrong token", auth.authenticated, False)
check("correct token accepted", auth.try_authenticate({"type": "auth", "token": "AAAA-BBBB"}), True)
check("authenticated after correct token", auth.authenticated, True)

check("start_capture gated when unauthenticated", agent.is_command_allowed(agent.ConnectionAuth("X"), {"type": "start_capture"}), False)
check("stop_capture gated when unauthenticated", agent.is_command_allowed(agent.ConnectionAuth("X"), {"type": "stop_capture"}), False)
check("set_interfaces gated when unauthenticated", agent.is_command_allowed(agent.ConnectionAuth("X"), {"type": "set_interfaces"}), False)

authed = agent.ConnectionAuth("X")
authed.try_authenticate({"type": "auth", "token": "X"})
check("start_capture allowed once authenticated", agent.is_command_allowed(authed, {"type": "start_capture"}), True)

check("auth message itself is not gated", agent.is_command_allowed(agent.ConnectionAuth("X"), {"type": "auth"}), True)
check("unknown message type is not gated", agent.is_command_allowed(agent.ConnectionAuth("X"), {"type": "something_else"}), True)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python local-agent/test_protocol.py`
Expected: `AttributeError: module 'agent' has no attribute 'ConnectionAuth'`

- [ ] **Step 3: Write minimal implementation**

In `local-agent/agent.py`, insert directly after Task 1's `build_hello_message` function:

```python
class ConnectionAuth:
    """Per-connection pairing state. One instance per WebSocket connection -
    pairing is not shared across connections or persisted to disk."""

    def __init__(self, expected_token: str):
        self.expected_token = expected_token
        self.authenticated = False

    def try_authenticate(self, message: dict) -> bool:
        if message.get("type") == "auth" and message.get("token") == self.expected_token:
            self.authenticated = True
            return True
        return False


GATED_COMMAND_TYPES = {"start_capture", "stop_capture", "set_interfaces"}


def is_command_allowed(auth: ConnectionAuth, message: dict) -> bool:
    """Only start_capture/stop_capture/set_interfaces require pairing - hello
    is sent unconditionally, and auth itself obviously can't require auth."""
    if message.get("type") not in GATED_COMMAND_TYPES:
        return True
    return auth.authenticated
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python local-agent/test_protocol.py`
Expected: `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent.py local-agent/test_protocol.py
git commit -m "agent: add pairing auth gate for start/stop/set_interfaces"
```

---

## Task 3: SnifferController state machine (pure orchestration)

**Files:**
- Modify: `local-agent/agent.py` (insert after `ConnectionAuth`/`is_command_allowed`, before `packet_to_dict`)
- Test: `local-agent/test_protocol.py` (append)

**Interfaces:**
- Produces: `class SnifferController` - constructor `SnifferController(default_interfaces: list[str])`; methods `is_sniffing() -> bool`, `set_interfaces(interfaces: list[str]) -> None`, `start_threads(spawn_fn) -> None`, `stop_threads() -> None`, `restart_threads(spawn_fn) -> None`, `state_message(available_interfaces: list[tuple[str,str]]) -> dict`; attribute `selected_interfaces: list[str]`. `spawn_fn` has signature `(iface_name: str, stop_event: threading.Event) -> Any` (the return value is only ever stored, never inspected by `SnifferController` itself - real callers pass a function that starts a real thread and returns it; tests pass a fake that just records the call).

- [ ] **Step 1: Write the failing test**

Append to `local-agent/test_protocol.py`:

```python
# --- SnifferController ---
class FakeSpawnCalls:
    """Records (iface_name, stop_event) calls instead of starting real threads,
    so orchestration logic is testable without scapy or real interfaces."""
    def __init__(self):
        self.calls = []

    def __call__(self, iface_name, stop_event):
        self.calls.append((iface_name, stop_event))
        return object()


sc = agent.SnifferController(default_interfaces=["eth0", "eth1"])
check("starts idle", sc.is_sniffing(), False)
check("default interfaces set", sc.selected_interfaces, ["eth0", "eth1"])

spawn = FakeSpawnCalls()
sc.start_threads(spawn)
check("sniffing after start_threads", sc.is_sniffing(), True)
check("start_threads spawns one call per selected interface", [c[0] for c in spawn.calls], ["eth0", "eth1"])
first_stop_event = spawn.calls[0][1]
check("both threads share the same stop_event", spawn.calls[1][1] is first_stop_event, True)

spawn2 = FakeSpawnCalls()
sc.start_threads(spawn2)
check("start_threads is a no-op while already sniffing", spawn2.calls, [])

sc.stop_threads()
check("idle after stop_threads", sc.is_sniffing(), False)
check("stop_threads sets the stop_event so old threads notice", first_stop_event.is_set(), True)

spawn3 = FakeSpawnCalls()
sc.stop_threads()
check("stop_threads is a no-op while already idle", sc.is_sniffing(), False)

sc.set_interfaces(["eth2"])
check("set_interfaces updates selected_interfaces", sc.selected_interfaces, ["eth2"])

sc.start_threads(spawn3)
check("start_threads after set_interfaces uses the new list", [c[0] for c in spawn3.calls], ["eth2"])
second_stop_event = spawn3.calls[0][1]

spawn4 = FakeSpawnCalls()
sc.set_interfaces(["eth3", "eth4"])
sc.restart_threads(spawn4)
check("restart_threads stops the old stop_event", second_stop_event.is_set(), True)
check("restart_threads starts threads for the new interface set", [c[0] for c in spawn4.calls], ["eth3", "eth4"])
check("restart_threads leaves the controller sniffing", sc.is_sniffing(), True)

sc.stop_threads()
spawn5 = FakeSpawnCalls()
sc.restart_threads(spawn5)
check("restart_threads while already idle stays idle (no spurious start)", sc.is_sniffing(), False)
check("restart_threads while idle does not spawn anything", spawn5.calls, [])

idle_msg = agent.SnifferController(default_interfaces=[]).state_message([("eth0", "Ethernet")])
check("state_message type", idle_msg["type"], "state")
check("state_message idle state", idle_msg["state"], "idle")
check("state_message reports available interfaces regardless of selection", idle_msg["interfaces"], [{"name": "eth0", "label": "Ethernet"}])

sc_sniffing = agent.SnifferController(default_interfaces=["eth0"])
sc_sniffing.start_threads(FakeSpawnCalls())
sniffing_msg = sc_sniffing.state_message([("eth0", "Ethernet")])
check("state_message sniffing state", sniffing_msg["state"], "sniffing")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python local-agent/test_protocol.py`
Expected: `AttributeError: module 'agent' has no attribute 'SnifferController'`

- [ ] **Step 3: Write minimal implementation**

In `local-agent/agent.py`, insert directly after `is_command_allowed` (still before `packet_to_dict`). Requires `threading`, already imported at the top of the file (line 21):

```python
class SnifferController:
    """Tracks whether the agent should be sniffing and on which interfaces,
    independent of the actual scapy/thread machinery. Thread creation is
    injected via spawn_fn(iface_name, stop_event) so this orchestration logic
    - start/stop/reconfigure - is unit-testable with a fake spawn_fn and no
    real interfaces or scapy involved. The real spawn_fn (wired up in main())
    starts a daemon thread running sniff_on_interface.

    A fresh threading.Event is created on every start_threads/restart_threads
    call rather than reusing one persistent Event: a still-exiting thread from
    a previous stop keeps checking the Event object it was given, so clearing
    and reusing one Event could make that lingering thread think a *new*
    session told it to keep going.
    """

    def __init__(self, default_interfaces):
        self.selected_interfaces = list(default_interfaces)
        self._sniffing = False
        self.stop_event = threading.Event()

    def is_sniffing(self) -> bool:
        return self._sniffing

    def set_interfaces(self, interfaces) -> None:
        self.selected_interfaces = list(interfaces)

    def start_threads(self, spawn_fn) -> None:
        if self._sniffing:
            return
        self.stop_event = threading.Event()
        for name in self.selected_interfaces:
            spawn_fn(name, self.stop_event)
        self._sniffing = True

    def stop_threads(self) -> None:
        if not self._sniffing:
            return
        self.stop_event.set()
        self._sniffing = False

    def restart_threads(self, spawn_fn) -> None:
        was_sniffing = self._sniffing
        self.stop_threads()
        if was_sniffing:
            self.start_threads(spawn_fn)

    def state_message(self, available_interfaces) -> dict:
        return {
            "type": "state",
            "state": "sniffing" if self._sniffing else "idle",
            "interfaces": [{"name": name, "label": label} for name, label in available_interfaces],
        }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python local-agent/test_protocol.py`
Expected: `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent.py local-agent/test_protocol.py
git commit -m "agent: add SnifferController state machine"
```

---

## Task 4: Wire pairing, commands, and SnifferController into the real agent

**Files:**
- Modify: `local-agent/agent.py:36-37` (add `AGENT_VERSION`), `:59-112` (`packet_to_dict`, tag its return with `"type": "packet"`), `:115-144` (`AgentServer.register`/`broadcast`), `:148` (remove `sniffer_error`), `:194-248` (`sniff_on_interface`, replace `start_sniffer`), `:251-268` (`main`)
- Test: `local-agent/verify_protocol.py` (new) - a real end-to-end smoke test against a running agent, since thread/scapy/websocket wiring can't be meaningfully unit-tested

**Interfaces:**
- Consumes: `generate_pairing_token`, `build_hello_message`, `ConnectionAuth`, `is_command_allowed`, `SnifferController` (Tasks 1-3)
- Produces: module-level `AGENT_VERSION: str`, `AVAILABLE_INTERFACES: list[tuple[str,str]]`, `PAIRING_TOKEN: str`, `sniffer: SnifferController`; `spawn_sniffer_thread(iface_name: str, stop_event: threading.Event) -> threading.Thread`; `packet_to_dict(pkt)`'s returned dict now includes `"type": "packet"`

- [ ] **Step 1: Add `AGENT_VERSION` constant**

In `local-agent/agent.py`, change lines 36-37 from:

```python
HOST = "localhost"
PORT = 8999
```

to:

```python
HOST = "localhost"
PORT = 8999
AGENT_VERSION = "1.1.0"
```

- [ ] **Step 2: Tag every packet message with `"type": "packet"`**

Every other message the agent sends now carries an explicit `type` (Global Constraints); packets are the one message shape that predates this plan, so `packet_to_dict`'s return needs the same tag or `parseAgentMessage` (Task 5) silently drops every captured packet - it wouldn't recognize an untyped message as anything, by design (the spec's "clean break", not a bug to work around).

In `local-agent/agent.py`, change the `return { ... }` at the end of `packet_to_dict` (currently lines 101-112) from:

```python
    return {
        "id": make_id(),
        "timestamp": int(time.time() * 1000),
        "source": source,
        "destination": destination,
        "protocol": proto,
        "sourcePort": sport,
        "destPort": dport,
        "length": len(pkt),
        "info": f"{proto} Traffic",
        "raw": base64.b64encode(bytes(pkt)).decode('ascii'),
    }
```

to:

```python
    return {
        "type": "packet",
        "id": make_id(),
        "timestamp": int(time.time() * 1000),
        "source": source,
        "destination": destination,
        "protocol": proto,
        "sourcePort": sport,
        "destPort": dport,
        "length": len(pkt),
        "info": f"{proto} Traffic",
        "raw": base64.b64encode(bytes(pkt)).decode('ascii'),
    }
```

- [ ] **Step 3: Update `sniff_on_interface` to accept a stop_event**

Replace lines 194-203 (current `sniff_on_interface`):

```python
def sniff_on_interface(iface_name, iface_label):
    try:
        # No BPF filter: capture every frame on the wire, the way Wireshark
        # does by default. This used to be "ip or ip6", which silently
        # discarded ARP, STP and every other non-IP protocol before they
        # could reach the browser - the frontend dissects all of them.
        # store=False keeps memory flat during long-running captures.
        sniff(prn=sniff_callback, store=False, iface=iface_name)
    except Exception as exc:  # e.g. an adapter that's disabled/down, or Npcap missing on Windows
        print(f"[agent] WARNING: capture failed on interface {iface_label!r} ({iface_name}): {exc}", file=sys.stderr)
```

with:

```python
def sniff_on_interface(iface_name, iface_label, stop_event):
    try:
        # No BPF filter: capture every frame on the wire, the way Wireshark
        # does by default. This used to be "ip or ip6", which silently
        # discarded ARP, STP and every other non-IP protocol before they
        # could reach the browser - the frontend dissects all of them.
        # store=False keeps memory flat during long-running captures.
        # stop_filter is checked after every captured packet (or scapy's own
        # read timeout on a quiet interface) - that's what makes stop_capture
        # actually stop the thread instead of blocking forever.
        sniff(prn=sniff_callback, store=False, iface=iface_name,
              stop_filter=lambda pkt: stop_event.is_set())
    except Exception as exc:  # e.g. an adapter that's disabled/down, or Npcap missing on Windows
        print(f"[agent] WARNING: capture failed on interface {iface_label!r} ({iface_name}): {exc}", file=sys.stderr)
```

- [ ] **Step 4: Remove `start_sniffer` and `sniffer_error`, add `spawn_sniffer_thread`**

Delete line 148 (`sniffer_error = None`) entirely - it was only ever set, never read, and the new error path is the `{"type":"error",...}` WebSocket message instead.

Delete lines 206-248 (the entire old `start_sniffer` function, including the `NETVIEW_IFACE` env var handling - runtime interface selection now happens via the `set_interfaces` command instead).

In its place, add:

```python
def spawn_sniffer_thread(iface_name, stop_event):
    label = INTERFACE_LABELS.get(iface_name, iface_name)
    t = threading.Thread(target=sniff_on_interface, args=(iface_name, label, stop_event), daemon=True)
    t.start()
    return t
```

- [ ] **Step 5: Rewrite `AgentServer.register` to send hello and handle incoming commands**

Replace lines 115-144 (the whole `AgentServer` class body from `register` through `_send_all`) with:

```python
class AgentServer:
    def __init__(self):
        self.clients = set()
        self.loop = None

    async def register(self, ws):
        self.clients.add(ws)
        print(f"[agent] client connected ({len(self.clients)} total)")
        auth = ConnectionAuth(PAIRING_TOKEN)
        state = "sniffing" if sniffer.is_sniffing() else "idle"
        await ws.send(json.dumps(build_hello_message(AGENT_VERSION, state, AVAILABLE_INTERFACES, auth_required=True)))
        try:
            async for raw in ws:
                await self._handle_message(ws, auth, raw)
        finally:
            self.clients.discard(ws)
            print(f"[agent] client disconnected ({len(self.clients)} total)")

    async def _handle_message(self, ws, auth, raw):
        try:
            message = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(message, dict):
            return

        if message.get("type") == "auth":
            if auth.try_authenticate(message):
                print("[agent] client authenticated")
            else:
                # Explicit rejection, not silence - the frontend needs this to
                # tell "stale token from a previous agent launch" apart from
                # "no response yet", otherwise a wrong/outdated stored token
                # just looks like nothing happened and the pairing banner
                # never comes back (see Task 12 Step 6).
                await ws.send(json.dumps({"type": "error", "message": "Invalid pairing code."}))
            return

        if not is_command_allowed(auth, message):
            await ws.send(json.dumps({"type": "error", "message": "Not authenticated. Enter the pairing code shown in the agent console."}))
            return

        msg_type = message.get("type")
        if msg_type == "start_capture":
            sniffer.start_threads(spawn_sniffer_thread)
        elif msg_type == "stop_capture":
            sniffer.stop_threads()
        elif msg_type == "set_interfaces":
            interfaces = message.get("interfaces")
            if isinstance(interfaces, list) and all(isinstance(i, str) for i in interfaces):
                sniffer.set_interfaces(interfaces)
                sniffer.restart_threads(spawn_sniffer_thread)
        else:
            return

        self.broadcast(sniffer.state_message(AVAILABLE_INTERFACES))

    def broadcast(self, message: dict):
        """Called from the sniffer thread (packet_to_dict results) as well as
        from _handle_message above - hop back onto the asyncio loop either way."""
        if not self.clients or self.loop is None:
            return
        data = json.dumps(message)
        asyncio.run_coroutine_threadsafe(self._send_all(data), self.loop)

    async def _send_all(self, data: str):
        dead = []
        for ws in self.clients:
            try:
                await ws.send(data)
            except websockets.ConnectionClosed:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)
```

This keeps `broadcast`/`_send_all` exactly as they were (still used by `sniff_callback` to push captured packets) and adds the new `register`/`_handle_message` on top.

- [ ] **Step 6: Rewrite `main()` to start idle and print the pairing code**

Replace lines 251-268 (current `main`, minus the trailing `if __name__ == "__main__":` block which stays as-is):

```python
async def main():
    global AVAILABLE_INTERFACES, INTERFACE_LABELS, sniffer, PAIRING_TOKEN

    if not has_admin_privileges():
        hint = (
            "Right-click and choose 'Run as administrator'."
            if os.name == "nt"
            else "Re-run with sudo, e.g.: sudo python3 agent.py"
        )
        print(f"ERROR: Packet capture requires elevated privileges.\n{hint}", file=sys.stderr)
        sys.exit(1)

    try:
        AVAILABLE_INTERFACES = list_interfaces()
    except Exception as exc:
        print(f"[agent] ERROR: could not enumerate network interfaces: {exc}", file=sys.stderr)
        sys.exit(1)
    INTERFACE_LABELS = dict(AVAILABLE_INTERFACES)

    print(f"[agent] detected {len(AVAILABLE_INTERFACES)} network interface(s):", file=sys.stderr)
    for name, label in AVAILABLE_INTERFACES:
        print(f"[agent]   {label} -> {name}", file=sys.stderr)

    # Starts idle on purpose - sniffing now only begins when a paired client
    # sends start_capture, not automatically at process launch.
    sniffer = SnifferController(default_interfaces=[name for name, _ in AVAILABLE_INTERFACES])

    PAIRING_TOKEN = generate_pairing_token()
    print(f"[agent] Pairing code: {PAIRING_TOKEN}", file=sys.stderr)
    print("[agent] Enter this code in NetView to connect.", file=sys.stderr)

    agent.loop = asyncio.get_running_loop()

    async with websockets.serve(agent.register, HOST, PORT):
        print(f"[agent] WebSocket server listening on ws://{HOST}:{PORT}")
        await asyncio.Future()  # run forever
```

- [ ] **Step 7: Run the unit tests from Tasks 1-3 to make sure nothing broke**

Run: `python local-agent/test_protocol.py`
Expected: `All checks passed.`

- [ ] **Step 8: Write the end-to-end smoke test**

Create `local-agent/verify_protocol.py`:

```python
#!/usr/bin/env python3
"""
End-to-end smoke test against a REAL running agent - not a unit test, since
this exercises the actual WebSocket/thread/scapy wiring that test_protocol.py
deliberately fakes out.

Start the agent first (as Administrator), note the printed pairing code, then:
  python local-agent/verify_protocol.py <pairing-code>
"""
import asyncio
import json
import sys

import websockets

AGENT_URL = "ws://localhost:8999"


async def recv_json(ws, timeout=3):
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    return json.loads(raw)


async def main():
    if len(sys.argv) != 2:
        print("Usage: python local-agent/verify_protocol.py <pairing-code>")
        sys.exit(1)
    token = sys.argv[1]

    failures = 0

    def check(name, condition):
        nonlocal failures
        ok = bool(condition)
        if not ok:
            failures += 1
        print(f"{'PASS' if ok else 'FAIL'}  {name}")

    async with websockets.connect(AGENT_URL) as ws:
        hello = await recv_json(ws)
        check("hello type", hello.get("type") == "hello")
        check("hello reports idle at connect", hello.get("state") == "idle")
        check("hello requires auth", hello.get("authRequired") is True)
        check("hello lists at least one interface", len(hello.get("interfaces", [])) > 0)

        await ws.send(json.dumps({"type": "start_capture"}))
        try:
            reply = await recv_json(ws, timeout=2)
            check("start_capture before auth is rejected", reply.get("type") == "error")
        except asyncio.TimeoutError:
            check("start_capture before auth is rejected", False)

        await ws.send(json.dumps({"type": "auth", "token": "WRONG-TOKEN"}))
        wrong_auth_reply = await recv_json(ws)
        check("wrong pairing code is rejected with an error", wrong_auth_reply.get("type") == "error")

        await ws.send(json.dumps({"type": "auth", "token": token}))
        await ws.send(json.dumps({"type": "start_capture"}))
        state = await recv_json(ws)
        check("state after start_capture", state.get("type") == "state")
        check("state is sniffing after start_capture", state.get("state") == "sniffing")

        await ws.send(json.dumps({"type": "stop_capture"}))
        state2 = await recv_json(ws)
        check("state is idle after stop_capture", state2.get("state") == "idle")

    print()
    if failures:
        print(f"{failures} check(s) FAILED")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    asyncio.run(main())
```

- [ ] **Step 9: Run the smoke test against a real agent to verify it passes**

In one terminal (as Administrator): `python local-agent/agent.py` - note the printed `Pairing code: XXXX-XXXX`.
In another terminal: `python local-agent/verify_protocol.py XXXX-XXXX`
Expected: `All checks passed.` - and the agent's own console should print "client authenticated" and show packet-count logging (`[agent] N packets captured so far`) starting shortly after `start_capture`, stopping incrementing after `stop_capture`.

- [ ] **Step 10: Commit**

```bash
git add local-agent/agent.py local-agent/verify_protocol.py
git commit -m "agent: idle-by-default with pairing, command handling, and real start/stop"
```

---

## Task 5: Frontend protocol module - message parsing

**Files:**
- Create: `src/services/agentProtocol.ts`
- Test: `scripts/agent-protocol/message-parsing.ts` (new)

**Interfaces:**
- Produces:
  ```typescript
  export interface AgentHelloMessage { type: 'hello'; version: string; state: 'idle' | 'sniffing'; authRequired: boolean; interfaces: { name: string; label: string }[]; }
  export interface AgentStateMessage { type: 'state'; state: 'idle' | 'sniffing'; interfaces: { name: string; label: string }[]; }
  export interface AgentErrorMessage { type: 'error'; message: string; }
  export interface AgentPacketMessage { type: 'packet'; [key: string]: unknown; }
  export type AgentMessage = AgentHelloMessage | AgentStateMessage | AgentErrorMessage | AgentPacketMessage;
  export function parseAgentMessage(raw: string): AgentMessage | null;
  ```

- [ ] **Step 1: Write the failing test**

Create `scripts/agent-protocol/message-parsing.ts`:

```typescript
/**
 * Assertion tests for agentProtocol.ts's pure message parsing.
 *
 *   npx tsx scripts/agent-protocol/message-parsing.ts
 */
import { parseAgentMessage } from '../../src/services/agentProtocol';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

check('malformed JSON returns null', parseAgentMessage('{not json'), null);
check('non-object JSON returns null', parseAgentMessage('42'), null);
check('unknown type returns null', parseAgentMessage('{"type":"mystery"}'), null);
check('missing type returns null (legacy untyped packet is dropped, per spec)', parseAgentMessage('{"source":"1.2.3.4"}'), null);

const hello = parseAgentMessage('{"type":"hello","version":"1.1.0","state":"idle","authRequired":true,"interfaces":[{"name":"eth0","label":"Ethernet"}]}');
check('valid hello parses', hello, { type: 'hello', version: '1.1.0', state: 'idle', authRequired: true, interfaces: [{ name: 'eth0', label: 'Ethernet' }] });
check('hello missing version returns null', parseAgentMessage('{"type":"hello","state":"idle","interfaces":[]}'), null);
check('hello missing interfaces returns null', parseAgentMessage('{"type":"hello","version":"1.0.0"}'), null);

const state = parseAgentMessage('{"type":"state","state":"sniffing","interfaces":[]}');
check('valid state parses', state, { type: 'state', state: 'sniffing', interfaces: [] });
check('state missing state field returns null', parseAgentMessage('{"type":"state","interfaces":[]}'), null);

const err = parseAgentMessage('{"type":"error","message":"nope"}');
check('valid error parses', err, { type: 'error', message: 'nope' });
check('error missing message returns null', parseAgentMessage('{"type":"error"}'), null);

const pkt = parseAgentMessage('{"type":"packet","source":"1.2.3.4","destination":"5.6.7.8"}');
check('packet passes through with all its fields', pkt, { type: 'packet', source: '1.2.3.4', destination: '5.6.7.8' });

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx scripts/agent-protocol/message-parsing.ts`
Expected: fails to even start - `Cannot find module '../../src/services/agentProtocol'`

- [ ] **Step 3: Write minimal implementation**

Create `src/services/agentProtocol.ts`:

```typescript
/**
 * The typed WebSocket protocol spoken with the local capture agent
 * (ws://localhost:8999) - message parsing, version comparison, and pairing
 * token storage. Kept dependency-free and pure so it's testable without a
 * real WebSocket (see scripts/agent-protocol/).
 */

export interface AgentHelloMessage {
  type: 'hello';
  version: string;
  state: 'idle' | 'sniffing';
  authRequired: boolean;
  interfaces: { name: string; label: string }[];
}

export interface AgentStateMessage {
  type: 'state';
  state: 'idle' | 'sniffing';
  interfaces: { name: string; label: string }[];
}

export interface AgentErrorMessage {
  type: 'error';
  message: string;
}

export interface AgentPacketMessage {
  type: 'packet';
  [key: string]: unknown;
}

export type AgentMessage = AgentHelloMessage | AgentStateMessage | AgentErrorMessage | AgentPacketMessage;

/**
 * Every agent message carries a `type` now - a clean break from the old
 * untyped packet-only stream (see spec: "there's no need to keep supporting
 * untyped legacy messages"). Anything that doesn't parse as one of the four
 * known shapes - including the old shape with no `type` at all - returns
 * null rather than throwing, so a single malformed message can't take down
 * the WebSocket handler.
 */
export function parseAgentMessage(raw: string): AgentMessage | null {
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!data || typeof data !== 'object') return null;
  const msg = data as Record<string, unknown>;

  switch (msg.type) {
    case 'hello':
      if (typeof msg.version !== 'string' || !Array.isArray(msg.interfaces)) return null;
      return msg as unknown as AgentHelloMessage;
    case 'state':
      if (typeof msg.state !== 'string' || !Array.isArray(msg.interfaces)) return null;
      return msg as unknown as AgentStateMessage;
    case 'error':
      if (typeof msg.message !== 'string') return null;
      return msg as unknown as AgentErrorMessage;
    case 'packet':
      return msg as unknown as AgentPacketMessage;
    default:
      return null;
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx scripts/agent-protocol/message-parsing.ts`
Expected: `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add src/services/agentProtocol.ts scripts/agent-protocol/message-parsing.ts
git commit -m "frontend: add typed agent message parsing"
```

---

## Task 6: Version comparison and command encoding

**Files:**
- Modify: `src/services/agentProtocol.ts` (append)
- Test: `scripts/agent-protocol/version-and-commands.ts` (new)

**Interfaces:**
- Consumes: nothing new from Task 5's types
- Produces:
  ```typescript
  export type AgentCommand =
    | { type: 'auth'; token: string }
    | { type: 'start_capture' }
    | { type: 'stop_capture' }
    | { type: 'set_interfaces'; interfaces: string[] };
  export function encodeAgentCommand(command: AgentCommand): string;
  export function isAgentOutdated(reportedVersion: string, requiredVersion: string): boolean;
  export const REQUIRED_AGENT_VERSION: string;
  ```

- [ ] **Step 1: Write the failing test**

Create `scripts/agent-protocol/version-and-commands.ts`:

```typescript
/**
 * Assertion tests for agentProtocol.ts's version comparison and command
 * encoding.
 *
 *   npx tsx scripts/agent-protocol/version-and-commands.ts
 */
import { encodeAgentCommand, isAgentOutdated } from '../../src/services/agentProtocol';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${expected}`);
    console.log(`        actual   ${actual}`);
  }
}

check('exact match is not outdated', isAgentOutdated('1.1.0', '1.1.0'), false);
check('lower patch is outdated', isAgentOutdated('1.1.0', '1.1.1'), true);
check('lower minor is outdated', isAgentOutdated('1.1.0', '1.2.0'), true);
check('lower major is outdated', isAgentOutdated('1.1.0', '2.0.0'), true);
check('higher patch is not outdated', isAgentOutdated('1.1.5', '1.1.0'), false);
check('minor beats patch: 1.9.9 vs 1.10.0 is outdated', isAgentOutdated('1.9.9', '1.10.0'), true);
check('minor beats patch: 1.10.0 vs 1.9.9 is not outdated', isAgentOutdated('1.10.0', '1.9.9'), false);

check('auth command encodes', encodeAgentCommand({ type: 'auth', token: 'ABCD-1234' }), '{"type":"auth","token":"ABCD-1234"}');
check('start_capture encodes', encodeAgentCommand({ type: 'start_capture' }), '{"type":"start_capture"}');
check('stop_capture encodes', encodeAgentCommand({ type: 'stop_capture' }), '{"type":"stop_capture"}');
check('set_interfaces encodes', encodeAgentCommand({ type: 'set_interfaces', interfaces: ['eth0', 'eth1'] }), '{"type":"set_interfaces","interfaces":["eth0","eth1"]}');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx scripts/agent-protocol/version-and-commands.ts`
Expected: `SyntaxError` / `does not provide an export named 'encodeAgentCommand'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/services/agentProtocol.ts`:

```typescript
/**
 * Bumped alongside AGENT_VERSION in local-agent/agent.py. Compared against
 * whatever the connected agent reports in its hello message to flag a
 * stale build in the UI.
 */
export const REQUIRED_AGENT_VERSION = '1.1.0';

/**
 * Simple major.minor.patch comparison - good enough for this agent's
 * versioning (no pre-release tags, no build metadata). Plain string
 * inequality would get "1.9.9" vs "1.10.0" backwards, which is why this
 * parses each segment as a number instead.
 */
export function isAgentOutdated(reportedVersion: string, requiredVersion: string): boolean {
  const parse = (v: string) => v.split('.').map((n) => parseInt(n, 10) || 0);
  const [rMajor, rMinor, rPatch] = parse(reportedVersion);
  const [qMajor, qMinor, qPatch] = parse(requiredVersion);
  if (rMajor !== qMajor) return rMajor < qMajor;
  if (rMinor !== qMinor) return rMinor < qMinor;
  return rPatch < qPatch;
}

export type AgentCommand =
  | { type: 'auth'; token: string }
  | { type: 'start_capture' }
  | { type: 'stop_capture' }
  | { type: 'set_interfaces'; interfaces: string[] };

export function encodeAgentCommand(command: AgentCommand): string {
  return JSON.stringify(command);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx scripts/agent-protocol/version-and-commands.ts`
Expected: `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add src/services/agentProtocol.ts scripts/agent-protocol/version-and-commands.ts
git commit -m "frontend: add agent version comparison and command encoding"
```

---

## Task 7: Pairing token storage

**Files:**
- Modify: `src/services/agentProtocol.ts` (append)
- Test: `scripts/agent-protocol/token-storage.ts` (new)

**Interfaces:**
- Produces: `getStoredPairingToken(): string | null`, `storePairingToken(token: string): void`, `clearStoredPairingToken(): void`

- [ ] **Step 1: Write the failing test**

Create `scripts/agent-protocol/token-storage.ts`:

```typescript
/**
 * Assertion tests for agentProtocol.ts's pairing token storage, against an
 * in-memory localStorage stand-in (this runs under plain Node via tsx, which
 * has no DOM/localStorage of its own).
 *
 *   npx tsx scripts/agent-protocol/token-storage.ts
 */
class MemoryStorage {
  private store = new Map<string, string>();
  getItem(key: string) { return this.store.has(key) ? this.store.get(key)! : null; }
  setItem(key: string, value: string) { this.store.set(key, value); }
  removeItem(key: string) { this.store.delete(key); }
}
(globalThis as any).localStorage = new MemoryStorage();

const { getStoredPairingToken, storePairingToken, clearStoredPairingToken } = await import('../../src/services/agentProtocol');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${expected}`);
    console.log(`        actual   ${actual}`);
  }
}

check('no token stored initially', getStoredPairingToken(), null);
storePairingToken('ABCD-1234');
check('stored token is retrievable', getStoredPairingToken(), 'ABCD-1234');
storePairingToken('WXYZ-5678');
check('storing again overwrites', getStoredPairingToken(), 'WXYZ-5678');
clearStoredPairingToken();
check('cleared token is gone', getStoredPairingToken(), null);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npx tsx scripts/agent-protocol/token-storage.ts`
Expected: `does not provide an export named 'getStoredPairingToken'`

- [ ] **Step 3: Write minimal implementation**

Append to `src/services/agentProtocol.ts`:

```typescript
const PAIRING_TOKEN_STORAGE_KEY = 'netview.agentPairingToken';

export function getStoredPairingToken(): string | null {
  return localStorage.getItem(PAIRING_TOKEN_STORAGE_KEY);
}

export function storePairingToken(token: string): void {
  localStorage.setItem(PAIRING_TOKEN_STORAGE_KEY, token);
}

export function clearStoredPairingToken(): void {
  localStorage.removeItem(PAIRING_TOKEN_STORAGE_KEY);
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `npx tsx scripts/agent-protocol/token-storage.ts`
Expected: `All checks passed.`

- [ ] **Step 5: Run the full type-check to confirm agentProtocol.ts is otherwise sound**

Run: `npm run lint`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
git add src/services/agentProtocol.ts scripts/agent-protocol/token-storage.ts
git commit -m "frontend: add pairing token storage"
```

---

## Task 8: Wire agentProtocol into App.tsx's WebSocket handling

**Files:**
- Modify: `src/App.tsx` (the agent-connection `useEffect`, currently `App.tsx:156-301` per the last full read of this file - re-locate by searching for `ws = new WebSocket("ws://localhost:8999")` since line numbers may have drifted since)

**Interfaces:**
- Consumes: `parseAgentMessage`, `AgentMessage`, `encodeAgentCommand`, `AgentCommand`, `isAgentOutdated`, `REQUIRED_AGENT_VERSION`, `getStoredPairingToken`, `storePairingToken`, `clearStoredPairingToken` (Tasks 5-7)
- Produces: new App.tsx state `agentCaptureState: 'idle' | 'sniffing'`, `agentVersion: string | null`, `agentOutdated: boolean`, `agentInterfaces: {name:string; label:string}[]`, `pairingRequired: boolean`; new function `sendAgentCommand(command: AgentCommand): void` (passed down through `Header`/`AppMenu`/`FloatingToolbar` props in Tasks 9-11)

- [ ] **Step 1: Add the new state and a ws ref**

In `src/App.tsx`, near the existing `const [agentStatus, setAgentStatus] = useState<...>(...)` declaration, add:

```typescript
  const [agentCaptureState, setAgentCaptureState] = useState<'idle' | 'sniffing'>('idle');
  const [agentVersion, setAgentVersion] = useState<string | null>(null);
  const [agentInterfaces, setAgentInterfaces] = useState<{ name: string; label: string }[]>([]);
  const [pairingRequired, setPairingRequired] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
```

Add the import at the top of the file, alongside the other `services/` imports:

```typescript
import { parseAgentMessage, encodeAgentCommand, isAgentOutdated, REQUIRED_AGENT_VERSION, getStoredPairingToken, storePairingToken, clearStoredPairingToken, type AgentCommand } from './services/agentProtocol';
```

`agentOutdated` doesn't need its own state - it's derived: add near the other derived values (e.g. next to `bufferPercent`/`filteredPackets` computations, whichever this file already uses that pattern for): `const agentOutdated = agentVersion !== null && isAgentOutdated(agentVersion, REQUIRED_AGENT_VERSION);`

- [ ] **Step 2: Replace the `let ws: WebSocket | null = null;` local with the ref, and set it in `connect()`**

Find `let ws: WebSocket | null = null;` inside the agent-connection `useEffect` and delete it - the ref declared in Step 1 replaces it. Every remaining `ws = new WebSocket(...)`, `ws.onopen`, `ws.onmessage`, etc. inside that effect becomes `wsRef.current = new WebSocket(...)`, `wsRef.current.onopen`, `wsRef.current.onmessage`, etc. The cleanup function's `if (ws) { ws.onclose = null; ws.close(); }` becomes `if (wsRef.current) { wsRef.current.onclose = null; wsRef.current.close(); }`.

- [ ] **Step 3: Add `sendAgentCommand`, sending the stored pairing token immediately on connect if present**

In `ws.onopen` (now `wsRef.current.onopen`), after the existing `console.log("[WirePulse] Connected to Local Agent");` line, add:

```typescript
        const storedToken = getStoredPairingToken();
        if (storedToken) {
          wsRef.current?.send(encodeAgentCommand({ type: 'auth', token: storedToken }));
        }
```

Add `sendAgentCommand` as a plain function in the component body (not inside the effect, so Header/AppMenu/FloatingToolbar can call it):

```typescript
  const sendAgentCommand = (command: AgentCommand) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(encodeAgentCommand(command));
    }
  };
```

- [ ] **Step 4: Replace the start of `ws.onmessage` with typed dispatch**

The existing `ws.onmessage = (event) => { if (!isCapturingRef.current) return; try { const rawPkt = JSON.parse(event.data); ... } catch (err) { ... } };` becomes:

```typescript
      wsRef.current.onmessage = (event) => {
        const message = parseAgentMessage(event.data);
        if (!message) return;

        if (message.type === 'hello') {
          setAgentVersion(message.version);
          setAgentCaptureState(message.state);
          setAgentInterfaces(message.interfaces);
          setPairingRequired(message.authRequired && !getStoredPairingToken());
          return;
        }

        if (message.type === 'state') {
          setAgentCaptureState(message.state);
          setAgentInterfaces(message.interfaces);
          return;
        }

        if (message.type === 'error') {
          console.warn('[WirePulse] Agent error:', message.message);
          // The only error the agent currently sends is an auth rejection
          // (wrong or stale token - e.g. the agent restarted and generated a
          // new pairing code since this token was stored). Clearing it and
          // re-showing the prompt is what makes Task 12's reconnect
          // walkthrough actually work, instead of the banner just never
          // coming back because a token *was* stored, even though it no
          // longer matches.
          clearStoredPairingToken();
          setPairingRequired(true);
          return;
        }

        // message.type === 'packet' from here on - the existing decode path.
        if (!isCapturingRef.current) return; // agent detected, but capture not started yet

        try {
          const rawPkt = message;
          const epochMs = typeof rawPkt.timestamp === 'number' ? rawPkt.timestamp : Date.now();
          // ... (rest of the existing packet-decoding body is unchanged - only
          // the JSON.parse(event.data) at the top and the surrounding
          // try/catch are removed, since parseAgentMessage already parsed
          // and validated the shape)
```

Concretely: delete the old `const rawPkt = JSON.parse(event.data); if (!rawPkt || typeof rawPkt !== 'object') return;` two lines (parsing now happens once in `parseAgentMessage` above, shared by every message type) and keep everything from `const epochMs = ...` down to the end of the existing packet-handling `try` block exactly as it is today, just re-indented one level deeper inside the new `if (message.type === 'hello') ... if (message.type === 'state') ... if (message.type === 'error') ...` chain. The outer `catch (err) { console.warn(...) }` stays, closing the same `try` block.

- [ ] **Step 5: Run the type-check**

Run: `npm run lint`
Expected: no errors. (This step is the closest thing to a test for this task - it's pure wiring into an existing effect, not new pure logic, so it's verified by type-checking now and by the full agent+browser walkthrough in Task 12.)

- [ ] **Step 6: Commit**

```bash
git add src/App.tsx
git commit -m "frontend: wire typed agent protocol into the WebSocket connection"
```

---

## Task 9: Agent-status pill gains an "outdated" state; pairing banner

**Files:**
- Modify: `src/components/common/Header.tsx` (the agent-status pill, `Header.tsx:149-181` per the last full read - re-locate if drifted)

**Interfaces:**
- Consumes: new `HeaderProps` fields `agentOutdated: boolean`, `pairingRequired: boolean`, `onSubmitPairingToken: (token: string) => void` (passed from `App.tsx`, wiring `storePairingToken` + `sendAgentCommand({type:'auth', token})` + clearing `pairingRequired`)

- [ ] **Step 1: Add the new props to `HeaderProps` and the component signature**

In `Header.tsx`, add to the `HeaderProps` interface:

```typescript
  agentOutdated: boolean;
  pairingRequired: boolean;
  onSubmitPairingToken: (token: string) => void;
```

and destructure them in the component's props list alongside the existing `agentStatus`.

- [ ] **Step 2: Extend the status pill's color/label logic for the outdated case**

The existing pill (`Header.tsx:150-181`) branches on `agentStatus`. Change the outer condition so "connected but outdated" is checked first:

```typescript
        <div
          className={`hidden sm:flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-full border font-mono ${
            agentStatus === 'connected' && agentOutdated
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400'
              : agentStatus === 'connected'
              ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-400'
              : agentStatus === 'connecting'
              ? 'bg-amber-500/10 border-amber-500/30 text-amber-600 dark:text-amber-400'
              : agentStatus === 'error'
              ? 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-400'
              : 'bg-secondary border-border text-muted-foreground'
          }`}
          title="NetView Agent connection status (ws://localhost:8999)"
        >
          <span
            className={`w-1.5 h-1.5 rounded-full ${
              agentStatus === 'connected' && agentOutdated
                ? 'bg-amber-500 dark:bg-amber-400'
                : agentStatus === 'connected'
                ? 'bg-emerald-500 dark:bg-emerald-400'
                : agentStatus === 'connecting'
                ? 'bg-amber-500 dark:bg-amber-400 animate-pulse'
                : agentStatus === 'error'
                ? 'bg-rose-500 dark:bg-rose-400'
                : 'bg-muted-foreground'
            }`}
          />
          <span>
            {agentStatus === 'connected' && agentOutdated
              ? 'Agent Outdated'
              : agentStatus === 'connected'
              ? 'Agent Connected'
              : agentStatus === 'connecting'
              ? 'Connecting...'
              : agentStatus === 'error'
              ? 'Connection Error'
              : 'Agent Disconnected'}
          </span>
        </div>
```

- [ ] **Step 3: Add the pairing banner**

Directly after the status-pill `</div>` (still inside the header's right-hand flex group), add:

```typescript
        {pairingRequired && (
          <PairingPrompt onSubmit={onSubmitPairingToken} />
        )}
```

Add the `PairingPrompt` component in the same file, above `Header`:

```typescript
const PairingPrompt: React.FC<{ onSubmit: (token: string) => void }> = ({ onSubmit }) => {
  const [value, setValue] = useState('');
  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (value.trim()) onSubmit(value.trim());
      }}
      className="hidden lg:flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-full border bg-secondary border-border"
    >
      <span className="text-muted-foreground">Pairing code:</span>
      <input
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder="XXXX-XXXX"
        className="w-20 bg-transparent outline-none font-mono placeholder:text-muted-foreground"
      />
      <button type="submit" className="text-cyan-500 font-semibold hover:text-cyan-400">
        Connect
      </button>
    </form>
  );
};
```

Add `useState` to the file's existing `import React from 'react';` if not already imported as a named import (check the top of `Header.tsx` - if it currently only imports `React` as a default import, change to `import React, { useState } from 'react';`).

- [ ] **Step 4: Wire the new props from `App.tsx`**

In `App.tsx`, where `<Header ... agentStatus={agentStatus} ... />` is rendered, add:

```typescript
          agentOutdated={agentOutdated}
          pairingRequired={pairingRequired}
          onSubmitPairingToken={(token) => {
            storePairingToken(token);
            sendAgentCommand({ type: 'auth', token });
            setPairingRequired(false);
          }}
```

(`storePairingToken` and `sendAgentCommand` already exist from Tasks 7 and 8.)

- [ ] **Step 5: Run the type-check**

Run: `npm run lint`
Expected: no errors.

- [ ] **Step 6: Manual verification**

Start the dev server (`npm run dev`), start the agent, load the app. Confirm the pairing banner appears with an empty pairing-code field. Type the wrong code, confirm nothing happens (still shows the banner). Type the real code from the agent's console and submit; confirm the banner disappears and the status pill shows "Agent Connected". Reload the page; confirm the banner does *not* reappear (token was stored and resent automatically).

- [ ] **Step 7: Commit**

```bash
git add src/components/common/Header.tsx src/App.tsx
git commit -m "frontend: agent-outdated status and pairing banner"
```

---

## Task 10: Start/Stop buttons actually command the agent

**Files:**
- Modify: `src/components/common/Header.tsx`, `src/components/common/FloatingToolbar.tsx`, `src/components/common/AppMenu.tsx`, `src/App.tsx`

**Interfaces:**
- Consumes: `sendAgentCommand` (Task 8), threaded down as a new prop `onSendAgentCommand: (command: AgentCommand) => void` to `Header`, `FloatingToolbar`, and `AppMenu` (all three already receive `onStartCapture`/`onPauseCapture`/`onStopCapture` today)

- [ ] **Step 1: Pass `onSendAgentCommand` from `App.tsx` to all three components**

Where `<Header ... onStartCapture={...} .../>`, `<FloatingToolbar ... onStartCapture={...} .../>`, and `<AppMenu ... onStartCapture={...} .../>` are rendered, add `onSendAgentCommand={sendAgentCommand}` to each (`sendAgentCommand` already exists from Task 8). Add `onSendAgentCommand: (command: AgentCommand) => void;` to each of the three components' prop interfaces, and the matching import of `AgentCommand` from `../../services/agentProtocol` in each file.

- [ ] **Step 2: `Header.tsx` - Start/Stop/Halt buttons also send commands**

In `Header.tsx`, the three capture buttons currently call `onPauseCapture`, `onStartCapture`, `onStopCapture` directly in their `onClick`. Change each to also send the matching agent command:

```typescript
              onClick={() => {
                onPauseCapture();
                onSendAgentCommand({ type: 'stop_capture' });
              }}
```

```typescript
              onClick={() => {
                onStartCapture();
                onSendAgentCommand({ type: 'start_capture' });
              }}
```

```typescript
              onClick={() => {
                onStopCapture();
                onSendAgentCommand({ type: 'stop_capture' });
              }}
```

- [ ] **Step 3: `FloatingToolbar.tsx` - same pattern**

```typescript
            onClick={() => {
              onStartCapture();
              onSendAgentCommand({ type: 'start_capture' });
            }}
```

```typescript
            onClick={() => {
              onStopCapture();
              onSendAgentCommand({ type: 'stop_capture' });
            }}
```

- [ ] **Step 4: `AppMenu.tsx` - same pattern inside the existing `run(...)` calls**

The Actions group's Start/Stop items currently do `onSelect={() => run(onPauseCapture)}` and `onSelect={() => run(onStartCapture)}`. Change to:

```typescript
                        onSelect={() => run(() => { onPauseCapture(); onSendAgentCommand({ type: 'stop_capture' }); })}
```

```typescript
                        onSelect={() => run(() => { onStartCapture(); onSendAgentCommand({ type: 'start_capture' }); })}
```

- [ ] **Step 5: Run the type-check**

Run: `npm run lint`
Expected: no errors.

- [ ] **Step 6: Manual verification**

With the agent running and paired (per Task 9's verification), click Start Capture in the header. Confirm the agent's console starts logging "N packets captured so far" and packets appear in the packet list. Click Stop Capture (or Halt). Confirm the agent's console packet count stops increasing (generate some traffic - e.g. browse a page - to confirm it's genuinely not capturing, not just quiet). Repeat via the FloatingToolbar and the AppMenu's Start/Stop item to confirm all three paths work.

- [ ] **Step 7: Commit**

```bash
git add src/components/common/Header.tsx src/components/common/FloatingToolbar.tsx src/components/common/AppMenu.tsx src/App.tsx
git commit -m "frontend: Start/Stop Capture now actually commands the agent"
```

---

## Task 11: Interface selection in the AppMenu drawer

**Files:**
- Modify: `src/components/common/AppMenu.tsx`, `src/App.tsx`

**Interfaces:**
- Consumes: `agentInterfaces: {name:string; label:string}[]` (Task 8's App.tsx state), `onSendAgentCommand` (Task 10)
- Produces: new `AppMenuProps` fields `agentInterfaces: {name:string;label:string}[]`, `selectedInterfaces: string[]`

- [ ] **Step 1: Add `agentInterfaces` and interface-selection state**

In `App.tsx`, add `const [selectedInterfaces, setSelectedInterfaces] = useState<string[]>([]);` alongside the other agent-related state from Task 8. When a `hello` or `state` message arrives with a non-empty `interfaces` list and `selectedInterfaces` is still empty, default it to "all interfaces" (matching the agent's own default): in the `parseAgentMessage` handling from Task 8's Step 4, inside the `hello` branch, add:

```typescript
          setSelectedInterfaces((prev) => (prev.length > 0 ? prev : message.interfaces.map((i) => i.name)));
```

- [ ] **Step 2: Pass the new props to `AppMenu`**

Add `agentInterfaces={agentInterfaces}` and `selectedInterfaces={selectedInterfaces}` to the `<AppMenu ... />` render in `App.tsx` (alongside `onSendAgentCommand` from Task 10).

- [ ] **Step 3: Add the checklist UI to `AppMenu.tsx`**

Add `agentInterfaces: { name: string; label: string }[];` and `selectedInterfaces: string[];` to `AppMenuProps`, destructure them.

In the "Views" `Command.Group`, after the existing Settings item, add:

```typescript
                    {agentInterfaces.length > 0 && (
                      <>
                        <Command.Separator className="my-1 h-px bg-border" />
                        <div className="px-2 py-1.5 text-[10px] font-bold uppercase tracking-wider font-mono text-muted-foreground">
                          Capture Interfaces
                        </div>
                        {agentInterfaces.map((iface) => {
                          const isSelected = selectedInterfaces.includes(iface.name);
                          return (
                            <Command.Item
                              key={iface.name}
                              value={`interface-${iface.name}`}
                              onSelect={() => {
                                const next = isSelected
                                  ? selectedInterfaces.filter((n) => n !== iface.name)
                                  : [...selectedInterfaces, iface.name];
                                onSendAgentCommand({ type: 'set_interfaces', interfaces: next });
                              }}
                              className={itemClass}
                            >
                              <span className={`w-3.5 h-3.5 shrink-0 rounded border flex items-center justify-center ${isSelected ? 'bg-cyan-500 border-cyan-500' : 'border-border'}`}>
                                {isSelected && <TbCheck className="w-3 h-3 text-slate-950" />}
                              </span>
                              <span className="truncate">{iface.label}</span>
                            </Command.Item>
                          );
                        })}
                      </>
                    )}
```

`TbCheck` needs adding to the existing `react-icons/tb` import at the top of `AppMenu.tsx` if it isn't already imported (check the current import list from the icon-overhaul work earlier this session before assuming it's missing).

Note: this command sends `set_interfaces` with the *next* full set directly from `App.tsx`'s `selectedInterfaces`, not from a local copy in `AppMenu` - the actual displayed `selectedInterfaces` prop only updates once the agent's `state` message round-trips back through Task 8's handler, which is the source of truth (the agent, not an optimistic local toggle) - matching the spec's "change interfaces should read as an immediate reconfiguration" without the UI getting ahead of what the agent actually did.

- [ ] **Step 4: Run the type-check**

Run: `npm run lint`
Expected: no errors.

- [ ] **Step 5: Manual verification**

With the agent running, paired, and capturing on all interfaces, open the AppMenu and confirm a "Capture Interfaces" section lists every interface the agent's console printed at startup, all checked. Uncheck one; confirm the agent's console shows the sniffer threads restart (the "detected N interfaces" list doesn't change, but capturing should visibly stop producing packets sourced from the unchecked interface if you can tell them apart - e.g. by IP range on a machine with more than one active adapter). Re-check it; confirm it resumes.

- [ ] **Step 6: Commit**

```bash
git add src/components/common/AppMenu.tsx src/App.tsx
git commit -m "frontend: interface selection in the AppMenu drawer"
```

---

## Task 12: Full end-to-end verification

**Files:** none (verification only)

- [ ] **Step 1: Run every automated check from this plan in sequence**

```bash
python local-agent/test_protocol.py
npx tsx scripts/agent-protocol/message-parsing.ts
npx tsx scripts/agent-protocol/version-and-commands.ts
npx tsx scripts/agent-protocol/token-storage.ts
npm run lint
npm run build
```

Expected: every command exits 0 / prints "All checks passed." / produces no errors.

- [ ] **Step 2: Fresh-start walkthrough**

Clear the browser's stored pairing token (DevTools -> Application -> Local Storage -> remove `netview.agentPairingToken`) to simulate a first-time connection. Start the agent fresh (as Administrator), note the pairing code. Load NetView. Confirm: agent status pill shows "Agent Disconnected" then "Agent Connected" once the WebSocket connects; the pairing banner appears since no token is stored; entering the wrong code does nothing; entering the printed code clears the banner.

- [ ] **Step 3: Capture control walkthrough**

Confirm packets do **not** start appearing in the packet list until Start Capture is clicked (this is the core behavior change from today, where the agent captured unconditionally). Click Start; confirm packets appear and the agent's console shows increasing packet counts. Click Stop; confirm packets stop appearing and the console's count stops increasing.

- [ ] **Step 4: Interface selection walkthrough**

Open the AppMenu, confirm the interface list matches what the agent printed on startup. Toggle one off and on, per Task 11 Step 5.

- [ ] **Step 5: Version mismatch walkthrough**

Temporarily change `AGENT_VERSION` in `local-agent/agent.py` to `"1.0.0"` (below `REQUIRED_AGENT_VERSION`), restart the agent, reconnect. Confirm the status pill switches to amber "Agent Outdated". Revert `AGENT_VERSION` back to `"1.1.0"` afterward - do not commit the temporary downgrade.

- [ ] **Step 6: Reconnect walkthrough**

With the agent running and paired, stop the agent process. Confirm the status pill returns to "Agent Disconnected" within the existing 3-second retry window. Restart the agent (same process, so the same pairing token is still valid only if you reused the token - restarting generates a *new* token per Task 1, so this should actually prompt the pairing banner again). Confirm the banner reappears since the newly-generated code doesn't match the stored one, and pairing again with the new code works.
