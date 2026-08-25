# Agent Background Service Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the manually-launched, visible-console NetView capture agent into a Windows service that installs once, runs headless from boot, authenticates browsers by origin instead of a pairing token, and captures only while a NetView page is connected.

**Architecture:** `agent.py` keeps its asyncio WebSocket server but loses all pairing machinery; a new `process_request` hook rejects disallowed origins at the HTTP handshake before the WebSocket upgrade. A new `service_windows.py` becomes the PyInstaller entry point, hosting `agent.main()` inside a pywin32 `ServiceFramework` and doubling as the silent install/remove CLI that Inno Setup drives. Capture is scoped to live connections: the last disconnect stops the sniffer.

**Tech Stack:** Python 3.14, scapy, websockets 17.x (`websockets.asyncio.server`), pywin32 312, PyInstaller 6.x, Inno Setup 6.1+, React 19 + TypeScript frontend.

**Spec:** `docs/superpowers/specs/2026-08-26-agent-background-service-design.md`

## Global Constraints

- `AGENT_VERSION` (Python) and `REQUIRED_AGENT_VERSION` (TypeScript) are both exactly `"2.0.0"` and must stay in sync.
- Windows only. macOS and Linux keep their existing manual-launch bootstrap scripts — do not modify `bootstrap_macos.command` or `bootstrap_linux.sh`.
- `python local-agent/agent.py` must keep working with a console and stderr logging throughout. Never regress that path.
- No test framework exists in this repo. Tests are plain assertion scripts: `local-agent/test_protocol.py` (run `python local-agent/test_protocol.py`) and `scripts/agent-protocol/*.ts` (run `npx tsx <file>`). Follow the existing `check(name, actual, expected)` / `check_true(name, condition)` helpers and the failure-counter + `sys.exit(1)` pattern already in those files.
- Frontend type-check is `npm run lint` (`tsc --noEmit`). It must pass at the end of every frontend task.
- Config file location is `%ProgramData%\NetView\config.json`. Log file is `%ProgramData%\NetView\agent.log`.
- Default allowed origins, exactly: `http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:4173`, `http://127.0.0.1:4173`.
- Service name is `NetViewAgent`; display name is `NetView Capture Agent`.
- An existing `config.json` is never overwritten by an install or upgrade.
- Every commit message ends with `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## File Structure

**New:**
- `local-agent/config.py` — config dir/path resolution, parse-with-fallback, origin normalization and matching. Pure; no scapy/websockets imports so it stays unit-testable.
- `local-agent/logging_setup.py` — rotating file handler plus optional stderr handler. One responsibility: build the `netview` logger.
- `local-agent/service_windows.py` — pywin32 `ServiceFramework` subclass and subcommand dispatch. The PyInstaller entry point.

**Modified:**
- `local-agent/agent.py` — remove pairing, add origin gate, wire config + logging, auto-stop on last disconnect, version 2.0.0.
- `local-agent/test_protocol.py` — drop pairing assertions, add config/origin/lifecycle assertions.
- `local-agent/netview_agent.spec`, `local-agent/requirements.txt`, `local-agent/installer/setup.iss`.
- `src/services/agentProtocol.ts`, `src/App.tsx`, `src/components/common/Header.tsx`, `src/services/platformDetect.ts`.
- `scripts/agent-protocol/message-parsing.ts`, `scripts/agent-protocol/version-and-commands.ts`.
- `CLAUDE.md`.

**Deleted:**
- `local-agent/bootstrap_windows.py` — its two jobs (install Npcap, launch the agent) move to the installer and the SCM.
- `scripts/agent-protocol/token-storage.ts` — tests functions that no longer exist.

---

### Task 1: Config module

**Files:**
- Create: `local-agent/config.py`
- Modify: `local-agent/test_protocol.py` (append a new section)

**Interfaces:**
- Consumes: nothing.
- Produces: `DEFAULT_ALLOWED_ORIGINS: list[str]`, `config_dir() -> str`, `config_path() -> str`, `parse_config(raw_text: str | None, on_warning=None) -> dict`, `load_config(on_warning=None) -> dict`, `normalize_origin(origin: str) -> str`, `is_origin_allowed(origin, allowed_origins) -> bool`. The dict returned by `parse_config`/`load_config` has exactly one key: `"allowedOrigins"` (a `list[str]`).

- [ ] **Step 1: Write the failing tests**

Append to the end of `local-agent/test_protocol.py`, immediately **before** the final `print()` / `if failures:` block:

```python
# --- config: origin normalization ---
import config

check("normalize lowercases scheme and host", config.normalize_origin("HTTP://LocalHost:3000"), "http://localhost:3000")
check("normalize strips a trailing slash", config.normalize_origin("http://localhost:3000/"), "http://localhost:3000")
check("normalize strips surrounding whitespace", config.normalize_origin("  http://localhost:3000  "), "http://localhost:3000")

# --- config: origin matching ---
allowed = ["http://localhost:3000", "http://127.0.0.1:4173"]
check_true("exact origin allowed", config.is_origin_allowed("http://localhost:3000", allowed))
check_true("second listed origin allowed", config.is_origin_allowed("http://127.0.0.1:4173", allowed))
check("unlisted origin rejected", config.is_origin_allowed("https://evil.com", allowed), False)
check("different port rejected", config.is_origin_allowed("http://localhost:9999", allowed), False)
check("missing origin rejected", config.is_origin_allowed(None, allowed), False)
check("empty origin rejected", config.is_origin_allowed("", allowed), False)
check("non-string origin rejected", config.is_origin_allowed(1234, allowed), False)
check_true("case-insensitive match", config.is_origin_allowed("HTTP://LOCALHOST:3000", allowed))
check_true("trailing slash tolerated", config.is_origin_allowed("http://localhost:3000/", allowed))

# --- config: parsing and fallback ---
check(
    "valid config is used",
    config.parse_config('{"allowedOrigins": ["http://example.test"]}')["allowedOrigins"],
    ["http://example.test"],
)
check("absent file falls back to defaults", config.parse_config(None)["allowedOrigins"], config.DEFAULT_ALLOWED_ORIGINS)
check("malformed JSON falls back to defaults", config.parse_config("{not json")["allowedOrigins"], config.DEFAULT_ALLOWED_ORIGINS)
check("non-object JSON falls back to defaults", config.parse_config('["a"]')["allowedOrigins"], config.DEFAULT_ALLOWED_ORIGINS)
check("missing allowedOrigins key falls back", config.parse_config('{"other": 1}')["allowedOrigins"], config.DEFAULT_ALLOWED_ORIGINS)
check("non-list allowedOrigins falls back", config.parse_config('{"allowedOrigins": "nope"}')["allowedOrigins"], config.DEFAULT_ALLOWED_ORIGINS)
check("non-string entries fall back", config.parse_config('{"allowedOrigins": [1, 2]}')["allowedOrigins"], config.DEFAULT_ALLOWED_ORIGINS)
check("config origins are normalized on load", config.parse_config('{"allowedOrigins": ["HTTP://Example.test/"]}')["allowedOrigins"], ["http://example.test"])

warnings = []
config.parse_config("{not json", on_warning=warnings.append)
check("malformed JSON emits exactly one warning", len(warnings), 1)

no_warnings = []
config.parse_config('{"allowedOrigins": ["http://example.test"]}', on_warning=no_warnings.append)
check("valid config emits no warning", no_warnings, [])

check("defaults are the four documented origins", config.DEFAULT_ALLOWED_ORIGINS, [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
])
check_true("config_path ends with config.json", config.config_path().endswith("config.json"))
check_true("config_path lives under the config dir", config.config_path().startswith(config.config_dir()))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python local-agent/test_protocol.py`
Expected: FAIL with `ModuleNotFoundError: No module named 'config'`

- [ ] **Step 3: Create the config module**

Create `local-agent/config.py`:

```python
#!/usr/bin/env python3
"""
Where the NetView agent's settings live, and which browser origins may
connect to it.

Deliberately imports neither scapy nor websockets: this module is the one
piece of the auth path that can be exercised with plain assertions, with no
capture driver and no running server (see test_protocol.py).
"""

import json
import os

# Port 3000 covers both the Vite dev server (`vite --port=3000`) and the
# Express production server (server.ts, PORT || 3000); 4173 is Vite's preview
# default. `localhost` and `127.0.0.1` are *different origins* to a browser,
# so each port needs both spellings or one of them silently fails to connect.
DEFAULT_ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]


def config_dir() -> str:
    """%ProgramData%\\NetView on Windows: readable by every user, writable
    only by administrators, and populated before anyone logs in - which a
    LocalSystem service needs, since it starts at boot with no user session.
    Falls back to ~/.netview elsewhere purely so this module stays importable
    for development on macOS/Linux."""
    if os.name == "nt":
        base = os.environ.get("ProgramData", r"C:\ProgramData")
        return os.path.join(base, "NetView")
    return os.path.join(os.path.expanduser("~"), ".netview")


def config_path() -> str:
    return os.path.join(config_dir(), "config.json")


def normalize_origin(origin: str) -> str:
    """An origin's scheme and host compare case-insensitively, and a trailing
    slash is not part of an origin at all. Browsers send neither variation,
    but a hand-edited config file easily contains both - and a config typo
    that silently blocks every connection is exactly the failure this whole
    module is written to avoid."""
    return origin.strip().rstrip("/").lower()


def _defaults() -> dict:
    return {"allowedOrigins": list(DEFAULT_ALLOWED_ORIGINS)}


def parse_config(raw_text, on_warning=None) -> dict:
    """Turns config.json's contents into a settings dict.

    Every failure mode - unreadable JSON, wrong shape, missing key - falls
    back to DEFAULT_ALLOWED_ORIGINS instead of raising. A headless service
    that refuses every connection because of a stray comma, with no console
    to say so, is the worst outcome available here; running on defaults and
    logging a warning is strictly better.
    """
    def warn(message):
        if on_warning is not None:
            on_warning(message)

    if raw_text is None:
        return _defaults()

    try:
        data = json.loads(raw_text)
    except (json.JSONDecodeError, TypeError, ValueError):
        warn("config.json is not valid JSON - using default allowed origins")
        return _defaults()

    if not isinstance(data, dict):
        warn("config.json is not a JSON object - using default allowed origins")
        return _defaults()

    origins = data.get("allowedOrigins")
    if not isinstance(origins, list) or not all(isinstance(o, str) for o in origins):
        warn("config.json has no valid 'allowedOrigins' string list - using default allowed origins")
        return _defaults()

    return {"allowedOrigins": [normalize_origin(o) for o in origins]}


def load_config(on_warning=None) -> dict:
    """Reads and parses config.json, falling back to defaults if it is absent
    or unreadable."""
    try:
        with open(config_path(), "r", encoding="utf-8") as handle:
            return parse_config(handle.read(), on_warning=on_warning)
    except FileNotFoundError:
        # Not a warning: no config file is the normal state until someone
        # customizes one, and the installer only seeds it on Windows.
        return parse_config(None, on_warning=on_warning)
    except OSError as exc:
        if on_warning is not None:
            on_warning(f"could not read config.json ({exc}) - using default allowed origins")
        return parse_config(None, on_warning=on_warning)


def is_origin_allowed(origin, allowed_origins) -> bool:
    """A missing Origin header means a non-browser client, and is rejected.
    Browsers always send Origin on a WebSocket handshake, so its absence is
    never a legitimate NetView tab - only curl, a script, or a native process
    (see spec: Authentication)."""
    if not origin or not isinstance(origin, str):
        return False
    normalized = normalize_origin(origin)
    return any(normalized == normalize_origin(allowed) for allowed in allowed_origins)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python local-agent/test_protocol.py`
Expected: PASS — `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add local-agent/config.py local-agent/test_protocol.py
git commit -m "$(cat <<'EOF'
agent: add config module with origin allowlist matching

Config lives at %ProgramData%\NetView\config.json. Every parse failure
falls back to the built-in default origins rather than raising: a headless
service that refuses all connections over a config typo, with no console to
explain why, is the worst available outcome.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Remove pairing from the agent

**Files:**
- Modify: `local-agent/agent.py`
- Modify: `local-agent/test_protocol.py`

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `build_hello_message(version, state, interfaces) -> dict` (note: the `auth_required` parameter is **removed**; the returned dict no longer has an `authRequired` key). `AgentServer.connections` becomes a `set` of WebSocket objects rather than a dict. `AGENT_VERSION == "2.0.0"`.

- [ ] **Step 1: Update the tests first**

In `local-agent/test_protocol.py`, **delete** these existing sections entirely (they test functions this task removes):
- the `# --- generate_pairing_token ---` section (both `check_true` lines and the `token = ...` line)
- the `# --- ConnectionAuth ---` section (every line from `auth = agent.ConnectionAuth(...)` through the `check("auth message itself is not gated", ...)` line, including the `is_command_allowed` checks and the `authed = ...` lines)

Then **replace** the existing `build_hello_message` checks with these:

```python
# --- build_hello_message ---
hello = agent.build_hello_message(
    version="2.0.0",
    state="idle",
    interfaces=[("\\Device\\NPF_{ABC}", "Wi-Fi")],
)
check("hello type", hello["type"], "hello")
check("hello version", hello["version"], "2.0.0")
check("hello state", hello["state"], "idle")
check("hello interfaces", hello["interfaces"], [{"name": "\\Device\\NPF_{ABC}", "label": "Wi-Fi"}])
check("hello no longer advertises authRequired", "authRequired" in hello, False)

hello_no_ifaces = agent.build_hello_message(version="2.0.0", state="sniffing", interfaces=[])
check("hello with no interfaces", hello_no_ifaces["interfaces"], [])
check("hello sniffing state", hello_no_ifaces["state"], "sniffing")

check("agent version is 2.0.0", agent.AGENT_VERSION, "2.0.0")
check("pairing token generation is gone", hasattr(agent, "generate_pairing_token"), False)
check("ConnectionAuth is gone", hasattr(agent, "ConnectionAuth"), False)
check("is_command_allowed is gone", hasattr(agent, "is_command_allowed"), False)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python local-agent/test_protocol.py`
Expected: FAIL — `hello no longer advertises authRequired` fails (the key is still present), `agent version is 2.0.0` fails (still `1.1.0`), and the three `hasattr` checks fail. The `build_hello_message` call itself raises `TypeError` for the missing `auth_required` argument, so expect a traceback rather than a clean failure count.

- [ ] **Step 3: Remove the pairing machinery from agent.py**

In `local-agent/agent.py`:

Change the version constant:

```python
AGENT_VERSION = "2.0.0"
```

**Delete** the entire `generate_pairing_token()` function, the entire `ConnectionAuth` class, the `GATED_COMMAND_TYPES` set, and the entire `is_command_allowed()` function.

Replace `build_hello_message` with:

```python
def build_hello_message(version: str, state: str, interfaces) -> dict:
    """The first message sent on every new connection, before anything else.

    No `authRequired` field: by the time this is sent the connection has
    already passed the origin check during the HTTP handshake, so there is no
    second authentication step left to advertise.
    """
    return {
        "type": "hello",
        "version": version,
        "state": state,
        "interfaces": [{"name": name, "label": label} for name, label in interfaces],
    }
```

Replace `AgentServer.__init__` and `register` with:

```python
class AgentServer:
    def __init__(self):
        # A plain set of sockets. Phase 1 needed a ws -> ConnectionAuth map so
        # packet fan-out could check each connection's pairing state; the
        # origin check now rejects disallowed clients during the handshake, so
        # every connection in this set is by construction an allowed one.
        self.connections = set()
        self.loop = None

    async def register(self, ws):
        self.connections.add(ws)
        log.info("client connected (%d total)", len(self.connections))
        state = "sniffing" if sniffer.is_sniffing() else "idle"
        await ws.send(json.dumps(build_hello_message(AGENT_VERSION, state, AVAILABLE_INTERFACES)))
        try:
            async for raw in ws:
                await self._handle_message(ws, raw)
        finally:
            self.connections.discard(ws)
            log.info("client disconnected (%d remaining)", len(self.connections))
```

Replace `_handle_message` with (note: the `auth` parameter is gone, and the `auth` branch and gate are removed):

```python
    async def _handle_message(self, ws, raw):
        try:
            message = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(message, dict):
            return

        msg_type = message.get("type")
        if msg_type == "start_capture":
            log.info("start_capture requested on %d interface(s)", len(sniffer.selected_interfaces))
            sniffer.start_threads(spawn_sniffer_thread)
        elif msg_type == "stop_capture":
            log.info("stop_capture requested")
            sniffer.stop_threads()
        elif msg_type == "set_interfaces":
            interfaces = message.get("interfaces")
            if isinstance(interfaces, list) and all(isinstance(i, str) for i in interfaces):
                if not interfaces:
                    # Sniffing "on zero interfaces" would otherwise succeed
                    # silently and broadcast state=sniffing while nothing is
                    # actually captured.
                    await ws.send(json.dumps({
                        "type": "error",
                        "code": "empty_interfaces",
                        "message": "At least one interface must be selected.",
                    }))
                    return
                log.info("set_interfaces: %d interface(s) selected", len(interfaces))
                sniffer.set_interfaces(interfaces)
                sniffer.restart_threads(spawn_sniffer_thread)
        else:
            return

        self.broadcast(sniffer.state_message(AVAILABLE_INTERFACES))
```

Replace `_send_all` with (the per-connection auth check is gone):

```python
    async def _send_all(self, message: dict):
        # list(...) snapshots the set before awaiting inside the loop, since a
        # client connecting or dropping mid-broadcast would otherwise mutate
        # self.connections while it is being iterated.
        data = json.dumps(message)
        dead = []
        for ws in list(self.connections):
            try:
                await ws.send(data)
            except websockets.ConnectionClosed:
                dead.append(ws)
        for ws in dead:
            self.connections.discard(ws)
```

In `main()`, remove the `PAIRING_TOKEN` entry from the `global` statement and delete these three lines:

```python
    PAIRING_TOKEN = generate_pairing_token()
    print(f"[agent] Pairing code: {PAIRING_TOKEN}", file=sys.stderr)
    print("[agent] Enter this code in NetView to connect.", file=sys.stderr)
```

Also update the call in `register` if a module-level `PAIRING_TOKEN = None` declaration exists — delete that too.

**Note on `log`:** this task's replacement code references a module-level `log`, which Task 5 introduces. To keep this task's code runnable on its own, add this placeholder near the top of `agent.py` (immediately after the `AGENT_VERSION` line); Task 5 replaces it with the real logger:

```python
import logging

# Replaced in Task 5 by logging_setup.setup_logging(). Until then this is a
# bare logger with no handlers, which is silent - the print() calls elsewhere
# in this file are still the visible output.
log = logging.getLogger("netview")
log.addHandler(logging.StreamHandler(sys.stderr))
log.setLevel(logging.INFO)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python local-agent/test_protocol.py`
Expected: PASS — `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent.py local-agent/test_protocol.py
git commit -m "$(cat <<'EOF'
agent: remove pairing token machinery, bump to 2.0.0

A LocalSystem service has no console to print a pairing code to, so the
token is replaced wholesale by the origin allowlist (next task). Deletes
generate_pairing_token, ConnectionAuth, is_command_allowed, the auth
message branch and the authRequired hello field.

Breaking protocol change, hence the major version bump: Phase 1's version
handshake now correctly flags a 1.x agent as outdated.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: Origin enforcement at the handshake

**Files:**
- Modify: `local-agent/agent.py`
- Modify: `local-agent/test_protocol.py`

**Interfaces:**
- Consumes: `config.load_config(on_warning)`, `config.is_origin_allowed(origin, allowed_origins)` from Task 1.
- Produces: `make_process_request(on_reject=None) -> callable`. The returned callable has signature `process_request(connection, request)` and returns `None` to accept or a `websockets` `Response` (from `connection.respond(...)`) to reject.

**Background the implementer needs:** `websockets` 17.0.1's `websockets.asyncio.server.serve()` accepts a `process_request` keyword argument. It is called after the HTTP request is parsed but before the WebSocket upgrade completes. Returning `None` lets the handshake proceed; returning a `Response` object aborts it and sends that response instead. `connection.respond(status, text)` builds one. This has been verified against the installed version — `ServerConnection.respond` exists and `serve()` accepts `process_request`.

- [ ] **Step 1: Write the failing tests**

Append to `local-agent/test_protocol.py`, before the final `print()` / `if failures:` block:

```python
# --- origin gate (process_request) ---
class FakeHeaders(dict):
    """Stands in for websockets' case-insensitive header mapping. Only .get()
    is used by the code under test."""


class FakeRequest:
    def __init__(self, origin):
        self.headers = FakeHeaders()
        if origin is not None:
            self.headers["Origin"] = origin


class FakeConnection:
    """Records what the gate tried to respond with, instead of writing HTTP."""

    def __init__(self):
        self.responded = None

    def respond(self, status, text):
        self.responded = (status, text)
        return self.responded


rejected = []
gate = agent.make_process_request(on_reject=rejected.append)

conn_ok = FakeConnection()
check("allowed origin passes the gate", gate(conn_ok, FakeRequest("http://localhost:3000")), None)
check("allowed origin produces no response", conn_ok.responded, None)
check("allowed origin is not recorded as rejected", rejected, [])

conn_bad = FakeConnection()
result_bad = gate(conn_bad, FakeRequest("https://evil.com"))
check_true("disallowed origin is rejected (non-None response)", result_bad is not None)
check_true("disallowed origin responds 403", conn_bad.responded is not None and conn_bad.responded[0] == 403)
check("disallowed origin is recorded", rejected, ["https://evil.com"])

conn_none = FakeConnection()
result_none = gate(conn_none, FakeRequest(None))
check_true("missing Origin header is rejected", result_none is not None)
check_true("missing Origin responds 403", conn_none.responded is not None and conn_none.responded[0] == 403)
check("missing Origin is recorded as None", rejected[-1], None)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python local-agent/test_protocol.py`
Expected: FAIL with `AttributeError: module 'agent' has no attribute 'make_process_request'`

- [ ] **Step 3: Add the origin gate**

In `local-agent/agent.py`, add to the imports near the top:

```python
from http import HTTPStatus

import config
```

Add this function immediately **after** the `AgentServer` class definition and the `agent = AgentServer()` line:

```python
def make_process_request(on_reject=None):
    """Builds the callback websockets invokes before completing the upgrade
    handshake. Returning None accepts the connection; returning a Response
    rejects it outright, so a disallowed page never receives `hello` and
    never receives a packet.

    The config is re-read here, on every connection, rather than once at
    startup. The file is tiny and connections are rare, so the cost is
    irrelevant - and it means adding an origin takes effect without
    restarting a service that has no UI to restart it from.
    """
    def process_request(connection, request):
        origin = request.headers.get("Origin")
        settings = config.load_config(on_warning=lambda msg: log.warning("config: %s", msg))
        if not config.is_origin_allowed(origin, settings["allowedOrigins"]):
            if on_reject is not None:
                on_reject(origin)
            return connection.respond(HTTPStatus.FORBIDDEN, "Origin not allowed\n")
        return None

    return process_request
```

In `main()`, replace the `websockets.serve(...)` call with:

```python
    def log_rejection(origin):
        log.warning("rejected connection from disallowed origin: %r", origin)

    async with websockets.serve(
        agent.register,
        HOST,
        PORT,
        process_request=make_process_request(on_reject=log_rejection),
    ):
        log.info("WebSocket server listening on ws://%s:%d", HOST, PORT)
        await asyncio.Future()  # run forever
```

Delete the old `print(f"[agent] WebSocket server listening on ws://{HOST}:{PORT}")` line it replaces.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python local-agent/test_protocol.py`
Expected: PASS — `All checks passed.`

- [ ] **Step 5: Verify against a real server**

Run the agent in one terminal (as Administrator): `python local-agent/agent.py`

In another terminal, confirm a disallowed origin is refused and an allowed one is accepted:

```bash
python -c "
import asyncio, websockets
async def go(origin):
    try:
        async with websockets.connect('ws://localhost:8999', origin=origin) as ws:
            print(origin, '-> ACCEPTED:', (await ws.recv())[:40])
    except Exception as exc:
        print(origin, '-> REJECTED:', type(exc).__name__, exc)
asyncio.run(go('http://localhost:3000'))
asyncio.run(go('https://evil.com'))
"
```

Expected: the first prints `ACCEPTED` followed by the start of a `hello` message; the second prints `REJECTED` with an HTTP 403. The agent's own output logs the rejected origin.

- [ ] **Step 6: Commit**

```bash
git add local-agent/agent.py local-agent/test_protocol.py
git commit -m "$(cat <<'EOF'
agent: reject disallowed origins at the WebSocket handshake

WebSockets are not subject to the same-origin policy, so any page can open
a socket to localhost:8999. The browser does stamp every handshake with an
Origin header that page JavaScript cannot forge, which is the hook this
uses: a connection whose Origin is not in config.json gets a 403 before
the upgrade completes and never sees hello or a packet.

Config is re-read per connection so adding an origin needs no restart.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Auto-stop capture on last disconnect

**Files:**
- Modify: `local-agent/agent.py`
- Modify: `local-agent/test_protocol.py`

**Interfaces:**
- Consumes: `AgentServer.connections` (a `set`) from Task 2; the existing `SnifferController.is_sniffing()` / `stop_threads()`.
- Produces: `AgentServer.handle_disconnect(ws)` — removes the socket and stops the sniffer when no connections remain.

- [ ] **Step 1: Write the failing tests**

Append to `local-agent/test_protocol.py`, before the final `print()` / `if failures:` block:

```python
# --- capture lifecycle: auto-stop when the last client disconnects ---
class FakeSpawn:
    def __call__(self, iface_name, stop_event):
        return None


# agent.sniffer is a module global that only exists once main() has run, so
# getattr (not agent.sniffer) is required here - importing the module alone
# leaves the name undefined.
previous_sniffer = getattr(agent, "sniffer", None)
try:
    agent.sniffer = agent.SnifferController(default_interfaces=["eth0"])
    server = agent.AgentServer()
    a, b = object(), object()
    server.connections.update({a, b})
    agent.sniffer.start_threads(FakeSpawn())
    check_true("sniffing before any disconnect", agent.sniffer.is_sniffing())

    server.handle_disconnect(a)
    check("one client left: still sniffing", agent.sniffer.is_sniffing(), True)
    check("disconnected socket removed", a in server.connections, False)

    server.handle_disconnect(b)
    check("last client gone: sniffing stopped", agent.sniffer.is_sniffing(), False)
    check("no connections remain", len(server.connections), 0)

    # Disconnecting when already idle must be a no-op, not an error.
    server.handle_disconnect(b)
    check("repeat disconnect is harmless", agent.sniffer.is_sniffing(), False)

    # A fresh connection must not resume capture on its own.
    server.connections.add(a)
    check("reconnect does not auto-resume capture", agent.sniffer.is_sniffing(), False)
finally:
    if previous_sniffer is None:
        del agent.sniffer
    else:
        agent.sniffer = previous_sniffer
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python local-agent/test_protocol.py`
Expected: FAIL with `AttributeError: 'AgentServer' object has no attribute 'handle_disconnect'`

- [ ] **Step 3: Add the lifecycle rule**

In `local-agent/agent.py`, add this method to `AgentServer`, immediately after `register`:

```python
    def handle_disconnect(self, ws):
        """Capture is scoped to live connections: with nobody watching,
        nothing should be captured. Closing the last NetView tab therefore
        stops the sniffer (see spec: Capture lifecycle).

        Sniffing deliberately does not resume when a client reconnects - a
        fresh connection arrives idle and must send start_capture again.
        Inferring intent across a disconnect would mean capturing traffic
        nobody explicitly asked for, which is the whole property that makes
        an always-running background capture agent acceptable.
        """
        self.connections.discard(ws)
        log.info("client disconnected (%d remaining)", len(self.connections))
        if not self.connections and sniffer.is_sniffing():
            log.info("last client disconnected - stopping capture")
            sniffer.stop_threads()
```

Then replace the `finally:` block inside `register` so it delegates here:

```python
        finally:
            self.handle_disconnect(ws)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python local-agent/test_protocol.py`
Expected: PASS — `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent.py local-agent/test_protocol.py
git commit -m "$(cat <<'EOF'
agent: stop capturing when the last client disconnects

This is what makes an always-running background capture agent acceptable:
close the NetView tab and sniffing halts, so traffic is never captured
with nobody watching. Reconnecting does not resume capture - a fresh
connection is idle and must ask again.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Rotating file logging

**Files:**
- Create: `local-agent/logging_setup.py`
- Modify: `local-agent/agent.py`

**Interfaces:**
- Consumes: `config.config_dir()` from Task 1.
- Produces: `setup_logging(directory, to_stderr=True, level=logging.INFO) -> logging.Logger` returning the `netview` logger. `agent.main(to_stderr=True)` gains that keyword argument, consumed by Task 6.

- [ ] **Step 1: Create the logging module**

Create `local-agent/logging_setup.py`:

```python
#!/usr/bin/env python3
"""
Logging for the NetView agent.

Once the agent runs as a service there is no console, so a file is the only
diagnostic channel that exists for either the user or a maintainer. This is
not optional polish - it is the entire observability story (see spec).
"""

import logging
import os
import sys
from logging.handlers import RotatingFileHandler

LOG_FILENAME = "agent.log"
# An agent running for months must not be able to fill a disk.
MAX_BYTES = 1_000_000
BACKUP_COUNT = 3

_configured = False


def setup_logging(directory, to_stderr=True, level=logging.INFO):
    """Configures and returns the shared `netview` logger.

    Idempotent: calling it twice returns the same logger without stacking
    duplicate handlers (which would print every line twice).
    """
    global _configured
    logger = logging.getLogger("netview")
    if _configured:
        return logger

    logger.setLevel(level)
    # propagate=False keeps these records out of the root logger, so a library
    # that configures logging.basicConfig() cannot double-print them.
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s")

    try:
        os.makedirs(directory, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(directory, LOG_FILENAME),
            maxBytes=MAX_BYTES,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        # An agent that cannot write its log must still run. When there is a
        # console this says so; under the SCM it is silently degraded, which
        # is still better than refusing to capture.
        if to_stderr:
            print(f"[agent] WARNING: cannot open log file in {directory}: {exc}", file=sys.stderr)

    if to_stderr:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        logger.addHandler(stream_handler)

    _configured = True
    return logger
```

- [ ] **Step 2: Migrate agent.py's print calls to the logger**

In `local-agent/agent.py`, **replace** the Task 2 placeholder logger block with:

```python
import logging

import logging_setup

# Configured for real in main(); until then this is a plain logger, so an
# import-time failure still has somewhere to go.
log = logging.getLogger("netview")
```

Replace every remaining `print(...)` call in the file with the logging equivalent:

| Existing call | Replacement |
|---|---|
| `print("[agent] first packet captured - capture is working", file=sys.stderr)` | `log.info("first packet captured - capture is working")` |
| `print(f"[agent] {_captured_count} packets captured so far", file=sys.stderr)` | `log.info("%d packets captured so far", _captured_count)` |
| `print(f"[agent] WARNING: failed to process a captured packet: {exc}", file=sys.stderr)` | `log.warning("failed to process a captured packet: %s", exc)` |
| `print(f"[agent] could not resolve friendly adapter names ({exc}); falling back to raw list", file=sys.stderr)` | `log.warning("could not resolve friendly adapter names (%s); falling back to raw list", exc)` |
| `print(f"[agent] WARNING: capture failed on interface {iface_label!r} ({iface_name}): {exc}", file=sys.stderr)` | `log.warning("capture failed on interface %r (%s): %s", iface_label, iface_name, exc)` |
| `print(f"ERROR: Packet capture requires elevated privileges.\n{hint}", file=sys.stderr)` | `log.error("packet capture requires elevated privileges. %s", hint)` |
| `print(f"[agent] ERROR: could not enumerate network interfaces: {exc}", file=sys.stderr)` | `log.error("could not enumerate network interfaces: %s", exc)` |
| `print(f"[agent] detected {len(AVAILABLE_INTERFACES)} network interface(s):", file=sys.stderr)` | `log.info("detected %d network interface(s)", len(AVAILABLE_INTERFACES))` |
| `print(f"[agent]   {label} -> {name}", file=sys.stderr)` | `log.info("  %s -> %s", label, name)` |

Leave the two `print(...)` calls in the scapy/websockets `ImportError` handlers at the top of the file alone — they run before logging can be configured and their whole job is to be visible to a developer running the script by hand.

Change the `main()` signature and add logging setup as its first action:

```python
async def main(to_stderr=True):
    global AVAILABLE_INTERFACES, INTERFACE_LABELS, sniffer, log

    log = logging_setup.setup_logging(config.config_dir(), to_stderr=to_stderr)
    log.info("NetView agent %s starting", AGENT_VERSION)
```

Then change the elevation check's failure path so it logs and exits cleanly rather than writing to a stderr nobody is attached to:

```python
    if not has_admin_privileges():
        hint = (
            "Right-click and choose 'Run as administrator'."
            if os.name == "nt"
            else "Re-run with sudo, e.g.: sudo python3 agent.py"
        )
        log.error("packet capture requires elevated privileges. %s", hint)
        return
```

Note this is now `return`, not `sys.exit(1)` — under the SCM, raising `SystemExit` out of the service body is a confusing way to report a configuration problem, and the log line is the real signal. Apply the same change to the interface-enumeration failure:

```python
    try:
        AVAILABLE_INTERFACES = list_interfaces()
    except Exception as exc:
        log.error("could not enumerate network interfaces: %s", exc)
        return
```

- [ ] **Step 3: Verify the console path still works**

Run (as Administrator): `python local-agent/agent.py`

Expected: timestamped log lines on stderr — `NetView agent 2.0.0 starting`, the interface list, and `WebSocket server listening on ws://localhost:8999`. Stop it with Ctrl+C.

- [ ] **Step 4: Verify the log file is written**

Run: `python -c "import os,sys; sys.path.insert(0,'local-agent'); import config; p=os.path.join(config.config_dir(),'agent.log'); print(p); print(open(p,encoding='utf-8').read()[-500:])"`

Expected: prints the log path and the tail of the same lines seen on stderr.

- [ ] **Step 5: Run the tests**

Run: `python local-agent/test_protocol.py`
Expected: PASS — `All checks passed.` (No assertions change here; this confirms the refactor broke nothing.)

- [ ] **Step 6: Commit**

```bash
git add local-agent/logging_setup.py local-agent/agent.py
git commit -m "$(cat <<'EOF'
agent: log to a rotating file instead of printing

Once the agent runs as a service there is no console, so the log file at
%ProgramData%\NetView\agent.log becomes the only diagnostic channel that
exists. Running interactively still logs to stderr as before.

Startup failures now log and return rather than sys.exit, since raising
SystemExit out of a service body reports a config problem confusingly.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Windows service host

**Files:**
- Create: `local-agent/service_windows.py`
- Modify: `local-agent/requirements.txt`

**Interfaces:**
- Consumes: `agent.main(to_stderr=False)` from Task 5.
- Produces: the `NetViewAgentService` class with `_svc_name_ = "NetViewAgent"`. The exe/script accepts `install`, `remove`, `start`, `stop`, `debug` and, with no arguments, runs under the Service Control Manager.

- [ ] **Step 1: Add the dependency**

Replace `local-agent/requirements.txt` with:

```
scapy>=2.5.0
websockets>=12.0
pyinstaller>=6.3.0
pywin32>=306; sys_platform == 'win32'
```

The environment marker keeps `pip install -r requirements.txt` working on macOS and Linux, where pywin32 does not exist and those platforms keep the manual-launch path anyway.

- [ ] **Step 2: Install it**

Run: `python -m pip install -r local-agent/requirements.txt`
Expected: pywin32 already satisfied (it was installed during the spec's feasibility check); no errors.

- [ ] **Step 3: Create the service host**

Create `local-agent/service_windows.py`:

```python
#!/usr/bin/env python3
"""
Windows service host for the NetView agent, and the PyInstaller entry point.

The same exe serves three roles:

  install / remove / start / stop   the CLI the Inno Setup installer drives.
                                    Silent - the installer checks exit codes,
                                    not output.
  debug                             runs the service body in the foreground
                                    with stderr logging. The only practical
                                    way to iterate on a frozen service.
  (no arguments, launched by SCM)   runs the service.

Built with console=False, so none of these ever show a window. Double-
clicking the exe deliberately does nothing visible.
"""

import asyncio
import os
import sys

import servicemanager
import win32event
import win32service
import win32serviceutil

# A frozen exe runs from a temp extraction directory; a plain script runs from
# local-agent/. Either way agent.py sits beside this file.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class NetViewAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NetViewAgent"
    _svc_display_name_ = "NetView Capture Agent"
    _svc_description_ = (
        "Captures network packets for the NetView web app. Idle until a "
        "NetView page connects, and stops capturing when the last one closes."
    )

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.stop_event = win32event.CreateEvent(None, 0, 0, None)
        self.loop = None

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.loop is not None:
            # The loop runs on the service's main thread; SvcStop is called on
            # a control thread, so this has to hop threads to touch it.
            self.loop.call_soon_threadsafe(self.loop.stop)
        win32event.SetEvent(self.stop_event)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        import logging

        import agent

        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(agent.main(to_stderr=False))
        except RuntimeError:
            # SvcStop called loop.stop() while run_until_complete was waiting
            # on agent.main()'s run-forever future. asyncio signals that as
            # "Event loop stopped before Future completed", which is the
            # normal shutdown path here, not a failure.
            pass
        except Exception:
            # Nothing is attached to stderr under the SCM. If this is not
            # written to the log file before the process dies, a crash at boot
            # is completely invisible.
            logging.getLogger("netview").exception(
                "service terminated with an unhandled exception"
            )
            raise
        finally:
            if self.loop is not None:
                self.loop.close()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No arguments means the Service Control Manager started us, rather
        # than a person or the installer running a subcommand.
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(NetViewAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(NetViewAgentService)
```

- [ ] **Step 4: Verify the debug path runs the agent**

In an **Administrator** terminal, run: `python local-agent/service_windows.py debug`

Expected: the agent's startup log lines appear on the console (interface list, `WebSocket server listening on ws://localhost:8999`). Stop with Ctrl+C. This proves the service body wires up to `agent.main()` correctly, without involving the SCM at all.

- [ ] **Step 5: Verify install/start/stop/remove against the real SCM**

In an **Administrator** terminal, run each and check the outcome:

```bash
python local-agent/service_windows.py install --startup auto
python local-agent/service_windows.py start
sc query NetViewAgent
python local-agent/service_windows.py stop
python local-agent/service_windows.py remove
```

Expected: `sc query NetViewAgent` reports `STATE : 4 RUNNING` between start and stop. If `start` fails, read `%ProgramData%\NetView\agent.log` — that file is the reason it exists.

Note: running these from a `.py` script registers the *Python interpreter* as the service host. That is fine for this check; Task 7 produces the frozen exe that gets registered for real.

- [ ] **Step 6: Commit**

```bash
git add local-agent/service_windows.py local-agent/requirements.txt
git commit -m "$(cat <<'EOF'
agent: add Windows service host and install/remove CLI

One exe, three roles: the SCM service body, the silent install/remove CLI
the installer drives, and a foreground debug mode - which exists because
iterating on a frozen headless service is otherwise impractical.

Unhandled exceptions are written to the log before the process dies;
under the SCM there is no stderr, so a boot crash would be invisible.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Freeze the service as a windowless exe

**Files:**
- Modify: `local-agent/netview_agent.spec`
- Delete: `local-agent/bootstrap_windows.py`

**Interfaces:**
- Consumes: `local-agent/service_windows.py` from Task 6.
- Produces: `local-agent/dist/netview-agent-windows.exe` — a windowless, multi-mode service exe.

- [ ] **Step 1: Rewrite the PyInstaller spec**

Replace `local-agent/netview_agent.spec` with:

```python
# PyInstaller spec for the NetView local agent - Windows service build.
# Build with:  pyinstaller netview_agent.spec
#
# Entry point is service_windows.py: the Service Control Manager host, and
# also the install/remove/start/stop/debug CLI the Inno Setup installer
# drives. agent.py, config.py and logging_setup.py are imported lazily or by
# name, so they are listed as hidden imports rather than discovered.
#
# Scapy loads many optional protocol layers dynamically, and pywin32's
# service machinery pulls win32timezone at runtime - both must be declared
# explicitly or PyInstaller silently drops them and the exe fails at start.

block_cipher = None

a = Analysis(
    ['service_windows.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # Our own modules - imported inside functions or via sys.path, so
        # PyInstaller's static analysis does not see them.
        'agent',
        'config',
        'logging_setup',
        # Scapy's dynamically loaded layers.
        'scapy.layers.all',
        'scapy.layers.inet',
        'scapy.layers.inet6',
        'scapy.arch.windows',
        'websockets.legacy.server',
        # pywin32 service machinery. win32timezone is the classic omission:
        # it is imported at runtime by pywintypes and its absence shows up
        # only as a service that refuses to start.
        'win32timezone',
        'servicemanager',
        'win32serviceutil',
        'win32service',
        'win32event',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='netview-agent-windows',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,         # no console window, ever - this is the whole point
    uac_admin=True,        # install/remove need elevation when run by hand;
                           # the SCM ignores the manifest when it starts a service
    icon='icon.ico',
)
```

- [ ] **Step 2: Delete the obsolete bootstrap**

```bash
git rm local-agent/bootstrap_windows.py
```

Its only jobs were installing Npcap (now the installer's, Task 8) and launching the agent (now the SCM's). Do not touch `bootstrap_macos.command` or `bootstrap_linux.sh` — those platforms keep the manual-launch path.

- [ ] **Step 3: Build**

Run: `python -m PyInstaller local-agent/netview_agent.spec --noconfirm --distpath local-agent/dist --workpath local-agent/build`
Expected: `Build complete!` and a rebuilt `local-agent/dist/netview-agent-windows.exe`.

- [ ] **Step 4: Verify the frozen exe is windowless and functional**

In an **Administrator** terminal:

```bash
local-agent/dist/netview-agent-windows.exe install --startup auto
local-agent/dist/netview-agent-windows.exe start
sc query NetViewAgent
```

Expected: no window of any kind appears at any point. `sc query` reports `STATE : 4 RUNNING`.

Confirm it is actually serving:

```bash
python -c "
import asyncio, websockets
async def go():
    async with websockets.connect('ws://localhost:8999', origin='http://localhost:3000') as ws:
        print('hello:', (await ws.recv())[:80])
asyncio.run(go())
"
```

Expected: a `hello` message reporting `"version": "2.0.0"`.

Then clean up before continuing:

```bash
local-agent/dist/netview-agent-windows.exe stop
local-agent/dist/netview-agent-windows.exe remove
```

If the service fails to start, read `%ProgramData%\NetView\agent.log` first, then re-run `service_windows.py debug` from source to isolate whether the fault is in the code or the freezing.

- [ ] **Step 5: Commit**

```bash
git add local-agent/netview_agent.spec
git commit -m "$(cat <<'EOF'
build: freeze the service host as a windowless exe

Entry point moves from bootstrap_windows.py to service_windows.py and
console goes to False. Adds hidden imports for our own lazily-imported
modules and for pywin32's service machinery - win32timezone in particular,
whose absence shows up only as a service that refuses to start.

Deletes bootstrap_windows.py: the installer now handles Npcap and the SCM
handles launching.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Installer

**Files:**
- Modify: `local-agent/installer/setup.iss`

**Interfaces:**
- Consumes: the frozen exe's `install` / `start` / `stop` / `remove` subcommands from Task 7.
- Produces: `local-agent/installer/output/NetView-Agent-Setup.exe`, consumed by Task 11.

**Prerequisite:** Inno Setup 6.1 or newer must be installed (`ISCC.exe`). It is **not** present on the current build machine. 6.1 is the floor because this uses `CreateDownloadPage`. Download from https://jrsoftware.org/isdl.php.

- [ ] **Step 1: Rewrite the installer script**

Replace `local-agent/installer/setup.iss` with:

```pascal
; NetView Agent installer
; Build with Inno Setup 6.1 or newer:  iscc setup.iss
;
; Installs the agent as a Windows service that starts at boot and shows no
; UI of any kind. Npcap is downloaded from the official distribution at
; install time rather than bundled: redistributing and silently installing
; the Npcap installer inside a packaged product requires an Npcap OEM
; licence, and downloading it on the user's machine is not redistribution.

#define MyAppName "NetView Agent"
#define MyAppVersion "2.0.0"
#define MyAppExeName "netview-agent-windows.exe"
#define MyAppPublisher "NetView"
#define NpcapUrl "https://npcap.com/dist/npcap-1.79.exe"

[Setup]
AppId={{4C2F8E1A-6B3D-4E9F-8A2C-1D5E7F9A3B6C}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=output
OutputBaseFilename=NetView-Agent-Setup
SetupIconFile=..\icon.ico
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Files]
Source: "..\dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
; Config and log live here. Readable by every user, writable only by admins,
; and present before anyone logs in - which a LocalSystem service needs.
Name: "{commonappdata}\NetView"

[Icons]
Name: "{group}\Uninstall {#MyAppName}"; Filename: "{uninstallexe}"

[Registry]
; --- netview:// custom URI scheme ---
; Vestigial: its purpose was launching a manually-started agent from the
; browser, which an always-running service makes unnecessary. Left registered
; rather than removed, to avoid churn in a file this release already rewrites.
Root: HKCR; Subkey: "netview"; ValueType: string; ValueName: ""; \
    ValueData: "URL:NetView Agent Protocol"; Flags: uninsdeletekey
Root: HKCR; Subkey: "netview"; ValueType: string; ValueName: "URL Protocol"; \
    ValueData: ""; Flags: uninsdeletevalue
Root: HKCR; Subkey: "netview\DefaultIcon"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"",0"
Root: HKCR; Subkey: "netview\shell\open\command"; ValueType: string; ValueName: ""; \
    ValueData: """{app}\{#MyAppExeName}"" ""%1"""

[Run]
Filename: "{tmp}\npcap-installer.exe"; Parameters: "/S /winpcap_mode=no"; \
    StatusMsg: "Installing the Npcap capture driver..."; \
    Check: NeedsNpcap; Flags: waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "install --startup auto"; \
    StatusMsg: "Registering the NetView Agent service..."; \
    Flags: runhidden waituntilterminated
Filename: "{app}\{#MyAppExeName}"; Parameters: "start"; \
    StatusMsg: "Starting the NetView Agent service..."; \
    Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "stop"; \
    Flags: runhidden waituntilterminated; RunOnceId: "StopNetViewAgent"
Filename: "{app}\{#MyAppExeName}"; Parameters: "remove"; \
    Flags: runhidden waituntilterminated; RunOnceId: "RemoveNetViewAgent"

[Code]
var
  DownloadPage: TDownloadWizardPage;

function IsNpcapInstalled: Boolean;
begin
  Result :=
    RegKeyExists(HKLM, 'SOFTWARE\WOW6432Node\Npcap') or
    RegKeyExists(HKLM, 'SOFTWARE\Npcap') or
    FileExists(ExpandConstant('{sys}\Npcap\npcap.sys'));
end;

function NeedsNpcap: Boolean;
begin
  Result := not IsNpcapInstalled;
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

procedure InitializeWizard;
begin
  DownloadPage := CreateDownloadPage(
    SetupMessage(msgWizardPreparing), SetupMessage(msgPreparingDesc), @OnDownloadProgress);
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if (CurPageID = wpReady) and NeedsNpcap then
  begin
    DownloadPage.Clear;
    DownloadPage.Add('{#NpcapUrl}', 'npcap-installer.exe', '');
    DownloadPage.Show;
    try
      try
        DownloadPage.Download;
      except
        // Abort rather than continue: finishing the install would leave a
        // registered service that can never capture anything.
        SuppressibleMsgBox(
          'Could not download the Npcap capture driver.'#13#10#13#10 +
          AddPeriod(GetExceptionMessage) + #13#10#13#10 +
          'Install it manually from https://npcap.com/#download and run this setup again.',
          mbCriticalError, MB_OK, IDOK);
        Result := False;
      end;
    finally
      DownloadPage.Hide;
    end;
  end;
end;

procedure WriteDefaultConfig;
var
  ConfigPath: String;
  Lines: TArrayOfString;
begin
  ConfigPath := ExpandConstant('{commonappdata}\NetView\config.json');
  // Never overwrite an existing config: a reinstall or upgrade must not
  // silently discard a customized origin allowlist.
  if FileExists(ConfigPath) then
    Exit;

  SetArrayLength(Lines, 8);
  Lines[0] := '{';
  Lines[1] := '  "allowedOrigins": [';
  Lines[2] := '    "http://localhost:3000",';
  Lines[3] := '    "http://127.0.0.1:3000",';
  Lines[4] := '    "http://localhost:4173",';
  Lines[5] := '    "http://127.0.0.1:4173"';
  Lines[6] := '  ]';
  Lines[7] := '}';
  SaveStringsToFile(ConfigPath, Lines, False);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
    WriteDefaultConfig;
end;
```

- [ ] **Step 2: Build the installer**

Run: `"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" local-agent/installer/setup.iss`
Expected: `Successful compile` and `local-agent/installer/output/NetView-Agent-Setup.exe` exists.

- [ ] **Step 3: Verify a full install**

Run `local-agent/installer/output/NetView-Agent-Setup.exe` and complete the wizard. Then check every claim it makes:

```bash
sc query NetViewAgent
sc qc NetViewAgent
type "%ProgramData%\NetView\config.json"
```

Expected: `STATE : 4 RUNNING`; `START_TYPE : 2 AUTO_START` and `SERVICE_START_NAME : LocalSystem`; the config file contains the four default origins. **No console window or tray icon appears at any point during or after install.**

- [ ] **Step 4: Verify config preservation on reinstall**

Edit `%ProgramData%\NetView\config.json` to add a distinctive origin (for example `http://localhost:9999`), then run the installer again over the top.

Expected: the edited file is unchanged — the added origin is still there.

- [ ] **Step 5: Verify uninstall**

Uninstall via Settings → Apps, then run: `sc query NetViewAgent`

Expected: `The specified service does not exist as an installed service.` Npcap remains installed (other software may depend on it).

- [ ] **Step 6: Commit**

```bash
git add local-agent/installer/setup.iss
git commit -m "$(cat <<'EOF'
installer: install the agent as an auto-start Windows service

Makes setup.iss the real distribution path. Registers the service as
LocalSystem/auto-start, seeds the default origin config without ever
overwriting an existing one, and stops plus deregisters the service on
uninstall.

Npcap is now downloaded at install time instead of bundled from a redist
folder that never existed in this repo. That fixes the build break and
resolves the OEM licensing caveat this file already carried: downloading
on the user's machine is not redistribution.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Frontend protocol cleanup

**Files:**
- Modify: `src/services/agentProtocol.ts`
- Modify: `scripts/agent-protocol/message-parsing.ts`
- Modify: `scripts/agent-protocol/version-and-commands.ts`
- Delete: `scripts/agent-protocol/token-storage.ts`

**Interfaces:**
- Consumes: nothing from earlier tasks (the wire format is mirrored, not imported).
- Produces: `AgentHelloMessage` without `authRequired`; `AgentCommand` without the `auth` variant; `REQUIRED_AGENT_VERSION === '2.0.0'`. `getStoredPairingToken` / `storePairingToken` / `clearStoredPairingToken` no longer exist.

- [ ] **Step 1: Update the tests first**

In `scripts/agent-protocol/message-parsing.ts`, remove every `authRequired` property from the hello fixtures being parsed, delete any assertion checking `authRequired`, and add these two cases (adapt the surrounding `check(...)` helper calls to the file's existing style):

```typescript
// A hello with no authRequired field must still parse - the field is gone
// from the 2.0.0 protocol entirely.
check(
  'hello parses without authRequired',
  parseAgentMessage(JSON.stringify({
    type: 'hello', version: '2.0.0', state: 'idle',
    interfaces: [{ name: 'eth0', label: 'Ethernet' }],
  }))?.type,
  'hello',
);

// A stray authRequired from an older agent is ignored, not rejected.
check(
  'hello tolerates a leftover authRequired field',
  parseAgentMessage(JSON.stringify({
    type: 'hello', version: '1.1.0', state: 'idle', authRequired: true,
    interfaces: [],
  }))?.type,
  'hello',
);
```

In `scripts/agent-protocol/version-and-commands.ts`, delete any assertion that encodes an `auth` command, and add:

```typescript
check('required agent version is 2.0.0', REQUIRED_AGENT_VERSION, '2.0.0');
check('a 1.1.0 agent is outdated against 2.0.0', isAgentOutdated('1.1.0', '2.0.0'), true);
check('a 2.0.0 agent is current', isAgentOutdated('2.0.0', '2.0.0'), false);
check('a 2.1.0 agent is not outdated', isAgentOutdated('2.1.0', '2.0.0'), false);
```

Delete the token-storage test file:

```bash
git rm scripts/agent-protocol/token-storage.ts
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx tsx scripts/agent-protocol/version-and-commands.ts`
Expected: FAIL — `required agent version is 2.0.0` reports actual `1.1.0`.

- [ ] **Step 3: Update the protocol module**

In `src/services/agentProtocol.ts`:

Update the file's docstring first line to drop the pairing mention:

```typescript
/**
 * The typed WebSocket protocol spoken with the local capture agent
 * (ws://localhost:8999) - message parsing, version comparison, and command
 * encoding. Kept dependency-free and pure so it's testable without a real
 * WebSocket (see scripts/agent-protocol/).
 */
```

Remove `authRequired` from the hello interface:

```typescript
export interface AgentHelloMessage {
  type: 'hello';
  version: string;
  state: 'idle' | 'sniffing';
  interfaces: { name: string; label: string }[];
}
```

Update the `code` comment on `AgentErrorMessage` (the token-related codes are gone):

```typescript
export interface AgentErrorMessage {
  type: 'error';
  message: string;
  // Discriminates why the agent rejected a command - currently only
  // 'empty_interfaces'. Optional, so an agent that sends a bare message
  // still parses.
  code?: string;
}
```

Remove the `authRequired` check from the hello branch of `parseAgentMessage`:

```typescript
    case 'hello':
      if (typeof msg.version !== 'string' || !isValidState(msg.state) || !isValidInterfaceList(msg.interfaces)) return null;
      return msg as unknown as AgentHelloMessage;
```

Bump the version constant:

```typescript
export const REQUIRED_AGENT_VERSION = '2.0.0';
```

Drop the `auth` variant from the command union:

```typescript
export type AgentCommand =
  | { type: 'start_capture' }
  | { type: 'stop_capture' }
  | { type: 'set_interfaces'; interfaces: string[] };
```

**Delete** the `PAIRING_TOKEN_STORAGE_KEY` constant and all three of `getStoredPairingToken`, `storePairingToken`, and `clearStoredPairingToken`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `npx tsx scripts/agent-protocol/message-parsing.ts && npx tsx scripts/agent-protocol/version-and-commands.ts`
Expected: both print `All checks passed.`

- [ ] **Step 5: Commit**

Note `npm run lint` will still fail here, because `App.tsx` and `Header.tsx` continue to reference the removed exports until Task 10. That is expected — commit anyway so the protocol change is reviewable on its own, and Task 10 restores a green type-check.

```bash
git add src/services/agentProtocol.ts scripts/agent-protocol/
git commit -m "$(cat <<'EOF'
frontend: drop pairing from the agent protocol module

Removes the auth command, the authRequired hello field and the localStorage
token helpers, and moves REQUIRED_AGENT_VERSION to 2.0.0 to match the agent.

tsc will not pass until the next task removes the App/Header call sites.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Remove the pairing UI

**Files:**
- Modify: `src/App.tsx`
- Modify: `src/components/common/Header.tsx`

**Interfaces:**
- Consumes: `AgentCommand`, `parseAgentMessage`, `encodeAgentCommand`, `isAgentOutdated`, `REQUIRED_AGENT_VERSION` from Task 9.
- Produces: a `Header` whose props no longer include `pairingRequired` or `onSubmitPairingToken`.

**Context the implementer needs:** `<AppMenu>` is rendered **only inside `Header.tsx`**, never directly by `App.tsx`. Verify with `grep -n "<AppMenu" src/App.tsx src/components/common/Header.tsx` before assuming otherwise. Nothing in this task changes AppMenu, but the prop chain runs App → Header → AppMenu and it is easy to mis-target.

- [ ] **Step 1: Strip pairing from App.tsx**

In `src/App.tsx`:

Update the import on line 19 to drop the three token helpers:

```typescript
import { parseAgentMessage, encodeAgentCommand, isAgentOutdated, REQUIRED_AGENT_VERSION, type AgentCommand } from "./services/agentProtocol";
```

Delete the `pairingRequired` state declaration (`const [pairingRequired, setPairingRequired] = useState(false);`) and the `pendingAuthAckRef` declaration (`const pendingAuthAckRef = useRef(false);`).

In `socket.onopen`, delete the stored-token block entirely:

```typescript
        const storedToken = getStoredPairingToken();
        if (storedToken) {
          pendingAuthAckRef.current = true;
          socket.send(encodeAgentCommand({ type: 'auth', token: storedToken }));
        }
```

Replace the whole `hello` branch with this version, which takes over the reconnect resync that used to hang off the post-auth `state` message:

```typescript
        if (message.type === 'hello') {
          if (helloTimeout) {
            clearTimeout(helloTimeout);
            helloTimeout = null;
          }
          setAgentIncompatible(false);
          setAgentVersion(message.version);
          setAgentCaptureState(message.state);
          setAgentInterfaces(message.interfaces);
          setSelectedInterfaces((prev) => (prev.length > 0 ? prev : message.interfaces.map((i) => i.name)));

          // Reconnect resync. A fresh connection always finds the agent idle
          // with every interface selected - it stops capturing when the last
          // client drops - so push our desired state back to it. Phase 1 hung
          // this off the post-auth `state` message; with pairing gone, `hello`
          // is the only per-connection signal there is.
          //
          // On a first-ever connection selectedInterfacesRef is still empty
          // (it gets populated from this very message), so nothing is sent and
          // the agent keeps its own default of every interface. That is correct.
          if (selectedInterfacesRef.current.length > 0) {
            socket.send(encodeAgentCommand({ type: 'set_interfaces', interfaces: selectedInterfacesRef.current }));
          }
          if (isCapturingRef.current) {
            socket.send(encodeAgentCommand({ type: 'start_capture' }));
          }
          return;
        }
```

(Note this sends on `socket` directly rather than through `sendAgentCommand`, matching how `onopen` already worked — the handler closes over the exact socket it was attached to, which avoids a rapid-reconnect race where `wsRef.current` could already point at a newer socket.)

Replace the `state` branch with the version that no longer waits on an auth ack:

```typescript
        if (message.type === 'state') {
          setAgentCaptureState(message.state);
          setAgentInterfaces(message.interfaces);
          return;
        }
```

Replace the `error` branch, dropping the `invalid_token` handling:

```typescript
        if (message.type === 'error') {
          console.warn('[WirePulse] Agent error:', message.message);
          return;
        }
```

In the `<Header ... />` render, delete both the `pairingRequired={pairingRequired}` line and the entire `onSubmitPairingToken={...}` prop block (lines 596-602).

Finally, check whether `selectedInterfacesRef` is still used anywhere after these edits — it is, by the new `hello` branch, so leave its declaration and the effect that keeps it current in place.

- [ ] **Step 2: Strip pairing from Header.tsx**

In `src/components/common/Header.tsx`:

Revert the React import (the only `useState` use was `PairingPrompt`):

```typescript
import React from 'react';
```

**Delete** the entire `PairingPrompt` component (lines 42-64).

Remove these two props from the `HeaderProps` interface:

```typescript
  pairingRequired: boolean;
  onSubmitPairingToken: (token: string) => void;
```

Remove `pairingRequired,` and `onSubmitPairingToken,` from the destructured parameter list.

Delete the render block at the end of the right-hand column:

```tsx
        {pairingRequired && (
          <PairingPrompt onSubmit={onSubmitPairingToken} />
        )}
```

- [ ] **Step 3: Type-check**

Run: `npm run lint`
Expected: PASS with no output. If it reports unused variables, remove them — they are leftovers from the deletions above.

- [ ] **Step 4: Verify end to end in the browser**

Start the agent (Administrator): `python local-agent/agent.py`
Start the dev server: `npm run dev`
Open http://localhost:3000.

Expected:
- The status pill reads **Agent Connected** (green), with no "Agent Outdated" amber state and no pairing-code input anywhere in the header.
- Clicking **Start Capture** produces packets, and the agent's log records the capture starting.
- Clicking **Stop Capture** stops them, and the agent logs the stop.
- Closing the browser tab makes the agent log `last client disconnected - stopping capture`.

- [ ] **Step 5: Commit**

```bash
git add src/App.tsx src/components/common/Header.tsx
git commit -m "$(cat <<'EOF'
frontend: remove the pairing prompt and auth handshake

The origin check happens during the WebSocket handshake now, so there is no
second authentication step for the UI to represent.

Reconnect resync moves from the post-auth state message to hello, which is
the only per-connection signal left. It matters more than before: the agent
stops capturing when the last client disconnects, so a reconnecting tab
always finds it idle.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Serve the installer and update the docs

**Files:**
- Modify: `src/services/platformDetect.ts`
- Modify: `CLAUDE.md`

**Interfaces:**
- Consumes: `local-agent/installer/output/NetView-Agent-Setup.exe` from Task 8.
- Produces: nothing consumed downstream.

- [ ] **Step 1: Point the Windows download at the installer**

In `src/services/platformDetect.ts`, replace the `windows` entry of `AGENT_DOWNLOADS`:

```typescript
  windows: {
    // The Inno Setup installer, not the bare exe: the bare exe is a service
    // host that installs nothing when double-clicked (see the agent
    // background-service spec).
    url: '/downloads/NetView-Agent-Setup.exe',
    filename: 'NetView-Agent-Setup.exe',
    label: 'Windows',
  },
```

Leave the `macos` and `linux` entries exactly as they are.

- [ ] **Step 2: Publish the built installer**

```bash
cp local-agent/installer/output/NetView-Agent-Setup.exe public/downloads/NetView-Agent-Setup.exe
rm -f public/downloads/netview-agent-windows.exe
```

`public/downloads/` is not tracked in git (see CLAUDE.md), so there is nothing to stage from this step.

- [ ] **Step 3: Verify the download button**

With `npm run dev` running, open http://localhost:3000, open the app menu, and click **Download Driver**.

Expected: the browser downloads `NetView-Agent-Setup.exe`, not `netview-agent-windows.exe`.

- [ ] **Step 4: Verify the outdated-agent path still works**

The spec requires that the outdated-agent state stay reachable and point at
the installer, since a 1.x agent can never satisfy a 2.0.0 webapp. The
pairing UI was removed from the same header — confirm this was not removed
with it.

Temporarily edit `local-agent/agent.py` to `AGENT_VERSION = "1.0.0"`, restart
the agent, and reload the page.

Expected: the status pill turns amber and reads **Agent Outdated**, and the
app menu's **Download Driver** item shows its amber **Update** badge.
Clicking it downloads `NetView-Agent-Setup.exe`.

**Revert `AGENT_VERSION` to `"2.0.0"` immediately afterwards** and confirm
`python local-agent/test_protocol.py` passes again — that file asserts the
version.

- [ ] **Step 5: Update the project documentation**

In `CLAUDE.md`, replace the `### Local capture agent (local-agent/)` section body with:

```markdown
This is a separate Python project, not built by the npm scripts:
- `pip install -r local-agent/requirements.txt` (scapy, websockets, pyinstaller, pywin32 on Windows)
- `python local-agent/agent.py` (run as Administrator/root — raw packet capture requires elevation on every OS). On Windows this development path needs Npcap installed already; the installer normally handles that, so install it from https://npcap.com/#download if you haven't run the installer.
- The agent speaks a typed WebSocket protocol (`hello`/`state`/`error`/`packet` from the agent; `start_capture`/`stop_capture`/`set_interfaces` to it) and starts **idle** — it only sniffs once a client sends `start_capture`, and stops again when the last client disconnects.
- Browsers are authenticated by **origin**, not a token: a connection whose `Origin` header isn't listed in `%ProgramData%\NetView\config.json` is rejected with a 403 during the handshake. Defaults cover localhost:3000 and localhost:4173. The file is re-read per connection, so adding an origin needs no restart.
- Logs go to `%ProgramData%\NetView\agent.log` (rotating). When the agent runs as a service there is no console, so this is the only place to look.

**Windows distribution** — the agent ships as a Windows service, installed once and thereafter invisible (no console, no tray icon, no UAC prompt):
- `pyinstaller local-agent/netview_agent.spec` builds `local-agent/dist/netview-agent-windows.exe` — the service host, entry point `service_windows.py`, built with `console=False`. It accepts `install` / `remove` / `start` / `stop` / `debug`; `debug` runs the service body in the foreground and is the practical way to iterate on it.
- `iscc local-agent/installer/setup.iss` (Inno Setup 6.1+) wraps that into `local-agent/installer/output/NetView-Agent-Setup.exe`, which downloads Npcap if missing, registers the `NetViewAgent` service as LocalSystem/auto-start, and seeds the config. Copy that installer into `public/downloads/` for the web app to serve.
- macOS and Linux keep the manual-launch bootstrap scripts (`bootstrap_macos.command`, `bootstrap_linux.sh`); the service model is Windows-only.
- Neither `local-agent/dist/` nor `public/downloads/` is tracked in git (rebuild rather than editing binaries).
```

Also update the **Data flow** paragraph's first sentence to reflect that capture is now controlled rather than automatic:

```markdown
`local-agent/agent.py` (Scapy sniff → JSON over WebSocket, idle until told to start) → `App.tsx`'s always-on WebSocket client (auto-reconnects every 3s, tracks `agentStatus` independent of whether capture is active) → ...
```

- [ ] **Step 6: Commit**

```bash
git add src/services/platformDetect.ts CLAUDE.md
git commit -m "$(cat <<'EOF'
Serve the service installer and document the new agent model

The Download Driver button offered the bare PyInstaller exe, which after
the service change installs nothing when double-clicked. It now serves
NetView-Agent-Setup.exe.

CLAUDE.md gains the service build/distribution steps, the origin-allowlist
auth model, the log location, and the idle-by-default capture lifecycle.

Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>
EOF
)"
```

---

## Final verification

After all tasks, run the complete check set:

```bash
python local-agent/test_protocol.py
npx tsx scripts/agent-protocol/message-parsing.ts
npx tsx scripts/agent-protocol/version-and-commands.ts
npm run lint
```

All four must pass. Then confirm the manual acceptance criteria from the spec on a real machine:

1. Install via `NetView-Agent-Setup.exe`; **no window of any kind appears**, and `sc query NetViewAgent` shows RUNNING with AUTO_START/LocalSystem.
2. Reboot; the service is running before any login.
3. Open NetView; it connects, shows **Agent Connected**, and capture works.
4. Close the tab; `agent.log` records `last client disconnected - stopping capture`.
5. A page from a disallowed origin is refused with 403 and the rejection is logged.
6. Uninstall; the service is stopped and deregistered.
