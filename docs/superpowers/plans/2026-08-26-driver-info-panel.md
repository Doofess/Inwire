# Driver Info Panel Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a Driver Info section to the Settings modal that shows agent status, version, capture state, and listening adapters, alongside a live view of the agent's own log streamed over the WebSocket.

**Architecture:** Two new protocol commands (`subscribe_logs` / `unsubscribe_logs`) and one new agent→app message (`log`). The agent serves a 200-line backlog by reading the tail of `agent.log`, then forwards each new line live through a `logging.Handler` installed on the `netview` logger. Log plumbing lives in a new `local-agent/agent_log.py` module so it is testable without a socket, mirroring how `config.py` and `logging_setup.py` are already split out of `agent.py`.

**Tech Stack:** Python 3 (websockets 17.0.1, stdlib `logging`), React 19 + TypeScript, Tailwind v4, motion/react, react-icons/tb.

**Spec:** `docs/superpowers/specs/2026-08-26-driver-info-panel-design.md`

## Global Constraints

- Agent protocol version moves `2.0.0` → `2.1.0`, and must be identical in all three locations: `AGENT_VERSION` in `local-agent/agent.py`, `REQUIRED_AGENT_VERSION` in `src/services/agentProtocol.ts`, `MyAppVersion` in `local-agent/installer/setup.iss`. `python local-agent/test_protocol.py` enforces this.
- There is no test framework in this repo. Both suites are plain assertion scripts with a module-level `failures` counter, a `check(name, actual, expected)` / `check_true(name, condition)` helper, and `sys.exit(1)` / `process.exit(1)` at the end. Do not introduce pytest, vitest, or jest.
- Python tests: `python local-agent/test_protocol.py`. TypeScript tests: `npx tsx scripts/agent-protocol/message-parsing.ts` and `npx tsx scripts/agent-protocol/version-and-commands.ts`. Type check: `npm run lint` (which is `tsc --noEmit`).
- Backlog is at most **200 lines**, read from at most the last **64 KB** of the file. The app-side buffer caps at **1000 entries**, oldest dropped first.
- A missing or unreadable log file is never an error: the agent sends an empty `lines` array.
- The log message shape is `{ "type": "log", "lines": [ { "time": <string|null>, "level": <string|null>, "message": <string> } ] }`. The same shape carries both backlog (many entries) and live lines (one entry).
- Never commit `src/components/common/FilterBar.tsx`. It holds an unrelated pre-existing uncommitted styling change that must be preserved untouched.
- Every `git add` must name explicit paths. Never use `git add -A` or `git add .`.

---

## File Structure

| File | Responsibility |
|---|---|
| `local-agent/agent_log.py` (new) | Pure log plumbing: parse one formatted log line into a protocol entry, read the tail of the log file, and the `logging.Handler` that forwards live records to a sink. No WebSocket, no agent globals. |
| `local-agent/agent.py` (modify) | Wires the above into the server: subscriber set, `subscribe_logs`/`unsubscribe_logs` handling, log fan-out, disconnect cleanup, handler installation in `main()`. |
| `local-agent/test_protocol.py` (modify) | Assertions for everything in `agent_log.py` plus the new `AgentServer` behavior. |
| `local-agent/verify_protocol.py` (modify) | Live end-to-end check against a running agent. |
| `local-agent/installer/setup.iss` (modify) | Version bump only. |
| `src/services/agentProtocol.ts` (modify) | `AgentLogEntry` / `AgentLogMessage` types, `log` parsing, the two new commands, version bump. |
| `scripts/agent-protocol/*.ts` (modify) | Assertions for the above. |
| `src/App.tsx` (modify) | Owns the `agentLog` buffer and the subscribe/unsubscribe/resubscribe wiring. |
| `src/components/common/DriverInfoPanel.tsx` (new) | Presentational: status block + log pane. Owns no agent state; everything arrives as props. |
| `src/components/common/SettingsModal.tsx` (modify) | Gains a two-section sidebar and hosts the panel. |
| `CLAUDE.md` (modify) | Documents the new protocol messages. |

---

### Task 1: Version bump to 2.1.0

Done first and alone so every later task starts from a green three-way version check. This task changes no behavior.

**Files:**
- Modify: `local-agent/agent.py:57`
- Modify: `src/services/agentProtocol.ts:87`
- Modify: `local-agent/installer/setup.iss:16`
- Test: `scripts/agent-protocol/version-and-commands.ts:35-38`

**Interfaces:**
- Consumes: nothing.
- Produces: `AGENT_VERSION = "2.1.0"`, `REQUIRED_AGENT_VERSION = '2.1.0'`, `MyAppVersion "2.1.0"`.

- [ ] **Step 1: Update the TypeScript version assertions to the new expected values**

In `scripts/agent-protocol/version-and-commands.ts`, replace lines 35-38 with:

```typescript
check('required agent version is 2.1.0', REQUIRED_AGENT_VERSION, '2.1.0');
check('a 1.1.0 agent is outdated against 2.1.0', isAgentOutdated('1.1.0', '2.1.0'), true);
check('a 2.0.0 agent is outdated against 2.1.0', isAgentOutdated('2.0.0', '2.1.0'), true);
check('a 2.1.0 agent is current', isAgentOutdated('2.1.0', '2.1.0'), false);
check('a 2.2.0 agent is not outdated', isAgentOutdated('2.2.0', '2.1.0'), false);
```

- [ ] **Step 2: Run both suites to verify they now fail**

```bash
npx tsx scripts/agent-protocol/version-and-commands.ts
python local-agent/test_protocol.py
```

Expected: the TypeScript suite FAILS on `required agent version is 2.1.0` (actual `2.0.0`). The Python suite still PASSES at this point — all three files still say `2.0.0`, which is self-consistent.

- [ ] **Step 3: Bump all three version locations**

`local-agent/agent.py` line 57:

```python
AGENT_VERSION = "2.1.0"
```

`src/services/agentProtocol.ts` line 87:

```typescript
export const REQUIRED_AGENT_VERSION = '2.1.0';
```

`local-agent/installer/setup.iss` line 16:

```pascal
#define MyAppVersion "2.1.0"
```

- [ ] **Step 4: Run both suites to verify they pass**

```bash
npx tsx scripts/agent-protocol/version-and-commands.ts
python local-agent/test_protocol.py
```

Expected: both PASS. The Python suite's three-way sync check confirms all three files agree on `2.1.0`.

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent.py src/services/agentProtocol.ts local-agent/installer/setup.iss scripts/agent-protocol/version-and-commands.ts
git commit -m "agent: bump protocol to 2.1.0 for log streaming"
```

---

### Task 2: Log line parsing and tail reading

**Files:**
- Create: `local-agent/agent_log.py`
- Test: `local-agent/test_protocol.py` (append before the final `print()` / `if failures:` block at the end of the file)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `agent_log.parse_log_line(raw: str) -> dict` returning `{"time": str|None, "level": str|None, "message": str}`
  - `agent_log.read_log_tail(path: str, max_lines: int = 200, max_bytes: int = 65536) -> list[str]` returning raw line strings, oldest first
  - `agent_log.BACKLOG_LINES = 200`, `agent_log.BACKLOG_BYTES = 65536`

- [ ] **Step 1: Write the failing tests**

Append to `local-agent/test_protocol.py`, immediately **before** the trailing `print()` / `if failures:` block:

```python
# --- agent log: line parsing ---
import agent_log

check(
    "parse_log_line splits a well-formed INFO line",
    agent_log.parse_log_line("2026-08-26 22:14:02,123 INFO    client connected (1 total)"),
    {"time": "2026-08-26 22:14:02,123", "level": "INFO", "message": "client connected (1 total)"},
)
check(
    "parse_log_line handles a level whose name is longer than the padding",
    agent_log.parse_log_line("2026-08-26 22:14:02,123 CRITICAL scapy is not installed"),
    {"time": "2026-08-26 22:14:02,123", "level": "CRITICAL", "message": "scapy is not installed"},
)
check(
    "parse_log_line keeps a traceback continuation line intact rather than dropping it",
    agent_log.parse_log_line('  File "agent.py", line 42, in main'),
    {"time": None, "level": None, "message": '  File "agent.py", line 42, in main'},
)
check(
    "parse_log_line handles an empty line",
    agent_log.parse_log_line(""),
    {"time": None, "level": None, "message": ""},
)
# agent.py logs its interface list with two leading spaces per line
# (log.info("  %s -> %s", ...)). With "INFO" padded to 7 and one separator
# space, those two spaces sit at the end of a six-space run - a greedy \s+
# would eat them along with the padding and silently flatten the startup
# banner. This is the regression test for that.
check(
    "parse_log_line preserves a message's own leading indentation",
    agent_log.parse_log_line("2026-08-26 22:14:02,123 INFO      Wi-Fi -> \\Device\\NPF_{GUID}"),
    {"time": "2026-08-26 22:14:02,123", "level": "INFO", "message": "  Wi-Fi -> \\Device\\NPF_{GUID}"},
)

# --- agent log: tail reading ---
_log_dir = tempfile.mkdtemp()
_log_file = os.path.join(_log_dir, "agent.log")

with open(_log_file, "w", encoding="utf-8") as fh:
    for i in range(10):
        fh.write(f"2026-08-26 22:14:{i:02d},000 INFO    line {i}\n")

_tail = agent_log.read_log_tail(_log_file, max_lines=200)
check("read_log_tail returns every line of a short file", len(_tail), 10)
check("read_log_tail returns lines oldest first", _tail[0].endswith("line 0"), True)
check("read_log_tail's last entry is the newest line", _tail[-1].endswith("line 9"), True)

_tail_3 = agent_log.read_log_tail(_log_file, max_lines=3)
check("read_log_tail caps at max_lines", len(_tail_3), 3)
check("read_log_tail keeps the NEWEST lines when capping", _tail_3[-1].endswith("line 9"), True)
check("read_log_tail drops the oldest lines when capping", _tail_3[0].endswith("line 7"), True)

# A byte window that lands mid-line must not emit a truncated fragment.
_tail_bytes = agent_log.read_log_tail(_log_file, max_lines=200, max_bytes=60)
check_true(
    "read_log_tail discards the partial line its byte window started in",
    all(line.startswith("2026-") for line in _tail_bytes),
)
check_true("read_log_tail honours the byte window", 0 < len(_tail_bytes) < 10)

check("read_log_tail on a missing file returns []", agent_log.read_log_tail(os.path.join(_log_dir, "nope.log")), [])
check("read_log_tail on a directory path returns []", agent_log.read_log_tail(_log_dir), [])

# Undecodable bytes must not take down a subscribe - errors="replace", not an exception.
_binary_file = os.path.join(_log_dir, "binary.log")
with open(_binary_file, "wb") as fh:
    fh.write(b"2026-08-26 22:14:02,123 INFO    caf\xe9 not utf-8\n")
_binary_tail = agent_log.read_log_tail(_binary_file)
check("read_log_tail survives undecodable bytes", len(_binary_tail), 1)
check_true("read_log_tail replaces undecodable bytes rather than raising", "not utf-8" in _binary_tail[0])

_empty_file = os.path.join(_log_dir, "empty.log")
open(_empty_file, "w", encoding="utf-8").close()
check("read_log_tail on an empty file returns []", agent_log.read_log_tail(_empty_file), [])
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python local-agent/test_protocol.py
```

Expected: FAIL with `ModuleNotFoundError: No module named 'agent_log'`.

- [ ] **Step 3: Create the module**

Create `local-agent/agent_log.py`:

```python
#!/usr/bin/env python3
"""
Turning the agent's own log into something a browser can display.

The agent runs as a LocalSystem service writing to
%ProgramData%\\NetView\\agent.log, a path no browser page can read. This
module holds the two halves of getting those lines onto the WebSocket -
reading the tail of the file for backlog, and a logging.Handler that
forwards each new record live - with no reference to the socket or to
agent.py's globals, so all of it is testable on its own.
"""

import logging
import os
import re
import threading

# Mirrors logging_setup's formatter, "%(asctime)s %(levelname)-7s %(message)s":
#   2026-08-26 22:14:02,123 INFO    client connected (1 total)
#
# Everything after the level is captured raw, because the separator's width
# is not fixed and cannot be matched greedily. levelname is left-justified to
# LEVEL_FIELD_WIDTH and then followed by one literal space, so "INFO" is
# trailed by four spaces while "CRITICAL" - which overflows the field - is
# trailed by one. Consuming that run with \s+ would also swallow a message's
# own leading indentation, and agent.py logs indented lines on purpose (the
# per-interface lines at startup). parse_log_line strips exactly the
# computed width instead, which is reversible; a greedy match is not.
LOG_LINE_RE = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) "
    r"(?P<level>[A-Z]+)"
    r"(?P<rest>.*)$"
)

# The `-7` in logging_setup's "%(levelname)-7s".
LEVEL_FIELD_WIDTH = 7

BACKLOG_LINES = 200
# Rotation lets agent.log reach 1 MB; a subscriber needs the recent end of
# it, and the socket should not carry the rest.
BACKLOG_BYTES = 65536


def parse_log_line(raw):
    """One raw line of agent.log -> one protocol log entry.

    A line that does not match the formatter's shape - a traceback
    continuation line, most often - is not dropped. It comes back with
    time and level None and its text preserved, because the lines
    around a crash are precisely the ones worth reading.
    """
    match = LOG_LINE_RE.match(raw)
    if match is None:
        return {"time": None, "level": None, "message": raw}
    level = match.group("level")
    # The padding the formatter added, plus its one literal separator space.
    # max(0, ...) because a level longer than the field (CRITICAL) is not
    # padded at all, and a negative slice offset would eat real characters.
    separator_width = max(0, LEVEL_FIELD_WIDTH - len(level)) + 1
    return {
        "time": match.group("time"),
        "level": level,
        "message": match.group("rest")[separator_width:],
    }


def read_log_tail(path, max_lines=BACKLOG_LINES, max_bytes=BACKLOG_BYTES):
    """The last `max_lines` lines of the log file, oldest first.

    Every failure mode returns [] rather than raising: a missing or
    unreadable log must not stop a client subscribing, it just means the
    panel starts empty and fills from live lines instead.
    """
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                # That seek almost certainly landed mid-line. Without this
                # read, the first entry would be a truncated fragment
                # displayed as though it were a whole line.
                fh.readline()
            data = fh.read()
    except OSError:
        return []

    # errors="replace" rather than a decode failure: a single bad byte
    # anywhere in the window must not cost the user their whole backlog.
    lines = data.decode("utf-8", errors="replace").splitlines()
    return lines[-max_lines:]
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python local-agent/test_protocol.py
```

Expected: PASS, ending in `All checks passed.`

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent_log.py local-agent/test_protocol.py
git commit -m "agent: add log line parsing and tail reading"
```

---

### Task 3: The live log handler

**Files:**
- Modify: `local-agent/agent_log.py`
- Test: `local-agent/test_protocol.py` (append before the final `print()` / `if failures:` block)

**Interfaces:**
- Consumes: `agent_log` module from Task 2.
- Produces: `agent_log.WebSocketLogHandler(sink, level=logging.INFO)`, a `logging.Handler` subclass whose `emit(record)` calls `sink(entry)` with an entry dict of the same `{"time", "level", "message"}` shape `parse_log_line` produces.

- [ ] **Step 1: Write the failing tests**

Append to `local-agent/test_protocol.py`, before the trailing `print()` / `if failures:` block:

```python
# --- agent log: live handler ---
_captured = []
_handler_logger = logging.getLogger("netview.test.handler")
_handler_logger.setLevel(logging.INFO)
_handler_logger.propagate = False
_handler = agent_log.WebSocketLogHandler(_captured.append)
_handler_logger.addHandler(_handler)

_handler_logger.info("hello %s", "world")
check("handler forwards one entry per record", len(_captured), 1)
check("handler applies logging's % args", _captured[0]["message"], "hello world")
check("handler reports the record's level", _captured[0]["level"], "INFO")
check_true(
    "handler's timestamp matches the log file format",
    agent_log.LOG_LINE_RE.match(f"{_captured[0]['time']} INFO    x") is not None,
)

_handler_logger.warning("careful")
check("handler forwards a second record", len(_captured), 2)
check("handler reports WARNING", _captured[1]["level"], "WARNING")

# A sink that logs re-enters emit(). Without the guard this recurses until
# the stack blows; with it, the nested record is dropped and the original
# call returns normally.
_recursive = []


def _recursive_sink(entry):
    _recursive.append(entry)
    _handler_logger.error("the sink itself failed")


_handler_logger.removeHandler(_handler)
_recursive_handler = agent_log.WebSocketLogHandler(_recursive_sink)
_handler_logger.addHandler(_recursive_handler)
_handler_logger.info("trigger")
check("reentrancy guard stops the sink's own logging from recursing", len(_recursive), 1)
check("reentrancy guard lets the original entry through", _recursive[0]["message"], "trigger")

# The guard must reset, or the handler would forward exactly one line ever.
_handler_logger.info("after recursion")
check("reentrancy guard resets between records", len(_recursive), 2)

# A raising sink must not propagate into whatever called log.info().
_handler_logger.removeHandler(_recursive_handler)


def _raising_sink(entry):
    raise RuntimeError("sink exploded")


_raising_handler = agent_log.WebSocketLogHandler(_raising_sink)
_raising_handler.handleError = lambda record: None  # silence the stderr report
_handler_logger.addHandler(_raising_handler)
_raised = False
try:
    _handler_logger.info("this must not raise")
except Exception:
    _raised = True
check("a raising sink never propagates into the caller", _raised, False)
_handler_logger.removeHandler(_raising_handler)
```

Add `import logging` to the imports at the top of `local-agent/test_protocol.py` (the file currently imports `asyncio`, `os`, `re`, `sys`, `tempfile`).

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python local-agent/test_protocol.py
```

Expected: FAIL with `AttributeError: module 'agent_log' has no attribute 'WebSocketLogHandler'`.

- [ ] **Step 3: Add the handler**

Append to `local-agent/agent_log.py`:

```python
# A bare Formatter purely for its formatTime(): with no datefmt it produces
# "%Y-%m-%d %H:%M:%S,%03d", byte-identical to what logging_setup writes into
# the file, so backlog entries and live entries carry the same time format.
_TIME_FORMATTER = logging.Formatter()


class WebSocketLogHandler(logging.Handler):
    """Forwards every log record to `sink` as a protocol log entry.

    Installed on the `netview` logger, this delivers each line the instant
    it is logged - no polling, no file-position bookkeeping, and nothing a
    RotatingFileHandler rollover mid-session can desync. It also keeps
    working when the log file itself is unwritable, which is the case where
    seeing the log matters most.

    `sink` is expected to be cheap and non-blocking: the real one returns
    immediately when nobody is subscribed.
    """

    def __init__(self, sink, level=logging.INFO):
        super().__init__(level)
        self.sink = sink
        # Thread-local rather than a plain attribute: sniffer threads log
        # concurrently with the asyncio loop, and one shared flag would let
        # one thread's guard swallow another thread's legitimate line.
        self._local = threading.local()

    def emit(self, record):
        # Any log call reachable from the sink re-enters emit(), which calls
        # the sink again, unboundedly. Nothing on today's send path logs, but
        # one warning added there later would produce an infinite loop with
        # no obvious cause. This makes that structurally impossible instead
        # of relying on nobody ever adding it.
        if getattr(self._local, "emitting", False):
            return
        self._local.emitting = True
        try:
            self.sink({
                "time": _TIME_FORMATTER.formatTime(record),
                "level": record.levelname,
                "message": record.getMessage(),
            })
        except Exception:
            # A logging handler must never raise into the code that logged.
            # handleError already no-ops when there is no stderr, which under
            # the console=False service build is always.
            self.handleError(record)
        finally:
            self._local.emitting = False
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python local-agent/test_protocol.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add local-agent/agent_log.py local-agent/test_protocol.py
git commit -m "agent: forward live log records through a guarded handler"
```

---

### Task 4: Wire log streaming into the agent server

**Files:**
- Modify: `local-agent/agent.py` (import block near line 59; `AgentServer.__init__` line 212-218; `handle_disconnect` line 236-251; `_handle_message` line 253-287; `_send_all` line 296-308; `main()` line 462)
- Test: `local-agent/test_protocol.py` (append before the final `print()` / `if failures:` block)

**Interfaces:**
- Consumes: `agent_log.parse_log_line`, `agent_log.read_log_tail`, `agent_log.WebSocketLogHandler` from Tasks 2-3.
- Produces:
  - `AgentServer.log_subscribers` — a `set` of sockets
  - `AgentServer.broadcast_log(entry: dict) -> None` — the sink passed to `WebSocketLogHandler`
  - `AgentServer.log_file_path() -> str`

- [ ] **Step 1: Write the failing tests**

Append to `local-agent/test_protocol.py`, before the trailing `print()` / `if failures:` block:

```python
# --- agent log: server wiring ---
class RecordingWS:
    """Captures what the server sent, instead of writing to a socket."""

    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


_prev_sniffer = getattr(agent, "sniffer", None)
_prev_interfaces = getattr(agent, "AVAILABLE_INTERFACES", None)
try:
    agent.sniffer = agent.SnifferController(default_interfaces=["eth0"])
    agent.AVAILABLE_INTERFACES = [("eth0", "Ethernet")]
    srv = agent.AgentServer()
    ws = RecordingWS()

    check("a fresh server has no log subscribers", len(srv.log_subscribers), 0)

    asyncio.run(srv._handle_message(ws, json.dumps({"type": "subscribe_logs"})))
    check("subscribe_logs registers the socket", ws in srv.log_subscribers, True)
    check("subscribe_logs sends exactly one message", len(ws.sent), 1)
    check("subscribe_logs replies with a log message", ws.sent[0]["type"], "log")
    check_true("subscribe_logs backlog is a list", isinstance(ws.sent[0]["lines"], list))
    check_true(
        "backlog entries carry the protocol shape",
        all(set(e) == {"time", "level", "message"} for e in ws.sent[0]["lines"]),
    )

    # Subscribing must not touch capture state or broadcast a state message.
    check("subscribe_logs does not start capture", agent.sniffer.is_sniffing(), False)
    check("subscribe_logs sends no state message", [m for m in ws.sent if m["type"] == "state"], [])

    asyncio.run(srv._handle_message(ws, json.dumps({"type": "unsubscribe_logs"})))
    check("unsubscribe_logs deregisters the socket", ws in srv.log_subscribers, False)
    check("unsubscribe_logs sends nothing further", len(ws.sent), 1)

    # Unsubscribing when not subscribed must be a no-op, not an error.
    asyncio.run(srv._handle_message(ws, json.dumps({"type": "unsubscribe_logs"})))
    check("repeat unsubscribe is harmless", len(srv.log_subscribers), 0)

    # A dropped connection must not leave a subscriber behind. A socket
    # stuck in log_subscribers is the same leak class as the register()
    # handshake leak: it would keep the fan-out trying to write to a dead
    # socket forever.
    srv.connections.add(ws)
    srv.log_subscribers.add(ws)
    srv.handle_disconnect(ws)
    check("disconnect clears the connection", ws in srv.connections, False)
    check("disconnect clears the log subscription", ws in srv.log_subscribers, False)

    # broadcast_log must be free when nobody is watching.
    srv.loop = None
    srv.broadcast_log({"time": None, "level": "INFO", "message": "nobody is listening"})
    check("broadcast_log with no subscribers is a no-op", len(srv.log_subscribers), 0)

    check_true("log_file_path ends in agent.log", srv.log_file_path().endswith("agent.log"))
finally:
    if _prev_sniffer is None:
        if hasattr(agent, "sniffer"):
            del agent.sniffer
    else:
        agent.sniffer = _prev_sniffer
    if _prev_interfaces is None:
        if hasattr(agent, "AVAILABLE_INTERFACES"):
            del agent.AVAILABLE_INTERFACES
    else:
        agent.AVAILABLE_INTERFACES = _prev_interfaces
```

Add `import json` to the imports at the top of `local-agent/test_protocol.py`.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
python local-agent/test_protocol.py
```

Expected: FAIL with `AttributeError: 'AgentServer' object has no attribute 'log_subscribers'`.

- [ ] **Step 3: Wire it into `agent.py`**

**3a.** Next to the existing `import logging_setup` (line 59), add:

```python
import agent_log
```

**3b.** In `AgentServer.__init__` (line 212), add after `self.connections = set()`:

```python
        # Sockets that asked for log lines, always a subset of connections.
        # Separate from connections because the common case is a client that
        # never opens Driver Info at all, and log fan-out should cost nothing
        # for those.
        self.log_subscribers = set()
```

**3c.** In `handle_disconnect` (line 247), directly after `self.connections.discard(ws)`:

```python
        # A socket left here after its connection died would make the log
        # fan-out write to a dead socket on every line, forever.
        self.log_subscribers.discard(ws)
```

**3d.** In `_handle_message`, **replace** the existing trailing two lines

```python
        else:
            return
```

with the block below. It adds two branches ahead of that `else` and keeps the `else` itself — do not leave the original `else` in place as well, or the chain ends up with two of them and the file will not parse.

```python
        elif msg_type == "subscribe_logs":
            backlog = agent_log.read_log_tail(self.log_file_path())
            await ws.send(json.dumps({
                "type": "log",
                "lines": [agent_log.parse_log_line(line) for line in backlog],
            }))
            # Registered only after the backlog is on the wire. Registering
            # first would let a line logged during the read arrive ahead of
            # the backlog it also appears in - a duplicated, out-of-order
            # timeline. This way the worst case is one line logged during the
            # send being missed, which is invisible next to a 200-line
            # backlog.
            self.log_subscribers.add(ws)
            return
        elif msg_type == "unsubscribe_logs":
            self.log_subscribers.discard(ws)
            return
        else:
            return
```

Note both branches `return` rather than falling through: subscribing changes no capture state, so broadcasting a `state` message to every client would be a lie about something having changed.

**3e.** In `_send_all` (line 307-308), extend the dead-socket sweep:

```python
        for ws in dead:
            self.connections.discard(ws)
            self.log_subscribers.discard(ws)
```

**3f.** Add these three methods to `AgentServer`, after `_send_all`:

```python
    def log_file_path(self) -> str:
        return os.path.join(config.config_dir(), logging_setup.LOG_FILENAME)

    def broadcast_log(self, entry: dict):
        """Sink for WebSocketLogHandler. Called from any thread that logs.

        Returns immediately when nobody is subscribed, which is the normal
        case: with the Driver Info panel closed the whole feature costs one
        set-emptiness check per log line.
        """
        if not self.log_subscribers or self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(
            self._send_logs({"type": "log", "lines": [entry]}), self.loop
        )

    async def _send_logs(self, message: dict):
        # Separate from _send_all so a client watching logs is not also sent
        # packets, and vice versa. list(...) snapshots before awaiting, since
        # a client subscribing or dropping mid-send would otherwise mutate
        # the set while it is being iterated.
        data = json.dumps(message)
        for ws in list(self.log_subscribers):
            try:
                await ws.send(data)
            except websockets.ConnectionClosed:
                self.log_subscribers.discard(ws)
                self.connections.discard(ws)
```

**3g.** In `main()`, directly after the `log = logging_setup.setup_logging(...)` line (line 462) and before `log.info("NetView agent %s starting", ...)`:

```python
    # Must come after setup_logging, which tears down existing handlers when
    # reconfigured - installing before it would silently remove this one.
    log.addHandler(agent_log.WebSocketLogHandler(agent.broadcast_log))
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
python local-agent/test_protocol.py
```

Expected: PASS.

- [ ] **Step 5: Confirm the agent still starts from source**

```bash
python -c "import sys; sys.path.insert(0, 'local-agent'); import agent; print('imports clean')"
```

Expected: `imports clean` with no traceback. (Actually starting the agent needs elevation and would collide with the installed service, so an import check is the right scope here.)

- [ ] **Step 6: Commit**

```bash
git add local-agent/agent.py local-agent/test_protocol.py
git commit -m "agent: stream log lines to subscribed clients"
```

---

### Task 5: Protocol types for the log message

**Files:**
- Modify: `src/services/agentProtocol.ts`
- Test: `scripts/agent-protocol/message-parsing.ts`, `scripts/agent-protocol/version-and-commands.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `export interface AgentLogEntry { time: string | null; level: string | null; message: string }`
  - `export interface AgentLogMessage { type: 'log'; lines: AgentLogEntry[] }`
  - `AgentMessage` union gains `AgentLogMessage`
  - `AgentCommand` union gains `{ type: 'subscribe_logs' }` and `{ type: 'unsubscribe_logs' }`

- [ ] **Step 1: Write the failing tests**

Append to `scripts/agent-protocol/message-parsing.ts`, before the trailing `console.log()` / `if (failures)` block:

```typescript
const logMsg = parseAgentMessage('{"type":"log","lines":[{"time":"2026-08-26 22:14:02,123","level":"INFO","message":"client connected"}]}');
check('valid log message parses', logMsg, {
  type: 'log',
  lines: [{ time: '2026-08-26 22:14:02,123', level: 'INFO', message: 'client connected' }],
});
check('log with an empty lines array parses', parseAgentMessage('{"type":"log","lines":[]}'), { type: 'log', lines: [] });
check(
  'log entry with null time and level parses (unparseable backlog line)',
  parseAgentMessage('{"type":"log","lines":[{"time":null,"level":null,"message":"  File \\"agent.py\\", line 42"}]}'),
  { type: 'log', lines: [{ time: null, level: null, message: '  File "agent.py", line 42' }] },
);
check('log missing lines returns null', parseAgentMessage('{"type":"log"}'), null);
check('log with lines not an array returns null', parseAgentMessage('{"type":"log","lines":"nope"}'), null);
check('log with a non-object entry returns null', parseAgentMessage('{"type":"log","lines":["nope"]}'), null);
check('log with an entry missing message returns null', parseAgentMessage('{"type":"log","lines":[{"time":null,"level":"INFO"}]}'), null);
check('log with a non-string message returns null', parseAgentMessage('{"type":"log","lines":[{"time":null,"level":null,"message":42}]}'), null);
check('log with a non-string level returns null', parseAgentMessage('{"type":"log","lines":[{"time":null,"level":7,"message":"x"}]}'), null);
```

Append to `scripts/agent-protocol/version-and-commands.ts`, before the trailing `console.log()` / `if (failures)` block:

```typescript
check('subscribe_logs encodes', encodeAgentCommand({ type: 'subscribe_logs' }), '{"type":"subscribe_logs"}');
check('unsubscribe_logs encodes', encodeAgentCommand({ type: 'unsubscribe_logs' }), '{"type":"unsubscribe_logs"}');
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
npx tsx scripts/agent-protocol/message-parsing.ts
npx tsx scripts/agent-protocol/version-and-commands.ts
```

Expected: `message-parsing.ts` FAILS on `valid log message parses` (actual `null`, since `log` hits the `default:` case). `version-and-commands.ts` fails to compile or fails its two new checks, because `subscribe_logs` is not yet a member of `AgentCommand`.

- [ ] **Step 3: Add the types, the validator, and the parse case**

In `src/services/agentProtocol.ts`:

**3a.** After the `AgentErrorMessage` interface (line 28), add:

```typescript
/**
 * One line of the agent's own log. `time` and `level` are null for a
 * backlog line the agent could not parse - a traceback continuation line,
 * most often - which still arrives with its text intact in `message`
 * rather than being dropped.
 */
export interface AgentLogEntry {
  time: string | null;
  level: string | null;
  message: string;
}

/**
 * Carries both the backlog sent on subscribe (many entries) and each live
 * line after it (one entry), so the app needs a single handler rather than
 * two message types that differ only in how many entries they hold.
 */
export interface AgentLogMessage {
  type: 'log';
  lines: AgentLogEntry[];
}
```

**3b.** Extend the union (line 35):

```typescript
export type AgentMessage =
  | AgentHelloMessage
  | AgentStateMessage
  | AgentErrorMessage
  | AgentLogMessage
  | AgentPacketMessage;
```

**3c.** After `isValidInterfaceList` (line 45), add:

```typescript
function isValidLogLines(lines: unknown): lines is AgentLogEntry[] {
  return Array.isArray(lines) && lines.every((l) => {
    if (!l || typeof l !== 'object') return false;
    const entry = l as Record<string, unknown>;
    if (typeof entry.message !== 'string') return false;
    if (entry.time !== null && typeof entry.time !== 'string') return false;
    if (entry.level !== null && typeof entry.level !== 'string') return false;
    return true;
  });
}
```

**3d.** In the `switch` in `parseAgentMessage`, add before `case 'packet':`:

```typescript
    case 'log':
      if (!isValidLogLines(msg.lines)) return null;
      return msg as unknown as AgentLogMessage;
```

**3e.** Extend `AgentCommand` (line 104):

```typescript
export type AgentCommand =
  | { type: 'start_capture' }
  | { type: 'stop_capture' }
  | { type: 'set_interfaces'; interfaces: string[] }
  | { type: 'subscribe_logs' }
  | { type: 'unsubscribe_logs' };
```

- [ ] **Step 4: Run the tests and the type check to verify they pass**

```bash
npx tsx scripts/agent-protocol/message-parsing.ts
npx tsx scripts/agent-protocol/version-and-commands.ts
npm run lint
```

Expected: both suites PASS, `npm run lint` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/services/agentProtocol.ts scripts/agent-protocol/message-parsing.ts scripts/agent-protocol/version-and-commands.ts
git commit -m "frontend: add the log message and log subscription commands"
```

---

### Task 6: App-side log buffer and subscription wiring

**Files:**
- Modify: `src/App.tsx` (imports line 36-ish; state near line 98; `socket.onmessage` line 218-260; `hello` handler line 222-249; the `SettingsModal` render at line 830-834)

**Interfaces:**
- Consumes: `AgentLogEntry`, `encodeAgentCommand({ type: 'subscribe_logs' | 'unsubscribe_logs' })` from Task 5.
- Produces (local identifiers in `App.tsx`, wired to the `SettingsModal` prop names shown in Task 7):
  - `agentLog: AgentLogEntry[]` → prop `agentLog`
  - `handleSubscribeAgentLog: () => void` → prop `onSubscribeAgentLog`
  - `handleUnsubscribeAgentLog: () => void` → prop `onUnsubscribeAgentLog`
  - `handleClearAgentLog: () => void` → prop `onClearAgentLog`

- [ ] **Step 1: Add the buffer cap constant and state**

In `src/App.tsx`, add to the `agentProtocol` import (line 36-ish, alongside `parseAgentMessage` / `encodeAgentCommand`):

```typescript
import type { AgentLogEntry } from "./services/agentProtocol";
```

Above the `App` component, next to the other module constants:

```typescript
// Same policy as the 4000-packet buffer: bounded, oldest dropped first. A
// session left open for hours must not grow the log pane without limit.
const AGENT_LOG_BUFFER_LIMIT = 1000;
```

After the `selectedInterfaces` state (line 98):

```typescript
  const [agentLog, setAgentLog] = useState<AgentLogEntry[]>([]);
  // Whether the Driver Info panel currently wants log lines. Read inside the
  // WebSocket handlers, so it must be a ref: those close over their first
  // render's values and would otherwise never see this change.
  const logSubscribedRef = useRef(false);
```

- [ ] **Step 2: Handle the `log` message**

In `socket.onmessage`, add immediately after the `error` branch (line 260) and before the packet path:

```typescript
        if (message.type === 'log') {
          setAgentLog((prev) => {
            const next = prev.concat(message.lines);
            return next.length > AGENT_LOG_BUFFER_LIMIT
              ? next.slice(next.length - AGENT_LOG_BUFFER_LIMIT)
              : next;
          });
          return;
        }
```

- [ ] **Step 3: Resubscribe on reconnect**

In the `hello` handler, after the existing `isCapturingRef` resync block (line 245-247) and before its `return`:

```typescript
          // A log subscription lives on the agent's socket, so a reconnect
          // drops it. Resubscribing here, and clearing first, avoids showing
          // a fresh backlog stitched onto the tail of the dead connection's
          // timeline as though it were continuous.
          if (logSubscribedRef.current) {
            setAgentLog([]);
            socket.send(encodeAgentCommand({ type: 'subscribe_logs' }));
          }
```

- [ ] **Step 4: Add the three callbacks**

Next to the other `useCallback` handlers in `App.tsx`:

```typescript
  const handleSubscribeAgentLog = useCallback(() => {
    logSubscribedRef.current = true;
    setAgentLog([]);
    const socket = wsRef.current;
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(encodeAgentCommand({ type: 'subscribe_logs' }));
    }
    // A closed socket is not an error: the hello handler resubscribes on
    // reconnect, so opening the panel while the agent is down and having it
    // fill in when the agent returns is the intended behavior.
  }, []);

  const handleUnsubscribeAgentLog = useCallback(() => {
    logSubscribedRef.current = false;
    const socket = wsRef.current;
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(encodeAgentCommand({ type: 'unsubscribe_logs' }));
    }
  }, []);

  const handleClearAgentLog = useCallback(() => setAgentLog([]), []);
```

Confirm `useCallback` is in the React import at the top of the file; add it if not.

- [ ] **Step 5: Type check**

```bash
npm run lint
```

Expected: exits 0. `agentLog` and the three callbacks are unused until Task 7 — that is fine, `tsc --noEmit` does not fail on unused locals here (`noUnusedLocals` is not enabled; if it turns out to be, complete Task 7 before committing this one).

- [ ] **Step 6: Commit**

```bash
git add src/App.tsx
git commit -m "frontend: buffer agent log lines and manage the subscription"
```

---

### Task 7: The Driver Info panel and Settings sidebar

**Files:**
- Create: `src/components/common/DriverInfoPanel.tsx`
- Modify: `src/components/common/SettingsModal.tsx`
- Modify: `src/App.tsx` (the `SettingsModal` render at line 830-834)

**Interfaces:**
- Consumes: `agentLog`, `handleSubscribeAgentLog`, `handleUnsubscribeAgentLog`, `handleClearAgentLog` from Task 6; `agentStatus`, `agentVersion`, `agentOutdated`, `agentCaptureState`, `agentInterfaces`, `selectedInterfaces` — all already in `App.tsx` state.
- Produces: the rendered feature. Nothing downstream consumes it.

- [ ] **Step 1: Create the panel**

Create `src/components/common/DriverInfoPanel.tsx`:

```tsx
import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import { TbTrash } from 'react-icons/tb';
import type { AgentLogEntry } from '../../services/agentProtocol';
import { detectOS } from '../../services/platformDetect';

interface DriverInfoPanelProps {
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentVersion: string | null;
  agentOutdated: boolean;
  agentCaptureState: 'idle' | 'sniffing';
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  agentLog: AgentLogEntry[];
  onSubscribe: () => void;
  onUnsubscribe: () => void;
  onClearLog: () => void;
}

const AGENT_STATUS_LABEL: Record<DriverInfoPanelProps['agentStatus'], string> = {
  connected: 'Running',
  connecting: 'Connecting',
  disconnected: 'Not reachable',
  error: 'Error',
};

const AGENT_STATUS_COLOR: Record<DriverInfoPanelProps['agentStatus'], string> = {
  connected: 'text-emerald-600 dark:text-emerald-400',
  connecting: 'text-amber-600 dark:text-amber-400',
  disconnected: 'text-muted-foreground',
  error: 'text-rose-600 dark:text-rose-400',
};

// The agent resolves this itself from %ProgramData% (config.config_dir()),
// so a machine with a relocated ProgramData would differ. Showing the
// standard path is enough to find the file; the agent is not asked for its
// real one, which would mean another protocol field for a rare case.
function logFilePath(): string {
  return detectOS() === 'windows'
    ? '%ProgramData%\\NetView\\agent.log'
    : '~/.netview/agent.log';
}

function levelColor(level: string | null): string {
  switch (level) {
    case 'ERROR':
    case 'CRITICAL':
      return 'text-rose-600 dark:text-rose-400';
    case 'WARNING':
      return 'text-amber-600 dark:text-amber-400';
    case 'DEBUG':
      return 'text-muted-foreground';
    default:
      return 'text-foreground';
  }
}

export const DriverInfoPanel: React.FC<DriverInfoPanelProps> = ({
  agentStatus,
  agentVersion,
  agentOutdated,
  agentCaptureState,
  agentInterfaces,
  selectedInterfaces,
  agentLog,
  onSubscribe,
  onUnsubscribe,
  onClearLog,
}) => {
  const scrollRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // Subscribe for as long as this panel is mounted, and only that long -
  // the whole point of the subscription model is that a closed panel costs
  // nothing on the wire.
  useEffect(() => {
    onSubscribe();
    return onUnsubscribe;
  }, [onSubscribe, onUnsubscribe]);

  // useLayoutEffect, not useEffect: scrolling after paint makes the newest
  // line visibly jump into place on every arrival.
  useLayoutEffect(() => {
    if (!autoScroll) return;
    const el = scrollRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [agentLog, autoScroll]);

  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    // Scrolling up to read something must not be fought by the next arriving
    // line; returning to the bottom opts back in.
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 24;
    setAutoScroll(atBottom);
  };

  const listening = agentInterfaces.filter((i) => selectedInterfaces.includes(i.name));

  return (
    <div className="flex flex-col gap-4 min-h-0">
      <div>
        <div className="text-xs font-semibold text-foreground mb-2">Agent</div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-xs">
          <dt className="text-muted-foreground">Status</dt>
          <dd className={`font-mono font-semibold ${AGENT_STATUS_COLOR[agentStatus]}`}>
            {AGENT_STATUS_LABEL[agentStatus]}
          </dd>

          <dt className="text-muted-foreground">Version</dt>
          <dd className="font-mono flex items-center gap-2">
            <span>{agentVersion ?? '—'}</span>
            {agentOutdated && (
              <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400">
                Update
              </span>
            )}
          </dd>

          <dt className="text-muted-foreground">Capture</dt>
          <dd className="font-mono">{agentCaptureState === 'sniffing' ? 'Sniffing' : 'Idle'}</dd>

          <dt className="text-muted-foreground">Listening on</dt>
          <dd className="font-mono">
            {listening.length === 0 ? (
              <span className="text-muted-foreground">No interfaces selected</span>
            ) : (
              <ul className="flex flex-col gap-0.5">
                {listening.map((i) => (
                  <li key={i.name} className="truncate" title={i.name}>{i.label}</li>
                ))}
              </ul>
            )}
          </dd>

          <dt className="text-muted-foreground">Log file</dt>
          <dd className="font-mono text-muted-foreground break-all">{logFilePath()}</dd>
        </dl>
      </div>

      <div className="flex flex-col min-h-0 flex-1">
        <div className="flex items-center justify-between mb-2">
          <div className="text-xs font-semibold text-foreground">
            Log
            {!autoScroll && (
              <span className="ml-2 text-[10px] font-normal text-muted-foreground">
                paused — scroll to the bottom to follow
              </span>
            )}
          </div>
          <button
            onClick={onClearLog}
            className="flex items-center gap-1.5 px-2 py-1 rounded-md text-[11px] font-medium text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
          >
            <TbTrash className="w-3.5 h-3.5" />
            Clear
          </button>
        </div>

        <div
          ref={scrollRef}
          onScroll={handleScroll}
          className="flex-1 min-h-[14rem] max-h-[22rem] overflow-y-auto overflow-x-auto rounded-lg border border-border bg-muted/40 p-2 font-mono text-[11px] leading-relaxed"
        >
          {agentLog.length === 0 ? (
            <div className="text-muted-foreground p-2">
              {agentStatus === 'connected'
                ? 'No log lines yet.'
                : 'Waiting for the agent to connect…'}
            </div>
          ) : (
            agentLog.map((line, index) => (
              // Index keys are correct here: this is an append-only buffer
              // whose only other mutation drops entries off the front, and
              // entries carry no identity of their own - two identical lines
              // a second apart are genuinely indistinguishable.
              <div key={index} className="whitespace-pre flex gap-2">
                <span className="text-muted-foreground shrink-0">{line.time ?? ''}</span>
                <span className={`shrink-0 w-16 ${levelColor(line.level)}`}>{line.level ?? ''}</span>
                <span className={levelColor(line.level)}>{line.message}</span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
```

- [ ] **Step 2: Restructure the Settings modal**

Rewrite `src/components/common/SettingsModal.tsx`. Keep the existing Appearance content exactly as it is; wrap it in a section chooser and widen the panel:

```tsx
import React, { useState } from 'react';
import { motion } from 'motion/react';
import { useTheme } from 'next-themes';
import { TbSettings, TbX, TbCheck, TbPalette, TbActivity } from 'react-icons/tb';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import { THEME_OPTIONS } from '../../lib/themeOptions';
import { DriverInfoPanel } from './DriverInfoPanel';
import type { AgentLogEntry } from '../../services/agentProtocol';

type SettingsSection = 'appearance' | 'driver';

const SECTIONS: { id: SettingsSection; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'appearance', label: 'Appearance', icon: TbPalette },
  { id: 'driver', label: 'Driver Info', icon: TbActivity },
];

interface SettingsModalProps {
  onClose: () => void;
  agentStatus: 'disconnected' | 'connecting' | 'connected' | 'error';
  agentVersion: string | null;
  agentOutdated: boolean;
  agentCaptureState: 'idle' | 'sniffing';
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  agentLog: AgentLogEntry[];
  onSubscribeAgentLog: () => void;
  onUnsubscribeAgentLog: () => void;
  onClearAgentLog: () => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  onClose,
  agentStatus,
  agentVersion,
  agentOutdated,
  agentCaptureState,
  agentInterfaces,
  selectedInterfaces,
  agentLog,
  onSubscribeAgentLog,
  onUnsubscribeAgentLog,
  onClearAgentLog,
}) => {
  const { theme, setTheme } = useTheme();
  const [section, setSection] = useState<SettingsSection>('appearance');

  return (
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className="w-full max-w-3xl rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground"
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-amber-500/20">
              <TbSettings className="w-5 h-5 text-foreground" />
            </div>
            <div>
              <div className="font-bold text-base">Settings</div>
              <p className="text-xs text-muted-foreground">Appearance and application preferences</p>
            </div>
          </div>

          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground">
            <TbX className="w-5 h-5" />
          </button>
        </div>

        {/* Body: sidebar + section */}
        <div className="flex min-h-0">
          <nav className="w-44 shrink-0 border-r border-border p-2 flex flex-col gap-1">
            {SECTIONS.map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setSection(id)}
                className={`flex items-center gap-2 px-2.5 py-2 rounded-md text-xs font-medium text-left transition-colors ${
                  section === id
                    ? 'bg-accent text-foreground'
                    : 'text-muted-foreground hover:bg-accent/50 hover:text-foreground'
                }`}
              >
                <Icon className="w-3.5 h-3.5 shrink-0" />
                <span>{label}</span>
              </button>
            ))}
          </nav>

          <div className="flex-1 min-w-0 p-5">
            {section === 'appearance' && (
              <>
                <div className="text-xs font-semibold text-foreground mb-2">Appearance</div>
                <div className="grid grid-cols-3 gap-2">
                  {THEME_OPTIONS.map(({ value, label, icon: Icon }) => {
                    const isActive = theme === value;
                    return (
                      <button
                        key={value}
                        onClick={() => setTheme(value)}
                        className={`relative flex flex-col items-center gap-1.5 py-3 rounded-lg border text-xs font-medium transition-colors ${
                          isActive
                            ? 'border-cyan-500 bg-cyan-500/10 text-cyan-600 dark:text-cyan-300'
                            : 'border-border bg-muted/40 text-muted-foreground hover:bg-accent hover:text-foreground'
                        }`}
                      >
                        {isActive && <TbCheck className="w-3.5 h-3.5 absolute top-1.5 right-1.5" />}
                        <Icon className="w-5 h-5" />
                        <span>{label}</span>
                      </button>
                    );
                  })}
                </div>
              </>
            )}

            {/* Mounted only while selected, so the log subscription starts
                and stops with the section rather than with the modal. */}
            {section === 'driver' && (
              <DriverInfoPanel
                agentStatus={agentStatus}
                agentVersion={agentVersion}
                agentOutdated={agentOutdated}
                agentCaptureState={agentCaptureState}
                agentInterfaces={agentInterfaces}
                selectedInterfaces={selectedInterfaces}
                agentLog={agentLog}
                onSubscribe={onSubscribeAgentLog}
                onUnsubscribe={onUnsubscribeAgentLog}
                onClearLog={onClearAgentLog}
              />
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-secondary hover:bg-accent text-foreground text-xs font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
};
```

- [ ] **Step 3: Pass the new props from `App.tsx`**

Replace the `SettingsModal` render (line 830-834) with:

```tsx
      <AnimatePresence>
        {showSettingsModal && (
          <SettingsModal
            key="settings-modal"
            onClose={() => setShowSettingsModal(false)}
            agentStatus={agentStatus}
            agentVersion={agentVersion}
            agentOutdated={agentOutdated}
            agentCaptureState={agentCaptureState}
            agentInterfaces={agentInterfaces}
            selectedInterfaces={selectedInterfaces}
            agentLog={agentLog}
            onSubscribeAgentLog={handleSubscribeAgentLog}
            onUnsubscribeAgentLog={handleUnsubscribeAgentLog}
            onClearAgentLog={handleClearAgentLog}
          />
        )}
      </AnimatePresence>
```

- [ ] **Step 4: Type check**

```bash
npm run lint
```

Expected: exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/components/common/DriverInfoPanel.tsx src/components/common/SettingsModal.tsx src/App.tsx
git commit -m "frontend: add the Driver Info settings section"
```

---

### Task 8: Live verification and documentation

**Files:**
- Modify: `local-agent/verify_protocol.py`
- Modify: `CLAUDE.md:25` (the protocol message list) and `CLAUDE.md:31` (the pyinstaller/debug paragraph is unchanged; only the protocol sentence moves)

**Interfaces:**
- Consumes: everything from Tasks 1-5.
- Produces: nothing downstream.

- [ ] **Step 1: Add the live log check**

In `local-agent/verify_protocol.py`, extend the docstring's Coverage list with:

```
  - subscribe_logs returns a backlog and then streams live lines, and
    unsubscribe_logs stops them
```

Then add this block inside `main()`, after the existing `set_interfaces` / empty-list checks and **before** the origin-rejection checks (those open their own connections, so anything using the main `ws` must come first):

```python
    # --- log streaming ---
    await ws.send(json.dumps({"type": "subscribe_logs"}))
    backlog = await recv_type(ws, "log")
    check("subscribe_logs returns a log message", backlog.get("type") == "log")
    check("backlog lines is a list", isinstance(backlog.get("lines"), list))
    check(
        "backlog entries have the protocol shape",
        all(set(e) == {"time", "level", "message"} for e in backlog["lines"]),
    )
    check(
        "backlog is capped at 200 lines",
        len(backlog["lines"]) <= 200,
    )

    # start_capture makes the agent log a line of its own; that line must
    # arrive live, which is the whole feature.
    await ws.send(json.dumps({"type": "start_capture"}))
    live_seen = False
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            msg = await recv_type(ws, "log", timeout=max(0.1, deadline - time.monotonic()))
        except asyncio.TimeoutError:
            break
        if any("start_capture" in entry["message"] for entry in msg["lines"]):
            live_seen = True
            break
    check("a live log line arrives after start_capture", live_seen)

    await ws.send(json.dumps({"type": "stop_capture"}))
    await recv_type(ws, "state")

    await ws.send(json.dumps({"type": "unsubscribe_logs"}))
    # Nothing acknowledges an unsubscribe, so prove it took by generating log
    # traffic and showing none of it arrives.
    await ws.send(json.dumps({"type": "start_capture"}))
    await recv_type(ws, "state")
    quiet = True
    try:
        await recv_type(ws, "log", timeout=2)
        quiet = False
    except asyncio.TimeoutError:
        pass
    check("no log lines arrive after unsubscribe_logs", quiet)
    await ws.send(json.dumps({"type": "stop_capture"}))
    await recv_type(ws, "state")
```

- [ ] **Step 2: Run it against the running service**

```bash
python local-agent/verify_protocol.py
```

Expected: `All checks passed.`

If the run fails on the new checks with the service reporting version `2.0.0`, that is the expected consequence of the version bump — the installed service predates this work. Rebuild and reinstall before concluding the code is wrong:

```bash
pyinstaller local-agent/netview_agent.spec
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" local-agent/installer/setup.iss
```

Then run the produced `local-agent/installer/output/NetView-Agent-Setup.exe` and re-run the verification. Reinstalling replaces a running service, so **ask the user before doing it** — it is a change to installed system state, not a repo change.

- [ ] **Step 3: Update `CLAUDE.md`**

Replace the protocol sentence at line 25 with:

```markdown
- The agent speaks a typed WebSocket protocol (`hello`/`state`/`error`/`log`/`packet` from the agent; `start_capture`/`stop_capture`/`set_interfaces`/`subscribe_logs`/`unsubscribe_logs` to it) and starts **idle** — it only sniffs once a client sends `start_capture`, and stops again when the last client disconnects.
- `subscribe_logs` streams the agent's own log to that one client: a backlog of up to 200 lines read from the tail of `agent.log`, then each new line live via a `logging.Handler` on the `netview` logger (`local-agent/agent_log.py`). Nothing is sent to clients that have not subscribed, and the subscription dies with the socket. The web app surfaces this in Settings → Driver Info.
```

- [ ] **Step 4: Run the full suite one more time**

```bash
python local-agent/test_protocol.py
npx tsx scripts/agent-protocol/message-parsing.ts
npx tsx scripts/agent-protocol/version-and-commands.ts
npm run lint
```

Expected: all four green.

- [ ] **Step 5: Commit**

```bash
git add local-agent/verify_protocol.py CLAUDE.md
git commit -m "Verify log streaming live and document the new protocol messages"
```

---

## Verification

After Task 8, the whole feature is exercised by:

| Command | Covers |
|---|---|
| `python local-agent/test_protocol.py` | Version sync across all three files, log line parsing, tail reading, the handler and its reentrancy guard, subscriber registration and disconnect cleanup |
| `npx tsx scripts/agent-protocol/message-parsing.ts` | `log` message parsing and every malformed-shape rejection |
| `npx tsx scripts/agent-protocol/version-and-commands.ts` | Command encoding for both new verbs, version comparison |
| `npm run lint` | Types across `agentProtocol.ts`, `App.tsx`, `SettingsModal.tsx`, `DriverInfoPanel.tsx` |
| `python local-agent/verify_protocol.py` | The real agent: backlog, live streaming, unsubscribe silence |

Manual pass in the browser, with the dev server running and the rebuilt agent installed: open Settings → Driver Info, confirm the status block shows Running / 2.1.0 / Idle and the selected adapters; confirm the log pane fills with backlog; start capture and watch a new line arrive live; scroll up and confirm autoscroll pauses; scroll to the bottom and confirm it resumes; press Clear and confirm the pane empties; close and reopen the section and confirm the backlog returns.
