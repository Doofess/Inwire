#!/usr/bin/env python3
"""
Plain-assertion tests for agent.py's pure protocol logic (no pytest in this
repo - see scripts/parity/crypto-vectors.ts for the equivalent frontend
convention this mirrors).

Run:  python local-agent/test_protocol.py
"""
import asyncio
import json
import logging
import os
import re
import sys
import tempfile

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


# --- agent version stays in sync across all three locations ---
# Any change to the agent's wire protocol or behavior must bump
# AGENT_VERSION, and all three locations below must move together. This
# reads the other two files by regex (resolved relative to this file's own
# location, not the CWD) rather than pinning a literal, so a legitimate
# version bump doesn't make this suite fail - it fails only if the three
# values drift apart, or if one of them isn't a MAJOR.MINOR.PATCH string.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_AGENT_PROTOCOL_TS = os.path.join(_REPO_ROOT, "src", "services", "agentProtocol.ts")
_SETUP_ISS = os.path.join(_REPO_ROOT, "local-agent", "installer", "setup.iss")


def _read_required_text(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        raise AssertionError(f"could not read {path!r} for version sync check: {exc}") from exc


def _extract(pattern, text, path):
    match = re.search(pattern, text)
    if not match:
        raise AssertionError(f"could not find version pattern {pattern!r} in {path!r}")
    return match.group(1)


_ts_text = _read_required_text(_AGENT_PROTOCOL_TS)
_iss_text = _read_required_text(_SETUP_ISS)

_ts_version = _extract(r"REQUIRED_AGENT_VERSION\s*=\s*'([^']+)'", _ts_text, _AGENT_PROTOCOL_TS)
_iss_version = _extract(r'#define\s+MyAppVersion\s+"([^"]+)"', _iss_text, _SETUP_ISS)

check("agentProtocol.ts REQUIRED_AGENT_VERSION matches agent.py AGENT_VERSION", _ts_version, agent.AGENT_VERSION)
check("setup.iss MyAppVersion matches agent.py AGENT_VERSION", _iss_version, agent.AGENT_VERSION)
check_true(
    "agent.py AGENT_VERSION is MAJOR.MINOR.PATCH",
    re.fullmatch(r"\d+\.\d+\.\d+", agent.AGENT_VERSION) is not None,
)

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

check("pairing token generation is gone", hasattr(agent, "generate_pairing_token"), False)
check("ConnectionAuth is gone", hasattr(agent, "ConnectionAuth"), False)
check("is_command_allowed is gone", hasattr(agent, "is_command_allowed"), False)

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
check("stop_event starts unset after start_threads", first_stop_event.is_set(), False)

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
check("fresh stop_event after set_interfaces (different object)", second_stop_event is not first_stop_event, True)
check("new stop_event starts unset", second_stop_event.is_set(), False)

spawn4 = FakeSpawnCalls()
sc.set_interfaces(["eth3", "eth4"])
sc.restart_threads(spawn4)
check("restart_threads stops the old stop_event", second_stop_event.is_set(), True)
check("restart_threads starts threads for the new interface set", [c[0] for c in spawn4.calls], ["eth3", "eth4"])
third_stop_event = spawn4.calls[0][1]
check("fresh stop_event on restart (different object)", third_stop_event is not second_stop_event, True)
check("restarted stop_event starts unset", third_stop_event.is_set(), False)
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

_tmpdir = tempfile.mkdtemp()
_badenc = os.path.join(_tmpdir, "config.json")
with open(_badenc, "wb") as _fh:
    _fh.write(b'{"allowedOrigins": ["http://caf\xe9.local"]}')
_real_config_path = config.config_path
config.config_path = lambda: _badenc
_warnings = []
try:
    _result = config.load_config(on_warning=_warnings.append)
    check("non-UTF-8 config falls back to defaults", _result["allowedOrigins"], config.DEFAULT_ALLOWED_ORIGINS)
    check_true("non-UTF-8 config emits a warning", len(_warnings) == 1)
finally:
    config.config_path = _real_config_path

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

# --- failed handshake: connection leak prevention ---
class FailingHelloWS:
    """A client that drops during the handshake, before hello lands."""
    async def send(self, data):
        raise ConnectionResetError("client vanished mid-handshake")
    def __aiter__(self):
        return self
    async def __anext__(self):
        raise StopAsyncIteration


_prev = getattr(agent, "sniffer", None)
_prev_avail = getattr(agent, "AVAILABLE_INTERFACES", None)
try:
    agent.sniffer = agent.SnifferController(default_interfaces=["eth0"])
    agent.sniffer.start_threads(FakeSpawn())
    agent.AVAILABLE_INTERFACES = [("eth0", "Ethernet")]
    _srv = agent.AgentServer()
    _ws = FailingHelloWS()
    try:
        asyncio.run(_srv.register(_ws))
    except ConnectionResetError:
        pass
    check("failed hello does not leak the connection", len(_srv.connections), 0)
    check("failed hello still triggers auto-stop", agent.sniffer.is_sniffing(), False)
finally:
    if _prev is None:
        if hasattr(agent, "sniffer"):
            del agent.sniffer
    else:
        agent.sniffer = _prev
    if _prev_avail is None:
        if hasattr(agent, "AVAILABLE_INTERFACES"):
            del agent.AVAILABLE_INTERFACES
    else:
        agent.AVAILABLE_INTERFACES = _prev_avail

# --- logging_setup: to_stderr / degraded-directory handling ---
import logging

import logging_setup

_netview_logger = logging.getLogger("netview")
_saved_handlers = list(_netview_logger.handlers)
_saved_configured_with = logging_setup._configured_with
_saved_level = _netview_logger.level
_saved_propagate = _netview_logger.propagate
try:
    # A changed to_stderr on a second call must actually take effect: a
    # stale StreamHandler from an earlier to_stderr=True call must not keep
    # writing to a stderr the caller just asked us not to use.
    for _h in list(_netview_logger.handlers):
        _netview_logger.removeHandler(_h)
        _h.close()
    logging_setup._configured_with = None

    _tmpdir1 = tempfile.mkdtemp()
    logging_setup.setup_logging(_tmpdir1, to_stderr=True)
    _stderr_handlers_before = [h for h in _netview_logger.handlers if getattr(h, "stream", None) is sys.stderr]
    check_true("to_stderr=True attaches a stderr stream handler", len(_stderr_handlers_before) == 1)

    logging_setup.setup_logging(_tmpdir1, to_stderr=False)
    # RotatingFileHandler is also a StreamHandler subclass, so this must
    # filter by the stderr stream specifically, not just the class.
    _stderr_handlers_after = [h for h in _netview_logger.handlers if getattr(h, "stream", None) is sys.stderr]
    check("to_stderr=False on a second call removes the stale stderr handler", _stderr_handlers_after, [])

    # An unwritable log directory plus to_stderr=False must still leave the
    # logger with a handler (a NullHandler), so logging.lastResort never
    # writes WARNING+ records to the real stderr behind the SCM's back.
    for _h in list(_netview_logger.handlers):
        _netview_logger.removeHandler(_h)
        _h.close()
    logging_setup._configured_with = None

    _blocking_file = tempfile.NamedTemporaryFile(delete=False)
    _blocking_file.close()
    _unwritable_dir = _blocking_file.name  # a file, not a directory: os.makedirs must fail
    try:
        logging_setup.setup_logging(_unwritable_dir, to_stderr=False)
        check_true("unwritable dir + to_stderr=False still leaves at least one handler", len(_netview_logger.handlers) >= 1)
        check_true(
            "that handler is a NullHandler, so logging.lastResort cannot engage",
            any(isinstance(h, logging.NullHandler) for h in _netview_logger.handlers),
        )
    finally:
        os.remove(_unwritable_dir)
finally:
    for _h in list(_netview_logger.handlers):
        _netview_logger.removeHandler(_h)
        _h.close()
    for _h in _saved_handlers:
        _netview_logger.addHandler(_h)
    logging_setup._configured_with = _saved_configured_with
    _netview_logger.level = _saved_level
    _netview_logger.propagate = _saved_propagate

# --- build_interface_label ---
check(
    "build_interface_label strips RTL marks from name",
    agent.build_interface_label("‏‏Ethernet 2", "Intel(R) Ethernet Controller"),
    "Ethernet 2 (Intel(R) Ethernet Controller)",
)
check(
    "build_interface_label strips RTL marks from description",
    agent.build_interface_label("Wi-Fi", "‏‏Intel(R) Wi-Fi 6E AX211 160MHz"),
    "Wi-Fi (Intel(R) Wi-Fi 6E AX211 160MHz)",
)
check(
    "build_interface_label name + description",
    agent.build_interface_label("Wi-Fi", "Intel(R) Wi-Fi 6E AX211 160MHz"),
    "Wi-Fi (Intel(R) Wi-Fi 6E AX211 160MHz)",
)
check(
    "build_interface_label with empty description",
    agent.build_interface_label("Loopback Pseudo-Interface 1", ""),
    "Loopback Pseudo-Interface 1",
)
check(
    "build_interface_label with None description",
    agent.build_interface_label("Loopback Pseudo-Interface 1", None),
    "Loopback Pseudo-Interface 1",
)
check(
    "build_interface_label with description equal to name avoids duplication",
    agent.build_interface_label("Ethernet 2", "Ethernet 2"),
    "Ethernet 2",
)
check(
    "build_interface_label trims surrounding whitespace",
    agent.build_interface_label("  Wi-Fi  ", "  Intel Wi-Fi  "),
    "Wi-Fi (Intel Wi-Fi)",
)
check(
    "build_interface_label with empty name returns just the description, unparenthesized",
    agent.build_interface_label("", "Software Loopback Interface 1"),
    "Software Loopback Interface 1",
)
check(
    "build_interface_label with both empty returns an empty string",
    agent.build_interface_label("", ""),
    "",
)

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

# --- broadcast backpressure: the bound that keeps the agent from wedging ---
class _FakeLoop:
    """Records scheduled coroutines instead of running them, which is exactly
    the backed-up-loop condition the bound exists for."""

    def __init__(self):
        self.scheduled = []


def _fake_schedule(coro, loop):
    loop.scheduled.append(coro)
    coro.close()  # never awaited; closing avoids "coroutine was never awaited"
    return None


_prev_schedule = agent.asyncio.run_coroutine_threadsafe
try:
    agent.asyncio.run_coroutine_threadsafe = _fake_schedule
    srv = agent.AgentServer()
    srv.loop = _FakeLoop()
    srv.connections.add(object())

    for _ in range(agent.MAX_PENDING_SENDS):
        srv.broadcast({"type": "packet"})
    check(
        "broadcast schedules up to the cap",
        len(srv.loop.scheduled),
        agent.MAX_PENDING_SENDS,
    )
    check("nothing dropped while under the cap", srv._dropped_sends, 0)

    # The loop is now "behind" - nothing has run, so pending stays at the cap.
    for _ in range(5000):
        srv.broadcast({"type": "packet"})
    check(
        "past the cap, broadcast drops instead of queueing",
        len(srv.loop.scheduled),
        agent.MAX_PENDING_SENDS,
    )
    check("dropped packets are counted", srv._dropped_sends, 5000)
    check_true(
        "pending never exceeds the cap - this is what bounds memory",
        srv._pending_sends <= agent.MAX_PENDING_SENDS,
    )
finally:
    agent.asyncio.run_coroutine_threadsafe = _prev_schedule


# A send that blows up must still free its slot, or the agent ratchets down to
# sending nothing at all - a far worse failure than dropping.
class _ExplodingWS:
    async def send(self, data):
        raise RuntimeError("nic on fire")


_srv2 = agent.AgentServer()
_srv2._pending_sends = 1
_srv2.connections.add(_ExplodingWS())
try:
    asyncio.run(_srv2._send_all({"type": "packet"}))
except RuntimeError:
    pass
check("a failed send still releases its slot", _srv2._pending_sends, 0)


# --- watchdog: capture must never outlive the app ---
_prev_sniffer = getattr(agent, "sniffer", None)
try:
    agent.sniffer = agent.SnifferController(default_interfaces=["eth0"])
    agent.sniffer.start_threads(lambda name, ev: None)
    check_true("sniffing before the watchdog runs", agent.sniffer.is_sniffing())

    _watch_srv = agent.AgentServer()
    _prev_agent = agent.agent
    agent.agent = _watch_srv
    try:
        agent.ORPHAN_CHECK_SECONDS = 0.01

        async def _run_watchdog_once():
            task = asyncio.ensure_future(agent.watch_for_orphaned_capture())
            await asyncio.sleep(0.05)
            task.cancel()

        # With a client connected, capture is left alone.
        _watch_srv.connections.add(object())
        asyncio.run(_run_watchdog_once())
        check("watchdog leaves capture alone while a client is connected",
              agent.sniffer.is_sniffing(), True)

        # With nobody connected, it stops capture.
        _watch_srv.connections.clear()
        asyncio.run(_run_watchdog_once())
        check("watchdog stops capture once no clients remain",
              agent.sniffer.is_sniffing(), False)
    finally:
        agent.agent = _prev_agent
        agent.ORPHAN_CHECK_SECONDS = 2
finally:
    if _prev_sniffer is None:
        if hasattr(agent, "sniffer"):
            del agent.sniffer
    else:
        agent.sniffer = _prev_sniffer


print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")
