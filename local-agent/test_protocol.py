#!/usr/bin/env python3
"""
Plain-assertion tests for agent.py's pure protocol logic (no pytest in this
repo - see scripts/parity/crypto-vectors.ts for the equivalent frontend
convention this mirrors).

Run:  python local-agent/test_protocol.py
"""
import asyncio
import json
import pathlib
import logging
import os
import re
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import agent
import npcap_access

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


# --- the agent's version IS the product's version ---
#
# It used to be its own number, locked across six stamps by two scripts that
# covered different subsets of them - and the subset THIS file covered was the
# legacy agent-only installer, which nothing builds. ADR 0035 collapsed the two
# numbers into one authored in package.json, which deletes the drift question
# rather than checking it more carefully.
#
# What is left here is the half a Python test is the right place for: that the
# agent reports the product's version, and that it has not gone backwards. The
# full singularity check - every stamp, both installers, the generated file -
# is `scripts/agent/version.ts`, which runs on every `npm run check`. This one
# is Python, and `scripts/check.ts` discovers only TypeScript, so it fires only
# when somebody runs it; that asymmetry is why the authoritative check lives
# there and not here.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_AGENT_PROTOCOL_TS = os.path.join(_REPO_ROOT, "src", "services", "agentProtocol.ts")


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
_ts_version = _extract(r"REQUIRED_AGENT_VERSION\s*=\s*'([^']+)'", _ts_text, _AGENT_PROTOCOL_TS)

_PACKAGE_JSON = os.path.join(_REPO_ROOT, "package.json")
_product_version = json.loads(_read_required_text(_PACKAGE_JSON))["version"]

# The one that matters at run time: what the agent puts in `hello` is what the
# app compares against REQUIRED_AGENT_VERSION. If the generated module has gone
# stale, this is where a running agent disagrees with the app that shipped it.
check("the agent reports the product's version", agent.AGENT_VERSION, _product_version)
check("agentProtocol.ts REQUIRED_AGENT_VERSION matches package.json", _ts_version, _product_version)
check_true(
    "the version is MAJOR.MINOR.PATCH",
    re.fullmatch(r"\d+\.\d+\.\d+", agent.AGENT_VERSION) is not None,
)
# There was a floor here, at 3.9.0, while the app compared versions as an
# ordering. It compares them for equality now (ADR 0051), so the number is free
# to go down - and did, to 0.x, because Inwire is in development.

# --- build_hello_message ---
hello = agent.build_hello_message(
    version="2.0.0",
    state="idle",
    interfaces=[("\\Device\\NPF_{ABC}", "Wi-Fi")],
)
check("hello type", hello["type"], "hello")
check("hello version", hello["version"], "2.0.0")
check("hello state", hello["state"], "idle")
check("hello interfaces carry their id", hello["interfaces"], [{"id": 0, "name": "\\Device\\NPF_{ABC}", "label": "Wi-Fi"}])
# It advertises it again since 3.3.0, and for a reason that did not exist when
# the origin check was the only control: a handshake refused at the HTTP level
# reaches a browser as an opaque WebSocket error, indistinguishable from "the
# agent is not running". Announcing the requirement is what lets the app say
# which of the two it is.
check("hello says whether a pairing token is needed", hello["authRequired"], False)
check(
    "...and says so when one is",
    agent.build_hello_message("3.3.0", "idle", [], auth_required=True)["authRequired"],
    True,
)

# The Npcap device object's DACL, which only a SYSTEM process can be relied on
# to read. A STRING and not a verdict: the agent states facts and the app
# decides what they mean (docs/decisions/0010, 0033). Null rather than absent,
# so a client can tell "this agent looked and found nothing" from "this agent
# does not report it" - a machine with no driver installed is the first.
check("hello carries the driver's access descriptor as null by default",
      hello["npcapAccess"], None)
check(
    "...and passes the string through untouched when there is one",
    agent.build_hello_message(
        "3.9.0", "idle", [],
        npcap_access_sddl="D:P(A;;FA;;;SY)(A;;FA;;;BA)",
    )["npcapAccess"],
    "D:P(A;;FA;;;SY)(A;;FA;;;BA)",
)
check_true(
    "the agent computes no verdict of its own about the driver's access",
    not any(
        hasattr(npcap_access, name)
        for name in ("is_admin_only", "admin_only", "decide_access")
    ),
)

# Nothing here may raise. A driver that is not installed, a pywin32 that is
# not present and a platform that is not Windows all have to answer None, or a
# failure to read a descriptor takes down the hello that carries it.
check_true(
    "an unreadable device answers None rather than raising",
    npcap_access.read_driver_sddl(r"\\.\INWIRE_NO_SUCH_DEVICE") is None,
)
_sddl = npcap_access.read_driver_sddl()
print(f"      this machine's Npcap DACL: {_sddl!r}")
check_true(
    "...and a real read is either None or an SDDL string",
    _sddl is None or (isinstance(_sddl, str) and "D:" in _sddl),
)

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
check("state_message reports available interfaces regardless of selection", idle_msg["interfaces"], [{"id": 0, "name": "eth0", "label": "Ethernet"}])

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

_inwire_logger = logging.getLogger("inwire")
_saved_handlers = list(_inwire_logger.handlers)
_saved_configured_with = logging_setup._configured_with
_saved_level = _inwire_logger.level
_saved_propagate = _inwire_logger.propagate
try:
    # A changed to_stderr on a second call must actually take effect: a
    # stale StreamHandler from an earlier to_stderr=True call must not keep
    # writing to a stderr the caller just asked us not to use.
    for _h in list(_inwire_logger.handlers):
        _inwire_logger.removeHandler(_h)
        _h.close()
    logging_setup._configured_with = None

    _tmpdir1 = tempfile.mkdtemp()
    logging_setup.setup_logging(_tmpdir1, to_stderr=True)
    _stderr_handlers_before = [h for h in _inwire_logger.handlers if getattr(h, "stream", None) is sys.stderr]
    check_true("to_stderr=True attaches a stderr stream handler", len(_stderr_handlers_before) == 1)

    logging_setup.setup_logging(_tmpdir1, to_stderr=False)
    # RotatingFileHandler is also a StreamHandler subclass, so this must
    # filter by the stderr stream specifically, not just the class.
    _stderr_handlers_after = [h for h in _inwire_logger.handlers if getattr(h, "stream", None) is sys.stderr]
    check("to_stderr=False on a second call removes the stale stderr handler", _stderr_handlers_after, [])

    # An unwritable log directory plus to_stderr=False must still leave the
    # logger with a handler (a NullHandler), so logging.lastResort never
    # writes WARNING+ records to the real stderr behind the SCM's back.
    for _h in list(_inwire_logger.handlers):
        _inwire_logger.removeHandler(_h)
        _h.close()
    logging_setup._configured_with = None

    _blocking_file = tempfile.NamedTemporaryFile(delete=False)
    _blocking_file.close()
    _unwritable_dir = _blocking_file.name  # a file, not a directory: os.makedirs must fail
    try:
        logging_setup.setup_logging(_unwritable_dir, to_stderr=False)
        check_true("unwritable dir + to_stderr=False still leaves at least one handler", len(_inwire_logger.handlers) >= 1)
        check_true(
            "that handler is a NullHandler, so logging.lastResort cannot engage",
            any(isinstance(h, logging.NullHandler) for h in _inwire_logger.handlers),
        )
    finally:
        os.remove(_unwritable_dir)
finally:
    for _h in list(_inwire_logger.handlers):
        _inwire_logger.removeHandler(_h)
        _h.close()
    for _h in _saved_handlers:
        _inwire_logger.addHandler(_h)
    logging_setup._configured_with = _saved_configured_with
    _inwire_logger.level = _saved_level
    _inwire_logger.propagate = _saved_propagate

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
_handler_logger = logging.getLogger("inwire.test.handler")
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
    # `register` admits a connection immediately when no pairing token is
    # configured; these drive _handle_message directly, so they say so here.
    srv.authenticated.add(ws)

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

# --- the pairing token -------------------------------------------------------------
# The origin check keeps an ordinary web page out of the agent and stops
# nothing that can set a header, which is any process on this machine. The
# token is the control that tells the user's browser from another program
# running as the user, and it lives in a file only an administrator can read.
check_true("a token is 256 bits of hex", len(config.make_token()) == 64)
check_true("...and two are not the same", config.make_token() != config.make_token())
check_true("a token matches itself", config.tokens_match("abc123", "abc123"))
check_true("...and nothing else", not config.tokens_match("abc123", "abc124"))
check_true("surrounding whitespace is forgiven, since it will be pasted",
           config.tokens_match("  abc123\n", "abc123"))
check_true("a missing token matches nothing", not config.tokens_match(None, "abc123"))
check("a config with no token means no token", config.parse_config('{}')["token"], None)
check('an empty token is no token, not a token of nothing',
      config.parse_config('{"token": "   "}')["token"], None)
check("a config with a token reports it",
      config.parse_config('{"token": "deadbeef"}')["token"], "deadbeef")

# A token we could not read must never be reported as a token that is not
# there. The origin list falls back to defaults on a broken file because doing
# so allows only the origins we would have allowed anyway; doing the same to
# the token would turn a stray comma into "authentication silently off", which
# is the whole of what stands between the user's browser and any other program
# running as the user.
check_true("unparseable JSON leaves the token UNKNOWN, not absent",
           config.parse_config("{not json")["token"] is config.TOKEN_UNREADABLE)
check_true("...and so does JSON that is not an object",
           config.parse_config('["a"]')["token"] is config.TOKEN_UNREADABLE)
check_true("...and an unknown token is not None, so the agent still gates on it",
           config.parse_config("{not json")["token"] is not None)
check_true("...and matches nothing offered, so it fails closed",
           not config.tokens_match("deadbeef", config.parse_config("{not json")["token"]))
check_true("...and the origin list still falls back to defaults",
           config.parse_config("{not json")["allowedOrigins"] == config.DEFAULT_ALLOWED_ORIGINS)
check_true("a genuinely absent file still means no token, which is open",
           config.parse_config(None)["token"] is None)
check_true(
    "the origin list survives a config whose token is the only valid key",
    config.parse_config('{"token": "x", "allowedOrigins": 7}')["allowedOrigins"]
    == config.DEFAULT_ALLOWED_ORIGINS,
)
check("...and the token survives an unusable origin list",
      config.parse_config('{"token": "x", "allowedOrigins": 7}')["token"], "x")

class _AuthWS:
    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


# ensure_config is what the installer calls. The rules it has to keep: never
# replace a token somebody has already pasted into a browser, never lose
# anything else in the file, and *do* fill in a token that is missing - an
# upgrade that left every existing install unauthenticated for ever would
# defeat the point of having one.
import tempfile as _tempfile

_prev_programdata = os.environ.get("ProgramData")
_prev_restrict = config.restrict_config_permissions
try:
    os.environ["ProgramData"] = _tempfile.mkdtemp(prefix="inwire-config-")
    # The real one locks the file to SYSTEM and administrators, which would
    # stop this process reading back what it just wrote. It is exercised for
    # real on an installed agent, not here.
    config.restrict_config_permissions = lambda path, on_warning=None: True

    _first = config.ensure_config()
    check("ensure_config mints a 256-bit token", len(_first["token"] or ""), 64)
    check_true("...and keeps it on a second run", config.ensure_config()["token"] == _first["token"])

    with open(config.config_path(), "w", encoding="utf-8") as _fh:
        json.dump({"allowedOrigins": ["http://example.test"], "custom": 42}, _fh)
    _upgraded = config.ensure_config()
    check_true("a config with no token gets one", bool(_upgraded["token"]))
    with open(config.config_path(), "r", encoding="utf-8") as _fh:
        _raw = json.load(_fh)
    check("...and everything else in the file survives", _raw.get("custom"), 42)
    check("...including an edited allowlist", _raw.get("allowedOrigins"), ["http://example.test"])
finally:
    config.restrict_config_permissions = _prev_restrict
    if _prev_programdata is None:
        os.environ.pop("ProgramData", None)
    else:
        os.environ["ProgramData"] = _prev_programdata

_auth = agent.AgentServer()
_auth_ws = _AuthWS()
_auth.connections.add(_auth_ws)
asyncio.run(_auth._handle_message(_auth_ws, json.dumps({"type": "start_capture"})))
check("an unauthenticated connection cannot start a capture",
      _auth_ws.sent[-1]["code"], "auth_required")
check_true("...and is told nothing else", len(_auth_ws.sent) == 1)

# --- capture ownership -----------------------------------------------------------
# One capture, one owner. Two tabs used to share a single global sniffer: the
# second one's remembered set_interfaces restarted it on that tab's adapter the
# moment it connected, and Stop in either stopped both. Which tab was "the"
# capture was decided by whoever spoke last.
_own = agent.AgentServer()
_own.loop = object()
_a, _b = object(), object()
_own.connections.update({_a, _b})
_own.client_ids[_a] = "id-a"
_own.client_ids[_b] = "id-b"


class _StoppedSniffer:
    def is_sniffing(self):
        return False


class _RunningSniffer:
    def is_sniffing(self):
        return True


# `sniffer` is created in main(), so it may not exist in a test process.
_prev = getattr(agent, "sniffer", None)
agent.sniffer = _StoppedSniffer()
check_true("with nothing running, nobody is locked out", not _own.owned_by_other(_a))
check("...and no owner is reported", _own.owner_id(), None)

_own.capture_owner = _a
agent.sniffer = _RunningSniffer()
check_true("the owner is not locked out of its own capture", not _own.owned_by_other(_a))
check_true("the other tab is", _own.owned_by_other(_b))
check("the owner is named by the id its connection was given", _own.owner_id(), "id-a")

# A stale owner must not lock the agent out of capturing at all - that is a
# worse failure than two tabs racing.
_own.connections.discard(_a)
check_true("an owner whose socket is gone holds nothing", not _own.owned_by_other(_b))
check("...and ownership is released", _own.capture_owner, None)

# Ownership only bites while a capture is running: an owner that stopped is
# not still holding the agent.
_own.connections.add(_a)
_own.capture_owner = _a
agent.sniffer = _StoppedSniffer()
check_true("an idle agent is not busy", not _own.owned_by_other(_b))
if _prev is None:
    del agent.sniffer
else:
    agent.sniffer = _prev
agent.sniffer = _prev

check_true(
    "state names the owner so a second tab can tell the two cases apart",
    "owner" in agent.SnifferController(["eth0"]).state_message([], "id-a"),
)
check(
    "...and reports it",
    agent.SnifferController(["eth0"]).state_message([], "id-a")["owner"],
    "id-a",
)
check(
    "an idle agent has no owner",
    agent.SnifferController(["eth0"]).state_message([], None)["owner"],
    None,
)
check_true(
    "hello tells a connection its own id",
    agent.build_hello_message(agent.AGENT_VERSION, "idle", [], client_id="id-a")["clientId"] == "id-a",
)

# --- packet queue backpressure: the bound that keeps the agent from wedging ---
# Before 3.2.0 each captured frame scheduled its own coroutine, and the bound
# on how many could be outstanding is what the agent's log records as
# ">=260,000 packets dropped". Frames are queued as encoded records now and one
# pump drains them in batches, so the bound is on the queue.
import packet_batch

srv = agent.AgentServer()
srv.loop = object()          # queue_packet only checks that a loop exists
# Queueing is owner-scoped since 3.3.0: a frame is only worth holding for the
# connection that asked for the capture.
srv.capture_owner = object()
srv.connections.add(srv.capture_owner)

_rec = packet_batch.encode_record(0, 0, 1000, 60, b"\x00" * 60)
for _ in range(agent.MAX_QUEUED_PACKETS):
    srv.queue_packet(_rec)
check("the queue fills to the cap", len(srv._packet_queue), agent.MAX_QUEUED_PACKETS)
check("nothing dropped while under the cap", srv._dropped_sends, 0)

for _ in range(5000):
    srv.queue_packet(_rec)
check(
    "past the cap the queue stops growing - this is what bounds memory",
    len(srv._packet_queue),
    agent.MAX_QUEUED_PACKETS,
)
check("dropped packets are counted", srv._dropped_sends, 5000)
check_true(
    "the byte total tracks the deque rather than drifting",
    srv._packet_queue_bytes == sum(len(r) for r in srv._packet_queue),
)

# A viewer that has fallen behind wants the NEWEST frames, so it is the oldest
# records that go. Anything else would show a live capture running minutes late.
srv2 = agent.AgentServer()
srv2.loop = object()
srv2.capture_owner = object()
srv2.connections.add(srv2.capture_owner)
for seq in range(agent.MAX_QUEUED_PACKETS + 3):
    srv2.queue_packet(packet_batch.encode_record(seq, 0, 1000, 60, b"\x00" * 60))
_first = packet_batch.decode_batch(packet_batch.encode_batch([srv2._packet_queue[0]]))[0]
check("the oldest queued frames are the ones dropped", _first["seq"], 3)

# A drain takes at most one batch, and leaves the rest for the next pass.
srv3 = agent.AgentServer()
srv3.loop = object()
srv3.capture_owner = object()
srv3.connections.add(srv3.capture_owner)
for seq in range(agent.MAX_BATCH_RECORDS + 10):
    srv3.queue_packet(packet_batch.encode_record(seq, 0, 1000, 60, b"\x00" * 60))
_batch, _more = srv3._drain_packets()
check("a drain takes at most one batch", len(_batch), agent.MAX_BATCH_RECORDS)
check("...and leaves the remainder queued", len(srv3._packet_queue), 10)
check("...and says so, which is what stops the pump sleeping on it", _more, True)
check(
    "the drained records are the oldest, in order",
    [r["seq"] for r in packet_batch.decode_batch(packet_batch.encode_batch(_batch))[:3]],
    [0, 1, 2],
)
srv3.discard_queued_packets()
check("a stop empties the queue", (len(srv3._packet_queue), srv3._packet_queue_bytes), (0, 0))

# **The throttle, asserted at the boundary that hid it for two releases.**
#
# A drain stops on EITHER bound. The pump used to decide whether the queue had
# run dry by re-testing the RECORD count, so a batch cut short by the 256 kB
# byte bound - which is what every real frame size produces - was read as "the
# queue is empty" and the pump slept 10 ms on a full queue. 256 kB / 10 ms is
# 25.6 MB/s, about 23,000 frames a second at the 1,101-byte mean this repo
# measured.
#
# Small frames reach 512 records first, which is why every synthetic test in
# this file passed while real captures dropped. So this one uses frames big
# enough to hit the byte bound, and asserts the batch is short AND `more` is
# true - the exact combination the old code could not represent.
srv4 = agent.AgentServer()
srv4.loop = object()
srv4.capture_owner = object()
srv4.connections.add(srv4.capture_owner)
# 1,100-byte frames: about the measured mean, and 256 kB of them is well under
# 512 records.
for seq in range(600):
    srv4.queue_packet(packet_batch.encode_record(seq, 0, 1000, 1100, b"\x00" * 1100))
_big, _big_more = srv4._drain_packets()
check_true("a batch of real-sized frames stops on the byte bound, not the record bound",
           len(_big) < agent.MAX_BATCH_RECORDS)
check_true("...so the record count alone would call a backed-up queue empty",
           len(_big) < agent.MAX_BATCH_RECORDS and len(srv4._packet_queue) > 0)
check("...and `more` reports the backlog the count cannot see", _big_more, True)
_drained = 0
while True:
    _b, _m = srv4._drain_packets()
    _drained += len(_b)
    if not _m:
        break
check("draining while `more` clears the queue", len(srv4._packet_queue), 0)
check("...having delivered every frame", _drained + len(_big), 600)


# --- the binary packet frame ------------------------------------------------
# The browser has its own decoder (src/services/agentBinary.ts). These assert
# the bytes, not a description of them, so the two cannot drift apart silently.
_records = [
    packet_batch.encode_record(0, 0, 1788477971653284300, 1514, bytes(range(64))),
    packet_batch.encode_record(4294967295, 7, 1788477971653285501, 60, b""),
    packet_batch.encode_record(9, 1, 1000, 9000, b"\xff" * 9000),
]
_frame = packet_batch.encode_batch(_records)
check("the batch is tagged so a decoder can refuse anything else", _frame[:4], b"IWP1")
check("...and carries its version", _frame[4], packet_batch.VERSION)
check("...and its record count", int.from_bytes(_frame[6:8], "little"), 3)

_decoded = packet_batch.decode_batch(_frame)
check("every record comes back", len(_decoded), 3)
check("the capture time survives to the nanosecond", _decoded[1]["tsNs"], 1788477971653285501)
check("a sequence number at the u32 ceiling round-trips", _decoded[1]["seq"], 4294967295)
check("a zero-length capture is a record, not an error", _decoded[1]["data"], b"")
check("the wire length is carried apart from the captured length", _decoded[2]["origLen"], 9000)
check("a truncated frame still reports its length on the wire",
      (_decoded[0]["origLen"], len(_decoded[0]["data"])), (1514, 64))
check("a record is twenty-two bytes of framing", packet_batch.RECORD.size, 22)
# A wire length no 16-bit field holds: version 3 clamped its excess at 65,535,
# version 4 carries it whole.
_long_wire = packet_batch.decode_batch(packet_batch.encode_batch(
    [packet_batch.encode_record(0, 0, 1000, 200000, bytes(4))]))[0]
check("a wire length past the u16 ceiling is carried, not clamped",
      _long_wire["origLen"], 200000)
check("the frame bytes are exact", _decoded[0]["data"], bytes(range(64)))
check("the interface index is carried", _decoded[1]["iface"], 7)

# **A frame past the old 16-bit ceiling now goes through whole** (version 4).
# Version 3 refused it: a captured length is one the reader SEEKS BY, so masking
# it would have the decoder take its next record from inside a frame. At 32
# bits a frame captured at dumpcap's snaplen - longer than 65,535 bytes when a
# send was offloaded - arrives with its length.
_long = bytes(range(256)) * 280
_round = packet_batch.decode_batch(packet_batch.encode_batch(
    [packet_batch.encode_record(0, 0, 1000, len(_long), _long)]))
check("a frame past the old 16-bit ceiling arrives whole", _round[0]["data"], _long)
check("...with its wire length", _round[0]["origLen"], len(_long))
check("a wire length is never sent below what was captured",
      packet_batch.decode_batch(packet_batch.encode_batch(
          [packet_batch.encode_record(0, 0, 1000, 2, b"\x00" * 4)]))[0]["origLen"], 4)

for _bad, _why in (
    (b"NOPE" + _frame[4:], "refuses a frame that is not a batch"),
    (_frame[:-1], "refuses a truncated record"),
    (_frame + b"\x00", "refuses trailing bytes"),
    (b"IWP1\x63\x00\x01\x00", "refuses a version it does not know"),
):
    try:
        packet_batch.decode_batch(_bad)
        check(_why, "accepted", "rejected")
    except ValueError:
        check(_why, "rejected", "rejected")


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

        async def _run_watchdog_once(may_exit=False):
            task = asyncio.ensure_future(
                agent.watch_for_orphaned_capture(may_exit=may_exit))
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

        # --- the idle exit (ADR 0035) ---
        #
        # The agent stops the whole process, not just the capture, once the app
        # has gone. Everything below drives `watch_for_orphaned_capture` with a
        # shutdown event in place and reads whether it was set, because "did the
        # service stop" is not otherwise observable from inside it.
        _prev_grace = agent.FIRST_CLIENT_GRACE_SECONDS

        async def _idle_run(may_exit, seconds, connected=False):
            agent._shutdown_event = asyncio.Event()
            agent._shutdown_loop = asyncio.get_running_loop()
            if connected:
                _watch_srv.connections.add(object())
            else:
                _watch_srv.connections.clear()
            task = asyncio.ensure_future(
                agent.watch_for_orphaned_capture(may_exit=may_exit))
            await asyncio.sleep(seconds)
            task.cancel()
            was_set = agent._shutdown_event.is_set()
            agent._shutdown_event = None
            agent._shutdown_loop = None
            return was_set

        # The grace period is what keeps a demand-started service alive long
        # enough for the app that started it to connect. Without it the agent
        # kills itself before Inwire's first retry lands, which reads to
        # `pipeTransport.ts` as a crash loop.
        agent.FIRST_CLIENT_GRACE_SECONDS = 5.0
        check("a fresh agent does not exit before its first client",
              asyncio.run(_idle_run(True, 0.08)), False)

        # Once the grace has passed, an agent nothing ever connected to does
        # stop - an app that died between `sc start` and its first connection
        # must not leave a capture service running for ever.
        agent.FIRST_CLIENT_GRACE_SECONDS = 0.0
        check("...but it does exit once the grace period has passed",
              asyncio.run(_idle_run(True, 0.08)), True)

        # A connected client holds it open, which is the ordinary running state.
        check("a connected client keeps the agent alive",
              asyncio.run(_idle_run(True, 0.08, connected=True)), False)

        # The macOS/Linux tarball has no SCM to start it again on demand, so
        # exiting there means never coming back. The orphan check still runs -
        # that guarantee is unconditional - but the process must not stop.
        check("the WebSocket agent never exits on idleness",
              asyncio.run(_idle_run(False, 0.08)), False)

        # `IDLE_EXIT_TICKS` is a number with a specific job: absorbing
        # `AgentPipeLink.recycle()`, which closes and reopens the pipe. One tick
        # would let a reconnect that takes milliseconds stop the service.
        check_true("idleness must persist for more than one tick",
                   agent.IDLE_EXIT_TICKS >= 2)

        agent.FIRST_CLIENT_GRACE_SECONDS = _prev_grace
    finally:
        agent.agent = _prev_agent
        agent.ORPHAN_CHECK_SECONDS = 2
finally:
    if _prev_sniffer is None:
        if hasattr(agent, "sniffer"):
            del agent.sniffer
    else:
        agent.sniffer = _prev_sniffer


# --- capture timestamps come from the wire, not the wall clock ---
import decimal

# Since 3.5.0 capture_time_us takes libpcap's timestamp directly rather than a
# dissected packet to read `.time` off - the agent no longer builds one. scapy
# hands over an EDecimal, which json cannot serialize; Decimal reproduces that
# hazard faithfully.
#
# The millisecond form is gone with the JSON packet message; microseconds are
# what the binary record carries and what the browser reads.
_us = agent.capture_time_us(decimal.Decimal("1787795981.131456"))
check("capture_time_us converts seconds to microseconds", _us, 1787795981131456)
check_true("...as an integer, exact as a JS number", isinstance(_us, int))
check("a plain float works too, which is what libpcap reports",
      agent.capture_time_us(1787795981.131456), 1787795981131456)
check_true(
    "sub-millisecond precision survives - this is the whole point",
    agent.capture_time_us(decimal.Decimal("1.000100"))
    != agent.capture_time_us(decimal.Decimal("1.000900")),
)

# Two frames a quarter-millisecond apart must not collapse onto one stamp,
# which is exactly what int(time.time() * 1000) did.
_a = agent.capture_time_us(decimal.Decimal("100.000250"))
_b = agent.capture_time_us(decimal.Decimal("100.000500"))
check_true("frames within the same millisecond stay distinguishable", _a != _b)

# A socket reporting no time gets the wall clock. The test is `not stamp` and
# not `stamp is None`, because that is the test scapy's own recv applies before
# it will set pkt.time - so 0 and None mean the same thing at both ends.
check_true(
    "no capture time falls back to the wall clock rather than failing",
    agent.capture_time_us(None) > 0,
)
check_true("...and so does a zero, which scapy also treats as absent",
           agent.capture_time_us(0) > 0)


# --- the interface list is re-read, not frozen at startup --------------------
# The agent used to enumerate interfaces exactly once, in main(), and replay
# that snapshot in every hello/state for the life of the process. Windows
# creates and destroys adapters constantly (WAN Miniports, Wi-Fi Direct
# virtuals), and Npcap may not have finished binding when an auto-start service
# launches at boot - so a process started at a bad moment served a short list
# for its whole life, and one started before Npcap was ready refused to start.

_real_list_interfaces = agent.list_interfaces


def _fake_interfaces(pairs):
    """Swaps enumeration for a fixed answer, the way the OS would change."""
    agent.list_interfaces = lambda: list(pairs)


try:
    _fake_interfaces([("dev-ethernet", "Ethernet")])
    agent.refresh_interfaces()
    check(
        "refresh picks up the current adapter list",
        agent.AVAILABLE_INTERFACES,
        [("dev-ethernet", "Ethernet")],
    )

    # An adapter that appears after startup is the reported bug.
    _fake_interfaces([("dev-ethernet", "Ethernet"), ("dev-wifi", "Wi-Fi")])
    check(
        "an adapter that appears later is reported",
        agent.refresh_interfaces(),
        [("dev-ethernet", "Ethernet"), ("dev-wifi", "Wi-Fi")],
    )

    # Labels must move with the list, or a newly-appeared adapter would show up
    # under its raw device name in the log and the UI.
    check(
        "labels are rebuilt alongside the list",
        agent.INTERFACE_LABELS.get("dev-wifi"),
        "Wi-Fi",
    )

    # An adapter going away must not linger in the list.
    _fake_interfaces([("dev-ethernet", "Ethernet")])
    agent.refresh_interfaces()
    check_true(
        "an adapter that disappears is dropped",
        "dev-wifi" not in dict(agent.AVAILABLE_INTERFACES),
    )

    # Enumeration can throw (driver mid-reload). Losing the list a client is
    # already using would be worse than serving a slightly stale one.
    _known = [("dev-ethernet", "Ethernet")]

    def _raise():
        raise OSError("wpcap busy")

    agent.list_interfaces = _raise
    check(
        "a failed enumeration keeps the previous list rather than emptying it",
        agent.refresh_interfaces(),
        _known,
    )
finally:
    agent.list_interfaces = _real_list_interfaces



# --- restarting is refused unless it can actually come back ------------------
# restart_agent is implemented by exiting and letting Windows start a new
# process. That makes the guard the entire feature: in any situation where
# nothing would restart the agent, exiting is not a restart but a stop that the
# app has no way to undo - no browser can start a Windows service. Both
# conditions are proven by reading the SCM back at startup, never assumed.

check(
    "restart allowed only when running as the service AND a restart policy exists",
    agent.decide_restart_allowed(True, True),
    True,
)
check(
    "refused when running from source, where there is no service to restart",
    agent.decide_restart_allowed(False, True),
    False,
)
check(
    "refused when no restart-on-failure policy exists - exiting would stay stopped",
    agent.decide_restart_allowed(True, False),
    False,
)
check(
    "refused when neither holds",
    agent.decide_restart_allowed(False, False),
    False,
)

# The default has to be the safe one: RESTART_SUPPORTED is consulted by the
# command handler, and anything that leaves it untouched (an SCM query that
# throws, a platform with no services) must not enable the exit path.
check("restart support defaults to off until proven", agent.RESTART_SUPPORTED, False)
check_true(
    "a reason is always available to send back when it is off",
    isinstance(agent.RESTART_UNAVAILABLE_REASON, str) and len(agent.RESTART_UNAVAILABLE_REASON) > 0,
)

# Exiting cleanly would read to the SCM as an intentional stop, and no restart
# action would fire.
check_true("the restart exit code is non-zero", agent.RESTART_EXIT_CODE != 0)

# On a non-Windows box neither probe may claim success.
if os.name != "nt":
    check("service identity is false off Windows", agent._running_as_service_process(), False)
    check("failure policy is false off Windows", agent._ensure_failure_policy(), False)


# Exiting ends a capture, so restart_agent is the capture owner's to give, like
# stop_capture: another window gets capture_busy and nothing is scheduled. The
# owner, and anyone while idle, may still restart.
class _RestartWS:
    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


async def _restart_as(server, ws):
    server.authenticated.add(ws)
    await server._handle_message(ws, json.dumps({"type": "restart_agent"}))
    await asyncio.sleep(0.7)  # the exit is deferred by 0.5s, so wait it out


class _CapturingSniffer:
    def is_sniffing(self):
        return True


_rs_prev = (getattr(agent, "sniffer", None), agent.RESTART_SUPPORTED, agent.exit_for_restart)
_rs_calls = []
try:
    agent.RESTART_SUPPORTED = True
    agent.exit_for_restart = lambda: _rs_calls.append(1)
    agent.sniffer = _CapturingSniffer()
    _rs = agent.AgentServer()
    _rs_owner, _rs_other = _RestartWS(), _RestartWS()
    _rs.connections.update({_rs_owner, _rs_other})
    _rs.capture_owner = _rs_owner

    asyncio.run(_restart_as(_rs, _rs_other))
    check("restart_agent from a non-owner is told capture_busy",
          [m.get("code") for m in _rs_other.sent], ["capture_busy"])
    check("...and no restart is scheduled", _rs_calls, [])
    asyncio.run(_restart_as(_rs, _rs_owner))
    check("the owner's own restart_agent is still honoured", _rs_calls, [1])
finally:
    agent.sniffer, agent.RESTART_SUPPORTED, agent.exit_for_restart = _rs_prev
    if agent.sniffer is None:
        del agent.sniffer



import adapters

# --- 3.1.0: every state-changing command answers with a state broadcast -------
# This went missing in a refactor once (the broadcast ended up after the
# interface-stats loop, where it never ran) and the app's "Capture:" row sat
# frozen for weeks. Asserted per command so it cannot quietly leave again.
class _RecordingWS:
    def __init__(self):
        self.sent = []

    async def send(self, data):
        self.sent.append(json.loads(data))


def _drive(server, ws, message):
    # Same as above: no token configured means every connection is admitted.
    server.authenticated.add(ws)
    asyncio.run(server._handle_message(ws, json.dumps(message)))


_prev_sniffer = getattr(agent, "sniffer", None)
_prev_spawn = agent.spawn_sniffer_thread
try:
    agent.sniffer = agent.SnifferController(default_interfaces=["eth0"])
    agent.spawn_sniffer_thread = lambda name, stop_event: None
    srv = agent.AgentServer()
    ws = _RecordingWS()
    srv.connections.add(ws)
    sent_states = []
    srv.send_control = lambda message: sent_states.append(message)

    _drive(srv, ws, {"type": "start_capture"})
    check("start_capture broadcasts a state", [m["type"] for m in sent_states], ["state"])
    check("...that says sniffing", sent_states[-1]["state"], "sniffing")

    # ADR 0048: a capture's adapters are fixed for its life. The change used to
    # restart the capture on the new set; now it is refused, to the sender only.
    _drive(srv, ws, {"type": "set_interfaces", "interfaces": ["eth1"]})
    check("set_interfaces mid-capture is refused",
          [(m.get("code"), m.get("message")) for m in ws.sent],
          [("capture_running", "Stop the capture before changing interfaces.")])
    check("...and broadcasts no state", len(sent_states), 1)
    check("...and the controller keeps the adapters it started on",
          agent.sniffer.selected_interfaces, ["eth0"])
    check("...and is still sniffing", agent.sniffer.is_sniffing(), True)

    _drive(srv, ws, {"type": "stop_capture"})
    check("stop_capture broadcasts a state", len(sent_states), 2)
    check("...that says idle", sent_states[-1]["state"], "idle")

    _drive(srv, ws, {"type": "set_interfaces", "interfaces": ["eth1"]})
    check("stopped, set_interfaces broadcasts a state", len(sent_states), 3)
    check("...and the controller now has the new list", agent.sniffer.selected_interfaces, ["eth1"])
    check("...and stays idle", sent_states[-1]["state"], "idle")

    ws.sent.clear()
    _drive(srv, ws, {"type": "set_interfaces", "interfaces": "eth1"})
    check("a malformed set_interfaces is answered, not ignored",
          [m.get("code") for m in ws.sent], ["invalid_interfaces"])
    check("...and broadcasts no state", len(sent_states), 3)

    _drive(srv, ws, {"type": "set_interfaces", "interfaces": []})
    check("an empty set_interfaces is still refused", ws.sent[-1].get("code"), "empty_interfaces")

    _drive(srv, ws, {"type": "teleport"})
    check("an unknown command is named back to the client", ws.sent[-1].get("code"), "unknown_command")
    check_true("...with the agent version in the message", agent.AGENT_VERSION in ws.sent[-1]["message"])
    check("...and broadcasts no state", len(sent_states), 3)

    _drive(srv, ws, {"type": "subscribe_logs"})
    check("a subscription does not broadcast state", len(sent_states), 3)

    # 3.6.0. Reading adapters changes nothing about what the agent is DOING,
    # so like every other subscription it must take the early return rather
    # than falling through to the broadcast at the foot of the handler.
    _prev_read = adapters.read_adapters
    try:
        adapters.read_adapters = lambda provider=None, keep=None: [
            {"id": "eth0", "name": "eth0", "ipv4": [], "ipv6": [], "dnsServers": []}]
        _drive(srv, ws, {"type": "subscribe_adapters"})
        check("subscribe_adapters answers with a snapshot", ws.sent[-1]["type"], "adapter_config")
        check("...immediately, rather than waiting for a change",
              [a["id"] for a in ws.sent[-1]["adapters"]], ["eth0"])
        check("...and broadcasts no state", len(sent_states), 3)
        check_true("...and the socket is now a subscriber", ws in srv.adapter_subscribers)

        # The tracker is silent when nothing changed, which is almost every
        # poll - so Refresh has to drop the previous reading, or pressing it
        # after changing nothing would answer with nothing at all.
        _drive(srv, ws, {"type": "refresh_adapters"})
        check("refresh_adapters answers even when nothing changed",
              ws.sent[-1]["type"], "adapter_config")
        check("...and still broadcasts no state", len(sent_states), 3)

        _drive(srv, ws, {"type": "unsubscribe_adapters"})
        check_true("unsubscribe_adapters drops the subscription",
                   ws not in srv.adapter_subscribers)
    finally:
        adapters.read_adapters = _prev_read
finally:
    agent.spawn_sniffer_thread = _prev_spawn
    if _prev_sniffer is None:
        del agent.sniffer
    else:
        agent.sniffer = _prev_sniffer


# --- 3.1.0: packets carry seq, iface, tsUs and origLen ---------------------------
#
# Since 3.5.0 there is no fake scapy packet to build here: packet_to_record
# takes the frame's bytes and its timestamp, which is all it ever read of one.
_frame = (bytes(range(256)) * 5 + bytes(234))     # 1514 bytes, and not all zero
_rec = agent.packet_to_record(_frame, decimal.Decimal("1788477971.653284"), iface_id=2, seq=41)
_msg = packet_batch.decode_batch(packet_batch.encode_batch([_rec]))[0]
check("packet carries its sequence number", _msg["seq"], 41)
check("packet carries its interface id", _msg["iface"], 2)
check("packet carries the capture time, as nanoseconds of a microsecond stamp",
      _msg["tsNs"], 1788477971653284000)
check("packet carries the wire length", _msg["origLen"], 1514)
check("packet carries the frame itself", len(_msg["data"]), 1514)
# The bytes go through untouched. Until 3.5.0 they made a round trip through a
# scapy object graph on the way; that they came back unchanged across all
# 27,640 frames of both fixtures is what made removing it a safe change.
check("...unaltered, byte for byte", _msg["data"], _frame)
check("capture_time_us rounds float noise away",
      agent.capture_time_us(decimal.Decimal("1.000001")), 1000001)
check_true("a frame with no time still gets a microsecond stamp",
           agent.capture_time_us(None) > 1_000_000_000_000_000)

_c = agent.CaptureCounters()
check("sequence numbers start at zero", _c.next_seq(0), 0)
check("...and count up across interfaces", [_c.next_seq(1), _c.next_seq(0)], [1, 2])
check("received is counted per interface", _c.snapshot()[1], {0: 2, 1: 1})
_c.reset()
check("reset restarts the sequence for a new capture", _c.next_seq(0), 0)

# --- 3.1.0: capture_stats ---------------------------------------------------------
_stats = agent.build_capture_stats(seq_high=10, received={0: 10, 1: 0},
                                   kernel_stats={0: (12, 2), 1: None}, dropped_agent=3)
check("capture_stats type", _stats["type"], "capture_stats")
check("capture_stats reports the next sequence number", _stats["seqHigh"], 10)
check("capture_stats reports the agent's own drops", _stats["droppedAgent"], 3)
check("capture_stats lists every interface with the driver's numbers",
      _stats["interfaces"],
      [{"iface": 0, "received": 10, "kernelReceived": 12, "droppedKernel": 2},
       {"iface": 1, "received": 0, "kernelReceived": None, "droppedKernel": None}])
check("an unreadable driver counter is null, never zero", _stats["interfaces"][1]["droppedKernel"], None)
# The handle lives on `pcap_fd` in current scapy and on `ins` in older ones.
# Reading only `ins` is why the driver's drop counter came back None on every
# real capture, which looked exactly like "this driver has no counter".
class _FakeWrapper:
    pcap = None


class _FakeSocketNewName:
    pcap_fd = _FakeWrapper()


class _FakeSocketOldName:
    ins = _FakeWrapper()


check_true("read_pcap_stats looks at pcap_fd", hasattr(_FakeSocketNewName, "pcap_fd"))
check("...and finds nothing when the handle is null",
      agent.read_pcap_stats(_FakeSocketNewName()), None)
check("...and still understands the older attribute name",
      agent.read_pcap_stats(_FakeSocketOldName()), None)

check("read_pcap_stats returns None for a socket with no pcap handle", agent.read_pcap_stats(object()), None)

_sc = agent.SnifferController(default_interfaces=["eth0", "eth1"])
_sc.start_threads(lambda name, ev: None)
check("one failed interface does not end the capture", _sc.mark_failed("eth0"), False)
check("the last failed interface does", _sc.mark_failed("eth1"), True)
_sc.stop_threads()
_sc.start_threads(lambda name, ev: None)
check("failures are forgotten on the next start", _sc.mark_failed("eth0"), False)

# --- 3.2.0: the packet queue is guarded by a lock -------------------------------
# The sniffer threads append and the pump drains, so an unguarded deque would
# let the byte total drift away from the deque it is supposed to describe -
# and the bound that keeps the agent from growing without limit is on that
# total.
check_true("the packet queue's counters are guarded", hasattr(agent.AgentServer(), "_packet_lock"))

# --- 3.4.0: which process owns which local socket -------------------------------
#
# The table is read on a one-second tick and reported as deltas, so the parts
# that can go wrong are all about what happens BETWEEN two readings: a socket
# that came and went, a local port handed to a different process, a client that
# subscribed after the table was already being watched. Each of those is a
# wrong process name on a packet row rather than a crash, which is exactly the
# kind of fault that ships.
import sockets


class _FakeAddr:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class _FakeConn:
    """Just enough of psutil's sconn: a type, a local address and a pid."""

    def __init__(self, kind, ip, port, pid, raddr=None):
        self.type = kind
        # psutil reports an absent address as an empty tuple rather than as an
        # object with empty fields, and a fake that got that wrong is what let
        # an unkeyable socket through the first time this was written.
        self.laddr = _FakeAddr(ip, port) if ip is not None else ()
        self.raddr = raddr
        self.pid = pid


class _FakeProcess:
    def __init__(self, name, exe=None, denied_exe=False):
        self._name = name
        self._exe = exe or ""
        self._denied_exe = denied_exe

    def name(self):
        return self._name

    def exe(self):
        if self._denied_exe:
            raise PermissionError("access is denied")
        return self._exe


_TCP, _UDP = 1, 2

check("an IPv6 zone index is stripped, so it can match a captured address",
      sockets.normalize_address("fe80::1%eth0"), "fe80::1")
check("...and an address without one is untouched",
      sockets.normalize_address("10.0.0.4"), "10.0.0.4")

# The measured fact this module is keyed on: Windows reports no remote address
# for UDP sockets, so a five-tuple key would attribute no QUIC and no DNS.
_table = sockets.read_socket_table(lambda: [
    _FakeConn(_UDP, "0.0.0.0", 5353, 4242),
    _FakeConn(_TCP, "10.0.0.4", 54321, 4242, raddr=_FakeAddr("1.1.1.1", 443)),
])
check("a socket is keyed by its local endpoint alone",
      sorted(_table), [("tcp", "10.0.0.4", 54321), ("udp", "0.0.0.0", 5353)])

check("a socket the OS will not attribute is kept, with no pid",
      sockets.read_socket_table(lambda: [_FakeConn(_TCP, "10.0.0.4", 1, None)]),
      {("tcp", "10.0.0.4", 1): 0})

check("a socket with no local address has nothing to key it by and is dropped",
      sockets.read_socket_table(lambda: [_FakeConn(_TCP, None, 0, 7)]), {})

check("a process that denies its path still gives up its name",
      sockets.describe_process(9, lambda pid: _FakeProcess("svchost.exe", denied_exe=True)),
      {"name": "svchost.exe", "exe": ""})
check("a process that exited between the two calls is reported as unknown",
      sockets.describe_process(9, lambda pid: (_ for _ in ()).throw(ProcessLookupError())), None)
check("pid 0 is not a process", sockets.describe_process(0), None)


# One mutable table the fake source reads, so a test can open and close a
# socket between polls the way the machine does.
_live = [_FakeConn(_TCP, "10.0.0.4", 54321, 100)]
_names = {100: _FakeProcess("chrome.exe", "C:/chrome.exe"),
          200: _FakeProcess("curl.exe", "C:/curl.exe")}
_tracker = sockets.SocketTracker(source=lambda: list(_live),
                                 namer=lambda pid: _names[pid])

_first = _tracker.poll()
check("the first poll of a subscription is a full snapshot", _first["full"], True)
check("...carrying every socket as an addition", _first["add"],
      [["tcp", "10.0.0.4", 54321, 100]])
check("...and naming the process behind it", _first["procs"]["100"]["name"], "chrome.exe")

check("a second with no change sends nothing at all", _tracker.poll(), None)

_live.append(_FakeConn(_UDP, "0.0.0.0", 62664, 100))
_second = _tracker.poll()
check("a later poll is a delta, not a snapshot", _second["full"], False)
check("...listing only what appeared", _second["add"], [["udp", "0.0.0.0", 62664, 100]])
check("...and nothing that was already known", _second["gone"], [])

_live.pop(0)
_third = _tracker.poll()
check("a closed socket is reported gone", _third["gone"], [["tcp", "10.0.0.4", 54321]])
check("...and nothing is re-added with it", _third["add"], [])

# The failure this design exists to survive. A local port freed by one process
# and taken by another must arrive as a NEW attribution, or every frame the
# second process sends is labelled with the first one's name.
_live.append(_FakeConn(_UDP, "0.0.0.0", 62664, 200))
_live.remove(_live[0])
_fourth = _tracker.poll()
check("a reused local port is re-attributed rather than left stale",
      _fourth["add"], [["udp", "0.0.0.0", 62664, 200]])
check("...and the new owner is named in the same message",
      _fourth["procs"]["200"]["name"], "curl.exe")

_tracker.reset()
_fifth = _tracker.poll()
check("reset makes the next poll a full snapshot again", _fifth["full"], True)
check("...of everything currently open", len(_fifth["add"]), len(_live))


# The subscription itself: a client that arrives late gets its own snapshot
# rather than a delta against a table it never had.
#
# `_handle_message` builds its own `SocketTracker()` with no source, so unlike
# every check above it there is nothing to inject and it reads the machine's
# real socket table. That is two problems rather than one. It needs a
# privilege: `psutil.net_connections()` is root-only on macOS, and this raised
# `psutil.AccessDenied` on the first CI run that ever got far enough to
# execute it. And what it returns is whatever the machine happens to have open,
# so the assertions below could only ever be about the message's SHAPE - the
# one thing a test of a subscription should not have to settle for.
#
# Patching the module function fixes both. The pid is this process's own, so
# the default namer resolves it without a second fake, and the snapshot is a
# known one row long.
_real_net_connections = sockets.psutil.net_connections
sockets.psutil.net_connections = lambda kind="inet": [
    _FakeConn(_TCP, "10.0.0.4", 54321, os.getpid()),
]
try:
    _srv = agent.AgentServer()
    _sock_ws = _RecordingWS()
    _srv.connections.add(_sock_ws)
    _sock_states = []
    _srv.send_control = lambda message: _sock_states.append(message)
    _drive(_srv, _sock_ws, {"type": "subscribe_sockets"})
finally:
    sockets.psutil.net_connections = _real_net_connections

check("subscribing is answered with a socket_table", _sock_ws.sent[-1]["type"], "socket_table")
check("...and that first one is a full snapshot", _sock_ws.sent[-1]["full"], True)
check("...carrying the table the agent actually read", _sock_ws.sent[-1]["add"],
      [["tcp", "10.0.0.4", 54321, os.getpid()]])
check("...and broadcasts no state", _sock_states, [])
check_true("...and registers the subscriber", _sock_ws in _srv.socket_subscribers)

_drive(_srv, _sock_ws, {"type": "unsubscribe_sockets"})
check_true("unsubscribing removes it", _sock_ws not in _srv.socket_subscribers)

# --- capture profiling -----------------------------------------------------------
#
# The instrument sits on the hot path it measures, so the property that matters
# most is that it costs nothing when nobody asked for it.
import capture_profile

_off = capture_profile.CaptureProfile(enabled=False)
_off.frame(0.5)
check("a disabled profile records nothing", _off.snapshot(), None)
check("...and says so rather than reporting zeroes", _off.describe(), "capture profiling is off")

_on = capture_profile.CaptureProfile(enabled=True)
check("an enabled profile with no frames reports none", _on.snapshot()["frames"], 0)
check("...and describes that without dividing by it", _on.describe(), "capture profile: no frames yet")

# Real elapsed time, not a fabricated number: the invariant below is that the
# measured halves fit inside the wall clock, and feeding it timings that never
# actually elapsed would assert nothing while appearing to.
#
# The elapsed values are KEPT, so the mean can be checked against the numbers
# that were actually fed in. It used to be checked against the range
# `900.0 <= callbackUs <= 3000.0`, which is a statement about how long
# `time.sleep(0.001)` takes - true on a workstation and not on a shared CI
# runner, where the macOS job overshot 3 ms and failed both halves. That is a
# flake rather than a finding: a wall-clock ceiling on a virtualised machine
# measures the hypervisor.
#
# Comparing against the mean is also the stronger check. The range would have
# passed on any number that happened to land inside it, including one measured
# from the wrong half; this one fails unless the profile averaged exactly the
# values it was given.
_cbs, _reads = [], []
for _ in range(4):
    _t0 = time.perf_counter()
    time.sleep(0.001)
    _cb = time.perf_counter() - _t0
    _t1 = time.perf_counter()
    time.sleep(0.001)
    _read = time.perf_counter() - _t1
    _cbs.append(_cb)
    _reads.append(_read)
    _on.frame(_cb, _read, _read)
_snap = _on.snapshot()
check("frames are counted", _snap["frames"], 4)
check_true("the callback share is the mean of what was measured",
           abs(_snap["callbackUs"] - (sum(_cbs) / len(_cbs)) * 1e6) < 0.05)
check_true("...and so is the copy share",
           abs(_snap["copyUs"] - (sum(_reads) / len(_reads)) * 1e6) < 0.05)
# The sleeps have to have actually elapsed, or the two checks above would be
# comparing zero against zero and passing.
check_true("...and the timings are real elapsed time, not zeroes",
           _snap["callbackUs"] >= 900.0 and _snap["copyUs"] >= 900.0)
check("every frame's read was timed on this branch", _snap["readFrames"], 4)
check_true("what a frame COSTS is the copy plus the callback",
           abs((_snap["callbackUs"] + _snap["copyUs"]) - _snap["busyUs"]) < 0.05)
# Arrival is a different quantity from cost, and keeping them apart is the
# whole correction. Wall time per frame includes everything the thread spent
# waiting for traffic, so it is at least the cost and usually much more.
check_true("arrival per frame is at least what a frame cost",
           _snap["arrivalPerFrameUs"] >= _snap["busyUs"])
check_true("...and the gap between them is reported as idle",
           abs((_snap["busyUs"] + _snap["idleUs"]) - _snap["arrivalPerFrameUs"]) < 0.05)
check_true("a ceiling is derived from the cost", _snap["sustainableFramesPerSecond"] > 0)

# **The regression this module exists to prevent.** `impliedFramesPerSecond` was
# `frames / wall`, which is the ARRIVAL rate: it counts the thread's idle time as
# if it were work, so it can never exceed the rate traffic happened to arrive at
# and can never say the thread could not keep up - the one question it was asked.
# `packet_batch.py` cites a driver limit derived from it.
#
# So: same per-frame cost, ten times the idle between frames. The ceiling must
# not move; the arrival rate must collapse. Asserted as a RATIO rather than as
# absolute numbers, because a loaded CI machine moves both together.
_idle = capture_profile.CaptureProfile(enabled=True)
for _ in range(4):
    time.sleep(0.010)
    _idle.frame(0.0002, 0.0002, 0.0002)
_slow = _idle.snapshot()
check_true("a quiet link does not lower the ceiling",
           _slow["sustainableFramesPerSecond"] > 1000)
check_true("...while the arrival rate reports the quiet",
           _slow["arrivalFramesPerSecond"] < 200)
check_true("...and utilisation names which of the two is the bottleneck",
           _slow["utilisation"] < 0.2)

# **The same mistake, one level down, and it shipped for a commit.** Timing the
# read instead of the wall clock was the first fix - and `pcap_next_ex` BLOCKS
# until a frame arrives, so a successful read on a quiet link is mostly waiting.
# Measured against a real 493 f/s adapter it reported 1,439 us a frame, which is
# 1/493 of a second: the link again, wearing the name of a cost.
#
# So the call and the copy are timed apart, and the ceiling comes from the copy.
# Here: a 10 ms blocking call that yields 200 us of actual copying. The ceiling
# must reflect the copy, and `waitBound` must say the driver's share was not
# visible in this sample.
_blocking = capture_profile.CaptureProfile(enabled=True)
for _ in range(4):
    time.sleep(0.010)
    _blocking.frame(0.0001, pcap_seconds=0.0100, copy_seconds=0.0002)
_bw = _blocking.snapshot()
check_true("a blocking read does not become a per-frame cost",
           _bw["sustainableFramesPerSecond"] > 2000)
check_true("...and the call's own time is still reported, apart from it",
           _bw["pcapUs"] > 9000)
check("...with a flag saying the driver's share was not measurable here",
      _bw["waitBound"], True)
# Under load the call stops being the wait, and the flag clears.
_loaded = capture_profile.CaptureProfile(enabled=True)
for _ in range(200):
    _loaded.frame(0.000002, pcap_seconds=0.000002, copy_seconds=0.000002)
check("a saturated link is not wait-bound", _loaded.snapshot()["waitBound"], False)

# The unmeasurable branch reports an absence, not a zero. `sniff(prn=...)`
# invokes the callback from inside scapy's own loop, so there is no read to
# bracket - and it is the SLOWEST branch, so a read rounded to 0 would have
# made it report the highest ceiling in the table.
_untimed = capture_profile.CaptureProfile(enabled=True)
_untimed.frame(0.0005)
_u = _untimed.snapshot()
check("a branch that cannot time its read says so", _u["copyUs"], None)
check("...and no frame is counted as timed", _u["readFrames"], 0)
check("...so there is no ceiling to report", _u["sustainableFramesPerSecond"], None)
check("...and no headroom either", _u["idleUs"], None)
check_true("...and describe() says which it could not measure",
           "no ceiling to report" in _untimed.describe())

_on.reset()
check("reset starts a fresh measurement", _on.snapshot()["frames"], 0)

# The env var is the only switch, and an unset or falsy one leaves it off - an
# installed service must not carry timing overhead because a variable was left
# lying around with "0" in it.
_saved = os.environ.get("INWIRE_PROFILE_CAPTURE")
try:
    for _value, _expected in (("", False), ("0", False), ("false", False), ("off", False),
                              ("1", True), ("yes", True)):
        os.environ["INWIRE_PROFILE_CAPTURE"] = _value
        check(f"INWIRE_PROFILE_CAPTURE={_value!r} enables profiling: {_expected}",
              capture_profile.profiling_enabled(), _expected)
    os.environ.pop("INWIRE_PROFILE_CAPTURE", None)
    check("an unset variable leaves profiling off", capture_profile.profiling_enabled(), False)
finally:
    if _saved is None:
        os.environ.pop("INWIRE_PROFILE_CAPTURE", None)
    else:
        os.environ["INWIRE_PROFILE_CAPTURE"] = _saved

check("the agent starts with profiling off unless asked",
      agent.profile.enabled, capture_profile.profiling_enabled())

# --- 3.5.0: the capture loop reads raw frames -------------------------------------
#
# The change with the most ways to go quietly wrong in this release. sniff()
# handed the callback a dissected packet; recv_raw hands over bytes and a
# timestamp, and the loop around it now owns three things sniff() used to do:
# honouring stop_event, tolerating a read timeout, and choosing a strategy per
# socket type. Each is checked here against a fake socket, because the real one
# needs an adapter and elevation.
import threading as _threading
from scapy.supersocket import SuperSocket as _SuperSocket


class _FakeWrapper:
    """scapy's `_PcapWrapper_libpcap`, as far as the agent looks at it: the one
    thing it wants is the raw libpcap handle on `.pcap`."""

    pcap = "HANDLE"


class _FakePcapSocket:
    """A libpcap-style socket.

    Since 3.7.0 the loop does not call `recv_raw` on one of these at all - it
    goes to `pcap_next_ex` itself, because scapy's wrapper around that call
    builds one Python int object per captured byte (see agent.read_frame). What
    identifies such a socket is a libpcap handle, so that is what this has;
    `recv_raw` stays so the fallback paths below can still be exercised.
    """

    pcap_fd = _FakeWrapper()

    def __init__(self, script):
        self.script = list(script)
        self.closed = False
        self.selects = 0

    def recv_raw(self, x=None):
        if not self.script:
            return None, None, None
        return self.script.pop(0)

    def select(self, socks, remain=None):
        self.selects += 1
        return socks

    def close(self):
        self.closed = True


class _FakeAfPacketSocket(_FakePcapSocket):
    """AF_PACKET blocks in recv_raw forever, so its loop must poll select().

    No libpcap handle, which is also what keeps it off the fast path: the
    per-byte cost that path avoids is scapy's libpcap wrapper's, and AF_PACKET's
    own recv_raw is a plain recvfrom that never had it.
    """
    pcap_fd = None


class _BaseRecvRawSocket(_FakePcapSocket):
    """A socket that never overrode recv_raw. SuperSocket's base returns no
    timestamp at all, so this one must NOT take the fast path."""
    pcap_fd = None
    recv_raw = _SuperSocket.recv_raw


def _run_capture(sock, frames_before_stop):
    """Drives sniff_on_interface against `sock`, stopping after N frames."""
    queued = []
    stop = _threading.Event()
    prev_l2listen = agent.scapy_conf.L2listen
    prev_queue = agent.agent.queue_packet
    prev_sniff = agent.sniff
    agent.counters.reset()
    sniff_calls = []

    def _queue(record):
        queued.append(record)
        if len(queued) >= frames_before_stop:
            stop.set()

    prev_read_frame = agent.read_frame
    prev_set_buffer = agent.set_kernel_buffer

    def _read_frame(handle, header, data):
        """Stands in for the ctypes call, replaying the socket's script.

        The loop's job is stop_event, read timeouts and picking a branch;
        read_frame's own job - caplen against wire length - is checked directly
        further down, against real memory.
        """
        if not sock.script:
            return None
        _cls, raw, ts = sock.script.pop(0)
        return None if raw is None else (raw, ts, len(raw))

    agent.scapy_conf.L2listen = lambda **kw: sock
    agent.agent.queue_packet = _queue
    agent.sniff = lambda **kw: (sniff_calls.append(kw), stop.set())[0]
    agent.read_frame = _read_frame
    agent.set_kernel_buffer = lambda s, size=None: 1234
    try:
        agent.sniff_on_interface("eth0", "Ethernet 0", stop, iface_id=3)
    finally:
        agent.scapy_conf.L2listen = prev_l2listen
        agent.agent.queue_packet = prev_queue
        agent.sniff = prev_sniff
        agent.read_frame = prev_read_frame
        agent.set_kernel_buffer = prev_set_buffer
    return queued, sniff_calls


_A = b"\xaa" * 64
_B = b"\xbb" * 128

_sock = _FakePcapSocket([
    (None, _A, decimal.Decimal("100.000001")),
    (None, None, None),                       # a read timeout, not an error
    (None, _B, decimal.Decimal("100.000002")),
])
_queued, _sniffs = _run_capture(_sock, frames_before_stop=2)
check("the raw loop queues a record per frame", len(_queued), 2)
check("...and does not fall back to sniff()", _sniffs, [])
_decoded = packet_batch.decode_batch(packet_batch.encode_batch(_queued))
check("...carrying the frame's own bytes", [m["data"] for m in _decoded], [_A, _B])
check("...its wire length", [m["origLen"] for m in _decoded], [64, 128])
check("...and libpcap's timestamp, to the microsecond",
      [m["tsNs"] for m in _decoded], [100000001000, 100000002000])
check("...numbered in capture order", [m["seq"] for m in _decoded], [0, 1])
check("...and tagged with the adapter", [m["iface"] for m in _decoded], [3, 3])
# A None from recv_raw is the read timeout expiring. Treating it as a frame
# would queue a null record; treating it as an error would end the capture on
# the first quiet moment on the wire.
check_true("a read timeout is skipped rather than queued or fatal", len(_queued) == 2)
check_true("the socket is closed on the way out", _sock.closed)
check("a libpcap socket is not polled with select()", _sock.selects, 0)


# --- 3.7.0: reading a frame without scapy's per-byte materialisation --------------
#
# `_PcapWrapper_libpcap.next()` ends with
#
#     pkt = bytes(bytearray(self.pkt_data[:self.header.contents.len]))
#
# and slicing a ctypes pointer builds a Python list holding one int object per
# byte. Measured over a real 300,228-frame capture: 26.67 us a frame against
# 2.22 for the single memcpy `string_at` does - 12x, and it scales with frame
# size, so a bulk transfer is exactly the traffic it drowns. It is the same
# class of waste 3.5.0 removed one layer up, left behind because that change
# stopped at `recv_raw` and this is inside it.
#
# That line also reads `.len` - the length on the WIRE - out of a buffer that
# only holds `.caplen`. The two are equal until something truncates a frame,
# and then it reads past the captured data. The checks below are on that
# distinction, against real memory rather than a fake, because getting it
# wrong is a buffer over-read rather than a wrong number.
import ctypes as _ctypes


class _FakeTimeval(_ctypes.Structure):
    _fields_ = [("tv_sec", _ctypes.c_long), ("tv_usec", _ctypes.c_long)]


class _FakeHeader(_ctypes.Structure):
    _fields_ = [("ts", _FakeTimeval), ("caplen", _ctypes.c_uint), ("len", _ctypes.c_uint)]


def _read_one(payload, caplen, wire_len, result=1):
    """Drives agent.read_frame over a real buffer with a stubbed pcap_next_ex."""
    buf = _ctypes.create_string_buffer(payload, len(payload))
    hdr = _FakeHeader()
    hdr.ts.tv_sec, hdr.ts.tv_usec = 100, 1
    hdr.caplen, hdr.len = caplen, wire_len
    header_ptr = _ctypes.pointer(hdr)
    data_ptr = _ctypes.cast(buf, _ctypes.POINTER(_ctypes.c_ubyte))

    prev = agent.pcap_next_ex

    def _next(handle, header_out, data_out):
        # Nothing is written through the byref() arguments: read_frame is
        # handed pointers that ALREADY point at the header and buffer below, so
        # returning 1 leaves it reading exactly what libpcap would have left
        # there. Assigning through a byref() object is not possible from Python
        # anyway - `_obj` is read-only.
        return result

    agent.pcap_next_ex = _next
    try:
        return agent.read_frame("HANDLE", header_ptr, data_ptr)
    finally:
        agent.pcap_next_ex = prev


_whole = _read_one(bytes([0xAB]) * 64, caplen=64, wire_len=64)
check("a whole frame comes back with its bytes, time and length",
      (_whole[0], _whole[1], _whole[2]), (bytes([0xAB]) * 64, 100.000001, 64))

# The bug in scapy's line. 64 bytes were captured of a 1,514-byte frame: copy
# 64, report 1,514. Reading `.len` bytes out of a `.caplen` buffer is an
# over-read of 1,450 bytes of whatever follows it in memory.
_short = _read_one(bytes([0xCD]) * 64, caplen=64, wire_len=1514)
check("a truncated frame copies caplen and reports the wire length",
      (len(_short[0]), _short[2]), (64, 1514))

# libpcap opens with to_ms=100 and returns 0 when that elapses. It is a quiet
# adapter, not an error, and treating it as one would end a capture the first
# time the wire went silent.
check("a read timeout is None rather than an empty frame",
      _read_one(b"", caplen=0, wire_len=0, result=0), None)

# **A timeout and a failure are different answers, and collapsing them spun the
# CPU.** This was `if result != 1: return None`, and the caller is
# `while not stop_event.is_set(): ... continue`. pcap_next_ex returns 0 for the
# timeout but -1 for an error - and an adapter removed mid-capture returns -1
# immediately, for ever. The loop then burned 100% of a core inside a
# LocalSystem service, with no frames, no log line and nothing on screen.
#
# Raising is what reaches the machinery that already existed: sniff_on_interface
# wraps this loop in a try/except that calls report_capture_failure, which is
# how the app is told an interface died.
for _result, _what in ((-1, "an error"), (-2, "end of capture")):
    _raised = "no error"
    try:
        _read_one(b"", caplen=0, wire_len=0, result=_result)
    except OSError:
        _raised = "OSError"
    check(f"{_what} raises rather than looping for ever", _raised, "OSError")


# --- 3.7.0: the capture driver's buffer ------------------------------------------
#
# scapy calls pcap_create, set_snaplen, set_promisc, set_timeout, activate -
# and never pcap_set_buffer_size, so Npcap runs on libpcap's Windows default of
# 1 MB. At a ~1,100-byte mean frame that is about 950 frames, or 67 ms of slack
# on a busy adapter; a real capture lost 302,448 frames to it, with one gap of
# 579 ms. `pcap_setbuff` rather than `pcap_set_buffer_size` because the latter
# has to precede pcap_activate, which scapy has already done.
check("a socket with no libpcap handle reports no buffer, rather than claiming one",
      agent.set_kernel_buffer(_FakeAfPacketSocket([])), None)
check("the handle is found on scapy's wrapper", agent.pcap_handle(_FakePcapSocket([])), "HANDLE")
check("...and is None when there is none", agent.pcap_handle(_FakeAfPacketSocket([])), None)
check_true("the buffer asked for is bigger than libpcap's 1 MB default",
           agent.KERNEL_BUFFER_BYTES > 1024 * 1024)
# The queue's two bounds are meant to be reached by different traffic, not for
# one to make the other unreachable. At the ~1,100-byte mean of a real capture
# the frame count now costs about as much as the byte cap allows; before, 8,192
# frames was 9 MB of a 32 MB budget and the bytes were never the binding half.
check_true("the queue's frame cap and byte cap are within reach of each other",
           0.5 < (agent.MAX_QUEUED_PACKETS * 1100) / agent.MAX_QUEUED_BYTES < 2.0)

# --- the kernel buffer is sized per core, because Npcap splits it per core ---
#
# Npcap divides an adapter's buffer into one independent segment per processor
# and drops a frame when the segment for the receiving core is full - so a flat
# figure is really that figure divided by the core count, and a burst does not
# spread itself across cores to suit us. These hold the shape of the fix rather
# than a number: whatever the constants become, more cores must never mean less
# slack per core, and the answer must stay bounded because this is non-paged
# kernel memory.
check_true("the buffer asked for never shrinks below the flat base",
           all(agent.kernel_buffer_bytes(c) >= agent.KERNEL_BUFFER_BASE_BYTES
               for c in (1, 2, 4, 8, 16, 32, 64, 128)))
check_true("...and grows with the core count",
           agent.kernel_buffer_bytes(64) > agent.kernel_buffer_bytes(8))
check_true("...but is capped, because this is non-paged kernel memory",
           agent.kernel_buffer_bytes(4096) == agent.KERNEL_BUFFER_MAX_BYTES)
# The `null != 0` rule again: not knowing how many cores a machine has is not
# knowing it has one. Falling to one core would ask for the flat base on a
# machine that needs the most, which is the direction that must not happen.
check("an unknown core count falls back to the base rather than to one core",
      agent.kernel_buffer_bytes(0), agent.KERNEL_BUFFER_BASE_BYTES)
check("...and so does a None", agent.kernel_buffer_bytes(None) >= agent.KERNEL_BUFFER_BASE_BYTES, True)
# Wireshark's dumpcap asks for 2 MiB by default, on every platform. Stated as an
# assertion so a future edit that "simplifies" this back to a flat value has to
# argue with the comparison rather than merely delete a comment.
check_true("every machine shape gets more than dumpcap's 2 MiB default",
           all(agent.kernel_buffer_bytes(c) > 2 * 1024 * 1024
               for c in (1, 8, 64, 0, None)))

# AF_PACKET has no read timeout: recv_raw blocks until a frame arrives, so
# stop_event would never be re-tested without select() in front of it.
_af = _FakeAfPacketSocket([(None, _A, 100.0), (None, _B, 100.1)])
_queued_af, _ = _run_capture(_af, frames_before_stop=2)
check("an AF_PACKET socket still captures", len(_queued_af), 2)
check_true("...and is polled with select() so a stop is honoured", _af.selects >= 2)

# The safety valve. SuperSocket's own recv_raw reports no timestamp, so a
# socket type that never overrode it would silently trade every frame's capture
# time for throughput - the one trade this change must not make.
_base = _BaseRecvRawSocket([])
_queued_base, _sniffs_base = _run_capture(_base, frames_before_stop=1)
check("a socket with no real recv_raw falls back to sniff()", len(_sniffs_base), 1)
check("...passing it the opened socket", _sniffs_base[0].get("opened_socket") is _base, True)
check("...and storing nothing, as before", _sniffs_base[0].get("store"), False)


print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")


# --- 3.6.0: adapter configuration -----------------------------------------------
#
# The providers are per-platform and only one of them can run on any given
# machine, so what is held here is the platform-independent half: the decoding,
# the normalisation, and the tracker's silence. The Windows registry decode in
# particular is worth pinning because its layout is undocumented and was
# derived by reading a live machine - a wrong stride would silently produce a
# plausible MAC rather than an error.
check("a gateway hardware record decodes to its address and MAC",
      adapters.decode_gateway_hardware(
          bytes([0x0a, 0, 0, 0x8a]) + (6).to_bytes(4, "little")
          + bytes([0x44, 0x15, 0x24, 0xaa, 0xbb, 0xcc])),
      {"10.0.0.138": "44:15:24:aa:bb:cc"})
check("two gateways decode from one blob",
      adapters.decode_gateway_hardware(
          bytes([10, 0, 0, 1]) + (6).to_bytes(4, "little") + bytes([1, 2, 3, 4, 5, 6])
          + bytes([10, 0, 0, 2]) + (6).to_bytes(4, "little") + bytes([7, 8, 9, 10, 11, 12])),
      {"10.0.0.1": "01:02:03:04:05:06", "10.0.0.2": "07:08:09:0a:0b:0c"})
# A truncated value must not read past its end. The count field is not trusted
# for this: the count and the blob are separate registry values that a
# half-written key could disagree about.
check("a truncated gateway record yields nothing rather than reading past the end",
      adapters.decode_gateway_hardware(
          bytes([10, 0, 0, 1]) + (6).to_bytes(4, "little") + bytes([1, 2, 3])), {})
check("a non-binary gateway value is ignored", adapters.decode_gateway_hardware("10.0.0.1"), {})

check("a MAC is normalised to the lowercase colon form every dissector uses",
      adapters._mac("04-7C-16-52-DB-17"), "04:7c:16:52:db:17")
check("something that is not a MAC is None, not a mangled string",
      adapters._mac("Intel(R) Ethernet"), None)

# The RTL marks are real: this machine reports its adapter as
# '\u200f\u200fEthernet 2', and build_interface_label strips them from the
# capture list. If these two disagree the Network panel names an adapter the
# picker does not.
check("right-to-left marks are stripped, so the name matches the capture list",
      adapters._text("\u200f\u200fEthernet 2"), "Ethernet 2")
check("a name that is only marks is nothing, not whitespace", adapters._text("\u200f\u200f"), None)

check("an IPv6 scope is named", adapters.address_scope("2606:4700:4700::1111"), "global")
check("...link-local", adapters.address_scope("fe80::1"), "link-local")
check("...and a unique local address", adapters.address_scope("fd00::1"), "ula")
check("an unparseable address has no scope rather than a wrong one",
      adapters.address_scope("not-an-address"), None)

# Windows reports no broadcast address at all, so it is computed. That is
# arithmetic the OS declined to do, not a guess about what it might be.
check("a broadcast address is computed from the prefix",
      adapters._broadcast("10.0.0.4", 24), "10.0.0.255")
check("...and is meaningless for IPv6, so there is none",
      adapters._broadcast("fe80::1", 64), None)
check("no prefix means no broadcast, rather than assuming /24",
      adapters._broadcast("10.0.0.4", None), None)

# The tracker speaks once and then stays quiet. Configuration changes when a
# lease renews or a cable moves, so a poll with nothing to say is the common
# case and a message every ten seconds would be noise the app has to diff.
_one = [{"id": "eth0", "name": "eth0", "ipv4": [], "ipv6": [], "dnsServers": []}]
_tracker = adapters.AdapterTracker(provider=lambda: [dict(a) for a in _one])
check("the first poll speaks", _tracker.poll()["type"], "adapter_config")
check("an unchanged poll says nothing at all", _tracker.poll(), None)
_one[0]["dhcpServer"] = "10.0.0.138"
check_true("a changed poll speaks again", _tracker.poll() is not None)
check("...and then goes quiet once more", _tracker.poll(), None)
_tracker.reset()
check_true("a reset makes the next poll speak, which is what Refresh needs",
           _tracker.poll() is not None)

# Windows lists 51 adapters - every LWF binding, WAN miniport and tunnel. The
# capture list is a handful. Sending all of them would be ten times the bytes
# and would hand the browser the configuration of adapters nobody is capturing
# on, which the privacy rule for this data does not justify.
_all = [{"id": "eth0", "name": "eth0", "ipv4": [], "ipv6": [], "dnsServers": []},
        {"id": "tunnel7", "name": "tunnel7", "ipv4": [], "ipv6": [], "dnsServers": []}]
check("only the adapters the capture list names are reported",
      [a["id"] for a in adapters.read_adapters(provider=lambda: _all, keep={"eth0"})],
      ["eth0"])
check("no filter means everything, which is what a direct read wants",
      len(adapters.read_adapters(provider=lambda: _all)), 2)

# --- pipe framing -------------------------------------------------------------
#
# The one new thing on the wire in the move off the WebSocket. Everything above
# it - packet_batch's 18-byte record, every control message - is
# transport-agnostic and unchanged.
#
# The vectors below are written out by hand and are byte-identical to the ones
# in scripts/agent/pipe-framing.ts. That is the same rule the packet batch
# follows: a format with two implementations agrees with itself only if
# something outside both of them says what it is.
import pipe_frame

check("a control message frames exactly",
      pipe_frame.encode_json({"type": "stop_capture"}).hex(" "),
      "18 00 00 00 00 7b 22 74 79 70 65 22 3a 22 73 74 6f 70 5f 63 61 70 74 75 72 65 22 7d")
check("a binary frame carries its payload untouched",
      pipe_frame.encode_frame(pipe_frame.FRAME_BINARY, b"IWP1").hex(" "),
      "05 00 00 00 01 49 57 50 31")
# The degenerate frame: the length field is 1, for the kind byte, never 0 -
# which is why the reader refuses a declared 0.
check("an empty payload still declares one byte",
      pipe_frame.encode_frame(pipe_frame.FRAME_JSON, b"").hex(" "),
      "01 00 00 00 00")

# A pipe read boundary has nothing to do with a message boundary. Both of these
# happen under load and neither could happen on a WebSocket.
_reader = pipe_frame.FrameReader()
_stream = (pipe_frame.encode_json({"a": 1}) + pipe_frame.encode_json({"b": 2}))
check("two frames in one read come back as two",
      [f.json() for f in _reader.push(_stream)], [{"a": 1}, {"b": 2}])
check("...leaving nothing behind", _reader.pending, 0)

_reader = pipe_frame.FrameReader()
_collected = []
for _byte in _stream:
    _collected.extend(f.json() for f in _reader.push(bytes([_byte])))
check("a stream delivered one byte at a time still frames",
      _collected, [{"a": 1}, {"b": 2}])

_reader = pipe_frame.FrameReader()
_frame = pipe_frame.encode_json({"type": "refresh_adapters"})
check("half a header yields nothing", list(_reader.push(_frame[:3])), [])
check("...and is remembered", _reader.pending, 3)
check("the rest completes it",
      [f.json() for f in _reader.push(_frame[3:])], [{"type": "refresh_adapters"}])


def _framing_refused(chunk):
    try:
        list(pipe_frame.FrameReader().push(chunk))
        return False
    except pipe_frame.FramingError:
        return True


# Checked on the declared length, before anything is allocated. This process is
# a privileged service; a five-byte header must never be able to ask for four
# gigabytes.
import struct as _struct
check_true("a frame past the ceiling is refused on its header alone",
           _framing_refused(_struct.pack("<IB", pipe_frame.MAX_FRAME_BYTES + 1, 0)))
check_true("a zero-length frame is refused",
           _framing_refused(_struct.pack("<IB", 0, 0)))
check_true("an unknown kind is refused rather than guessed",
           _framing_refused(_struct.pack("<IB", 2, 9) + b"x"))
try:
    pipe_frame.encode_frame(9, b"")
    check("...and encoding one is refused too", "did not raise", "raised")
except ValueError:
    check("...and encoding one is refused too", "raised", "raised")

# --- the pipe connection, which has to look like a WebSocket ------------------
#
# `AgentServer.register` does its whole job through two operations - `await
# ws.send(data)` and `async for raw in ws` - so a connection that provides
# exactly those needs no change anywhere else: ownership, subscriptions, the
# hello handshake and the disconnect rules all keep working. These assert the
# two, and the type-to-frame-kind rule the WebSocket used to give for free.
#
# Cross-platform on purpose: `PipeConnection` takes its write and close as
# callables, so the half with the decisions in it runs on the CI machines that
# have no named pipes at all.
import pipe_server


sheddables = []


def _connection():
    written = []
    loop = asyncio.new_event_loop()
    # Takes the record count `send` now passes - the transport's writer needs
    # it so the shed counter can be in packets rather than in queued items.
    def _write(frame, records=0, sheddable=False):
        written.append(frame)
        sheddables.append(sheddable)
    conn = pipe_server.PipeConnection(loop, _write, lambda: None)
    return loop, conn, written


_loop, _conn, _written = _connection()
_loop.run_until_complete(_conn.send('{"type":"state"}'))
# A str is a control message and bytes are a batch, which is exactly how the
# WebSocket told them apart.
check("a string is sent as a JSON frame",
      _written[-1].hex(" "),
      "11 00 00 00 00 7b 22 74 79 70 65 22 3a 22 73 74 61 74 65 22 7d")
_loop.run_until_complete(_conn.send(b"IWP1"))
check("bytes are sent as a binary frame", _written[-1].hex(" "), "05 00 00 00 01 49 57 50 31")
# Only a packet batch may be shed; a control message never is, because nothing
# tells the app that a shed one was lost.
check("a control message is sent as unsheddable, and a batch as sheddable", sheddables[-2:], [False, True])


async def _drain(conn, expected):
    seen = []
    async for raw in conn:
        seen.append(raw)
        if len(seen) == expected:
            break
    return seen


_loop, _conn, _written = _connection()
_conn.deliver('{"type":"start_capture"}')
_conn.deliver('{"type":"stop_capture"}')
check("delivered messages arrive in order over the async iterator",
      _loop.run_until_complete(_drain(_conn, 2)),
      ['{"type":"start_capture"}', '{"type":"stop_capture"}'])

# The half that matters for the disconnect rules: the iterator has to END when
# the client goes, because `register`'s `finally` is what stops a capture whose
# owner has left. An iterator that simply blocked for ever would leave the
# sniffer running with nobody watching - the thing this agent is designed not
# to do.
_loop, _conn, _written = _connection()
_conn.finish()
check("a finished connection ends its iterator rather than hanging",
      _loop.run_until_complete(_drain(_conn, 1)), [])

# And once it has gone, sending must fail rather than queue into nothing.
_sent_after_close = "no error"
try:
    _loop.run_until_complete(_conn.send("{}"))
except ConnectionError:
    _sent_after_close = "ConnectionError"
check("sending to a client that has gone raises", _sent_after_close, "ConnectionError")
_loop.close()

# --- the outbound queue, which used to lose frames in silence ---------------------
#
# Three defects lived here together, and each hid the others.
#
#   1. A full queue CLOSED the connection. Closing drops the client; the client
#      leaving is what stops the capture. So the protection against a slow
#      reader terminated the thing it was protecting - and took with it the
#      connection that would have reported the loss.
#   2. The close set a LOCAL `closed` Event, while `PipeConnection.send` tested
#      its own `_closed`. Two flags, so every send after the writer gave up
#      returned success and discarded its frame. `_send_to_owner`'s `except`
#      exists for exactly this and could never fire.
#   3. The bound was a frame COUNT on items of up to 256 kB - 4,096 of them is
#      a gigabyte inside a LocalSystem service. The sniffer queue beside it
#      records adding a byte budget for this precise reason.
# **The counter is in PACKETS, not in queued items**, and that is a real bug
# rather than a nicety. The items here are batches of up to 512 packets, while
# the app adds `droppedPipe` straight into a frames-lost total beside
# `droppedAgent` and `droppedKernel`, which are packets. Counting items reported
# a shed batch of twelve frames as one lost frame.
#
# Found by asserting conservation end to end against the Rust agent - delivered
# plus shed plus still-queued must equal what the driver handed over - where
# 37,793 shed batches accounted for 398,000 missing packets.
_ob = pipe_server._Outbound(max_frames=3, max_bytes=10_000)
for _i in range(3):
    _ob.put(bytes([_i]) * 10, records=12, sheddable=True)
check("frames queue up to the count bound", _ob.qsize(), 3)
check("...losing none of them", _ob.dropped, 0)
_ob.put(b"\x09" * 10, records=12, sheddable=True)
check("past the bound the queue does not grow", _ob.qsize(), 3)
check("...and the shed batch is counted in PACKETS, not as one item",
      _ob.dropped, 12)
check("...the OLDEST being the one shed, as in the sniffer queue",
      _ob.get(), b"\x01" * 10)

# **A control message is never shed.** It used to be the oldest item of any kind
# that went, so a capture_boundary, a capture_stopped or an error could vanish
# under backpressure - uncounted, because a control message carries no packets.
_obc = pipe_server._Outbound(max_frames=3, max_bytes=10_000_000)
_obc.put(b"\x01", records=10, sheddable=True)
_obc.put(b"ctl", records=0, sheddable=False)
_obc.put(b"\x02", records=10, sheddable=True)
_obc.put(b"\x03", records=10, sheddable=True)   # over by one: \x01 goes, "ctl" stays
check("a control message is never shed",
      [_obc.get(), _obc.get(), _obc.get()], [b"ctl", b"\x02", b"\x03"])
check("...and only the batch is counted, in packets", _obc.dropped, 10)

# The case the rule exists for: the control message is the OLDEST item.
_obo = pipe_server._Outbound(max_frames=3, max_bytes=10_000_000)
_obo.put(b"ctl", records=0, sheddable=False)
for _i in (1, 2, 3):
    _obo.put(bytes([_i]), records=4, sheddable=True)
check("...even when it is the oldest item",
      [_obo.get(), _obo.get(), _obo.get()], [b"ctl", b"\x02", b"\x03"])
check("...and what made room was the oldest batch", _obo.dropped, 4)

# A client that lets 4 MB of control messages queue is not reading at all: the
# connection ends rather than the queue growing without bound.
_obx = pipe_server._Outbound(max_frames=4096, max_bytes=10_000_000, max_control_bytes=8)
check("a control backlog under its cap is accepted", _obx.put(b"\x00" * 6, sheddable=False), True)
check("a control backlog past its cap ends the connection",
      _obx.put(b"\x00" * 6, sheddable=False), False)
check("...the queue holds only the stop signal", _obx.get(), pipe_server._SHUTDOWN)
check_true("...and says why", _obx.overflowed)
check("...and takes nothing more", _obx.put(b"\x00", sheddable=False), False)
check("the cap is 4 MB", pipe_server.MAX_CONTROL_BYTES, 4 * 1024 * 1024)

# The byte bound bites first when the items are big, which is the case the
# count bound could not express at all.
_ob2 = pipe_server._Outbound(max_frames=4096, max_bytes=1000)
for _ in range(5):
    _ob2.put(b"\x00" * 400, records=7, sheddable=True)
check_true("a byte budget sheds before the count bound is anywhere near",
           _ob2.qsize() < 4096 and _ob2.dropped > 0)
check("...counting every packet in every batch it shed", _ob2.dropped % 7, 0)
check_true("...leaving the queue inside its budget", _ob2.pending_bytes() <= 1000)

# A single frame larger than the whole budget must still be delivered: a queue
# that evicts its own newest arrival delivers nothing at all.
_ob3 = pipe_server._Outbound(max_frames=4096, max_bytes=100)
_ob3.put(b"\x00" * 500, sheddable=True)
check("an oversized frame is kept rather than shed into nothing", _ob3.qsize(), 1)

# The writer thread blocks on `get()` waiting for the stop signal, so shedding
# it would leave that thread parked until the handle closed underneath it.
_ob4 = pipe_server._Outbound(max_frames=1, max_bytes=10)
_ob4.put(pipe_server._SHUTDOWN)
for _ in range(4):
    _ob4.put(b"\x00" * 50, sheddable=True)
check("the stop signal is never shed", _ob4.get(), pipe_server._SHUTDOWN)

# The descriptor is the whole security model now, so its shape is worth
# pinning even where it cannot be applied. IU is the interactive user - the
# app - and its absence is what would make the pipe unopenable by the very
# process it exists for. WD/AN/NU are absent because a named pipe is reachable
# over SMB unless the descriptor says otherwise.
import inspect
_sddl_source = inspect.getsource(pipe_server._security_attributes)
check_true("the descriptor admits the interactive user", "(A;;GRGW;;;IU)" in _sddl_source)
check_true("...and SYSTEM and administrators",
           "(A;;GA;;;SY)" in _sddl_source and "(A;;GA;;;BA)" in _sddl_source)
check_true("...and is protected, so nothing is inherited", "D:P" in _sddl_source)
check_true("...and admits nobody else",
           all(sid not in _sddl_source for sid in (";;;WD)", ";;;AN)", ";;;NU)")))

# The log folder is the other thing a LocalSystem service rotates with
# remove/rename, so the same rule as agent-rs/src/agent_log.rs: admin-owned,
# protected, and a junction is refused. The real ACL needs pywin32 on Windows,
# so like the pipe's descriptor above this pins the source where it cannot run.
import logging_setup
_log_source = inspect.getsource(logging_setup)
check_true("the log folder descriptor is admin-owned and protected",
           "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)" in _log_source)
check_true("...a reparse point is refused", "0x400" in _log_source)
check_true("...and the DACL is protected, so nothing is inherited",
           "PROTECTED_DACL_SECURITY_INFORMATION" in _log_source)
check_true("...and links planted under a log name are cleared", "_clear_planted_links" in _log_source)
check_true("...and the service, which is SYSTEM, is what asks for it",
           "harden=True" in (pathlib.Path(__file__).parent / "service_windows.py").read_text(encoding="utf-8"))

# Behaviour that runs without pywin32: a link planted under a log name is
# removed and what it pointed at is not, and a folder that cannot be secured
# is not written to. (On Windows the second would really harden a temp folder.)
_planted_dir = tempfile.mkdtemp()
_planted_target = tempfile.mkdtemp()
with open(os.path.join(_planted_target, "keep"), "w") as _f:
    _f.write("x")
try:
    os.symlink(_planted_target, os.path.join(_planted_dir, "agent.log.3"), target_is_directory=True)
    os.symlink(os.path.join(_planted_target, "keep"), os.path.join(_planted_dir, "agent.log.1"))
    _can_link = True
except (OSError, NotImplementedError):
    _can_link = False  # an unprivileged Windows account cannot make symlinks
if _can_link:
    logging_setup._clear_planted_links(_planted_dir)
    check_true("a planted directory link is removed",
               not os.path.lexists(os.path.join(_planted_dir, "agent.log.3")))
    check_true("a planted file link is removed",
               not os.path.lexists(os.path.join(_planted_dir, "agent.log.1")))
    check_true("what the links pointed at is kept",
               os.path.exists(os.path.join(_planted_target, "keep")))
if os.name != "nt":
    _hl = logging.getLogger("inwire")
    _hl_saved = (list(_hl.handlers), _hl.level, _hl.propagate)
    _hl_dir = tempfile.mkdtemp()
    try:
        logging_setup._configured_with = None
        logging_setup.setup_logging(_hl_dir, to_stderr=False, harden=True)
        check_true("a folder that cannot be secured gets no file handler",
                   not any(isinstance(h, logging.FileHandler) for h in _hl.handlers))
        check("...and no log file is created in it", os.listdir(_hl_dir), [])
    finally:
        for _h in list(_hl.handlers):
            _hl.removeHandler(_h)
            _h.close()
        for _h in _hl_saved[0]:
            _hl.addHandler(_h)
        _hl.setLevel(_hl_saved[1])
        _hl.propagate = _hl_saved[2]
        logging_setup._configured_with = None

# --- a pipe name someone else created, and a lost instance (ADR 0068) --------------
#
# The first instance carries FILE_FLAG_FIRST_PIPE_INSTANCE, so a name a user
# made before the service started is refused instead of joined; and an instance
# the system will not give is retried instead of ending the server. The real
# CreateNamedPipe needs Windows and pywin32, and CI runs this file on ubuntu and
# macOS - so the flag is held by a source check, and the decisions by a server
# whose `_create_instance` is a stand-in.
check_true("the first pipe instance asks for FILE_FLAG_FIRST_PIPE_INSTANCE",
           pipe_server.FILE_FLAG_FIRST_PIPE_INSTANCE == 0x00080000
           and "FILE_FLAG_FIRST_PIPE_INSTANCE if first" in inspect.getsource(pipe_server.PipeServer._create_instance))

import logging as _logging


class _Lines(_logging.Handler):
    def __init__(self):
        super().__init__()
        self.lines = []

    def emit(self, record):
        self.lines.append((record.levelname, record.getMessage()))


class _FakePipes(pipe_server.PipeServer):
    """A PipeServer whose instances are strings, and whose creation can fail."""

    def __init__(self, outcomes):
        super().__init__(asyncio.new_event_loop(), lambda connection: None, name=r"\\.\pipe\inwire-test")
        self._outcomes = list(outcomes)
        self.asked = []
        self._retry = 0.01
        self.closed = []

    def _create_instance(self, first):
        self.asked.append(first)
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def _close_handle(self, handle):
        self.closed.append(handle)


_lines = _Lines()
pipe_server.log.addHandler(_lines)
try:
    _squatted = _FakePipes([OSError(5, "Access is denied.")])
    _squatted._begin()
    check("a name that already exists is refused", _squatted.refused, "the pipe name is already in use")
    check("...the refusal asked for the FIRST instance", _squatted.asked, [True])
    check_true("...and nothing is serving or accepting", not _squatted.serving and _squatted._accept_thread is None)
    check_true("...the log says another process created it first",
               any(level == "ERROR" and "already exists - another process created it first" in text
                   for level, text in _lines.lines))

    # A lost instance is retried, and said once per failing streak.
    _lines.lines.clear()
    _lost = _FakePipes(["first-instance", OSError(231, "busy"), OSError(231, "busy"), "second-instance"])
    _lost._first_handle = _lost._acquire_instance()
    check("the first call hands over the instance made before the thread",
          _lost._next_instance(), "first-instance")
    check("a refused instance is retried until the system gives one",
          _lost._next_instance(), "second-instance")
    check("...asking for a non-first instance every time", _lost.asked, [True, False, False, False])
    check("...logging the streak once, not once per attempt",
          sum(1 for level, text in _lines.lines if "could not create a pipe instance, retrying" in text), 1)
    check_true("...and not refusing: a lost slot does not stop the server", _lost.refused is None)

    _stopping = _FakePipes([OSError(231, "busy")] * 3)
    _stopping._stopping.set()
    check("a stop ends the retrying", _stopping._next_instance(), None)

    # The first-instance guarantee holds whenever the server holds no instance,
    # not only for the very first one: a user who drains the slots and
    # recreates the name must not be joined by the next retry.
    _drained = _FakePipes(["a", "b", "c", OSError(5, "Access is denied."), "d"])
    _a = _drained._acquire_instance()
    _b = _drained._acquire_instance()
    check("a second instance is not asked for as a first", _drained.asked, [True, False])
    check("...and both are counted", _drained._held, 2)
    _drained._release_instance(_a)
    check("an instance the server still holds another of is not a reason to ask for a first",
          (_drained._held, _drained._acquire_instance()), (1, "c"))
    check("...asked for non-first again", _drained.asked, [True, False, False])
    _drained._release_instance(_b)
    _drained._release_instance("c")
    check("closing an instance counts it out", (_drained._held, _drained.closed), (0, ["a", "b", "c"]))
    try:
        _drained._acquire_instance()
    except OSError:
        pass
    check("with none held, the next creation asks for a FIRST instance", _drained.asked[-1], True)
    check("...a refusal is not counted as held", _drained._held, 0)
    check("...and the retry after it asks for a first instance again",
          (_drained._next_instance(), _drained.asked[-1]), ("d", True))
    check("...which is then held", _drained._held, 1)
finally:
    pipe_server.log.removeHandler(_lines)


# The one claim a pipe connection makes that a socket cannot: the descriptor
# was checked before the handle existed, so `register` skips the pairing token
# rather than answering it. Transitional - the attribute and the token both go
# when the WebSocket does - but while both transports are live, this is what
# stops the app being asked to paste a string the pipe made meaningless.
check_true("a pipe connection is vouched for by the kernel",
           pipe_server.PipeConnection.kernel_authenticated)
check_true("...and the agent reads it off the connection, not off the transport",
           'getattr(ws, "kernel_authenticated", False)' in inspect.getsource(agent.AgentServer.register))


# --- a capture filter and a snaplen ------------------------------------------
#
# The Rust agent's rules and sentences: a start carries a filter and a snaplen,
# blank is no filter, and anything that is not one is refused rather than
# captured on defaults - a filter ignored is a capture of everything that its
# owner believes is narrowed.
check("a start with neither captures everything",
      agent.parse_capture_options({"type": "start_capture"}), {"filter": None, "snaplen": 262144})
check("a start carries its filter and snaplen",
      agent.parse_capture_options({"type": "start_capture", "filter": "tcp port 443", "snaplen": 128}),
      {"filter": "tcp port 443", "snaplen": 128})
check("a blank filter is no filter",
      agent.parse_capture_options({"type": "start_capture", "filter": "  "})["filter"], None)
for _bad in ({"filter": 5}, {"snaplen": 0}, {"snaplen": 262145}, {"snaplen": 1.5}, {"snaplen": "128"},
             {"snaplen": True}, {"filter": "a" * (agent.MAX_CAPTURE_FILTER_CHARS + 1)}):
    _refused = None
    try:
        agent.parse_capture_options({"type": "start_capture", **_bad})
    except agent.CaptureOptionsError as exc:
        _refused = str(exc)
    check_true(f"...and {_bad if 'filter' not in _bad or len(str(_bad)) < 40 else 'a filter too long'} is refused",
               _refused is not None)
check("the sentence is the Rust agent's",
      _refused,
      f"A capture filter is at most {agent.MAX_CAPTURE_FILTER_CHARS} characters long.")

# Every command the app sends, from the shared fixture the Rust agent reads,
# is one this agent can read - which is the check that was missing when the
# selection was misread (scripts/agent/command-vectors.json).
_commands = json.loads((pathlib.Path(__file__).resolve().parent.parent
                        / "scripts" / "agent" / "command-vectors.json").read_text(encoding="utf-8"))["commands"]
_start = next(json.loads(c) for c in _commands if '"start_capture"' in c)
# The app's own start asks for a ring, and this agent writes no files (ADR
# 0052): refused in a sentence, never captured without the ring it asked for.
_ring_refused = None
try:
    agent.parse_capture_options(_start)
except agent.CaptureOptionsError as exc:
    _ring_refused = str(exc)
check("the app's own start_capture, with a ring, is refused by an agent that writes no files",
      _ring_refused, "This agent writes no capture files, so start_capture's ring cannot be honoured.")
_plain = {k: v for k, v in _start.items() if k not in ("ring", "autostop")}
check("...and without one parses to its filter and snaplen, its capture id set aside",
      agent.parse_capture_options(_plain), {"filter": _start["filter"], "snaplen": _start["snaplen"]})
_bad_id = None
try:
    agent.parse_capture_options({"type": "start_capture", "captureId": "..\\..\\Windows"})
except agent.CaptureOptionsError as exc:
    _bad_id = str(exc)
check("a capture id that is not one is refused in the Rust agent's words",
      _bad_id, "start_capture's captureId must name a capture, cap-YYYYMMDD-HHMMSS-xxxx.")
_root = next(json.loads(c) for c in _commands if '"set_capture_root"' in c)
check_true("main's set_capture_root is a command this agent understands",
           'msg_type == "set_capture_root"' in inspect.getsource(agent.AgentServer))
check("...and it carries a folder", isinstance(_root.get("dir"), str), True)

# Over the real libpcap, where there is one: a spelling mistake is named in
# libpcap's words, a good filter is not, and the filter is echoed.
try:
    import scapy.libs.winpcapy  # noqa: F401
    _have_pcap = True
except Exception:
    _have_pcap = False
if _have_pcap:
    check("a good filter compiles",
          agent.check_capture_filter("arp or udp port 53", []),
          {"type": "capture_filter_check", "filter": "arp or udp port 53", "error": None})
    _bad_check = agent.check_capture_filter("udp prot 53", [])
    check("a bad one is echoed", _bad_check["filter"], "udp prot 53")
    check_true("...with libpcap's reason", "syntax error" in (_bad_check["error"] or ""))
else:
    print("SKIP  no libpcap on this machine - the filter checks need one")


# --- the summary, and the exit code ------------------------------------------
#
# **This file counted failures and then exited 0.** Every `check` above
# incremented `failures`, printed FAIL, and told nobody: the script simply ran
# off the end, and Python exits 0 when it does. So the suite was advisory to
# anything that reads an exit code - which is `.github/workflows/ci.yml:65`,
# where it is a build step, and the release checklist in `local-agent/CLAUDE.md`,
# where a person is told to run it before shipping.
#
# Two thousand lines of assertions that could not fail a build. It is the same
# shape as a check pointed at the wrong file - it passes for exactly as long as
# it is wrong - but wholesale, and it was found only because a real regression
# printed FAIL while the exit code stayed 0.
print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All protocol checks passed.")
sys.exit(0)
