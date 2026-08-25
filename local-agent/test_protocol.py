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

print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")
