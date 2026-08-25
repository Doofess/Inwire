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

print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")
