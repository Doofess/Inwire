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

print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")
