"""Assertion tests for the per-interface rate sampler.

    python local-agent/test_interface_stats.py

Counters are injected rather than read from the machine, so the rates are
checked against known deltas instead of whatever the network happened to do.
"""
import sys
from collections import namedtuple

import interface_stats

Counters = namedtuple("Counters", "bytes_sent bytes_recv packets_sent packets_recv")

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


# The real shapes: a capture device path paired with "{friendly} ({driver})",
# and OS counter keys carrying the Windows RTL marks.
INTERFACES = [
    ("\\Device\\NPF_{AAA}", "‏Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)"),
    ("\\Device\\NPF_{BBB}", "Wi-Fi (Intel(R) Wi-Fi 6E AX211 160MHz)"),
    ("\\Device\\NPF_{CCC}", "Ethernet (Some Other NIC)"),
    ("\\Device\\NPF_{DDD}", "‏‏חיבור מקומי* 8 (WAN Miniport (Network Monitor))"),
]

# --- name mapping ------------------------------------------------------------
mapping = interface_stats.map_devices_to_nics(
    INTERFACES, ["‏Ethernet 2", "Wi-Fi", "Ethernet"],
)
check("RTL marks do not stop a match", mapping.get("\\Device\\NPF_{AAA}"), "‏Ethernet 2")
check("plain friendly name matches", mapping.get("\\Device\\NPF_{BBB}"), "Wi-Fi")
check(
    "longest prefix wins, so Ethernet 2 is not swallowed by Ethernet",
    mapping.get("\\Device\\NPF_{CCC}"),
    "Ethernet",
)
check(
    "an adapter the OS keeps no counters for is simply absent",
    "\\Device\\NPF_{DDD}" in mapping,
    False,
)

# --- rates -------------------------------------------------------------------
state = {"counters": {}}
sampler = interface_stats.InterfaceRateSampler(INTERFACES, lambda: state["counters"])


def set_counters(packets, byte_count):
    state["counters"] = {
        "‏Ethernet 2": Counters(0, byte_count, 0, packets),
        "Wi-Fi": Counters(0, 0, 0, 0),
        "Ethernet": Counters(0, 0, 0, 0),
    }


def rate_for(results, device, key="packetsPerSec"):
    return next(r[key] for r in results if r["name"] == device)


set_counters(1000, 500_000)
first = sampler.sample(100.0)
check("every interface is reported, mapped or not", len(first), 4)
check(
    "the first sample reports zero, not the machine's lifetime total",
    rate_for(first, "\\Device\\NPF_{AAA}"),
    0,
)

set_counters(3000, 1_500_000)
second = sampler.sample(102.0)
check("packets/sec over the real elapsed time", rate_for(second, "\\Device\\NPF_{AAA}"), 1000.0)
check(
    "bytes/sec over the real elapsed time",
    rate_for(second, "\\Device\\NPF_{AAA}", "bytesPerSec"),
    500000.0,
)

# A late tick must divide by the interval that actually happened, not the
# nominal one, or a stalled loop reports a spike it invented.
set_counters(3400, 1_700_000)
third = sampler.sample(106.0)
check("a late tick divides by real elapsed time", rate_for(third, "\\Device\\NPF_{AAA}"), 100.0)

# Disabling and re-enabling an adapter resets its counters.
set_counters(5, 100)
fourth = sampler.sample(107.0)
check(
    "a counter reset reports zero rather than a negative spike",
    rate_for(fourth, "\\Device\\NPF_{AAA}"),
    0,
)

set_counters(105, 1100)
fifth = sampler.sample(108.0)
check("sampling recovers after a reset", rate_for(fifth, "\\Device\\NPF_{AAA}"), 100.0)

check(
    "an unmapped adapter stays flat instead of erroring",
    rate_for(fifth, "\\Device\\NPF_{DDD}"),
    0,
)

print()
if failures:
    print(f"{failures} check(s) FAILED")
    sys.exit(1)
print("All checks passed.")
