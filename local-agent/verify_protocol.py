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
import time

import websockets

AGENT_URL = "ws://localhost:8999"


async def recv_json(ws, timeout=3):
    raw = await asyncio.wait_for(ws.recv(), timeout=timeout)
    return json.loads(raw)


async def recv_type(ws, wanted, timeout=3):
    """Reads messages until one of type `wanted` shows up, discarding
    anything else (e.g. queued `packet` messages on a machine with live
    traffic) along the way. The timeout applies to the whole wait, not
    per-message - otherwise a steady stream of the wrong message type could
    stall this forever instead of failing cleanly."""
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        msg = await recv_json(ws, timeout=remaining)
        if msg.get("type") == wanted:
            return msg


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
        try:
            hello = await recv_json(ws)
            check("hello type", hello.get("type") == "hello")
            check("hello reports idle at connect", hello.get("state") == "idle")
            check("hello requires auth", hello.get("authRequired") is True)
            check("hello lists at least one interface", len(hello.get("interfaces", [])) > 0)
        except asyncio.TimeoutError:
            check("hello received within timeout", False)

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
        auth_state = await recv_type(ws, "state")
        check("state sent immediately after successful auth", auth_state.get("type") == "state")

        await ws.send(json.dumps({"type": "start_capture"}))
        # Real packets may already be queued ahead of the state message once
        # capture is live, so skip past any of those instead of grabbing
        # whatever arrives first.
        state = await recv_type(ws, "state")
        check("state after start_capture", state.get("type") == "state")
        check("state is sniffing after start_capture", state.get("state") == "sniffing")

        await ws.send(json.dumps({"type": "stop_capture"}))
        state2 = await recv_type(ws, "state")
        check("state is idle after stop_capture", state2.get("state") == "idle")

    print()
    if failures:
        print(f"{failures} check(s) FAILED")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    asyncio.run(main())
