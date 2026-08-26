#!/usr/bin/env python3
"""
End-to-end smoke test against a REAL running agent - not a unit test, since
this exercises the actual WebSocket/thread/scapy wiring that test_protocol.py
deliberately fakes out.

Coverage:
  - hello on connect, start_capture -> sniffing, stop_capture -> idle
  - set_interfaces narrowed to a single interface, exercised through a full
    start/stop cycle, then restored back to the full interface list (the
    agent persists the selection for the session, so leaving it narrowed
    would silently change what the user's browser captures afterwards)
  - set_interfaces with an empty list is rejected with an "empty_interfaces"
    error instead of silently succeeding
  - the origin allowlist - the agent's only authentication - actually
    rejects a disallowed Origin, and a missing Origin, with HTTP 403

Start the agent first (as Administrator), then:
  python local-agent/verify_protocol.py
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
    failures = 0

    def check(name, condition):
        nonlocal failures
        ok = bool(condition)
        if not ok:
            failures += 1
        print(f"{'PASS' if ok else 'FAIL'}  {name}")

    # The agent's origin gate rejects any handshake whose Origin header is not
    # in the allowed list (default: localhost:3000/4173 and their 127.0.0.1
    # spellings), returning HTTP 403 before the connection is even accepted.
    # websockets.connect sends no Origin header by default, so it must be set
    # explicitly here to one of the defaults.
    async with websockets.connect(AGENT_URL, origin="http://localhost:3000") as ws:
        try:
            hello = await recv_json(ws)
            check("hello type", hello.get("type") == "hello")
            check("hello has a version", "version" in hello)
            check("hello reports idle at connect", hello.get("state") == "idle")
            check("hello lists at least one interface", len(hello.get("interfaces", [])) > 0)
        except asyncio.TimeoutError:
            check("hello received within timeout", False)

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

        # --- interface selection round trip ---
        all_interfaces = [i.get("name") for i in hello.get("interfaces", [])]
        if len(all_interfaces) < 2:
            print(
                "SKIP  interface-selection round trip "
                f"(hello reported only {len(all_interfaces)} interface(s); need at least 2 "
                "to prove selection actually narrows what's captured)"
            )
        else:
            first_iface = all_interfaces[0]

            await ws.send(json.dumps({"type": "set_interfaces", "interfaces": [first_iface]}))
            narrowed_state = await recv_type(ws, "state")
            check("state message received after narrowing set_interfaces", narrowed_state.get("type") == "state")

            await ws.send(json.dumps({"type": "start_capture"}))
            start_state = await recv_type(ws, "state")
            check("state is sniffing after start_capture on narrowed interface", start_state.get("state") == "sniffing")

            await ws.send(json.dumps({"type": "stop_capture"}))
            stop_state = await recv_type(ws, "state")
            check("state is idle after stop_capture on narrowed interface", stop_state.get("state") == "idle")

            # Restore the full selection - the agent persists whatever was
            # last selected for the rest of the session, so leaving it
            # narrowed here would silently change what the user's browser
            # captures afterwards.
            await ws.send(json.dumps({"type": "set_interfaces", "interfaces": all_interfaces}))
            restored_state = await recv_type(ws, "state")
            check("state message received after restoring full interface selection", restored_state.get("type") == "state")
            print(f"      interface selection restored to all {len(all_interfaces)} interface(s)")

        # --- empty interface list is rejected, not silently accepted ---
        await ws.send(json.dumps({"type": "set_interfaces", "interfaces": []}))
        empty_error = await recv_type(ws, "error")
        check("empty set_interfaces produces an error message", empty_error.get("type") == "error")
        check("empty set_interfaces error code is empty_interfaces", empty_error.get("code") == "empty_interfaces")

        if all_interfaces:
            # The agent rejects the empty list before touching the selection,
            # so this should be a no-op - but send it anyway in case that
            # ever changes, since a narrowed selection left behind would
            # silently change what the user's browser captures afterwards.
            await ws.send(json.dumps({"type": "set_interfaces", "interfaces": all_interfaces}))
            restored_state2 = await recv_type(ws, "state")
            check("state message received after re-restoring full interface selection", restored_state2.get("type") == "state")
            print(f"      interface selection restored to all {len(all_interfaces)} interface(s)")

    # --- origin allowlist actually rejects disallowed/missing origins ---
    # This is the agent's ONLY authentication mechanism. If either of these
    # connections *succeeds*, the allowlist has stopped working and that is
    # a hard FAIL, not a soft warning.
    try:
        async with websockets.connect(AGENT_URL, origin="https://evil.example"):
            check("disallowed origin is rejected by the agent", False)
            print("      FAIL: connected successfully with a disallowed Origin - the origin allowlist is not enforcing!")
    except websockets.exceptions.InvalidStatus as exc:
        check("disallowed origin rejected with HTTP 403", exc.response.status_code == 403)
    except Exception as exc:  # noqa: BLE001 - any other failure mode still means "not a clean 403 rejection"
        check(f"disallowed origin rejected with HTTP 403 (unexpected exception type: {type(exc).__name__})", False)

    try:
        async with websockets.connect(AGENT_URL):
            check("missing origin is rejected by the agent", False)
            print("      FAIL: connected successfully with no Origin header at all - the origin allowlist is not enforcing!")
    except websockets.exceptions.InvalidStatus as exc:
        check("missing origin rejected with HTTP 403", exc.response.status_code == 403)
    except Exception as exc:  # noqa: BLE001
        check(f"missing origin rejected with HTTP 403 (unexpected exception type: {type(exc).__name__})", False)

    print()
    if failures:
        print(f"{failures} check(s) FAILED")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    asyncio.run(main())
