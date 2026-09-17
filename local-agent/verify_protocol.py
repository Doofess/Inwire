#!/usr/bin/env python3
"""
End-to-end smoke test against a REAL running agent - not a unit test, since
this exercises the actual WebSocket/thread/scapy wiring that test_protocol.py
deliberately fakes out.

## macOS and Linux only. It cannot reach the Windows service.

Everything below dials ``ws://localhost:8999`` with a pairing token and an
``Origin`` header, and on Windows none of those three exist: the transport is
the named pipe, the token is gone because the pipe's descriptor is the
authentication (docs/decisions/0029), and ``main()`` returns from the pipe
branch without ever calling ``websockets.serve`` - ``PipeServer.start`` sets
``serving`` on every win32 run, so there is no fallback. ``websockets`` is not
even importable in the frozen build: ``agent.py`` sets it to ``None`` on win32
and ``inwire_agent.spec`` lists it in ``excludes``.

The release checklist used to send people here after installing on Windows,
where the only possible outcome is a connection refused. The Windows
equivalents are ``npx tsx scripts/electron/smoke.ts`` (real app, real pipe,
frames on screen) and ``python local-agent/test_protocol.py`` for the protocol
itself. Porting this to the pipe is worth doing and has not been done.

Coverage:
  - hello on connect, start_capture -> sniffing, stop_capture -> idle
  - set_interfaces narrowed to a single interface, exercised through a full
    start/stop cycle, then restored back to the full interface list (the
    agent persists the selection for the session, so leaving it narrowed
    would silently change what the user's browser captures afterwards)
  - set_interfaces with an empty list is rejected with an "empty_interfaces"
    error instead of silently succeeding
  - the origin allowlist - the agent's only authentication ON THESE
    PLATFORMS; on Windows it is the pipe's descriptor and there is no
    Origin at all - actually rejects a disallowed Origin, and a missing
    Origin, with HTTP 403
  - subscribe_logs returns a backlog and then streams live lines, and
    unsubscribe_logs stops them

Start the agent first (as Administrator), then:
  python local-agent/verify_protocol.py
"""
import asyncio
import json
import os
import sys
import time

# Before `import websockets`, so a Windows run says why rather than dying on an
# ImportError (the frozen build excludes the library) or, with it installed, on
# a connection refused against a port the Windows agent never opens.
if sys.platform == "win32":
    print(
        "verify_protocol.py is the macOS/Linux check and cannot reach the Windows\n"
        "agent: that one speaks the named pipe, and ws://localhost:8999 is not\n"
        "opened at all. On Windows run:\n"
        "  npx tsx scripts/electron/smoke.ts   - the real app over the real pipe\n"
        "  python local-agent/test_protocol.py - the protocol itself",
        file=sys.stderr,
    )
    sys.exit(2)

import websockets  # noqa: E402  (must follow the platform guard above)

import config  # noqa: E402

AGENT_URL = "ws://localhost:8999"


def read_pairing_token():
    """The token this agent expects, if this process can read it.

    Tried in the order that fails most usefully: an argument, then the
    environment, then config.json itself - which is readable by an
    administrator and, deliberately, by nobody else. Running this script
    elevated is the normal case, since it is verifying a service.
    """
    for index, arg in enumerate(sys.argv[1:]):
        if arg == "--token" and index + 2 <= len(sys.argv) - 1:
            return sys.argv[index + 2]
    from_env = os.environ.get("INWIRE_TOKEN")
    if from_env:
        return from_env
    try:
        return config.load_config().get("token")
    except Exception:
        return None


async def recv_json(ws, timeout=3):
    """Reads the next *control* message, skipping packet batches.

    Since 3.2.0 captured frames arrive as binary WebSocket messages, not JSON
    (docs/decisions/0005). This script predated that and called json.loads on
    whatever turned up, so the first frame captured during the run killed it
    with a UnicodeDecodeError - which is what a verification tool doing its job
    should never look like.
    """
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        if isinstance(raw, (bytes, bytearray)):
            BINARY_FRAMES.append(len(raw))
            continue
        return json.loads(raw)


# Packet batches seen during the run, for the "packets actually flow" check.
BINARY_FRAMES = []


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
            hello = {}

        # Pairing, when this agent has a token. Everything below is a command,
        # and an unpaired connection is answered with auth_required and nothing
        # else - so without this the rest of the script would report the whole
        # protocol as broken.
        if hello.get("authRequired"):
            token = read_pairing_token()
            check("a pairing token is available to this process", bool(token))
            if token:
                await ws.send(json.dumps({"type": "authenticate", "token": token}))
                paired = await recv_type(ws, "state")
                check("the token is accepted", paired.get("type") == "state")

        await ws.send(json.dumps({"type": "start_capture"}))
        # Real packets may already be queued ahead of the state message once
        # capture is live, so skip past any of those instead of grabbing
        # whatever arrives first.
        state = await recv_type(ws, "state")
        check("state after start_capture", state.get("type") == "state")
        check("state is sniffing after start_capture", state.get("state") == "sniffing")

        # 3.1.0: while sniffing the agent reports what was dropped, once a
        # second, whether or not any packet arrived.
        try:
            stats = await recv_type(ws, "capture_stats", timeout=3)
            check("capture_stats arrives while sniffing", stats.get("type") == "capture_stats")
            check("capture_stats carries the agent's drop count", isinstance(stats.get("droppedAgent"), int))
            check("capture_stats carries a sequence high-water mark", isinstance(stats.get("seqHigh"), int))
            check("capture_stats lists interfaces", isinstance(stats.get("interfaces"), list))
        except asyncio.TimeoutError:
            check("capture_stats arrives while sniffing", False)

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

        # --- 3.1.0: an unknown command is named, not swallowed ---
        await ws.send(json.dumps({"type": "teleport"}))
        unknown = await recv_type(ws, "error")
        check("an unknown command is answered with unknown_command", unknown.get("code") == "unknown_command")

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

    # --- adapter configuration (3.6.0) ---
    #
    # The one part of this feature that cannot be checked without a real
    # agent: test_protocol.py drives the handler with a fake socket and fake
    # providers, so what is untested until here is whether the providers
    # actually read THIS machine. A subscription that answers with an empty
    # list would pass every unit test and show an empty panel.
    async with websockets.connect(AGENT_URL, origin="http://localhost:3000") as ws:
        hello = await recv_type(ws, "hello")
        # Same pairing step as above: an unpaired connection is answered with
        # auth_required and nothing else, which would read here as the whole
        # feature being broken.
        if hello.get("authRequired"):
            token = read_pairing_token()
            if token:
                await ws.send(json.dumps({"type": "authenticate", "token": token}))
                await recv_type(ws, "state")
        await ws.send(json.dumps({"type": "subscribe_adapters"}))
        message = await recv_type(ws, "adapter_config", timeout=20)
        adapters = message.get("adapters") or []
        check("subscribe_adapters answers with a snapshot", len(adapters) > 0)

        # Narrowed to the capture list rather than every binding Windows
        # lists - which is 51 on the machine this was written on.
        check("...only the adapters the capture list names", len(adapters) <= 24)

        # At least one adapter this machine could actually capture on has to
        # be answerable, or the panel has nothing to show.
        usable = [a for a in adapters if a.get("mac") and (a.get("ipv4") or a.get("ipv6"))]
        check("...including at least one with a MAC and an address", len(usable) > 0)
        if usable:
            one = usable[0]
            check("an adapter carries the join key to a capture interface", bool(one.get("id")))
            check("...and says which provider answered", isinstance(one.get("source"), dict))
            # Nulls are the contract, so their absence is not required - but
            # every key has to be PRESENT, or the panel cannot tell "not
            # known" from "this build does not report it".
            for key in ("name", "status", "mtu", "dhcpEnabled", "gatewayV4",
                        "gatewayMac", "dnsServers", "leaseExpires"):
                check(f"...and carries the key {key!r}", key in one)
            print(f"      {len(adapters)} adapters, {len(usable)} with an address")
            print(f"      e.g. {one.get('name')!r} mac={one.get('mac')} "
                  f"gw={one.get('gatewayV4')} gwmac={one.get('gatewayMac')} "
                  f"dns={one.get('dnsServers')}")

        # Refresh drops the cache and answers even when nothing has changed -
        # which is the whole point of it, since pressing Refresh is a
        # statement that something just did.
        await ws.send(json.dumps({"type": "refresh_adapters"}))
        again = await recv_type(ws, "adapter_config", timeout=30)
        check("refresh_adapters answers even when nothing changed",
              isinstance(again.get("adapters"), list))

        await ws.send(json.dumps({"type": "unsubscribe_adapters"}))

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
