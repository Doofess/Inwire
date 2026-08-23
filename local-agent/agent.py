#!/usr/bin/env python3
"""
NetView Agent

Captures live packet metadata with Scapy and streams it as JSON to any
connected browser tab over a local WebSocket. This never leaves the
machine it runs on - the web app only talks to ws://localhost:8999.

Run elevated:
  Windows (as Administrator):  python agent.py
  macOS / Linux (as root):     sudo python3 agent.py
"""

import asyncio
import base64
import ctypes
import json
import os
import random
import sys
import threading
import time

try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP
except ImportError:
    print("ERROR: scapy is not installed. Run: pip install scapy", file=sys.stderr)
    sys.exit(1)

try:
    import websockets
except ImportError:
    print("ERROR: websockets is not installed. Run: pip install websockets", file=sys.stderr)
    sys.exit(1)

HOST = "localhost"
PORT = 8999


def make_id() -> str:
    return f"py-{int(time.time() * 1000)}-{random.randrange(36**5):0>5x}"


def has_admin_privileges() -> bool:
    """Packet capture needs raw-socket access, which requires elevation
    on every OS. Fail fast with a clear message instead of a cryptic
    scapy/OS permission error."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def packet_to_dict(pkt):
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
    else:
        return None  # non-IP traffic (ARP, etc.) - skip to keep the schema simple

    if TCP in pkt:
        proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif UDP in pkt:
        proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
    else:
        proto, sport, dport = "Other", None, None

    return {
        "id": make_id(),
        "timestamp": int(time.time() * 1000),
        "source": ip_layer.src,
        "destination": ip_layer.dst,
        "protocol": proto,
        "sourcePort": sport,
        "destPort": dport,
        "length": len(pkt),
        "info": f"{proto} Traffic",
        "raw": base64.b64encode(bytes(pkt)).decode('ascii'),
    }


class AgentServer:
    def __init__(self):
        self.clients = set()
        self.loop = None

    async def register(self, ws):
        self.clients.add(ws)
        print(f"[agent] client connected ({len(self.clients)} total)")
        try:
            await ws.wait_closed()
        finally:
            self.clients.discard(ws)
            print(f"[agent] client disconnected ({len(self.clients)} total)")

    def broadcast(self, message: dict):
        """Called from the sniffer thread - hop back onto the asyncio loop."""
        if not self.clients or self.loop is None:
            return
        data = json.dumps(message)
        asyncio.run_coroutine_threadsafe(self._send_all(data), self.loop)

    async def _send_all(self, data: str):
        dead = []
        for ws in self.clients:
            try:
                await ws.send(data)
            except websockets.ConnectionClosed:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)


agent = AgentServer()
sniffer_error = None


_captured_count = 0


def sniff_callback(pkt):
    global _captured_count
    _captured_count += 1
    if _captured_count == 1:
        print("[agent] first packet captured - capture is working", file=sys.stderr)
    elif _captured_count % 100 == 0:
        print(f"[agent] {_captured_count} packets captured so far", file=sys.stderr)

    try:
        info = packet_to_dict(pkt)
    except Exception as exc:
        print(f"[agent] WARNING: failed to process a captured packet: {exc}", file=sys.stderr)
        return
    if info is not None:
        agent.broadcast(info)


def list_interfaces():
    """Returns a list of (device_name, friendly_label) tuples to capture on.
    On Windows this cross-references Npcap's raw NPF_{GUID} device paths
    against Windows' own adapter list so failures/logs are readable."""
    from scapy.all import get_if_list

    if os.name == "nt":
        try:
            from scapy.arch.windows import get_windows_if_list
            interfaces = []
            for w in get_windows_if_list():
                guid = w.get("guid", "")
                npf_name = f"\\Device\\NPF_{guid}" if guid else w.get("name", "")
                label = f"{w.get('name', '?')} ({w.get('description', '?')})"
                interfaces.append((npf_name, label))
            if interfaces:
                return interfaces
        except Exception as exc:
            print(f"[agent] could not resolve friendly adapter names ({exc}); falling back to raw list", file=sys.stderr)

    return [(name, name) for name in get_if_list()]


def sniff_on_interface(iface_name, iface_label):
    try:
        # store=False keeps memory flat during long-running captures.
        sniff(prn=sniff_callback, store=False, filter="ip or ip6", iface=iface_name)
    except Exception as exc:  # e.g. an adapter that's disabled/down, or Npcap missing on Windows
        print(f"[agent] WARNING: capture failed on interface {iface_label!r} ({iface_name}): {exc}", file=sys.stderr)


def start_sniffer():
    global sniffer_error
    iface_override = os.environ.get("NETVIEW_IFACE") or None

    try:
        interfaces = list_interfaces()
    except Exception as exc:
        sniffer_error = exc
        print(f"[agent] ERROR: could not enumerate network interfaces: {exc}", file=sys.stderr)
        return

    print(f"[agent] detected {len(interfaces)} network interface(s):", file=sys.stderr)
    for name, label in interfaces:
        print(f"[agent]   {label} -> {name}", file=sys.stderr)

    if iface_override:
        print(f"[agent] NETVIEW_IFACE override set - capturing ONLY on: {iface_override}", file=sys.stderr)
        targets = [(iface_override, iface_override)]
    else:
        print(f"[agent] no NETVIEW_IFACE override set - capturing on ALL {len(interfaces)} interface(s) "
              "simultaneously (like Wireshark's 'any' capture). Note this can show the same real-world "
              "traffic twice if a virtual adapter bridges the same link as a physical one - set "
              "NETVIEW_IFACE to a single interface from the list above if you need to avoid that.",
              file=sys.stderr)
        targets = interfaces

    if not targets:
        sniffer_error = RuntimeError("no network interfaces found")
        print("[agent] ERROR: no network interfaces available to capture on.", file=sys.stderr)
        return

    # Each interface gets its own thread and its own try/except (inside
    # sniff_on_interface) so one disabled/inactive adapter can't take capture
    # down on the rest - this call blocks (via join) since start_sniffer()
    # already runs in its own background thread, started from main().
    threads = [
        threading.Thread(target=sniff_on_interface, args=(name, label), daemon=True)
        for name, label in targets
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


async def main():
    if not has_admin_privileges():
        hint = (
            "Right-click and choose 'Run as administrator'."
            if os.name == "nt"
            else "Re-run with sudo, e.g.: sudo python3 agent.py"
        )
        print(f"ERROR: Packet capture requires elevated privileges.\n{hint}", file=sys.stderr)
        sys.exit(1)

    agent.loop = asyncio.get_running_loop()

    sniffer_thread = threading.Thread(target=start_sniffer, daemon=True)
    sniffer_thread.start()

    async with websockets.serve(agent.register, HOST, PORT):
        print(f"[agent] WebSocket server listening on ws://{HOST}:{PORT}")
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[agent] shutting down.")
