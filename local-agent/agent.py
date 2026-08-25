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
from http import HTTPStatus

import config

try:
    from scapy.all import sniff, ARP, Dot3, Ether, IP, IPv6, TCP, UDP
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
AGENT_VERSION = "2.0.0"

import logging

# Replaced in Task 5 by logging_setup.setup_logging(). Until then this is a
# bare logger with no handlers, which is silent - the print() calls elsewhere
# in this file are still the visible output.
log = logging.getLogger("netview")
log.addHandler(logging.StreamHandler(sys.stderr))
log.setLevel(logging.INFO)


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


def build_hello_message(version: str, state: str, interfaces) -> dict:
    """The first message sent on every new connection, before anything else.

    No `authRequired` field: by the time this is sent the connection has
    already passed the origin check during the HTTP handshake, so there is no
    second authentication step left to advertise.
    """
    return {
        "type": "hello",
        "version": version,
        "state": state,
        "interfaces": [{"name": name, "label": label} for name, label in interfaces],
    }


class SnifferController:
    """Tracks whether the agent should be sniffing and on which interfaces,
    independent of the actual scapy/thread machinery. Thread creation is
    injected via spawn_fn(iface_name, stop_event) so this orchestration logic
    - start/stop/reconfigure - is unit-testable with a fake spawn_fn and no
    real interfaces or scapy involved. The real spawn_fn (wired up in main())
    starts a daemon thread running sniff_on_interface.

    A fresh threading.Event is created on every start_threads/restart_threads
    call rather than reusing one persistent Event: a still-exiting thread from
    a previous stop keeps checking the Event object it was given, so clearing
    and reusing one Event could make that lingering thread think a *new*
    session told it to keep going.
    """

    def __init__(self, default_interfaces):
        self.selected_interfaces = list(default_interfaces)
        self._sniffing = False
        self.stop_event = threading.Event()

    def is_sniffing(self) -> bool:
        return self._sniffing

    def set_interfaces(self, interfaces) -> None:
        self.selected_interfaces = list(interfaces)

    def start_threads(self, spawn_fn) -> None:
        if self._sniffing:
            return
        self.stop_event = threading.Event()
        for name in self.selected_interfaces:
            spawn_fn(name, self.stop_event)
        self._sniffing = True

    def stop_threads(self) -> None:
        if not self._sniffing:
            return
        self.stop_event.set()
        self._sniffing = False

    def restart_threads(self, spawn_fn) -> None:
        was_sniffing = self._sniffing
        self.stop_threads()
        if was_sniffing:
            self.start_threads(spawn_fn)

    def state_message(self, available_interfaces) -> dict:
        return {
            "type": "state",
            "state": "sniffing" if self._sniffing else "idle",
            "interfaces": [{"name": name, "label": label} for name, label in available_interfaces],
        }


def packet_to_dict(pkt):
    """Builds the JSON message for one captured frame.

    These metadata fields are only a *fallback*: whenever "raw" is present the
    browser re-dissects the frame itself with the same code path an imported
    pcap goes through, and overwrites all of them. So the job here is to send
    every frame with its bytes intact, not to classify it - which is why a
    frame with no IP layer is described from its Ethernet header rather than
    being dropped.
    """
    if IP in pkt:
        ip_layer = pkt[IP]
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
    else:
        ip_layer = None

    if TCP in pkt:
        proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif UDP in pkt:
        proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
    else:
        proto, sport, dport = "Other", None, None

    if ip_layer is not None:
        source, destination = ip_layer.src, ip_layer.dst
    else:
        # A frame with no network layer - ARP, STP, IEEE 1905 - shows its MAC
        # addresses, which is what Wireshark puts in those columns too. The
        # browser resolves them to vendor names once it re-dissects.
        #
        # Both link layers have to be checked: an 802.3 frame (where bytes
        # 12-13 are a length rather than an ethertype, as in every STP BPDU)
        # parses as Dot3, not Ether, so testing only for Ether loses exactly
        # the frames this fallback exists to describe.
        link_layer = pkt.getlayer(Ether) or pkt.getlayer(Dot3)
        if link_layer is not None:
            source, destination = link_layer.src, link_layer.dst
            proto = "ARP" if ARP in pkt else "Other"
        else:
            source, destination = "unknown", "unknown"

    return {
        "type": "packet",
        "id": make_id(),
        "timestamp": int(time.time() * 1000),
        "source": source,
        "destination": destination,
        "protocol": proto,
        "sourcePort": sport,
        "destPort": dport,
        "length": len(pkt),
        "info": f"{proto} Traffic",
        "raw": base64.b64encode(bytes(pkt)).decode('ascii'),
    }


class AgentServer:
    def __init__(self):
        # A plain set of sockets. Phase 1 needed a ws -> ConnectionAuth map so
        # packet fan-out could check each connection's pairing state; the
        # origin check now rejects disallowed clients during the handshake, so
        # every connection in this set is by construction an allowed one.
        self.connections = set()
        self.loop = None

    async def register(self, ws):
        self.connections.add(ws)
        log.info("client connected (%d total)", len(self.connections))
        state = "sniffing" if sniffer.is_sniffing() else "idle"
        await ws.send(json.dumps(build_hello_message(AGENT_VERSION, state, AVAILABLE_INTERFACES)))
        try:
            async for raw in ws:
                await self._handle_message(ws, raw)
        finally:
            self.connections.discard(ws)
            log.info("client disconnected (%d remaining)", len(self.connections))

    async def _handle_message(self, ws, raw):
        try:
            message = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(message, dict):
            return

        msg_type = message.get("type")
        if msg_type == "start_capture":
            log.info("start_capture requested on %d interface(s)", len(sniffer.selected_interfaces))
            sniffer.start_threads(spawn_sniffer_thread)
        elif msg_type == "stop_capture":
            log.info("stop_capture requested")
            sniffer.stop_threads()
        elif msg_type == "set_interfaces":
            interfaces = message.get("interfaces")
            if isinstance(interfaces, list) and all(isinstance(i, str) for i in interfaces):
                if not interfaces:
                    # Sniffing "on zero interfaces" would otherwise succeed
                    # silently and broadcast state=sniffing while nothing is
                    # actually captured.
                    await ws.send(json.dumps({
                        "type": "error",
                        "code": "empty_interfaces",
                        "message": "At least one interface must be selected.",
                    }))
                    return
                log.info("set_interfaces: %d interface(s) selected", len(interfaces))
                sniffer.set_interfaces(interfaces)
                sniffer.restart_threads(spawn_sniffer_thread)
        else:
            return

        self.broadcast(sniffer.state_message(AVAILABLE_INTERFACES))

    def broadcast(self, message: dict):
        """Called from the sniffer thread (packet_to_dict results) as well as
        from _handle_message above - hop back onto the asyncio loop either way."""
        if not self.connections or self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self._send_all(message), self.loop)

    async def _send_all(self, message: dict):
        # list(...) snapshots the set before awaiting inside the loop, since a
        # client connecting or dropping mid-broadcast would otherwise mutate
        # self.connections while it is being iterated.
        data = json.dumps(message)
        dead = []
        for ws in list(self.connections):
            try:
                await ws.send(data)
            except websockets.ConnectionClosed:
                dead.append(ws)
        for ws in dead:
            self.connections.discard(ws)


agent = AgentServer()


def make_process_request(on_reject=None):
    """Builds the callback websockets invokes before completing the upgrade
    handshake. Returning None accepts the connection; returning a Response
    rejects it outright, so a disallowed page never receives `hello` and
    never receives a packet.

    The config is re-read here, on every connection, rather than once at
    startup. The file is tiny and connections are rare, so the cost is
    irrelevant - and it means adding an origin takes effect without
    restarting a service that has no UI to restart it from.
    """
    def process_request(connection, request):
        origin = request.headers.get("Origin")
        settings = config.load_config(on_warning=lambda msg: log.warning("config: %s", msg))
        if not config.is_origin_allowed(origin, settings["allowedOrigins"]):
            if on_reject is not None:
                on_reject(origin)
            return connection.respond(HTTPStatus.FORBIDDEN, "Origin not allowed\n")
        return None

    return process_request


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


def sniff_on_interface(iface_name, iface_label, stop_event):
    try:
        # No BPF filter: capture every frame on the wire, the way Wireshark
        # does by default. This used to be "ip or ip6", which silently
        # discarded ARP, STP and every other non-IP protocol before they
        # could reach the browser - the frontend dissects all of them.
        # store=False keeps memory flat during long-running captures.
        # stop_filter is checked after every captured packet (or scapy's own
        # read timeout on a quiet interface) - that's what makes stop_capture
        # actually stop the thread instead of blocking forever.
        sniff(prn=sniff_callback, store=False, iface=iface_name,
              stop_filter=lambda pkt: stop_event.is_set())
    except Exception as exc:  # e.g. an adapter that's disabled/down, or Npcap missing on Windows
        print(f"[agent] WARNING: capture failed on interface {iface_label!r} ({iface_name}): {exc}", file=sys.stderr)


def spawn_sniffer_thread(iface_name, stop_event):
    label = INTERFACE_LABELS.get(iface_name, iface_name)
    t = threading.Thread(target=sniff_on_interface, args=(iface_name, label, stop_event), daemon=True)
    t.start()
    return t


async def main():
    global AVAILABLE_INTERFACES, INTERFACE_LABELS, sniffer

    if not has_admin_privileges():
        hint = (
            "Right-click and choose 'Run as administrator'."
            if os.name == "nt"
            else "Re-run with sudo, e.g.: sudo python3 agent.py"
        )
        print(f"ERROR: Packet capture requires elevated privileges.\n{hint}", file=sys.stderr)
        sys.exit(1)

    try:
        AVAILABLE_INTERFACES = list_interfaces()
    except Exception as exc:
        print(f"[agent] ERROR: could not enumerate network interfaces: {exc}", file=sys.stderr)
        sys.exit(1)
    INTERFACE_LABELS = dict(AVAILABLE_INTERFACES)

    print(f"[agent] detected {len(AVAILABLE_INTERFACES)} network interface(s):", file=sys.stderr)
    for name, label in AVAILABLE_INTERFACES:
        print(f"[agent]   {label} -> {name}", file=sys.stderr)

    # Starts idle on purpose - sniffing now only begins when a paired client
    # sends start_capture, not automatically at process launch.
    sniffer = SnifferController(default_interfaces=[name for name, _ in AVAILABLE_INTERFACES])

    agent.loop = asyncio.get_running_loop()

    def log_rejection(origin):
        log.warning("rejected connection from disallowed origin: %r", origin)

    async with websockets.serve(
        agent.register,
        HOST,
        PORT,
        process_request=make_process_request(on_reject=log_rejection),
    ):
        log.info("WebSocket server listening on ws://%s:%d", HOST, PORT)
        await asyncio.Future()  # run forever


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[agent] shutting down.")
