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
import logging
import os
import random
import sys
import threading
import time
from http import HTTPStatus

import config


def _report_missing_dependency(name: str, install_hint: str) -> None:
    """Runs at import time, before logging is configured, and possibly in a
    frozen console=False build where sys.stderr is None - so it must not
    assume a console exists."""
    message = f"ERROR: {name} is not installed. Run: {install_hint}"
    if sys.stderr is not None:
        print(message, file=sys.stderr)
    try:
        logging.getLogger("netview").critical(message)
    except Exception:
        pass


try:
    from scapy.all import sniff, ARP, Dot3, Ether, IP, IPv6, TCP, UDP
    from scapy.all import conf as scapy_conf
except ImportError:
    _report_missing_dependency("scapy", "pip install scapy")
    sys.exit(1)

try:
    import websockets
except ImportError:
    _report_missing_dependency("websockets", "pip install websockets")
    sys.exit(1)

HOST = "localhost"
PORT = 8999
AGENT_VERSION = "2.3.0"

# The most packet sends that may be queued onto the event loop at once. Past
# this, frames are dropped instead of queued (see AgentServer.broadcast). A
# few hundred is roughly a quarter-second of a busy interface: enough to ride
# out a normal render hitch on the client, far too little to accumulate into
# the gigabyte-scale backlog that previously wedged the agent.
MAX_PENDING_SENDS = 400

# How often the watchdog checks that capture is not running with nobody
# watching (see watch_for_orphaned_capture).
ORPHAN_CHECK_SECONDS = 2

import logging_setup
import agent_log

# Configured for real in main(); until then this is a plain logger, so an
# import-time failure still has somewhere to go.
log = logging.getLogger("netview")


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


def capture_time_ms(pkt):
    """Epoch milliseconds for when the frame was actually captured.

    scapy sets pkt.time from libpcap's per-packet header, which carries
    microsecond resolution. Falls back to the current wall clock only if a
    packet somehow arrives without one - a frame with no time at all would
    otherwise break the browser's relative-time column outright, which is a
    worse outcome than one slightly-late timestamp.
    """
    stamp = getattr(pkt, "time", None)
    if stamp is None:
        return time.time() * 1000
    return float(stamp) * 1000


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
        # The frame's real capture time, from libpcap, in fractional
        # milliseconds. Was int(time.time() * 1000): the wall clock read when
        # Python happened to process the frame, truncated to a whole
        # millisecond. That is wrong twice over - it measures this process's
        # scheduling rather than the wire, and at even modest rates several
        # frames land on the same millisecond and become indistinguishable in
        # time. A 1368-frame sample held only 604 distinct timestamps, with up
        # to six frames sharing one.
        #
        # float() because scapy hands back an EDecimal, which json cannot
        # serialize. Kept fractional rather than rounded so sub-millisecond
        # ordering survives into the packet list and the pcap export.
        "timestamp": capture_time_ms(pkt),
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
        # Sockets that asked for log lines, always a subset of connections.
        # Separate from connections because the common case is a client that
        # never opens Driver Info at all, and log fan-out should cost nothing
        # for those.
        self.log_subscribers = set()
        self.loop = None
        # How many _send_all coroutines are scheduled but have not yet run.
        # Bounding this is what stops a fast interface growing the agent
        # without limit - see broadcast().
        self._pending_sends = 0
        self._dropped_sends = 0

    async def register(self, ws):
        self.connections.add(ws)
        log.info("client connected (%d total)", len(self.connections))
        try:
            # The hello send is inside the try because a client dropping
            # mid-handshake would otherwise leak the connection and permanently
            # disable auto-stop: handle_disconnect only stops capture when
            # not self.connections, so any stuck entry means the condition
            # can never be true again. Every exit path must reach finally.
            state = "sniffing" if sniffer.is_sniffing() else "idle"
            await ws.send(json.dumps(build_hello_message(AGENT_VERSION, state, AVAILABLE_INTERFACES)))
            async for raw in ws:
                await self._handle_message(ws, raw)
        finally:
            self.handle_disconnect(ws)

    def handle_disconnect(self, ws):
        """Capture is scoped to live connections: with nobody watching,
        nothing should be captured. Closing the last NetView tab therefore
        stops the sniffer (see spec: Capture lifecycle).

        Sniffing deliberately does not resume when a client reconnects - a
        fresh connection arrives idle and must send start_capture again.
        Inferring intent across a disconnect would mean capturing traffic
        nobody explicitly asked for, which is the whole property that makes
        an always-running background capture agent acceptable.
        """
        self.connections.discard(ws)
        # A socket left here after its connection died would make the log
        # fan-out write to a dead socket on every line, forever.
        self.log_subscribers.discard(ws)
        log.info("client disconnected (%d remaining)", len(self.connections))
        if not self.connections and sniffer.is_sniffing():
            log.info("last client disconnected - stopping capture")
            sniffer.stop_threads()

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
        elif msg_type == "subscribe_logs":
            backlog = agent_log.read_log_tail(self.log_file_path())
            await ws.send(json.dumps({
                "type": "log",
                "lines": [agent_log.parse_log_line(line) for line in backlog],
            }))
            # Registered only after the backlog is on the wire. Registering
            # first would let a line logged during the read arrive ahead of
            # the backlog it also appears in - a duplicated, out-of-order
            # timeline. This way the worst case is one line logged during the
            # send being missed, which is invisible next to a 200-line
            # backlog.
            self.log_subscribers.add(ws)
            return
        elif msg_type == "unsubscribe_logs":
            self.log_subscribers.discard(ws)
            return
        else:
            return

        self.broadcast(sniffer.state_message(AVAILABLE_INTERFACES))

    def broadcast(self, message: dict):
        """Called from the sniffer thread (packet_to_dict results) as well as
        from _handle_message above - hop back onto the asyncio loop either way.

        Drops the message rather than queueing it when the loop is already
        behind. This bound is not an optimization, it is the difference
        between a bad minute and an unusable machine: without it every
        captured frame scheduled a coroutine plus its JSON string with
        nothing limiting how many could pile up, so an interface faster than
        the client could drain - loopback runs ~1200 packets/sec - grew the
        agent to 1.2 GB and starved its own event loop until it stopped
        answering the service manager's stop request and could no longer even
        be shut down.

        Dropping is the correct trade. This is a live view of traffic, not a
        recording: a viewer that cannot keep up wants the newest frames, not
        an ever-growing backlog of stale ones it will never catch up on.
        """
        if not self.connections or self.loop is None:
            return
        if self._pending_sends >= MAX_PENDING_SENDS:
            self._dropped_sends += 1
            # Logged sparsely and only on crossings of a power-of-ten-ish
            # boundary: the drop path is the hot path when it is running at
            # all, and logging per drop would recreate the flood one level up
            # (log records also fan out to subscribed clients).
            if self._dropped_sends in (1, 100, 1000) or self._dropped_sends % 10000 == 0:
                log.warning(
                    "dropped %d packet(s): the client is not keeping up with this interface",
                    self._dropped_sends,
                )
            return
        self._pending_sends += 1
        asyncio.run_coroutine_threadsafe(self._send_all(message), self.loop)

    async def _send_all(self, message: dict):
        # list(...) snapshots the set before awaiting inside the loop, since a
        # client connecting or dropping mid-broadcast would otherwise mutate
        # self.connections while it is being iterated.
        try:
            data = json.dumps(message)
            dead = []
            for ws in list(self.connections):
                try:
                    await ws.send(data)
                except websockets.ConnectionClosed:
                    dead.append(ws)
            for ws in dead:
                self.connections.discard(ws)
                self.log_subscribers.discard(ws)
        finally:
            # In a finally so any unexpected failure still frees the slot.
            # Leaking slots would silently ratchet the agent down to sending
            # nothing at all, which is far harder to diagnose than dropping.
            self._pending_sends -= 1

    def log_file_path(self) -> str:
        return os.path.join(config.config_dir(), logging_setup.LOG_FILENAME)

    def broadcast_log(self, entry: dict):
        """Sink for WebSocketLogHandler. Called from any thread that logs.

        Returns immediately when nobody is subscribed, which is the normal
        case: with the Driver Info panel closed the whole feature costs one
        set-emptiness check per log line.
        """
        if not self.log_subscribers or self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(
            self._send_logs({"type": "log", "lines": [entry]}), self.loop
        )

    async def _send_logs(self, message: dict):
        # Separate from _send_all so a client watching logs is not also sent
        # packets, and vice versa. list(...) snapshots before awaiting, since
        # a client subscribing or dropping mid-send would otherwise mutate
        # the set while it is being iterated.
        data = json.dumps(message)
        for ws in list(self.log_subscribers):
            try:
                await ws.send(data)
            except websockets.ConnectionClosed:
                self.log_subscribers.discard(ws)
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
        log.info("first packet captured - capture is working")
    elif _captured_count % 10000 == 0:
        # Every 10,000 rather than every 100. At 100 this single line was 82%
        # of the log file (930 of 1129 lines in one session), which churned
        # the 1MB rotation fast enough to discard real history - and once the
        # Driver Info panel could subscribe to the log, it also meant a
        # capture drowned every genuine diagnostic in the viewer.
        log.info("%d packets captured so far", _captured_count)

    try:
        info = packet_to_dict(pkt)
    except Exception as exc:
        log.warning("failed to process a captured packet: %s", exc)
        return
    if info is not None:
        agent.broadcast(info)


_RTL_MARKS = ("‎", "‏")


def _strip_rtl_marks(text: str) -> str:
    for mark in _RTL_MARKS:
        text = text.replace(mark, "")
    return text.strip()


def build_interface_label(name, description) -> str:
    """Builds the "{name} ({description})" label scapy/Windows interfaces are
    shown with, stripping the Unicode RTL marks (U+200E, U+200F) that
    Windows embeds in localized adapter names/descriptions. Falls back to
    just the (cleaned) name - or, if that's empty, just the (cleaned)
    description - when there's no distinct pair to combine."""
    clean_name = _strip_rtl_marks(name or "")
    clean_description = _strip_rtl_marks(description or "")
    if not clean_name:
        return clean_description
    if not clean_description or clean_description == clean_name:
        return clean_name
    return f"{clean_name} ({clean_description})"


def list_interfaces():
    """Returns a list of (device_name, friendly_label) tuples to capture on.

    On Windows this enumerates devices via scapy's `conf.ifaces`, which is
    populated from libpcap/Npcap's pcap_findalldevs() - the same source
    Wireshark's interface list comes from. `get_windows_if_list()` is
    deliberately NOT used here: it returns every Windows adapter *binding*
    (LightWeight Filter bindings, QoS Packet Scheduler bindings, Npcap
    Packet Driver bindings, WAN Miniports, Teredo/6to4/IP-HTTPS tunneling
    adapters, ...), most of which Npcap cannot actually capture on. Sniffing
    on those floods the log with "Interface '...' not found !" warnings and
    makes any capture-interface picker built from the list unusable.

    conf.ifaces only reflects the true pcap_findalldevs() results when scapy
    successfully loaded Npcap's wpcap.dll (conf.use_pcap is True). When it
    couldn't, scapy silently degrades conf.ifaces to yield the raw Windows
    adapter list instead - i.e. the exact ~51-binding over-enumeration this
    function exists to avoid, returned as if it were trustworthy. That case
    is detected and treated as a hard failure (empty list, logged error)
    rather than a fallback, since get_if_list() on Windows is itself derived
    from that same degraded conf.ifaces and would just return the same wrong
    list.
    """
    from scapy.all import get_if_list

    if os.name == "nt":
        if not getattr(scapy_conf, "use_pcap", False):
            # scapy could not load wpcap.dll, so conf.ifaces (and
            # get_if_list()) would silently degrade to the raw ~51-binding
            # Windows adapter list - exactly what this function exists to
            # avoid. Without Npcap there is nothing to capture on anyway.
            log.error(
                "Npcap's packet driver is not available (scapy could not load wpcap.dll). "
                "Packet capture will not work. Install Npcap from https://npcap.com/#download"
            )
            return []
        try:
            interfaces = []
            for iface in scapy_conf.ifaces.values():
                device_name = getattr(iface, "network_name", "") or ""
                if not device_name:
                    continue
                label = build_interface_label(
                    getattr(iface, "name", "") or "",
                    getattr(iface, "description", "") or "",
                )
                interfaces.append((device_name, label))
            if interfaces:
                return interfaces
        except Exception as exc:
            log.warning("could not resolve friendly adapter names (%s); falling back to raw list", exc)

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
        log.warning("capture failed on interface %r (%s): %s", iface_label, iface_name, exc)


def spawn_sniffer_thread(iface_name, stop_event):
    label = INTERFACE_LABELS.get(iface_name, iface_name)
    t = threading.Thread(target=sniff_on_interface, args=(iface_name, label, stop_event), daemon=True)
    t.start()
    return t


async def watch_for_orphaned_capture():
    """Stops capture whenever nothing is watching.

    handle_disconnect already stops on the last client leaving, and in normal
    operation that is what fires. This exists because that path is a single
    point of failure for a promise the agent has to keep unconditionally: a
    background service with no UI must never sit capturing traffic once the
    app is closed. Any way of losing a connection that does not run
    handle_disconnect - a dropped TCP session the library reports oddly, an
    exception on an unexpected path, a future edit - would otherwise leave a
    capture running invisibly and indefinitely.

    Polling is the right shape for a guarantee like this precisely because it
    does not depend on any event arriving.
    """
    while True:
        await asyncio.sleep(ORPHAN_CHECK_SECONDS)
        if sniffer is not None and sniffer.is_sniffing() and not agent.connections:
            log.warning("capture was running with no clients connected - stopping it")
            sniffer.stop_threads()


async def main(to_stderr=True):
    global AVAILABLE_INTERFACES, INTERFACE_LABELS, sniffer, log

    log = logging_setup.setup_logging(config.config_dir(), to_stderr=to_stderr)
    # Must come after setup_logging, which tears down existing handlers when
    # reconfigured - installing before it would silently remove this one.
    log.addHandler(agent_log.WebSocketLogHandler(agent.broadcast_log))
    log.info("NetView agent %s starting", AGENT_VERSION)

    if not has_admin_privileges():
        hint = (
            "Right-click and choose 'Run as administrator'."
            if os.name == "nt"
            else "Re-run with sudo, e.g.: sudo python3 agent.py"
        )
        log.error("packet capture requires elevated privileges. %s", hint)
        return False

    try:
        AVAILABLE_INTERFACES = list_interfaces()
    except Exception as exc:
        log.error("could not enumerate network interfaces: %s", exc)
        return False
    if not AVAILABLE_INTERFACES:
        log.error("no capturable network interfaces found - cannot start")
        return False
    INTERFACE_LABELS = dict(AVAILABLE_INTERFACES)

    log.info("detected %d network interface(s)", len(AVAILABLE_INTERFACES))
    for name, label in AVAILABLE_INTERFACES:
        log.info("  %s -> %s", label, name)

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
        asyncio.create_task(watch_for_orphaned_capture())
        await asyncio.Future()  # run forever

    return True


if __name__ == "__main__":
    try:
        _ok = asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[agent] shutting down.")
    else:
        if _ok is False:
            sys.exit(1)
