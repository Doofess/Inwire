#!/usr/bin/env python3
"""
Inwire Agent

Captures live packet metadata with Scapy and streams it as JSON to any
connected browser tab over a local WebSocket. This never leaves the
machine it runs on - the web app only talks to ws://localhost:8999.

Run elevated:
  Windows (as Administrator):  python agent.py
  macOS / Linux (as root):     sudo python3 agent.py
"""

import asyncio
import collections
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
import pipe_server
import packet_batch
import capture_profile


def _report_missing_dependency(name: str, install_hint: str) -> None:
    """Runs at import time, before logging is configured, and possibly in a
    frozen console=False build where sys.stderr is None - so it must not
    assume a console exists."""
    message = f"ERROR: {name} is not installed. Run: {install_hint}"
    if sys.stderr is not None:
        print(message, file=sys.stderr)
    try:
        logging.getLogger("inwire").critical(message)
    except Exception:
        pass


try:
    # Scapy is a capture *driver* here and nothing else. Since 3.2.0 the agent
    # sends raw frames and the browser dissects them, so the protocol classes
    # this used to import - ARP, Ether, IP, IPv6, TCP, UDP - had no reader left;
    # they were still being loaded, along with the other seventeen hundred.
    #
    # `load_layers` has to be set before `scapy.all` is touched, because
    # importing it is what loads them. Three are kept: `l2` for the link layer
    # (Ethernet, and the Loopback header a DLT_NULL adapter carries), `inet` and
    # `inet6` for the raw-IP link types a VPN or tunnel adapter reports, since
    # the capture socket looks up a class for the link type it is handed and a
    # missing one is an error rather than a graceful degradation.
    #
    # Measured on this machine: 65.6 MB and 0.33 s of import time become 39.9 MB
    # and 0.17 s. That memory is resident for the life of a service that spends
    # almost all of it idle.
    from ctypes import POINTER, byref, c_ubyte, string_at
    from scapy.config import conf as scapy_conf
    scapy_conf.load_layers = ["l2", "inet", "inet6"]
    from scapy.all import sniff  # noqa: E402  (must follow load_layers)
    from scapy.data import ETH_P_ALL
    # Only to ask whether a socket has overridden recv_raw - see
    # sniff_on_interface. Importing it loads no protocol layers.
    from scapy.supersocket import SuperSocket
    # The libpcap calls the agent makes directly, past scapy. Two of the three
    # scapy does not expose at all (statistics, buffer sizing) and the third it
    # exposes only through a wrapper that costs 12x what the call does - see
    # read_frame. Importing this loads no protocol layers either.
    from scapy.libs.winpcapy import pcap_next_ex, pcap_pkthdr
except ImportError:
    _report_missing_dependency("scapy", "pip install scapy")
    sys.exit(1)

# The WebSocket is the transport on macOS and Linux and nowhere else. On
# Windows the app reaches the agent over a named pipe, so requiring this here
# would make the service depend on a library it never loads a line of - and
# would ship it inside a signed installer for no reason. Missing is fatal only
# where it is needed.
if sys.platform == "win32":
    websockets = None
else:
    try:
        import websockets
    except ImportError:
        _report_missing_dependency("websockets", "pip install websockets")
        sys.exit(1)

#: What "the client has gone" is, whichever transport it went from.
#:
#: A dead WebSocket raises `websockets.ConnectionClosed`; a dead pipe raises
#: the builtin `ConnectionError`. Only one place needs to tell that apart from
#: a real fault, and it must not be spelled as one transport's exception -
#: which it was, and which on Windows would have raised `AttributeError` on the
#: `except` clause itself the first time a log subscriber's pipe closed.
CLIENT_GONE = (
    (ConnectionError,) if websockets is None
    else (ConnectionError, websockets.ConnectionClosed)
)

HOST = "localhost"
PORT = 8999
AGENT_VERSION = "3.8.0"

# How often per-interface traffic rates are sampled while a client has the
# capture-interface picker open. 500ms is fast enough that the sparkline
# reacts while you are looking at it, slow enough that reading the OS counters
# stays invisible in the agent's CPU use.
INTERFACE_STATS_INTERVAL_SECONDS = 0.5

# Packet batching (packet_batch.py). Captured frames are queued by the sniffer
# threads and drained by one pump task, so the event loop sees a batch every
# PACKET_BATCH_INTERVAL_SECONDS rather than a coroutine per frame - which is
# what the per-packet path spent its time on, and why it dropped frames long
# before the socket was actually saturated.
#
# 10ms is below the browser's own 100ms flush, so batching adds no perceptible
# latency to the packet list; at 5,000 packets/second it turns 5,000 sends a
# second into 100.
PACKET_BATCH_INTERVAL_SECONDS = 0.01
# Bounds on one batch, so a burst is split across sends rather than building
# one enormous frame that blocks the loop while it is written.
MAX_BATCH_RECORDS = 512
MAX_BATCH_BYTES = 256 * 1024

# How many encoded frames may wait in the queue. Past this the OLDEST are
# dropped: this is a live view of traffic, not a recording, and a viewer that
# cannot keep up wants the newest frames rather than an ever-growing backlog of
# stale ones it will never catch up on. Every drop is counted and reaches the
# app in capture_stats. ~8,000 frames is a second or two of a busy adapter -
# enough to ride out a render hitch on the client, far too little to accumulate
# into the gigabyte-scale backlog that once wedged the agent.
#
# 8,192 was chosen against a frame count and the byte bound was never the one
# that bound: at the ~1,100-byte mean of a real bulk capture, 8,192 frames is
# 9 MB of the 32 MB allowed, so the agent began dropping with two thirds of its
# own budget unused. Sized to the budget instead - 30,000 frames is 33 MB at
# that mean, so whichever bound is reached first now depends on the traffic
# rather than on one of them being set nine times tighter than the other. In
# time it is 0.58 s of slack at the old count against ~2 s at this one.
MAX_QUEUED_PACKETS = 30000
MAX_QUEUED_BYTES = 32 * 1024 * 1024

# What the capture driver is asked to hold before it starts dropping frames.
#
# libpcap's Windows default is 1 MB and scapy never raises it (see
# set_kernel_buffer), which is ~67 ms of slack on a busy adapter. 32 MB is
# about two seconds at the same rate - enough to ride out the bursts that
# actually cause loss, and small enough to be uncontroversial as non-paged
# kernel memory on any machine that can run a browser.
KERNEL_BUFFER_BYTES = 32 * 1024 * 1024

# How often the watchdog checks that capture is not running with nobody
# watching (see watch_for_orphaned_capture).
ORPHAN_CHECK_SECONDS = 2

# How often capture_stats is sent while sniffing. One second is what the
# drop counter in the app is expected to move at; the numbers behind it are
# two integers per interface and cost nothing to read.
CAPTURE_STATS_INTERVAL_SECONDS = 1.0

# How often the socket table is re-read for process attribution.
#
# One second, because that is the resolution the attribution can honestly
# claim: a socket opened and closed inside one tick is never seen, and no
# faster cadence removes that - it only narrows the window. Reading the table
# costs about 3.5 ms and naming the processes in it about 2.9 ms (measured,
# ~890 sockets, 60 processes), so a tick is well under 1% of a core.
SOCKET_TABLE_INTERVAL_SECONDS = 1.0

# How often the adapter configuration is re-read.
#
# Ten seconds, because that is the timescale the thing being watched
# actually moves on: an IPv6 privacy address rotates, a DHCP lease renews,
# a cable is unplugged. None of those is a sub-second event, and the read
# is far more expensive than the socket table's - the Windows path spawns
# PowerShell when the address list changes, at about half a second. It is
# cached against exactly that, so a quiet poll costs 26 ms (measured).
ADAPTER_CONFIG_INTERVAL_SECONDS = 10.0

# How long one sniff() call may block before the thread re-checks its stop
# event. Bounds how long a stopped capture can linger on a quiet adapter,
# which before was "until the next packet arrives".
CAPTURE_POLL_SECONDS = 0.5

import logging_setup
import agent_log
import interface_stats
import sockets
import adapters

# Configured for real in main(); until then this is a plain logger, so an
# import-time failure still has somewhere to go.
log = logging.getLogger("inwire")

# The adapters currently available to capture on, as (device_name, label), and
# the same data as a lookup. Deliberately module-level rather than created in
# main(): these are re-read while the agent runs (see refresh_interfaces), so
# they are ordinary state with a starting value, not a one-time snapshot.
AVAILABLE_INTERFACES: list = []
INTERFACE_LABELS: dict = {}
# Device name -> position in AVAILABLE_INTERFACES, which is what a packet's
# `iface` field carries (see interface_entries).
INTERFACE_IDS: dict = {}


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


# --- Restarting this process --------------------------------------------------

SERVICE_NAME = "InwireAgent"
# Any non-zero code. The service manager treats a service process that dies
# with one as a failure, which is what triggers the restart action below - a
# clean exit(0) reads as an intentional stop and nothing would come back.
RESTART_EXIT_CODE = 1
# How long the SCM waits before restarting, and how long a run has to last
# before its failure count resets. A day is deliberate: three restarts is a
# genuine crash loop worth leaving stopped, not something to forgive hourly.
FAILURE_ACTION_DELAY_MS = 5000
FAILURE_RESET_SECONDS = 86400

# Resolved once at startup by refresh_restart_support(). False unless proven
# otherwise - see decide_restart_allowed for why that direction matters.
RESTART_SUPPORTED = False
RESTART_UNAVAILABLE_REASON = "Restart is unavailable: this agent is not running as the Inwire service."


def decide_restart_allowed(is_service_process: bool, failure_policy_confirmed: bool) -> bool:
    """Whether a restart_agent command may be honored.

    Restarting is implemented by exiting and letting Windows start the agent
    again, so BOTH halves have to hold or the command is not a restart at all -
    it is a one-way stop that nothing on this machine will undo:

      - `is_service_process`: an agent run from source (python agent.py) has no
        service behind it. Exiting would just close it, and no browser can
        start it again.
      - `failure_policy_confirmed`: without restart-on-failure actions the SCM
        treats the exit as a dead service and leaves it stopped until someone
        starts it or reboots.

    Both are proven by reading the SCM back, never assumed, and this is a pure
    function so that reasoning is testable without a service to talk to.
    """
    return bool(is_service_process and failure_policy_confirmed)


def _open_own_service(access):
    """Opens this machine's InwireAgent service, or None if unreachable."""
    import win32service

    scm = win32service.OpenSCManager(None, None, win32service.SC_MANAGER_CONNECT)
    try:
        return scm, win32service.OpenService(scm, SERVICE_NAME, access)
    except Exception:
        win32service.CloseServiceHandle(scm)
        raise


def _running_as_service_process() -> bool:
    """True only when THIS process is the one the SCM runs as InwireAgent.

    Compares the SCM's reported process id against our own rather than
    inferring from how the code was launched: `debug` mode runs the real
    service body in the foreground, and a source run imports the very same
    module, so nothing about the call path distinguishes them reliably.
    """
    if os.name != "nt":
        return False
    try:
        import win32service

        scm, svc = _open_own_service(win32service.SERVICE_QUERY_STATUS)
        try:
            status = win32service.QueryServiceStatusEx(svc)
            return status.get("ProcessId") == os.getpid()
        finally:
            win32service.CloseServiceHandle(svc)
            win32service.CloseServiceHandle(scm)
    except Exception as exc:
        log.debug("could not determine service identity (%s)", exc)
        return False


def _ensure_failure_policy() -> bool:
    """Asserts restart-on-failure actions, and returns whether they are in place.

    Writes first and then reads back, because only the read decides. The write
    can legitimately fail - a non-elevated source run has no right to change
    service config - and the installer may already have set the policy, so a
    failed write is not a failed outcome. Never trusting the write is also what
    keeps a silently-ignored ChangeServiceConfig2 from being read as success.
    """
    if os.name != "nt":
        return False
    try:
        import win32service

        scm, svc = _open_own_service(
            win32service.SERVICE_CHANGE_CONFIG | win32service.SERVICE_QUERY_CONFIG
        )
        try:
            try:
                win32service.ChangeServiceConfig2(
                    svc,
                    win32service.SERVICE_CONFIG_FAILURE_ACTIONS,
                    {
                        "ResetPeriod": FAILURE_RESET_SECONDS,
                        "RebootMsg": None,
                        "Command": None,
                        "Actions": [
                            (win32service.SC_ACTION_RESTART, FAILURE_ACTION_DELAY_MS)
                        ]
                        * 3,
                    },
                )
            except Exception as exc:
                # Not fatal: the policy may already be correct from the
                # installer, which the read below is the judge of.
                log.debug("could not write failure actions (%s)", exc)

            current = win32service.QueryServiceConfig2(
                svc, win32service.SERVICE_CONFIG_FAILURE_ACTIONS
            )
            actions = current.get("Actions") or ()
            return any(a[0] == win32service.SC_ACTION_RESTART for a in actions)
        finally:
            win32service.CloseServiceHandle(svc)
            win32service.CloseServiceHandle(scm)
    except Exception as exc:
        log.debug("could not read failure actions (%s)", exc)
        return False


def refresh_restart_support() -> bool:
    """Works out once, at startup, whether restart_agent can be honored."""
    global RESTART_SUPPORTED, RESTART_UNAVAILABLE_REASON

    is_service = _running_as_service_process()
    policy_ok = _ensure_failure_policy() if is_service else False
    RESTART_SUPPORTED = decide_restart_allowed(is_service, policy_ok)

    if RESTART_SUPPORTED:
        RESTART_UNAVAILABLE_REASON = ""
        log.info("restart is available (service restart-on-failure policy confirmed)")
    elif not is_service:
        RESTART_UNAVAILABLE_REASON = (
            "Restart is unavailable: this agent is not running as the Inwire service."
        )
        log.info("restart is unavailable - not running as the %s service", SERVICE_NAME)
    else:
        RESTART_UNAVAILABLE_REASON = (
            "Restart is unavailable: Windows has no restart-on-failure policy for the "
            "Inwire service, so the agent would not come back. Reinstall the agent to fix this."
        )
        log.warning(
            "restart is unavailable - no restart-on-failure policy on %s; refusing to "
            "exit on request because nothing would start the agent again",
            SERVICE_NAME,
        )
    return RESTART_SUPPORTED


def exit_for_restart() -> None:
    """Ends this process so the service manager starts a fresh one.

    os._exit rather than a graceful shutdown: the point is for the SCM to see
    the service process terminate unexpectedly, which is what triggers the
    restart action. Logging is flushed first because after this line there is
    no further record of why the agent went away.
    """
    log.info("restarting now - exiting so the service manager starts a new process")
    logging.shutdown()
    os._exit(RESTART_EXIT_CODE)


def build_hello_message(version: str, state: str, interfaces, client_id: str = "",
                        owner=None, auth_required: bool = False) -> dict:
    """The first message sent on every new connection, before anything else.

    `authRequired` says whether this agent has a pairing token configured. It
    is announced rather than discovered because the alternative is worse: a
    connection refused during the HTTP handshake reaches the browser as an
    opaque WebSocket error, indistinguishable from "the agent is not running".
    Answering the handshake and then asking is what lets the app say which of
    the two it is.

    Nothing else is sent until the token arrives - no interfaces beyond the
    list, no log, no packets - so announcing the requirement gives away only
    that there is one.
    """
    return {
        "type": "hello",
        "version": version,
        "state": state,
        "interfaces": interface_entries(interfaces),
        # This connection's own id, so it can recognise itself in `state`'s
        # `owner` field. Opaque and per-connection: it identifies a tab for the
        # length of one socket, not a user and not a machine.
        "clientId": client_id,
        "owner": owner,
        "authRequired": auth_required,
    }


def interface_entries(interfaces) -> list:
    """The interface list as every message carries it.

    `id` is the position in this list and is what a packet's `iface` field
    refers to (docs/decisions/0005). It is an index rather than the device
    name so a packet costs four bytes of identity, not sixty.
    """
    return [{"id": i, "name": name, "label": label} for i, (name, label) in enumerate(interfaces)]


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
        self.failed_interfaces = set()

    def is_sniffing(self) -> bool:
        return self._sniffing

    def set_interfaces(self, interfaces) -> None:
        self.selected_interfaces = list(interfaces)

    def start_threads(self, spawn_fn) -> None:
        if self._sniffing:
            return
        self.stop_event = threading.Event()
        self.failed_interfaces = set()
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

    def state_message(self, available_interfaces, owner=None) -> dict:
        return {
            "type": "state",
            "state": "sniffing" if self._sniffing else "idle",
            "interfaces": interface_entries(available_interfaces),
            # Which connection asked for this capture, by the id that
            # connection was given in `hello`. A second tab compares it against
            # its own and knows the difference between "capture is running" and
            # "capture is running and I am the one who can stop it". Null when
            # nothing is being captured.
            "owner": owner,
        }

    def mark_failed(self, iface_name) -> bool:
        """Records that a selected interface could not be captured on.

        Returns True when every selected interface has now failed - the case
        where the controller still says "sniffing" but no thread is alive to
        capture anything, which is exactly what the app must not be left
        believing.
        """
        self.failed_interfaces.add(iface_name)
        return all(name in self.failed_interfaces for name in self.selected_interfaces)


def capture_time_us(stamp) -> int:
    """Epoch microseconds for when the frame was actually captured.

    Takes libpcap's per-packet timestamp directly, as `recv_raw` returns it.
    It carries microsecond resolution; an integer count of microseconds carries
    all of it and nothing invented.

    A falsy stamp falls back to the current wall clock, which is the same test
    scapy's own `SuperSocket.recv` applies (`if ts: pkt.time = ts`) - so a
    socket that reports no time gets the clock either way. A frame with no time
    at all would break the browser's relative-time column outright, which is a
    worse outcome than one slightly-late timestamp.
    """
    if not stamp:
        return int(time.time() * 1_000_000)
    # float() of an EDecimal keeps ~7 fractional digits at epoch magnitude,
    # so the microseconds survive; rounding removes the float's last-bit noise.
    return int(round(float(stamp) * 1_000_000))


def packet_to_record(raw, ts, iface_id=0, seq=0, wire_len=None) -> bytes:
    """Encodes one captured frame for the binary batch (packet_batch.py).

    Until 3.2.0 this built a JSON object with source, destination, protocol,
    ports and an info string alongside the base64 bytes. Every one of those
    was thrown away: whenever "raw" was present the browser re-dissected the
    frame itself with the same code path an imported pcap goes through, and
    overwrote all of them. So the agent no longer classifies anything - it
    sends the bytes, the wire length, when the frame was captured, which
    adapter it came from and where it sits in the capture's sequence, and
    nothing else.

    Runs on the sniffer thread, and takes the frame's bytes exactly as the
    driver handed them over. Until 3.5.0 it took a dissected scapy packet and
    called `bytes(pkt)` on it, which re-serialised an object graph scapy had
    just built from those same bytes and which nothing here ever read - about
    80 us a frame, measured over both fixture captures, to arrive back at the
    bytes we started with. (The two were verified byte-identical across all
    27,640 frames of those captures before the dissection was removed, which is
    what made this a pure performance change rather than a wire change.)
    """
    # `wire_len` is what the frame measured ON THE WIRE and `len(raw)` is what
    # was captured of it. They differ only when a snaplen truncated the frame,
    # and this agent sets none - but the two are kept apart rather than
    # collapsed, because the browser shows the wire length in its Length column
    # and a truncated capture that reported the short number would be quietly
    # wrong about every frame it truncated. None means "the caller does not
    # know", which is every path that is not the libpcap fast one.
    return packet_batch.encode_record(
        seq, iface_id, capture_time_us(ts),
        len(raw) if wire_len is None else wire_len, raw,
    )


class CaptureCounters:
    """What the sniffer threads count, for the sequence number and capture_stats.

    One instance per process; reset() on every start_capture so `seq` restarts
    at 0 and the counters describe this capture rather than the process's
    lifetime. Threads increment under one lock - the counts are what the app
    shows as "received", and a lost increment is a lie in the other direction
    from the one this feature exists to expose.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.seq = 0
        self.received = {}
        self.sockets = {}

    def reset(self):
        with self._lock:
            self.seq = 0
            self.received = {}

    def next_seq(self, iface_id) -> int:
        with self._lock:
            n = self.seq
            self.seq += 1
            self.received[iface_id] = self.received.get(iface_id, 0) + 1
            return n

    def register_socket(self, iface_id, sock):
        with self._lock:
            self.sockets[iface_id] = sock

    def unregister_socket(self, iface_id):
        with self._lock:
            self.sockets.pop(iface_id, None)

    def snapshot(self):
        """(seq_high, {iface_id: received}, {iface_id: socket}) at one instant."""
        with self._lock:
            return self.seq, dict(self.received), dict(self.sockets)


counters = CaptureCounters()

# Per-frame timing for the sniffer thread, off unless INWIRE_PROFILE_CAPTURE is
# set. See capture_profile.py for why the number that matters is the one it
# derives rather than the one it measures directly.
profile = capture_profile.CaptureProfile()


def pcap_handle(sock):
    """The raw libpcap handle behind a scapy capture socket, or None.

    scapy keeps its wrapper on `pcap_fd`; releases before 2.5 called it `ins`.
    Looking only at `ins` is why read_pcap_stats silently returned None on
    every capture and the app showed the driver's loss as "unknown" for the
    life of the feature, so both names are tried in one place now rather than
    in each caller.
    """
    wrapper = getattr(sock, "pcap_fd", None) or getattr(sock, "ins", None)
    return getattr(wrapper, "pcap", None)


def set_kernel_buffer(sock, size_bytes=KERNEL_BUFFER_BYTES):
    """Asks the driver to hold `size_bytes` of frames before it starts dropping.

    scapy never does this. `_PcapWrapper_libpcap.__init__` calls pcap_create,
    then set_snaplen/set_promisc/set_timeout, then pcap_activate - and
    `pcap_set_buffer_size` is not among them, so Npcap runs on libpcap's
    Windows default of 1 MB. At a 1,100-byte mean frame that is about 950
    frames: **67 ms of slack** at the rate one sniffer thread sustains, which
    is why measured loss here is bursty and large. One 579 ms gap in a real
    capture cost 302,448 frames.

    `pcap_setbuff`, not `pcap_set_buffer_size`: the latter must be called
    before pcap_activate, which scapy has already done by the time we are
    handed the socket. The former is the WinPcap/Npcap call that resizes the
    buffer of a handle that is already live, which is the only kind we have.

    Returns the size set, or None when the call is unavailable or refused -
    never a lie about having set it. Not fatal either way: a smaller buffer
    drops more frames, it does not stop a capture.
    """
    handle = pcap_handle(sock)
    if not handle:
        return None
    try:
        from scapy.libs.winpcapy import pcap_setbuff
    except Exception:
        # Not built on this platform. Linux's AF_PACKET ring is sized by
        # scapy/libpcap elsewhere and has no equivalent call here.
        return None
    try:
        if pcap_setbuff(handle, size_bytes) != 0:
            return None
    except Exception:
        return None
    return size_bytes


def read_frame(handle, header, data):
    """One captured frame as (bytes, timestamp, wire length), or None.

    **Not `sock.recv_raw()`**, and this is the same class of finding as 3.5.0's.
    That change stopped scapy dissecting every frame into an object graph the
    agent threw away. It left `recv_raw` in place, which calls
    `_PcapWrapper_libpcap.next()`, whose last line is:

        pkt = bytes(bytearray(self.pkt_data[:self.header.contents.len]))

    Slicing a ctypes pointer builds **a Python list with one int object per
    byte** - 1,514 of them for a full-size frame - and then copies that into a
    bytearray and again into a bytes. Measured over a real 300,228-frame
    capture on this machine: **26.67 us a frame against 2.22** for the single
    memcpy `ctypes.string_at` does, a 12x difference that scales with frame
    size. A bulk transfer, where two thirds of frames are over 1,400 bytes, is
    therefore the exact workload it drowns.

    It also fixes a bug in that line. It reads `.len` - the length the frame
    had **on the wire** - where the buffer only holds `.caplen`. The two differ
    the moment a snaplen truncates anything, and the read runs past the end of
    the captured data. Here they are kept apart: `caplen` says how much to
    copy, `len` is reported as the wire length so the browser still knows the
    frame was longer than what it was given.

    Returns None on the read timeout (libpcap opens with to_ms=100), which is
    how a stop is honoured promptly on a silent adapter.
    """
    result = pcap_next_ex(handle, byref(header), byref(data))
    if result != 1:
        return None
    contents = header.contents
    caplen = contents.caplen
    raw = string_at(data, caplen)
    ts = contents.ts.tv_sec + contents.ts.tv_usec / 1e6
    return raw, ts, contents.len


def read_pcap_stats(sock):
    """(received, dropped) as the capture driver counts them, or None.

    scapy's socket wraps a libpcap handle but exposes no statistics call, so
    this reaches past it to pcap_stats() on the raw handle. `dropped` is the
    kernel-buffer drops plus the interface's own, which are the frames the
    agent never saw and therefore the one number nothing downstream can infer.
    None - never zero - when the handle or the call is unavailable, so the app
    shows "unknown" rather than a reassuring 0.
    """
    try:
        from scapy.libs.winpcapy import pcap_stat, pcap_stats
        handle = pcap_handle(sock)
        if not handle:
            return None
        stat = pcap_stat()
        if pcap_stats(handle, byref(stat)) != 0:
            return None
        return int(stat.ps_recv), int(stat.ps_drop) + int(stat.ps_ifdrop)
    except Exception:
        return None


def build_capture_stats(seq_high, received, kernel_stats, dropped_agent) -> dict:
    """One capture_stats message. Pure, so the shape is testable."""
    interfaces = []
    for iface_id in sorted(received):
        kernel = kernel_stats.get(iface_id)
        interfaces.append({
            "iface": iface_id,
            "received": received[iface_id],
            "kernelReceived": None if kernel is None else kernel[0],
            "droppedKernel": None if kernel is None else kernel[1],
        })
    return {
        "type": "capture_stats",
        "intervalMs": int(CAPTURE_STATS_INTERVAL_SECONDS * 1000),
        "seqHigh": seq_high,
        "droppedAgent": dropped_agent,
        "interfaces": interfaces,
    }


class AgentServer:
    def __init__(self):
        # A plain set of sockets. Phase 1 needed a ws -> ConnectionAuth map so
        # packet fan-out could check each connection's pairing state; the
        # origin check now rejects disallowed clients during the handshake, so
        # every connection in this set is by construction an allowed one.
        self.connections = set()
        # Connections that have presented the pairing token, when one is
        # configured. A connection not in here may send `authenticate` and
        # nothing else - no capture, no log, no interface stats - and receives
        # no packets.
        #
        # The origin check alone could never do this job: `Origin` is a header
        # the client writes, so it keeps an ordinary web page out and stops
        # nothing that can set a header, which is any process on the machine.
        # The token lives in a file only an administrator can read.
        self.authenticated = set()
        # An opaque id per connection, told to that connection in `hello` and
        # used in `state` to name whoever owns the capture. Opaque because it
        # is nobody's business but the two ends of that socket: it identifies a
        # tab, not a user or a machine.
        self.client_ids = {}
        # The connection that asked for the capture that is running, or None.
        #
        # Before this, capture was a single global with no owner: two tabs open
        # meant the second one's remembered `set_interfaces` restarted the
        # sniffer on *its* adapter the moment it connected, and Stop in either
        # one stopped both. Which of them was "the" capture was decided by
        # whoever spoke last.
        self.capture_owner = None
        # Sockets that asked for log lines, always a subset of connections.
        # Separate from connections because the common case is a client that
        # never opens Driver Info at all, and log fan-out should cost nothing
        # for those.
        self.log_subscribers = set()
        # Sockets with the interface picker open. Same reasoning as
        # log_subscribers: sampling runs only while somebody is looking, so a
        # client that never opens the picker costs nothing.
        self.interface_stats_subscribers = set()
        self._interface_stats_task = None
        # Sockets that asked which process owns which local endpoint. Same
        # lifecycle rule again: a client that never turns process attribution
        # on never causes the table to be read.
        self.socket_subscribers = set()
        self._socket_task = None
        # One tracker for the fan-out, so the table is read once per tick
        # however many clients are watching. A client that subscribes later
        # gets its own full snapshot on the spot (see subscribe_sockets) and
        # then follows these deltas.
        self._socket_tracker = sockets.SocketTracker()
        # Sockets that asked how this machine's adapters are configured. Same
        # lifecycle rule as every other subscription: a client that never opens
        # the Network panel never causes the registry to be read.
        self.adapter_subscribers = set()
        self._adapter_task = None
        # Narrowed to the capture list rather than reporting all 51 bindings
        # Windows lists - see adapters.read_adapters. Passed as a callable
        # because refresh_interfaces() replaces that list whenever a client
        # connects, and a set captured here would go stale the first time an
        # adapter was unplugged.
        self._adapter_tracker = adapters.AdapterTracker(
            keep=lambda: {name for name, _label in AVAILABLE_INTERFACES})
        self.loop = None
        # Frames the agent itself dropped this process, because the queue was
        # full (see queue_packet). Reported per capture in capture_stats.
        self._dropped_sends = 0
        self._capture_stats_task = None
        # Encoded packet records waiting for the pump (see queue_packet). The
        # sniffer threads append and the loop drains, so both are under one
        # lock; `_packet_queue_bytes` tracks the byte bound without walking the
        # deque on every append.
        self._packet_queue = collections.deque()
        self._packet_queue_bytes = 0
        self._packet_lock = threading.Lock()
        self._packet_pump_task = None
        # _dropped_sends at the moment the current capture started, so the
        # number the app shows is this capture's, not the process's lifetime.
        self._dropped_at_capture_start = 0

    async def register(self, ws):
        self.connections.add(ws)
        self.client_ids[ws] = make_id()
        log.info("client connected (%d total)", len(self.connections))
        try:
            # The hello send is inside the try because a client dropping
            # mid-handshake would otherwise leak the connection and permanently
            # disable auto-stop: handle_disconnect only stops capture when
            # not self.connections, so any stuck entry means the condition
            # can never be true again. Every exit path must reach finally.
            state = "sniffing" if sniffer.is_sniffing() else "idle"
            # Re-read per connection, like the origin list: setting a token
            # should not need a service restart on a machine with no console.
            settings = config.load_config(on_warning=lambda msg: log.warning("config: %s", msg))
            expected_token = settings.get("token")
            # A connection the OPERATING SYSTEM vouched for needs no token of
            # ours. The pipe's descriptor already decided who may open it, and
            # a token is only worth anything where anyone could connect and
            # claim to be the app - which is what a loopback TCP port is and a
            # pipe is not. So the pairing question is not merely answered for a
            # pipe client, it is never asked: `hello` says `authRequired:
            # false` and there is nothing to paste.
            if getattr(ws, "kernel_authenticated", False):
                expected_token = None
            if expected_token is None:
                self.authenticated.add(ws)
            # Re-read the adapters here rather than trusting the list built at
            # startup: this message is what the app builds its interface picker
            # from, so a client connecting is exactly the moment the answer has
            # to be current. See refresh_interfaces().
            interfaces = refresh_interfaces()
            await ws.send(json.dumps(build_hello_message(
                AGENT_VERSION, state, interfaces,
                client_id=self.client_ids.get(ws, ""),
                owner=self.owner_id(),
                auth_required=expected_token is not None,
            )))
            async for raw in ws:
                await self._handle_message(ws, raw)
        finally:
            self.handle_disconnect(ws)

    def handle_disconnect(self, ws):
        """Capture is scoped to live connections: with nobody watching,
        nothing should be captured. Closing the last Inwire tab therefore
        stops the sniffer (see spec: Capture lifecycle).

        Sniffing deliberately does not resume when a client reconnects - a
        fresh connection arrives idle and must send start_capture again.
        Inferring intent across a disconnect would mean capturing traffic
        nobody explicitly asked for, which is the whole property that makes
        an always-running background capture agent acceptable.
        """
        self.connections.discard(ws)
        self.client_ids.pop(ws, None)
        self.authenticated.discard(ws)
        # A socket left here after its connection died would make the log
        # fan-out write to a dead socket on every line, forever.
        self.log_subscribers.discard(ws)
        # Same for the stats fan-out - and dropping it here is what lets the
        # sampling loop wind down when the last picker goes away with its tab.
        self.interface_stats_subscribers.discard(ws)
        self._stop_interface_stats_task_if_idle()
        self.socket_subscribers.discard(ws)
        self._stop_socket_task_if_idle()
        self.adapter_subscribers.discard(ws)
        self._stop_adapter_task_if_idle()
        log.info("client disconnected (%d remaining)", len(self.connections))

        # The owner leaving stops the capture even when other tabs are still
        # connected. Those tabs never asked for it - packets were not going to
        # them - and inheriting a capture nobody present requested is the
        # always-on background capture this agent is designed not to do.
        if ws is self.capture_owner:
            self.capture_owner = None
            if sniffer.is_sniffing():
                log.info("the client that started this capture disconnected - stopping")
                self.stop_capture()
            self.broadcast_state()
        elif not self.connections and sniffer.is_sniffing():
            log.info("last client disconnected - stopping capture")
            # stop_capture(), not sniffer.stop_threads(): the latter leaves the
            # packet pump, the capture-stats ticker and everything still queued
            # behind. Reachable whenever capture_owner was already cleared -
            # _send_to_owner nulls it when the owner's socket dies, without
            # stopping the sniffer.
            self.stop_capture()

    async def _handle_message(self, ws, raw):
        try:
            message = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return
        if not isinstance(message, dict):
            return

        msg_type = message.get("type")

        if msg_type == "authenticate":
            settings = config.load_config()
            expected = settings.get("token")
            if expected is None or config.tokens_match(message.get("token"), expected):
                self.authenticated.add(ws)
                log.info("client authenticated")
                await ws.send(json.dumps(sniffer.state_message(AVAILABLE_INTERFACES, self.owner_id())))
            else:
                # Logged without the offered value: a wrong token in a log file
                # that clients can subscribe to would be a second place the
                # right one could leak from.
                log.warning("a client offered a token that did not match")
                await ws.send(json.dumps({
                    "type": "error",
                    "code": "auth_failed",
                    "message": "That pairing token does not match this agent's.",
                }))
            return

        if ws not in self.authenticated:
            await ws.send(json.dumps({
                "type": "error",
                "code": "auth_required",
                "message": "This agent needs its pairing token before it will do anything.",
            }))
            return

        if msg_type in ("start_capture", "stop_capture", "set_interfaces") and self.owned_by_other(ws):
            await ws.send(json.dumps({
                "type": "error",
                "code": "capture_busy",
                "message": "Another Inwire window started this capture. Stop it there, or close that window.",
            }))
            return

        if msg_type == "start_capture":
            log.info("start_capture requested on %d interface(s)", len(sniffer.selected_interfaces))
            self.capture_owner = ws
            self.start_capture()
        elif msg_type == "stop_capture":
            log.info("stop_capture requested")
            self.capture_owner = None
            self.stop_capture()
        elif msg_type == "set_interfaces":
            interfaces = message.get("interfaces")
            if not (isinstance(interfaces, list) and all(isinstance(i, str) for i in interfaces)):
                # Used to be ignored in silence, which read as "the agent is
                # not listening" from the other end.
                await ws.send(json.dumps({
                    "type": "error",
                    "code": "invalid_interfaces",
                    "message": "set_interfaces needs a list of interface names.",
                }))
                return
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
            if sniffer.is_sniffing():
                self.stop_capture()
                self.start_capture()
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
        elif msg_type == "subscribe_interface_stats":
            self.interface_stats_subscribers.add(ws)
            self._ensure_interface_stats_task()
            return
        elif msg_type == "unsubscribe_interface_stats":
            self.interface_stats_subscribers.discard(ws)
            self._stop_interface_stats_task_if_idle()
            return
        elif msg_type == "subscribe_sockets":
            self.socket_subscribers.add(ws)
            # This client's own full snapshot, now, rather than waiting for the
            # shared ticker - which sends deltas, and a delta against a table
            # this client never received would leave it permanently short of
            # every socket that existed before it subscribed. The same reason
            # subscribe_logs hands over a backlog.
            #
            # Re-sending an add the next delta also carries, or a remove for a
            # socket this snapshot never listed, are both harmless: the app
            # applies each message idempotently.
            # Off the event loop: this is psutil.net_connections() plus a
            # describe_process() per pid - ~6.5 ms measured, and more on a
            # machine holding many sockets. _socket_loop wraps the identical
            # call for the same reason; doing it inline here stalled packet
            # delivery for every subscriber.
            snapshot = await asyncio.to_thread(lambda: sockets.SocketTracker().poll())
            await ws.send(json.dumps(snapshot))
            self._ensure_socket_task()
            # Subscribing changes nothing about what the agent is DOING, so it
            # takes the same early return every other subscription takes rather
            # than falling through to the state broadcast at the foot of this
            # method.
            return
        elif msg_type == "unsubscribe_sockets":
            self.socket_subscribers.discard(ws)
            self._stop_socket_task_if_idle()
            return
        elif msg_type == "subscribe_adapters":
            self.adapter_subscribers.add(ws)
            # This client's own snapshot immediately, for the same reason
            # subscribe_sockets sends one: the shared ticker only speaks when
            # something changed, and adapter configuration changes on the
            # timescale of a lease. A client that waited for the next change
            # could sit in front of an empty panel for an hour.
            #
            # Off the event loop because the first read on Windows spawns
            # PowerShell - about half a second, measured - and doing that
            # inline would stall packet delivery for every other client.
            snapshot = await asyncio.to_thread(
                lambda: adapters.AdapterTracker(
                    keep=lambda: {n for n, _l in AVAILABLE_INTERFACES}).poll())
            await ws.send(json.dumps(snapshot))
            self._ensure_adapter_task()
            return
        elif msg_type == "unsubscribe_adapters":
            self.adapter_subscribers.discard(ws)
            self._stop_adapter_task_if_idle()
            return
        elif msg_type == "refresh_adapters":
            # The user pressed Refresh, which is a statement that they have
            # just changed something. Answering from a cached reading taken
            # before they changed it is the one answer that is certainly wrong,
            # so the caches are dropped and the tracker is made to speak even
            # if the result is identical.
            self.adapter_subscribers.add(ws)
            def _reread():
                adapters.invalidate_caches()
                self._adapter_tracker.reset()
                return self._adapter_tracker.poll()
            snapshot = await asyncio.to_thread(_reread)
            await ws.send(json.dumps(snapshot))
            self._ensure_adapter_task()
            return
        elif msg_type == "restart_agent":
            if not RESTART_SUPPORTED:
                # Refusing is the whole safety property: this command is
                # implemented by exiting, and where nothing would start the
                # agent again that is a stop the user cannot undo from the app.
                log.warning("restart_agent refused - %s", RESTART_UNAVAILABLE_REASON)
                await ws.send(json.dumps({
                    "type": "error",
                    "code": "restart_unavailable",
                    "message": RESTART_UNAVAILABLE_REASON,
                }))
                return
            log.info("restart_agent requested by a client")
            # Deferred by a moment rather than exiting inline so this handler
            # can return, the log line reaches any subscriber, and the socket
            # closes as a normal drop instead of mid-message.
            asyncio.get_running_loop().call_later(0.5, exit_for_restart)
            return
        else:
            # Named rather than dropped: a newer app talking to an older agent
            # gets told, instead of waiting for an answer that never comes.
            await ws.send(json.dumps({
                "type": "error",
                "code": "unknown_command",
                "message": f"This agent ({AGENT_VERSION}) does not understand '{msg_type}'.",
            }))
            return
        # Every command that changes what the agent is doing is answered with
        # the resulting state, to every client. This is how a reconnecting
        # tab, a second tab, and Driver Info's "Capture:" row stay truthful;
        # it went missing in a refactor once and nothing noticed for weeks,
        # which is why test_protocol.py now asserts it per command.
        self.broadcast_state()

    def owner_id(self):
        """The owning connection's id, or None when nothing is being captured."""
        if self.capture_owner is None:
            return None
        return self.client_ids.get(self.capture_owner)

    def owned_by_other(self, ws) -> bool:
        """True when someone else's capture is running.

        Ownership only bites while a capture is actually running: an owner that
        stopped, or one whose socket died between the check and here, holds
        nothing. That is deliberate - a stale owner would lock the agent out of
        capturing at all, which is a worse failure than two tabs racing.
        """
        if self.capture_owner is None or self.capture_owner is ws:
            return False
        if self.capture_owner not in self.connections:
            self.capture_owner = None
            return False
        return sniffer is not None and sniffer.is_sniffing()

    async def _send_to_owner(self, data):
        """Packets and their statistics go to the connection that asked for
        them and to no one else. A tab that never pressed Start should not
        quietly accumulate somebody else's traffic."""
        ws = self.capture_owner
        if ws is None or ws not in self.connections or ws not in self.authenticated:
            return
        try:
            await ws.send(data)
        except Exception:
            self.connections.discard(ws)
            self.log_subscribers.discard(ws)
            self.capture_owner = None

    def start_capture(self):
        """Starts the sniffer threads and the capture_stats ticker together."""
        counters.reset()
        profile.reset()
        self._dropped_at_capture_start = self._dropped_sends
        sniffer.start_threads(spawn_sniffer_thread)
        if self.loop is not None and (self._capture_stats_task is None or self._capture_stats_task.done()):
            self._capture_stats_task = asyncio.create_task(self._capture_stats_loop())
        if self.loop is not None and (self._packet_pump_task is None or self._packet_pump_task.done()):
            self._packet_pump_task = asyncio.create_task(self._packet_pump())

    def stop_capture(self):
        sniffer.stop_threads()
        if self._capture_stats_task is not None:
            self._capture_stats_task.cancel()
            self._capture_stats_task = None
        if self._packet_pump_task is not None:
            self._packet_pump_task.cancel()
            self._packet_pump_task = None
        # The sniffer threads are stopped, so nothing more will be appended;
        # what is still queued belongs to a capture nobody is watching.
        self.discard_queued_packets()

    def broadcast_state(self):
        self.send_control(sniffer.state_message(AVAILABLE_INTERFACES, self.owner_id()))

    def send_control(self, message: dict):
        """Sends a control message to every client, from any thread.

        Not subject to the packet backpressure bound: control messages are
        rare and are the thing a client needs most when packets are being
        dropped.
        """
        if not self.connections or self.loop is None:
            return
        asyncio.run_coroutine_threadsafe(self._send_to_all(json.dumps(message)), self.loop)

    async def _send_to_all(self, data: str):
        """Broadcasts to every connection, dropping the ones that have died.

        The failure used to be swallowed whole - `except Exception: pass` - so
        a socket that had gone away stayed in `self.connections` for ever and
        every later broadcast tried it again and failed again, silently. A
        client that stopped receiving state updates left no trace anywhere,
        which is the one thing the log exists to prevent.
        """
        dead = []
        for ws in list(self.connections):
            try:
                await ws.send(data)
            except Exception as exc:
                dead.append((ws, exc))
        for ws, exc in dead:
            # Discard, not remove: the close handler may have got there first,
            # and that is the normal way a connection leaves.
            self.connections.discard(ws)
            log.debug("dropping a connection that could not be written to: %s", exc)

    def report_capture_failure(self, iface_id, iface_name, iface_label, reason):
        """A sniffer thread could not open or read its adapter.

        Before this the warning went to the log alone and the app sat on
        "capturing" with an empty list for as long as anyone cared to watch.
        """
        self.send_control({
            "type": "error",
            "code": "capture_failed",
            "iface": iface_id,
            "message": f"Could not capture on {iface_label}: {reason}",
        })
        if sniffer.mark_failed(iface_name):
            log.warning("every selected interface failed - capture stopped")
            # Back onto the event loop first. This runs on a sniffer THREAD,
            # and stop_capture() calls Task.cancel(), which is not thread
            # safe - the same reason send_control hops via
            # run_coroutine_threadsafe rather than awaiting here.
            if self.loop is not None:
                self.loop.call_soon_threadsafe(self._stop_capture_and_broadcast)
            else:
                self._stop_capture_and_broadcast()

    def _stop_capture_and_broadcast(self):
        """stop_capture + broadcast_state, as one thing to hand to the loop."""
        self.stop_capture()
        self.broadcast_state()

    async def _capture_stats_loop(self):
        try:
            while sniffer is not None and sniffer.is_sniffing():
                seq_high, received, sockets = counters.snapshot()
                kernel = {iface_id: read_pcap_stats(sock) for iface_id, sock in sockets.items()}
                dropped_agent = self._dropped_sends - self._dropped_at_capture_start
                await self._send_to_owner(json.dumps(
                    build_capture_stats(seq_high, received, kernel, dropped_agent)
                ))
                await asyncio.sleep(CAPTURE_STATS_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("capture stats stopped: %s", exc)
        finally:
            # Only if this reference is still to THIS task. `set_interfaces`
            # while sniffing cancels and recreates in the same breath, so by
            # the time a cancelled task unwinds, the attribute may already
            # hold its replacement - and clearing it there would strand the
            # replacement, uncancellable, for the life of the process.
            if self._capture_stats_task is asyncio.current_task():
                self._capture_stats_task = None

    def _ensure_interface_stats_task(self):
        if self._interface_stats_task is None or self._interface_stats_task.done():
            self._interface_stats_task = asyncio.create_task(self._interface_stats_loop())

    def _stop_interface_stats_task_if_idle(self):
        """Sampling exists to feed an open picker; with none open it stops.

        Cancelled rather than left spinning on an empty subscriber set, so a
        closed menu leaves nothing running - the same lifecycle rule capture
        itself follows.
        """
        if not self.interface_stats_subscribers and self._interface_stats_task is not None:
            self._interface_stats_task.cancel()
            self._interface_stats_task = None

    def _ensure_socket_task(self):
        if self._socket_task is None or self._socket_task.done():
            self._socket_task = asyncio.create_task(self._socket_loop())

    def _stop_socket_task_if_idle(self):
        if not self.socket_subscribers and self._socket_task is not None:
            self._socket_task.cancel()
            self._socket_task = None
            # The next subscriber gets a full snapshot of its own anyway, but
            # the shared tracker must not carry a table read minutes ago into
            # the first delta after it - every socket that came and went in
            # between would arrive as one impossible burst.
            self._socket_tracker.reset()

    async def _socket_loop(self):
        """Pushes socket-table deltas to whoever asked for them.

        Reading the table is blocking work - a few milliseconds of it - so it
        runs in a thread rather than on the event loop, where it would stall
        packet delivery for as long as it took.
        """
        try:
            while self.socket_subscribers:
                await asyncio.sleep(SOCKET_TABLE_INTERVAL_SECONDS)
                delta = await asyncio.to_thread(self._socket_tracker.poll)
                # None means nothing opened or closed this second, which on an
                # idle machine is most seconds.
                if delta is None:
                    continue
                message = json.dumps(delta)
                for ws in list(self.socket_subscribers):
                    try:
                        await ws.send(message)
                    except Exception:
                        self.socket_subscribers.discard(ws)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Never take a capture down over attribution. The packet list is
            # the product; a missing process name is a missing annotation.
            log.warning("socket table polling stopped: %s", exc)
        finally:
            self._socket_task = None

    def _ensure_adapter_task(self):
        if self._adapter_task is None or self._adapter_task.done():
            self._adapter_task = asyncio.create_task(self._adapter_loop())

    def _stop_adapter_task_if_idle(self):
        if not self.adapter_subscribers and self._adapter_task is not None:
            self._adapter_task.cancel()
            self._adapter_task = None
            # The next subscriber is sent a snapshot of its own, but the shared
            # tracker must not hold a reading from before the gap: it would
            # compare the next poll against a configuration that may be hours
            # old and stay silent about everything that changed in between.
            self._adapter_tracker.reset()

    async def _adapter_loop(self):
        """Pushes adapter configuration to whoever asked for it.

        Reading it is blocking work - the registry on Windows, `ip` and
        `resolvectl` on Linux - so it runs in a thread rather than on the event
        loop, where it would stall packet delivery for as long as it took.
        """
        try:
            while self.adapter_subscribers:
                await asyncio.sleep(ADAPTER_CONFIG_INTERVAL_SECONDS)
                message = await asyncio.to_thread(self._adapter_tracker.poll)
                # None means nothing about any adapter changed, which is almost
                # every poll: this is configuration, not traffic.
                if message is None:
                    continue
                encoded = json.dumps(message)
                for ws in list(self.adapter_subscribers):
                    try:
                        await ws.send(encoded)
                    except Exception:
                        self.adapter_subscribers.discard(ws)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Never take a capture down over configuration. Same rule as the
            # socket loop: the packet list is the product, and this is an
            # annotation on it.
            log.warning("adapter configuration polling stopped: %s", exc)
        finally:
            self._adapter_task = None

    async def _interface_stats_loop(self):
        # Constructed per subscription rather than kept alive: its first sample
        # is always zero (it has no previous reading to difference against), so
        # a stale sampler would report one bogus spike covering however long
        # the menu was closed.
        sampler = interface_stats.InterfaceRateSampler(AVAILABLE_INTERFACES)
        try:
            while self.interface_stats_subscribers:
                # A monotonic clock, so a system time change mid-capture cannot
                # produce a negative interval and a nonsense rate.
                rates = sampler.sample(time.monotonic())
                message = json.dumps({
                    "type": "interface_stats",
                    "intervalMs": int(INTERFACE_STATS_INTERVAL_SECONDS * 1000),
                    "interfaces": rates,
                })
                for ws in list(self.interface_stats_subscribers):
                    try:
                        await ws.send(message)
                    except Exception:
                        self.interface_stats_subscribers.discard(ws)
                await asyncio.sleep(INTERFACE_STATS_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # Never take the connection down over a sparkline: the picker still
            # works without it, and the counters are the least important thing
            # the agent reports.
            log.warning("interface stats sampling stopped: %s", exc)
        finally:
            self._interface_stats_task = None

    def queue_packet(self, record: bytes):
        """Queues one encoded packet record (packet_batch.encode_record).

        Called from the sniffer threads. Nothing is sent here and no coroutine
        is scheduled: the record joins a deque that one pump task drains into
        batched binary frames. Before 3.2.0 this scheduled a coroutine and a
        JSON string per captured frame, and the bound that kept that from
        growing without limit is what the agent's log records as ">=260,000
        packets dropped: the client is not keeping up". Most of that was the
        loop failing to keep up with its own scheduling.

        When the queue is full the OLDEST records go, not this one. This is a
        live view of traffic, not a recording: a viewer that has fallen behind
        wants the newest frames rather than a backlog of stale ones it will
        never catch up on. Every drop is counted and reaches the app in
        capture_stats within the second.
        """
        if self.capture_owner is None or self.loop is None:
            return
        dropped = None
        with self._packet_lock:
            self._packet_queue.append(record)
            self._packet_queue_bytes += len(record)
            while (len(self._packet_queue) > MAX_QUEUED_PACKETS
                   or self._packet_queue_bytes > MAX_QUEUED_BYTES):
                self._packet_queue_bytes -= len(self._packet_queue.popleft())
                self._dropped_sends += 1
                dropped = self._dropped_sends
        if dropped is not None and (dropped in (1, 100, 1000) or dropped % 10000 == 0):
            # Logged sparsely and only on crossings of a power-of-ten-ish
            # boundary: the drop path is the hot path when it is running at
            # all, and logging per drop would recreate the flood one level up
            # (log records also fan out to subscribed clients). The full count
            # reaches the app every second in capture_stats regardless.
            log.warning(
                "dropped %d packet(s): the client is not keeping up with this interface",
                dropped,
            )

    def _drain_packets(self):
        """Takes up to one batch off the queue. Runs on the loop, under the
        same lock the sniffer threads append with, and holds it only for the
        pops - the send happens outside it."""
        batch = []
        size = 0
        with self._packet_lock:
            while self._packet_queue and len(batch) < MAX_BATCH_RECORDS and size < MAX_BATCH_BYTES:
                record = self._packet_queue.popleft()
                self._packet_queue_bytes -= len(record)
                batch.append(record)
                size += len(record)
        return batch

    async def _packet_pump(self):
        """Drains the packet queue into batched binary frames.

        One task for the whole process, started with capture and cancelled
        with it. It keeps draining while there is anything queued rather than
        sleeping between batches, so a burst is cleared as fast as the socket
        will take it; the sleep is only for the idle case.
        """
        try:
            while True:
                batch = self._drain_packets()
                if not batch:
                    await asyncio.sleep(PACKET_BATCH_INTERVAL_SECONDS)
                    continue
                payload = packet_batch.encode_batch(batch)
                await self._send_to_owner(payload)
                if len(batch) < MAX_BATCH_RECORDS:
                    await asyncio.sleep(PACKET_BATCH_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A pump that died silently would look exactly like an idle
            # network, which is the worst way for this to fail.
            log.error("packet pump stopped: %s", exc)
        finally:
            # See _capture_stats_loop: only clear a reference to this task.
            # The stats loop self-heals because it re-tests is_sniffing(); the
            # pump is `while True`, so a stranded one runs for ever, draining
            # the same queue as its replacement and interleaving batches on
            # the owner's socket.
            if self._packet_pump_task is asyncio.current_task():
                self._packet_pump_task = None

    def discard_queued_packets(self):
        """Empties the queue without counting the drops - for a stop, where
        the frames were captured but nobody is waiting for them any more."""
        with self._packet_lock:
            self._packet_queue.clear()
            self._packet_queue_bytes = 0

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
            except CLIENT_GONE:
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


def sniff_callback(raw, ts, iface_id=0, wire_len=None):
    global _captured_count
    # Wall time for this frame's own callback. The expensive half - the driver
    # read and scapy's dissection - already happened before we were called, so
    # capture_profile derives it from the gap between frames instead.
    profile_start = time.perf_counter() if profile.enabled else 0.0
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

    seq = counters.next_seq(iface_id)
    try:
        record = packet_to_record(raw, ts, iface_id, seq, wire_len)
    except Exception as exc:
        log.warning("failed to process a captured packet: %s", exc)
        return
    agent.queue_packet(record)
    if profile.enabled:
        profile.frame(time.perf_counter() - profile_start)
        if _captured_count % 10000 == 0:
            log.info("%s", profile.describe())


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
    The reference analyzer's interface list comes from. `get_windows_if_list()` is
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

    # scapy builds conf.ifaces once, when it initialises, and it is a plain
    # dict from then on - iterating it hands back that original snapshot no
    # matter how much later you ask. Without this reload the agent would keep
    # re-reading a cache from process start, and re-enumerating on connect
    # would look correct while changing nothing. reload() clears the table and
    # re-runs pcap_findalldevs, which is the actual query.
    try:
        scapy_conf.ifaces.reload()
    except Exception as exc:
        log.warning("could not reload the interface table (%s); using the cached one", exc)

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


def refresh_interfaces():
    """Re-reads the adapter list into AVAILABLE_INTERFACES, and returns it.

    The list used to be built once in main() and replayed in every hello and
    state message for the life of the process, which was wrong in two ways that
    both showed up in the field:

      - Windows creates and destroys adapters constantly - WAN Miniports and
        Wi-Fi Direct virtual adapters appear and vanish on their own - so an
        agent that happened to start at a quiet moment reported a short list
        forever. An adapter plugged in afterwards could never be captured on,
        with nothing in the UI to suggest why.

      - As an auto-start service the agent can win the race against Npcap's
        driver binding at boot and enumerate nothing at all.

    Calling this whenever a client connects means opening the app is enough to
    get an accurate list, without a poll loop or any protocol change.

    A failed enumeration keeps the previous list. The alternative - emptying it
    because one call threw while a driver was reloading - would take the picker
    away from a client that is using it, which is worse than being briefly out
    of date.
    """
    global AVAILABLE_INTERFACES, INTERFACE_LABELS, INTERFACE_IDS

    try:
        interfaces = list_interfaces()
    except Exception as exc:
        log.warning(
            "could not re-enumerate network interfaces (%s); keeping the previous list", exc
        )
        return AVAILABLE_INTERFACES

    if interfaces == AVAILABLE_INTERFACES:
        return AVAILABLE_INTERFACES

    previous = dict(AVAILABLE_INTERFACES)
    AVAILABLE_INTERFACES = interfaces
    INTERFACE_LABELS = dict(interfaces)
    INTERFACE_IDS = {name: i for i, (name, _) in enumerate(interfaces)}

    log.info("detected %d network interface(s)", len(interfaces))
    for name, label in interfaces:
        if name not in previous:
            log.info("  interface available: %s -> %s", label, name)
    for name, label in previous.items():
        if name not in INTERFACE_LABELS:
            log.info("  interface gone: %s -> %s", label, name)

    return AVAILABLE_INTERFACES


def sniff_on_interface(iface_name, iface_label, stop_event, iface_id=0):
    # The capture socket is opened here rather than left to sniff(iface=...)
    # for two reasons: an adapter that cannot be opened fails HERE, once, with
    # a message the app gets to see; and holding the socket is what lets the
    # stats loop ask the driver how many frames it dropped (read_pcap_stats).
    try:
        sock = scapy_conf.L2listen(type=ETH_P_ALL, iface=iface_name)
    except Exception as exc:  # e.g. an adapter that's disabled/down, or Npcap missing on Windows
        log.warning("capture failed on interface %r (%s): %s", iface_label, iface_name, exc)
        agent.report_capture_failure(iface_id, iface_name, iface_label, str(exc))
        return
    counters.register_socket(iface_id, sock)
    buffered = set_kernel_buffer(sock)
    log.info("%s: capture buffer %s", iface_label,
             f"{buffered // (1024 * 1024)} MB" if buffered else "driver default (could not be set)")
    try:
        # No BPF filter: capture every frame on the wire, the way the reference
        # analyzer does by default. This used to be "ip or ip6", which silently
        # discarded ARP, STP and every other non-IP protocol before they could
        # reach the browser - the frontend dissects all of them.
        #
        # `recv_raw`, not `sniff(prn=...)`. sniff() calls SuperSocket.recv,
        # which is `cls, val, ts = self.recv_raw(x)` followed by `cls(val)` -
        # so every frame was dissected into an Ether/IP/TCP object graph that
        # this agent then threw away, because packet_to_record reads only the
        # bytes, the length and the timestamp. recv_raw is the same call
        # without the half we discard.
        #
        # It is the complete primitive on both platforms that matter, not a
        # shortcut past something: the libpcap socket's recv_raw returns
        # libpcap's own per-packet timestamp, and Linux's L2Socket.recv_raw
        # applies the PACKET_OUTGOING rule and fills the timestamp in itself.
        # A socket that has NOT overridden it inherits SuperSocket's base,
        # which reports no timestamp at all - so that case keeps sniff(),
        # rather than silently trading capture times for throughput.
        handle = pcap_handle(sock)
        if handle:
            # The fast path, and the one almost every capture takes. Straight
            # to pcap_next_ex, because scapy's own wrapper around it costs 12x
            # what the call does - see read_frame for the measurement.
            #
            # The handle is opened with to_ms=100, so the read returns on its
            # own timeout and a stop is honoured within 100 ms even on a silent
            # adapter. Header and data pointers are allocated ONCE and reused:
            # libpcap writes into its own buffer and hands back a pointer to
            # it, so allocating a pair per frame would add two ctypes objects
            # per frame to the path this exists to shorten.
            header = POINTER(pcap_pkthdr)()
            data = POINTER(c_ubyte)()
            while not stop_event.is_set():
                frame = read_frame(handle, header, data)
                if frame is None:
                    continue
                raw, ts, wire_len = frame
                sniff_callback(raw, ts, iface_id, wire_len)
        elif type(sock).recv_raw is SuperSocket.recv_raw:
            log.info("%s: no raw receive on this socket type - using sniff()", iface_label)
            while not stop_event.is_set():
                sniff(opened_socket=sock, prn=lambda pkt: sniff_callback(bytes(pkt), pkt.time, iface_id),
                      store=False, timeout=CAPTURE_POLL_SECONDS)
        else:
            # Linux's AF_PACKET socket, which has no libpcap handle. Its
            # recv_raw is a plain recvfrom returning bytes, so it carries none
            # of the per-byte cost the libpcap wrapper does and is left alone.
            # It blocks indefinitely, so it is polled with select().
            while not stop_event.is_set():
                if not sock.select([sock], CAPTURE_POLL_SECONDS):
                    continue
                _cls, raw, ts = sock.recv_raw()
                # None is the read timeout expiring, not an error: loop round
                # and re-test stop_event.
                if raw is None:
                    continue
                sniff_callback(raw, ts, iface_id)
    except Exception as exc:
        log.warning("capture failed on interface %r (%s): %s", iface_label, iface_name, exc)
        agent.report_capture_failure(iface_id, iface_name, iface_label, str(exc))
    finally:
        counters.unregister_socket(iface_id)
        try:
            sock.close()
        except Exception:
            pass


def spawn_sniffer_thread(iface_name, stop_event):
    label = INTERFACE_LABELS.get(iface_name, iface_name)
    iface_id = INTERFACE_IDS.get(iface_name, 0)
    t = threading.Thread(target=sniff_on_interface, args=(iface_name, label, stop_event, iface_id), daemon=True)
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
    # The interface globals are owned by refresh_interfaces() now, and only
    # read here, so they are deliberately not declared global.
    global sniffer, log

    log = logging_setup.setup_logging(config.config_dir(), to_stderr=to_stderr)
    # Must come after setup_logging, which tears down existing handlers when
    # reconfigured - installing before it would silently remove this one.
    log.addHandler(agent_log.WebSocketLogHandler(agent.broadcast_log))
    log.info("Inwire agent %s starting", AGENT_VERSION)

    # After logging is up, so the one interesting failure has somewhere to go.
    # Only the config moves: agent.log is a rotating log, not user data, and an
    # old one left behind in the previous directory is harmless history.
    if config.migrate_legacy_config(on_warning=log.warning):
        log.info("carried config.json over from the previous install directory")

    if not has_admin_privileges():
        hint = (
            "Right-click and choose 'Run as administrator'."
            if os.name == "nt"
            else "Re-run with sudo, e.g.: sudo python3 agent.py"
        )
        log.error("packet capture requires elevated privileges. %s", hint)
        return False

    # Resolved once, here, rather than per request: it queries the SCM, and the
    # answer cannot change while this process runs - a process either is the
    # service or is not. Also writes the restart-on-failure policy, so an agent
    # installed before that policy existed heals itself on its next start.
    refresh_restart_support()

    refresh_interfaces()
    if not AVAILABLE_INTERFACES:
        # Deliberately not fatal any more. As an auto-start service the agent
        # can beat Npcap's driver binding at boot and enumerate nothing, and
        # refusing to start turned a few seconds of bad timing into an agent
        # that stayed down until someone restarted it by hand - which is
        # exactly what happened here on 2026-08-29 09:26. The list is re-read
        # whenever a client connects, so an agent that starts empty heals
        # itself as soon as the app is opened.
        log.warning(
            "no capturable network interfaces found at startup - starting anyway. "
            "If this persists, Npcap may not be installed: https://npcap.com/#download"
        )

    # Starts idle on purpose - sniffing now only begins when a paired client
    # sends start_capture, not automatically at process launch.
    sniffer = SnifferController(default_interfaces=[name for name, _ in AVAILABLE_INTERFACES])

    agent.loop = asyncio.get_running_loop()

    def log_rejection(origin):
        log.warning("rejected connection from disallowed origin: %r", origin)

    # One transport, and which one is decided by the platform.
    #
    # On Windows the app connects over a named pipe: the kernel decides who may
    # open it, so there is no token to paste and no origin to check, and the
    # loopback port is not opened AT ALL. Leaving it listening beside the pipe
    # would keep the whole attack surface the pipe exists to remove - a port
    # every process on the machine can reach, defended by a bearer token any
    # process running as that user could read.
    #
    # Elsewhere the WebSocket stays, and the pairing token with it. Those
    # platforms install from the tarball and have no bundled app yet; see
    # `pipe_server.start` for why a socket file is not simply the same thing
    # with a different name.
    pipes = pipe_server.PipeServer(agent.loop, agent.register)
    pipes.start()

    if pipes.serving:
        try:
            asyncio.create_task(watch_for_orphaned_capture())
            await asyncio.Future()  # run forever
        finally:
            pipes.stop()
        return True

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
    if "--version" in sys.argv[1:]:
        print(AGENT_VERSION)
        sys.exit(0)
    try:
        _ok = asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[agent] shutting down.")
    else:
        if _ok is False:
            sys.exit(1)
