#!/usr/bin/env python3
"""
Inwire Agent

Captures raw frames off the wire and hands them to the Inwire desktop app,
which does all the dissecting. A record carries the bytes, the driver's
timestamp, a per-capture sequence number and the interface index - no source,
destination, protocol, ports or info, because the app always overwrote those
(docs/decisions/0010). Frames travel in batches in the binary format
``packet_batch.py`` defines; control messages are JSON.

The transport depends on the platform, and this is the part worth reading
before anything else here:

  Windows            a named pipe, ``\\\\.\\pipe\\inwire-agent``, whose
                     security descriptor is what decides who may connect
                     (``pipe_server.py``; docs/decisions/0029). The loopback
                     port is not opened AT ALL - see ``main()``.
  macOS / Linux      a WebSocket on localhost, with the pairing token and the
                     origin allowlist that a reachable-by-anything port needs.
                     Installed from the tarball; there is no desktop app yet.

Nothing leaves the machine either way.

This docstring used to say the agent "streams live packet metadata as JSON to
any connected browser tab" over ``ws://localhost:8999``. All three halves of
that went: JSON metadata in 3.2.0, the browser in the Electron migration, and
the port on Windows in 3.8.0.

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
import re
import sys
import threading
import time
from http import HTTPStatus

import config
import npcap_access
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

# The agent's version IS Inwire's version (ADR 0035). Imported rather than
# written here so that `package.json` is the only place it is authored - see
# `agent_version.py`, which `npm run sync:version` generates and
# `scripts/agent/version.ts` holds to the product.
#
# Re-exported under this name because it is what `hello` carries, what
# `--version` prints, and what four other files read; moving the value out of
# this module did not need to move the name with it.
from agent_version import AGENT_VERSION  # noqa: E402

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
#
# For scale: dumpcap's `-B` default is **2 MiB** on every platform including
# Windows, so this is sixteen times what Wireshark asks for by default.
KERNEL_BUFFER_BASE_BYTES = 32 * 1024 * 1024

# **Npcap splits that buffer per processor, and a burst does not.**
#
# From Npcap's own maintainer (nmap/npcap#30, mirrored in npcap.com's API
# guide): the adapter buffer "is split into a number of independent segments
# according to the number of processors on the system. When a packet is received
# by the driver, it is put into the buffer segment corresponding to the driver
# thread's current processor. If there is not enough room in that segment, the
# packet is dropped."
#
# So a flat 32 MB is 32/N MB of usable slack against a burst that lands on one
# core - 2 MB on a sixteen-core machine, which is dumpcap's *default* and the
# opposite of what asking for sixteen times it was meant to buy. It is also the
# shape that best explains a burst of hundreds of thousands of frames in seconds
# showing up as driver drops on a machine with plenty of memory.
#
# Sized per core instead, so the per-segment share is what the number means.
# Floored at the old value so nothing gets smaller, and capped because this is
# **non-paged kernel memory** - a 64-core machine must not be asked for a
# gigabyte of it on the strength of a capture starting.
KERNEL_BUFFER_PER_CORE_BYTES = 4 * 1024 * 1024
KERNEL_BUFFER_MAX_BYTES = 256 * 1024 * 1024


def kernel_buffer_bytes(cores=None):
    """How much to ask the driver for on this machine.

    Pure and parameterised so `test_protocol.py` can drive every machine shape
    rather than the one it is running on.

    `cores` unknown falls back to the flat base rather than to one core - the
    same rule the rest of this codebase keeps about a reading it could not take.
    """
    if cores is None:
        cores = os.cpu_count()
    if not cores or cores < 1:
        return KERNEL_BUFFER_BASE_BYTES
    wanted = cores * KERNEL_BUFFER_PER_CORE_BYTES
    return max(KERNEL_BUFFER_BASE_BYTES, min(wanted, KERNEL_BUFFER_MAX_BYTES))


KERNEL_BUFFER_BYTES = kernel_buffer_bytes()

# How often the watchdog checks that capture is not running with nobody
# watching (see watch_for_orphaned_capture).
ORPHAN_CHECK_SECONDS = 2

# How many consecutive idle watchdog ticks end the process.
#
# Two rather than one, and the reason is `AgentPipeLink.recycle()`: the app
# closes the pipe and reopens it immediately to make the agent re-enumerate
# adapters after a driver install. That gap is milliseconds, but a tick landing
# inside it would read as "the app is gone" and stop the service the app is
# mid-way through reconnecting to. Two ticks means idleness has to persist for
# between two and four seconds, which no reconnect does and no human notices.
IDLE_EXIT_TICKS = 2

# How long to wait for a first client before exiting on idleness.
#
# The agent is demand-start (ADR 0035): the app asks the SCM for it at
# `whenReady()` and connects a moment later. Between those two events the agent
# has no clients and has never had one, and stopping there would be a service
# that kills itself before the thing that started it can arrive - which looks
# exactly like a crash loop, including to `pipeTransport.ts`'s own
# short-connection counter.
#
# It is a bound rather than "wait for ever": if the app dies between starting
# the service and connecting to it, something still has to clean up.
FIRST_CLIENT_GRACE_SECONDS = 30

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

# The capture engine, once main() has built one.
#
# **Declared here rather than only assigned in main(), and that is a fix.** It
# was an undeclared module global: three separate guards test `sniffer is not
# None`, and every one of them raised `NameError` instead of returning false
# for the whole window between process start and main()'s assignment. A guard
# that raises is not a guard - it is the failure it was written to prevent,
# with a worse message.
sniffer = None

# Set when something has asked the run loop to return; see request_shutdown.
# Both are written once, by main(), and read from the service's control thread.
_shutdown_event = None
_shutdown_loop = None

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
                        owner=None, auth_required: bool = False,
                        npcap_access_sddl=None) -> dict:
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

    `npcapAccess` is the Npcap device object's DACL as an SDDL string, or null
    where it could not be read - which is every non-Windows agent, and every
    Windows machine with no driver installed. It is a **string and not a
    verdict** on purpose: the agent runs as LocalSystem and is the part of the
    system that can read the descriptor, and the app is the part that decides
    what it means. docs/decisions/0033; npcap_access.py has the rest.
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
        # Null rather than absent, so a client can tell "this agent does not
        # report it" from "this agent looked and found nothing" - the first is
        # a missing key, the second is this.
        "npcapAccess": npcap_access_sddl,
    }


# What pcap_datalink() said about a device, remembered for the life of the
# process. See datalink_of.
_DATALINK_CACHE: dict = {}


def datalink_of(device_name):
    """The device's LINKTYPE_* value, or None when it could not be read.

    **Neither agent used to say, so the app assumed Ethernet.** That is right
    for every adapter on a Windows machine except Npcap's loopback device,
    which is DLT_NULL - a 4-byte address family and then the IP header. Read as
    Ethernet, bytes 12-13 land on the IP header's TTL and protocol, so a
    loopback capture showed a stream of ethertypes 0x8006 and 0x8011: 0x80 is
    the Windows default TTL, 0x06 and 0x11 are TCP and UDP. It also produced
    two fabricated MAC addresses with vendors resolved from them, a direction
    decided from those MACs, and no transport layer at all.

    **libpcap will only answer about a handle it has open**, so asking costs a
    pcap_open_live and a pcap_close per device - and the interface list is
    re-read on every client connection (refresh_interfaces). Cached by device
    name, which is safe because a device's link type is a property of what the
    device IS: an Ethernet adapter does not become a loopback one. What can
    change under a running agent is the SET of devices, and that is re-read per
    connection exactly as before.

    Opened NON-PROMISCUOUS and closed immediately: this is a question, not a
    capture, and putting an adapter into promiscuous mode in order to list the
    adapters would be a visible side effect of opening the app.

    None on any failure - a device in use by something that will not share it,
    a driver that has just removed it, or a scapy build without these symbols.
    The app's own fallback is Ethernet, so a 1 returned here would be
    indistinguishable from having asked and been told.
    """
    if device_name in _DATALINK_CACHE:
        return _DATALINK_CACHE[device_name]

    answer = None
    try:
        from scapy.libs.winpcapy import pcap_open_live, pcap_close, pcap_datalink
        errbuf = ctypes.create_string_buffer(256)
        handle = pcap_open_live(device_name.encode("utf-8"), 65535, 0, 100, errbuf)
        if handle:
            try:
                answer = int(pcap_datalink(handle))
            finally:
                pcap_close(handle)
    except Exception as exc:
        log.debug("could not read the link type of %s: %s", device_name, exc)

    _DATALINK_CACHE[device_name] = answer
    return answer


#: What the capture being started asked the driver for: a libpcap capture
#: filter, and the most bytes of each frame to keep. Set by `start_capture`
#: before its threads spawn, and read by each one as it opens its adapter.
CAPTURE_OPTIONS = {"filter": None, "snaplen": 262144}

#: The largest snaplen a client may ask for, and what no snaplen means:
#: dumpcap's default, and the Rust agent's `npcap::SNAPLEN`. The wire carries
#: 32-bit lengths since version 4, so nothing downstream caps it lower.
MAX_SNAPLEN = 262144

#: The longest capture filter a client may send - the Rust agent's
#: MAX_CAPTURE_FILTER_CHARS, with the same reason: the text reaches log lines.
MAX_CAPTURE_FILTER_CHARS = 4096


#: The app's capture ids, `cap-YYYYMMDD-HHMMSS-xxxx` - the Rust agent's
#: `is_capture_id`.
CAPTURE_ID_PATTERN = re.compile(r"cap-\d{8}-\d{6}-[0-9a-f]{4}")


class CaptureOptionsError(ValueError):
    """A filter or snaplen that is not one. The message is the reply's."""


def _filter_of(message, command):
    value = message.get("filter")
    if value is None:
        return None
    if not isinstance(value, str):
        raise CaptureOptionsError(f"{command}'s filter must be text.")
    if len(value) > MAX_CAPTURE_FILTER_CHARS:
        raise CaptureOptionsError(
            f"A capture filter is at most {MAX_CAPTURE_FILTER_CHARS} characters long.")
    return value if value.strip() else None


def parse_capture_options(message):
    """`start_capture`'s filter and snaplen, or CaptureOptionsError.

    **Refused, never defaulted.** A filter this agent could not read and
    ignored would be a capture of everything that its owner believes is
    narrowed - the same rule, and the same sentences, as the Rust agent's
    `filter_of` and `snaplen_of`.
    """
    snaplen = message.get("snaplen")
    if snaplen is None:
        snaplen = MAX_SNAPLEN
    elif isinstance(snaplen, bool) or not isinstance(snaplen, int) or not 1 <= snaplen <= MAX_SNAPLEN:
        raise CaptureOptionsError(
            "start_capture's snaplen must be a whole number of bytes from 1 to 262144.")
    # **This agent writes no capture files** (ADR 0052: the Rust agent does,
    # this one has no desktop app on its platforms to ask it to). A capture id
    # is checked with the Rust agent's sentence and then set aside - the
    # capture goes ahead, and the app offers no as-captured file for it. A
    # ring or an autostop is refused rather than ignored: one ignored is a
    # disk its owner believes is bounded, or a capture that never stops.
    capture_id = message.get("captureId")
    if capture_id is not None and not (isinstance(capture_id, str) and CAPTURE_ID_PATTERN.fullmatch(capture_id)):
        raise CaptureOptionsError(
            "start_capture's captureId must name a capture, cap-YYYYMMDD-HHMMSS-xxxx.")
    for key in ("ring", "autostop"):
        if message.get(key) is not None:
            raise CaptureOptionsError(
                f"This agent writes no capture files, so start_capture's {key} cannot be honoured.")
    return {"filter": _filter_of(message, "start_capture"), "snaplen": snaplen}


def _compile_error(handle, text):
    """libpcap's reason `text` will not compile on `handle`, or None."""
    from scapy.libs.winpcapy import bpf_program, pcap_compile, pcap_freecode  # noqa: PLC0415
    program = bpf_program()
    if pcap_compile(handle, byref(program), text.encode("utf-8"), 1, -1) != 0:
        return _pcap_error_text(handle)
    pcap_freecode(byref(program))
    return None


def apply_capture_filter(handle, text):
    """Has the driver drop every frame `text` does not match, or raises.

    On the raw handle rather than through scapy's `L2listen(filter=...)`,
    because scapy's `setfilter` logs a compile failure and carries on - which
    is a capture of everything, reported as a capture of what was asked.
    """
    from scapy.libs.winpcapy import bpf_program, pcap_compile, pcap_freecode, pcap_setfilter  # noqa: PLC0415
    program = bpf_program()
    if pcap_compile(handle, byref(program), text.encode("utf-8"), 1, -1) != 0:
        raise OSError(f"the capture filter does not apply here: {_pcap_error_text(handle)}")
    try:
        if pcap_setfilter(handle, byref(program)) != 0:
            raise OSError(f"the capture filter does not apply here: {_pcap_error_text(handle)}")
    finally:
        pcap_freecode(byref(program))


def check_capture_filter(text, names):
    """The `capture_filter_check` answer: whether `text` compiles for every
    link type among the adapters `names`, in libpcap's words when it does not.

    The Rust agent's `check_capture_filter`, rule for rule: per link type,
    Ethernet for an adapter whose type is unknown and when none is named, and
    the adapter's label on the reason only when the selection mixes types.
    """
    if not text.strip():
        return {"type": "capture_filter_check", "filter": text, "error": None}
    try:
        from scapy.libs.winpcapy import pcap_close, pcap_open_dead  # noqa: PLC0415
    except Exception:
        return {"type": "capture_filter_check", "filter": text,
                "error": "Npcap is not installed, so a capture filter cannot be checked"}
    kinds = []
    for name in names:
        if name not in INTERFACE_LABELS:
            continue
        link_type = datalink_of(name)
        link_type = 1 if link_type is None else link_type
        if all(known != link_type for known, _ in kinds):
            kinds.append((link_type, INTERFACE_LABELS[name]))
    if not kinds:
        kinds.append((1, None))
    for link_type, label in kinds:
        handle = pcap_open_dead(link_type, MAX_SNAPLEN)
        if not handle:
            reason = f"libpcap cannot compile for link type {link_type}"
        else:
            try:
                reason = _compile_error(handle, text)
            finally:
                pcap_close(handle)
        if reason is not None:
            if label is not None and len(kinds) > 1:
                reason = f"{label}: {reason}"
            return {"type": "capture_filter_check", "filter": text, "error": reason}
    return {"type": "capture_filter_check", "filter": text, "error": None}


def interface_entries(interfaces) -> list:
    """The interface list as every message carries it.

    `id` is the position in this list and is what a packet's `iface` field
    refers to (docs/decisions/0005). It is an index rather than the device
    name so a packet costs four bytes of identity, not sixty.

    `linkType` is **omitted when it could not be read** rather than sent as 1.
    The app falls back to Ethernet either way, so a guess written into the
    field would be indistinguishable from having asked - and an agent too old
    to have looked would then be indistinguishable from one that looked and
    found Ethernet. See datalink_of.

    `tsPrecision` is 6 wherever the link type could be read, because this agent
    stamps in microseconds whatever the driver could do - see packet_to_record.
    The Rust agent asks the driver for nanoseconds and says 9.
    """
    entries = []
    for i, (name, label) in enumerate(interfaces):
        entry = {"id": i, "name": name, "label": label}
        link_type = datalink_of(name)
        if link_type is not None:
            entry["linkType"] = link_type
            entry["tsPrecision"] = 6
        entries.append(entry)
    return entries


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
    #
    # The wire carries nanoseconds since version 3, and this agent has
    # microseconds: scapy activates the handle before a precision could be
    # asked for. So they are sent as nanoseconds with three zeros, and every
    # interface says `tsPrecision: 6` (interface_entries) so the app knows the
    # zeros were never measured.
    return packet_batch.encode_record(
        seq, iface_id, capture_time_us(ts) * 1000,
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


#: Where `read_frame` leaves the copy time for the loop to collect.
#:
#: Thread-local: one sniffer thread per adapter, and a shared slot would give
#: one thread's measurement to another thread's frame. Only written when
#: profiling is on.
_timing = threading.local()


def _pcap_error_text(handle) -> str:
    """libpcap's own message for the last failure on this handle.

    Best-effort by design: this runs on the failure path of a capture that has
    already gone wrong, and an import or a decode raising here would replace a
    useful diagnosis with a traceback about fetching the diagnosis.
    """
    try:
        from scapy.libs.winpcapy import pcap_geterr  # noqa: PLC0415
        text = pcap_geterr(handle)
        if not text:
            return "no message"
        return text.decode("utf-8", "replace") if isinstance(text, bytes) else str(text)
    except Exception:
        return "no message"


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

    **A timeout and a failure are different answers, and collapsing them span
    the CPU.** This used to be `if result != 1: return None`, and the caller is
    `while not stop_event.is_set(): ... continue`. `pcap_next_ex` returns 0 for
    the timeout, but **-1 for an error and -2 at end-of-capture** - and an
    adapter removed mid-capture returns -1 immediately, for ever. The loop then
    spun at 100% of a core inside a LocalSystem service, with no frames, no log
    line and nothing on screen, until the capture was stopped by hand.

    So an error raises. `sniff_on_interface` already wraps this loop in a
    `try/except` that calls `report_capture_failure`, which is how the app gets
    told an interface died - machinery that existed the whole time and that a
    silent `None` walked straight past.
    """
    result = pcap_next_ex(handle, byref(header), byref(data))
    if result == 0:
        return None
    if result != 1:
        # -1 is an error, -2 is end-of-capture on a savefile. Neither is
        # survivable by looping, and the text is worth having: "device is no
        # longer attached" is the whole diagnosis on a removed USB adapter.
        raise OSError(f"pcap_next_ex failed ({result}): {_pcap_error_text(handle)}")
    contents = header.contents
    caplen = contents.caplen
    if profile.enabled:
        # **The copy is timed apart from the call, because only one of them is
        # work.** `pcap_next_ex` BLOCKS until a frame arrives or `to_ms`
        # expires, so on a quiet link a successful read is mostly waiting - and
        # a per-frame cost that includes the wait is the arrival rate again,
        # which is the exact error `capture_profile.py` exists to have stopped
        # making. Measured on a 493 f/s link it reported 1,439 us a frame,
        # which is the gap between frames, not the cost of one.
        #
        # `string_at` and the arithmetic below are OURS and are always
        # meaningful. Thread-local because there is one sniffer thread per
        # adapter and a shared slot would hand one thread's copy time to
        # another thread's frame.
        _copy_start = time.perf_counter()
        raw = string_at(data, caplen)
        ts = contents.ts.tv_sec + contents.ts.tv_usec / 1e6
        _timing.copy_seconds = time.perf_counter() - _copy_start
        return raw, ts, contents.len
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


def build_capture_stats(seq_high, received, kernel_stats, dropped_agent,
                        dropped_pipe=None) -> dict:
    """One capture_stats message. Pure, so the shape is testable.

    `dropped_pipe` is the third loss site and the one that had no number at
    all: frames shed from the outbound pipe queue because the client was not
    reading fast enough. It is **omitted** rather than sent as 0 when the
    transport cannot report it - the WebSocket has no counterpart - so the app
    can tell "none were lost here" from "nobody counted", which is the rule
    `droppedKernel` already follows.
    """
    interfaces = []
    for iface_id in sorted(received):
        kernel = kernel_stats.get(iface_id)
        interfaces.append({
            "iface": iface_id,
            "received": received[iface_id],
            "kernelReceived": None if kernel is None else kernel[0],
            "droppedKernel": None if kernel is None else kernel[1],
        })
    message = {
        "type": "capture_stats",
        "intervalMs": int(CAPTURE_STATS_INTERVAL_SECONDS * 1000),
        "seqHigh": seq_high,
        "droppedAgent": dropped_agent,
        "interfaces": interfaces,
    }
    if dropped_pipe is not None:
        message["droppedPipe"] = dropped_pipe
    return message


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
        # The pipe's own shed counter lives on the connection, which
        # outlives a capture, so it is rebased the same way.
        self._dropped_pipe_at_capture_start = 0

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
                # Read per connection rather than once at startup, for the
                # same reason the interface list is: Npcap can be reinstalled
                # while the service keeps running, and a reconnect is exactly
                # what the Update Center triggers afterwards.
                npcap_access_sddl=npcap_access.read_driver_sddl(),
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

        # Before the ownership gate, as the Rust agent's parse is: options that
        # are not options are refused whoever sent them, and a start that
        # cannot be read must never become a capture on defaults.
        options = None
        if msg_type in ("start_capture", "check_capture_filter"):
            try:
                if msg_type == "start_capture":
                    options = parse_capture_options(message)
                else:
                    text = _filter_of(message, "check_capture_filter") or ""
                    names = message.get("interfaces")
                    if names is None:
                        names = []
                    if not (isinstance(names, list) and all(isinstance(n, str) for n in names)):
                        raise CaptureOptionsError(
                            "check_capture_filter's interfaces must be a list of names.")
                    await ws.send(json.dumps(check_capture_filter(text, names)))
                    return
            except CaptureOptionsError as exc:
                await ws.send(json.dumps({
                    "type": "error", "code": "invalid_capture_options", "message": str(exc),
                }))
                return

        # restart_agent is on the list because it ends the capture by exiting:
        # it is the owner's to give, like stop_capture.
        if msg_type in ("start_capture", "stop_capture", "set_interfaces", "restart_agent") and self.owned_by_other(ws):
            await ws.send(self._capture_busy_message())
            return

        if msg_type == "start_capture":
            log.info("start_capture requested on %d interface(s)", len(sniffer.selected_interfaces))
            # A capture already running keeps its own: they were applied to
            # handles that are still reading, as in the Rust agent.
            if not sniffer.is_sniffing():
                CAPTURE_OPTIONS.update(options)
                if options["filter"] is not None:
                    log.info("capture filter: %r", options["filter"])
                if options["snaplen"] < MAX_SNAPLEN:
                    log.info("snaplen: %d bytes", options["snaplen"])
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
            if sniffer.is_sniffing():  # a capture's adapters are fixed for its life (ADR 0048)
                return await ws.send(json.dumps({"type": "error", "code": "capture_running",
                                                 "message": "Stop the capture before changing interfaces."}))
            log.info("set_interfaces: %d interface(s) selected", len(interfaces))
            sniffer.set_interfaces(interfaces)
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
        elif msg_type == "set_capture_root":
            # Where the app's captures live, for the capture files this agent
            # does not write (see `parse_capture_options`). Understood, so a
            # current app is not told it spoke a language this agent lacks.
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
            #
            # The ownership gate above was answered half a second before the
            # exit, and another window can start a capture in that time, so the
            # gate is asked again when the exit is due (same rule as the Rust
            # agent).
            def restart_if_still_allowed():
                if self.owned_by_other(ws):
                    log.warning("restart_agent cancelled - another client started a capture")
                    # call_later callbacks are synchronous; a send to a socket
                    # that has since closed must not raise out of this one.
                    async def tell_asker():
                        try:
                            await ws.send(self._capture_busy_message())
                        except Exception:  # noqa: BLE001 - the asker may be gone
                            pass
                    asyncio.ensure_future(tell_asker())
                    return
                exit_for_restart()

            asyncio.get_running_loop().call_later(0.5, restart_if_still_allowed)
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

    @staticmethod
    def _capture_busy_message() -> str:
        """The refusal sent to a client that does not own the running capture."""
        return json.dumps({
            "type": "error",
            "code": "capture_busy",
            "message": "Another Inwire window started this capture. Stop it there, or close that window.",
        })

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

    async def _send_to_owner(self, data, records=0):
        """Packets and their statistics go to the connection that asked for
        them and to no one else. A tab that never pressed Start should not
        quietly accumulate somebody else's traffic."""
        ws = self.capture_owner
        if ws is None or ws not in self.connections or ws not in self.authenticated:
            return
        try:
            # `records` travels so the pipe's shed counter can be in PACKETS.
            # A shed batch loses every packet in it, and a counter that ticks
            # once per shed ITEM understates the loss by the batch size.
            await ws.send(data, records)
        except TypeError:
            # A transport whose `send` predates the second argument - the
            # WebSocket on macOS and Linux. Its queue does not shed, so there
            # is no counter to keep in packets.
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
        _outbound = getattr(self.capture_owner, "outbound", None)
        self._dropped_pipe_at_capture_start = 0 if _outbound is None else _outbound.dropped
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

    def _dropped_pipe(self):
        """Frames shed from the owner's outbound pipe queue, this capture.

        `None` when the transport cannot say - the WebSocket has no
        counterpart, and there may be no owner at all - so the app renders
        "unknown" rather than a confident zero. Same `getattr` idiom as
        `kernel_authenticated`, for the same reason: the agent stays ignorant
        of which transport it has.

        Rebased per capture like `droppedAgent`, because a number that
        accumulated across every capture since the service started would be
        read as belonging to the one on screen.
        """
        owner = self.capture_owner
        outbound = getattr(owner, "outbound", None) if owner is not None else None
        if outbound is None:
            return None
        return outbound.dropped - self._dropped_pipe_at_capture_start

    def _log_queue_depths(self):
        """Where the frames are sitting, once a second, under the profile flag.

        **This is the reading that tells two opposite problems apart**, and
        without it they look identical from outside - `droppedAgent` climbs in
        both:

          sniffer queue pinned, pipe empty   the PUMP is not draining fast
                                             enough. Fix the agent.
          sniffer queue pinned, pipe full    the CLIENT is not reading fast
                                             enough. Fix the app, or shed.
          both near empty                    the loss is upstream, in the
                                             driver's own ring, and only
                                             reading faster reaches it.

        Bytes as well as counts for the sniffer queue, because it is bounded by
        both and the count alone cannot say which bound is biting - the lesson
        `MAX_QUEUED_BYTES` was added for.

        Off unless `INWIRE_PROFILE_CAPTURE` is set: this runs once a second on
        an installed service, and a log line a second is how a rotation loses
        the history somebody is looking for.
        """
        if not profile.enabled:
            return
        with self._packet_lock:
            queued = len(self._packet_queue)
            queued_bytes = self._packet_queue_bytes
        owner = self.capture_owner
        # `getattr`, because the WebSocket transport has no counterpart - the
        # same idiom `kernel_authenticated` uses. `None` reads as "this
        # transport cannot say", never as an empty queue.
        depth = getattr(owner, "outbound_depth", None) if owner is not None else None
        pipe_depth = depth() if depth is not None else None
        log.info(
            "queues: sniffer %d frames / %d bytes (of %d / %d), pipe %s frames (of %d)",
            queued, queued_bytes, MAX_QUEUED_PACKETS, MAX_QUEUED_BYTES,
            "unknown" if pipe_depth is None else pipe_depth,
            pipe_server.MAX_OUTBOUND_FRAMES,
        )

    async def _capture_stats_loop(self):
        try:
            while sniffer is not None and sniffer.is_sniffing():
                seq_high, received, sockets = counters.snapshot()
                kernel = {iface_id: read_pcap_stats(sock) for iface_id, sock in sockets.items()}
                dropped_agent = self._dropped_sends - self._dropped_at_capture_start
                await self._send_to_owner(json.dumps(
                    build_capture_stats(seq_high, received, kernel, dropped_agent,
                                        self._dropped_pipe())
                ))
                self._log_queue_depths()
                await asyncio.sleep(CAPTURE_STATS_INTERVAL_SECONDS)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("capture stats stopped: %s", exc)
        finally:
            # Only if this reference is still to THIS task. A stop_capture then
            # a start_capture cancels and recreates it in the same breath, so
            # by the time a cancelled task unwinds, the attribute may already
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
        """Takes up to one batch off the queue, and says whether more is left.

        Runs on the loop, under the same lock the sniffer threads append with,
        and holds it only for the pops - the send happens outside it.

        **Returning `more` is what fixes the throttle.** This loop stops on
        EITHER bound - 512 records or 256 kB - but the pump used to decide
        whether to sleep by re-testing the record count alone. At the 1,101-byte
        mean frame this repo measured, 256 kB is about 233 records, so every
        batch on real traffic came back under 512 and was read as "the queue ran
        dry" when it had not. The pump then slept 10 ms with a full queue behind
        it, capping delivery at 256 kB / 10 ms = 25.6 MB/s, roughly 23,000
        frames a second at that mean and 17,000 at 1,514 bytes.

        Small-frame floods reach 512 records first and were never affected,
        which is why every synthetic test passed and only real captures lost
        frames.

        `more` is read under the lock, so it cannot be a stale answer about a
        queue a sniffer thread has since appended to.
        """
        batch = []
        size = 0
        with self._packet_lock:
            while self._packet_queue and len(batch) < MAX_BATCH_RECORDS and size < MAX_BATCH_BYTES:
                record = self._packet_queue.popleft()
                self._packet_queue_bytes -= len(record)
                batch.append(record)
                size += len(record)
            more = bool(self._packet_queue)
        return batch, more

    async def _packet_pump(self):
        """Drains the packet queue into batched binary frames.

        One task for the whole process, started with capture and cancelled
        with it. It keeps draining while there is anything queued rather than
        sleeping between batches, so a burst is cleared as fast as the socket
        will take it; the sleep is only for the idle case.
        """
        try:
            while True:
                batch, more = self._drain_packets()
                if not batch:
                    await asyncio.sleep(PACKET_BATCH_INTERVAL_SECONDS)
                    continue
                payload = packet_batch.encode_batch(batch)
                await self._send_to_owner(payload, len(batch))
                if not more:
                    await asyncio.sleep(PACKET_BATCH_INTERVAL_SECONDS)
                else:
                    # **A yield, not a delay.** `more` means the queue is still
                    # backed up, so sleeping would be the bug this replaced -
                    # but the loop cannot simply spin either. On the pipe,
                    # `PipeConnection.send` is an `async def` with no `await`
                    # inside it, and awaiting such a coroutine does NOT hand
                    # control back to the event loop. Draining 30,000 records
                    # without this would starve the reader, the stats ticker and
                    # every subscription for the whole drain - trading a
                    # throughput cap for an unresponsive agent.
                    await asyncio.sleep(0)
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


def sniff_callback(raw, ts, iface_id=0, wire_len=None, pcap_seconds=None,
                   copy_seconds=None):
    global _captured_count
    # Wall time for this frame's own callback. The other half - the driver read
    # - happened before we were called, so the LOOP brackets it and passes it
    # in as `read_seconds`. It used to be derived from the gap between frames
    # instead, which measured how fast traffic arrived rather than what a frame
    # cost; `capture_profile.py` has the post-mortem.
    #
    # `None` means "this branch cannot time its own read", not "the read was
    # free" - only `sniff(prn=...)` is in that position, and it is the slowest
    # branch, so rounding it to zero would have made it look like the fastest.
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

    # The snaplen, cut here: scapy opens its handle at its own fixed snaplen,
    # so this agent truncates what it was handed rather than asking the driver
    # to - the same frames on the wire, without the kernel-buffer saving the
    # Rust agent's `pcap_set_snaplen` buys.
    snaplen = CAPTURE_OPTIONS["snaplen"]
    if len(raw) > snaplen:
        if wire_len is None:
            wire_len = len(raw)
        raw = raw[:snaplen]
    seq = counters.next_seq(iface_id)
    try:
        record = packet_to_record(raw, ts, iface_id, seq, wire_len)
    except Exception as exc:
        log.warning("failed to process a captured packet: %s", exc)
        return
    agent.queue_packet(record)
    if profile.enabled:
        profile.frame(time.perf_counter() - profile_start, pcap_seconds, copy_seconds)
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
    # Before a frame is read, and a failure fails this adapter alone - the
    # Rust agent's rule. A socket with no libpcap handle cannot be filtered
    # here, and is refused rather than read unfiltered.
    capture_filter = CAPTURE_OPTIONS["filter"]
    if capture_filter is not None:
        try:
            handle_for_filter = pcap_handle(sock)
            if not handle_for_filter:
                raise OSError("the capture filter does not apply here: this socket has no libpcap handle")
            apply_capture_filter(handle_for_filter, capture_filter)
        except Exception as exc:
            log.warning("capture failed on interface %r (%s): %s", iface_label, iface_name, exc)
            agent.report_capture_failure(iface_id, iface_name, iface_label, str(exc))
            try:
                sock.close()
            except Exception:
                pass
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
                # Bracketed here rather than inside `read_frame`, so the timing
                # costs one `perf_counter` pair per frame on a path that is
                # already two ctypes calls - and nothing at all when profiling
                # is off, which is the state an installed service is in.
                read_start = time.perf_counter() if profile.enabled else 0.0
                frame = read_frame(handle, header, data)
                if frame is None:
                    # The `to_ms=100` timeout expiring. Deliberately NOT
                    # recorded: the thread was idle, and counting idle time as
                    # read cost would make a quiet link look like an expensive
                    # one - which is the error the old whole-wall metric made.
                    continue
                if profile.enabled:
                    # Two numbers, because they answer different questions.
                    # `pcap` is the call, and on a quiet link it is mostly the
                    # wait for a frame that had not arrived. `copy` is ours and
                    # is always work. See capture_profile.py.
                    pcap_seconds = time.perf_counter() - read_start
                    copy_seconds = getattr(_timing, "copy_seconds", 0.0)
                else:
                    pcap_seconds = copy_seconds = None
                raw, ts, wire_len = frame
                sniff_callback(raw, ts, iface_id, wire_len, pcap_seconds, copy_seconds)
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
                # The select is the wait; the recv is the read. Only the recv
                # is timed, for the same reason the fast path skips its
                # timeouts - see capture_profile.py.
                read_start = time.perf_counter() if profile.enabled else 0.0
                _cls, raw, ts = sock.recv_raw()
                # None is the read timeout expiring, not an error: loop round
                # and re-test stop_event.
                if raw is None:
                    continue
                read_seconds = (time.perf_counter() - read_start) if profile.enabled else None
                # recv_raw returns bytes it allocated itself, so the call and
                # the copy are not separable here - the same number is both.
                sniff_callback(raw, ts, iface_id, None, read_seconds, read_seconds)
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


def request_shutdown(reason):
    """Asks the run loop to return, from any thread.

    The only orderly way out of `main()`. Before this existed, `SvcStop` called
    `loop.stop()` directly, which stops the loop **wherever it is** - and where
    it was is suspended inside `await asyncio.Future()`, so the `finally:
    pipes.stop()` beneath it never ran and the pipe name was released by process
    exit rather than by anything that had decided to release it. That is the
    defect this fixes; the idle exit below is what made it urgent, because a
    service that stops itself every time the app closes performs that shutdown
    constantly instead of once a reboot.

    Safe from a control thread: `call_soon_threadsafe` is the only way to touch
    a loop you are not running on, and a loop that has already closed raises
    rather than corrupting anything - which a stop racing a stop will do.
    """
    event, loop = _shutdown_event, _shutdown_loop
    if event is None or loop is None:
        return
    log.info("shutting down: %s", reason)
    try:
        loop.call_soon_threadsafe(event.set)
    except RuntimeError:
        # Already closed. A second stop, or a stop racing shutdown; there is
        # nothing left to ask.
        pass


async def watch_for_orphaned_capture(may_exit):
    """Stops capture whenever nothing is watching, and then stops the agent.

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

    ## The second job, which is the whole of ADR 0035

    With `may_exit` set, an agent that has been idle for `IDLE_EXIT_TICKS`
    consecutive ticks asks the process to stop. That is what makes closing
    Inwire stop the service rather than merely stop the capture, and it is done
    **here, by the agent itself**, rather than by the app running `sc stop`:

      - the app deliberately has no right to stop this service, and granting
        `WP` would grant it to every interactive logon - so a second Windows
        user could stop a capture the first is running (ADR 0030);
      - a self-stop survives the app crashing or being killed from Task
        Manager, where an `sc stop` on the quit path does not;
      - and the agent is the only party that knows whether some *other* client
        is still connected.

    `may_exit` is false on the macOS/Linux WebSocket path, where there is no
    SCM to start the agent again on demand and exiting would mean it never
    comes back.
    """
    idle_ticks = 0
    started = time.monotonic()
    seen_a_client = False

    while True:
        await asyncio.sleep(ORPHAN_CHECK_SECONDS)
        if sniffer is not None and sniffer.is_sniffing() and not agent.connections:
            log.warning("capture was running with no clients connected - stopping it")
            sniffer.stop_threads()

        if not may_exit:
            continue

        if agent.connections:
            seen_a_client = True
            idle_ticks = 0
            continue

        # Never had one, and the grace has not run out: the app that started
        # this service is still on its way. See FIRST_CLIENT_GRACE_SECONDS.
        if not seen_a_client and time.monotonic() - started < FIRST_CLIENT_GRACE_SECONDS:
            continue

        idle_ticks += 1
        if idle_ticks >= IDLE_EXIT_TICKS:
            request_shutdown(
                "no clients connected" if seen_a_client
                else "no client connected within the startup grace period"
            )
            return


async def main(to_stderr=True):
    # The interface globals are owned by refresh_interfaces() now, and only
    # read here, so they are deliberately not declared global.
    global sniffer, log, _shutdown_event, _shutdown_loop

    _shutdown_event = asyncio.Event()
    _shutdown_loop = asyncio.get_running_loop()

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
    if pipes.refused:
        # The pipe name existed before this process made it (ADR 0068). Already
        # logged by `PipeServer`; ending here also keeps a refusal from falling
        # through to the WebSocket, which Windows must never open.
        return False

    if pipes.serving:
        try:
            # `may_exit=True`: this is the Windows service, which the SCM starts
            # again the moment the app asks for it. ADR 0035.
            asyncio.create_task(watch_for_orphaned_capture(may_exit=True))
            # **Not `asyncio.Future()` any more.** That never completes, so the
            # only way out was stopping the loop from underneath it and this
            # `finally` never ran - the pipe name was released by process exit.
            # Now every exit path passes through the line below it.
            await _shutdown_event.wait()
        finally:
            pipes.stop()
            if sniffer is not None and sniffer.is_sniffing():
                # A capture still running at shutdown. Stopping it here rather
                # than letting the process die on top of it is what closes the
                # pcap handles and flushes the last counters - the sniffer
                # threads are daemons and would otherwise simply vanish.
                sniffer.stop_threads()
        return True

    async with websockets.serve(
        agent.register,
        HOST,
        PORT,
        process_request=make_process_request(on_reject=log_rejection),
    ):
        log.info("WebSocket server listening on ws://%s:%d", HOST, PORT)
        # `may_exit=False`: macOS and Linux install from the tarball and have no
        # SCM to start this again on demand, so an agent that exited on idleness
        # would be an agent that never came back. The orphan check still runs -
        # that guarantee is unconditional.
        asyncio.create_task(watch_for_orphaned_capture(may_exit=False))
        await _shutdown_event.wait()

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
