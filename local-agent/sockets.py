"""Which process owns which local socket.

This is the one thing a capture cannot tell you and a program on the captured
machine can. A frame says 10.0.0.4:54321 talked to 142.250.185.14:443; the
operating system knows that 54321 belongs to chrome.exe, and nothing on the
wire does. Wireshark cannot answer "what is talking to that address" at all -
not because nobody wanted it, but because a passive observer is in the wrong
place to know.

**Keyed by the LOCAL endpoint, not by a five-tuple**, and that is forced rather
than chosen: on Windows `GetExtendedUdpTable` has no remote column, so every
UDP socket in the table reports an empty remote address. Measured on a real
machine: 63 of 63. The local endpoint is what the OS actually owns, and it is
the only key that works for both transports.

**Deltas, not snapshots.** The full table here is 890 sockets - about 52 KB of
JSON - and it changes by one or two sockets a second. Measured over eight
seconds: 50 to 250 bytes of churn per tick against 52 KB for a resend, so a
delta is roughly two hundred times cheaper and does not compete with packet
delivery for the socket. Control messages are exempt from the packet queue's
backpressure (see `send_control`), so a delta cannot be silently dropped, and a
reconnecting client re-subscribes and gets a fresh full snapshot - which is why
there is no sequence number and no resync handshake.

The agent takes no view on what the table means. It reports appearances and
disappearances with the times they happened; deciding which frame belongs to
which process - including what to do about a reused port - is the app's, in
`services/flowAnnotations.ts`.
"""
import psutil

# The transports the app can key on. Anything else the OS lists is not
# something a captured frame can be matched against.
_TCP = 1  # socket.SOCK_STREAM
_UDP = 2  # socket.SOCK_DGRAM


def _proto(kind) -> str:
    if kind == _TCP:
        return "tcp"
    if kind == _UDP:
        return "udp"
    return ""


def normalize_address(address: str) -> str:
    """Strips an IPv6 zone index.

    psutil reports link-local addresses as `fe80::1%eth0`; a captured frame
    carries the address alone. Without this the two never compare equal, and
    link-local traffic - which is most of what a quiet network carries - would
    be the traffic that never gets attributed.
    """
    if not address:
        return ""
    at = address.find("%")
    return address if at == -1 else address[:at]


def read_socket_table(source=None) -> dict:
    """`{(proto, local address, local port): pid}` for every inet socket.

    A socket with no local address is skipped: there is nothing to key it by.
    A pid of None (a socket the OS will not attribute, which on Windows is a
    handful of system ones) is kept as 0, so that the app learns the socket
    exists and still reports no process for it - an unattributed socket is not
    the same fact as no socket, and collapsing the two would let a frame fall
    through to a stale entry for a reused port.
    """
    connections = source() if source else psutil.net_connections(kind="inet")
    table = {}
    for conn in connections:
        proto = _proto(conn.type)
        if not proto or not conn.laddr:
            continue
        address = normalize_address(conn.laddr.ip)
        # Every key this returns has to be one a captured frame could match,
        # and no frame carries an empty address. A socket without one is not a
        # socket this can say anything about.
        if not address:
            continue
        key = (proto, address, conn.laddr.port)
        # First writer wins. Two sockets can share a local endpoint (a
        # listener and its accepted connections on some platforms); the
        # listener's owner is the same process either way.
        table.setdefault(key, conn.pid or 0)
    return table


def describe_process(pid: int, namer=None) -> dict:
    """`{name, exe}` for a pid, or None when it cannot be read.

    Not cached. Caching by pid alone is wrong - pids are reused, and a cache
    keyed on one would eventually name a socket after the process that used to
    hold that number, which is the single most misleading thing this module
    could do. Guarding a cache with `create_time` would cost a syscall per pid
    per poll, which is what the cache was meant to save. Measured without one:
    60 distinct pids named in 2.9 ms.
    """
    if not pid:
        return None
    try:
        process = namer(pid) if namer else psutil.Process(pid)
        name = process.name()
    except Exception:
        # AccessDenied on a protected process, NoSuchProcess when it exited
        # between the table read and this call. Both mean the same thing to a
        # caller: this socket has no name to show.
        return None
    try:
        exe = process.exe()
    except Exception:
        # Common and not an error - a service can deny its own path while
        # freely giving its name. The name alone is still worth having.
        exe = ""
    return {"name": name, "exe": exe}


class SocketTracker:
    """Turns successive readings of the socket table into add/remove deltas.

    Holds the previous reading, so the first poll after construction reports
    the whole table as additions and every poll after it reports only what
    moved.
    """

    def __init__(self, source=None, namer=None):
        # Injected so the tests can drive the table directly rather than
        # opening real sockets and hoping the OS agrees.
        self._source = source
        self._namer = namer
        self._previous = None

    def reset(self) -> None:
        """Forgets the previous reading, so the next poll is a full snapshot.

        Called when a client subscribes: it has no table of its own yet, and a
        delta against a table it never received would leave it permanently
        short of every socket that existed before it arrived.
        """
        self._previous = None

    def poll(self) -> dict:
        """The next message for subscribers, or None when nothing changed.

        `full` marks the first poll of a subscription, so a client can drop
        whatever it held rather than merging a snapshot into a stale table.

        `procs` carries an entry for every pid this message's additions refer
        to, re-sent even when an earlier message already named it. That costs a
        few dozen bytes on a delta that averages two sockets and lets the app
        treat each message on its own.
        """
        current = read_socket_table(self._source)
        full = self._previous is None
        previous = self._previous or {}

        added = {key: pid for key, pid in current.items()
                 if key not in previous or previous[key] != pid}
        gone = [key for key in previous if key not in current]
        self._previous = current

        # An unchanged second is the common case on an idle machine, and an
        # empty delta every second is a message that says nothing.
        if not full and not added and not gone:
            return None

        procs = {}
        for pid in {pid for pid in added.values() if pid}:
            described = describe_process(pid, self._namer)
            if described is not None:
                procs[str(pid)] = described

        return {
            "type": "socket_table",
            "full": full,
            "procs": procs,
            "add": [[proto, address, port, pid]
                    for (proto, address, port), pid in added.items()],
            "gone": [[proto, address, port] for (proto, address, port) in gone],
        }
