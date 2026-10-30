"""A named-pipe server that looks like a WebSocket to the rest of the agent.

Why a pipe
----------

The agent listened on ``ws://localhost:8999``, and a loopback TCP port is
reachable by every process on the machine. Everything in ``config.py`` exists
because of that: a 256-bit pairing token compared with ``hmac.compare_digest``,
an origin allowlist, an ``icacls`` call locking ``config.json`` to SYSTEM and
administrators, and a string the user has to paste into the app once.

A named pipe carries a security descriptor. The kernel decides who may connect,
so none of that is needed - and none of it was ever very good: ``Origin`` is a
header the client writes, and the token, once pasted, sat in the app's own
storage where any process running as that user could read it.

The shape, and why it is this shape
-----------------------------------

``AgentServer.register`` does its whole job through two operations: ``await
ws.send(data)``, and ``async for raw in ws``. So ``PipeConnection`` provides
exactly those two, and **the agent's connection handling is unchanged** -
ownership, subscriptions, the hello handshake, the disconnect rules, all of it.

Threads, not IOCP
-----------------

Reading and writing happen on dedicated threads, which hand off to the event
loop with ``call_soon_threadsafe``. The alternative, ``loop.start_serving_pipe``,
integrates with the proactor properly but creates its pipe instances itself -
with the creating process's default DACL, which for a LocalSystem service
admits SYSTEM and administrators and therefore **not the unelevated app this
exists to serve**. Passing our own security descriptor means creating the
instances ourselves, and once we are doing that the threads are the simpler
half.

It is also the pattern the agent already uses everywhere else: the sniffer is
threads feeding the loop, for the same reason.

Overlapped, though - and this is not an optimisation
----------------------------------------------------

The threads are ours; the I/O has to be asynchronous anyway. A handle opened
without ``FILE_FLAG_OVERLAPPED`` is a **synchronous** handle, and Windows
serialises every operation on one: while the reader thread sits in
``ReadFile`` waiting for the client's next command, a ``WriteFile`` from the
writer thread does not fail and does not block visibly - it simply waits its
turn behind a read that may not complete for minutes.

That is not a hypothesis. Driven against the real client, ``hello`` and the
first reply arrived and everything after them did not: writes landed only when
one happened to fall in the gap between the reader returning and blocking
again. Which is the worst possible shape for a bug - it works on the handshake,
which is what anyone tests, and stops on the traffic, which is what the pipe is
for.

So the pipe is created ``FILE_FLAG_OVERLAPPED`` and every operation carries its
own ``OVERLAPPED`` with its own event. Its own, not a shared one: two
concurrent operations signalling one event is the same bug wearing a different
hat. The waits are bounded rather than infinite so that ``stop()`` is observed
- an ``INFINITE`` wait on a client that never speaks again would leave a thread
pinned for the life of the process.

The writer waits for each frame to complete before starting the next, because
two outstanding writes on one handle have no defined order and a packet batch
delivered out of order is a capture that lies about the wire. Measured against
the real client, that costs nothing worth having: **4,000 batches of 64 kB -
262 MB - in 539 ms, or 487 MB/s**. A saturated gigabit adapter is 125 MB/s and
this agent's own stream is a 256 kB batch about thirty times a second.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import sys
import os
import threading
from typing import Awaitable, Callable, Optional

import pipe_frame

log = logging.getLogger("inwire.pipe")

#: Where the app looks. One instance per connected client.
#:
#: ``INWIRE_AGENT_PIPE`` overrides it, and that is not a debugging nicety - it
#: is the only way this agent can be run beside the installed service, which
#: owns the production name. ``electron/main.ts`` and the Rust agent's
#: ``runtime::pipe_name`` already read the same variable, so one export points
#: every half of the system at a private pipe; without it here, comparing the
#: two agents meant unregistering one of them first.
#:
#: Empty is treated as unset, so ``INWIRE_AGENT_PIPE=`` in a shell profile
#: cannot leave the service listening on a name nothing dials.
PIPE_NAME = os.environ.get("INWIRE_AGENT_PIPE") or r"\\.\pipe\inwire-agent"

#: How many connections may exist at once.
#:
#: More than one because the ownership model still means something: a second
#: Windows user logged into the same machine runs their own copy of the app
#: against the one machine-wide service, and `capture_busy` is what arbitrates.
MAX_PIPE_INSTANCES = 8

#: Fails ``CreateNamedPipe`` when the name already exists (ADR 0068). Set on the
#: first instance only, so the agent never serves a pipe someone else made.
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000

#: Seconds before an instance the system refused is asked for again (ADR 0068).
INSTANCE_RETRY_SECONDS = 1.0

#: Read buffer. A batch is capped at 256 kB and a control message is smaller.
READ_CHUNK = 64 * 1024

#: Queued outbound frames before the oldest are shed.
#:
#: The same reasoning as ``MAX_QUEUED_PACKETS`` in the sniffer: backpressure
#: has to end somewhere, and a client that cannot keep up must cost the client
#: rather than the agent's memory.
MAX_OUTBOUND_FRAMES = 4096

#: ...and the byte budget beside it, for the reason ``MAX_QUEUED_BYTES`` exists.
#:
#: **A count bound alone was the wrong shape here and the sniffer already knew
#: it.** ``agent.py`` records adding ``MAX_QUEUED_BYTES`` because a frame is 60
#: bytes to 64 kB, so a count says nothing about memory. The items in THIS queue
#: are whole batches of up to 256 kB, which makes the mismatch far worse: 4,096
#: of them is up to **1 GB**, queued inside a LocalSystem service, on a machine
#: whose owner is watching it for using too much memory.
#:
#: 32 MB, matching ``MAX_QUEUED_BYTES`` and ``KERNEL_BUFFER_BYTES`` - the same
#: order of magnitude as every other buffer on this path.
MAX_OUTBOUND_BYTES = 32 * 1024 * 1024

_SHUTDOWN = object()


class _Outbound:
    """Frames waiting for the writer thread, bounded by count AND bytes.

    A ``queue.Queue`` was here, and it could only express the count bound. The
    items are whole batches of up to 256 kB, so 4,096 of them is up to a
    gigabyte held inside a LocalSystem service - the same mistake ``agent.py``
    records fixing in the sniffer queue when it added ``MAX_QUEUED_BYTES``
    beside ``MAX_QUEUED_PACKETS``. A deque under a condition is what that queue
    is, so this is the same shape as the one on the other end of the pump.

    **Full means shed the oldest, not drop the client.** It used to close the
    connection, and that is worse than it sounds: closing drops the client, the
    client leaving is what stops the capture (``handle_disconnect``), so the
    protection against a slow reader terminated the very thing it was
    protecting. It also made the loss unreportable - the connection that would
    have carried the number is the one being closed.

    Oldest-first, matching the sniffer queue, and **counted**, which is the
    other half of what was missing: frames vanished here with no counter, no
    per-drop log line and nothing in ``capture_stats``.
    """

    def __init__(self, max_frames: int, max_bytes: int) -> None:
        self._frames: collections.deque = collections.deque()
        # How many captured packets each queued frame carries, in step with
        # `_frames`. Kept apart rather than stored as a tuple so the hot path -
        # the writer thread's `get()` - still pops a plain bytes object.
        self._records: collections.deque = collections.deque()
        self._bytes = 0
        self._max_frames = max_frames
        self._max_bytes = max_bytes
        self._cond = threading.Condition()
        self.dropped = 0

    def put(self, frame, records: int = 0) -> None:
        """Queues one outbound frame.

        `records` is **how many captured packets this frame carries** - a
        packet batch holds up to 512 of them, a control message holds none.

        **The counter is in packets, and getting that wrong was a real bug.**
        It counted ITEMS, and the items here are batches; the app adds
        `droppedPipe` straight into a frames-lost total beside `droppedAgent`
        and `droppedKernel`, which are packets. So a shed batch of twelve
        frames was reported as one lost frame, and the figure was short by
        roughly the batch size - measured against the Rust agent under load,
        37,793 shed batches accounted for 398,000 missing packets.

        Caught by asserting conservation end to end rather than by reading it:
        delivered plus shed plus still-queued has to equal what the driver
        handed over, and it did not.
        """
        with self._cond:
            self._frames.append(frame)
            if frame is not _SHUTDOWN:
                self._bytes += len(frame)
                self._records.append(records)
            # `> 1` so the frame just queued is never the one shed: a queue that
            # evicted its own newest arrival would deliver nothing at all once
            # a single frame exceeded the budget.
            while (len(self._frames) > self._max_frames
                   or self._bytes > self._max_bytes) and len(self._frames) > 1:
                oldest = self._frames.popleft()
                if oldest is _SHUTDOWN:
                    # Never shed the stop signal - the writer thread is waiting
                    # for it and would block until the handle closed under it.
                    self._frames.appendleft(oldest)
                    break
                self._bytes -= len(oldest)
                # In PACKETS, not in queued items. See `put`.
                self.dropped += self._records.popleft()
            self._cond.notify()

    def get(self):
        with self._cond:
            while not self._frames:
                self._cond.wait()
            frame = self._frames.popleft()
            if frame is not _SHUTDOWN:
                self._bytes -= len(frame)
                self._records.popleft()
            return frame

    def qsize(self) -> int:
        with self._cond:
            return len(self._frames)

    def pending_bytes(self) -> int:
        with self._cond:
            return self._bytes


class PipeConnection:
    """One connected client, presented the way ``register`` expects.

    ``send`` accepts what the WebSocket accepted - ``str`` for a control
    message, ``bytes`` for a packet batch - and the frame kind follows from the
    type, which is how the WebSocket distinguished them too.
    """

    #: The one thing this connection claims that a WebSocket cannot.
    #:
    #: The kernel checked the descriptor before the handle existed, so
    #: ``register`` skips the pairing token rather than answering it - see the
    #: comment there. Read with ``getattr``, so the WebSocket needs no
    #: counterpart and the agent needs no knowledge of which transport it has.
    kernel_authenticated = True

    def __init__(self, loop: asyncio.AbstractEventLoop, write: Callable[[bytes], None],
                 close: Callable[[], None]) -> None:
        self._loop = loop
        self._write = write
        self._close = close
        self._inbox: asyncio.Queue = asyncio.Queue()
        self._closed = False

    # -- what `register` uses ------------------------------------------------

    async def send(self, data, records: int = 0) -> None:
        """Sends one message.

        `records` is how many captured packets `data` carries, and it exists so
        the shed counter can be in PACKETS. A batch that is shed loses every
        packet in it, and reporting that as one lost frame understates the loss
        by the batch size - see `_Outbound.put`.
        """
        if self._closed:
            raise ConnectionError("the pipe client has gone")
        if isinstance(data, str):
            frame = pipe_frame.encode_frame(pipe_frame.FRAME_JSON, data.encode("utf-8"))
        else:
            frame = pipe_frame.encode_frame(pipe_frame.FRAME_BINARY, bytes(data))
        self._write(frame, records)

    def __aiter__(self):
        return self

    async def __anext__(self) -> str:
        item = await self._inbox.get()
        if item is _SHUTDOWN:
            raise StopAsyncIteration
        return item

    # -- what the reader thread uses -----------------------------------------

    def deliver(self, text: str) -> None:
        """Called from the reader thread with one decoded control message."""
        self._loop.call_soon_threadsafe(self._inbox.put_nowait, text)

    def finish(self) -> None:
        """Called from the reader thread when the client has gone."""
        if self._closed:
            return
        self._closed = True
        self._loop.call_soon_threadsafe(self._inbox.put_nowait, _SHUTDOWN)

    def close(self) -> None:
        self._closed = True
        self._close()


def _security_attributes():
    """A descriptor that admits the interactive user and nobody else.

    ``D:P`` - a protected DACL, so nothing is inherited - granting full access
    to SYSTEM, to administrators, and to ``IU``, the well-known SID for anyone
    logged on interactively. That last one is the whole point: the service runs
    as LocalSystem and the app does not, and without it the default DACL admits
    SYSTEM and administrators only, so the app could never connect.

    Deliberately absent: ``WD`` (everyone), ``AN`` (anonymous) and ``NU``
    (network). A named pipe is reachable over SMB as ``\\\\host\\pipe\\name``
    unless the descriptor says otherwise, and a capture agent answering the
    network is not a thing anyone asked for.
    """
    import win32security  # noqa: PLC0415 - Windows only, imported where used

    sddl = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"
    descriptor = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
        sddl, win32security.SDDL_REVISION_1,
    )
    attributes = win32security.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = descriptor
    attributes.bInheritHandle = False
    return attributes


class PipeServer:
    """Accepts clients on the named pipe and hands each to ``register``."""

    def __init__(self, loop: asyncio.AbstractEventLoop,
                 register: Callable[[PipeConnection], Awaitable[None]],
                 name: str = PIPE_NAME) -> None:
        self._loop = loop
        self._register = register
        self._name = name
        self._stopping = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        #: Whether this is the agent's transport. See `start`.
        self.serving = False
        #: Why the server would not start, or None. Set when the pipe name
        #: already existed (ADR 0068); `agent.main` reads it and ends, rather
        #: than falling through to the WebSocket this platform must not open.
        self.refused: Optional[str] = None
        #: The instance made before the accept thread, with
        #: ``FILE_FLAG_FIRST_PIPE_INSTANCE``. See `_begin`.
        self._first_handle = None
        #: Seconds before an instance the system refused is asked for again.
        self._retry = INSTANCE_RETRY_SECONDS

    def start(self) -> None:
        if sys.platform != "win32":
            # macOS and Linux keep the WebSocket, and keep the pairing token
            # with it. A named pipe is a Windows object; the Unix equivalent
            # would be a socket file, and deciding who may open one is a
            # genuinely different question - there is no interactive-user SID
            # to name, so it would come down to a mode, a group, or reading the
            # peer's credentials and having a policy about them. That is worth
            # designing rather than approximating, and until it is designed the
            # honest thing is to leave those platforms exactly as they were.
            log.info("named pipe not started: this platform uses the socket")
            return
        self._begin()

    def _begin(self) -> None:
        """Makes the first instance, then starts accepting on it.

        **The first instance is created here, before the thread, with
        ``FILE_FLAG_FIRST_PIPE_INSTANCE``** (ADR 0068): if another process
        created the name first, creation fails and the agent refuses to serve a
        pipe whose descriptor someone else chose. Same sentence as the Rust
        agent.
        """
        try:
            self._first_handle = self._create_instance(first=True)
        except Exception as error:  # noqa: BLE001 - pywintypes.error on Windows
            log.error(
                "%s already exists - another process created it first, "
                "so the agent will not serve it: %s", self._name, error,
            )
            self.refused = "the pipe name is already in use"
            return
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="inwire-pipe-accept", daemon=True,
        )
        self._accept_thread.start()
        self.serving = True
        log.info("listening on %s", self._name)

    def stop(self) -> None:
        self._stopping.set()

    # -- the threads ---------------------------------------------------------

    def _create_instance(self, first: bool):
        """Creates one pipe instance carrying the descriptor (Windows only).

        ``first`` adds ``FILE_FLAG_FIRST_PIPE_INSTANCE``, which fails the call
        when any process has already created the name (ADR 0068).
        """
        import win32file  # noqa: PLC0415
        import win32pipe  # noqa: PLC0415

        return win32pipe.CreateNamedPipe(
            self._name,
            # OVERLAPPED because the reader and the writer are two
            # threads on one handle; see the header. Without it a write
            # queues behind whatever read is outstanding.
            win32pipe.PIPE_ACCESS_DUPLEX | win32file.FILE_FLAG_OVERLAPPED
            | (FILE_FLAG_FIRST_PIPE_INSTANCE if first else 0),
            # BYTE mode both ways: the framing is ours, and message
            # mode would add a second, redundant idea of a boundary
            # that the two ends would then have to agree about twice.
            win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE
            | win32pipe.PIPE_WAIT | win32pipe.PIPE_REJECT_REMOTE_CLIENTS,
            MAX_PIPE_INSTANCES,
            READ_CHUNK, READ_CHUNK,
            0,
            _security_attributes(),
        )

    def _next_instance(self):
        """The instance to wait for a client on, or None once stopping.

        The first call hands over the instance made before the thread started.
        After that, a refusal is **not** a reason to stop - any user can take a
        slot - so it is logged once per failing streak and retried (ADR 0068).
        """
        if self._first_handle is not None:
            handle, self._first_handle = self._first_handle, None
            return handle
        failing = False
        while not self._stopping.is_set():
            try:
                return self._create_instance(first=False)
            except Exception as error:  # noqa: BLE001 - pywintypes.error on Windows
                if not failing:
                    failing = True
                    log.warning("could not create a pipe instance, retrying: %s", error)
                self._stopping.wait(self._retry)
        return None

    def _accept_loop(self) -> None:
        import pywintypes  # noqa: PLC0415
        import win32file  # noqa: PLC0415

        while not self._stopping.is_set():
            handle = self._next_instance()
            if handle is None:
                return
            try:
                if not self._await_client(handle):
                    win32file.CloseHandle(handle)
                    return
            except pywintypes.error as error:
                if self._stopping.is_set():
                    return
                log.warning("pipe accept failed: %s", error)
                win32file.CloseHandle(handle)
                # A tight retry loop on a persistent failure would fill the log
                # faster than anyone could read it.
                self._stopping.wait(1.0)
                continue

            threading.Thread(
                target=self._serve, args=(handle,),
                name="inwire-pipe-client", daemon=True,
            ).start()

    def _await_client(self, handle) -> bool:
        """Waits for one client, or for ``stop()``. False means stop."""
        import pywintypes  # noqa: PLC0415
        import win32event  # noqa: PLC0415
        import win32file  # noqa: PLC0415
        import win32pipe  # noqa: PLC0415
        import winerror  # noqa: PLC0415

        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            try:
                win32pipe.ConnectNamedPipe(handle, overlapped)
            except pywintypes.error as error:
                # The client can win the race between CreateNamedPipe and this
                # call, and Windows reports that as a failure. It is a success:
                # there is a client on the other end, which is all we asked.
                if error.winerror != winerror.ERROR_PIPE_CONNECTED:
                    raise
                return True

            while True:
                if win32event.WaitForSingleObject(overlapped.hEvent, 250) == win32event.WAIT_OBJECT_0:
                    return True
                if self._stopping.is_set():
                    # Bounded waits rather than INFINITE exist for this line:
                    # a pipe instance nobody ever connects to would otherwise
                    # pin this thread for the life of the process.
                    win32file.CancelIo(handle)
                    return False
        finally:
            win32file.CloseHandle(overlapped.hEvent)

    def _serve(self, handle) -> None:
        import pywintypes  # noqa: PLC0415
        import win32file  # noqa: PLC0415
        import win32pipe  # noqa: PLC0415

        outbound = _Outbound(MAX_OUTBOUND_FRAMES, MAX_OUTBOUND_BYTES)
        closed = threading.Event()

        def write(frame: bytes, records: int = 0) -> None:
            if closed.is_set():
                # **Raised, not returned.** This used to return silently while
                # `PipeConnection.send` tested a DIFFERENT flag - its own
                # `_closed` - so every send after the writer gave up returned
                # success and every frame in it was discarded. `_send_to_owner`
                # has an `except` that exists for exactly this and could never
                # fire. One flag decides now, and it decides out loud.
                raise ConnectionError("the pipe client has gone")
            outbound.put(frame, records)

        def close() -> None:
            closed.set()

        connection = PipeConnection(self._loop, write, close)
        # Diagnostics only, read through `getattr` the way `kernel_authenticated`
        # is, so the WebSocket transport needs no counterpart. This is the one
        # reading that tells "the pump is the bottleneck" (the sniffer queue is
        # pinned and this is empty) apart from "the client is slow" (both full),
        # and the two want opposite fixes.
        connection.outbound_depth = outbound.qsize
        connection.outbound_bytes = outbound.pending_bytes
        # Read by the agent into `capture_stats.droppedPipe`. A plain
        # attribute on the shared object rather than a callback, so the
        # count survives the connection being handed around.
        connection.outbound = outbound

        writer_thread = threading.Thread(
            target=self._write_loop, args=(handle, outbound, closed),
            name="inwire-pipe-write", daemon=True,
        )
        writer_thread.start()

        registration = asyncio.run_coroutine_threadsafe(self._register(connection), self._loop)
        try:
            self._read_loop(handle, connection, closed)
        finally:
            closed.set()
            connection.finish()
            # Wake the writer out of its wait so the handle is not closed under
            # an operation still referencing it.
            outbound.put(_SHUTDOWN)
            writer_thread.join(timeout=1.0)
            # `register`'s `finally` runs `handle_disconnect`, which is what
            # stops a capture whose owner has gone.
            registration.cancel()
            try:
                win32pipe.DisconnectNamedPipe(handle)
            except Exception:  # noqa: BLE001 - the handle may already be gone
                pass
            try:
                win32file.CloseHandle(handle)
            except Exception:  # noqa: BLE001
                pass

    def _read_loop(self, handle, connection: PipeConnection, closed: threading.Event) -> None:
        import pywintypes  # noqa: PLC0415
        import win32event  # noqa: PLC0415
        import win32file  # noqa: PLC0415

        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
        buffer = win32file.AllocateReadBuffer(READ_CHUNK)
        reader = pipe_frame.FrameReader()
        try:
            while not closed.is_set():
                win32event.ResetEvent(overlapped.hEvent)
                try:
                    win32file.ReadFile(handle, buffer, overlapped)
                except pywintypes.error:
                    return
                # Bounded, so `closed` is observed on a connection that has
                # gone quiet rather than only when bytes next arrive.
                while win32event.WaitForSingleObject(
                    overlapped.hEvent, 250,
                ) != win32event.WAIT_OBJECT_0:
                    if closed.is_set():
                        win32file.CancelIo(handle)
                        return
                try:
                    read = win32file.GetOverlappedResult(handle, overlapped, False)
                except pywintypes.error:
                    return
                if read == 0:
                    return
                try:
                    for frame in reader.push(bytes(buffer[:read])):
                        if frame.kind == pipe_frame.FRAME_JSON:
                            connection.deliver(frame.text())
                        # A client has no reason to send a binary frame, and
                        # guessing at one would be inventing a message.
                        else:
                            log.warning("pipe client sent a binary frame - ignoring")
                except pipe_frame.FramingError as error:
                    # Unrecoverable by construction: the stream position is no
                    # longer known, so there is nothing to resynchronise to.
                    log.warning("pipe framing error, dropping the client: %s", error)
                    return
        finally:
            win32file.CloseHandle(overlapped.hEvent)

    def _write_loop(self, handle, outbound: "_Outbound", closed: threading.Event) -> None:
        import pywintypes  # noqa: PLC0415
        import win32event  # noqa: PLC0415
        import win32file  # noqa: PLC0415

        overlapped = pywintypes.OVERLAPPED()
        overlapped.hEvent = win32event.CreateEvent(None, True, False, None)
        try:
            while True:
                frame = outbound.get()
                if frame is _SHUTDOWN or closed.is_set():
                    return
                win32event.ResetEvent(overlapped.hEvent)
                try:
                    win32file.WriteFile(handle, frame, overlapped)
                    # Waited to completion before the next frame is written:
                    # two outstanding writes on one handle have no defined
                    # order, and a packet batch delivered out of order is a
                    # capture that lies about the wire.
                    win32file.GetOverlappedResult(handle, overlapped, True)
                except pywintypes.error:
                    closed.set()
                    return
        finally:
            win32file.CloseHandle(overlapped.hEvent)
