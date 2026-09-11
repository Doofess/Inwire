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

Reading and writing use blocking pywin32 calls on dedicated threads, which
hand off to the event loop with ``call_soon_threadsafe``. The alternative,
``loop.start_serving_pipe``, integrates with the proactor properly but creates
its pipe instances itself - with the creating process's default DACL, which for
a LocalSystem service admits SYSTEM and administrators and therefore **not the
unelevated app this exists to serve**. Passing our own security descriptor
means creating the instances ourselves, and once we are doing that the
threads are the simpler half.

It is also the pattern the agent already uses everywhere else: the sniffer is
threads feeding the loop, for the same reason.
"""

from __future__ import annotations

import asyncio
import logging
import queue
import sys
import threading
from typing import Awaitable, Callable, Optional

import pipe_frame

log = logging.getLogger("inwire.pipe")

#: Where the app looks. One instance per connected client.
PIPE_NAME = r"\\.\pipe\inwire-agent"

#: How many connections may exist at once.
#:
#: More than one because the ownership model still means something: a second
#: Windows user logged into the same machine runs their own copy of the app
#: against the one machine-wide service, and `capture_busy` is what arbitrates.
MAX_PIPE_INSTANCES = 8

#: Read buffer. A batch is capped at 256 kB and a control message is smaller.
READ_CHUNK = 64 * 1024

#: Queued outbound frames before a slow reader is dropped.
#:
#: The same reasoning as ``MAX_QUEUED_PACKETS`` in the sniffer: backpressure
#: has to end somewhere, and a client that cannot keep up must cost the client
#: rather than the agent's memory.
MAX_OUTBOUND_FRAMES = 4096

_SHUTDOWN = object()


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

    async def send(self, data) -> None:
        if self._closed:
            raise ConnectionError("the pipe client has gone")
        if isinstance(data, str):
            frame = pipe_frame.encode_frame(pipe_frame.FRAME_JSON, data.encode("utf-8"))
        else:
            frame = pipe_frame.encode_frame(pipe_frame.FRAME_BINARY, bytes(data))
        self._write(frame)

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

    def start(self) -> None:
        if sys.platform != "win32":
            # macOS and Linux keep the WebSocket for now; their agent is
            # installed from the tarball and is not bundled with the app yet.
            log.info("named pipe not started: this platform uses the socket")
            return
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="inwire-pipe-accept", daemon=True,
        )
        self._accept_thread.start()
        log.info("listening on %s", self._name)

    def stop(self) -> None:
        self._stopping.set()

    # -- the threads ---------------------------------------------------------

    def _accept_loop(self) -> None:
        import pywintypes  # noqa: PLC0415
        import win32file  # noqa: PLC0415
        import win32pipe  # noqa: PLC0415

        while not self._stopping.is_set():
            handle = None
            try:
                handle = win32pipe.CreateNamedPipe(
                    self._name,
                    win32pipe.PIPE_ACCESS_DUPLEX,
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
                win32pipe.ConnectNamedPipe(handle, None)
            except pywintypes.error as error:
                if self._stopping.is_set():
                    return
                log.warning("pipe accept failed: %s", error)
                if handle is not None:
                    win32file.CloseHandle(handle)
                # A tight retry loop on a persistent failure would fill the log
                # faster than anyone could read it.
                self._stopping.wait(1.0)
                continue

            threading.Thread(
                target=self._serve, args=(handle,),
                name="inwire-pipe-client", daemon=True,
            ).start()

    def _serve(self, handle) -> None:
        import pywintypes  # noqa: PLC0415
        import win32file  # noqa: PLC0415
        import win32pipe  # noqa: PLC0415

        outbound: queue.Queue = queue.Queue(maxsize=MAX_OUTBOUND_FRAMES)
        closed = threading.Event()

        def write(frame: bytes) -> None:
            if closed.is_set():
                return
            try:
                outbound.put_nowait(frame)
            except queue.Full:
                # A reader that cannot keep up costs itself, not the agent.
                log.warning("pipe client fell too far behind - dropping it")
                closed.set()

        def close() -> None:
            closed.set()

        connection = PipeConnection(self._loop, write, close)

        def writer() -> None:
            while not closed.is_set():
                try:
                    frame = outbound.get(timeout=0.2)
                except queue.Empty:
                    continue
                try:
                    win32file.WriteFile(handle, frame)
                except pywintypes.error:
                    closed.set()
                    return

        writer_thread = threading.Thread(target=writer, name="inwire-pipe-write", daemon=True)
        writer_thread.start()

        registration = asyncio.run_coroutine_threadsafe(self._register(connection), self._loop)
        reader = pipe_frame.FrameReader()
        try:
            while not closed.is_set():
                try:
                    result, data = win32file.ReadFile(handle, READ_CHUNK)
                except pywintypes.error:
                    break
                if result != 0 or not data:
                    break
                try:
                    for frame in reader.push(bytes(data)):
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
                    break
        finally:
            closed.set()
            connection.finish()
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
