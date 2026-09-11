"""Message framing for the pipe to the app.

The exact counterpart of ``src/services/agentFraming.ts``. The layout is::

    length  u32   bytes that follow, this field excluded
    kind    u8    0 = JSON control message, 1 = binary packet batch
    payload ...   length - 1 bytes

little-endian, matching ``packet_batch.py``.

Why this exists at all
----------------------

The agent was a WebSocket server on a loopback TCP port, which every process
on the machine can reach. That is why there was a pairing token, why there was
an origin allowlist, and why the user had to paste a 64-character string in
once - ``Origin`` is a header the client writes, so it kept an ordinary web
page out and stopped nothing else.

A named pipe with a security descriptor asks the operating system instead, and
the kernel's answer needs no secret. What the WebSocket also provided, and a
byte stream does not, is message boundaries and a text/binary distinction -
which is all this module is.

Nothing above it changes. ``packet_batch.py``'s 18-byte record, every control
message, and the fixed byte vectors both ends assert are transport-agnostic.

A declared length is not a length to trust
------------------------------------------

``MAX_FRAME_BYTES`` is checked before anything is allocated. This process is a
privileged service; a five-byte header claiming four gigabytes has to be a
refusal rather than an out-of-memory.
"""

from __future__ import annotations

import json
import struct
from typing import Iterator, NamedTuple

HEADER = struct.Struct("<IB")
HEADER_BYTES = HEADER.size

FRAME_JSON = 0
FRAME_BINARY = 1

# A batch is bounded by MAX_BATCH_BYTES (256 kB) and the largest control
# message is the adapter snapshot at ~6 kB. Eight megabytes is far above both
# and far below anything that could hurt.
MAX_FRAME_BYTES = 8 * 1024 * 1024


class Frame(NamedTuple):
    kind: int
    payload: bytes

    def text(self) -> str:
        return self.payload.decode("utf-8")

    def json(self) -> object:
        return json.loads(self.text())


class FramingError(Exception):
    """A stream that cannot be read as frames. Always closes the connection."""


def encode_frame(kind: int, payload: bytes) -> bytes:
    """Wraps one payload. ``kind`` is FRAME_JSON or FRAME_BINARY."""
    if kind not in (FRAME_JSON, FRAME_BINARY):
        raise ValueError(f"unknown frame kind {kind}")
    return HEADER.pack(len(payload) + 1, kind) + payload


def encode_json(value: object) -> bytes:
    """Wraps a control message.

    ``separators`` so the bytes are stable: the fixed vectors in
    ``test_protocol.py`` compare exact output, and a stray space between a
    colon and a value would make the two implementations disagree about
    something that does not matter.
    """
    text = json.dumps(value, separators=(",", ":"))
    return encode_frame(FRAME_JSON, text.encode("utf-8"))


class FrameReader:
    """Reassembles frames from a stream that arrives in arbitrary pieces.

    A pipe read boundary has nothing to do with a message boundary: one read
    can carry half a header and the next can carry nine whole batches. Both
    happen under load, and a reader that assumed one read was one message
    would work perfectly until the machine got busy.
    """

    def __init__(self) -> None:
        self._buffer = bytearray()

    def push(self, chunk: bytes) -> Iterator[Frame]:
        """Feeds bytes in and yields whatever whole frames they completed."""
        self._buffer.extend(chunk)
        while True:
            if len(self._buffer) < HEADER_BYTES:
                return
            declared, kind = HEADER.unpack_from(self._buffer, 0)
            # Before the payload is waited for, let alone copied.
            if declared < 1 or declared > MAX_FRAME_BYTES:
                raise FramingError(f"a frame declared {declared} bytes")
            total = 4 + declared
            if len(self._buffer) < total:
                return
            if kind not in (FRAME_JSON, FRAME_BINARY):
                raise FramingError(f"unknown frame kind {kind}")
            payload = bytes(self._buffer[HEADER_BYTES:total])
            del self._buffer[:total]
            yield Frame(kind, payload)

    @property
    def pending(self) -> int:
        """Bytes held waiting for the rest of their frame. For assertions."""
        return len(self._buffer)
