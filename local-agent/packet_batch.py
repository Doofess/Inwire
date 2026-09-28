"""The binary packet frame: many captured packets in one WebSocket message.

Until 3.2.0 every captured frame was its own JSON text message with the bytes
base64-encoded inside it. That cost three things at once, and the agent's own
log is the evidence: 260,000+ frames dropped in a single session because the
client could not keep up.

  * **Scheduling.** Each frame scheduled its own coroutine on the event loop
    (`run_coroutine_threadsafe` per packet). At a few thousand packets a second
    the loop spent its time on scheduling rather than on sending, and the bound
    that exists to stop the agent growing without limit (MAX_PENDING_SENDS)
    started dropping frames long before the socket was actually saturated.
  * **Size.** base64 is +33% over the wire, and the JSON envelope around it
    repeated eleven field names per frame - for fields the browser then threw
    away, because whenever `raw` is present it re-dissects the bytes itself and
    overwrites every one of them.
  * **Parsing.** The browser ran `JSON.parse` and `atob` per frame on its main
    thread, inside the socket handler, before anything could be batched.

So packets now travel as raw bytes in a batched binary frame, and the metadata
that was only ever a fallback is simply not sent. Control messages - hello,
state, error, log, interface_stats, capture_stats - stay JSON text: there are a
handful of them a second at most, they are the messages a human ever needs to
read off the wire, and a binary control channel would buy nothing.

Layout (little-endian throughout; the browser reads it with a DataView, so no
field needs to be aligned):

    magic    4 bytes   'IWP1'
    version  u8        4
    flags    u8        reserved, 0
    count    u16       records in this frame

  then `count` records, each:

    seq        u32       per-capture sequence number (docs/decisions/0005)
    iface      u16       index into the interface list in hello/state
    capLen     u32       bytes actually present
    origLen    u32       length on the wire
    tsNs       u64       capture time, epoch nanoseconds
    bytes      capLen    the frame

**Both lengths are 32 bits since version 4** (ADR 0052), and the record is 22
bytes. The Rust agent captures at dumpcap's 262,144-byte snaplen and writes the
same frames into its own pcapng, so the wire has to carry a frame longer than
65,535 bytes - an offloaded send can be - where version 3 refused one. The
history below is why the record was 18; the four bytes it gave back are the
price of not refusing frames.

**`tsNs` was an f64 of microseconds until version 3.** Epoch nanoseconds are
past 2^53, so no float could carry the precision Npcap gives when asked for
it; the same eight bytes as an integer carry it exactly. This agent stamps in
microseconds - scapy activates its handle before we could ask for more - and
sends them as nanoseconds with three zeros, reporting `tsPrecision: 6` for
each interface so the app knows those zeros were never measured.

A record carries no source, destination, protocol or info. It never needed to:
the browser dissects the bytes with the same code an imported pcap goes
through. What the agent used to send in those fields was overwritten before it
was ever displayed.

**The record is 18 bytes and was 24** (version 2). Three fields paid for
themselves and one did not:

  * `_pad` was two reserved bytes on a layout the browser reads with a
    DataView, which needs no alignment. It bought nothing at all.
  * `capLen` was a u32 for a number that cannot exceed the snaplen, and a
    snaplen is a u16 in every capture format there is.
  * `origLen` was a second u32 holding, on every untruncated frame in
    existence, exactly what `capLen` already said. It is now the **difference**,
    which is 0 whenever nothing was truncated and still describes a 64 kB
    offloaded frame captured at 128 bytes.

Measured on a real 300,228-frame capture: 7.21 MB of framing becomes 5.40 MB.
Be honest about the size of that - it is **0.53% of the whole stream**, because
a captured frame averaged 1,101 bytes and nothing about framing was ever going
to matter beside the frame itself. On the 78,480 frames at or under 100 bytes
it is 6% of each record, which is where it shows.

**Six more bytes were available and deliberately left.** `seq` and `tsNs` are
largely redundant WITHIN a batch - a u16 delta and a u32 delta off a base in
the header would carry both, taking the record to 12 bytes. That encoding
cannot be produced by `encode_record`, because a record is encoded on the
**sniffer thread** and does not yet know which batch it will land in; deriving
the bases would move the encoding to the event loop, the thread that already
decides how fast the browser is fed. It would also make a record's meaning
depend on its batch, so the queue could no longer drop, reorder or re-batch
records freely - which is exactly what it does when a viewer falls behind.
Another 0.5% of this stream does not buy either of those.
"""

import struct

MAGIC = b"IWP1"
# 4 since both lengths became 32 bits; 3 since the timestamp became integer
# nanoseconds; 2 since the record shrank from 24 bytes to 18. The browser
# refuses a version it does not know rather than reading the old layout at the
# new offsets, which would produce plausible frames with wrong lengths instead
# of an error.
VERSION = 4

HEADER = struct.Struct("<4sBBH")
RECORD = struct.Struct("<IHIIQ")

assert HEADER.size == 8
assert RECORD.size == 22


def encode_record(seq: int, iface: int, ts_ns: int, orig_len: int, data: bytes) -> bytes:
    """One record, ready to be concatenated into a batch.

    Encoded on the sniffer thread - it is a struct pack and a bytes() of a
    frame that is already in memory, which is cheap enough to do there and is
    what lets the event loop see a queue of finished records rather than live
    scapy packets it would have to serialize itself. That placement is also why
    the record is self-contained rather than relative to its batch; see the
    module docstring.

    `orig_len` is the length on the wire. It is never sent as less than what
    was captured - a wire length below the frame's own bytes would be nonsense -
    so it is raised to `cap_len` instead.
    """
    cap_len = len(data)
    # **Refused, not masked.** The payload is appended in FULL, so a masked
    # length would have the decoder take its next record from inside a frame -
    # a plausible record read out of the middle of one, and the rest of the
    # batch discarded with no error anywhere. At 32 bits it takes a 4 GB frame.
    if cap_len > 0xFFFFFFFF:
        raise ValueError(
            f"a captured frame of {cap_len} bytes cannot be framed: "
            "the record's length field is 32 bits, and masking it would "
            "desynchronise the decoder rather than truncate the frame"
        )
    orig = min(max(orig_len, cap_len), 0xFFFFFFFF)
    return RECORD.pack(seq & 0xFFFFFFFF, iface & 0xFFFF,
                       cap_len, orig, int(ts_ns)) + data


def encode_batch(records) -> bytes:
    """Frames a list of encoded records. `records` must not be empty.

    The `+ data` in `encode_record` and the `join` here copy each frame's bytes
    twice, which looks like the obvious thing to remove with `pack_into` into
    one pre-sized bytearray. Measured, it is not worth it: 0.36 us a frame at a
    batch of 64 against 0.37 for pack_into, and 1.17 against 1.05 at a batch of
    256 - a 10% win at the larger size and a small loss at the smaller one,
    against a capture loop that costs 0.58 us a frame. Restructuring would also
    move the encode off the sniffer thread, which is where it is deliberately
    (see `encode_record`).

    **This used to end "and a driver that tops out near 12,000 frames/s", and
    that number is withdrawn.** It came from `capture_profile.py`'s
    `impliedFramesPerSecond`, which was `frames / wall` - the rate traffic
    happened to ARRIVE at, counting every microsecond the thread spent waiting
    as though it were work. It could never exceed the arrival rate, so it could
    never report a driver limit; it reported the link. The conclusion above
    does not depend on it - 0.36 against 0.37 microseconds is its own argument -
    but the figure should not be quoted again. `sustainableFramesPerSecond` is
    the honest one, and nothing has measured the driver with it yet.
    """
    count = len(records)
    if count == 0:
        raise ValueError("a batch with no records would say nothing")
    if count > 0xFFFF:
        raise ValueError("a batch holds at most 65535 records")
    return HEADER.pack(MAGIC, VERSION, 0, count) + b"".join(records)


def decode_batch(payload: bytes):
    """The inverse, for the tests. The browser has its own decoder in
    `src/services/agentBinary.ts`; this one exists so `test_protocol.py` can
    assert the two agree on a byte level rather than on a description."""
    if len(payload) < HEADER.size:
        raise ValueError("truncated header")
    magic, version, _flags, count = HEADER.unpack_from(payload, 0)
    if magic != MAGIC:
        raise ValueError(f"not a packet batch: {magic!r}")
    if version != VERSION:
        raise ValueError(f"unsupported batch version {version}")
    out = []
    offset = HEADER.size
    for _ in range(count):
        if offset + RECORD.size > len(payload):
            raise ValueError("truncated record header")
        seq, iface, cap_len, orig_len, ts_ns = RECORD.unpack_from(payload, offset)
        offset += RECORD.size
        if offset + cap_len > len(payload):
            raise ValueError("truncated record payload")
        out.append({
            "seq": seq,
            "iface": iface,
            "tsNs": ts_ns,
            "origLen": orig_len,
            "data": payload[offset:offset + cap_len],
        })
        offset += cap_len
    if offset != len(payload):
        raise ValueError("trailing bytes after the last record")
    return out
