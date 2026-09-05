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
    version  u8        1
    flags    u8        reserved, 0
    count    u16       records in this frame

  then `count` records, each:

    seq      u32       per-capture sequence number (docs/decisions/0005)
    iface    u16       index into the interface list in hello/state
    _pad     u16       reserved, 0
    tsUs     f64       capture time, epoch microseconds
    origLen  u32       length on the wire
    capLen   u32       bytes actually present
    bytes    capLen    the frame

A record carries no source, destination, protocol or info. It never needed to:
the browser dissects the bytes with the same code an imported pcap goes
through. What the agent used to send in those fields was overwritten before it
was ever displayed.
"""

import struct

MAGIC = b"IWP1"
VERSION = 1

HEADER = struct.Struct("<4sBBH")
RECORD = struct.Struct("<IHHdII")

assert HEADER.size == 8
assert RECORD.size == 24


def encode_record(seq: int, iface: int, ts_us: float, orig_len: int, data: bytes) -> bytes:
    """One record, ready to be concatenated into a batch.

    Encoded on the sniffer thread - it is a struct pack and a bytes() of a
    frame that is already in memory, which is cheap enough to do there and is
    what lets the event loop see a queue of finished records rather than live
    scapy packets it would have to serialize itself.
    """
    return RECORD.pack(seq & 0xFFFFFFFF, iface & 0xFFFF, 0, float(ts_us),
                       orig_len & 0xFFFFFFFF, len(data)) + data


def encode_batch(records) -> bytes:
    """Frames a list of encoded records. `records` must not be empty."""
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
        seq, iface, _pad, ts_us, orig_len, cap_len = RECORD.unpack_from(payload, offset)
        offset += RECORD.size
        if offset + cap_len > len(payload):
            raise ValueError("truncated record payload")
        out.append({
            "seq": seq,
            "iface": iface,
            "tsUs": ts_us,
            "origLen": orig_len,
            "data": payload[offset:offset + cap_len],
        })
        offset += cap_len
    if offset != len(payload):
        raise ValueError("trailing bytes after the last record")
    return out
