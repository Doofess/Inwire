# 0010 - The agent receives raw frames and dissects nothing

**Status:** Accepted 2026-09-05 (agent 3.5.0)

## Context

`CLAUDE.md` has said since 3.2.0 that "Scapy is a capture driver here and
nothing else". That was half true. `conf.load_layers` was cut to `l2`/`inet`/
`inet6` so that importing `scapy.all` stopped loading seventeen hundred
protocol classes - but the classes that remained were still *used*, on every
frame, by the capture loop itself.

`sniff(opened_socket=sock, prn=...)` calls `SuperSocket.recv`, which is:

```python
cls, val, ts = self.recv_raw(x)
pkt = cls(val, **kwargs)          # <- the whole Ether/IP/TCP object graph
```

So every captured frame was dissected into a Python object graph before the
callback saw it. `packet_to_record` then read exactly three things from that
graph - `bytes(pkt)`, `len(pkt)` and `pkt.time` - and the first of those
**re-serialised the object scapy had just built from those same bytes**. The
agent was decoding a frame and re-encoding it in order to arrive back at the
bytes it was handed, and then throwing the decode away. The browser dissects;
nothing on the agent side had read a protocol field since 3.2.0.

Measured on the `inwire` fixture (12,858 real frames), the encode path per
frame:

| | per frame | implied ceiling |
|---|---|---|
| `Ether(raw)` + `bytes(pkt)` + `encode_record` | **83.36 us** | ~12,000 frames/s |
| `encode_record` on the raw bytes | **0.58 us** | ~1,700,000 frames/s |

**142.8x**, and ~83 us a frame of pure waste. The ~12,000 frames/s ceiling that
the old path implies matches the drops this project has actually seen: ADR 0003
records "260k+ drops on 3 Sep", and `droppedKernel` is by definition the
sniffer thread failing to drain the driver's ring in time.

## Decision

**The capture loop calls `recv_raw()` and never `recv()`.**

1. `sniff_on_interface` loops on `sock.recv_raw()` directly.
   `sniff_callback(raw, ts, iface_id)`, `packet_to_record(raw, ts, ...)` and
   `capture_time_us(ts)` all take the frame's bytes and libpcap's timestamp
   instead of a scapy packet.

2. **This is not a shortcut past something.** `recv_raw` is the complete
   primitive on both platforms that matter: the libpcap socket's returns
   libpcap's own per-packet timestamp, and Linux's `L2Socket.recv_raw` applies
   the `PACKET_OUTGOING` rule and fills the timestamp in itself. `recv()` is
   `recv_raw()` plus the dissection, and the dissection is the part with no
   reader.

3. **A socket that has not overridden `recv_raw` keeps `sniff()`.**
   `SuperSocket`'s base implementation returns `(conf.raw_layer, data, None)` -
   no timestamp at all - so an unknown platform falling through to it would
   silently trade every frame's capture time for throughput. That is the one
   trade this change must not make, so it is detected
   (`type(sock).recv_raw is SuperSocket.recv_raw`) and refused.

4. **Polling differs by socket, because the sockets differ.** A libpcap socket
   is opened with `to_ms=100`, so `recv_raw` returns on its own read timeout and
   a stop is honoured within 100 ms even on a silent adapter - tighter than the
   0.5 s the old `sniff()` loop gave. An `AF_PACKET` socket blocks indefinitely,
   so it is polled with `select()` on `CAPTURE_POLL_SECONDS` as before.

5. **A `None` from `recv_raw` is the read timeout, not an error.** It is skipped
   and the loop re-tests `stop_event`. Treating it as a frame would queue a null
   record; treating it as an error would end the capture at the first quiet
   moment on the wire.

## Why this was safe to do

The output had to be byte-identical, and it is. `bytes(Ether(raw)) == raw` was
verified for **all 27,640 frames of both fixture captures** before the
dissection was removed - so the round trip the agent was paying for was, in
every observed case, the identity function. `test_protocol.py` asserts the same
property on a synthetic frame, and the whole capture loop is exercised against
fake sockets covering the libpcap path, the `AF_PACKET` path, the read timeout,
and the base-`recv_raw` fallback.

## Consequences

- The sniffer thread is no longer the capture ceiling. **The Worker is**, at
  ~5,900 frames/s (`scripts/perf/throughput.ts`), of which dissection is 95%.
  That is the next thing to fix, and it is ADR 0001's unfinished migration.
- `stop_filter` is gone: it was a Python lambda invoked per frame that ignored
  its argument, and the loop tests `stop_event` itself now.
- `sniff()` is no longer re-entered every 0.5 s, so the `AsyncSniffer` state,
  session object and control `ObjectPipe` are no longer rebuilt twice a second
  per adapter.
- Nothing about the wire format, the message protocol or the drop counters
  changed. The version moved to 3.5.0 because agent *behaviour* did.

## Not done, deliberately

`counters.next_seq()` and `queue_packet()` still take one lock each, so the hot
path takes two. Merging them was in the plan; it is perhaps 0.2 us against the
83 us this ADR removes, and it would couple the capture counters to the agent's
send queue - two things that are separate on purpose. Left alone.
