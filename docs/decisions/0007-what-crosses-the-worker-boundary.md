# 0007 - What crosses the worker boundary: bytes yes, tree no

**Status:** Accepted 2026-09-04 (Phase 11)

> **Amended by [0049](0049-a-frames-tree-is-rebuilt-from-its-own-record.md).** The
> boundary below still stands - bytes cross, trees do not. What changed is how a
> tree that was not carried gets built: from the frame's own record, written at
> arrival, rather than by replaying its conversation on the click. The replay
> described here is now the fallback for a frame with no record.

## Context

ADR 0003 decided that the whole pipeline moves into one Worker and that it
posts "column rows and new-frame deltas" to the main thread, with the tree and
the bytes fetched per frame on request. That was written before anything had
been measured, and it made two claims at once - that a whole `Packet` is too
expensive to clone, and that the bytes are the expensive part of it.

`scripts/perf/clone-cost.ts` measures both on the `inwire` fixture (12,858 real
frames, dissected by the real parser):

| | per frame | share of dissection | 100k frames |
|---|---|---|---|
| dissect | 178 us | - | - |
| clone whole `Packet` | **57 us** | 32 % | - |
| clone without `layers` | **5.1 us** | 2.9 % | - |
| clone without `layers` or `rawBytes` | 4.0 us | 2.2 % | - |
| resident: raw frame bytes | 1.2 kB | | 117 MB |
| resident: raw + protocol tree | 10.6 kB | | **1.06 GB** |

Both halves of the assumption were wrong in the same direction. The **tree** is
the entire cost - it is 91 % of the clone and 89 % of the memory. The **bytes**
are almost free: carrying them adds 1.1 us per frame to the clone and are what
make a 100,000-frame buffer 117 MB instead of a gigabyte.

The difference matters because of what depends on each. The bytes are read by
the pcap/pcapng writer, Follow Stream, the hex view and session persistence -
every frame in the buffer, not just the selected one. The tree is read by
exactly one thing: the detail pane, for one frame at a time.

## Decision

**The bytes ride along on every posted `Packet`; the tree stays in the Worker.**

1. The Worker posts a `Packet` with `rawBytes` intact and `layers: []`. Export,
   Follow Stream, the hex view, the byte-range highlighter and session
   persistence keep working on the main thread with no change at all.
2. `Packet.expert` carries the frame's findings as a flat list, published by
   the summary pass. Expert Information aggregates over the whole buffer and
   used to get there by walking every frame's tree; with the tree gone it needs
   the findings themselves, which is what ADR 0001's `DissectSummary.expert`
   was for.
3. The detail pane asks for a tree by frame number. The Worker answers from a
   bounded cache of recently dissected trees (`DETAIL_CACHE_FRAMES`), and on a
   miss **replays that frame's stream** through fresh trackers and dissects the
   target with the tree kept.

   Replay rather than retention, because the tree of a frame in the middle of a
   TLS conversation is not a function of its own bytes: the record cursor, the
   QUIC keys, the DNS and ICMP pairings and the TCP relative sequence numbers
   are all state built up by the frames before it. Wireshark re-dissects for
   the same reason. A stream is selected by five-tuple
   (`services/followStream.ts`), which is bounded by the buffer and is usually
   a few hundred frames.
4. Import and session restore run in the same Worker, so a frame's shape does
   not depend on where it came from - the property that already makes live
   capture and file import share `decodeRawEthernetPacket`.

## Consequences

- The main thread never dissects. It never parses JSON per packet, never
  base64-decodes, and never advances a tracker.
- A 100,000-frame buffer costs ~117 MB of bytes plus ~60 MB of summaries on the
  main thread, and the Worker holds trees for the most recent
  `DETAIL_CACHE_FRAMES` only.
- Selecting a frame is now asynchronous. The detail pane renders its columns
  and hex dump immediately (both come off the packet) and fills the tree in
  when it arrives.
- A replayed tree is rebuilt from the frames still in the buffer. When a
  stream's earlier frames have been trimmed away the replay starts mid-stream,
  and the tree says so rather than presenting sequence numbers relative to a
  base it had to invent.
- ADR 0003's typed-array column store is **not** built. It exists to make the
  packet list cheap to render, and the list already renders from a windowed
  slice; the measurement above says the boundary was never the problem the
  column store was proposed to solve.
