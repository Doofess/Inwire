# 0013 - What a million frames actually cost

**Status:** Accepted 2026-09-05. Supersedes the *reasoning* of the planned
"bytes stay in the Worker" work; see Decision.

## Context

The plan for a million-frame buffer had one large item in it: move
`Packet.rawBytes` off the main thread into the Worker, on the argument that raw
frames are what a big buffer is made of. Its own gate said to re-measure before
committing to it, and to stop if the numbers did not support it.

They do not.

## The measurement

Per frame, over the `inwire` fixture's 12,858 distinct frames, with
`node --expose-gc`:

| | per frame | at 1M frames |
|---|---|---|
| **summary object** | **2,342 B** | **2,342 MB** |
| raw frame bytes | 1,176 B | 1,176 MB |
| | | **3,518 MB** |

And within the summary:

| component | per frame | at 1M |
|---|---|---|
| **`Packet.fields`** | **1,174 B** | **1,174 MB** |
| `info` | 122 B | 122 MB |
| `expert` | 95 B | 95 MB |
| `source` / `destination` | 90 B | 90 MB |
| `frameProtocols` | 85 B | 85 MB |

**The summaries are the larger half, and `Packet.fields` alone is as large as
every raw frame in the capture put together.**

### The earlier number was wrong

`scripts/perf/buffer-cost.ts` reported 209 B per summary, and that figure was
used to claim raw bytes were 85% of a big buffer. It grew an array of
`{...packet}` shallow copies and divided out the heap difference - and a shallow
copy shares every string, every `fields` object and every array with the packet
it came from. It measured an object header and nothing the object points at.
Corrected in the same change as this file.

### Relocating bytes does not reduce memory

A `Uint8Array`'s backing store is external; it does not appear in `heapUsed` and
is not bounded by the V8 heap limit. And a dedicated Worker shares its page's
renderer process, so moving the bytes there changes **which heap holds them, not
how much the tab holds**. The planned item would have moved a third of the
problem sideways.

## Decision

1. **"Bytes stay in the Worker" is not the way to a million-frame buffer**, and
   is not done. It addresses the smaller half of the cost and does not reduce
   the total.

2. **The bytes are already on disk.** `toStoredFrame` writes `frame.raw` for
   every frame, and the store is keyed by frame id. Nothing needs relocating for
   them to stop being resident - the buffer simply does not know it can forget
   them and read them back. That is the cheap 1,176 MB, and it needs no Worker
   protocol change, no typed columns and no OPFS.

3. **`Packet.fields` is the real target**, and it is what finally justifies
   ADR 0003's typed-column store - on grounds ADR 0003 never had. 0003 proposed
   columns to make crossing the worker boundary cheap; 0007 measured that and
   correctly refuted it. This is a different argument: not the cost of *moving*
   a summary, but the cost of *holding a million of them*. 0007 stands, and its
   scope is the boundary.

4. **Order, cheapest first.** Each step is worth doing alone and none of them
   requires the next:

   | step | frees at 1M | shape |
   |---|---|---|
   | bytes not resident, read back by id | 1,176 MB | store gains a by-id read; consumers fetch |
   | `fields` interned or columnar | **~145 MB, not ~1,100** | see below |
   | the rest of the summary | ~400 MB | only if the first two are not enough |

## What `Packet.fields` turned out to be

The table above first said "up to ~1,100 MB", on the assumption that a bag
costing 1,174 B a frame had most of that available to a better representation.
Measured (`scripts/perf/fields-cost.ts`), it does not:

| | |
|---|---|
| entries per frame | mean 22.5, p95 34 |
| distinct keys in the capture | 122 |
| values | 216,191 number, 73,187 string, 0 bool |
| distinct string values | **434**, i.e. 98.8% of string content repeats |

Three candidate fixes, measured rather than argued:

- **Interning the strings: 82 MB at 1M** - taken, and it turned out to be 145 MB
  once `Packet.source` and `Packet.destination` came with it. The address
  formatters now pool their results (`services/addressFormat.ts`), which is the
  same shape as the `resolveMacName` memo in 0011: a value computed per frame
  over a domain of a few dozen. Verified by counting duplicate string objects
  afterwards: zero.
- **Rebuilding the bag in one go: 46 MB at 1M** - not taken. Real but small, and
  it would put an allocation in the hot path for 4%.
- **A column per key: WORSE.** One array per key over 122 keys measured at
  976 B a frame against 294 B for one object per frame, because a key only a few
  frames carry still costs a slot in every frame. ADR 0003's typed-column store
  would need presence bitmaps and per-key encoding to beat the object it
  replaces - it is not the free win it looks like, and the naive version is
  three times the size.

An earlier reading of that last comparison suggested rebuilding would free
~880 MB. It would not: `{...fields}` shares its strings and numbers with the
object it copies, so it measures structure alone. The direct test - replace every
bag, drop the originals, collect, measure - is the 46 MB above. Recorded because
the wrong number was convincing enough to act on.

**So there is no cheap large win in `fields`.**

> **Superseded 2026-09-05 by `0017-the-dense-sparse-split.md`.** The three
> measurements above are right; the conclusion drawn from them was too broad.
> The column experiment gave every one of the 122 keys a column, which is why a
> key a few frames carry cost a slot in all of them - it tested the extreme
> rather than the split. Measured again with columns for only the 27 keys
> present on 20% or more of frames, and the object kept for the rest, the saving
> is **1,295 B a frame**: within 47 B of deleting the data outright, and with no
> capability given up at all. It is ~1,030 MB at a million
frames after interning, and getting it materially lower means a real structural
change, with a measurement showing the replacement is smaller than what it
replaces before it is written.

## Consequences

- A million frames is ~3.5 GB today, so the buffer cap stays where it is until
  at least the first step lands. Raising it first would trade dropped frames for
  a dead tab, which is the trade the plan already warned against.
- Anything reading `Packet.rawBytes` on the main thread becomes a caller that
  may have to wait for them. Most only ever want the selected frame or one
  stream; export and anonymise want every frame, and are the two that decide how
  the first step is shaped.
- The measurement tooling is committed, so the next person does not have to take
  any of this on trust - and, given this file exists because a measurement was
  wrong, should not.
