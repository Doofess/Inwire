# 0018 - Implementing the field split

**Status:** Accepted 2026-09-05. Implements 0017, and **corrects its central
number twice**.

## The result

| | per frame | at 1M |
|---|---|---|
| resident record, before | 1,876 B | 1,876 MB |
| **resident record, after** | **663 B** | **663 MB** |
| `Packet.fields`, before | 1,431 B | 1,431 MB |
| `Packet.fields`, after | **154 B** (76 sparse + 78 columns) | 154 MB |

A 65% reduction, with no field, filter, column, statistic or export lost.
tshark parity is identical on both fixtures - every column at its floor, every
enforced count matching, and the two unenforced gaps unchanged. Throughput is
~19,580 frames/s.

## Two corrections to 0017

**0017 said the columns would cost 47 B a frame. They cost 242 as it modelled
them, and 78 as built.**

The 47 B was measured with `heapUsed`, and a typed array's bytes live *outside*
the JS heap. The measurement was counting the one `Array` of string references
that happened to be on the heap - 48 B a frame - and none of the `Float64Array`
and `Uint8Array` beside it. **This is the same trap ADR 0013 documented for raw
frame bytes**, walked into by the script written to avoid repeating 0013's other
mistake.

Corrected, and re-run against what 0017 actually modelled - a `Float64Array` per
numeric key and a byte of presence per key - the split **loses**:

| the same capture, three ways | per frame |
|---|---|
| bag as today | 757 B |
| dense keys simply dropped | 563 B |
| dense keys as naive columns | **805 B** |

So the design decisions taken while planning are not refinements. They are the
entire difference between a 49 B a frame loss and a 1,213 B a frame win:

- **Each column is the width of its field in its own protocol.** A TTL is a
  byte, a port is two, a sequence number is four - not eight apiece.
- **Presence is a packed bit, not a byte.** 33 keys is 5 bytes a row rather
  than 33.
- **A string column holds two-byte indices into a per-block table**, not
  eight-byte references.

242 B a frame becomes 78.

## What was built

**The dissector is untouched.** `Packet.fields` is assembled by scattered
assignment across some two hundred lines of `pcapParser.ts` and by
`Object.assign` from every sub-dissector, so there is no single write to
intercept - but there *is* a single moment when a finished frame is handed to a
buffer, and the split happens there: `buildPacketsFromFrames` for an import,
`App`'s flush for live capture.

**Blocks are referenced by their frames, not registered anywhere.** A frame
holds its block and its row; when the buffer trims the last frame that shares
one, it becomes unreachable and the collector takes it. Nothing rebases, nothing
is keyed by position in the buffer, and trimming, filtering and sorting all keep
working without knowing blocks exist. One writer per capture rather than per
flush, or a slow capture's small batches would each get a block whose fixed cost
exceeds what its columns save.

**The widths come from the protocols, not from the fixtures**, and two of them
differ from what the captures suggested. `tcp.flags` measured a maximum of 25,
which fits a `u8` - but the field is 12 bits and a frame carrying ECN exceeds
it. `tcp.len` measured 63,888, just under a `u16` - but segment offload
routinely presents segments past 64 KB. Both would have been silent truncation
on traffic nobody tested with. Where a field is computed rather than read off
the wire and no protocol bounds it, the column **widens at runtime** instead.

**Absence is a bit, because zero is a value.** `tcp.flags.syn == 0` is a filter
people write, and a field a frame does not carry must not match under any
operator - so presence cannot be folded into a sentinel.

**The bag remains the contract.** A frame that never joined a buffer - imported
from a CSV, or replayed to build a detail tree - carries its whole bag, has no
block, and reads exactly as it always did. `dissect/fieldAccess.ts` is the only
code that knows a value can be in two places, and the filter engine resolves
which half at *compile* time, so the 90 sparse keys never probe a column.

## What parity caught, and what it did not

`tcpRst` fell from 11 to 0 the moment the split went live, because the parity
harness reads `p.fields['tcp.flags.reset']` directly and lives under `scripts/`,
which the accessor migration had not covered. That is parity working: 27,640
frames of differential test finding a reader that no unit test would have.

It did **not** catch the second one, and nothing would have. `dense-fields.ts`
counts key frequency to check the declaration, and it too read the bag - so once
the split landed it found none of the dense keys, reported **0.0% coverage, and
passed**. A test that can no longer fail is worse than no test, and the only
reason it was noticed is that the number it printed was absurd. Both scripts now
read through the accessor.

The same class of bug was already sitting in `anonymise.ts`, which cleared
`fields` and nothing else: every address, port and sequence number stayed
readable through the block on a frame it had just declared anonymous. Its test
now proves the split happened *before* asserting the values are gone, so it
cannot pass vacuously.

## Consequences

- A million frames is ~663 MB of summaries rather than 1,876 MB, so the buffer
  cap is closer to a product decision than a memory one.
- The streaming filter deferred in 0015 stays deferred, and for a better reason:
  if the records fit, nothing needs re-dissecting and the filter never becomes
  asynchronous.
- `record-cost.ts` and `fields-split-cost.ts` both count `arrayBuffers` now. Any
  future measurement that touches a typed array and does not is wrong.
- `fields-split-cost.ts` reconstitutes the undivided bag before measuring, since
  the pipeline now performs the split it exists to evaluate.

## What is left

`info`, at 125 B a frame and the largest single component remaining. 60.7% of
its strings are distinct, and pooling them measured 20 B a frame *worse* than
leaving them alone (0016). An arena is the only remaining option, and at 125 MB
a million frames against the 1,213 already taken, it is not the next thing.
