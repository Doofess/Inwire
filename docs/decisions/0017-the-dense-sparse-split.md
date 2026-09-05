# 0017 - Dense columns and a sparse bag

**Status:** Measured 2026-09-05, not yet built. **Corrects the conclusion of
0013**, which said there was no cheap large win in `Packet.fields`.

## Context

After 0016, a resident record is 1,876 B a frame and `fields` is 1,431 B of it -
**76% of everything left**. 0013 had already looked for a way to shrink it and
found none worth taking:

> Interning the strings: 82 MB - taken. Rebuilding the bag in one go: 46 MB -
> not taken. **A column per key: WORSE.** One array per key over 122 keys
> measured at 976 B a frame against 294 B for one object per frame, because a
> key only a few frames carry still costs a slot in every frame.
>
> **So there is no cheap large win in `fields`.**

That conclusion has stood since, and it is what left "keep a recent window,
re-dissect beyond" as the only remaining idea - a project touching the display
filter, the colour chain, Apply as Column, Statistics and the export writers.

The question was re-opened by a different one: a user offered to give up export
and import file formats to unblock the work. Checking what that would actually
buy turned up the shape of the bag, and the shape says why 0013's column
experiment failed.

## The measurement

Over both fixtures' 27,640 frames, **682,570 entries across 123 keys - 24.7 a
frame**. The distribution is what matters:

| | |
|---|---|
| keys holding the first half of all entries | **15 of 123** |
| keys on >= 20% of frames ("dense") | **27** |
| entries those 27 hold | **583,108 - 85.4%** |

And the commonest are near-universal and tiny: `eth.ig` on every frame with 2
distinct values, `tcp.flags.syn` on 22,063 with 2, `eth.type` on 27,526 with 5,
`ipv6.nxt` on 22,996 with 4. They cost a full dictionary-mode property slot each
- about 58 B - to hold one bit.

**0013's experiment applied one representation to both halves.** A dense key is
cheap as a column and expensive as a property; a sparse key is the reverse.
Measured as a split (`scripts/perf/fields-split-cost.ts`):

| the same capture, three ways | per frame | at 1M |
|---|---|---|
| bag as today | 1,866 B | 1,866 MB |
| dense keys simply dropped | 524 B | 524 MB |
| **dense keys as columns** | **571 B** | **571 MB** |

**The split saves 1,295 B a frame - 69% of the whole record - and the columns
themselves cost 47 B.** It comes within 47 B of *deleting the data outright*,
which is the floor no representation can beat.

Nothing is given up. Every value is still there, still exact, still filterable;
only where it is stored changes.

## What this says about the trade that prompted it

Export was never the constraint, and giving up file formats would have paid a
real price for nothing:

| consumer | keys read from `fields` |
|---|---|
| CSV / XLSX (`packetToRow`) | **0** - it reads id, times, addresses, protocol, length, info, status, anomalies, raw bytes |
| classic pcap | 0 |
| **pcapng** | **3** (`inwire.process.name` / `.pid` / `.path`, for the EPB comment) |
| import | 0 |

Three keys of 123, on outbound frames only. The plan's "hard retain" note about
process attribution is still right - it cannot be re-derived - but it constrains
0.02% of the bag, not the bag.

## Decision

**Design the split; do not take the capability trade.** The 1,295 B a frame is
available without losing a single feature, which is strictly better than any
amount of feature removal, and it makes "re-dissect beyond a window" unnecessary
for the foreseeable size.

Not built yet, and these are the parts that need designing rather than
measuring:

- **Where the columns live.** They are indexed by buffer position, and the
  buffer trims - so either they rebase with it, or they are keyed some other
  way. This is the same coupling that made a `Uint8Array` colour index not worth
  it in 0015, and it needs a better answer here because the prize is 60x larger.
- **Presence is its own bit.** "Absent" and "zero" are different answers: a
  filter asking about a field a frame does not carry must not match it. That is
  why the measurement carries a `Uint8Array` of presence per column and counts
  its cost.
- **One accessor, not two call sites.** Everything reading `packet.fields[key]`
  today - `filter/compile.ts`, the colour chain, Apply as Column, Statistics,
  `processFields.ts` - has to go through something that knows which half a key
  lives in. `compile.ts` resolves field readers once at compile time, which is
  the right seam and already exists.
- **Which keys are dense is a property of the capture**, not of the registry.
  A capture of pure IPv4 has a different dense set from these two fixtures. The
  set has to be decided from what arrives, and changing it mid-capture means
  migrating a column - or the set is fixed from the registry's own layer list
  and simply accepts being wrong for unusual captures.
- **The Worker boundary.** Columns are typed arrays and would transfer rather
  than clone, which is cheaper than today - but the buffer is assembled on the
  main thread from many batches, so the columns have to be appended to, not
  replaced.

## Consequences

- 0013's "no cheap large win in `fields`" is superseded. Its three measurements
  were right; the conclusion drawn from them was too broad, because the column
  experiment tested the extreme rather than the split.
- The record would be ~571 B a frame, so a million frames is ~571 MB of
  summaries rather than 1,866 MB - and the buffer cap becomes a product decision
  rather than a memory one.
- The streaming filter deferred in 0015 stays deferred, and for a better reason:
  if `fields` fits, nothing needs re-dissecting, and the filter never becomes
  asynchronous at all.
