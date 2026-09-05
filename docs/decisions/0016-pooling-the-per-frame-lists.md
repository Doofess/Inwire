# 0016 - Pooling the per-frame lists

**Status:** Accepted 2026-09-05. Continues 0013's step four, and replaces the
encodings it proposed.

## Context

The plan's last step was to compact the frame record component by component, in
the order `frameProtocols` → bitmask, `analysisFlags` → bitmask, `expert` →
severity byte, `info` → arena, with `fields` last.

That order was asserted, not measured. The one number behind it -
`SUMMARY_BYTES_PER_FRAME = 2342` in `scripts/perf/buffer-cost.ts` - is a
**hardcoded constant printed as though it were a measurement**, and it was stale
by two changes (address pooling took it down, `colorSlot` put some back).

## The measurement

`scripts/perf/record-cost.ts`, added by this work: dissect both fixtures for
real, strip one component from every frame, and compare what the heap still
holds.

Getting the method right took three attempts, and the two failures are worth
recording because both produced numbers rather than errors:

- **Repeating one fixture to 200,000 frames** shares string objects across the
  copies, so `info`, `source`, `destination` and `protocolLabel` all measured
  **0 B a frame**. Not a small number - no number. This is the same shallow-copy
  mistake that once reported a summary at 209 B instead of 2,342 (ADR 0013).
- **Rebuilding each record from JSON** fixes the strings and breaks two other
  things: it undoes the address pooling the dissector does, charging pooled
  strings as though they were per-frame, and it builds `fields` with a known
  shape where the dissector assigns keys one at a time. It reported `fields` at
  451 B against a real 1,431.

So nothing is copied: the records are the dissector's own. The cost is a full
dissection per component, and a noise floor that is measured and printed, with
rows below it marked as not readings.

| component | before | plan's proposal |
|---|---|---|
| **`fields`** | **1,407 B** | last |
| `info` | 137 B | arena |
| `frameProtocols` | 115 B | bitmask |
| `expert` | 75 B | severity byte |
| `analysisFlags` | 25 B | bitmask |
| whole record | 2,080 B | |

**The plan's order is the reverse of the costs.** The four components it does
first are 352 B between them; the one it leaves for last is 1,407 B, 68% of the
record. Doing the cheap four first is defensible on risk - `fields` is much the
hardest - but the expected payoff should be stated as the 17% it is.

## Decision

### 1. Pool the lists; do not encode them

`frameProtocols`, `analysisFlags` and `expert` have very few distinct values.
Measured over both fixtures' 27,640 frames:

| | distinct | frames with none |
|---|---|---|
| protocol chains | **21** | - |
| analysis flag sets | **13** | 23,898 (86%) |
| expert finding sets | **209** | 18,894 (68%) |

So one array per distinct list replaces one per frame
(`services/dissect/tokenPool.ts`), and the result is:

| component | before | after |
|---|---|---|
| `frameProtocols` | 115 B | 0 B |
| `analysisFlags` | 25 B | 0 B |
| `expert` | 102 B | 15 B |
| **whole record** | **2,080 B** | **1,876 B** |

**A bitmask was the wrong answer and would have broken something.** The protocol
hierarchy reads `frameProtocols` **in nesting order** - a token's position is
what makes it a child of the layer before it, which is how `quic` came to sit
under the TLS it carries - and a set of bits has no order. Pooling keeps each
array exactly as it was: same contents, same order, same type. Nothing
downstream changes, and there is no decode step on the read side.

Pooling turns a per-frame value into shared mutable state, which is the actual
risk here, so the pooled arrays are **frozen** and
`scripts/dissect/token-pool.ts` holds what that has to guarantee: equal lists
share, unequal ones never do (including reorderings and the `join(':')`
collision a careless key would allow), order survives, a writer throws, and the
pool is bounded and degrades to unpooled rather than to wrong.

### 2. `info` is not worth pooling - measured, not assumed

16,766 of 27,640 `info` strings are distinct (60.7%), so pooling would share the
other 39%. It **costs more than it saves**: a pool of 16,766 entries is larger
than the 10,874 duplicate strings it removes.

```
held, info as dissected   54.83 MB
held, info pooled         55.37 MB   (includes the pool itself)
difference                  -20 B/frame
```

An arena is the only remaining option for `info`, and it is a large change -
every consumer reads `packet.info` as a string - for 138 MB at a million frames,
against `fields` at 1,431 MB. Not now.

## What the saving actually is, per path

This matters and is easy to overclaim. The pool lives wherever dissection
happens, and live-captured frames cross a `postMessage` on the way to the
buffer:

| path | sharing | frozen |
|---|---|---|
| **import** (main thread dissects) | full - one array per distinct list | yes |
| **live capture**, within one flush | preserved | **no** |
| **live capture**, across flushes | lost | - |

Structured clone preserves references *within* one message and not between two,
and the Worker posts a whole flush as one message - so each batch contributes
~21 chain arrays rather than one per frame. The saving is therefore proportional
to how many frames a flush carries, which is proportional to the capture rate:
a busy capture, which is the one that fills the buffer, gets nearly all of it; a
trickle gets little, and never fills the buffer either.

Structured clone also does **not** preserve frozen-ness, so the freeze catches a
would-be mutation in the Worker and on the import path but not on a
live-captured frame in the main thread's buffer. It is a guard, not a
guarantee - which is why the readers were checked by hand as well.

## Consequences

- 204 B a frame, 204 MB at a million, for no change to any consumer.
- Throughput is unchanged: ~19,259 frames/s sustained, against ~19,178 before.
- tshark parity is identical on both fixtures.
- `scripts/perf/buffer-cost.ts` still prints its hardcoded 2,342. It should read
  from a measurement or say plainly that it is quoting one; leaving a constant
  that looks like a reading is how this step got its order wrong.

## What is left

`fields`, at **1,431 B a frame - 76% of what remains**. ADR 0013 already
measured the encodings: interning gave 82 MB, rebuilding 46 MB, and a column per
key was *three times worse* than the object it replaced. There is no cheap large
win in it.

The remaining idea is 0013's own - keep it for a recent window and re-dissect
beyond - and it is a project rather than a change, because everything reads it:
the display filter, the colour chain's first match, "Apply as Column", the
Statistics tables, and the CSV/XLSX writers. Re-dissecting on demand also makes
filtering asynchronous, which needs the streaming pass measured and deferred in
ADR 0015. That pass and this are the same piece of work, and it should be taken
as one.
