# 0015 - The colour index, and a strip that fills rather than blocks

**Status:** Accepted 2026-09-05.

## Context

The plan this comes from asked for a **colour index**: the matched rule computed
once and kept as one byte a frame, so the packet list and the minimap never walk
the rule chain and `fields`, `frameProtocols`, `analysisFlags` and `rawBytes`
can eventually stop being resident.

`ColorRulesEngine` already memoised, in a `WeakMap<Packet, ColorRule | null>`,
so the premise needed checking before anything was built on it - two premises in
this same plan had already failed measurement (the tree was 3.3% of dissection,
not the bulk of it; raw bytes were the smaller half of a buffer, not the larger).

## The measurement

`scripts/perf/color-index-cost.ts`, over the inwire fixture's frames repeated to
each buffer size, against the shipped 21-rule chain:

| buffer | cold pass | warm pass |
|---|---|---|
| 10,000 | 27.8 ms | 0.5 ms |
| 50,000 | 120.3 ms | 1.9 ms |
| **100,000** (today's cap) | **202.1 ms** | 6.5 ms |
| 1,000,000 | **1,985.3 ms** | 103.8 ms |

| holding the answer | per frame | at 1M |
|---|---|---|
| `WeakMap<Packet, ColorRule>` | 41 B | 41 MB |

Both premises hold, and the first one holds harder than expected. **The cold
pass is not hypothetical: it happens on every colour-rule edit, today.**
`App.tsx` builds a new `ColorRulesEngine` whenever the chain changes, a new
engine has an empty memo, and the minimap paints *every frame in the buffer* on
every repaint - synchronously, inside a layout effect. So a rule edit at the
current 100,000 cap is a 202 ms stall, and the plan's own UX review was wrong
about this in the user's favour: it recorded a rule edit as "effectively
instant, because the re-match is lazy". Visible rows are lazy. The minimap is
not.

## Decision

### 1. The answer lives on the packet

`Packet.colorSlot` is one number packing **which engine decided** with **which
rule it decided**. The engine writes it on first match and reads it thereafter.

| | per frame | warm pass at 1M |
|---|---|---|
| `WeakMap` | 41 B | 103.8 ms |
| `Packet.colorSlot` | **15 B** | **22.7 ms** |

Not the 1 B the plan projected, and the gap is worth recording: 1 B is what a
`Uint8Array` indexed by buffer position would cost, and reaching it would mean
the colour engine owning the buffer's ordering and rebasing that array every
time the buffer trims. That is a coupling worth more than the 14 B it saves, so
the side array is measured in the script and deliberately not built.

**The generation is what makes a cache on a shared mutable object safe.** A
packet outlives the engine that coloured it, so an edited chain would otherwise
read the previous chain's decision as its own and paint frames with a rule they
no longer match. Every engine takes a number no engine has had; a cached answer
carrying a different one is not recognised. That also means an edited chain
needs **no invalidation pass** over the buffer - the old answers are simply not
its answers.

A chain longer than 254 enabled rules cannot be encoded, and then the engine
**stops caching** rather than wrapping. Wrapping would hand back a rule the
frame did not match, which is the one failure worse than being slow.

### 2. The minimap fills; it never blocks

The first pass paints only what is already decided - instant, since on an
ordinary repaint that is everything - and the rest is decided in ~6 ms slices
between animation frames.

A row nobody has coloured yet is painted in the theme's own ground, the same as
a row matching no rule. That ambiguity is deliberate and is the lesser of the
two: the alternative is showing a colour that is not this chain's answer, and a
wrong colour is worse than a late one.

`matchedRuleIfKnown` is what makes this expressible. `getPacketStyle` returns
`{}` for a frame that matched nothing, which is an answer; this returns
`undefined` for a frame nothing has asked about, which is not one. Painting the
two the same way is precisely how a strip would show a chain's decision for
frames it never evaluated.

The hint while it catches up is a pulsing dot, not a progress bar, and the
distinction is the point: **nothing is waiting.** The list is complete and
interactive throughout, and a bar filling would claim otherwise. The slice
budget is a clock rather than a row count, because a row holds one frame at
10,000 and eighty at a million.

## Consequences

- A colour-rule edit no longer stalls the main thread, at any buffer size.
- `Packet.colorSlot` is never persisted and never exported: `toStoredFrame` and
  the export writers both build explicit objects, so it is inert in both. A
  restored frame arrives without it and is matched on first sight.
- Themes still cost nothing to switch. What is cached is the *rule*, not a pair
  of colours, so `resolveRuleColors` applies the theme afterwards and no theme
  change invalidates anything - unchanged from the `WeakMap`.
- tshark colour parity is identical on both fixtures (99.99% and 99.98%).
- The properties that make the cache safe are in `scripts/color-rules/library.ts`
  and are about staleness rather than speed: a new chain must not read the old
  chain's answer, "matched nothing" must come back as a decision rather than as
  an absence, and an over-long chain must decline to cache rather than wrap.

## What this does not do

It does not retire `fields`, `frameProtocols` or `analysisFlags` from the
resident record - the rule chain still reads them on the first match, and the
first match still has to happen. The index is a **precondition** for that work
(ADR 0013's step four), not the work itself. A frame whose `fields` had been
dropped could not be re-matched after a rule edit at all, so whatever replaces
them has to answer the chain, or the chain has to stop asking.
