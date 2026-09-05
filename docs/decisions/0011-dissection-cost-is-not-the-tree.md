# 0011 - Dissection's cost was not the tree

**Status:** Accepted 2026-09-05

## Context

ADR 0001 specified a two-phase dissector: `dissectSummary` "must be O(bytes)
and allocate no tree nodes", with `dissectTree` run on demand. The interfaces
were written into `src/services/dissect/types.ts` and the migration was never
done - `decodeRawEthernetPacket` still builds the full `ProtocolLayer[]` for
every frame, and the Worker discards ~92% of them within one flush window.

That looks like an obvious performance bug, and the plan for this work assumed
it was: finish the migration, and the Worker's per-frame cost falls from ~115 us
to under 25 us.

**It was measured before it was acted on, and the assumption was wrong.**

`scripts/perf/tree-cost.ts` counts the tree a real capture actually produces -
4.1 layers and 68.2 fields per frame - and times allocating that many
equivalent objects:

| | per frame |
|---|---|
| dissection, tree built | 166.65 us |
| allocating the same tree shape | **5.44 us** |

**3.3%.** Removing the tree could not have delivered what was expected of it,
because building the tree's *objects* was never the cost.

## What the cost actually was

A CPU profile (`node --cpu-prof`) of a full dissection run put one function at
**38% of the entire profile, and more than half of all dissection time**:

```
self%    ms     function
38.34   1269     formatArrivalTime   services/pcapParser.ts
```

`formatArrivalTime` constructed `new Intl.DateTimeFormat(...)` on every call,
and is called twice per frame - once local, once UTC. Constructing one resolves
a locale and initialises ICU; it measured at ~49 us. A 12,858 frame capture
built 25,716 of them and threw every one away.

The two formatters are now module-level lazy singletons, and the six
`parts.find()` scans per call became one pass.

| | before | after |
|---|---|---|
| dissect + trackers | 161.75 us/frame | **~45 us/frame** |
| total per frame | 169.75 us | **~53 us** |
| sustained Worker ceiling | 5,891 frames/s | **~19,000 frames/s** |
| flushes over the 100 ms budget | 3 of 26 | **0 of 26** |

Output is unchanged: old and new implementations were compared over 120,234
formattings spanning DST boundaries, leap days, year ends and both time zones,
with zero mismatches, and both parity fixtures hold every column at its floor.

`resolveMacName` was the same shape of mistake - a pure function of a MAC
string, called twice a frame over a domain of a couple of dozen addresses,
recomputing the same answers. Memoised (capped at 4,096 entries).

## Decision

1. **The ADR 0001 migration is not justified by throughput.** Its measured
   ceiling is now ~6% of dissection. It remains the right *contract* - the tree
   is 89% of a buffer's memory (ADR 0007) and the Worker already discards most
   of them - so it stays a memory and design argument, not a speed one. Anyone
   picking it up should not expect it to move the frame rate.

2. **Expensive objects are constructed once, and a script enforces it.**
   `scripts/perf/hot-path-allocations.ts` fails on a `new Intl.*`,
   `new TextDecoder` or `new TextEncoder` inside a function body anywhere under
   `src/services/`. It found four more of the same kind on its first run
   (`crypto/hkdf.ts`, `crypto/md5.ts`, `dissectors/tls.ts`), all now hoisted.

   The rule is about *where the line is*, not about whether the caller looks
   hot, because "this one is not on a hot path" is the exact reasoning that put
   the formatter where it was. The lazy-singleton form (`x ??= new ...`) passes:
   it runs at most once, and it keeps locale-data loading out of a Worker's
   startup.

3. **Measure before refactoring.** Both numbers this rests on - the 3.3% tree
   share and the 38% formatter share - took under an hour to obtain and pointed
   in the opposite direction to the plan. The tooling is committed
   (`scripts/perf/throughput.ts`, `tree-cost.ts`) so the next such question is
   cheaper still.

## Consequences

- The Worker ceiling is ~19,000 frames/s, up from ~5,900. Together with agent
  3.5.0 (ADR 0010), which removed the sniffer thread as a limit, the pipeline
  is roughly 3x faster end to end than at the start of this work.
- `formatArrivalTime` is still the top entry in the profile at ~11%, now purely
  `formatToParts`. It produces two tree rows that 92% of frames never show
  anyone, so it is the strongest remaining argument for ADR 0001's migration -
  worth perhaps 5 us a frame, not the 90 that was hoped for.
- The tail is now the thing to watch: dissect p99 is ~665 us against a p50 of
  ~22 us. `flush()` is synchronous, so the tail is what overruns a budget. No
  flush exceeds 100 ms on the fixtures today, but a p99 that far from the median
  is where the next drop will come from.
