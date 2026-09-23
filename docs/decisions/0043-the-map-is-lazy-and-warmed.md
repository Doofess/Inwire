# 0043 — The map's code is lazy and warmed, and a per-kilobyte launch figure does not extrapolate

**Status:** accepted. Closes the item ADR 0041 left open.

## Context

`GeoMap.tsx` was a static import of `App.tsx`, and it reaches maplibre-gl and
`three`. Together they were **1.51 MB of the 3.95 MB eager chunk** — the chunk
that must parse before React's first commit — behind a rail button most launches
never press.

ADR 0041 left this open with a number attached: ~70 kB-derived milliseconds,
extrapolated from the one split that had been measured (jspdf, 413 kB, ~32 ms).

**The audit that first proposed `React.lazy` here refuted it, and the refutation
is still correct.** `GeoMap.tsx` calls `setWorkerUrl` and then
`setRTLTextPlugin` at module scope; the second acquires MapLibre's worker
pool — up to three Workers, each parsing the 487 kB shared chunk — which is why
that ordering carries a paragraph of comment in the file. Under a bare
`React.lazy` that spawn moves to the click that opens the map, landing *in front
of* the 2–4 serial HTTPS round trips to openfreemap that the first basemap pixel
already waits on. That trades a launch cost which is mostly paid for an open
cost which is entirely serial.

## Decision

**The chunk is lazy and the load is warmed.** `geoMapLoader.tsx` holds one
`import('./GeoMap')` thunk shared by two callers: `React.lazy`, and a
`warmGeoMap()` that `App` calls once from a `requestIdleCallback` after mount.
The parse and the worker-pool spawn happen where nothing is waiting on them, the
eager chunk stops carrying them, and the rail button finds the module already in
the registry — `React.lazy` resolves from its own cache rather than fetching.

`import()` is idempotent per specifier, which is the whole mechanism: the warm
and the mount cannot become two parses.

The Suspense fallback is the window's own ground rather than a spinner, for the
reason `electron/window.ts` fixes `backgroundColor`: the one frame it occupies
must not be a flash of a different shade.

## What it measured

Five runs after against three before, `smoke.ts` on this machine, ranges
**non-overlapping** on both numbers:

| | document | first painted UI | eager JS | eager CSS |
|---|---|---|---|---|
| before | 1036–1053 (med 1041) | 1258–1276 (med **1266**) | 3,954,823 | 160,324 |
| after | 993–1019 (med 1002) | 1153–1255 (med **1235**) | 2,442,182 | 77,286 |

**~35 ms, for 1.51 MB of JavaScript and 83 kB of CSS.**

### The part worth keeping: the per-kilobyte figure does not extrapolate

ADR 0041's measured 32 ms per 413 kB predicts **~117 ms** here. The real answer
is about a third of that, and the ranges are tight enough that the gap is not
noise.

So **that figure is a measurement of one split, not a rate**, and this ADR
amends 0041 by saying so. The plausible reason is V8's lazy compilation: bytes
that are never *executed* cost a pre-parse rather than a full compile, and
nothing in maplibre or `three` ran at launch except the two module-scope calls
this change moved. jspdf's chunk had more top-level work. Plausible, not
measured — recorded as the open question rather than the answer, because the
thing 0041 exists to prevent is exactly a confident number nobody took.

The rule that survives intact is 0041's second one: **establish the instrument's
noise before trusting a delta.** Three runs a side with overlapping ranges would
have been worth nothing here; five against three with no overlap is what makes
35 ms reportable at all.

## A non-retrying locator reported the change as a defect

`smoke.ts` asked `geoButton.isVisible()` — a snapshot, not a retry — immediately
after clicking Routing Map. With a synchronous import the pane was there; with a
Suspense boundary the pane's first render is a tick later, so it answered
`false`, and the branch below it reported **"the `Turn on location lookup`
button is on screen: FAIL"**.

That is the check behaving exactly as designed — its `else` is deliberately a
failure rather than a skip, because "a run that never found it has tested
nothing while looking like it did". Every other locator in that file gets
Playwright's 30-second retry; this one was the exception and had no reason to
be. It now waits, and prints how long the pane took: **37–42 ms typical**, which
is React's commit rather than a fetch, and is the number that says the warm is
working.

## Consequences

- `test/perf/ceilings.json` falls by 1.51 MB of eager JS and 83 kB of eager CSS.
  The total barely moves — this is re-chunking, not deletion.
- A launch that never opens the map still parses it, in idle time rather than
  before first paint. That is deliberate: not parsing it at all would put the
  pool spawn back in front of the map's network path, which is the thing this
  design exists to avoid.
- `scripts/electron/gpu-restore-drive.ts` passes unchanged, which is the check
  that proves the map genuinely mounts and holds its custom layers through the
  lazy boundary — `smoke.ts` only reaches the consent button, because its
  outbound hosts are blocked.
- ADR 0041's 32 ms/413 kB is amended to a measurement of one split. Anyone
  reaching for it to size a future split should take their own.
