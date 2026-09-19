# 0036 — The packet buffer sizes itself, and the renderer stands down before V8 aborts

**Status:** accepted. Extends `0025` ("the capture lives on disk") — the buffer
is a window onto that capture, which is why a full one loses nothing. Does not
supersede `0028`; the capture store's own guard is unchanged and is the model
this follows.

## Context

The question was: *why is the buffer capped at 1 GB — what stops users having as
much RAM as they have?*

Three things about the premise were wrong, and finding out which is most of the
answer.

**It was 512 MB, not 1 GB.** 1 GB was the largest of four options; 512 MB was
the default, and a default is what almost everyone runs.

**It bounds summaries only.** `bufferBudget.ts` counts summaries because they
are the dominant term and the only unbounded one. Raw frame bytes are a separate
window of 25,000 frames (~29 MB, constant), and tracker state is capped at about
28 MB by `0014`. Raising the budget moves one of three pools.

**And nothing was enforcing the real ceiling.** The buffer lives in the
renderer's JavaScript heap. V8 fixes that heap's limit when it creates the
isolate — measured on this machine at **4,192 MB** — and past it V8 does not
degrade, it **aborts**: `MarkCompactCollector: young object promotion failed`
into a stderr a packaged GUI app pipes into a log nobody is reading, and the
window disappears.

`electron/store/heapGuard.ts` already records this argument in full, for the
capture store, along with the measurement proving `--max-old-space-size` does
not move the limit. The store got a watchdog because it was **seen to die at
4,060 MB**. The renderer — the process that holds the buffer, the dissected
trees, React's tree and a virtualized hex dump — never got one.

So the cap was doing a guard's job badly: a number low enough that nobody
reached the wall.

## Decision

### 1. The ceiling is the heap, and it is enforced by a guard

`src/services/rendererHeapGuard.ts` samples `performance.memory` every two
seconds, warns once at 80% of the wall, and stops the capture at the wall. The
wall is 90% of V8's own limit, because the last tenth is where the collector is
the whole workload — the same ratio, for the same measured reason, as the
store's guard.

Stopping deliberately is mild here in a way it would not be in most
applications: the buffer is a *window* onto a capture that is entirely on disk
(`0025`), so frames leaving it are still in the list and still readable. What is
lost by stopping is the frames that had not arrived yet. What is lost by
aborting is the window.

**An unknown limit says nothing.** A guard that stopped captures on a machine it
could not measure would be strictly worse than the absence it replaced.

### 2. The budget is sized from the machine, with the heap as the cap

`autoBufferBudget` takes an eighth of physical RAM and caps it at half of V8's
heap limit, with a 128 MB floor. `'auto'` is what the app ships with; the
explicit sizes remain as overrides, and 2 GB joins them.

Both facts come from the preload, which reads them out of Electron's own
`process` shim — `getSystemMemoryInfo()` and `getHeapStatistics()`.
**Not `node:os`**: `os.totalmem()` is the obvious call and is the documented
trap in `§6`, where a sandboxed preload that requires an arbitrary Node module
dies while loading and takes `window.inwire` with it, silently.

**An eighth, because a bigger window buys scrollback and nothing else.** The
capture is on disk either way; a larger buffer avoids a filter scan reaching for
older frames. Trading half the machine for that would be a bad deal even on a
machine that has it.

**A `null` reading falls back to the fixed default rather than computing from
zero.** The arithmetic multiplies by a fraction, so a zero would produce a
buffer of nothing and a capture that trimmed every frame it took — the same
confident wrong answer `provesAbsent` exists to prevent, and the same rule
`droppedKernel` keeps by being `null` rather than 0.

### 3. `'auto'` is a stored value, not the absence of one

"Size it for me" and "I chose 512 MB, which happens to be what auto would say"
are different intentions: the first follows the machine if the app moves to
another one. So `packetBufferBytes` is `number | 'auto'`, and it resolves at one
place in `App`.

Two traps came with that, both live before this landed. `Segmented` is a Radix
`RadioGroup`, so a stored-but-unoffered value renders a control with **nothing
checked**; and the handler did `Number(v)` unconditionally, which turns `'auto'`
into `NaN` and writes that `NaN` into the stored preference. The normalizer is
the second line of defence and is asserted.

## Consequences

**On the machine this was written on the buffer went from 512 MB to 2,096 MB**,
and it is bound by the heap rather than by RAM: 31.7 GB of memory would give
3.96 GB at an eighth, and half of V8's 4,192 MB limit is 2,096. That is the
answer to the original question stated as a number — *the machine's RAM was
never the binding constraint*.

**Measured rather than inferred**, because the value that mattered was one this
codebase had already been wrong about once: the preload reports a heap limit of
4,395,630,592 bytes, `performance.memory.jsHeapSizeLimit` reports the same, and
both match the 4,192 MB the store's guard measured independently. The budget and
the guard therefore agree about where the wall is, which they must, since one
sizes for it and the other enforces it.

**Raising the budget further means moving off the JS heap**, not raising a
constant. The remaining lever inside the heap is `--js-flags` on the Electron
command line, which is process-wide and would put the same ceiling on main; and
`NODE_OPTIONS` is the wrong direction entirely, since
`enableNodeOptionsEnvironmentVariable` is a fuse this app intends to turn off
before signing. The real next step is the one `§10` already names: dissection
and retention in the store process, with the renderer a viewer that asks for
rows.

**The store's guard and this one are deliberately separate modules.** They share
a shape and two constants' worth of reasoning, not code: one reads
`v8.getHeapStatistics()` in a Node process and stops a writer, the other reads
`performance.memory` in a sandboxed renderer and stops a capture. Merging them
would mean a module importing `node:v8` reachable from `src/main.tsx`, which
`scripts/capture/node-safe.ts` exists to refuse.
