# 0028 — Where the capture store runs, and what the boundary costs

**Status:** accepted, with the measurement `0025` and the migration plan both
asked for and neither had. **Extends `0027`**; leaves `0007` intact for the
frame path, which does not go this way.

## Context

`0025` put the capture in four append-only files behind a `BlockFile` seam and
gave two reasons for a storage-only Worker: `createSyncAccessHandle()` exists
nowhere else, and encoding a summary costs 8.91 µs against the dissection
Worker's whole 28.6 µs budget.

`0027` voided the first one. `node:fs` is synchronous everywhere in Node, so
the sync seam no longer needs a Worker to exist in. That reopened the question
of where the store should run, and the honest position was that nobody knew:
the migration plan called the answer "the measurement that decides the
topology" and named `append` and `readBytes` across a process boundary as the
first thing to measure. It was not measured. This ADR is that measurement and
what it decided.

## Decision

**The capture store runs in an Electron `utilityProcess`.** `entry.ts` is the
process, `host.ts` forks it and brokers a `MessageChannelMain`, `volume.ts` is
the `node:fs` implementation of the four files, and `captureHost.ts` — which
holds every decision worth testing — imports neither Electron nor `node:fs` and
is driven from plain Node by `scripts/capture/store-protocol.ts`.

## Why not a Worker in the renderer, which is what it replaced

Three reasons, and the first two are disqualifying on their own.

`nodeIntegrationInWorker` is **renderer-wide**. Turning it on to give the store
`node:fs` gives `node:fs` and `child_process` to `pipeline.worker.ts` as well —
the module whose entire job is parsing bytes an attacker put on the wire. It
also requires `nodeIntegration: true`, which is incompatible with
`sandbox: true`, and the banner at the top of `CLAUDE.md` exists because that
trade must never be made for convenience.

It does not work with `type: 'module'` workers, which is what `captureClient`
used.

And a crash domain is worth having. An `ENOSPC` or a corrupt index kills the
store and leaves the window alive, which the client already degrades to.

## What the boundary costs

Measured by `scripts/perf/store-boundary.ts` over 100,000 frames in batches of
300 — realistic frames, which matters more than it sounds: a synthetic packet
with an empty field bag and eight bytes of payload clones several times faster
than a real one, and an earlier version of this measurement flattered itself
by a factor of three that way.

| | |
|---|---|
| `CaptureWriter` over `NodeBlockFile`, no boundary at all | 26.68 µs a frame — **37,477 f/s** |
| `v8.serialize` + `v8.deserialize` | 5.27 µs a frame |
| The whole hop over a real `MessagePort`, ack included | 5.26 µs a frame |
| **Both together** | 31.94 µs a frame — **31,308 f/s** |

**The crossing is 16% of the cost, and 1,955 B a frame on the wire.**

That is the number, and it says the opposite of what everyone assumed. The
worry was that a process hop would dominate — `captureClient.ts`'s own header
reasons from `0007`'s 5.1 µs same-process clone to "~178 ms of main-thread time
per second of capture" and says the arithmetic no longer holds across a
process. It holds better than expected. **Moving the store back in-process
would buy 16%**, which is not an argument for anything, and in particular is
not the argument for engine-side dissection that the Direction note in
`CLAUDE.md` was reaching for.

### One optimisation this measurement invited and then refused

The writer issues one `writeSync` per frame for raw bytes. Standalone, that is
3.40 µs against 0.28 µs for the same bytes in one write per batch — 12% of the
writer, apparently free.

Batching the writer for real measured **3% slower**, twice, because copying
1,100 bytes a frame into a coalescing buffer costs more than a `writeSync` to a
file the operating system has cached. Tried, measured, reverted. The comparison
stays in the script labelled as the trap it is: **a microbenchmark of a part is
not a measurement of the whole.**

## The rule the boundary imposes, which nobody wrote down

A `postMessage` is a structured clone, and **a structured clone drops
prototypes**. That is not a performance note, it is a correctness rule, and
breaking it cost more than every number above put together.

A buffered `Packet` keeps its 33 commonest fields in a `FieldBlock` class
instance (`0017`, `0018`). Once the store became a process, every frame arrived
with a `cols` object that had no methods, `encodeChunk` threw
`block.read is not a function`, the throw was caught and reported as a
non-fatal failure, and the next append did the same — for the life of every
capture. The directory filled with raw frame bytes and **no rows**. `ordinalOf`
answered -1, the app read that as "the window is the whole capture", and
everything looked normal.

So: **what crosses this boundary is data, not objects.**
`services/capture/storePacket.ts` flattens the dense columns back into the bag
at the seam. Flattened rather than rehydrated, because a block holds 4,096 rows
against a ~300-frame batch and would cross fourteen times as it fills — about
1.7 kB a frame, roughly doubling a hop that costs 5.26.

The second half is subtler and is the part worth remembering. `prepareBatch`
calls `persist` *before* `absorb`, and `send` awaits the port — so the store is
handed frames that do not yet carry a block, and the `postMessage` serialises
them a microtask later, after the field writer has attached one. A
`plainForStore` that returned the packet unchanged when there was nothing to
fold therefore fixed nothing. **A message is a snapshot**: it always copies.

## The ceiling, and a flag that does nothing

`host.ts` forks with `execArgv: ['--max-old-space-size=2048']` and a comment
saying a runaway store then kills itself rather than the machine. **It does
not.** The flag arrives — the store's own `process.execArgv` reads it back —
and `heap_size_limit` is 4192 MB, V8's 64-bit default, because V8 fixes the
limit when it creates the isolate. `v8.setFlagsFromString` at the top of the
entry point does not move it either. Both measured against the running app,
after the store was seen to die at 4,060 MB.

`store/heapGuard.ts` enforces it instead: sample the heap, warn once at 80%
while the capture can still be stopped whole, seal and stand down at the
ceiling with a message. A blown V8 heap aborts with
`MarkCompactCollector: young object promotion failed` into a log nobody reads
and the app says "the capture store stopped (exit 134)". The wall is the lower
of our 2 GB and 90% of V8's own, because standing down at 2 GB on a machine
where V8 aborts at 1 GB is the same failure again.

## Consequences

- `0025` Decision 1's second reason for a Worker — the 8.91 µs against 28.6 µs
  budget — is the one that survives, and it survives as an argument for the
  store being *somewhere else*, not for it being a Worker.
- Engine-side dissection needs a different trigger than "the boundary is
  expensive", because it is not. The remaining candidates are a profile showing
  the copy on the *frame* path — which does not cross this boundary at all, see
  `0007` and `0029` — or a sustained rate above ~100 MB/s.
- Anything that sends a `Packet` anywhere must send data. The guard is in
  `fieldAccess.ts`, which now throws a named error for a block with no methods,
  and in `scripts/capture/store-protocol.ts`, which puts every appended frame
  through `v8.serialize`/`deserialize` first. Before that, no test in the
  repository crossed a boundary.
- The store's inbound queue is unbounded and each pending `append` holds its
  frames. At 31,000 frames a second it has not been seen to matter, so the
  4 GB heap remains unexplained rather than diagnosed. Written down as open.
