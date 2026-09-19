# 0038 — Bytes and rows are two arrivals, so dissection is off the capture path

**Status:** accepted. Extends `0025` (the capture lives on disk) and `0007` (no
captured frame crosses the renderer's main thread) — both are preserved, and
`0007` is the constraint that decided where this code lives. Does not supersede
`0028`: the store is still a `utilityProcess` and the boundary cost is
unchanged.

## Context

The capture path was: agent → pipe → main → Worker → **dissect** → 100 ms flush
→ renderer main thread → store → disk. A frame reached disk only after it had
been dissected, and only as part of a row.

The entry that motivated moving this said a slow Worker flush starves the port
and overflows the agent's queue. **That chain was a WebSocket property and has
been broken since `0029`**: on the pipe, nothing downstream of the sniffer
applies backpressure, so a slow renderer grows *its own* queue and cannot make
`droppedAgent` climb. So the stated trigger was already gone.

Two real problems remained, and neither is throughput.

**A frame whose dissection threw was simply lost.** `ingest`'s `catch` posted a
failure and the frame was gone: not on disk, not in the list, not in any
counter. The one place the bytes were safe — `frames.iwbyt`, which needs no
dissection to be written — was only reached through the dissector.

**And the renderer's backlog was unbounded.** `pendingPacketsRef` is a plain
array flushed every 100 ms; under sustained overload it grows until the heap
does. `0036` made that a deliberate stand-down rather than a V8 abort, which is
better than a crash and still worse than not holding the frames in RAM at all.

## Decision

### 1. The writer takes bytes and rows as independent arrivals

`CaptureWriter.appendBytes(frames)` writes a frame's bytes and opens a slot;
`attachRows(packets)` fills the slot in later. They are matched by frame id **in
either order** — a row that overtakes its bytes is held and claimed, because two
channels into one process have no ordering guarantee between them and the
failure that would produce is a silently missing row.

**A slot with no row when its chunk seals is written as a placeholder.** Holding
the chunk back would make a slow dissector stall the write path, which is the
coupling being removed. The frame is not lost: its bytes are exact and complete
on disk, and `frames.iwbyt` is what a re-read reconstructs from. What the
placeholder stands in for is the derived accelerator row, and its Info column
**says so** rather than inventing a plausible one.

The ageing test now reads the **slot's** timestamp rather than its packet's. A
horizon that depended on a row arriving would never age out while the dissector
was behind — which is exactly the stall this removes, and it is asserted.

### 2. The Worker writes the bytes, and it does so before dissecting

Ids are assigned and bytes posted for the **whole released group** before any of
it is dissected. Per frame inside the loop would put each write behind the
previous frame's dissection.

**The Worker rather than main**, because main treats a batch as an opaque buffer
and `§3` says so; decoding it there to get ids would end that. **The Worker
rather than the renderer's main thread**, because `0007`. The Worker is the only
place that holds a frame's bytes and its assigned id at the same moment.

It gets its own `MessagePort` to the store, ferried through the renderer exactly
as the agent's port is — carried once and never used.

### 3. The store's ports are role-tagged, and only one answers

`entry.ts` took `event.ports[0]` from **any** parent message and assigned it to
its single `port`. Correct with one channel; silently wrong with two — the
second would replace the first, the store would keep writing, and every reply
would go down a port nothing was reading. A hung hex viewer and no error
anywhere.

The role travels with the port now. The ingest port is one-way and never becomes
the port replies go to.

### 4. The writer decides whether bytes are already down — the app never does

There are three cases: a live capture sends bytes ahead of rows; an import has
both at once; a build whose preload predates the ingest port sends only rows.
The app would have to know which, and two of the three are invisible from the
renderer — getting it wrong writes every frame's bytes twice or not at all.

So there is **no `attachRows` message**. Rows keep arriving as `append`, and the
writer answers one local question: *do I already have a slot for this id?* A
sealed frame counts as having one, because its bytes are emphatically on disk
and a second copy would break the contiguity `sealChunk` checks for every chunk
after it.

That is also what makes the whole change degrade correctly: without an ingest
port, everything behaves exactly as it did before.

## What this does and does not buy

**It does**: a frame whose dissection throws now reaches disk. Bytes for a
released group are down before any of it is dissected. The write path no longer
stalls behind the dissector at any horizon.

**It does not** make dissection asynchronous. Within one Worker, decoding and
dissection are still serialized: if dissection is uniformly slower than arrival,
the Worker's own message queue backs up and everything lags together. Real
decoupling needs dissection off this thread entirely — the `worker_threads` pool
in the store process that `§10` describes, whose trigger is still a profile and
not a plan. **Nothing here should be read as having done that.**

## Consequences

**Rows still carry `rawBytes` across the boundary even when the store already
has them.** `plainForStore` is unchanged, so this is a missed saving rather than
a regression — the bytes crossed once before and cross once now, just twice in
total on the live path. Stripping them is a follow-up with a measurement
attached, not a tidy-up.

**Two drive scripts were SKIPping and are not any more.** `disk-drive.ts` had
the same pipe collision `smoke.ts` had — the installed service owns the
production pipe name, so the one script that reaches the disk path could not run
on a development machine. It has its own pipe name now, and running it
immediately found a **stale locator**: it looked for the filter field by
`ip.addr ==`, which stopped being the placeholder when the display filter moved
into the title row. A selector in a test nobody could run.

Verified against the real app: 174,000 frames past the RAM window, the
whole-capture filter matching 43 frames read back off disk in order, and a
400,000-frame import scrolling back to frame 1.

**`missedPatches` gains a second source.** A patch for a slot whose row has not
arrived cannot be applied to nothing, so it is counted as missed. In practice
this is rare and self-correcting: the dissector applies its own patches before
emitting a row, so a patch arriving separately for a row that has not arrived
means the two crossed.
