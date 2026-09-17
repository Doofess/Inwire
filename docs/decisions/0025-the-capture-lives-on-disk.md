# 0025 — The capture lives on disk, and the disk stops deleting

> **Decision 1's mechanism is superseded by**
> **[0027](0027-the-app-is-a-desktop-app.md)** - the app is an Electron app, so
> the capture is in real files rather than the browser storage this file reasons
> about, and the quota arithmetic here is void on a real disk. Everything else
> stands, and [0031](0031-a-filter-answers-over-the-whole-capture.md) completes
> it: one evaluator, a bitmap over capture ordinals.

**Status:** accepted. Supersedes the *mechanism* of `0012` and the storage half
of `0013`; `0012`'s rule survives intact and is strengthened.

## Context

ADR 0012 made a stored capture outlive the app: closing the last window no
longer wiped it, and discarding became something only the user does. It named
one exception and was honest about it:

> A capture left on disk is bounded only by `STORAGE_BUDGET_BYTES` (512 MB) …
> the arithmetic is `planBudgetEviction`, a pure exported function, so the one
> thing that still deletes a user's frames can be tested directly.

That exception was not a wart, it was the shape of the storage. IndexedDB held
one record per frame, keyed by id, containing the frame's **bytes** and five
scalars; a refresh rebuilt the capture by re-dissecting all of it. ADR 0013 is
what put the bytes there, and its reasoning was measured and right at the time:
storing whole dissected packets cost 4.6× the disk and 2.6× the write.

Two things have since made that arrangement wrong rather than merely dated.

**A frame's row is not a function of its own bytes.** The TCP sequence base,
the TLS record cursor, the DNS pairing and every `[TCP PDU reassembled in N]`
are state the frames *before* it built. Re-dissecting one frame from the middle
of a capture can therefore produce a **different Info line**, not merely a
slower one — and a restore that re-dissects from an arbitrary starting point
does exactly that. It was invisible while the store held roughly what the
buffer held; it is not invisible when the disk is where the capture lives.

**The budget's floor rose faster than the RAM window's.** `evictOldBytes` may
only drop a frame's bytes when the store can supply them again. Once the
512 MB budget had evicted the beginning of a capture, every frame it evicted
was *below* the store's floor and *inside* the buffer, so its bytes stayed in
memory for the rest of the capture — up to another ~760 MB on top of the
512 MB summary budget. The two ends squeezed and the frames between them were
stuck.

## Decision 1 — the capture is four append-only files in OPFS

`inwire/<capture-id>/` holds `index.iwidx`, `prefix.iwpfx`, `summary.iwsum`
and `frames.iwbyt`. Written by a storage-only Worker, because
`createSyncAccessHandle()` exists nowhere else and because encoding a summary
costs 8.91 µs against the dissection Worker's whole 28.6 µs budget.

Measured in Chrome on the development machine before committing to it:
sequential writes at **1,686 MB/s** (~30× what a 35,000 f/s capture needs, so
throughput was never the constraint), `estimate().quota` at **10.8 GB** (which
*is* the constraint, and is why v1 targets 5 GB and v2 segments), and
`navigator.storage.persist()` returning **false**, as expected.

## Decision 2 — the summary is stored, and the row is read back rather than re-derived

This reverses 0013's storage decision on the strength of a measurement 0013 did
not have. Interned per chunk and deflated, a summary costs **27.5 B/frame on
`bulk` and 33.9 on `inwire`** — 2.5–2.9% on top of the frame's own bytes,
against the 250–350 B/frame a naive row format implied. Storing the row is
cheap; re-deriving it is wrong.

Frames themselves are **never compressed**: 40,000 frames of a real bulk-TLS
capture deflate to 94% of their size, so compressing them would spend CPU on
the hot write path for nothing on exactly the traffic that makes a capture
large.

0013's headline conclusion is untouched. A million-frame buffer still cannot
hold every frame's bytes, and `packetBytes.ts` is still the seam that lets it
stop trying. Only the disk underneath that seam changed, which is what its
header promised: *"the day the buffer starts dropping bytes, none of them has
to change again."*

## Decision 3 — nothing on disk is deleted to make room

`STORAGE_BUDGET_BYTES`, `planBudgetEviction`, the write ledger and the
single-flight drain loop are gone. So is 0012's one exception: **there is now
no automatic deletion of a user's frames anywhere in the app.** `planBufferTrim`
is the last function that forgets a frame, and what it forgets is a frame's
place in *memory*, not in the capture.

The write ledger's replacement is `CaptureIndex.idRange`, deliberately the same
shape and the same null-when-empty rule so `packetBytes.ts` did not change. The
difference that matters is that an index only grows.

## Decision 4 — one capture on disk, for now

A startup restores the capture directory the stored session names, and removes
every other. Start does the same for the directory it just created.

This is **today's rule on a new backend, not a new rule**: `clearSession()` at
Start already wiped the previous capture out of IndexedDB, so exactly one
capture has ever survived a restart. The retention the user asked for — keep
the last three, prompt on launch — changes the policy, and changing a policy
that deletes frames deserves its own step and its own ADR rather than arriving
as a side effect of moving the bytes.

## Consequences

- **A restore is a read, not a dissection.** The main thread no longer builds a
  TCP, ICMP, QUIC, DNS or L3 tracker to restore a session, and no longer pays
  the measured 115 µs/frame — 5.8 s for a full buffer — to get back what it
  already had. It reads the newest chunks that fit the budget, from the end
  backwards, because a chunk is self-contained and the tail is what the reader
  was looking at.
- **`SessionMeta.captureId` binds the two halves.** The metadata is still in
  IndexedDB, which is right for a few hundred bytes written every couple of
  seconds; pairing it with a *different* capture's frames would shift every
  timestamp in the list, so the session names its directory and restores
  nothing if that directory is gone.
- **IndexedDB's `frames` object store is dropped, not emptied.** Deleting the
  store is the only way to reclaim what a previous build wrote, and it is up to
  512 MB counting against the same origin quota the capture store now needs.
  That is what `DB_VERSION` 2 is for.
- **A frame below the RAM window is on disk but not yet reachable.** The
  capture store has it, `bytesAreRecoverable` says so, and nothing in the UI
  can scroll to it. The row source that closes that gap is the next step, and
  until it lands `droppedBuffer`'s wording is still true.
- **Storage is best-effort.** `persist()` returns false in Chrome on a plain
  page, and the panel says so rather than implying a guarantee the browser has
  not given.
