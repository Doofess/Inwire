# 0031 — A display filter answers over the whole capture

**Status:** accepted. **Completes `0025`** — the capture has been on disk since
then and the filter had not noticed. Depends on `0028` for where the work runs.

## Context

A display filter ran over `packets`, which is the RAM window. That was the
whole capture until `0025` put the capture on disk, and after it the filter
kept answering a question nobody asked — *of the frames that happen to still be
in memory, which match* — and answered it without saying so.

`dns` on a 5 GB capture showed the last few minutes of DNS and looked complete.
The list said "PACKETS: 412 / 5,231" while four million frames sat unexamined,
and the only hint was a note in the empty state, shown when a filter matched
*nothing*, which is the one case where the reader was already suspicious.

`captureScan.ts` and `matchSet.ts` were written for this and had no consumer
outside their own tests for two months.

## Decision

**The store runs the filter over the capture and returns a bitmap; the list
addresses matches instead of frames.**

Three parts, and the interesting content is in the second and third.

## One evaluator, because two would be two answers

The store is sent the **expression**, not a predicate — a compiled filter is a
closure and a closure does not cross a process boundary — and compiles it with
`filter/compile.ts`, the renderer's own compiler.

The tempting alternative is a second evaluator over the **prefix block**: the
fixed-width record written beside every chunk, holding both addresses in
binary, both ports, the length, the status and two bitmaps. A `DataView` scan
over that is tens of nanoseconds a row where decoding the summary is a couple
of microseconds, and the plan costed it at 0.19 s against 11.8 s for a 5 GB
capture.

It is not what this does, and the reason is not effort. `filter/compile.ts` is
a hundred operators, four comparison semantics, multi-value fields, CIDR
containment and the dense/sparse split. A filter that answered differently
depending on whether a frame happened to be in RAM would be wrong **silently,
and only on the frames nobody can see to check**. `==` meaning "contains" is a
bug this codebase has already fixed once.

Then it was measured rather than argued: `scripts/capture/scan.ts` puts the
decode-and-evaluate pass at **1.61 and 1.64 µs a frame** over both fixtures, so
a 5 GB capture — 4.3M frames — filters in about **seven seconds**, with a
progress bar and a cancel in front of it. Seven seconds is worth more than a
second answer would cost.

If an accelerator is ever built, the rule for it is already fixed: it may
**exclude** a row from decoding and may never include one, so the answer stays
this evaluator's answer.

## A bitmap, and why it is shipped to the renderer

The result cannot be a list of frames: a filter over 47M frames can match 47M
frames. Even a list of ordinals is 4 bytes each — 188 MB for a filter as
ordinary as `tcp`. A bitmap is **one bit per frame whatever the filter
matches**: 5.9 MB for 47M frames, 590 kB at the 5 GB target.

It carries rank/select — a running count per 4,096-frame block — because a
virtualised list asks for "filtered rows 12,000 to 12,050", which means "the
12,000th set bit", and walking the bitmap to answer that is O(frames) *per
scroll event*.

The bitmap crosses to the renderer rather than staying in the store, and that
is the deliberate part. `count()`, `ordinalAt(k)` and `rank(ordinal)` are
called **from render**, once per visible row, forty times a frame. None of them
can be a message. Shipping 590 kB once per applied filter is the price of the
other three being synchronous.

## The boundary between disk and window is the window, not the scan

This is the part that would have been wrong in an obvious-looking way.

A filtered list reads from two places: the bitmap for the rows below the RAM
window, and the in-memory filter for the window itself. **The window's frames
are on disk as well** — the writer wrote them — so the scan covers them too,
and where the two halves meet decides whether every frame in the window is
listed once or twice.

```
rows 0 .. rank(below)        the scan's matches, read off disk
rows rank(below) ..          the filtered window, filtered in memory
```

`rank(below)` is the matches strictly *before* the window. The window wins for
everything from there up, because it is the same filter and the more current of
the two answers.

`rank` is clamped to what the scan covered. A capture that grew after the scan
started has ordinals the bitmap does not describe, and asking `rank` about them
counts them as **misses** rather than as unknown — a filter quietly
under-reporting on exactly the frames a live capture is producing. What the
scan did not reach is reported separately and settled by a button, not folded
into a number that looks whole.

That arithmetic lives in `lib/captureRowSpace.ts` with no React in it, because
getting it wrong does not fail: it shows the wrong frame, confidently, at the
right row height. `scripts/session/capture-row-space.ts` checks it by counting
the list's rows two completely different ways — *the list has exactly as many
rows as the filter has matches over the whole capture* — which catches both the
double count and the gap.

## The scan is sliced, and settles exactly once

The store serves byte reads and row reads while a scan runs: the reader is
scrolling and the detail pane is fetching. A scan that ran to completion in one
message would freeze both for seven seconds. `step()` does whole chunks until a
time budget is spent — a chunk being the smallest sensible slice, since it is
one inflate and one decode — and the message goes back through the store's
queue between slices.

A scan settles exactly once, whichever way it ends: superseded by a newer
filter, cancelled, its capture closed underneath it, or finished. A cancel
names the scan it means, because a cancel arriving after its own scan finished
must not abandon the one that replaced it — which is the shape of every "the
user retyped the filter" sequence. A cancelled scan hands back **no bitmap at
all** rather than a partial one, because a half-built `MatchSet` answers
`count()` and refuses `ordinalAt`.

## Consequences

- The list's two counts now describe the capture rather than the buffer, and
  the badge carries the scan's state beside them — while a scan runs those
  counts describe the RAM window alone, and a percentage that quietly changes
  meaning as the answer lands is worse than one that says which question it
  answered.
- A quick-find search and a sort by any other column still run over the window
  and only the window. Those are different problems with different answers; a
  sort over a capture larger than memory in particular is not this.
- The scan is a snapshot, and a live capture grows underneath it. Re-running it
  as the capture grows is a whole-capture pass about once a second at full
  rate, so it does not: the gap is stated and the reader asks for another pass.
- Nothing about this was watchable until the store started storing rows at all
  (`0028`), which it had not been. The end-to-end proof is
  `scripts/electron/disk-drive.ts`: 178,200 frames captured against a
  115,476-frame window, a filter matching one frame in 4,096 finding **44**
  across the capture where the window alone holds 28, and the top of the list
  reading frames 4,096 apart off disk.
