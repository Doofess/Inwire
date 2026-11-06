# 0074 — Capture-file import dissects in a Worker: its own ingest port to the store, each batch packed once, Cancel discards

**Status:** accepted 2026-11-06. The owner chose, on 2026-11-05, a Worker for
capture files only and a working Cancel that discards the import. It amends
[0073](0073-one-shared-key-log.md) (a third reader context) and refines
[0007](0007-what-crosses-the-worker-boundary.md) for file import. [0053](0053-the-live-path-falls-behind-on-disk.md)
stays the live path's decision.

## Context

A pcap or pcapng import ran `PcapService.streamCaptureFile` on the renderer's
main thread. A 2.7 GB burst capture (2,410,416 frames) froze the window for the
whole import: its longest main-thread task was up to 4.1 s, and every long task
together was about 100% of the wall time. The gate this decision was held to:
no main-thread task over 200 ms, long tasks under 10% of the import, wall time
within +10% of the baseline, the Tab process's private peak no worse than the
baseline median, and the same "newest N are in memory" count.

Before this decision, on the owner's 2.7 GB burst pcapng (2,410,416 frames, the
newest 2,258,559 kept in memory), built app, background window
(`scripts/electron/import-heap-drive.ts`): the import took 66-67 s, and the main
thread was busy for all of it - long tasks summed to 101-103% of wall time,
41 of them over 200 ms, the longest 3.5-4.1 s. The Tab process peaked at
5,057-5,197 MB private.

## Decision

**A Worker per import, in the pipeline script's import role.**
`src/workers/importRole.ts` is a fourth role of the one pipeline script
(`IMPORT_NAME`, `src/services/pipeline/importRun.ts`), spawned through the one
Worker factory for each import and terminated at its end. Only capture files go
there; CSV, JSON, xlsx and a pcap inside a zip stay in-process (small, capped, no
file handle). Why a role of the same script: the walk, batcher, trackers and
`DerivedStore` are the engine the equivalence rests on, and a second bundle
would be a second copy of them.

**The Worker writes to the store over an ingest port of its own.** The page
asks for the port; it is not the live pipeline's. Nothing posted to the store
carries a transfer list (the store's utility process drops such a message, see
`src/services/pipeline/CLAUDE.md`). The Worker's messages queue until the
page's `storeOpen` names the capture, and every append is **tagged** with that
capture. The host drops a tagged `append` or `appendRecords` for a capture that
is not the open one, or with none open, without a reply: a straggler of a
cancelled import can neither write into the next capture nor raise an orphan
failure. `appendBytes` is left untagged: only an empty credit or barrier slab
goes down the ingest port, and the host already acks that on its own reply. The
page awaits the open (`CaptureClient.beginAwaited`), which rejects on a failed
or unavailable store.

**Credit and a barrier.** The Worker sends at most `IMPORT_CREDIT_FRAMES`
(50,000) frames ahead of what the store has acked, so the store's heap guard
needs no main-thread pacing. Before `done` it sends one empty acked
`appendBytes`: the ingest port's replies are ordered, so the ack means every
earlier append has landed. Stop's rule (drain, await writes, then seal) is kept.

**Pack once.** Each batch is packed once (`packRows` into a self-sealed
`PackedFlush`). The same pack goes to the store as a tagged `appendPacked`
(cloned, with the sent bytes all 0: the rows carry their own) and to the page
(transferred) with that batch's push-time size estimates. The page keeps the
`ImportTail`, trimmed by the buffer budget as before. Nothing comes back after
the walk; `done` carries totals, facts, missed patches and the decrypted
answers. The first design returned the tail from the Worker after the walk:
about 14 s serial, held twice, and failed the gate.

**Imports write v3 pack-native chunks.** The store receives packed rows and
seals them as pack-native chunks (ADR 0053 phase 6). A build older than that
cannot read their rows. The kill switch is `packNative: false` on
`CaptureWriterOptions` (`captureWriter.ts`): it makes the writer decode packs and
write plain rows. It is reached only through `CaptureHostOptions.writer`, a test
seam; production passes nothing, so it has no user-facing switch.

**The key log: the page stays the one writer (0073).** The Worker adopts
`keylog-shared` snapshots like the pipeline Worker does and never loads one. A
Decryption Secrets Block goes to the page (`secrets`, with a `seq`); the page
adds it to its `KeyLogStore`, answers `secretsTaken` with a fresh snapshot, and
the walk waits for that ack. Frames after the block decrypt from
the new snapshot. A cleared key log empties the Worker's `DerivedStore`.

**Adoption in slices, the minimap held.** At `done` the page hands the finished
buffer to the list in slices of `ADOPT_SLICE_ROWS` (150,000), a task each. Why:
profiled, the 700 ms task at `done` was `useIncrementalAggregate` folding 2.26M
rows in one render plus the commit; a grown prefix is a plain extension for
`prefixShift`. The panel awaits the adoption, so the job stays `running` until
the last slice and the success line follows it. The minimap strip is held from
the first slice to the last (a repaint per slice decided up to 50,000 colours,
~160 ms); `MinimapBands.sync` keeps a partial colour index and resumes it, and
finds the selection line by bisection when ids are ordered.

**Cancel.** The phases are `importFlow.ts`'s:

| Phase | A Cancel here |
|---|---|
| begin (live capture sealing) | seen when the seal resolves, before the file is touched; no store is open, so nothing is discarded; the previous capture is offered |
| read (Worker run) | invalidates the run token, terminates the Worker; `fail()` discards the opened capture and offers the previous one |
| read (in-process format) | seen when the parse returns; its rows are dropped |
| lock (sealed, previous capture pruned) | not offered: nothing could be given back (the last ~1-2 s of a large import) |
| adopt | not offered |

The job stays `running` until `fail()` returns, there is no dialog and a quiet
line is shown. A store that dies or fails for good mid-import ends the Worker
run as a failure (`CaptureClient.onLost`, `onStoreLost`); otherwise the Worker
waits for ever on credit or the barrier.

## Measurements

Three runs each, alternated in the same hour, same file, built app, background
window (`import-heap-drive.ts --gate --expect-resident 2258559`):

| Run | Route | Wall | Longest task | Long tasks / wall | Over 200 ms | Tab private peak |
|---|---|---|---|---|---|---|
| 1 | before | 67.0 s | 3,531 ms | 102.3% | 41 | 5,057 MB |
| 1 | Worker | 69.0 s | 113 ms | 1.1% | 0 | 3,299 MB |
| 2 | before | 66.0 s | 4,129 ms | 102.5% | 41 | 5,085 MB |
| 2 | Worker | 68.7 s | 113 ms | 1.0% | 0 | 3,539 MB |
| 3 | before | 67.4 s | 3,504 ms | 100.7% | 41 | 5,197 MB |
| 3 | Worker | 68.6 s | 140 ms | 1.4% | 0 | 3,424 MB |

The Worker route's median wall is 68.7 s against 67.0 s: +2.5%, inside the +10%
bound. Every run kept exactly 2,258,559 frames resident. The Tab peak, which
counts the import Worker too (it lives in the renderer process), fell by about
1.7 GB: each batch is packed once instead of copied for the store, cloned and
repacked for the tail.

`scripts/electron/import-worker-drive.ts --pcap` read the sealed capture back and
matched the in-process import on all 2,410,416 frames: rows, bytes and records.

## Rejected

- **A relay through the live pipeline Worker.** It would put an import's frames
  in the live path's queues, ordering and backpressure, which are tuned for an
  agent's batches (0052, 0053), and tie an import's progress to a capture's.
- **Hosting the import on the coordinator Worker.** The coordinator is the live
  path's measured limit (about 25% idle at 120k frames/s); an import there would
  compete with a running capture's ordering and shed.
- **A `cancelling` job state.** Every `status === 'running'` gate (Start,
  Reopen, Clear View, export) would open while the discard is still running.
- **Reading the tail back from the store.** Measured: 1,157,040 rows in ~14.5 s,
  about 4x the handover budget, and restored rows estimate heavier, so the
  resident count would change.
- **Comparing records byte for byte in the drive.** `env:now` is the wall clock
  at arrival, recorded on purpose (certificate validity on revisit), so two runs
  of one file never match there. The drive compares entry by entry and holds
  `env:now` to a Date inside the app's import window.

## Consequences

- An imported capture is a v3 pack-native capture. A build older than ADR 0053
  phase 6 cannot read its rows; the capture's
  bytes and index are unaffected.
- Revisit of imported frames is unchanged: records are written at arrival by
  the Worker, and a missing record falls back to replay (ADR 0049).
- On the main thread remain the decode of each `rows` message, the page's
  `KeyLogStore.add` for a large Decryption Secrets Block, and the adoption
  slices (a task each, measured 148-193 ms at 250,000 rows, so 150,000).
- Two copies of a batch exist briefly: the clone in the store's queue and the
  page's tail. The Worker keeps neither.
- The Worker lives in the renderer process, so its heap counts against the Tab's
  private bytes, which the gate measures, not the page heap alone.
- A cancelled import leaves its secrets in the key log, as before.

## Checks

`scripts/capture/import-worker-equivalence.ts` (the Worker route and the
in-process route in their own threads: store messages, tail, totals, facts,
derived equal); `scripts/capture/import-client.ts`, `import-job.ts`,
`import-lifecycle.ts`, `scripts/session/import-gate.ts`,
`scripts/session/adopt-slices.ts` and `minimap-bands.ts`;
`scripts/electron/import-worker-drive.ts` (built app, Cancel; by hand) and
`import-heap-drive.ts --gate` (the numbers above).
