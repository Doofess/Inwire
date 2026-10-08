# 0053 — The live path falls behind on disk, and dissects on every core

**Status:** accepted 2026-10-08. **Phase 1 landed 2026-10-08**: every
app-side queue is bounded and the status bar says how far behind live the
view is and what it skipped. `ui-burst-drive.ts` on the real burst, before ->
after: at 40,000 frames a second the Worker advanced 28,600 -> 34,500 a second
with its heap peaking 520 -> 296 MB and the main thread's long tasks 29% -> 0%;
at 60,000 (sent ~70,000) it advanced 12,700 -> 36,700 a second, the backlog
grew without limit (1.18 million frames and rising) -> held near 400,000, the
Worker's heap peaked 727 MB and rising -> 356 MB, and 880,122 frames were shed
and counted as skipped - in the capture file, said so on screen and on the
frame after each hole. **Phase 2 landed 2026-10-08**: `dissect/sequencer.ts`
owns everything numbered across conversations - the four conversation
indexes, the TCP connection order with its eviction, `tcp.stream`,
`tls.stream`, and the frame clock - and the trackers ask it, so the output is
byte for byte what it was (342,321 frames of the fixtures and the burst, and a
20,000-connection capture that evicts, hashed before and after).
`dissect/frameLane.ts` reads from the headers which frames phase 3 may shard,
in 0.7 us a frame; on every fixture and the burst it reached 100% of TCP
frames, each numbered by the dissection exactly as its headers said
(`scripts/pipeline/sequencer.ts`). One thing phase 2 found that the design did
not list: **`tls.stream` cannot be read ahead** - a connection takes it on its
first TLS record, which only dissecting the payload finds - so phase 3 needs
it numbered late, in merge order (see **Phases**). The rest of the phases are
still to come. The fixes
that measured the problem landed the same day and are listed under **What came
first**. Narrows **[0038](0038-the-worker-writes-the-bytes.md)**: the
Worker still writes the bytes before it dissects, and now also stops when the
store has not taken them. Answers CLAUDE.md §10's **Engine-side dissection**,
but **not** with the store's `utilityProcess`, for the reason in **Where the
pool lives**.

## Context

A real download on the owner's machine - 2.41 million frames in 66.5 s, 36,000
frames a second on average and near 50,000 at its peaks, 312 Mb/s over 159 TCP
connections, four of them carrying ~70,000 frames each - was more than the app
could take. What happened, in order:

- **The store fell behind.** It took 31,000 frames a second; 57% of its writer
  was DEFLATE in `fflate`'s JavaScript.
- **Its inbound queue grew by the difference**, because nothing applies
  backpressure: main posts every pipe batch to the Worker without waiting, and
  the Worker posts every flush to the store without waiting.
- **The store's heap guard stopped it at 2 GB**, 51.28 s in. Every frame
  before that was stored, none after; the agent's own pcapng kept all
  2,410,000.
- **The window could not keep up either.** Above 15,000 frames a second, 71%
  of the main thread was long tasks, and with a display filter 93%.

The single Worker dissects at 25.6 us a frame on that traffic (18.8 us bundled,
after the speedups below) - about 39,000 to 53,000 a second on one core of a
24-core machine. A faster single core moves the line; it does not remove it.
The next link will be faster.

## Decision

**1. Only disk is unbounded.** The agent writes its pcapng *before* its live
queue (`agent-rs/src/runtime.rs`), and its per-client queue already sheds its
oldest batches and counts them (`outbound.rs`). So the file is the source of
truth and the live stream is best-effort, and every queue on the app's side
gets a budget:

- **main -> Worker:** credit by batches the Worker has dissected
  (`electron/pipeCredit.ts`, 256 MB); past it **main sheds whole batches
  itself and tells the Worker which**, with hysteresis so a hole is one hole.
  - **Not by stopping the pipe**, which this said when it was written: the
    agent's per-client queue would then shed whatever is oldest, and it carries
    control messages too - a lost `capture_boundary` misfiles a ring, a lost
    state message leaves a stopped capture looking live. Main tells a batch
    from a control message by its frame kind alone, so it sheds only batches.
- **Worker -> store:** a count of unanswered `appendBytes` (the store answers
  each with `bytesTaken`, 50,000 frames, `pipeline/liveFlow.ts`); past it the
  Worker stops releasing from its ordering window. The flush also dissects in
  50 ms slices now, so a Worker that is behind still answers the detail pane
  and main's report between them.
- **Worker -> shards:** at most two flushes in flight per shard.

The heap guards stay, as backstops that should never fire again.

**Until phase 4, a hole is reported, not caught up.** The first frame after
it carries `inwire.live.skipped`, a `CaptureGap` finding saying the frames are
in the capture file, and a row on its Frame layer. TCP analysis runs across
the hole and says "previous segment not captured" of the streams that crossed
it - true of what the view dissected, filed as a capture gap rather than as
loss, and what keeps the TLS record cursor from reading past a hole as the
middle of a record (`dissect/liveGapFields.ts`).

**2. A hole is caught up from the file, never dissected across.** A jump in
the agent's sequence numbers means the live stream shed. Dissecting across it
would make every TCP stream report a segment not captured. Instead the Worker
freezes the live feed at sequence S, main streams the capture's own pcapng
from the block holding S (`capture_boundary` names each ring file's range,
`ringFiling.ts`), the Worker reads it with the pcapng reader it already has,
and rejoins live within a second of it, dropping live frames it already read.

**3. The user is told.** Once a second, in the status bar: *Behind live by
12 s, 410,000 frames to go, nothing lost*. The follow chip says *catching up*.
Past about two minutes behind, a **Pause live view** offer: keep capturing,
stop dissecting, open the file when the capture stops - Wireshark's *update
list in real time* switched off.

**4. Dissection runs on several cores, in the renderer.** The pipeline Worker
becomes a coordinator and spawns N shard Workers:

- **Sharded by the IP address pair**, so every fragment, every connection of a
  pair and an echo with its reply land together. TCP first; everything else
  stays on lane 0, the coordinator's own path, which is today's code.
- **A Sequencer on the coordinator owns everything numbered across
  conversations**: frame ids and times, the `eth`/`ip`/`ipv6`/`udp` stream
  indexes, and `tcp.stream` with its 16,384-connection eviction. Shards get
  those as ordinary tracker answers through `trackerApi.ts`, recorded like any
  other (ADR 0049). The single-Worker build *is* N = 1, so equality between
  the two is structural.
- **Frames are merged in id order** before they reach the renderer; records
  and patches go by id as they already do.
- **A setting, Dissection threads: auto / 1**, where 1 is today's path.

**Where the pool lives.** In the renderer, as nested dedicated Workers - not in
the store's `utilityProcess` that §10 named. Every shard parses hostile bytes;
a renderer Worker has no Node and no filesystem and the store's process has
both. The hop the `utilityProcess` would save is 5 us a frame, and a transfer
between Workers costs nothing. Each Worker is also its own heap.

**One accepted difference:** HTTP/1's shared 32 MB body budget becomes 32/N per
shard. It only shows when more than 32 MB of bodies are being collected at
once, and it is recorded, so a revisit agrees with arrival.

## Phases

1. **Bounded queues and the behind-live readout** (1-3 above, without the
   catch-up): no heap grows without limit, and the user sees the lag.
2. **The Sequencer, with one Worker** - stream numbering and the TCP eviction
   moved behind `trackerApi`, no behaviour change, every gate green.
   *Landed.*
3. **TCP shards**, behind the setting. The first speed-up: roughly 3-4x at
   four shards on a bulk-TCP burst. What it needs from phase 2, and what is
   still open:
   - The coordinator runs `frameLane` and, for a TCP-lane frame, asks the
     Sequencer in frame order: `eth`, then `ip`/`ipv6` (`ConversationIndex.
     observe`), then `TcpOrder.locate` and `streamId`. The shard's trackers
     answer those same calls from what it was sent, the way `FrameRevisit`
     answers from a record, and drop the state for any key the order evicted
     (`TcpStreamTracker.forget` is already the one place that does).
   - **`tls.stream` must be numbered at the merge.** A shard reports that a
     frame was its connection's first TLS record; the coordinator assigns the
     number in id order and the merge writes it into the row, the field and
     the record's answer. Until that exists, a capture with TLS keeps its TCP
     on the sequential lane, or `tls.stream` comes out in shard order.
   - A frame marked `fragmentOf: 'tcp'` holds back later frames of its address
     pair until the shard reports the reassembled datagram's connection.
4. **Catch-up from the agent's file.**
5. **QUIC and UDP sharding** - the CID-to-connection map into the Sequencer,
   QUIC sharded by server; SDP handed out in frame order.
6. **Shards post rows straight to the store and renderer**, merged by a
   watermark - only if a profile asks, above ~120,000 frames a second.

**The equality test** (`scripts/pipeline/parallel.ts`, plain `tsx`): every
fixture and the burst, today's path against virtual shards at N = 1, 2 and 7
and an adversarial assignment; every frame's summary, field bag, record bytes,
patches and tree identical, then `revisit` over the parallel records. A
`worker_threads` test covers the transport; `ui-burst-drive.ts` the live app.

## What came first

Measured before any of the above, because the rule in CLAUDE.md §7 is that no
performance change lands until a profile names the function:

- **The store compresses with node's zlib** at level 1, passed in by
  `electron/store/entry.ts`: 24.6 -> 9.7 us a frame for the writer, 31,000 ->
  67,000 frames a second with its boundary. `scripts/capture/native-zlib.ts`.
- **A cross-frame link is written into a bag its owner holds** rather than a
  copy, in the dissection pass: -11%.
- **MACs from a table and the TCP bag built by assignment**: a further -10%.
- **A patched packet no longer reads as a new buffer**: the window compared
  the old buffer's last packet by identity, and a patch replaces it with a
  copy on most flushes of a download, so every incremental cache started
  again. The tail compares by id behind an identity check on the head, and a
  patch log (`patchLog.ts`) tells the filter exactly which frames to decide
  again - which also ended a filtered list showing a patched frame's stale
  copy.
- **The minimap paints from a colour index** (`lib/minimapBands.ts`) rather
  than walking the buffer twice a second.

`scripts/perf/ui-burst-drive.ts`, replaying the real burst into the built app:

| | before | after |
|---|---|---|
| 15,000 f/s following | 16.5 fps, 71% long tasks | 140 fps, 0% |
| 10,000 f/s with a filter | 34 fps, 67% | 141 fps, 0% |
| 20,000 f/s, 1.3 GB buffer | 1 fps, 19% | 136 fps, 0%, 0.25 s behind |

Above about 20,000 frames a second the Worker is the limit - 97% busy at
40,000, advancing 19,000 to 24,000 - which is what the phases are for.

## Consequences

- The live view can be behind live. That is the honest state of a machine
  receiving more than it can dissect, and it is now said rather than hidden in
  a queue that ends in a heap guard.
- N isolates, N heap walls; `rendererHeapGuard` is per isolate.
- The Sequencer must decide new TCP connections and evictions exactly as the
  tracker does. One shared key function, and the equality test on `bulk`,
  whose 30 streams each open with one SYN.
- Fragment-heavy TCP (tunnels) makes the Sequencer wait on a shard for the
  completing fragment's ports. Rare; measure before it matters.
- Every byte is written twice, by the agent and by the store. The store could
  index the agent's file instead; a later decision, not this one.
