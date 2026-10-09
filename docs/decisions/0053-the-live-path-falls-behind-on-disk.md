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
it numbered late, in merge order (see **Phases**). **Phase 3 landed
2026-10-08**, behind **Settings > Interface > Performance > Dissection
threads**, default `auto`: the pipeline Worker coordinates N shard Workers
(`auto` is cores - 2, at most 6; 6 on the owner's machine) and the output is
frame for frame the single Worker's - `scripts/pipeline/parallel.ts` holds
every fixture, a 20,000-connection capture that evicts, a capture of TCP in IP
fragments, and the 300,000-frame burst to it, at seven arrangements including
two adversarial ones. On the burst, live: at 40,000 frames a second the view
kept up (40,750 advanced against 37,400 on one core, its lag flat at ~11,000
frames instead of growing past 75,000); at 60,000 the dissection is no longer
the limit - the app's main thread is - see **Phases** for the numbers and what
changed from the design. The rest of the phases are still to come. The fixes
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
- **Worker -> shards:** at most two flushes in flight per shard. *Built as
  three batches of at most 384 frames, and the coordinator holds at most
  65,536 frames it has not merged.*
- **Worker -> window** (added in phase 3): rows the app has not committed,
  60,000 (`LiveFlow.rendererBehind`).

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
  *Phase 3 shards by connection instead - one pair was more than half of the
  burst; see **Phase 3, as built**.*
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
once, and it is recorded, so a revisit agrees with arrival. *As built, a frame
records the room only up to one message's 1 MB, so its record is the single
Worker's until a shard's share actually binds.* Two more, both counted rather
than silent: a sharded connection that lane 0 later meets (`crossLane`), and
an out-of-order fragment whose first fragment is more than 4,096 frames behind
it, which can reassemble on a different shard from its connection's.

## Phases

1. **Bounded queues and the behind-live readout** (1-3 above, without the
   catch-up): no heap grows without limit, and the user sees the lag.
2. **The Sequencer, with one Worker** - stream numbering and the TCP eviction
   moved behind `trackerApi`, no behaviour change, every gate green.
   *Landed.*
3. **TCP shards**, behind the setting. *Landed* - see below.

### Phase 3, as built

`services/pipeline/coordinator.ts` (the coordinator), `shard.ts` (a shard),
`shardProtocol.ts` (what they say), `frameDissector.ts` (the dissection both
share), `dissect/shardNumbering.ts` (a shard's stand-in Sequencer),
`workers/shardRole.ts` (a shard Worker is the pipeline's own script, started by
its own URL - no second bundle, same origin, same COEP and CSP).

- **The coordinator numbers every frame in id order** through the one
  Sequencer: for a plain TCP segment `eth.stream`, `ip`/`ipv6.stream`,
  `TcpOrder.locate` and `streamId`, sent with the frame; a connection the order
  forgets is forgotten on whichever lane holds it, placed in that lane's queue
  where the single Worker forgot it. Everything else - UDP, QUIC, tunnels,
  anything `frameLane` leaves sequential - is dissected on the coordinator
  itself, as it is dispatched, by today's code with the real trackers.
- **`tls.stream` is numbered at the merge** (`DeferredTlsNumbers`): every lane,
  the coordinator's included, hands out negative placeholders and the merge
  numbers them in id order, then corrects the field, the record's answer
  (`settleDeferredAnswers` splices it - the call log has no lengths) and the
  cached tree of any frame dissected before the number came back.
- **A fragment of a TCP datagram goes to the shard of the connection its first
  fragment names** (or the first fragment found ahead, or its pair), every
  fragment of a datagram to one shard, as a barrier: nothing after it is
  numbered until the shard reports what reassembly did to the TCP order, and
  the shard was told in advance what a new connection would be numbered and
  would forget.
- **A connection lane 0 meets first stays on lane 0** (`keyHome`), so its
  state is never split. The reverse - a sharded connection lane 0 later meets,
  through a tunnel or an IPv6 extension header - is counted (`crossLane`) and
  is the one way this build can differ from one core. None of the fixtures or
  the burst does it.
- **Trees stay with the lane that built them**: lane 0's in the Worker's
  cache, a shard's in its own (2,000 each). A click on a recent frame is asked
  of its shard; anything older is rebuilt from its record, as before. The rows
  the merge adds - the process, a live gap, a fingerprint, links from later
  frames - are sent to whichever lane holds the tree.
- **Revisit is unchanged**: it needs no trackers, so the coordinator does it
  from the record exactly as the single Worker does.

**Changed from the design, each measured:**

- **Sharded by connection, not by address pair.** On the burst one address
  pair carried 54% of the frames (161,631 of 300,000), which caps pair
  sharding at 1.86x however many cores; one connection carried 22%. Every
  property the pair was chosen for holds by connection too - fragments go by
  their datagram's connection, ICMP and UDP stay on lane 0 - and
  `parallel.ts` runs both, and adversarial assignments, to the same output.
  `route: 'pair'` in `pipeline.worker.ts` puts the ADR's routing back.
- **A new connection goes to the shard least recently loaded**, not by hash:
  a hash put the two heaviest connections of the burst on one shard of seven
  (44% of it). Which shard is never an answer anyone reads.
- **Batches of at most 384 frames, three in flight per shard**, rather than
  two flushes: a shard answers once a batch, and one batch of everything
  queued left the merge waiting on its slowest frame while the shard idled.
  A batch is packed - one `Float64Array` of numbers and a string table
  (`OpWriter`) - because a list of objects cost the shard 6 us a frame to
  read.
- **The window is bounded too.** Phase 1 bounded main -> Worker and Worker ->
  store; with shards the Worker outran the renderer's main thread, which at
  60,000 a second fell 400,000 rows behind in 16 s with nothing shed. The app
  now answers each flush (`rowsTaken`) and the Worker stops releasing past
  60,000 rows owed (`LiveFlow.rendererBehind`), so main sheds and says so.
- **HTTP/1's body budget is asked for at most one message's worth**
  (`sharedBodyRoom(atMost)`), so the recorded answer is the same on any number
  of shards until the budget binds; each shard and lane 0 get 32/N MB.
- **An eviction's body release is no longer recorded** into the frame that
  caused it. It sat between two answers a revisit asks for, so on one core
  every frame that pushed out a connection with HTTP state missed on revisit;
  on several it is not that frame's question at all.
- **Two tree caches stopped evicting from a Map's front**, which walks every
  hole earlier deletes left - 11 us a frame at the coordinator's size
  (`FifoMap`, `IdRing`).

**Measured.** `scripts/perf/parallel-threads.ts` (dissection alone, real
threads, second pass): one core 50,000 frames a second; 6 shards 81,000 to
95,000 (1.6-1.9x), the coordinator 63-82% busy. Two things hold it below the
3-4x this phase was sized at: one connection is 22% of the burst, and a
shard dissects a frame in 33-40 us against 20 on the main thread, most of it
the machine (one shard alone is 26 us plus 4 us posting; six together are
slower each).

`ui-burst-drive.ts`, the burst replayed into the built app, three runs each:

| offered | one core | `auto` (6 shards) |
|---|---|---|
| 20,000/s | keeps up | keeps up, Worker heap 15-35 MB against 50-250 |
| 40,000/s | 36,957 / 37,633 / 37,703 advanced, lag growing past 75,000 | 40,734 / 40,755 / 40,774, lag flat ~11,000 |
| 60,000/s | ~37,500 advanced, ~200,000 shed and counted | see the next paragraph |

At 60,000 the main thread is the limit now: before the window was bounded it
committed 40,700-54,400 rows a second with 52-54% of its time in long tasks,
and the queue in front of it grew without limit. With it bounded, three
more runs: 47,218 / 47,128 / 56,121 committed a second against ~37,500 on
one core, 49-53% of the main thread in long tasks, nothing shed inside the
16 s phase (one core shed ~200,000), and the backlog (sent - counted -
skipped) at 270,000-333,000 by its end against one core's ~270,000 plus what
it shed. Inside 16 s the window's own bound cannot be told apart from
phase 1's, which it sits behind; it is there so a longer burst ends in a
counted shed rather than in the renderer's heap. The next limit is the main
thread's per-row work - unpacking each flush, learning names from each
frame, the field writer - and that is not dissection.

**What phase 3 leaves for later.** Imports still dissect on the main thread
(they never used the Worker). Shards post rows through the coordinator,
which deserializes and re-serializes each - its next limit near 100,000 a
second; phase 6 is that. QUIC and UDP stay on lane 0 until phase 5.

**The main thread, after phase 3** (2026-10-09). Profiled first, by
`ui-burst-drive.ts --profile` on the burst at 60,000 a second, six shards. The
top of the renderer's main thread was the rows going to the store - the window
cloning every frame a second time on its own port, 19.7% - then unpacking the
flush (11.9%), the dense-field writer (6.9%), and a walk in `evictOldBytes`
over every frame the store had not sealed yet (5.4%). What changed:

- **A live capture's rows and patches go to the store from the Worker**, on
  its own port behind the bytes it already sent there, and the window sends
  them only when the Worker had no port (`stored` on the flush). They travel
  **without their bytes** (`bytesSent`): the store already wrote those, and the
  copy was 30% of a row's clone and a second copy of every staged frame in the
  store's heap. Stop's drain now waits for the store to ack an empty append
  behind everything, because the last rows and the `finish` are on two ports.
- **`evictOldBytes` starts at the stored range's edge**, by binary search.
- **The field writer takes one lookup per field** (`tryWrite`), and a filter's
  network is parsed once (`cidrMatcher`).
- **An upward wheel stops the list following by itself.** The lighter main
  thread exposed a race `smoke.ts` then lost one run in three.

Three runs each, before (`7a5e036`) -> after, unminified builds with source
maps: at 60,000 a second
the main thread's long tasks 32-36% -> 2-5%, animation 47-51 -> 110-115 fps,
its idle 15-18% -> 40-43%, frames advanced 55,300-55,900 -> 57,500-59,900 a
second and the lag at the end of the phase 123,000-136,000 -> 61,000-101,000
frames; at 40,000, 100-103 -> 131-132 fps. **The cost moved to the
coordinator** - its idle at 60,000 went from ~27% to ~9%, as it now clones
each row for the store as well as for the window - so it, not the window, is
the next limit, and phase 6 is still what removes it. What is left on the
main thread is the flush's unpacking (12.5%), which is the message's shape,
not code.
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
