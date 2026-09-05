# 0014 - Bounding the trackers

**Status:** Accepted 2026-09-05. Extends 0013, which measured the buffer and
missed everything that is not in it.

## Context

Every memory number this project has is per frame: 2,342 B of summary and
1,176 B of raw bytes at the time of 0013, 2,197 B and 0 B resident after the
work it led to. All of them measure the **packet buffer**, and the packet buffer
is the one thing here that was already bounded - `trimToCap` slices the array,
trims the session store and evicts raw bytes the moment the cap is reached.

Dissection also accumulates state that is not in a `Packet` and never crosses
the worker boundary: which segment a TCP connection expects next, where each
direction is inside the TLS record layer, a QUIC flow's keys and reassembly
cursors, the echo requests still waiting for a reply, which process held which
local port when.

**`trimToCap` never touched any of it.** `resetPipeline`, the only thing that
clears the trackers, fires on exactly four events - clear buffer, delete
session, file import, end of restore - and all four mean *the buffer is gone*.
None of them means *the buffer got smaller*. So a capture left running trimmed
frames for hours while its tracker state only grew.

## The measurement

`scripts/perf/tracker-cost.ts`, added by this work because the number had never
existed. It feeds frames through the real dissector, discards every packet, and
measures what is still reachable.

| workload | per unit | retained |
|---|---|---|
| 5,000 TCP connections, each opened and cleanly closed | **2,162 B/connection** | 10.5 MB |
| a 4,096-host ping sweep, no replies | **255 B/probe** | 1.0 MB |

The `TcpStreamTracker` was 2,269 B of that first row on its own, held in **nine
map entries per connection** - three keyed by the connection, three by the
direction, two by the stream index - each storing its own copy of a ~40-character
key string.

The line that decides the priority: **tracker state overtakes the `Packet`
records once a capture averages fewer than ~10-30 frames per connection.** A
browsing session is exactly that shape. Chasing 2,197 B a frame while this grew
without limit would have been optimising the wrong number.

### Two things about the measurement itself

**The obvious way to attribute it does not work.** Running one pass and dropping
the trackers one at a time charged 11 MB to `QuicFlowTracker` on a synthetic
capture containing no QUIC, whose census showed it holding zero entries; and on
the inwire fixture the five deltas summed to 1,056 KB against 441 KB actually
retained. `heapUsed` after a collection moves with what the collector happened to
finish, so a sequence of deltas attributes the pass's own garbage to whichever
step it lands on. Each tracker now gets its own pass - present during it, alone
at the end of it - and the pass's residue is measured separately and subtracted.

**The fixtures cannot measure this at all.** 84 and 33 conversations retain less
than the pass's own residue, so the script says so and suppresses the
attribution rather than printing a number it cannot defend. That is why the
synthetic workload exists, and it is a standing caution for anything else
measured against these two captures: they are two browsing sessions, and they
are small.

## Decision

### 1. One record per connection, not nine map entries

`TcpStreamTracker` holds a `Map<string, TcpConnection>` in which the connection
key is stored once, plus a `Map<number, TcpConnection>` for the callers that
hold only a stream index. Every field is created on first use, so a connection
carrying no TLS allocates no TLS conversation.

The public API is unchanged - every method still takes the four endpoint
components - so no caller moved. **2,162 -> 1,645 B per connection**, and,
which matters more than the bytes, forgetting a connection became one delete
instead of nine that could fall out of step.

### 2. Least-recently-used caps, not sweeps

| structure | bound |
|---|---|
| `TcpStreamTracker.connections` | 16,384, LRU |
| `QuicFlowTracker` flows | 4,096, LRU; a flow's eviction reaches every map keyed by it |
| `QuicFlowTracker` streams | 8,192, LRU |
| QUIC connection ids per flow | 32, oldest first |
| QUIC held stream bytes, all flows | 8 MB (the per-stream 256 KB had no sum) |
| `IcmpEchoTracker.pendingRequests` | 4,096, oldest first |
| `FlowAnnotationStore.lives` | closed lives swept after 120 s; 8 per endpoint |

**LRU is what makes a plain cap the right mechanism**, and it is the load-bearing
choice here. A connection that closes stops receiving frames, so it stops being
touched and drifts to the front of the eviction queue on its own: the entries
evicted first are the conversations already finished, with no FIN needing to be
acted on and no sweep needing a clock. Oldest-first would have done the opposite
- dropping the long-lived connection opened at the start of the capture, which
is the one most likely to be the reason someone is capturing.

Insertion-ordered `Map` is the whole implementation: `keys().next()` is the
least recently used, and delete-then-set is the touch. `L3Tracker` already did
this and was the model.

The socket table is the exception, and swept by age rather than capped, because
its entries are not touched by traffic - they are written by a table arriving
once a second. A **closed** life can be dropped once no frame that could still
be dissected falls inside it, which is knowable because dissection runs
forwards. An **open** life is never swept however old it is: "still open" is not
a timestamp, and the socket open longest is the one whose attribution is worth
most.

### 3. Eviction is counted, not silent

`TcpStreamTracker.evictedConnections` is zero for every ordinary capture.
Non-zero means some frames were given a fresh stream index and relative-sequence
base part-way through a conversation, and that is a thing to be able to say.

## Consequences

- **A frame on an evicted connection reads as a connection never seen before**:
  a new stream index, and a relative-sequence base of "first seen minus one".
  That is not a new behaviour - it is exactly what the tracker has always done
  for a capture started mid-connection - but it now has a second cause, and the
  counter above is what distinguishes them.
- **Stream indexes are never reused.** `nextStreamId` only counts up, so an
  index freed by eviction cannot collide with anything. Follow Stream, the
  statistics tables and every filter naming an index keep their meaning.
- **A reply whose echo request was evicted loses its `(request in N)`
  cross-reference** and nothing else. The frame is still dissected, filtered and
  exported.
- **The ceiling is now a ceiling.** 30,000 connections through the synthetic
  workload retain 16,384 and 21 MB, and would retain the same after 300,000.
- Throughput is unchanged at ~19,178 frames/s sustained: the LRU touch is one
  delete-and-reinsert per frame, not per call, because every lookup made while
  dissecting one frame asks about the same connection.
- tshark parity is byte-identical on both fixtures, including the
  retransmission, out-of-order and lost-segment counts - which are what would
  break first if the direction selection in the new record were wrong.
- `scripts/tcp/tracker-bounds.ts` holds the properties that make eviction safe
  rather than lossy. They are deliberately not memory assertions: dropping a
  connection while keeping its stream index, reusing an index, evicting by age
  instead of by use, or sweeping a socket that is still open would all pass a
  memory measurement and all fail there.

## What this does not do

The caps are generous and the numbers behind them are one workload's. A capture
that legitimately holds more than 16,384 live TCP connections - a busy transit
link rather than a workstation - will evict conversations that are still running,
and today the only sign of that is a counter nothing displays. Surfacing it
belongs with the other "say what was counted" work.
