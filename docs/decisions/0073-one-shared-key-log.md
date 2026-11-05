# 0073 — One shared key log per renderer: the page writes a compact store in shared memory, the pipeline Worker and its shards read it in place, and a key log past 512 MiB loads from its newest part

**Status:** accepted 2026-11-05. The owner chose "Compact + cap" and then "One
shared store" the same day, after the measurement below, and approved the
plan. It amends [0045](0045-the-key-log-is-followed-not-loaded.md), whose
follower streamed the log's lines to a store in every context; main still
streams them, but only the page parses them now. It keeps
[0008](0008-key-material.md) as it is: the shared buffer is memory, never a
file.

## Context

On 2026-11-04 the app began to die about five seconds after the window opened,
every launch, installed and `start:app` alike, with nothing clicked. Main's log
said `[renderer] gone: oom (exit code -36861)`.

The owner's browser had been writing `SSLKEYLOGFILE` since September, and
Inwire had been following it (0045). The file was 217 MB, 1,392,698 lines. At
every launch main sends a followed file whole, and each context that dissects
TLS held its own `KeyLogStore`:

| | |
|---|---|
| `KeyLogStore`, Map-based, measured in Node | 543 B a line, 715 MB for a 205 MB log |
| copies in one renderer | the page, the pipeline Worker, and each shard (Auto is `min(6, cores - 2)`: six here) |
| also held | the Worker's `keyLogTexts`, the raw text, to replay to a shard started later |

The page and its dedicated Workers share one V8 pointer-compression cage of
about 4 GB. Eight copies do not fit in it. A synthetic log of the same shape
(215 MB, 1,380,000 lines, random hex) crashed a fresh profile in 8 to 9 s with
-36861 while the page's own heap read 550 MB; the same profile without a key
log ran flat at 22 MB. The crash had nothing to do with 91192cc6, the merge it
followed: the file had crossed the size at which the copies no longer fit.

## Decision

**One store per renderer, written by the page.** Every writer was already on
the page: the follower's lines, the Decryption panel's Load, and a pcapng
import's Decryption Secrets Block (`pcapParser.ts`, in `PcapService`'s walk).
They all call `keyLog.add` there. The Worker and every shard *adopt* the page's
buffer and read it in place. The `keylog` and `keylog-clear` text messages, the
shard's `keylog` / `keylogClear`, and `keyLogTexts` are gone; the one message
left carries a buffer (`keylog-shared` to the Worker, `keylogShared` to a
shard) and is sent only when the buffer is replaced. A side effect: a DSB's
secrets now reach the Worker, so a tree the Worker rebuilds for an imported
frame can decrypt. Before, it never saw them.

**Compact, outside the JS heap.** `src/services/tls/keyLogTable.ts` keeps the
log in one buffer: a 128-byte header of Int32 fields, an open-addressed slot
table, 36-byte connection entries, 16-byte record entries, then an arena of
secret bytes. The slot is HalfSipHash-2-4 of all 32 bytes of the client
random, keyed with 64 random bits drawn when the table is made and kept in
its header. A key log and a pcapng's Decryption Secrets Block are input
someone else can write, and the first version hashed bytes 16 to 31 with no
key: 20,000 lines that differed only in bytes 0 to 15 sat in one run of
20,000 slots and took 2.4 s to load against 38 ms, a cost that grows with the
square of the count (40,000 took 9.3 s). The `Map` it replaced was safe from
this because V8 seeds its string hash.
`KeyLogStore` is a facade over it with the same surface
(`add`, `stats`, `secretsFor`, `isEmpty`, `serialise`, `clear`) plus
`share` / `adopt` / `onSnapshot`. `secretsFor` stays synchronous and returns
fresh copies.

**One writer; publication by Atomics.** The page writes the data, then stores
the counts with `Atomics.store`; a reader loads them with `Atomics.load` and
reads nothing past them. A reader never writes. When a region fills, the
writer builds a new buffer in which only that region doubles, copies, and
posts it; the old buffer is never written again, so a reader still on it
answers from a frozen state until it adopts the new one. The generation (what
tells a TLS or QUIC conversation to re-derive its keys) lives in the header,
never goes backwards across a replacement, and is bumped on the retired
buffer when a growth lands part-way through one `add`, so a reader still
there does not keep half-derived keys.

**Clear retires the buffer.** `clear()` makes a new, empty table at the next
generation and posts it at once with `cleared: true`; each context flushes its
AES cache (`clearDerivedKeys`) on adopting it, and the Worker clears its
trees, derived answers and rebuilt trees, as it did on `keylog-clear`. A
file the panel is still reading when Clear is pressed stops at its next
chunk (`loadKeyLogFile` compares the store's count of clears), so the rest of
the file does not refill the store Clear just emptied.

**Bounds.** `KEYLOG_CAP_BYTES` is 512 MiB, 2.4 times the owner's file, so
that file loads whole. A followed file larger than the cap is read from
`size - cap`, its partial first line dropped, on every read from the top
(first read, truncation, replacement); the follow card says how many bytes
were skipped. A file loaded through the panel is cut the same way. The store
holds at most `MAX_KEYLOG_SECRETS` (4,194,304) records; lines past that are
counted as dropped and the panel says so. `INWIRE_KEYLOG_CAP_BYTES` is a
main-only test hook that lowers the cap.

**Strict hex.** A random or secret that is not even-length hex of the right
width is an ignored line. The old `parseInt` accepted `1g` and `-1` and stored
what it made of them.

**Where memory cannot be shared, copies.** `npm run dev` sends no COOP/COEP,
so the page is not cross-origin isolated and has no `SharedArrayBuffer`. The
same messages then carry frozen `ArrayBuffer` copies: after an add that
changed something, at most one per 250 ms (`COPY_SNAPSHOT_MS`), so a 200 MB
log followed in dev is not copied once per 1 MB chunk. A clear posts at once.
Correct and slower, and dev only.

**The export writes from bytes.** `serialise()` returns ASCII bytes, and the
pcapng writer puts them in the Decryption Secrets Block unchanged. A log near
the cap is longer than V8's longest string, so decoding it to a string would
throw before the export started.

## Measurements

Task 1, in Node, against the old store as an oracle:

| | |
|---|---|
| buffer per accepted line, growth slack included | 77.3 B (target ≤ 128) |
| JS heap for 400,000 lines | 0.52 to 0.62 MiB more than empty (target ≤ 16 MiB) |
| replacements while adding 1,000,000 lines | 18 |
| a `worker_threads` reader, 1,000,000 lines, 19 adoptions | 0 wrong answers, 0 torn reads |
| the keyed hash against the unkeyed one, 1,380,000 lines added in 1 MiB pieces | 1,059 to 1,258 ms against 951 to 1,066 ms (three runs each) |
| 20,000 lines that differ only in bytes 0 to 15, or only 0 to 3 | 44 ms, longest run of slots 14 to 16 (ordinary lines: 39 ms, 13) |

Task 5, in the built app (`scripts/electron/keylog-heap-drive.ts`): a
synthetic log of the owner's shape, 205 MB and 1,380,000 lines for 260,000
connections, followed from a fresh profile with a capture running on the stub.

| | before (91192cc6) | after |
|---|---|---|
| Auto (6 shards) | renderer gone at about 5 s: `oom` | alive; every secret counted 3.9 s after launch |
| 16 threads | gone: -36861, out of JavaScript heap | alive; 3.5 s |
| capped at 64 MiB | gone: -36861 | alive; 430,304 secrets, 148,111,136 B skipped and said so |

The key log's share of the renderer's private bytes is a run less the same run
following an empty file, because the renderer's own cost moves with the thread
count (420 MB at Auto and 621 MB at 16 with no key log, at 30 s). The table
itself is 107 MB; loading it replaced the buffer 9 times and allocated 315 MB
in all.

| share | peak | at 30 s | after a GC in the page and every Worker |
|---|---|---|---|
| Auto | +384 MB | +373 MB | +145 MB |
| 16 threads | +391 MB | +386 MB | +146 MB |
| copy mode (sharing switched off), Auto | +1,563 MB | +1,538 MB | +876 MB |
| copy mode, 16 threads | +3,708 MB | +3,679 MB | +1,950 MB |

The page's `usedJSHeapSize` is 32 MB at both thread counts. The copy-mode rows
are a mutation, `canShareMemory()` returning false in a scratch build: one copy
per context, which is what `npm run dev` does. The gap between "at 30 s" and
"after a GC" is retired buffers that idle shards have not collected (see
Consequences); one GC frees them, which no copy would allow. Each run is its
own launch of a profile whose settings an earlier launch wrote. A reload to
apply them would leave the first page's half-done load in the renderer, which
raised the owner's file's peak by 445 MB in a first version of the drive.

Live, `scripts/electron/keylog-live-drive.ts` streams the key-log fixture
(14,615 frames, 337 secrets) through the stub. `http2 || http3` shows 1,509
frames at one thread, at Auto, and at Auto with the keys appended after Start:
the same count as in process. With no key log it shows 0.

The owner's own file, followed in place from a fresh profile on 2026-11-05:
218 MB, 1,382,995 secrets, with the browser still appending to it. At Auto the
renderer is alive at 30 s, and every secret is counted 3.9 s after launch. Its
peak share is +576 MB and it holds +151 MB after a GC; the page heap is 32 MB.

## Alternatives rejected

- **A compact copy in every context, with a cap scaled by the thread count.**
  Still one copy per shard, so the cap a user could load would fall as they
  raised Dissection threads, and the page's heap would still pay for every
  copy's parse.
- **A compact copy in every context, with a fixed cap.** Eight copies of a
  512 MiB log at 77 B a line is about 1.4 GB, and growth makes each copy's
  peak about twice that: back near the cage at the cap.
- **A cap with no compaction.** At 543 B a line the cap that fits eight Map
  copies is about 100 MB, half the owner's file today.

## Consequences

- **COOP and COEP are load-bearing now.** Before this, nothing depended on
  cross-origin isolation (`electron/CLAUDE.md` said so). A packaged or
  `start:app` build that lost `ISOLATION_HEADERS` would not crash: it would
  fall to copy mode and post a copy of the log to every context, which is the
  memory this decision removes. `scripts/electron/smoke.ts` evaluates
  `crossOriginIsolated`.
- A context that has adopted the page's buffer is a reader for good: its
  `add` and `clear` throw. Only the page loads a key log.
- A retired buffer lives until every context that adopted it has collected
  it. An idle shard allocates nothing and so does not collect: after a large
  load, the retired buffers stay in the renderer's private bytes until the
  shards next GC. They total under twice the table, about 230 MB for the
  205 MB log. They sit outside the JS heap's cage, the one that crashed. A
  buffer is at most 2 GB (`MAX_BUFFER_BYTES`). Pre-sizing the table from the
  length main is about to send would remove most of them; it was not done.
- A renderer minidump would now hold the log once rather than eight times.
  Crash reporting stays off (0008).
