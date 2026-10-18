# 0062 — The monitoring journal is cut into segments; whole segments expire into a sealed archive the user's retention policy asks for

**Status:** accepted 2026-10-19, with the owner's four rulings: checkpoints in
the sidecar and the archive cut, the milestone-1 file sealed and expired whole,
`clamp(limit/32, 1 MiB, 256 MiB)` segments, and expiry by replay, cut and the
rebuild rule. Measured in
[`docs/monitoring-1.5-measurements.md`](../monitoring-1.5-measurements.md).
It supersedes three rules of
[0059](0059-monitoring-evidence-journal-and-rollups.md): the single
`journal.iwmj`, "nothing expires in milestone 1", and "a rollup is always a
rebuildable cache".

## Context

[0059](0059-monitoring-evidence-journal-and-rollups.md) keeps every received
datagram in one file and stops recording at the storage limit. Nothing ever
expires, which was right for a first milestone and is wrong for a collector
left running: at the 8 GiB default it stops after about nine days at the
planning rate. Users need to choose between that and keeping recent evidence
by dropping old evidence. One file cannot lose its head without being
rewritten, and rewriting evidence is the one thing the journal must never do.

Dropping raw evidence has a second cost. Its minute rollups are no longer
rebuildable, so they stop being a cache and become the only record of that
range. They need a home that is never rebuilt, never "repaired", and says what
it is.

Milestone 2 decodes NetFlow v9 and IPFIX under a second decoder policy, and
v9 and IPFIX decoding depends on templates received earlier. Both facts shape
the format here, so 1.5 reserves what 2 needs rather than changing the format
twice.

## Decision

### Segments

The journal becomes a series of files, **segments**, each holding a
contiguous run of entries. Entry ids stay global: they rise by one across
segment boundaries, exactly as within a file, and the receive ordinal is still
the entry id.

- **A segment is named `journal-<first entry id>.iwmj`**, the id zero-padded
  to 12 digits (more if it ever needs them). Readers order segments by the id
  in the header, never by name or date.
- **Segment size is `clamp(limit / 32, 1 MiB, 256 MiB)`.** At the 8 GiB
  default that is 256 MiB, 32 files and about 7.3 hours a segment at the
  planning rate. At the 16 MiB minimum it is 1 MiB, so even the smallest limit
  has something to expire. Measured: an open costs the same per byte at 64 MiB,
  256 MiB and 1 GiB (402-433 MiB/s), a file costs about 0.3 ms on top, and a
  roll costs 1 ms. Size is therefore chosen for expiry granularity and file
  count, not open speed.
- **A roll happens before an append that would take the open segment past its
  size.** The new segment's header is written and flushed, then the entry. A
  segment is never empty except for the moment between those two writes, and
  an empty newest segment is a torn tail. The size in force is the one
  computed from the limit when the segment was created; changing the limit
  changes later segments only.
- **The milestone-1 `journal.iwmj` is read as the first segment,** format 1,
  policy 1, first entry id 1. It is never renamed. A 1.5 build **seals** it:
  it never appends to it again, except to truncate a torn tail on open, and
  the next entry starts a new segment. It expires whole, so a milestone-1
  dataset near its limit loses all of that file in one expiry. The sheet says
  so before a retention policy that would do it is turned on.

**Segment header, format 2, 128 bytes:**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 8 | magic | ASCII `INWIREMJ` |
| 8 | 2 | format version | `2` |
| 10 | 2 | decoder-policy version | the policy this segment's datagrams are decoded under |
| 12 | 4 | header length | `128` |
| 16 | 16 | generation | the dataset's, the same in every segment |
| 32 | 8 | created, ms since the epoch | |
| 40 | 8 | first entry id | |
| 48 | 16 | open session id | the session open when the segment was created, or zero |
| 64 | 4 | exporter IPv4 | that session's recorded source, or zero |
| 68 | 4 | bind IPv4 | |
| 72 | 2 | port | |
| 74 | 2 | flags | bit 0: a session was open at creation |
| 76 | 48 | reserved | zero |
| 124 | 4 | CRC-32 of bytes `[0, 124)` | |

Entries keep 0059's framing, 24-byte header and 65,531-byte body cap
unchanged. A format-1 reader refuses a format-2 segment, as 0059 requires.

**Sessions across segments.** A datagram belongs to the session opened by the
nearest `start` before it. When that `start` is in an earlier segment, the
segment header names the session, so a segment whose predecessors have
expired still says which session, and whose source, its first datagrams
belong to. A header that says no session was open, followed by a datagram
before any `start`, is corruption, as in 0059.

**The `start` boundary gains `source`**, `{ exporterIPv4, bindIPv4, port }`,
the configuration that session was started with. A reader ignores fields it
does not know, so 0059's readers are unaffected. A dataset's recorded source
is the newest one ([0061](0061-monitoring-dataset-location-adoption-discard.md)).

**Contiguity.** The first entry id of each segment is one more than the last
entry id of the segment before it. The oldest retained segment starts at 1, or
at one past the `throughEntryId` of the archive's last cut. Any other gap is
interior corruption: the dataset opens read-only (0061), and nothing is
expired or appended.

### The accepted-policies rule

- **Each segment records the policy it was written under, and a reader
  accepts a set of policies.** 1.5 accepts `{1}` and writes 1. A segment, or
  an archived minute, under a policy outside the set is refused as
  `refused-version` and the file is left untouched.
- **A datagram is decoded under its segment's policy.** History is never
  silently reinterpreted. Milestone 2 writes policy 2 and accepts `{1, 2}`; a
  v9 datagram in a policy-1 segment stays *unsupported*, as it was counted
  when it arrived. Re-decoding old segments is a later, explicit feature.

### Source keys carry their protocol

v5 keeps `ip/type/id`, a legacy identifier for existing datasets. NetFlow v9
sources are `v9:ip/sourceId` and IPFIX sources `ipfix:ip/odid`; milestone 2
decodes them, and 1.5 reserves the forms so no v5 key can collide with them.
The 16-sources-per-exporter limit (`LIMITS.enginesPerExporter`) counts all
three protocols together.

### Retention: chosen by the user, off by default

| Setting | Values | Default |
|---|---|---|
| keep raw evidence for | off, or N days | off |
| at the storage limit | stop recording, or expire the oldest raw evidence | stop recording (0059's behaviour) |

- **Only whole sealed segments expire.** The open segment never does. A
  segment expires by age once its last entry is older than N days.
- **At the limit, expiry starts early.** When `expire the oldest` is chosen
  and the space left under the limit falls below two segments, the oldest
  sealed segment is expired. If nothing is expirable, or expiring every
  expirable segment would not make room, recording stops with
  `storage-limit` as in 0059.
- **The archive counts against the limit.** Its minutes are the only record
  of what expired, so they are kept, and 59 MiB of deflated rollups a day
  (0059's measurement) is what a very long retention costs.
- **"Expire evidence before a date"** (0061) is the same expiry, run once,
  with reason `user-before`. The segment holding the date is kept, so the cut
  is at a segment boundary and the dialog states where it actually falls.
- Which segments go is decided by one pure function,
  `planExpiry(segments, policy, nowMs, usedBytes, limitBytes)`, which never
  names the open segment and returns nothing rather than everything when its
  input is empty.

### Expiry, in order

1. `planExpiry` names the segments.
2. **The Worker replays exactly the expiring entries** and produces one
   minute fragment per `(source, minute)` they touch. A minute that straddles
   the cut gets a fragment for its expiring part only.
3. **The archive appends the fragments, then a cut** naming the range, and
   flushes.
4. **The journal appends an `expired` boundary** with the same range.
5. **The segments are unlinked.**
6. **The cache is brought back to the rule below.**

**Reopen finishes what a crash interrupted, and never repeats it.**
Fragments after the archive's last cut are an unfinished step 3: they are
truncated, and the segments are still there to expire again. A cut whose range
still has segments on disk is a finished step 3: the `expired` boundary is
appended if it is missing, and the segments are unlinked. A range a cut covers
is never archived twice.

**The `expired` boundary** is a boundary entry, kind 2, whose body is:

```
{ "action": "expired", "sessionId", "receivedMs", "fromEntryId", "throughEntryId",
  "fromMs", "throughMs", "reason": "age" | "limit" | "user-before", "source" }
```

`sessionId` is the session open when the boundary was written, or `""`.
`receivedMs` is when it was written. `fromMs` and `throughMs` are the receipt
times of the first and last expired entries. An `expired` boundary does not
open or close a session, so a session can span one. It is what lets a reader
tell "never received" from "received and expired" from the evidence itself.

### The sealed archive, `archive.iwma`

The archive uses 0059's framing with its own magic and the sidecar's 1 MiB
body cap (`ROLLUP_FRAMING`), because a deflated minute near the 16,384-key
budget can pass 64 KiB.

- **Header:** 0059's 64-byte format-1 layout with magic `INWIREMA`, format 1,
  the dataset's generation, and **policy `0`, meaning "per entry"**. The
  accepted-policies check applies to each minute, never to this field.
- **Kind 1, a minute fragment:** the sidecar's minute body unchanged,
  `u16 keyLength, key, u64 minuteMs, u64 throughEntryId, rollup bytes`, where
  the rollup bytes start with the u16 policy they were encoded under.
  `throughEntryId` is the last expired entry that contributed.
- **Kind 2, a cut**, 44 bytes and then a checkpoint:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | from entry id |
| 8 | 8 | through entry id |
| 16 | 8 | from, receipt ms |
| 24 | 8 | through, receipt ms |
| 32 | 4 | fragments written since the previous cut |
| 36 | 1 | reason: `1` age, `2` limit, `3` user-before |
| 37 | 3 | reserved, zero |
| 40 | 4 | checkpoint length, `0` in 1.5 |
| 44 | n | checkpoint, defined by milestone 2's ADR |

- **The archive is never rebuilt and never repaired.** A torn tail and an
  unfinished step 3 are truncated, as the journal's torn tail is. Interior
  corruption is preserved: minutes from the damage on are reported as
  **history lost**, never as zeros, and appends are refused. With appends
  refused nothing can expire, so at the limit recording stops with
  `storage-limit`, and the sheet says why.
- **Readers sum fragments**, as 0059 already requires of the sidecar, across
  policies too: each fragment is decoded under its own policy into the same
  in-memory rollup.

**Its tests are exact.** A minute wholly inside the expired range has an
archive fragment byte-identical to the cache minute it replaced. For a minute
that straddles the cut, the archive fragment summed with the retained
fragment equals the cache minute from before the expiry.

### The cache covers retained evidence, and must equal a rebuild of it

`rollups.iwmr` keeps 0059's rule, narrowed: it is derived from the retained
segments, and **after an expiry it must equal a rebuild from the retained
segments plus the archive's last cut**. The segment header supplies the
session state at the cut; the cut's checkpoint supplies template state from
milestone 2 on. Resetting the cache and rebuilding it by streaming meets the
rule, and 0059 measured that at 18 s a day and 38 s a week; a compaction that
keeps the retained minutes is allowed only if a test shows its output equal
to the rebuild's.

Sidecar entry kind 3 is reserved for a checkpoint at each segment start,
which milestone 2 defines. It is derived like everything else in the sidecar,
so it is rebuilt with it.

### Queries and coverage

Queries read the archive for expired ranges, the cache for complete minutes
with evidence, and the journal for the rest. A straddling minute sums the
archive's fragment and the retained one.

`BucketCoverage` gains **`aggregate-only`**: a bucket any of whose minutes
draws on the archive. The chart draws it in the observed style, marked, and
the legend says *Evidence expired*. The supporting-records panel, the datagram
detail and the port and protocol drill-down say *Detailed evidence for this
range expired on \<date\> under the retention policy* (or *was discarded
before \<date\>*), *and totals come from retained minute rollups.* An
over-budget minute whose evidence has expired keeps its exact totals, and its
tables say it exceeded the key budget and its evidence has expired. CSV gains
a coverage column that can say `aggregate-only`.

### The test vectors

`npx tsx scripts/monitoring/measurement.ts vector` prints these after 0059's.
An implementation must reproduce them exactly.

Segment header: format 2, policy 1, generation `00 01 … 0f`, created
`1700000000000`, first entry `4097`, session `a0 a1 … af` open, exporter
`192.0.2.1` sending to `192.0.2.10:2055`:

```
49 4e 57 49 52 45 4d 4a 02 00 01 00 80 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
00 68 e5 cf 8b 01 00 00 01 10 00 00 00 00 00 00 a0 a1 a2 a3 a4 a5 a6 a7 a8 a9 aa ab ac ad ae af
c0 00 02 01 c0 00 02 0a 07 08 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 cd e3 56 70
```

Entry 4200: an `expired` boundary whose body is exactly this UTF-8, with no
whitespace:
`{"action":"expired","sessionId":"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf","receivedMs":1700000600000,"fromEntryId":1,"throughEntryId":4096,"fromMs":1700000000123,"throughMs":1700000599000,"reason":"age","source":{"exporterIPv4":"192.0.2.1","bindIPv4":"192.0.2.10","port":2055}}`.
Its 24-byte entry header, whose CRC pins the body:

```
49 57 4a 45 0e 01 00 00 68 10 00 00 00 00 00 00 02 00 00 00 3e d6 c9 2a
```

Archive header: generation `00 01 … 0f`, created `1700000000000`:

```
49 4e 57 49 52 45 4d 41 01 00 00 00 40 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
00 68 e5 cf 8b 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 5a 76 07 02
```

Archive entry 1: a minute fragment for source `192.0.2.1/0/0`, minute
`1699999980000`, through entry `4096`, rollup bytes `01 00 de ad` (policy 1,
then two bytes the archive treats as opaque):

```
49 57 4a 45 23 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 59 e9 91 69
0d 00 31 39 32 2e 30 2e 32 2e 31 2f 30 2f 30 e0 19 e5 cf 8b 01 00 00 00 10 00 00 00 00 00 00 01 00 de ad
```

Archive entry 2: the cut of entries 1 to 4096, `1700000000123` to
`1700000599000`, one fragment, reason age, no checkpoint:

```
49 57 4a 45 2c 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 4d 60 49 72
01 00 00 00 00 00 00 00 00 10 00 00 00 00 00 00 7b 68 e5 cf 8b 01 00 00 d8 8b ee cf 8b 01 00 00
01 00 00 00 01 00 00 00 00 00 00 00
```

Like 0059's, these pin framing and layout. The values are chosen to be
recognizable, not to describe one consistent dataset.

## Consequences

- A collector can run indefinitely under a retention policy, and an
  aggregate whose evidence is gone says so wherever it is shown.
- The archive is the one aggregate that cannot be checked against evidence.
  It is labelled, kept apart from the cache, tested at the moment it is
  written, and never written over.
- Expiry costs a replay of what it drops, a few seconds a segment in the
  Worker, then a cache rebuild. Archive and unlink take tens of milliseconds.
- A milestone-1 journal is kept whole and expires whole. Splitting it would
  mean rewriting evidence.
- Milestone 2 changes no format here: its policy, its source keys, its cut
  checkpoint and its sidecar checkpoint all have reserved places.
