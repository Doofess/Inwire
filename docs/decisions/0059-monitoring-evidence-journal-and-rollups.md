# 0059 — Monitoring keeps its own journal of what it received, and derives minute rollups beside it

**Status:** accepted 2026-10-17, with the owner's three rulings folded in:
address-pair conversations, a bound per table, and an 8 GiB default. Measured
in [`docs/monitoring-v5-measurements.md`](../monitoring-v5-measurements.md).
Implementation landed 2026-10-18 (merge 41b4a43).

## Context

[0058](0058-monitoring-intake-and-lifetime.md) puts a NetFlow v5 listener in a
`utilityProcess`. What it receives has to outlive the window and a renderer
reload, and survive a crash without being counted twice. It also has to answer
"what did this source send in the last day" without reading a day of
datagrams every time. The capture store is the wrong home for it.
[0026](0026-one-capture-on-disk.md) keeps one capture on disk, and capture
pruning is the wrong lifetime for monitoring history. A capture's frames and
an exporter's records also answer different questions.

The plan proposed a 5-tuple conversation key, a 5,000-key minute budget and a
50,000-key range bound. Measured against generated traffic, the 5-tuple key is
close to one key per record, so a rollup keyed that way would be the journal
over again. At 7 datagrams a second, 5,000 keys left 385 of 1,440 minutes
incomplete with address pairs and all of them with service ports. A day's
distinct conversations reached the 50,000-key bound, and the first rebuild
that held every minute ran node out of memory at 3.5 GB.

## Decision

### A standalone dataset

Monitoring history lives in `<userData>/monitoring/`, beside `captures/` and
never inside it. `planPrune` removes only directories matching
`CAPTURE_ID_PATTERN` under `captures/`, so neither a capture prune nor
[0012](0012-stored-captures-persist.md)'s delete rule can reach
it. Nothing about a capture writes to it, rewrites it or reads it: starting,
stopping or importing a capture, clearing the view and changing the capture
filter leave monitoring exactly as it was.

It holds two files:

- **`journal.iwmj`**, the evidence: every datagram received from the
  configured exporter, plus the lifecycle boundaries around them. **It is the
  only authority.**
- **`rollups.iwmr`**, minute rollups derived from it. **It is a cache.** Any
  doubt about it is settled by rebuilding it from the journal.

The location is fixed for milestone 1. A chooser, adoption of an existing
dataset, discard, expiry and the evidence bundle are milestone 1.5.

### The journal's framing

Every integer is **little-endian**. An IPv4 address is stored as its four
octets in network order, so `192.0.2.10` is `c0 00 02 0a`. The checksum is
**CRC-32/ISO-HDLC** (the zlib and PNG CRC: polynomial 0x04C11DB7, reflected,
initial and final XOR 0xFFFFFFFF). Its check value is
`crc32("123456789") = 0xcbf43926`.

**File header, 64 bytes, at offset 0:**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 8 | magic | ASCII `INWIREMJ` |
| 8 | 2 | format version | `1` |
| 10 | 2 | decoder-policy version | `1` |
| 12 | 4 | header length | `64` |
| 16 | 16 | generation | random, fixed for the life of the file |
| 32 | 8 | created, ms since the epoch | |
| 40 | 20 | reserved | zero |
| 60 | 4 | CRC-32 of bytes `[0, 60)` | |

**Entry, a 24-byte header followed by its body:**

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `0x454a5749` (ASCII `IWJE` on disk) |
| 4 | 4 | body length | at most 65,531 |
| 8 | 8 | entry id | 1 for the first entry, then +1 per entry |
| 16 | 1 | kind | `1` datagram, `2` boundary |
| 17 | 1 | flags | zero |
| 18 | 2 | reserved | zero |
| 20 | 4 | CRC-32 | of header bytes `[0, 20)` continued over the body |

**Datagram body:** 24 bytes of receipt metadata, then the payload exactly as
received. The payload is at most 65,507 bytes, the IPv4 UDP maximum, which is
why a body is at most 65,531.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | received, ms since the epoch (the utility's wall clock at receipt) |
| 8 | 4 | local IPv4 |
| 12 | 2 | local port |
| 14 | 4 | remote IPv4 |
| 18 | 2 | remote port |
| 20 | 4 | reserved, zero |
| 24 | n | payload |

**Boundary body:** a UTF-8 JSON object with the fields
`{ action, sessionId, receivedMs, reason, droppedDatagrams }`, where `action`
is one of `start`, `stop`, `suspend`, `resume`, `interrupted` or `gap`. A
reader ignores fields it does not know.

**Sessions and ordinals.** A datagram belongs to the session opened by the
nearest `start` boundary before it. Its receive ordinal *is* its entry id,
which rises one at a time, so arrival order never depends on the clock. A
datagram with no open session, or an entry id that repeats or skips, is
corruption.

A reader refuses a declared body length over 65,531 **before allocating
anything**. This is the rule `agentFraming.ts` follows for the pipe.

### The test vector

`npx tsx scripts/monitoring/measurement.ts vector` prints these bytes. An
implementation of this format must reproduce them exactly.

File header: generation `00 01 … 0f`, created `1700000000000`, policy `1`:

```
49 4e 57 49 52 45 4d 4a 01 00 01 00 40 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
00 68 e5 cf 8b 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 e2 31 78 45
```

Entry 1: a datagram received at `1700000000123` on `192.0.2.10:2055` from
`192.0.2.1:50000`, payload `00 05 00 00`:

```
49 57 4a 45 1c 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 fe 88 ca 1b
7b 68 e5 cf 8b 01 00 00 c0 00 02 0a 07 08 c0 00 02 01 50 c3 00 00 00 00 00 05 00 00
```

Entry 2: a boundary whose body is `{"action":"start"}`:

```
49 57 4a 45 12 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 9c 76 68 a6
7b 22 61 63 74 69 6f 6e 22 3a 22 73 74 61 72 74 22 7d
```

The vector pins **framing**, not the boundary schema. Its body is the
smallest valid JSON object, so it also checks that framing treats a body as
opaque bytes. In real use a session's first entry is its `start` boundary.

### Recovery: truncate only a torn tail

Opening scans every entry header and checks every CRC. Measured: 1.5 s for a
day at 7 a second and 3.4 s for a week at 2 a second. A header-only scan takes
a tenth of that.

- **A torn tail** is a bad or incomplete entry with nothing after it. Its
  header is cut short, or its declared extent reaches end-of-file. Only that
  is truncated. It is what an interrupted append leaves, and nothing valid
  lies behind it.
- **Interior corruption** is a bad entry with bytes after it. The file is
  **preserved**, append is refused, and the sheet reports the problem.
  History stays readable up to the bad entry. Later evidence is never
  truncated on a guess.
- **An unknown format or policy version** is treated the same way: preserved,
  append refused, problem reported. Old history is never reinterpreted under
  a different decoder policy, and a new policy needs its own migration design.
- **A session left open** by a crash (no `stop` before the end of the file)
  gets an `interrupted` boundary appended on the next open. Its `receivedMs`
  is the last entry's, so the time from there to the next `start` is a gap.

### Durability

An append is acknowledged once it is written to the OS. It is recoverable
after a process crash under normal OS behaviour, and **is not called
power-loss durable**. A one-second timer, and every Stop, flushes and moves a
separate `syncedThroughEntryId`. Measured at 7 a second, that flush costs 0.24
ms. An `fsync` per append was measured at 249 µs and rejected: it would cap
intake near 4,000 datagrams a second and buys nothing a one-second watermark
does not report.

### Receipt time, source identity and counting

- **History is bucketed by receipt time.** Every record in a datagram is
  filed under the minute its datagram was received in. A record's own flow
  start and end stay inspectable, but they never move it to another bucket.
  The sheet labels this *Received traffic records*. With the common 30-minute
  active timeout (see the survey), a long flow shows up as a spike every half
  hour, which is the reason it is not labelled bandwidth.
- **A source is the configured exporter address plus the v5 engine type and
  engine id.** The local bind, the session and the remote UDP port are
  provenance and stay in the evidence. A changing source port never splits a
  source, and a second engine never joins one. **At most 16 engines per
  exporter.** A datagram from a seventeenth is kept in the journal, counted
  as rejected (`engine-limit`) and never given a row.
- **Counters are `bigint` and summed exactly.** They become strings at the
  JSON and CSV boundaries, deliberately, because a day of 32-bit octet
  counters passes 2^53.
- **Unknown sampling stays unknown.** A v5 header's sampling field is
  reported as it is, and its absence is never read as 1:1.

### Rollups: the conversation is the directional address pair

The Worker computes rollups; the utility only stores them and never reads
them. One rollup covers one source and one receipt-time minute, and holds:

- exact bucket totals: records, reported octets, reported packets, malformed,
  unsupported
- every **endpoint** with octets sent and octets received
- every **conversation** keyed by **source address → destination address**,
  with reported octets and packets

This **revises the plan's `MinuteRollup`.** The conversation loses `srcPort`,
`dstPort` and `protocol`, and `QuerySpec.focus`'s conversation form loses them
too. Ports and protocols are answered by a **raw drill-down**: the same query
run over the journal, scoped to one endpoint or conversation and a short
range, and refused once it passes the raw budget. Measured on a day at 7 a
second:

| Key | Keys a minute | Distinct in a day | Sidecar a day, raw |
|---|---|---|---|
| 5-tuple | 11,691 | not measured, about one per record | as large as the journal |
| service port | 5,843 (7,285 peak) | 1,718,961 | 248 MiB |
| **address pair** | **3,974 (5,218 peak)** | **50,037** | **158 MiB** |

**The minute budget is 16,384 keys**, endpoints and conversations together.
It left no incomplete minute at 2 or 7 a second with address pairs, where
5,000 left 385 of 1,440. A minute over budget is stored **incomplete**: totals
exact, both maps empty. A query takes such a minute from the raw journal
within the raw budget, or refuses the range. It is never approximated.

**The rollup body is encoded by the Worker** and versioned by the policy
version. The sidecar uses this file's framing with its own magic,
`INWIREMR`. Each entry carries one minute, deflated with node's zlib at level
1, as the capture store does, which measured 59 MiB a day against 158 raw.

### Rebuild: from the journal, streamed, never trusted stale

The sidecar records the watermark it covers: `{ generation, throughEntryId,
policyVersion }`, plus its own CRCs. If the generation or policy differs from
the journal's, a CRC fails, or the watermark is past the journal's end, the
sidecar is **rebuilt, never trusted**. If the watermark is behind the end, the
missing tail is computed and appended.

A rollup answer and a raw-scan answer over the same complete minutes must be
**identical**. That is the test that holds the two together.

**Rebuild streams.** It holds one open minute per source, encodes it when a
later minute begins, and drops it. Its memory is therefore bounded by the
minute budget, not by the range. Measured: a day in 18.0 s at a peak heap of
159 MiB, a week in 38.0 s at 189 MiB. The version that kept every minute ran
out of memory.

**A receipt clock that steps back** files a datagram under an earlier minute
that has already been written. The rollup then gets a second **fragment**
for that `(source, minute)`. A reader sums fragments, takes the union of their
keys, and checks the union against the budget again, marking it incomplete if
it is now over. Entry ids still order everything, so a step back can split a
minute but cannot hide a record.

### Gaps, never zeros

A bucket is one of three things:

- **observed-records**: it holds records
- **no-records**: it lies inside a session and nothing arrived
- **collection-gap**: it lies outside any session

The time between a `stop`, `suspend` or `interrupted` boundary and the next
`start` or `resume` is a gap, and so is anything after a stop at the storage
limit. A `gap` boundary records datagrams shed locally, as a count. The
kernel's own drops cannot be observed, and are reported as unknown rather
than as a measured zero.

### Limits

| Limit | Value | Measured against |
|---|---|---|
| storage limit, default | **8 GiB**, minimum 16 MiB, of which 64 KiB is reserved for closing records | journal plus deflated sidecar, 0.88 GiB a day at 7 a second: about 9 days, and about 30 at 2 a second |
| minute key budget | **16,384** | the table above |
| raw query | 100,000 datagrams and 50,000 distinct keys | 1.7 s for 100,000 datagrams |
| range, per table | 50,000 endpoints, 50,000 conversations | a day's distinct address pairs, about 50,000 |
| buckets / top rows | 120 / 20 | |
| concurrent history queries | 2; a newer one for the same view supersedes the older | |

**At the limit, recording stops** with a `stop` boundary whose reason is
`storage-limit`. The gap is shown, and nothing is expired.

**Each table is bounded on its own.** A day's distinct address pairs reached
50,000 at both rates, and a real network can have more than the model's
ceiling, so a whole-query refusal would refuse most day and week views.
Instead, bucket totals are never refused. The endpoint and conversation
tables each have a 50,000-key bound, and a table that passes its bound comes
back empty with its own `range-too-large` and a narrower-range hint, while
the totals stay exact. **This revises the plan's `HistoryResult`**, which
gains a status per table. A range whose incomplete minutes pass the raw
budget is still refused whole, because then its totals cannot be exact
either.

## Retained-history semantics

- Nothing expires in milestone 1. Closing the app, stopping monitoring and
  any capture operation all leave history as it was.
- Committed history is everything up to the last acknowledged append, and the
  Worker catches up from its cursor after a reload or a crash. Recovery never
  counts an entry twice, because the entry id is the cursor.
- A query answers against a **snapshot**, `{ generation, throughEntryId }`,
  and a page past it returns `stale-generation` rather than a mixed answer.

## Consequences

- Product code is written against this framing, under its own tests, with the
  vector above as a fixed assertion. `measurement.ts` holds a prototype and is
  not product code.
- Port and protocol questions cost a raw drill-down. The sheet asks them only
  of a selected endpoint or conversation over a short range.
- The 8 GiB default is the owner's choice over the plan's 1 GiB, which held
  about 27 hours at the planning rate. The minimum stays 16 MiB, and the
  sheet shows the limit before the first Start.
