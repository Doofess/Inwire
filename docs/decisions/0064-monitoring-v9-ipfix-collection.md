# 0064 — Monitoring collects NetFlow v9 and UDP IPFIX: templates in their RFC scope, checkpointed and never buffered; counts as reported, with sampling, clock and sequence status

**Status:** proposed 2026-10-23. Measured in
[`docs/monitoring-v9-ipfix-measurements.md`](../monitoring-v9-ipfix-measurements.md).
It supersedes one item of
[0058](0058-monitoring-intake-and-lifetime.md)'s "Later, not built": v9 and
IPFIX. The other items in that list stay later.

## Context

[0058](0058-monitoring-intake-and-lifetime.md) collects NetFlow v5 only, and
the enterprise end of the vendor survey exports v9 or IPFIX. v5 is a fixed
layout. v9 and IPFIX are not: a data record means nothing without a template
received earlier, possibly much earlier, possibly before the app was last
closed. That one fact touches everything [0059](0059-monitoring-evidence-journal-and-rollups.md)
and [0062](0062-monitoring-segments-retention-archive.md) promise:

- a rollup must equal a raw scan;
- a rebuild must equal the live result;
- an expired segment must not take the templates the next segment needs.

0062 reserved the places milestone 2 needs: decoder policy 2, protocol-
qualified source keys, a checkpoint in the archive cut, and sidecar entry
kind 3. This ADR fills them.

The relevant standards:

- **RFC 3954 (NetFlow v9).** Templates are scoped by exporter address and
  Source ID. The sequence number counts export packets. The exporter
  refreshes templates every N packets and/or N minutes, with no defaults.
  The collector expires them after an unspecified timeout. Data that
  arrives before its template SHOULD be stored and decoded later.
- **RFC 7011 (IPFIX).**
  - §8: templates; a changed definition MUST replace the old one.
  - §8.4: over UDP, a template's scope includes the exporter's source port
    and the Observation Domain. Its lifetime SHOULD default to at least
    three times the observed retransmission interval. **Withdrawals MUST NOT
    be sent over UDP and MUST be ignored by UDP collectors.**
  - §3.1 and §10.3.2: the sequence number counts the Data Records sent
    *before* this message, modulo 2^32.
- **RFC 5103 (biflow).** A reverse element has the forward element's number
  with the enterprise bit set and PEN 29305.

The lab measured what two independent exporters send, and three decoders
agree on it:

- Both resend templates by **count only**: softflowd every 16 datagrams,
  pmacct every 18.
- softflowd's IPFIX sequence number **includes the current message's
  records**, against the RFC.
- softflowd's IPFIX flow times are uptime-relative and need IE 160.
- pmacct sends absolute 152/153 even in v9, and no options at all unless
  sampling is configured.

## Decision

### Intake

- The single configured IPv4 exporter may send v5, v9 or IPFIX (version 10)
  to the same port, and the version field selects the decoder. There is no
  protocol setting.
- Flows inside may carry IPv6 addresses. The exporter and the bind stay
  IPv4, and a bind of `0.0.0.0` is still refused (0058).
- Milestone 2 writes **decoder policy 2** and accepts policies {1, 2}
  (0062's accepted-policies rule).
  - Under policy 2, v5 decodes exactly as under policy 1.
  - A v9 or IPFIX datagram in a policy-1 segment stays *unsupported*,
    exactly as it was counted. Re-decoding history is a later, explicit
    feature.
- Out of scope: SCTP and TCP IPFIX, IPFIX files, several exporters, IPv6
  exporters, and sFlow.

### Source identity

- v5 keeps `ip/type/id`, a legacy identifier.
- v9 is `v9:ip/sourceId` and IPFIX is `ipfix:ip/odid`, both in decimal.
- `isEngineSourceKey` and `exporterOf` learn both forms.
- `LIMITS.enginesPerExporter` (16) bounds all three protocols together. The
  seventeenth source is kept in the journal and counted as rejected.
- A changing UDP source port never splits a source row (0059). For IPFIX it
  does change the template scope (below).

### Template scope

| Protocol | A template's scope |
|---|---|
| v9 | exporter address, Source ID (RFC 3954 §5.1) |
| IPFIX over UDP | exporter address, exporter source port, Observation Domain (RFC 7011 §8.4, §10.3) |

A template in one scope never decodes data in another; this is tested as
the isolation test. Template IDs below 256 are not templates and are counted
as malformed.

The collector keeps its own template store. The tree's first-wins
`MemoryTemplateStore` is for dissection parity and is not reused.

### Template lifecycle

- **A redefinition replaces.** The same ID with different field specifiers
  replaces the template from that entry on (RFC 7011 §8). Its interval
  history starts again. The same specifiers again are a refresh.
- **Withdrawals are ignored and counted.** An IPFIX template withdrawal, or a
  withdraw-all (a template record with field count 0), received over UDP
  changes nothing. It is counted per scope as *withdrawals ignored (RFC 7011
  §8.4)*. This departs from the spec's "a withdrawal removes": the RFC
  forbids a UDP exporter to send one and requires a UDP collector to ignore
  it. Honouring one would let a stray or replayed datagram disable a live
  template.
- **The lifetime.** A template is expired when a datagram of its scope
  arrives and **both** of these hold:
  - receipt time since it was last received exceeds
    **max(30 min, 3 × the longest receipt-time interval observed between
    its refreshes)**;
  - the scope's messages since it was last received exceed
    **max(48, 3 × the longest message interval observed between its
    refreshes)**.

  Expired templates of a scope are removed before that datagram is decoded.

  Why both conditions:
  - The 30-minute floor and the factor of three are RFC 7011 §8.4's
    guidance.
  - Every exporter measured refreshes by count, not by time. A slow
    exporter can therefore go hours between refreshes without anything
    being wrong, and a time-only lifetime would expire its templates during
    a quiet spell.
  - 48 is three refreshes of softflowd's 16.

  Intervals are measured only between two receipts in the same collection
  session.
- **Across a collection gap** (Stop, suspend, quit, or the app closed), the
  exporter may have restarted unseen. For the first datagram of each scope
  after a session's `start` boundary, the message condition counts as met,
  so templates past the time condition are expired then.
- **Templates carry across** Stop, app restart and suspend only within
  their lifetime, by way of the checkpoints below.

### Restart detection

A restart invalidates every template of the scope, resets that source's
sequence learning, and records a `source-restart` health event. A restart
is any of:

- **v9:** `sysUptime` decreases by more than 10 s, unless it is a wrap: the
  previous value within an hour of 2^32 ms and the new one under an hour. A
  smaller decrease is a reordered datagram, not a restart.
- **IPFIX:** the exporter's source port changes for the same exporter and
  Observation Domain. The new port is a new scope, and the old scope is
  dropped.
- **IPFIX:** `systemInitTimeMilliseconds` (IE 160) changes by more than 10 s.

### Data before its template

Data whose template is not in scope is **kept in the journal and neither
decoded nor buffered**:

- it is counted per (source, template ID) as **awaiting template**, with
  records unknown and bytes and sets counted;
- data for a template refused under the bounds is counted the same way,
  as **template refused**.

RFC 3954 suggests storing such data and decoding it later. That is
deliberately not done here, for two reasons:

- decoding it later would rewrite minutes that are already sealed;
- it would make a raw scan depend on when it ran.

### The raw-scan definition

A datagram is decoded with only those templates that were received
**strictly earlier in entry order** and are **still within their lifetime
at its receipt time**, under the rules above. The live path, a rebuild, a
raw query and the checkpoints all implement this one definition, so
rollups and raw scans agree.

### Bounds

| Limit | Value | Over it |
|---|---|---|
| `templatesPerScope` | 256 | the new template is refused and counted; nothing older is evicted |
| `templates` | 4,096 in all | refused and counted |
| `templateFieldBytes` | 768 KiB of field specifiers in all | refused and counted |
| `samplersPerSource` | 16 | refused and counted; the source's sampling becomes *unsupported* |
| `checkpointBytes` | 1,048,532 (1 MiB less the archive cut's 44 bytes) | cannot be reached within the three bounds above (measured worst case 972,106 B) |

The field budget exists because a template has no fixed size. 4,096
templates as large as one IPFIX set allows would not fit a checkpoint.

**A refused redefinition removes the old definition.** The exporter has
said the old one is wrong, and decoding with it would be worse than not
decoding.

Scopes are bounded by sources: each source has one live scope, because a
port change replaces the old one. That makes at most 16 scopes.

### Checkpoints

Template state is derived, and the monitoring Worker owns it. A
**checkpoint** is that state encoded after one entry: the templates and
their scopes, each source's sampling, samplers and sequence state.

The Worker produces checkpoints. The monitoring utility stores them as
opaque bytes, as it stores rollups. They are kept in two files:

- **The archive cut's checkpoint field** (0062), uncompressed, as of the
  cut's through entry. Expiring a segment leaves this checkpoint, so the
  remaining raw still decodes. Once the raw is gone it cannot be rebuilt.
  Expiry itself never needs the sidecar: its replay of what it drops starts
  at the previous cut's checkpoint, or from empty state when there is none.
- **Sidecar entry kind 3.** 0062 reserved it for segment starts. This ADR
  uses it for two roles:
  - **Role 1, segment start:** state up to the previous segment's last
    entry. It is written at the first segment start that is at least
    256 MiB of journal after the previous role-1 checkpoint, or after the
    oldest retained entry. At the 8 GiB default, where segments are
    256 MiB, that is every segment start. At smaller limits they are spaced
    out, so there are never more than limit / 256 MiB of them. A raw query
    or a rebuild that starts mid-journal begins at the nearest role-1
    checkpoint at or before it, or at the cut's, and replays forward:
    under 512 MiB of journal.
  - **Role 2, stop:** state at a `stop` boundary. It is written only when
    an hour or more of receipt time has passed since the latest kind-3
    entry. Tail catch-up after an open begins at the latest kind-3 entry at
    or before the rollup watermark, or at the cut's.

  The kind-3 body is laid out as follows:

  | Offset | Size | Field |
  |---|---|---|
  | 0 | 1 | role: `1` segment start, `2` stop |
  | 1 | 3 | reserved, zero |
  | 4 | 4 | encoded checkpoint length, at most `checkpointBytes` |
  | 8 | n | the checkpoint, deflated with the sidecar's injected deflate, as minutes are, and inflated under that length bound |

**The sidecar's bytes count toward the storage limit, kind 3 included**
(0059). The bound works out as follows:

- Role-1 entries are at most limit / 256 MiB checkpoints of at most
  1,048,532 bytes each, under 0.4% of the limit before compression.
- Role-2 entries are at most one per hour of collection.
- A typical exporter's checkpoint, a handful of templates, is about a
  kilobyte.
- After an expiry, 0062 rebuilds the sidecar. The rebuild writes exactly the
  kind-3 entries the live path would write for the retained journal, so
  checkpoints of expired segments go with them.

The rules for using them:

- A sidecar checkpoint is derived like everything in the sidecar. A bad CRC,
  a bad length or an unknown format discards it, and a rebuild writes it
  again.
- A damaged cut checkpoint cannot be rebuilt. The retained raw then decodes
  from empty state, its data counts as awaiting template until templates
  arrive, and the sheet says why.
- **The encoding is deterministic.** A checkpoint written live and the one
  a rebuild writes for the same entry are byte-identical. The tests compare
  them.

#### The encoding

Little-endian, like the other monitoring formats. Field specifiers are the
exception: they are copied from the wire unchanged, in network order. The
file starts with a 32-byte header.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `INWIREMT` |
| 8 | 2 | format, `1` |
| 10 | 2 | decoder policy the state was derived under, `2` |
| 12 | 2 | scope count |
| 14 | 2 | source count |
| 16 | 8 | through entry id |
| 24 | 8 | that entry's receipt ms |

Then the scopes, sorted by protocol, then Source ID or domain, then port.
Each scope is 36 bytes followed by its templates:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | protocol, `9` or `10` |
| 1 | 1 | flags: bit 0 a `sysUptime` is known, bit 1 IE 160 is known; others zero |
| 2 | 2 | exporter source port (IPFIX scope; for v9 the last seen) |
| 4 | 4 | exporter IPv4, network order |
| 8 | 4 | Source ID (v9) or Observation Domain (IPFIX) |
| 12 | 4 | last `sysUptime`, ms (v9) |
| 16 | 8 | `systemInitTimeMilliseconds` (IPFIX) |
| 24 | 8 | messages received in this scope |
| 32 | 2 | template count |
| 34 | 2 | reserved, zero |

Each template is 44 bytes followed by its field specifiers, in ID order:

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | template ID |
| 2 | 1 | flags: bit 0 options template, bit 1 v9 options (scope types are v9's) |
| 3 | 1 | reserved, zero |
| 4 | 2 | scope field count (options), else 0 |
| 6 | 2 | field count, scope fields included |
| 8 | 4 | longest refresh interval, ms; `0` not yet observed |
| 12 | 4 | longest refresh interval, messages; `0` not yet observed |
| 16 | 8 | entry id that defined it |
| 24 | 8 | last received, receipt ms |
| 32 | 8 | last received, as the scope's message count |
| 40 | 4 | n, field specifier bytes |
| 44 | n | field specifiers as received: 4 bytes each, 8 with an enterprise number; scope fields first |

Then the sources, sorted by key bytes. Each is `29 + k` bytes followed by
its samplers:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | k, key length |
| 1 | k | source key, ASCII |
| 1+k | 1 | sampling: `0` absent, `1` known, `2` unsupported |
| 2+k | 1 | flags: bit 0 a sequence number has been seen |
| 3+k | 2 | sampler count |
| 5+k | 4 | sampling interval N when known, else 0 |
| 9+k | 8 | sampling known since entry id |
| 17+k | 1 | sequence mode: `0` learning, `1` RFC, `2` own-records, `3` unrecognized |
| 18+k | 1 | discriminating pairs in the current learning window |
| 19+k | 1 | of them fitting the RFC convention |
| 20+k | 1 | of them fitting own-records |
| 21+k | 4 | last sequence number |
| 25+k | 4 | data records in that message |

Each sampler is 16 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | sampler ID (v9 IE 48), or the IPFIX options record's scope value |
| 4 | 2 | algorithm (v9 IE 49, IPFIX IE 304) |
| 6 | 2 | reserved, zero |
| 8 | 4 | interval (v9 IE 50, IPFIX IE 305) |
| 12 | 4 | space (IPFIX IE 306; 0 for v9) |

The trailer is a u32 CRC-32, as the journal's, over every byte before it.

#### The test vector

`npx tsx scripts/monitoring/measurement.ts checkpoint` prints this vector.
An implementation must reproduce it exactly. It encodes:

- the checkpoint through entry `4096`, at `1700000600000`;
- one IPFIX scope: exporter `192.0.2.1`, port `50000`, domain 0,
  `systemInitTimeMilliseconds` `1699990000000`, 4,090 messages;
- in ID order:
  - options template 256, with 1 scope field: `[143:4 305:4 306:4 304:2]`,
    defined at entry 17, last received `1700000590000` at message 4,080,
    interval 30,000 ms and 16 messages;
  - template 1024 `[8:4 12:4 22:4 21:4 1:4 2:4]`, defined at 17, last
    received `1700000000000` at message 4,080, with the same intervals;
- source `ipfix:192.0.2.1/0`: sampling known at 1-in-10 since entry 17;
  sequence mode RFC after 8 pairs, all 8 fitting RFC; last sequence number
  123,456, in a message of 30 records.

```
49 4e 57 49 52 45 4d 54 01 00 02 00 01 00 01 00 00 10 00 00 00 00 00 00 c0 8f ee cf 8b 01 00 00
0a 02 50 c3 c0 00 02 01 00 00 00 00 00 00 00 00 80 d1 4c cf 8b 01 00 00 fa 0f 00 00 00 00 00 00
02 00 00 00 00 01 01 00 01 00 04 00 30 75 00 00 10 00 00 00 11 00 00 00 00 00 00 00 b0 68 ee cf
8b 01 00 00 f0 0f 00 00 00 00 00 00 10 00 00 00 00 8f 00 04 01 31 00 04 01 32 00 04 01 30 00 02
00 04 00 00 00 00 06 00 30 75 00 00 10 00 00 00 11 00 00 00 00 00 00 00 00 68 e5 cf 8b 01 00 00
f0 0f 00 00 00 00 00 00 18 00 00 00 00 08 00 04 00 0c 00 04 00 16 00 04 00 15 00 04 00 01 00 04
00 02 00 04 11 69 70 66 69 78 3a 31 39 32 2e 30 2e 32 2e 31 2f 30 01 01 00 00 0a 00 00 00 11 00
00 00 00 00 00 00 01 08 08 00 40 e2 01 00 1e 00 00 00 b3 f3 bd ee
```

Like 0059's and 0062's vectors, it pins framing and layout. The values are
chosen to be recognizable, not to describe one consistent exporter.

### Options data

Options data is decoded, and it describes the exporter, never a flow. Its
records are not flows and are never totalled.

- **Sampling:** v9 IE 34/35 and the sampler table 48-50; IPFIX 305, 306 and
  304, plus IE 34/35 when an IPFIX exporter sends them.
- **`systemInitTimeMilliseconds`** (IE 160).
- **Interface names** (IE 82), shown beside the interface indexes 10/14.

### Sampling: counts as reported, the rate stated

- Counters are kept as reported. Nothing is scaled.
- Each source has a sampling status:
  - **known:** rate N, since entry X;
  - **absent:** no sampling information has been received. Absence never
    means 1:1;
  - **unsupported:** for example a random algorithm with no interval, or
    an IPFIX selector algorithm other than 1;
  - **changed in range:** a query-time status, when the rate is not
    constant over the range.
- **How the rate is derived:**
  - v9: IE 34 (`samplingInterval`) ≥ 1 gives N = IE 34, with IE 35's
    algorithm named. Data records that carry a sampler ID (IE 48) use that
    sampler's interval (IE 50).
  - IPFIX: selector algorithm 1 (systematic count-based, IE 304) gives a
    rate of 305 in 305 + 306, so N = (305 + 306) / 305.
  - An exporter that states 1-in-1 is *known* at 1: softflowd unsampled
    sends IE 34 = 1, or 305 = 1 with 306 = 0.
- The sheet shows the rate beside the values it qualifies.
- An **estimated** figure (reported × N) appears only when the status is
  known and constant over the range. It is labelled as an estimate and kept
  apart from reported totals.

### Clock: receipt time stays the history axis

- History is bucketed by receipt time, as in milestones 1 and 1.5.
- Each source has a **clock status**: export time from the header minus
  receipt time, for the latest datagram, plus the range's extremes. It is
  **flagged past ±10 s**.
  - The lab measured −11 to −1,002 ms. IPFIX export time is whole seconds, so
    up to −1 s is truncation.
  - 10 s is far above both and far below a minute bucket.
- Flow times are converted for inspection only:
  - v9 IEs 21/22 are converted against the header's export time and
    `sysUptime`.
  - IPFIX:
    - absolute seconds, milliseconds, microseconds and nanoseconds
      (150-157; the last four are NTP format, RFC 7011 §6.1.9);
    - the delta-microsecond forms (158/159) against the export time;
    - 21/22 only when IE 160 is known.
  - Otherwise a flow time is shown as **unknown**, never as the receipt
    time.
- A v9 `sysUptime` that goes backwards is a restart (above), not a clock
  fault.
- Interval-distributed (flow-time) history is a later feature with its own
  estimation design.

### Sequence numbers

The two RFC conventions:

- **v9** counts export packets per Source ID: the next number is the last
  plus 1 (RFC 3954).
- **IPFIX** counts Data Records, options data records included, sent
  *before* this message, per Observation Domain, modulo 2^32: the next
  number is the last plus the last message's data records (RFC 7011 §3.1).

There is also one alternate, measured from softflowd's IPFIX:

- **Own-records** is the last plus **this** message's flow data records,
  options data records excluded. It fitted 127 of 127 pairs counted that
  way, and the pairs carrying an options record fit only with it excluded.

No measured exporter shows whether an RFC exporter counts options data
records. In RFC mode, a message that follows one carrying options data
records is therefore expected at either number, with or without them, and
neither is a gap.

Each source learns its exporter's convention before it counts anything:

1. A **pair** is two consecutive messages of the source in entry order.
   For IPFIX, a pair is **discriminating** only if the RFC expectation and
   the own-records expectation differ. The lab found that most pairs fit
   both: whenever adjacent messages carry the same number of records, the
   two readings agree.
2. After **8 discriminating pairs** (v9: 8 pairs), the source is in:
   - **RFC** mode, if all 8 fit RFC;
   - **own-records** mode, if all 8 fit own-records. The sheet labels this
     mode as the exporter's own convention;
   - otherwise the window starts again. The mode is shown as
     **unrecognized** until a later window settles, and no gaps are counted
     meanwhile.
3. Once settled, a message whose number is ahead of the expected one by d
   (d < 2^31, modulo 2^32) adds d to the **suspected export gap**: export
   packets for v9, data records for IPFIX. Counting then continues from the
   received number. A wrap is not a gap.
4. A number behind the expected one is counted as **reordered or
   duplicate**. It changes no state, and no record is ever dropped for it.
5. A restart resets learning.

The suspected export gap is kept apart from local intake drops. It is
reported as evidence under stated assumptions, not as network loss.

### Information elements interpreted

The collector interprets these elements:

- addresses: IPv4 and IPv6 source and destination (8/12/27/28);
- ports (7/11) and protocol (4);
- counts:
  - delta octets and packets (1/2) and total octets and packets (85/86),
    up to 64-bit, as **bigint**;
  - totals are used only when a template has no delta count, and such a
    template is labelled *total counts*, because a long-lived flow exported
    with them is counted again at each export;
- every flow-time form above;
- interfaces (10/14), direction (61) and TCP flags (6);
- sampling and options, as above;
- **RFC 5103 reverse counts:** PEN 29305 with IE 1, 2, 85 or 86. A biflow
  record adds its forward direction to src → dst and its reverse to
  dst → src, so conversations stay directional (0059's key).

Everything else is kept in the journal, not interpreted:

- Unknown, enterprise and variable-length elements stay in the journal.
- Each template is listed with *"not interpreted: PEN n / IE m"*.
- A data template without any octet count is an **unsupported template**,
  named with its ID. Its records are counted but not totalled.

### Accounting differences are the exporters'

Counts are kept as the exporter reports them. The lab measured three
differences, and the sheet's help says so:

- softflowd counts bytes past the Ethernet header, padding included, and
  pmacct counts the IP length;
- nfdump scales sampled counts, and Inwire does not;
- nfdump sums a biflow record's two directions, and Inwire keeps them
  directional.

### Reuse of the tree decoder

`readFlowHeader`, `readFlowSets`, `setKind`, `readTemplateSet` and
`readDataRecords` (`flowExport.ts`) are reused. `normalizeFlows` and
`recordFrom` are not, for four reasons: they drop pre-template data and
options data silently, ignore withdrawal accounting, keep templates without
lifetimes, and read counters as `number`.

`flowExport.ts` behaviour stays unchanged for the tree, whose parity tests
stay green. Any shared fix is tested separately.

## Departures from the spec

The spec (`2026-10-19-monitoring-dataset-and-templates-design.md`) left
these to Task 7, or said otherwise:

- **Withdrawals are ignored over UDP and counted.** The spec says they
  remove templates. RFC 7011 §8.4 forbids the exporter to send them over
  UDP and requires the collector to ignore them.
- **The lifetime uses the *longest* observed interval, with a message
  condition beside the time condition.** The spec says "3x the refresh
  interval it was last seen at, never under 30 minutes". Every measured
  exporter refreshes by count, so time alone expires templates during a
  quiet spell.
- **Tail checkpoints are written at Stop, at most one an hour, not at every
  watermark advance.** Role-1 checkpoints are spaced 256 MiB apart rather
  than at every segment start below the default limit. Both choices keep
  the sidecar's share of the storage limit bounded; a near-bound checkpoint
  is about 950 KiB.
- **Restart detection has a 10 s tolerance**, so a reordered v9 datagram is
  not a restart. A change of IE 160 is also a restart; the spec names only
  uptime regression and a port change.
- **The IPFIX sequence convention is learned, not assumed.** softflowd
  departs from RFC 7011. A collector that assumed the RFC would report a
  false gap at every change in record count.

## Consequences

- **What Task 8 tests.** Each of these is a plain-tsx test:
  - template isolation and lifecycle: replace, refresh, lifetime under both
    conditions, the collection gap;
  - ignored withdrawals;
  - each restart signal;
  - awaiting template and template refused;
  - the bounds;
  - options decoding;
  - unknown and enterprise fields;
  - learning of both sequence conventions;
  - byte-identical checkpoints from live and rebuilt state.

  The datagrams come from `scripts/monitoring/exporter-vectors.json`,
  which two independent exporters authored: the eight fixture passes, plus
  the first 40 or 80 datagrams of each refresh pass. Those are long enough
  to see refreshes and to settle sequence learning. Cases no exporter
  produces are synthetic and cross-checked against tshark.
- **What it costs.** These are estimates composed from the readers, not
  measurements of the collector; Task 11 measures the real decoder in the
  Worker.
  - A day of v9 should take under 30 s to rebuild.
  - A mid-journal query replays under 512 MiB from its checkpoint, which
    should take under 10 s.
  - A checkpoint costs about a hundred bytes for a typical template, and is
    bounded at 1,048,532.
- **What is deliberately lost.** Data that arrives before its template is
  never decoded. With a count-only exporter that is at most one refresh
  period after a restart or a collection gap: 16 or 18 datagrams for the
  exporters measured.
- **Known limits:**
  - An exporter that sends one domain from several source ports at once
    looks like a series of restarts. The `source-restart` count makes this
    visible.
  - Whether options data records count toward the IPFIX sequence number
    follows the RFC, but no measured exporter distinguished the two.
  - A long idle spell between refreshes lengthens that template's lifetime
    from then on. A redefinition or a restart still replaces it.
- **Not run:** ipt_NETFLOW, hardware exporters, and SCTP or TCP IPFIX
  (the measurements report).
