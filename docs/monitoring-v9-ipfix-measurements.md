# Monitoring milestone 2: what v9 and IPFIX exporters send, and what decoding them costs

What two independent exporters actually put on the wire, read three ways,
and the decode and checkpoint costs ADR
[0064](decisions/0064-monitoring-v9-ipfix-collection.md) quotes. All of it
was measured before the collector's decoder exists. The throughput figures
come from the tree's readers in `flowExport.ts`, not from Task 8's decoder,
so they are a **pre-implementation estimate**. Task 11 measured the
collector's own decoder; see *The collector's decoder*.

Every number is a property of the machine it ran on: the machine in
[`monitoring-v5-measurements.md`](monitoring-v5-measurements.md#the-machine),
with WSL 2 running Ubuntu.

- `npx tsx scripts/monitoring/exporter-lab.ts [--write-vectors]` reproduces
  the exporter sections. It needs WSL with softflowd, pmacct, nfdump and
  python3, plus tshark on Windows.
- `npx tsx scripts/monitoring/measurement.ts v9decode` reproduces the decode
  costs.
- `npx tsx scripts/monitoring/measurement.ts checkpoint` reproduces the
  checkpoint figures.

All three scripts are in `check.ts`'s `NOT_TESTS`.

**Not run is not passed.** Everything this report would like to say but
could not measure is listed under **Not run**.

## The lab

| Tool | Version | Role |
|---|---|---|
| softflowd | 1.1.1 (Ubuntu package) | exporter |
| pmacct `pmacctd` with the `nfprobe` plugin | 1.7.8-4 (Ubuntu package) | second, independent exporter |
| nfdump (`nfcapd`, `nfdump`) | 1.7.6-1 (Ubuntu package) | independent decoder |
| tshark | 4.6.9 on Windows | independent decoder |

pmacct and nfdump were installed in WSL only, with the owner's approval as
recorded in the spec. Nothing was installed on Windows, and nothing is
shipped. The Ubuntu package starts an `nfdump.service` on install. It was
stopped and disabled, because the lab runs its own `nfcapd` per pass.

Neither exporter ever read a real capture. They read two generated ones:

- **the fixture:** the synthetic capture `interop.ts --fixture-only` writes.
  It has 612 frames, 16 directional IPv4 pairs, 7 non-IP frames and 102
  expected records.
- **the refresh capture:** 4,000 one-packet UDP flows over four seconds,
  long enough to show how each exporter refreshes its templates.

Both captures are copied into WSL's `/tmp`. IE 82 (interface name) therefore
carries a WSL path, never a Windows one.

Each exporter sends to a keeper process in WSL. The keeper records every
datagram with its receipt time and source port. The recorded bytes are then
read three ways:

- by the readers in `flowExport.ts` (`readFlowHeader`, `readFlowSets`,
  `readTemplateSet`, `readDataRecords`);
- by tshark's `cflow` decode;
- replayed into `nfcapd`, then summarised by `nfdump`.

`scripts/monitoring/exporter-vectors.json` holds the datagrams as hex, with
their source ports, relative receipt times and the three decoders' totals
over what was kept. It contains:

- every fixture pass;
- the first 40 (v9) or 80 (IPFIX) datagrams of each refresh pass: enough to
  see refreshes and to learn a sequence convention (ADR 0064).

A plain-tsx test can therefore decode them without WSL. A vector proves something only when the end that authored it is not
the end under test (`scripts/CLAUDE.md`); these were authored by two
exporters, neither of them ours.

## What each exporter sends

Template IDs and fields are given as `IE:length`, with `PEN/IE` for
enterprise fields. In every pass, both exporters used source ID or
observation domain 0, and sent every template in the first datagram.

| Pass | Data templates | Options template | Flow times |
|---|---|---|---|
| softflowd `-v 9` | 1024 (IPv4), 1025 (ICMPv4, `32:2` in place of ports), 2048 (IPv6, `27:16 28:16`), 2049 (ICMPv6, `139:2`); 16 or 14 fields, 4-byte counters `1:4 2:4` | 256, 1 scope: `[2:4 34:4 35:1 82:16]`; IE 34 = 1, IE 35 = 1 | `22`/`21`, uptime-relative |
| softflowd `-v 9 -s 10` | as `-v 9` | as `-v 9`; IE 34 = 10 | `22`/`21` |
| softflowd `-v 10` | as `-v 9`, in set 2 | 256 in set 3, 1 scope: `[143:4 160:8 305:4 306:4 304:2 82:16 130:4 131:16 403:4 404:16]`; 305 = 1, 306 = 0, 304 = 1 | `22`/`21`, with IE 160 in options |
| softflowd `-v 10 -b` | as `-v 10`, plus `29305/1:4 29305/2:4 29305/5:1` and `29305/6:1` (1024, 2048), `29305/32:2` (1025) or `29305/139:2` (2049) | as `-v 10` | `22`/`21` |
| softflowd `-v 10 -s 10` | as `-v 10` | as `-v 10`; 305 = 1, 306 = 9 | `22`/`21` |
| softflowd `-v 10 -A milli` | as `-v 10`, with `152:8 153:8` | as `-v 10` | `152`/`153`, absolute ms |
| pmacct `nfprobe_version: 9` | 1024, 1025, 2048, 2049: `[153:8 152:8 1:8 2:8 60:1 10:4 14:4 61:1 …]`, 8-byte counters | none (sent only when sampling is configured) | `152`/`153`, absolute ms, **even in v9** |
| pmacct `nfprobe_version: 10` | the same four, in set 2 | none | `152`/`153` |

What this means for the decoder:

- **Flow times differ by exporter.** softflowd's flow times in IPFIX are
  uptime-relative 21/22 and become absolute only through IE 160
  (`systemInitTimeMilliseconds`), which it sends in its options data.
  pmacct sends absolute milliseconds, 152/153, in v9 as well as in IPFIX.
- **A sampling status of 1-in-1 is stated, never assumed.** Unsampled
  softflowd still says 1-in-1: IE 34 = 1 in v9, and 305 = 1 with 306 = 0 in
  IPFIX. pmacct sends no options template, so its sampling status is
  *absent*.
- **Bidirectional records (`-b`) carry the reverse direction under the RFC
  5103 PEN**, 29305, with the forward IE numbers.
- **No exporter here sends a withdrawal, a variable-length field, a
  non-zero domain, or a template redefinition.** Those cases are synthetic
  only (ADR 0064).

## Totals, three ways

| Pass | Datagrams | Records | Packets | Octets | Readers vs tshark | nfdump |
|---|---|---|---|---|---|---|
| softflowd `-v 9` | 4 | 105 | 609 | 161,644 | agree | agrees |
| softflowd `-v 9 -s 10` | 3 | 56 | 62 | 4,524 | agree | 620 packets, 45,240 bytes: **scaled ×10** |
| softflowd `-v 10` | 4 | 105 | 609 | 161,644 | agree | agrees |
| softflowd `-v 10 -b` | 3 | 56 | 348 + 261 reverse | 78,875 + 82,769 reverse | agree | 609 packets, 161,644 bytes: **both directions summed** |
| softflowd `-v 10 -s 10` | 3 | 56 | 62 | 4,524 | agree | **scaled ×10** |
| softflowd `-v 10 -A milli` | 5 | 105 | 609 | 161,644 | agree | agrees |
| pmacct v9 | 15 | 105 | 609 | **159,184** | agree | agrees |
| pmacct v10 | 15 | 105 | 609 | **159,184** | agree | agrees |
| refresh, all four | 127 to 519 | 4,000 | 4,000 | 240,000 | agree | agrees |

The decoders agree on every pass except for three accounting differences,
which are properties of the exporters and decoders, not errors:

- **The two exporters count different bytes.** pmacct counts the IP total
  length. softflowd counts everything past the Ethernet header, including
  padding on short frames. On the same capture that is 159,184 against
  161,644 octets.
- **nfdump scales sampled counts.** Inwire keeps counters as reported and
  states the rate beside them (spec, *Sampling*).
- **nfdump sums a biflow record's two directions into one total.** Inwire
  keeps them directional: forward is source to destination and reverse is
  destination to source (ADR 0059's key).

tshark files reverse counts under `cflow.octets` and `cflow.packets` too, and
marks them only in its verbose tree ("Reverse Type 1 BYTES"). The lab reads
those lines and subtracts them. Read naively, tshark's field totals are
nfdump's sums.

## Template refresh

From the refresh capture:

| Exporter | Templates and options template resent | By |
|---|---|---|
| softflowd v9 and IPFIX | at datagram 0, then every **16** datagrams (0, then 16 ×7 of 127) | count only |
| pmacct v9 and IPFIX | at datagram 0, then every **18** datagrams (0, then 18 ×28 of 519) | count only, hard-coded |

Neither exporter refreshes on a timer. The source code agrees:

- softflowd 1.1.1 resends every 16 export packets;
- pmacct 1.7.8 resends every 18, a constant.

At a slow trickle, a refresh can therefore be minutes or hours apart. That
is why ADR 0064's lifetime has a message-count condition alongside the
30-minute time condition.

## Sequence numbers

| Exporter | Header sequence counts | Fits RFC? |
|---|---|---|
| softflowd v9 | export packets, from 1 (deltas 1 ×126) | yes: RFC 3954 |
| pmacct v9 | export packets (deltas 1 ×518) | yes: RFC 3954 |
| pmacct IPFIX | data records sent **before** this message (518 of 518 pairs) | yes: RFC 7011 §3.1 |
| softflowd IPFIX | data records **including this message's own** (127 of 127 pairs) | **no** |

softflowd's IPFIX sequence is off by one message. Under RFC 7011's reading,
every message where the record count changes would show a gap of the
difference.

Many message pairs fit both readings, because the two counts are equal
whenever adjacent messages carry the same number of records:

- softflowd's refresh pass: the RFC reading fits 111 of its 127 pairs;
- pmacct's: softflowd's reading fits 460 of 518.

Only a pair whose record counts differ tells the two apart. ADR 0064 learns
the convention from such pairs alone.

Options records cannot settle whether an options data record counts:

- pmacct sends none;
- softflowd sends one per refresh, and the lab's options-inclusive reading
  fits exactly as many of its pairs as the data-only one.

ADR 0064 follows RFC 7011's definition, under which options data records
are data records. That case is synthetic only.

## Clocks

The header's export time minus the receipt time ranged from **−32 to
−1,002 ms** across all passes of the run that wrote the vectors (earlier runs: −11 to −997 ms). IPFIX export time is whole seconds, so up to
−1 s of that is truncation. WSL's virtual network accounts for the rest.

pmacct v9's first sysUptime was about 4 s; softflowd's was 0.

## Decode throughput

A day at the planning rate of 7 datagrams a second is 622,570 datagrams.
Each pass's recorded datagrams were repeated to that count and read back by
the readers, with no rollup work:

| Input | Mean datagram | Time for a day | Datagrams/s | Records/s | MiB/s | A 256 MiB segment |
|---|---|---|---|---|---|---|
| v5, `decodeV5` (baseline) | 1,464 B, 30 records | 1.51 s | 411,381 | 12,341,432 | 574.4 | - |
| softflowd v9 | 1,187 B | 8.42 s | 73,930 | 2,045,392 | 83.7 | 3.1 s |
| softflowd IPFIX | 1,211 B | 9.24 s | 67,398 | 1,909,606 | 77.8 | 3.3 s |
| softflowd IPFIX `-b` | 1,114 B | 10.74 s | 57,959 | 1,217,130 | 61.6 | 4.2 s |
| pmacct v9 | 452 B | 2.85 s | 218,261 | 1,605,774 | 94.0 | 2.7 s |
| pmacct IPFIX | 448 B | 2.88 s | 216,391 | 1,592,019 | 92.4 | 2.8 s |

The readers decode records about six times more slowly than v5's fixed
layout. The slowest pass still reads more than 8,000 times the planning rate.

These ran on Node's main thread, not in the monitoring Worker, and no
rebuild was run. Two figures are therefore **estimates composed from the
table**, not measurements:

- **A day of v9 rebuilt from its nearest checkpoint:** 8 to 11 s of
  decoding, plus the rollup work 0059 measured at 18 s a day for v5. That
  is under 30 s a day.
- **A raw query starting mid-journal:** it replays at most 512 MiB from its
  checkpoint (ADR 0064 spaces them 256 MiB apart, at segment starts). At
  the slowest pass's rate that is under 10 s.

## The collector's decoder

`npx tsx scripts/monitoring/measurement.ts v9collector` (Task 11) times the
code the Worker runs, not the readers. Each recorded pass is repeated to a day
(622,570 datagrams), with its template datagram re-sent every 16 datagrams as
softflowd does and the headers rewritten so that clock, uptime and sequence
run on at 7 a second. One pass of each recording first gives the same record
count through the collector as through the readers.

The figures below are from a `node:worker_threads` thread, the nearest
plain-tsx stand-in for the Chromium Worker; the main thread's were within
run-to-run spread of them. Two full runs were made, the first beside an
Electron drive; where they differ, both are given.

| Input | Decoder only, a day | Datagrams/s | Decoder and the Worker's rollup step, a day | Datagrams/s | A 256 MiB segment, with rollups |
|---|---|---|---|---|---|
| v5, 30 records (baseline) | 2.0 s | 304,474 | 60.1 s | 10,366 | - |
| softflowd v9 | 15.4 to 16.1 s | 38,596 | 20.9 to 22.4 s | 29,837 | 7.5 s |
| softflowd IPFIX | 15.6 s | 40,031 | 20.3 s | 30,617 | 7.2 s |
| softflowd IPFIX `-b` | 12.8 s | 48,479 | 18.3 s | 33,944 | 7.0 s |
| pmacct v9 | 4.7 s | 131,345 | 6.6 s | 95,066 | 6.3 s |
| pmacct IPFIX | 4.8 s | 129,954 | 6.7 s | 93,408 | 6.5 s |

- **The collector decodes 1.2 to 2.5 times more slowly than the readers**
  above. It keeps template, sequence, clock and sampling state per datagram,
  which the readers do not. The slowest pass with rollups still runs about
  4,000 times the planning rate.
- **The v5 baseline's rollup step is not 0059's 18 s a day.** These flows
  have about 10,000 distinct address pairs a minute, near the key bound,
  where 0059's workload had fewer. A profile puts 4.6 to 5.6 s in
  `ipv4Number`, called from `byAddress` on every sort comparison when a minute
  is sealed. The final review fixed that by computing each row's key once
  before sorting. The quick run's v5 decode plus rollup went from 5.39 s to
  2.67 s, while v9 stayed at 2.0 s. The full-day figures above are from
  before the fix.

**A day rebuilt through the runtime.** A day of v9 was written under policy
2 through `MonitoringJournal`, then read by the real `MonitoringWorkerHost`
over `LocalRuntime` and `RollupStore`:

| Journal | Whole-day rebuild (empty sidecar) | An hour's catch-up with the sidecar current |
|---|---|---|
| softflowd v9: 741 MiB, 3 segments | 25.4 s, 30.7 s on the second run | 7.9 s, from the checkpoint at entry 430,443 (217,331 entries) |
| pmacct v9: 295 MiB, 2 segments | 10.8 s, 17.5 s | 9.5 s, from entry 1: no checkpoint, the second segment being under 256 MiB from the first |

ADR 0064's estimates, against these:

- **"A day of v9 should take under 30 s to rebuild":** on the line, 25 to
  31 s for softflowd's records.
- **"A mid-journal query replays under 512 MiB from its checkpoint, which
  should take under 10 s":** the bound on what is replayed holds, by the
  checkpoint spacing; the time does not. At 7.0 to 7.5 s per 256 MiB with
  rollups, 512 MiB is 14 to 15 s, and decoding alone is 9 to 12 s.

Table C used node's zlib and a host clock that never yields; the Worker
inflates with fflate and yields between messages.

## The checkpoint

The prototype encoder in `measurement.ts checkpoint` follows the layout ADR
0064 pins:

| Contents | Encoded | Of which field specifiers | Encode | Deflated |
|---|---|---|---|---|
| the vector: 1 scope, 2 templates, 1 source | **246 B** | 40 B | - | - |
| 4,096 templates like softflowd's 1024 (16 fields) | 447,818 B | 256.0 KiB | 8.6 ms | 5,676 B |
| 4,096 templates like softflowd `-b` (20 fields, 4 enterprise) | 578,890 B | 384.0 KiB | 6.0 ms | 12,001 B |
| 4,096 templates of 48 fields | 972,106 B | 768.0 KiB | 12.8 ms | 12,099 B |
| the worst a 768 KiB specifier budget allows | **972,106 B** (949.3 KiB) | 768.0 KiB | 10.7 ms | 11,989 B |

The sidecar's and the archive's framing take a body of at most 1,048,576 B,
and an archive cut spends 44 bytes before its checkpoint (ADR 0062). A
checkpoint of at most **1,048,532 B** therefore fits a cut, and the worst
case leaves 74 KiB of headroom.

A template has no fixed size. Without a field budget, 4,096 templates of a
legal 65,535-byte IPFIX template set would not fit, so ADR 0064 bounds the
specifiers as well as the count.

The deflated sizes are of identical synthetic templates and flatter
compression. The encoded size is the one that gets bounded.

## Through the app

`npx tsx scripts/monitoring/interop.ts --templated-only` (Task 11) replays
each pass's recorded datagrams from the lab into the built app, over
loopback, and reads the result three ways: the sheet, the rollup path and the
raw path of the closed profile's journal. `--v5-only` runs the v5 passes of
[the v5 report](monitoring-v5-measurements.md). On 2026-10-23 every pass
passed (139 checks for v9 and IPFIX, 28 for v5):

| Pass | Datagrams | Records | Packets | Octets | nfdump |
|---|---|---|---|---|---|
| softflowd `-v 9` | 4 | 105 | 609 | 161,644 | equal |
| softflowd `-v 10` | 4 | 105 | 609 | 161,644 | equal |
| softflowd `-v 10 -b` | 3 | 56 | 348 + 261 reverse | 78,875 + 82,769 reverse | 609 / 161,644: both directions summed |
| softflowd `-v 9 -s 10` | 3 | 56 | 62 | 4,524 | 620 / 45,240: scaled ×10 |
| softflowd `-v 10 -s 10` | 3 | 56 | 62 | 4,524 | 620 / 45,240: scaled ×10 |
| pmacct nfprobe v9 | 15 | 105 | 609 | 159,184 | equal |
| pmacct nfprobe v10 | 15 | 105 | 609 | 159,184 | equal |

For every pass:

- the sheet's record count and accepted datagrams equal tshark's records and
  the datagrams sent;
- the exporter card names the source (`NetFlow v9, source ID 0` or
  `IPFIX, domain 0`) and says every data set had its template, and a
  sampled pass's card says `Sampled 1 in 10`;
- History's estimate on a sampled pass is the reported packets ×10, which is
  nfdump's scaled total, labelled an estimate;
- Top endpoints and Top conversations on the sheet, and every endpoint and
  directional pair on both query paths, equal tshark's per record, exactly,
  with a biflow's reverse counts as the destination-to-source leg;
- the journal holds one source for the exporter, and the rollup and raw paths
  agree on everything but provenance.

The three accounting differences above are asserted as differences: nfdump's
scaled and summed totals are checked against the app's reported ones times
the interval, or forward plus reverse.

## Under fault and load

`npx tsx scripts/electron/monitoring-drive.ts` adds four v9 scenarios to the
v5 ones, each checked on the sheet and then against the closed profile's
journal by an offline oracle. On 2026-10-23 every scenario passed in 379 s,
except 10 and 15, which were not run:

- **13, exporter restart mid-run.** v9 template and data, then data-only
  datagrams with the uptime stepped back to 5 s. The card shows the restart
  and the data sets that waited for template 256, and the record count does
  not move. Template and data again, and it grows by exactly the new
  records. The journal holds every datagram, and both query paths equal the
  ledger of decodable records only.
- **14, app restart within the template lifetime.** Template and data, Stop,
  close, reopen, Start, then data-only datagrams: they decode, nothing waits
  for a template, and no restart is counted.
- **15, app restart past the lifetime.** Not run: it needs 31 minutes of wall
  clock and runs only with `--lifetime`.
- **16, retention expiry during v9.** The 16 MiB limit with the oldest
  segment expired at the limit, and 297 datagrams of about 58 KB. A segment
  expires, data-only datagrams still decode, nothing is shed and intake goes
  on. History over the whole run equals the ledger, with the expired part as
  aggregate-only. The retained journal, replayed from the archive cut's
  template state, equals the raw answer. After Stop, the sidecar is rebuilt
  from the retained journal within about 2 s.

  A first run quit straight after Stop and left `rollups.iwmr` at 64 bytes,
  the header alone. Every expiry resets the sidecar to the journal's new start
  (ADR 0062), and the Worker is not told. So its first post after the expiry
  continues from the old watermark and is refused ("does not continue the
  sidecar"), and the retry a second later rebuilds it. That run quit inside
  the second. Answers stayed exact throughout, and the next open rebuilds. The
  room the limit left was 2.6 MB against a batch of a few hundred bytes, so
  this was not a storage refusal. `scripts/monitoring/expiry-sidecar.ts`
  holds the sequence, and the drive now waits for the sidecar to grow.

  What that reset costs at the default limit is estimated, not measured. At
  8 GiB a segment is 256 MiB and an expiry at the limit frees two. At
  softflowd's day of 741 MiB, that is an expiry about every 17 hours. Each one
  rebuilds the roughly 10 days still retained, from the archive cut's
  checkpoint. At the measured 25 to 31 s a day, that is 4 to 5 minutes of
  Worker time, and History reads "Rebuilding summaries" meanwhile. ADR 0062
  chose reset-and-rebuild and allows a compaction once a test shows it equal.

`npx tsx scripts/monitoring/load.ts --quick --protocol v9` (and `ipfix`)
sends templated datagrams, the template set in the first and every 20th:

| | v9 | IPFIX |
|---|---|---|
| Highest rate sustained | 199.2/s, all accepted, none shed | 199.0/s, all accepted, none shed |
| Restart, history back | 5,281 ms | 5,023 ms |
| Restart with the sidecar deleted (a rebuild), history back | 6,030 ms | 5,912 ms |
| Records before and after the restart | 65,899, equal | 65,939, equal |
| Storage exhaustion: offered, accepted, shed | 11,169, 10,963, 0 | 11,176, 10,779, 0 |

Both stopped at the 16 MiB limit with the guidance shown and the history
still readable.

## Not supported

These are outside milestone 2, by decision, and the app says so rather than
guessing:

- **IPFIX over SCTP or TCP.** The collector binds UDP only.
- **IPv6 exporters.** The exporter's address and the bind are IPv4
  (`config.ts`). IPv6 *flow* addresses inside v9 and IPFIX records are
  decoded and kept in policy-2 minutes (ADR 0066).
- **Reprocessing policy-1 segments.** Datagrams journalled before the upgrade
  stay under the policy they were written with; v9 and IPFIX in them count as
  unsupported and are not decoded again (ADRs 0062 and 0064).
- **ipt_NETFLOW and hardware exporters:** not run and unverified; see below.

## Not run

- **ipt_NETFLOW:** it needs a kernel module that WSL does not offer.
- **Hardware exporters** (Cisco, FortiGate, PAN-OS, Juniper, Meraki,
  MikroTik, OPNsense, pfSense, Sophos): none was available, so they remain
  unverified, as the survey said.
- **SCTP and TCP IPFIX:** out of scope.
- **Template withdrawals, variable-length and enterprise-specific fields
  other than RFC 5103's, redefinition, non-zero domains and source IDs, an
  IPFIX port change and malformed sets:** no exporter here produces them.
  They are synthetic cases in Task 8's tests, each cross-checked against
  tshark.
- **An app restart past the template lifetime** (drive scenario 15): it
  needs 31 minutes of wall clock and runs only with `--lifetime`. The
  lifetime rule itself is held by Task 8's template-store tests.
- **The decoder in the Chromium Worker itself:** it was timed in a Node
  worker thread and on the main thread, not in the sandboxed Worker.
- **A real network path:** every datagram crossed WSL's virtual network on
  one machine.
