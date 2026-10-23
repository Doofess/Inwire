# 0066 — Policy 2 reaches the stores: it starts at the next Start, a policy-2 minute keeps full addresses and template totals, and checkpoints are indexed by entry

**Status:** accepted 2026-10-23 by the owner, before Task 9 wired
[0064](0064-monitoring-v9-ipfix-collection.md)'s decoder into the journal, the
rollup sidecar, the archive and the queries. The owner chose four rulings:
policy 2 starts at the next Start, policy-2 minutes keep full IPv6 addresses,
biflow totals count both directions, and *awaiting template* counts data sets.
It amends one detail of 0064, the kind-3 body, which no file holds yet, and
leaves everything else in 0059, 0062 and 0064 standing.

## Context

0062 and 0064 decide *that* datagrams decode under their segment's policy, that
the archive cut and sidecar kind 3 carry checkpoints, and that the rollup bytes
start with their policy. They leave six things open, and each is a format or a
user-visible number:

- **When policy 2 starts.** The journal rolls a segment only when one is full
  or legacy. An upgraded dataset would keep appending into its policy-1
  segment, where v9 and IPFIX stay *unsupported* for good, for up to 256 MiB.
- **Where a reader learns the policy.** Evidence read from the journal does
  not say which segment it came from.
- **What the sidecar's policy means.** 0059's sidecar records one policy for
  the file and refuses any other. A 1.5 cache, of policy 1, is followed by
  policy-2 minutes, so one policy per file cannot describe it, and wiping
  the cache on upgrade would be a full rebuild that nothing requires.
- **What a policy-2 minute stores.** 0059's minute stores addresses as 4 bytes
  and has no field for awaiting or unsupported-template data, sampling or
  clock. Archived minutes are kept for good, so this is a durable format.
- **How a checkpoint is found.** 0064's kind-3 body holds the checkpoint
  deflated, so the store, which never inflates, cannot tell which entry it
  belongs to.
- **Who computes the cut's checkpoint, and what a raw scan replays.** Expiry
  runs in the monitoring utility, and 0064 says the Worker produces
  checkpoints.

## Decision

### Policy 2 starts at the next Start

- The journal starts a new segment at its next append whenever its newest
  segment's policy is older than the policy it writes. For an upgraded
  dataset, that append is the next Start's `start` boundary, so v9 and IPFIX
  decode from the first Start after the upgrade.
- Evidence read from the journal carries its segment's **policy** and the
  first entry id of its segment, **segmentFirstId**. A datagram is decoded
  under that policy, as 0062 says.

### The sidecar records the highest policy it has decoded

- The sidecar header's policy is the policy the file was created under. Each
  watermark entry's policy is the highest policy of any minute it covers.
- Watermark policies never decrease. The header and every watermark must be
  in the accepted policies and no newer than the written one. Anything else
  is `rebuild-required`, as before.
- A 1.5 cache therefore opens `ok` and is continued. Its minutes keep policy
  1, and only the entries past its watermark decode under policy 2. Nothing
  is rebuilt.
- A minute is encoded under the policy of the segment its entries came from.
  When the policy changes, the aggregator seals its open minutes, as at a
  `stop`. In practice that only happens at a `start`, after a `stop` has
  already sealed them.

### A policy-2 minute

The u16 policy prefix and the deflate are 0059's. Inside the deflate, in this
order:

| Field | Encoding |
|---|---|
| flags | u8: bit 0 complete, bit 1 clock present |
| source key | u16 length, then UTF-8 |
| minuteMs, records, reportedOctets, reportedPackets, malformed, unsupported, unknownSamplingRecords | u64 each, as in policy 1 |
| awaitingSets, awaitingBytes, unsupportedTemplateRecords, unsupportedSamplingRecords | u64 each |
| samplingInterval | u32: `0` when no record states one, `0xffffffff` when the records state different ones |
| clock, only when flag bit 1 is set | i64 minSkewMs, i64 maxSkewMs, i64 lastSkewMs |
| endpoints | u32 count, then for each: u8 address length (4 or 16), the address, u64 sent, u64 received |
| conversations | u32 count, then for each: u8 length, src, u8 length, dst, u64 octets, u64 packets |

- Rows are sorted by address bytes, and a 4-byte address sorts before a
  16-byte one. The encoding is deterministic, so a replay produces the same
  bytes.
- Policy-1 bytes are unchanged, and a policy-1 minute reads with the new
  fields as zero and no clock.

### What the counts mean

- **Biflow (RFC 5103).** The forward counts go to src → dst and the reverse
  counts to dst → src: the source sends the forward octets, the destination
  sends the reverse ones, and conversations stay directional (0059's key).
  **Bucket totals count both directions**, so they equal the sum of the
  conversation rows. The record counts once.
- **Awaiting template counts data sets.** It covers data whose template was
  not in scope and data whose template the bounds refused, with their bytes
  kept alongside. Records inside such sets are unknown.
- **An unsupported template's records** count in `records` and
  `unsupportedTemplateRecords`, and are not totalled.
- **A record's sampling** is its own interval (IE 34 or 50), else its
  sampler's rate, else its source's sampling status after its datagram's
  options. A *known* status gives the interval, *absent* counts the record in
  `unknownSamplingRecords`, and *unsupported* counts it in
  `unsupportedSamplingRecords`. A v5 record reports its header's interval,
  and an interval of 0 counts as 1.
- **Clock skew** is a v9 or IPFIX datagram's export time less its receipt
  time. v5 records none.
- **A range's answer** sums its minutes:
  - *awaiting template* is the sum of the sets;
  - *unsupported templates* is the sum of those records;
  - *sampling* is *unsupported* if any record was, else *absent* if no record
    stated a rate, else *known* with the one interval, else *mixed*;
  - *clock* is the minimum and maximum skew and the last minute's last skew,
    flagged when either bound is past `clockFlagMs`.

  The live per-source status, with its reasons and its sequence state, is
  pushed separately and is not part of a history answer.

### Kind 3 is indexed by entry (amends 0064)

The kind-3 body becomes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | role: `1` segment start, `2` stop |
| 1 | 3 | reserved, zero |
| 4 | 4 | deflated checkpoint length |
| 8 | 8 | u64 through entry id, equal to the checkpoint's own |
| 16 | 8 | u64 through receipt time, equal to the checkpoint's own |
| 24 | n | the checkpoint, deflated with the sidecar's injected deflate and inflated under `checkpointBytes` |

- Kind-3 entries are written in the same batch as minutes, before its
  watermark entry, and a checkpoint's through entry is at or below that
  watermark. A batch's minutes may be empty when it carries only a
  checkpoint.
- The roles' spacing is computed from the retained journal alone, so a
  rebuild writes the entries the live path would:
  - the base is the archive's last cut, or else the first retained entry;
  - role 1 is measured in retained segment bytes from the base or the
    previous role-1 entry;
  - role 2 is measured in receipt time from the latest kind-3 entry, or else
    from the base.

### Which checkpoint is used

- A reader that needs the state before entry *n* uses the newest checkpoint
  whose through entry is below *n*. That is any kind-3 entry of either role,
  or the archive's last cut. Without one, it uses empty state, from the first
  retained entry.
- A checkpoint that fails its own decode (its CRC, its lengths, its format)
  is skipped in favour of the one before it, and is never trusted. A sidecar
  whose framing CRC fails is still `rebuild-required` as a whole, as 0059
  says.
- **The cut's checkpoint is computed by the expiry's replay**, the same pure
  code the Worker runs, starting from the previous cut's checkpoint. Expiry
  never needs the sidecar (0064), and the utility runs it. The Worker still
  produces every sidecar checkpoint.
- **A raw scan replays state without counting it.** It replays from the
  checkpoint up to its window, and only the window counts toward
  `rawQueryDatagrams`.
  - The replay is bounded by `replayBytes`, 512 MiB of entry bytes. A
    v9 or IPFIX query that needs more is refused as range too large, and the
    message says the checkpoints are missing.
  - A v5 source needs no state, and neither does a policy-1 segment, so
    neither replays.

## Consequences

- An upgraded dataset decodes v9 and IPFIX from its next Start. What it
  recorded before stays exactly as it was counted.
- The 1.5 cache survives the upgrade. `policy-1-cache-under-policy-2` tests
  that.
- `checkpoint-rebuild-equals-raw` can compare field for field, because every
  stored and answered value depends on the entry and checkpointed state only:
  - sampling kinds and sampler tables are checkpointed;
  - skew is per datagram;
  - the sequence state stays in the live push.
- Archived IPv6 conversations keep their full addresses.
- A rollup grows by about 50 bytes before deflate, plus 13 bytes for each
  IPv6 row.
- `MAX_ROLLUP_INFLATED_BYTES` is computed from the policy-2 shape:
  33-byte endpoint rows and 50-byte conversation rows at most.
