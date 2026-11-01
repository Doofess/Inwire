# 0071 — An expiry trims the rollup sidecar instead of resetting it: minutes are sealed at every segment start, and the retained part is copied to a new file

**Status:** accepted 2026-11-01 by the owner, who chose the approach the same day
("seal and rewrite"), in answer to I3 of the Milestone 2 final review. It
replaces [0062](0062-monitoring-segments-retention-archive.md)'s
reset-and-rebuild after an expiry with the compaction 0062 allowed "only if a
test shows its output equal to the rebuild's". The rest of 0062 stands: the
archive, the cut, the order of an expiry and its recovery.

## Context

`runExpiry` (`archive.ts`) ends with `resetIfStale`. Once the journal's
`expired` boundary is durable, `rollups.iwmr` is emptied and the Worker
rebuilds everything retained from the archive cut's checkpoint. At the 8 GiB
default a segment is 256 MiB, and an expiry at the limit frees two. At
softflowd's measured day of 741 MiB, that is an expiry about every 17 hours,
each rebuilding about 10 retained days. At the measured 25 to 31 s a day, that
is 4 to 5 minutes of Worker time
([monitoring-v9-ipfix-measurements.md](../monitoring-v9-ipfix-measurements.md)),
during which History says "Rebuilding summaries" and a v9 raw query can answer
`range-too-large`. As a side effect, the Worker's first post after an expiry is
refused as "not continuing the sidecar", and the retry rebuilds.

The sidecar cannot simply drop the expired entries today, for one reason: a
minute fragment can **straddle** the cut. The aggregator seals a minute when
receipt time passes it, at a stop, suspend or interruption, and at a policy
change, but not at a segment start. A fragment holds entries from both sides
of a segment boundary, and kind 1 records only its last entry.

## Decision

### Minutes are sealed at every segment start

- The evidence for the **first entry of a segment** says so. `EvidenceRef`
  gains `segmentStart: true`, set by the journal's page reader and by the live
  feed when the utility has just rolled a segment.
- Before feeding such an entry, the aggregator seals every open minute
  (`seal(Infinity)`, as at a stop). No fragment then holds entries from two
  segments, and an expiry, which only ever takes whole segments, never cuts
  through one. A minute that spans a segment start has two fragments, and every
  reader already sums a minute's fragments (0062's straddling minute).
- This also makes the per-minute identity count of
  [0070](0070-monitoring-identities-evict-least-recent.md) exact on replay:
  checkpoints and expiry cuts are at segment starts, where no minute is open.

### The sidecar's format 2

- The sidecar's header format becomes `2`, meaning "no fragment straddles a
  segment start". It gets its own constant: today the sidecar reads the shared
  `FORMAT_VERSION` (1) in `types.ts`. A format 1 sidecar is `rebuild-required`
  once, which `rollupStore.ts` already does for any other format. It is a cache
  (0059), and this is the rebuild 0062 would have run at the next expiry anyway.
- Header bytes 40 to 47 (inside the CRC'd 60) hold the **trimmed-through entry
  id**: 0 for a sidecar that has never been trimmed, else the last entry id of
  the expiry it was trimmed for. It is also the base a batch must continue from
  when the file holds no watermark, so `reset(base)`'s base is now persisted,
  not held only in memory.

### The trim

`RollupStore.trim(cutThroughEntryId)` makes a new sidecar from the old one,
in the utility, which owns the file:

1. It writes `rollups.iwmr.<12 hex>.partial` (already a recognized name): a
   fresh format 2 header with the same generation and policy, and
   trimmed-through set to the cut.
2. It copies, in file order, every entry of the old file that the cut leaves:
   - a minute (kind 1) whose through entry is after the cut;
   - a checkpoint (kind 3) whose through entry is after the cut;
   - a watermark (kind 2) whose through entry is after the cut.
   Everything else describes expired entries, which the archive now holds. The
   bytes are copied as they are, without being inflated or re-encoded.
3. It copies in slices of at most 4 MiB and yields between them, so the
   utility keeps serving the socket. The Worker's appends during the copy go
   to the old file as usual. The last slice, which is whatever was appended
   meanwhile, is copied, synced and renamed over `rollups.iwmr` in one turn,
   and the store's handle and index switch to the new file.

`runExpiry`'s order is unchanged up to the journal's `expired` boundary. The
final step trims instead of resetting:

- **Trimmed**: the Worker is not told. Its next post continues from the
  watermark it already knew, which the new file kept, and is accepted.
- **The trim fails, or the process dies before the rename**: the old file is
  untouched, and its trimmed-through is behind the newest `expired` boundary.
  `resumeExpiry` and the Worker host's connect check treat that exactly as
  today's stale cache: reset and rebuild. A sidecar `.partial` that a crash
  left is removed when the dataset is opened writable. This is new: today
  nothing removes a crash's partial (`atomicWrite` cleans up only after a
  thrown failure), and a trim's can be as large as the sidecar.
- **The sidecar held nothing after the cut** (its watermark at or before it):
  the new file is empty with base = cut. The Worker's post is refused, and the
  retry rebuilds from the cut, as today.

`resetIfStale`'s test becomes: the sidecar is stale if its trimmed-through is
before the newest `expired` boundary's through entry **and** its watermark is
before that boundary's own entry.

### Equality

0062's condition is met by a test, not argued. For v5 and v9 journals of
several segments, expired at each segment start in turn, the trimmed sidecar
must equal a sidecar rebuilt from the retained journal and the cut's
checkpoint in these ways:

- the same set of (source, minute, policy, through entry, rollup bytes)
  fragments and the same checkpoints;
- the same answers to History queries, which `rollup.ts` already compares
  against the raw scan.

Byte equality of the whole file is not required, because watermarks fall where
the Worker happened to post.

## Consequences

- An expiry costs one copy of the sidecar, not a re-decode of the journal.
  The sidecar's size per GiB of journal, and the copy's time at 8 GiB, are
  measured when this lands, in the v9/IPFIX measurements document, beside the
  estimate this replaces.
- One more fragment per source at every segment start. At 256 MiB segments
  that is a few hundred bytes a segment: noise.
- Sidecars of format 1 rebuild once after the upgrade. During that rebuild,
  History says "Rebuilding summaries" as it does today.
- The "first post after an expiry is refused" sequence that
  `scripts/monitoring/expiry-sidecar.ts` pins becomes the fallback path. The
  test is rewritten to pin both: trim accepted, and reset after a failed trim.
- Rejected: **a sidecar file per segment** (no copy at all, but new names in
  adoption, discard and the bundle, and a query over many files), and
  **re-decoding the minutes at the cut** (a cache format change plus a replay
  path in the Worker, kept only to avoid the seal).

## Enforcers

- `scripts/monitoring/expiry-sidecar.ts`: trim, equality with a rebuild at
  each segment start (v5, v9), the fallback after a failed or interrupted trim,
  and the Worker's post continuing after a trim.
- `scripts/monitoring/journal.ts`: the format 2 header and trimmed-through,
  a format 1 sidecar `rebuild-required`, and a leftover `.partial` removed.
- `scripts/monitoring/rollup.ts`: a minute spanning a segment start is two
  fragments, and the answer still equals the raw scan.
- `scripts/monitoring/runtime.ts`: the live feed marks the first entry after a
  roll.
