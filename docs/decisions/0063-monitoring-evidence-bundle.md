# 0063 — A monitoring evidence bundle is one exported file: a manifest, the journal entries of a range with their original ids, and the archived minutes for its expired parts

**Status:** accepted 2026-10-19.

## Context

The sheet exports a history view as CSV, which is an answer and not evidence.
Someone asked to show what an exporter actually sent over a period needs the
datagrams themselves, with enough around them to read them: which dataset
they came from, which source, which session, which decoder policy, and which
parts of the period had already expired. Copying the dataset folder carries
everything but the range, ties the copy to Inwire's internal layout, and drags
the rest of the history along.

Opening such a file is a different problem from writing it. A bundle from
somewhere else is hostile input and needs a bounded parser in the Worker,
which milestone 1.5 does not build. The format is decided now so that reader
can be added later without changing it.

## Decision

### What is exported

- **The user picks a time range in the sheet and exports a `.iwmon` file**
  through the existing streamed save sink (`openSaveSink`,
  `src/lib/saveSink.ts`): a main-owned dialog, a `.partial` file, pieces
  appended, then a rename. The renderer never names a path.
- **The journal slice is contiguous by entry id**: from the lowest id received
  within the range to the highest id received within it. Both ends are in
  range, so a clock that stepped outside it, however far, never stretches the
  slice over raw flows the user did not ask for. An entry in between whose
  receipt clock is outside the range is included, so the slice has no holes and
  its ids run one by one.
- **Archived minutes** whose minute falls in the range are included, for the
  parts whose evidence expired ([0062](0062-monitoring-segments-retention-archive.md)).
  A minute folded from an entry the journal still holds (an expiry that wrote
  its cut and died before dropping the segments) is left out: those entries
  are in the bundle as entries, and counting them twice would double every
  flow. A refused archive over a journal that has expired anything fails an
  export that reaches expired time `history-lost`, as a damaged one does; a
  range whose first entry is past the journal's first retained one reaches no
  expired time and is exported without it.
- **The rebuildable cache is left out.** A reader recomputes it from the
  journal slice.
- **Export only.** Opening a bundle is a later milestone. Nothing in 1.5 reads
  one.

### Format

0059's framing, with the magic `INWIREMB` and a 1 MiB body cap, because an
archived minute can pass 64 KiB.

- **Header:** 0059's 64-byte format-1 layout with magic `INWIREMB`, format 1,
  **policy `0` ("per entry")**, the generation of the dataset it was exported
  from, and the export time as its created time.
- **Bundle entry ids** are the bundle's own, 1 and then +1 per entry, as in
  any file with this framing. The journal's ids travel inside the bodies.

| Kind | Entry | Body |
|---|---|---|
| 1 | manifest | UTF-8 JSON, below. Exactly one, and it is entry 1 |
| 2 | journal entry | a 16-byte prefix, then the original entry's body unchanged. At most 65,547 bytes |
| 3 | archived minute | an archive minute fragment's body unchanged (0062) |
| 4 | checkpoint | reserved: template state at the slice's first entry, defined by milestone 2's ADR |
| 5 | end | UTF-8 JSON `{ "journalEntries", "archivedMinutes" }`. Exactly one, and it is last |

**The journal-entry prefix:**

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | original entry id |
| 8 | 1 | original kind: `1` datagram, `2` boundary |
| 9 | 1 | reserved, zero |
| 10 | 2 | the decoder policy of the segment it came from |
| 12 | 4 | reserved, zero |

Original ids start at the manifest's `journal.firstEntryId` and rise by one.
Breaking 0059's "the first entry is 1" is the point of the declared first id.

**The manifest:**

```
{
  "bundleFormat": 1,
  "inwireVersion": "<package.json version>",
  "exportedMs": <ms>,
  "dataset": { "generation", "createdMs", "replaced" },
  "range": { "fromMs", "throughMs" },
  "journal": null | { "firstEntryId", "throughEntryId", "policies": [ ... ] },
  "sessionAtStart": null | { "sessionId", "source", "startEntryId" },
  "archive": { "minutes", "policies": [ ... ] },
  "history": { "cuts": [ { "fromEntryId", "throughEntryId", "fromMs", "throughMs", "reason" } ] }
}
```

- `dataset.replaced` is copied from `dataset.json` ([0061](0061-monitoring-dataset-location-adoption-discard.md)).
- `sessionAtStart` names the session open at the slice's first entry and the
  source it recorded, so the leading datagrams can be attributed even though
  their `start` lies before the range. `startEntryId` may be below
  `firstEntryId`.
- `history.cuts` lists every archive cut that overlaps the range, so a reader
  can say which parts expired, when and why.
- A reader ignores fields it does not know.

### The test vectors

`npx tsx scripts/monitoring/measurement.ts vector` prints these after 0062's.

Bundle header: generation `00 01 … 0f`, created `1700000000000`:

```
49 4e 57 49 52 45 4d 42 01 00 00 00 40 00 00 00 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
00 68 e5 cf 8b 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 99 a6 6e 81
```

Bundle entry 2: journal entry `4097`, a datagram from a policy-1 segment,
carrying 0059's entry-1 datagram body:

```
49 57 4a 45 2c 00 00 00 02 00 00 00 00 00 00 00 02 00 00 00 f3 b7 d6 26
01 10 00 00 00 00 00 00 01 00 01 00 00 00 00 00
7b 68 e5 cf 8b 01 00 00 c0 00 02 0a 07 08 c0 00 02 01 50 c3 00 00 00 00 00 05 00 00
```

### A future reader

When a later milestone opens bundles, the reader runs in the monitoring
Worker, never in main or the renderer thread. It refuses a declared body over
the cap before allocating, a kind-2 body over 65,547, a manifest that is not
entry 1, an end that is not last, original ids that do not rise by one, and a
policy outside its accepted set. What it opens is read-only and is never
merged into a dataset. Nothing in this format has to change for it.

## Consequences

- A bundle is evidence that can leave the machine. It holds raw flow records:
  the addresses, ports and volumes of the network that was monitored. It is
  written only by an explicit export to a path the user chose, and Inwire
  sends it nowhere.
- The format is mostly 0059's codec. The new parts are the manifest, the
  16-byte prefix and the end entry.
- A bundle is not a backup. It holds no cache, no `settings.json`, and only
  the archive minutes inside its range. Copying the dataset folder is the
  backup.
