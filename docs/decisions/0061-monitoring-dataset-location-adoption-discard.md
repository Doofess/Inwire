# 0061 — A monitoring dataset can live in a folder the user picks, is adopted only if every file in it is its own, and is discarded by name

**Status:** accepted 2026-10-19. Measured in
[`docs/monitoring-1.5-measurements.md`](../monitoring-1.5-measurements.md).
It supersedes [0059](0059-monitoring-evidence-journal-and-rollups.md)'s
"the location is fixed for milestone 1".

## Context

[0059](0059-monitoring-evidence-journal-and-rollups.md) fixed the dataset at
`<userData>/monitoring/` and left a chooser, adoption of an existing dataset
and discard to milestone 1.5. At the 8 GiB default a dataset is about nine days
of a busy small office, and the system disk is not always where a user wants
that. A dataset that outlives a reinstall, or moves with a disk, has to be
found again and opened without being damaged. A discard has to remove a
dataset and nothing else.

Capture pruning already has the rule this needs. `planPrune`
(`src/services/capture/captureDirectory.ts`) deletes only names that match
`CAPTURE_ID_PATTERN` and reports everything else as foreign, and
`scripts/capture/prune-guard.ts` holds it to that, including the case where
an empty keep list would otherwise mean "everything". Monitoring gets the same
shape over its own names.

## Decision

### The location: point, never move

- **The user picks a folder in a dialog main opens**, on the
  `keyLogs.choose` precedent (`electron/keyLogFollower.ts`). The renderer
  sends an intent and receives a status; it never names a path, and main
  treats nothing from it as one.
- **Inwire keeps the dataset in an `Inwire Monitoring` subfolder of the
  picked folder,** creating it if needed. The picked folder is never the
  dataset, so a discard can never remove a folder the user chose. The one
  exception is choosing a folder that already *is* a dataset: if the picked
  folder itself holds `journal.iwmj` or a segment, it is used as it is. That is how
  choosing the old `Inwire Monitoring` folder, or the default folder, adopts
  it again.
- **The default stays `<userData>/monitoring/`**, without a subfolder, and
  its files keep milestone 1's names. They are legacy identifiers.
- **Overlap with captures is refused in both directions.** After resolving
  real paths, compared case-insensitively on Windows, a dataset folder inside
  `<userData>/captures/`, or a `captures/` folder inside a dataset folder, is
  refused with the reason in words. Monitoring files are not captures, and
  neither prune can be allowed to see the other's files.
- **A folder that cannot be created or written is refused** with its OS
  error, in words, and the previous location stays in use.
- **Changing the location moves nothing.** The previous dataset stays where
  it was, unopened. Moving a dataset is a later feature.
- **The location changes only while monitoring is stopped,** like the source.

### Settings, version 2

`settings.json` stays in `<userData>/monitoring/`, wherever the dataset is,
because it is the app's and not the dataset's. It becomes
`{ version: 2, source, location }`, where `location` is the dataset folder's
absolute path, or `null` for the default. A version-1 file reads as
`location: null`, and is rewritten as version 2 on the next save. A version
above 2 is refused with the version named, as version-1 builds refuse it
today.

### What a dataset folder may hold

One pure function, `classifyMonitoringName(name, { isDefaultLocation })`,
decides every name. It is the only place the list lives:

| Name | Class |
|---|---|
| `journal.iwmj` | dataset (milestone 1's journal, the first segment) |
| `journal-<12 to 20 digits>.iwmj` | dataset (a segment, named by its first entry id, zero-padded to 12 digits; [0062](0062-monitoring-segments-retention-archive.md)) |
| `rollups.iwmr` | dataset (the rebuildable cache) |
| `archive.iwma` | dataset (the sealed archive, 0062) |
| `dataset.json` | dataset (below) |
| any of the above followed by `.<12 hex digits>.partial` | dataset (an interrupted atomic write, `electron/atomicWrite.ts`) |
| `settings.json`, in the default location only | app, never touched by discard |
| anything else | foreign |

### `dataset.json`

The journal and archive are the authority for what the dataset holds, whose
it is and what has expired: the source is in each segment header and `start`
boundary, and every expiry is an archive cut and an `expired` boundary (0062).
`dataset.json` holds only what they cannot:

```
{ "version": 1, "generation": "<32 hex>", "createdMs": <ms>,
  "replaced": null | { "discardedAtMs", "previousGeneration", "previousFromMs", "previousThroughMs" },
  "discarding": null | { "generation" } }
```

It is written with `writeFileAtomic`. Its generation must equal every
segment's. A dataset from milestone 1 has none, and one is written on the
first open by a 1.5 build that is allowed to write, from the journal's
generation.

### Adoption

Choosing a folder scans it before anything is shown. The scan is milestone
1's open, run over every segment in entry-id order, so its cost is bytes:
**8 GiB took 20.3 s on this machine with a warm cache**, inside the 128 s
`LIMITS.openScanBytesPerSecond` allows. The sheet shows progress and can
cancel, and a cancelled scan leaves the previous location in use.

| Found | Result |
|---|---|
| an empty or missing folder | a fresh dataset: a new generation and `dataset.json` |
| only dataset names; supported format; every policy accepted; contiguous entry ids; every CRC good | **adopted** |
| the same, except a torn tail on the newest segment | **adopted**, the tail truncated as an ordinary open does (`MonitoringJournal.open`), and the sheet says how many bytes |
| interior corruption; a gap in entry ids between segments; a leading gap 0062 does not account for; a generation that differs between segments or from `dataset.json` | **adopted read-only**: history up to the damage is shown, Start is disabled, and nothing is written, not even the sidecar or `dataset.json` |
| unknown magic in a dataset name; a format newer than this build's; a policy outside the accepted set | **refused, untouched** (`refused-version`): the sheet names what it found and what this build reads |
| any foreign name | **refused, untouched** (`foreign-files`): nothing is created beside files Inwire did not write. The sheet names up to five of them |

A rollup sidecar that does not match is rebuilt, as in milestone 1, except in
a read-only adoption, where queries take their minutes from the journal
within the raw budget and nothing is stored.

**An adopted dataset shows its own source,** the one its newest segment
recorded, not the saved configuration. The history path scopes on it. Start
against a dataset whose recorded exporter or bind differs from the configured
source asks first, then records a `start` boundary carrying the new source.

### Discard

- **Discard the whole dataset** deletes the names
  `classifyMonitoringName` calls dataset, inside the dataset folder, and
  nothing else: never a foreign file, never `settings.json`, never the folder.
  The plan is pure, `planMonitoringDiscard(present, { isDefaultLocation })`
  returning `{ remove, keep, foreign }`, and it has its own guard script in
  `scripts/monitoring/`, which also asserts that an empty listing removes
  nothing.
- **It is crash-safe.** `dataset.json` is first rewritten with
  `discarding: { generation }`. Then the files go, segments newest first, the
  archive and sidecar after, and last a fresh `dataset.json` with a new
  generation and `replaced` filled in. An open that finds `discarding` set
  finishes the deletion before anything else. So a crash can leave a dataset
  half-deleted, but never one that looks whole.
- **Expire evidence before a date** is 0062's expiry, run once with reason
  `user-before`. It is the only partial discard. Per-source and arbitrary-range
  discard would mean rewriting the journal, and are out of scope.
- Both run only while monitoring is stopped, and only after a dialog main
  opens that states what goes, what stays and the actual cut. The renderer
  sends the intent.

## Consequences

- A dataset can be pointed at a second disk, left behind, and adopted again.
  It cannot be moved by Inwire, so a user who wants it elsewhere copies the
  folder and points at the copy.
- A folder with anything else in it cannot hold a dataset. That refuses some
  harmless cases, a `desktop.ini` for one, and it is the price of discard
  never having to judge a file it did not write.
- A milestone-1 dataset is adopted as it is, and the first writing open adds
  `dataset.json`. Going back to a milestone-1 build afterwards is not
  supported: it knows only `journal.iwmj`, would not see the segments 0062
  adds, and would append to a file 1.5 has sealed.
- `dataset.json` is not evidence. Losing it loses the "previously discarded"
  note and nothing else; it is recreated from the journal's generation.
