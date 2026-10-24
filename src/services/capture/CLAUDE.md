# src/services/capture/CLAUDE.md

The on-disk capture format and the store protocol; loaded when you work under `src/services/capture/`. The store's process, memory ceiling and ports are in `electron/CLAUDE.md`, and `docs/architecture.md` has the data flow.

## Layout

- A capture is a directory named `cap-YYYYMMDD-HHMMSS-xxxx` (`CAPTURE_ID_PATTERN`, `captureDirectory.ts`) holding six files: `index.iwidx`, `prefix.iwpfx`, `summary.iwsum`, `frames.iwbyt`, `records.iwrec` and `streams.iwdig`.
- `records.iwrec` is one deflated block of frame records per chunk (ADR 0049), written before the chunk's index record so recovery covers it unchanged.
- The index is version 3 (`INDEX_VERSION` in `captureIndex.ts`): an 80-byte stride carrying the records' extent and each chunk's segment. Versions 2 and 1 still open and are continued as themselves; a version 1 capture's trees fall back to the replay. Never migrate an old capture in place.
- A chunk is version 2 and records each frame's `linkType`. Version 1 still decodes; `RowBlock.linkTypesStored` says whether an absent link type means Ethernet (v2) or not recorded (v1). Imports need it stored: every frame of one carries one adapter label whatever its link type (ADR 0046).
- `streams.iwdig` is the stream digest's snapshot (ADR 0055, `digestCodec.ts`): every row folded into a summary per stream, its TCP states, totals and outcome. **It is a cache, never a source.** The store writes it at `finish` and at close (`trySnapshot` in `captureHost.ts`), and an open trusts it only when it was folded through the capture's newest id; missing, torn, another format or another id, it is folded again from the rows, sliced through the queue like a scan. The file is emptied before that fold starts and never written while one runs or after one dropped rows (`DIGEST_DEFERRED_MAX`), because a partial digest written as whole is a wrong answer the next open would trust. A partial one is sent as `partial` with the digest's answer, and the Statistics note says so. `snapshot()` hands out the digest's own entries and `restore` adopts what it is given: encode at once, and pass `restore` only fresh decode output. A copy either way was seconds at 100k streams, and the format writes 512-entry deflated chunks, because one JSON string of the whole digest passes V8's string limit near 300k streams. One per capture, beside the index, not per segment. `scripts/capture/stream-digest-store.ts`.
- Writing is `captureWriter.ts` through `chunkCodec.ts`; reading is `captureReader.ts`; addressing `captureIndex.ts`; search `captureScan.ts` and `matchSet.ts`.

## Ring segments (ADR 0052)

- A capture following the agent's ring keeps data in segments: segment 0 is the four data files beside the index, segment *n* a `seg-NNNNNN` directory. Segments are filed by the agent's `capture_boundary` messages (`src/services/pipeline/ringFiling.ts`).
- `segments.ts` is the only place a capture's frames are deleted without the user pressing anything. A segment goes only if it is not segment 0, not the one being written, every frame in it was filed under the capture the agent deleted from, and its newest frame is at or below the deleted file's last sequence number. Oldest first, no gaps.
- Delete by sequence number, never by file: a shed `capture_boundary` would file a whole ring file under the one before it.
- Floor first: the header records the first chunk still held, every lookup below it answers as a hole, ordinals never move. The list, a filter's bitmap and an export start at the floor, they do not renumber.
- `scripts/capture/segment-guard.ts` puts each refusal back wrong. Run it after touching `segments.ts`.

## Deletion

- A capture is deleted only when the user asks (ADR 0012). `planPrune` in `captureDirectory.ts` removes only directories matching `CAPTURE_ID_PATTERN`, never anything else in the folder. `prune([])` on a real directory is a recursive delete of `%LOCALAPPDATA%\Inwire\captures`, and was reachable whenever `loadSessionMeta()` returned nothing. `scripts/capture/prune-guard.ts`.
- Monitoring files (`journal.iwmj`, `rollups.iwmr`) match no capture id and live under a different root, so pruning never reaches them; keep it that way.
- Auto-pause at 99% made the disk buffer unreachable: `planBufferTrim` acts above `1 + BUDGET_SLACK` (0.05). `DISK_RESERVE_BYTES` (2 GiB, `src/services/bufferBudget.ts`) replaced it; `scripts/session/buffer-budget.ts` asserts the inversion.

## File and serialisation traps

- `blockFile.ts` is the seam; `nodeBlockFile.ts` is the real file and the only module here allowed `node:fs`. It must **loop** `readSync` and `writeSync`: a short read on a 5 GB `frames.iwbyt` read as a torn tail and truncated a healthy capture. `scripts/capture/block-file.ts` injects short reads.
- Recovery: a capture whose trailing chunk is incomplete loses that chunk and nothing else (`scripts/capture/recovery-on-disk.ts`).
- `serialQueue.ts` exists because `void handle(msg)` let `append` overtake an async `open` and lost 500 frames. Do not call store handlers unawaited.
- A structured clone drops prototypes. A buffered `Packet` carries its 33 commonest fields in a `FieldBlock` class instance, so across the store's process boundary `encodeChunk` threw for every frame: `frames.iwbyt` grew, `index.iwidx` stayed empty, `ordinalOf` answered -1 and the list showed the RAM window as the whole capture.
- `storePacket.ts` (`plainForStore`) flattens at the boundary and folds dense columns back into `fields`. A message is a snapshot: always copy, even when there is nothing to fold, because `prepareBatch` calls `persist` before `absorb` and the `postMessage` serialises a microtask later.
- `scripts/capture/store-protocol.ts` round-trips every appended frame through `v8.serialize` and `deserialize` first; it drives the store's whole message union and opens with "every request answers, even when it fails". `scripts/electron/disk-drive.ts` drives a capture past the RAM budget and asserts the two counts diverge.
- The store compresses with node's `zlib` at level 1 (`electron/store/entry.ts`); the rest of the app reads with `fflate`. `scripts/capture/native-zlib.ts` holds that either reads the other.
- This directory imports no Electron and no `node:*` besides `nodeBlockFile.ts` (`scripts/capture/node-safe.ts`).
- Imports are not capped by memory: `IMPORT_PATCH_WINDOW` (100,000, `src/services/pcapParser.ts`) is how long a frame stays reachable by a patch. `scripts/capture/import-stream.ts` forces it small so frames really leave it.
