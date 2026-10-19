# src/services/monitoring/CLAUDE.md

The NetFlow v5 monitoring collector (ADRs 0058, 0059, 0060); loaded when you work under `src/services/monitoring/`, and relevant to `electron/monitoring/`, `src/workers/monitoring.worker.ts` and the Monitoring sheet. It is implemented, not planned. It shares no code or state with the capture path: its files are not captures and `planPrune` never reaches them.

## Process split

- Main forks one utilityProcess (`electron/monitoring/host.ts`, `serviceName: 'inwire-monitoring'`, `stdio: 'pipe'`). It owns the UDP socket and the journal file and nothing else. It never decodes NetFlow.
- The socket is `dgram` udp4 in `electron/monitoring/udp.ts`: `reuseAddr: false`, bind `exclusive: true`, an 8 MiB `recvBufferSize`, and one permanent `error` listener. It is unprivileged. The agent never collects (the banner in the root `CLAUDE.md`); do not move the socket there.
- Decode, rollups and queries run in the sandboxed Worker `src/workers/monitoring.worker.ts`, which holds no file and gets datagrams over a port. Wiring is `workerHost.ts` and `runtimeRpc.ts`; `localRuntime.ts` and `runtime.ts` are the runtime both sides share.
- Main keeps the settings (`electron/monitoring/settings.ts`, `{version: 2, source, location, retention}`, a v1 file read as location null and the default retention, written atomically through `electron/atomicWrite.ts`) and the IPC channels (port request, start, stop, config get, config save, location choose, discard, retention save) in `electron/main.ts`. settings.json always stays in the default root, the `monitoring` folder of the user data directory.
- The location (ADR 0061): the renderer sends `'pick'` or `'default'`, never a path; main's own dialog returns the folder and `resolveDatasetFolder` (`electron/monitoring/location.ts`) makes it `<picked>/Inwire Monitoring`, or the picked folder itself when it already holds a journal. Overlap with the captures folder either way is refused (`refuseLocation`, after realpath). Changing it moves nothing. Location, discard and retention are refused (`busy`) while collecting.
- The utility inspects before it opens (`classifyAdoption` in `datasetPlan.ts`, read-only): a folder with any name Inwire did not write is refused untouched; a read-only adoption opens the journal with `readOnly` (no torn-tail truncation, no pending unlink, no `interrupted` boundary), serves its history from it (`RollupStore` opened `readOnly`) and writes nothing, Start included, not even an empty file.
- A relocation or a whole discard reopens the dataset under a live Worker: the collector posts `notifyReopened` (`runtimeRpc.ts`) before the live feed reattaches, and the Worker re-adopts and rebuilds. Port order is the only thing that keeps the notice ahead of the new dataset's pushes; do not send it on another channel, and do not replace it with a generation compare (a same-generation older copy would be missed).
- A discard deletes only after main's own dialog: main asks the utility for a preview (the same segment selection the discard runs, so the stated cut is the cut), shows `discardConfirmation` (`electron/monitoring/discardConfirm.ts`, Cancel default), then sends the discard. The renderer sends the intent only and adds no confirm of its own. dataset.json holds the generation, what a discard replaced and the `discarding` marker that makes a whole discard crash-safe; deletion goes only through `planMonitoringDiscard`, which never names settings.json or a foreign file.
- The UI is the third value of `sheet` in `src/App.tsx`, opened by the command `monitoring.open` (`src/lib/commands.ts`). `APP_VIEWS` and `Ctrl+1` to `Ctrl+5` are unchanged: it is a sheet, not a view.

## Files

- The journal is the evidence and the only authority. It is a run of segments `journal-<first id, 12+ digits>.iwmj` (ADR 0062, `segments.ts`), ordered by the first entry id in each header and contiguous by id; a pre-0062 `journal.iwmj` is read as the first segment and is never appended to again. `rollups.iwmr` is a cache (magic `INWIREMR`) and is rebuilt when its generation, policy or watermark disagree with the journal. Never answer from a sidecar the journal does not back. All go through `NodeBlockFile` (`NodeSegmentDirectory` in `electron/monitoring/volume.ts`) and match no `CAPTURE_ID_PATTERN`.
- Journal format (ADRs 0059, 0062, `journalCodec.ts`, `segments.ts`): little-endian, CRC-32/ISO-HDLC, magic `INWIREMJ`; a segment's 128-byte header carries the generation, the decoder policy (only `ACCEPTED_POLICIES` open; any other is `refused-version`, untouched), the first entry id and the open session with its source. 24-byte entry header, body at most 65,531 bytes. Boundary entries are `start` (with its `source`), `stop`, `suspend`, `resume`, `interrupted`, `gap` and `expired` (`journal.ts`). A `start` names a 32-hex session id. Rollups are deflated with `fflate` at level 1 and read back through `boundedInflate.ts`; never inflate without a bound.
- Recovery truncates only a torn tail of the newest segment (a header-only newest segment is a torn roll and is removed). Interior corruption, an id gap or a generation mismatch preserves every file untouched and refuses append. Never "repair" the middle. Segments leave only whole, through `dropSegments`, which records an `expired` boundary before unlinking; reopen finishes an interrupted drop.
- Retention is not capture pruning. The storage limit is the journal's own.
- A `.iwmon` bundle (ADR 0063, `bundle.ts`) is assembled in the Worker and pulled by the renderer one chunk at a time into a save sink; nothing holds the range. Journal entries go in as their raw bodies (`readRawPage`), never re-encoded from evidence, because boundary parsing is lenient. The manifest is entry 1, so what it counts is frozen at open: a cut, a reopen or a generation change before the end fails the export with `changed`. A `.iwmon` beside a dataset is a user file: adoption tolerates it and a discard keeps it.

## Limits and stop reasons

- Every number is in `LIMITS` in `types.ts`; read it there, do not copy values into code. Shape: default storage 8 GiB (owner's ruling), minimum 16 MiB, a 64 KiB closing reserve so the final boundary always fits; 16,384 keys a minute; 16 engines per exporter; 16 rejected senders plus an overflow count; inbox 1,024 datagrams or 8 MiB; live feed 4 batches in flight of 64 datagrams or 256 KiB; 256 entries or 1 MiB a page; 120 buckets, 20 top rows, 2 concurrent queries; 100,000 datagrams and 50,000 keys for a raw query; 15 s handshake and request, 5 s drain, 60 s stale.
- Every table is bounded on its own, and totals stay exact. A table past 50,000 keys comes back empty with its own `range-too-large`; the others still answer. Do not make one table's overflow fail the whole query.
- `StopReason` is `user`, `quit` or `suspend` (`control.ts`). The intake adds `socket-error`, `storage-limit` and `storage-failed` (`IntakeStopReason`, set in `electron/monitoring/collector.ts`). A stop always records a boundary with its reason; do not add a path that stops silently.
- A collection gap is shown as a gap, never as zeros. Start is explicit on every launch: a saved source is a remembered setting, not a standing instruction to listen.
- Quit drains: the `will-quit` handler in `electron/main.ts` uses `planQuitDrain` and `runQuitDrain` (`electron/monitoring/quitDrain.ts`), which always ends in `settled` so a rejecting drain cannot hold the quit, then calls `app.quit()` again from `setImmediate`. `powerMonitor` `suspend` calls `monitoring.suspend()`.
- Windows shutdown, logoff and the installer's Restart Manager never reach `will-quit`. Recovery at the next open is the design; do not add a handler that claims to cover them.

## Rulings (the owner's, in ADRs 0058-0060)

- A conversation is a **directional address pair** (source to destination). Ports and protocols are answered by a raw drill-down over the journal, not by widening the key.
- Bounds are per table, with exact totals (above). The default storage is 8 GiB.
- The configured exporter address is an intake filter, **not authentication**: v5 has none. Datagrams from other senders are counted for at most 16 addresses plus an overflow count, and dropped.
- `src/services/monitoring/config.ts` refuses a bind address of `0.0.0.0`, and an exporter address of `0.0.0.0` or `255.255.255.255`.
- Source health is derived (`sourceHealth.ts`) and pushed by the Worker; the sheet does not invent a state.

## Enforcers

All plain `tsx`, under `scripts/monitoring/` and run by `npm run check`:

- `journal.ts`: journal and sidecar codecs, recovery, torn tail versus interior corruption.
- `rollup.ts`: a rollup answer equals the raw-scan answer. This is the property that makes rollups safe; run it after any change to either.
- `queries.ts`: History queries, the Worker host and the bounded inflate.
- `history-range.ts` and `query-refresher.ts`: range arithmetic, and that a refresh tick never cancels a query slower than the tick.
- `config-v5.ts`: configuration refusals and the exact v5 decoder.
- `health-budget.ts` and `health-push.ts`: source-health reducer, admission budget and what the Worker pushes.
- `runtime.ts`: intake, journal ownership, the live feed, the port's live-ack and busy rules.
- `runtime-host.ts`: main's host, saved settings, atomic write, the client and the state reducer; a discard is sent only after a preview and an accepted confirm.
- `dataset.ts`: the adoption table, dataset.json, `refuseLocation` and the discard plan. `location.ts`: the collector on a real folder (a discard keeps the picked folder and foreign files, busy while collecting, a crashed discard finishes, read-only writes nothing, the preview's cut is the discard's, a reopen tells the Worker once). `location-choose.ts`: `resolveDatasetFolder`. `discard-confirm.ts`: the dialog's copy and its Cancel default.
- `quit-drain.ts`: the drain always settles.
- `export.ts`: the history CSV exporter (exact bigints, hostile cells, one owner for the sink).
- `bundle.ts`: the `.iwmon` evidence bundle (ADR 0063): the vectors, raw bodies contiguous by id, `sessionAtStart`, archived minutes for expired parts, a change mid-export failing `changed`, one owner for the sink, and that the Worker's import graph reaches no capture export writer or dissector.
- `sheet-source.ts`: facts about the sheet read from component source.
- `scripts/electron/monitoring-ui.ts` drives the sheet; `scripts/electron/monitoring-drive.ts` and `monitoring-shots.ts` are in `NOT_TESTS`, as are `measurement.ts`, `interop.ts`, `load.ts`, `fixtures.ts` and `queryRig.ts` here. A pass elsewhere is not a pass on those.
