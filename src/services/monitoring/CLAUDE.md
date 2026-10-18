# src/services/monitoring/CLAUDE.md

The NetFlow v5 monitoring collector (ADRs 0058, 0059, 0060); loaded when you work under `src/services/monitoring/`, and relevant to `electron/monitoring/`, `src/workers/monitoring.worker.ts` and the Monitoring sheet. It is implemented, not planned. It shares no code or state with the capture path: its files are not captures and `planPrune` never reaches them.

## Process split

- Main forks one utilityProcess (`electron/monitoring/host.ts`, `serviceName: 'inwire-monitoring'`, `stdio: 'pipe'`). It owns the UDP socket and the journal file and nothing else. It never decodes NetFlow.
- The socket is `dgram` udp4 in `electron/monitoring/udp.ts`: `reuseAddr: false`, bind `exclusive: true`, an 8 MiB `recvBufferSize`, and one permanent `error` listener. It is unprivileged. The agent never collects (the banner in the root `CLAUDE.md`); do not move the socket there.
- Decode, rollups and queries run in the sandboxed Worker `src/workers/monitoring.worker.ts`, which holds no file and gets datagrams over a port. Wiring is `workerHost.ts` and `runtimeRpc.ts`; `localRuntime.ts` and `runtime.ts` are the runtime both sides share.
- Main keeps the settings (the saved source in `electron/monitoring/settings.ts`, `{version: 1, source}`, written atomically through `electron/atomicWrite.ts`) and the IPC channels (port request, start, stop, config get, config save) in `electron/main.ts`. The monitoring root is the `monitoring` folder of the user data directory.
- The UI is the third value of `sheet` in `src/App.tsx`, opened by the command `monitoring.open` (`src/lib/commands.ts`). `APP_VIEWS` and `Ctrl+1` to `Ctrl+5` are unchanged: it is a sheet, not a view.

## Files

- `journal.iwmj` is the evidence and the only authority. `rollups.iwmr` is a cache (magic `INWIREMR`) and is rebuilt when its generation, policy or watermark disagree with the journal. Never answer from a sidecar the journal does not back. Both go through `NodeBlockFile` (`electron/monitoring/volume.ts`) and match no `CAPTURE_ID_PATTERN`.
- Journal format (ADR 0059, `journalCodec.ts`): little-endian, CRC-32/ISO-HDLC, 64-byte header with magic `INWIREMJ`, 24-byte entry header, body at most 65,531 bytes. Boundary entries are `start`, `stop`, `suspend`, `resume`, `interrupted`, `gap` (`journal.ts`). Rollups are deflated with `fflate` at level 1 and read back through `boundedInflate.ts`; never inflate without a bound.
- Recovery truncates only a torn tail. Interior corruption preserves the file untouched and refuses append. Never "repair" the middle.
- Retention is not capture pruning. The storage limit is the journal's own.

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
- `runtime-host.ts`: main's host, saved source, atomic write, the client and the state reducer.
- `quit-drain.ts`: the drain always settles.
- `export.ts`: the history CSV exporter (exact bigints, hostile cells, one owner for the sink).
- `sheet-source.ts`: facts about the sheet read from component source.
- `scripts/electron/monitoring-ui.ts` drives the sheet; `scripts/electron/monitoring-drive.ts` and `monitoring-shots.ts` are in `NOT_TESTS`, as are `measurement.ts`, `interop.ts`, `load.ts`, `fixtures.ts` and `queryRig.ts` here. A pass elsewhere is not a pass on those.
