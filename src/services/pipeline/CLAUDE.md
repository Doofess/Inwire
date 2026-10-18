# src/services/pipeline/CLAUDE.md

The live frame path between the pipe and the store; loaded when you work under `src/services/pipeline/` (the Worker itself is `src/workers/pipeline.worker.ts`). Process topology is in `docs/architecture.md`; the store's side is in `src/services/capture/CLAUDE.md`.

## Order of operations

- The Worker assigns ids and posts a released group's bytes to the store over its own `MessagePort` **before** it dissects anything (ADR 0038). A frame whose dissection throws must still reach disk.
- Rows travel with `bytesSent` and without their bytes, and are attached, never staged: an empty `rawBytes` must not be written as a frame. A Worker with no store port says `stored: false` on its flush.
- Never invent a renderer-side "bytes and row" versus "row only" choice. The writer answers one local question: does this id already have a slot?
- Nothing is transferred to the store; messages are copied. After the Worker's own flush transfer to the renderer every view of those bytes is detached, so a tracker keeping bytes past its frame must `.slice()` them. A TLS tracker that kept a view lost its client random and left live connections undecrypted. `scripts/pipeline/moved-bytes.ts` dissects every real capture twice, detaching after each frame, and fails on any changed tree; `scripts/pipeline/arrival.ts` detaches too.

## Stop and drain

- Stop waits for the Worker's `drain` and flushes the last rows before the store `finish` (`stopCaptureAndSeal` in `src/App.tsx`, `handlePauseCapture`). Two ports into one process have no ordering between them.
- `answerDrain` replies only after the store acks an empty `appendBytes` posted behind everything else on the Worker's port, bounded by `DRAIN_BARRIER_MS` (5000).
- Worker failures post `{type:'failure'}` and reach `pipeline.onFailure`, which is only `console.warn` (`src/hooks/useAgentConnection.ts`). Listen for them in drives: about 5% of live frames once failed to dissect unnoticed.

## Flow control and catch-up

- Bound every queue. `liveFlow.ts` stops releasing frames past 50,000 unanswered by the store; main sheds whole batches past 256 MB owed (`electron/pipeCredit.ts`). A link faster than the app falls behind into the agent's pcapng, which holds every frame, and the status bar says by how much. `scripts/pipeline/live-flow.ts`.
- `catchUp.ts` reads a hole back from the agent's file, asking main for a capture id and the agent's file name, never a path. A file frame is numbered by counting from its `capture_boundary`, and the count is checked against a live frame on each side of the hole. Where the check fails, mark the hole. `scripts/pipeline/catch-up.ts` holds the result to an uninterrupted run, frame for frame.
- With Multi Threaded Capture on `auto` or above 1, the Worker is a coordinator (`coordinator.ts`): the one `Sequencer` numbers every frame, plain TCP segments go to shard Workers by connection (`shard.ts`, `src/workers/shardRole.ts`), everything else is dissected on the coordinator, and results merge back in id order. `1` is the single Worker exactly as before. `scripts/pipeline/parallel.ts` holds both to one output (ADR 0053).
- A shard is the same script started by its own URL; its trees stay in its cache and a click on a recent one is asked of it.

## Revisit

- A frame's tree is not a function of its own bytes. A `FrameRecorder` writes every tracker answer at arrival and a `FrameRevisit` hands them back (ADR 0049). Dissectors reach tracker state only through `src/services/dissect/trackerApi.ts`, and outside facts (clock, HTTP/1 body budget, direction) through `src/services/dissect/dissectEnv.ts`.
- A record never holds a key or plaintext. Plaintext answers live in the Worker's memory-only `derivedStore.ts` and are emptied with the key log. A miss throws `RecordMiss` and falls back to `replay.ts`.
- `scripts/pipeline/revisit.ts` revisits every fixture frame and fails on a wrong tree; `scripts/electron/live-revisit-drive.ts` does it on a live capture through the installed agent. Run the drive after anything on this path.
