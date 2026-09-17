# 0003 - Keep dissection synchronous; move the whole pipeline into one Worker

> **Corrected by [0007](0007-what-crosses-the-worker-boundary.md).** "The whole
> pipeline into one Worker" held; what this file got wrong is what crosses the
> boundary. 0007 is the rule in force: bytes cross, trees do not.

**Status:** Accepted 2026-09-04

## Context

All dissection runs on the main thread inside `WebSocket.onmessage` (`App.tsx:1104+`),
one packet per message, with a 100 ms flush into React state. The QUIC Initial
decryption uses hand-rolled synchronous AES-GCM/HKDF/SHA-256 precisely because
WebCrypto is Promise-based and a Promise per packet would force the entire pipeline
async. Measured single-thread parse rate is 6-7k pkt/s in Node; the agent log shows the
browser failing to keep up with real traffic (260k+ drops on 3 Sep).

The v2 spec proposed both "move to a worker" and "use WebCrypto"; the two conflict.

## Decision

1. **Dissection stays synchronous.** No `await` in `dissectSummary`, `dissectTree`,
   the trackers or the crypto. WebCrypto is not introduced. The existing
   `src/services/crypto/*` is the crypto layer for TLS decryption in Phase 13 too
   (AES-GCM exists; ChaCha20-Poly1305 is added there in the same style).
2. **One dedicated Worker owns the pipeline** (Phase 11): socket -> batch decode ->
   ordering window (ADR 0005) -> `dissectSummary` -> trackers -> filter predicate ->
   aggregates. It posts to the main thread:
   - column rows for the visible window and new-frame deltas (transferable typed
     arrays: `tsUs: Float64Array`, `len: Uint32Array`, `flags: Uint8Array`, plus
     string columns as a batched array);
   - per-frame `DissectSummary` for frames the UI asks about (selection, hover,
     export), on request;
   - tracker/aggregate deltas (conversations, endpoints, hierarchy, expert counts,
     name-resolution map) every flush.
   The main thread never sees `rawBytes` for unselected frames; bytes live in the
   Worker's ring buffer and are fetched by frame number when needed.
3. **`Packet` identity in the main thread is per-row-cache, not per-message.** The
   main thread keeps a `Map<frameNo, Packet>` of materialised packets for what it
   displays; the colour-rule cache keys on those. Structured clone across the worker
   boundary is therefore never on the hot path.
4. **Import and session restore use the same Worker** with a file/IndexedDB source
   instead of a socket, so live and imported captures share one code path, as they
   do today via `decodeRawEthernetPacket`.
5. **Filters compile in the Worker** (ADR 0002 registry + Phase 9 AST); the main
   thread sends the filter string and receives the matching frame-number list.

Until Phase 11 the pipeline stays on the main thread but is written against these
interfaces: `dissectSummary` takes a `DissectInput` view over a buffer, never a
base64 string, and the ordering window (Phase 3) is a standalone module with no DOM
or React dependency, so it moves without change.

## Consequences

- Phases 3-10 must not add React or DOM dependencies to anything under
  `src/services/dissect/`. Enforced by an assertion script that greps imports.
- `maplibre-gl` already runs its own workers; Vite's worker handling is known-good
  in this project (`vite.config.ts` notes). The pipeline Worker is a plain
  `new Worker(new URL('./pipeline.worker.ts', import.meta.url), { type: 'module' })`.
- Session persistence moves into the Worker too, which removes the main-thread
  `sessionStore` write pressure that `TRIM_BATCH`/`MAX_PENDING_FRAMES` exist to manage.
