/**
 * The messages between the page and an import Worker (the pipeline script's
 * fourth role, `workers/importRole.ts`; design: `docs/superpowers/specs/
 * 2026-11-05-import-worker-design.md`).
 *
 * The Worker is spawned per import and never outlives it. The capture store's
 * ingest port arrives with `start` (`event.ports[0]`); rows and records go
 * straight to the store on it, and only what the page must act on comes back
 * here.
 */
import type { CaptureFileFacts } from '../captureFileFacts';
import type { KeyLogShared } from '../tls/keyLog';
import type { PackedRows } from './rowPack';

/**
 * How many tail rows go back in one message. The page decodes a chunk in one
 * task, so this is the length of the longest main-thread task the handover
 * makes. A starting figure: the page client's measurement fixes it.
 */
export const TAIL_CHUNK_ROWS = 20_000;

/** Frames the store has not yet acknowledged before the walk pauses (as `liveFlow`). */
export const IMPORT_CREDIT_FRAMES = 50_000;

export interface ImportRunOptions {
  /** Whether to keep each frame's record, which the store is handed ahead of the rows. */
  record: boolean;
  /** The RAM tail's bounds (`ImportTail`). */
  residentBytes: number;
  maxFrames: number;
  /** The decrypted-answer store's budget, as the live Worker's (`derivedBudgetFor`). */
  derivedBudget: number;
  /** Test seams, as `streamCaptureFile`'s. */
  patchWindow?: number;
  batchFrames?: number;
  windowBytes?: number;
  /** Rows per `tail` message; default `TAIL_CHUNK_ROWS`. */
  tailChunkRows?: number;
  /** Test seam: the unanswered-frames bound; default `IMPORT_CREDIT_FRAMES`. */
  creditFrames?: number;
}

export type ToImport =
  /** The ingest MessagePort is `event.ports[0]`. */
  | { type: 'start'; file: Blob; fileName: string; options: ImportRunOptions }
  /** The page's key log, adopted before the run starts; later snapshots follow it. */
  | { type: 'keylog-shared'; snapshot: KeyLogShared }
  /** The page has added `secrets` message `seq` to its key log; the walk may read on. */
  | { type: 'secretsTaken'; seq: number; snapshot?: KeyLogShared }
  /** The page has opened the capture (`opening` was the request). */
  | { type: 'storeOpen'; captureId: string }
  /** The store has these frames' bytes through `id`: the tail may let go of its own. */
  | { type: 'storedThrough'; id: number };

export type FromImport =
  | { type: 'progress'; readBytes: number; totalBytes: number }
  /** A Decryption Secrets Block's key log; the walk waits for `secretsTaken` with this `seq`. */
  | { type: 'secrets'; seq: number; text: string }
  /** The first batch is built: open the capture, then say `storeOpen`. Sent once. */
  | { type: 'opening' }
  /** A chunk of the tail, oldest first. The slab behind `pack` is transferred. */
  | { type: 'tail'; pack: PackedRows; estimates: number[] }
  | {
      type: 'done';
      totalFrames: number;
      built: number;
      missedPatches: number;
      facts: CaptureFileFacts;
      derived: [number, Uint8Array][];
    }
  | { type: 'failed'; message: string };
