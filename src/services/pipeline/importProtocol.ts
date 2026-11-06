/**
 * The messages between the page and an import Worker (the pipeline script's
 * fourth role, `workers/importRole.ts`; design: `docs/superpowers/specs/
 * 2026-11-05-import-worker-design.md`).
 *
 * The Worker is spawned per import and never outlives it. The capture store's
 * ingest port arrives with `start` (`event.ports[0]`); each batch is packed once
 * and the pack goes to the store on it and, transferred, to the page as `rows`
 * (the page keeps the RAM tail).
 */
import type { CaptureFileFacts } from '../captureFileFacts';
import type { KeyLogShared } from '../tls/keyLog';
import type { PackedRows } from './rowPack';

/**
 * The first key of the packs an import Worker makes (one per batch, counting up).
 * The store host has ONE `PackReader`, shared with the live pipeline Worker, whose
 * keys count up from zero: starting an import's far above them means a pack of the
 * live Worker that is still held can never be replaced by an import's. Kept below
 * 2^31 and above zero: `PackedRows.order` uses -1 for an object row.
 */
export const IMPORT_PACK_KEY_BASE = 0x40000000;

/** The name the page gives an import Worker. Not a shard's or the reader's. */
export const IMPORT_NAME = 'inwire-import';

/** Frames the store has not yet acknowledged before the walk pauses (as `liveFlow`). */
export const IMPORT_CREDIT_FRAMES = 50_000;

export interface ImportRunOptions {
  /** Whether to keep each frame's record, which the store is handed ahead of the rows. */
  record: boolean;
  /**
   * The RAM tail's bounds (`ImportTail`). The page keeps the tail, so the Worker
   * does not read these; they ride with the rest of the import's options.
   */
  residentBytes: number;
  maxFrames: number;
  /** The decrypted-answer store's budget, as the live Worker's (`derivedBudgetFor`). */
  derivedBudget: number;
  /** Test seams, as `streamCaptureFile`'s. */
  patchWindow?: number;
  batchFrames?: number;
  windowBytes?: number;
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
  | { type: 'storeOpen'; captureId: string };

export type FromImport =
  | { type: 'progress'; readBytes: number; totalBytes: number }
  /** A Decryption Secrets Block's key log; the walk waits for `secretsTaken` with this `seq`. */
  | { type: 'secrets'; seq: number; text: string }
  /** The first batch is built: open the capture, then say `storeOpen`. Sent once. */
  | { type: 'opening' }
  /**
   * One batch's rows, final (the batcher drains a frame only after its patch
   * window closed), packed once: the store was sent this same pack first, so the
   * buffers behind `pack` are transferred here. `sizes` is each row's
   * `estimateSummaryBytes`, taken where the row was dissected; the page's
   * `ImportTail` trims by them. Every pack is read whole within its message, so
   * the page keeps no pack state and `packsReset` is never set.
   */
  | { type: 'rows'; pack: PackedRows; sizes: number[] }
  | {
      type: 'done';
      totalFrames: number;
      built: number;
      missedPatches: number;
      facts: CaptureFileFacts;
      derived: [number, Uint8Array][];
    }
  | { type: 'failed'; message: string };
