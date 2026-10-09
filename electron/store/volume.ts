/**
 * The capture directory, over `node:fs`.
 *
 * The adapter half of `services/capture/captureHost.ts`: it holds no decisions,
 * only the calls a host needs to reach a filesystem. Everything it does is
 * synchronous, which is what the `BlockFile` interface is shaped for and what
 * OPFS could only offer inside a Worker.
 */
import { existsSync, mkdirSync, readdirSync, rmSync, statfsSync } from 'node:fs';
import path from 'node:path';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import type { CaptureVolume, OpenVolume } from '../../src/services/capture/captureHost';
import type { DataFiles, SegmentFiles } from '../../src/services/capture/captureWriter';
import { segmentName, segmentNumberOf } from '../../src/services/capture/segments';

/** The files a capture is. Names unchanged from the OPFS layout. */
const FILES = {
  index: 'index.iwidx',
  pfx: 'prefix.iwpfx',
  sum: 'summary.iwsum',
  byt: 'frames.iwbyt',
  // Each frame's record, so its tree can be rebuilt from that frame alone
  // (ADR 0049). Absent from a capture written before it existed, and opened
  // (and so created) empty for one: a version 1 index never points into it.
  rec: 'records.iwrec',
  // The stream digest's snapshot (ADR 0055): one per capture, beside the
  // index and never in a segment. A cache - absent or stale, the store folds
  // it again from the rows - so a capture from before it opens it empty.
  digest: 'streams.iwdig',
} as const;

type OpenData = DataFiles & { close(): void };

/** One directory's four data files: a capture's own, or one segment's. */
function openData(dir: string): OpenData {
  const pfx = NodeBlockFile.open(path.join(dir, FILES.pfx));
  const sum = NodeBlockFile.open(path.join(dir, FILES.sum));
  const byt = NodeBlockFile.open(path.join(dir, FILES.byt));
  const rec = NodeBlockFile.open(path.join(dir, FILES.rec));
  return {
    pfx, sum, byt, rec,
    close() {
      for (const file of [pfx, sum, byt, rec]) {
        try { file.close(); } catch { /* already gone */ }
      }
    },
  };
}

/**
 * A capture's segments, `seg-NNNNNN/` beside its index (ADR 0052). Handles are
 * opened once and held until the segment is removed or the capture closed.
 *
 * **`remove` builds the name itself, from a number**, and deletes only that:
 * the directory is one a person can drop files into, and nothing a caller
 * passes can widen it to anything else (`segments.ts`).
 */
function segmentsOf(captureDir: string): SegmentFiles & { closeAll(): void } {
  const held = new Map<number, OpenData>();
  return {
    open(n) {
      const cached = held.get(n);
      if (cached !== undefined) return cached;
      const dir = path.join(captureDir, segmentName(n));
      mkdirSync(dir, { recursive: true });
      const files = openData(dir);
      held.set(n, files);
      return files;
    },
    find(n) {
      const cached = held.get(n);
      if (cached !== undefined) return cached;
      const dir = path.join(captureDir, segmentName(n));
      if (!existsSync(dir)) return null;
      const files = openData(dir);
      held.set(n, files);
      return files;
    },
    remove(n) {
      const name = segmentName(n);
      held.get(n)?.close();
      held.delete(n);
      rmSync(path.join(captureDir, name), { recursive: true, force: true });
    },
    list() {
      try {
        return readdirSync(captureDir)
          .map(segmentNumberOf)
          .filter((n): n is number => n !== null)
          .sort((a, b) => a - b);
      } catch {
        return [];
      }
    },
    closeAll() {
      for (const files of held.values()) files.close();
      held.clear();
    },
  };
}

export function captureVolume(directory: string): CaptureVolume {
  mkdirSync(directory, { recursive: true });

  return {
    directory,

    open(captureId: string): OpenVolume {
      const dir = path.join(directory, captureId);
      const index = NodeBlockFile.open(path.join(dir, FILES.index));
      const digest = NodeBlockFile.open(path.join(dir, FILES.digest));
      const data = openData(dir);
      const segments = segmentsOf(dir);
      return {
        index, pfx: data.pfx, sum: data.sum, byt: data.byt, rec: data.rec,
        digest,
        segments,
        close() {
          try { index.close(); } catch { /* already gone */ }
          try { digest.close(); } catch { /* already gone */ }
          data.close();
          segments.closeAll();
        },
      };
    },

    list(): string[] {
      try {
        // Names only, which is all `planPrune` decides on: it matches each
        // against `CAPTURE_ID_PATTERN` and refuses everything else, file or
        // directory alike. This read `{ withFileTypes: true }` and then
        // `.map(e => e.name)`, with a comment claiming a stray file was
        // "reported as foreign rather than attempted as a directory" - the map
        // threw the dirent away, so the result was identical to this and the
        // distinction never crossed the seam. Widening `list()` to carry the
        // type is the change to make if that distinction is ever wanted.
        return readdirSync(directory);
      } catch {
        return [];
      }
    },

    remove(captureId: string): void {
      // Only ever called with a name `planPrune` approved, or the id of the
      // capture the user just discarded. `force` so removing something already
      // gone is not an error; no `maxRetries`, because a failure here is
      // reported and retried on the next launch rather than spun on.
      rmSync(path.join(directory, captureId), { recursive: true, force: true });
    },

    freeBytes(): number | null {
      try {
        const stats = statfsSync(directory);
        return stats.bavail * stats.bsize;
      } catch {
        // Not every filesystem answers. Null is "unknown", which the panel
        // renders as an em dash rather than as zero.
        return null;
      }
    },
  };
}
