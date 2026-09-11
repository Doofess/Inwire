/**
 * The capture directory, over `node:fs`.
 *
 * The adapter half of `services/capture/captureHost.ts`: it holds no decisions,
 * only the four calls a host needs to reach a filesystem. Everything it does is
 * synchronous, which is what the `BlockFile` interface is shaped for and what
 * OPFS could only offer inside a Worker.
 */
import { mkdirSync, readdirSync, rmSync, statfsSync } from 'node:fs';
import path from 'node:path';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import type { CaptureVolume, OpenVolume } from '../../src/services/capture/captureHost';

/** The four files a capture is. Names unchanged from the OPFS layout. */
const FILES = {
  index: 'index.iwidx',
  pfx: 'prefix.iwpfx',
  sum: 'summary.iwsum',
  byt: 'frames.iwbyt',
} as const;

export function captureVolume(directory: string): CaptureVolume {
  mkdirSync(directory, { recursive: true });

  return {
    directory,

    open(captureId: string): OpenVolume {
      const dir = path.join(directory, captureId);
      const index = NodeBlockFile.open(path.join(dir, FILES.index));
      const pfx = NodeBlockFile.open(path.join(dir, FILES.pfx));
      const sum = NodeBlockFile.open(path.join(dir, FILES.sum));
      const byt = NodeBlockFile.open(path.join(dir, FILES.byt));
      return {
        index, pfx, sum, byt,
        close() {
          for (const file of [index, pfx, sum, byt]) {
            try { file.close(); } catch { /* already gone */ }
          }
        },
      };
    },

    list(): string[] {
      try {
        // `withFileTypes` so a stray file is reported as foreign rather than
        // attempted as a directory - `planPrune` refuses both, and this keeps
        // the reason accurate.
        return readdirSync(directory, { withFileTypes: true }).map((entry) => entry.name);
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
