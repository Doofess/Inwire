/**
 * A `CaptureVolume` over memory: the four files, surviving a close.
 *
 * Lifted out of `scripts/capture/store-protocol.ts` because a second harness
 * needed the same thing - the export's whole-capture iterator is driven
 * through a real `CaptureHost` - and two copies of a fake are two fakes that
 * can disagree about what a volume does.
 *
 * Reopening has to find what was written - recovery, the resume and the torn
 * tail are the whole point of `open` being one message rather than two - so
 * the files outlive the `OpenVolume` that wrapped them.
 *
 * Under `src/` rather than `scripts/` so both harnesses import one module, and
 * it imports no `node:*`, so `scripts/capture/node-safe.ts` holds it like
 * anything else here. Nothing in the app uses it.
 */
import { MemoryBlockFile } from './blockFile';
import type { CaptureVolume, OpenVolume } from './captureHost';
import type { CaptureFiles } from './captureWriter';

function emptyFiles(): CaptureFiles {
  return {
    index: new MemoryBlockFile(), pfx: new MemoryBlockFile(),
    sum: new MemoryBlockFile(), byt: new MemoryBlockFile(), rec: new MemoryBlockFile(),
  };
}

export class MemoryVolume implements CaptureVolume {
  readonly directory = 'C:\\memory\\captures';
  private readonly stored = new Map<string, CaptureFiles>();
  /** Opens minus closes. A leaked handle is a Windows EBUSY on the next prune. */
  outstanding = 0;

  open(captureId: string): OpenVolume {
    let files = this.stored.get(captureId);
    if (files === undefined) {
      files = emptyFiles();
      this.stored.set(captureId, files);
    }
    this.outstanding++;
    let closed = false;
    return {
      ...files,
      close: () => {
        if (closed) return;
        closed = true;
        this.outstanding--;
      },
    };
  }

  list(): string[] { return [...this.stored.keys()]; }
  remove(captureId: string): void { this.stored.delete(captureId); }
  freeBytes(): number { return 1_000_000_000_000; }
  /** Entries that are not captures, for the prune guard. */
  plant(name: string): void { this.stored.set(name, emptyFiles()); }
}
