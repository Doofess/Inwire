/**
 * A `CaptureVolume` over memory: the files, surviving a close.
 *
 * Lifted out of `scripts/capture/store-protocol.ts` because a second harness
 * needed the same thing - the export's whole-capture iterator is driven
 * through a real `CaptureHost` - and two copies of a fake are two fakes that
 * can disagree about what a volume does.
 *
 * Reopening has to find what was written - recovery, the resume and the torn
 * tail are the whole point of `open` being one message rather than two - so
 * the files outlive the `OpenVolume` that wrapped them. A capture's segments
 * (ADR 0052) are held the same way.
 *
 * Under `src/` rather than `scripts/` so both harnesses import one module, and
 * it imports no `node:*`, so `scripts/capture/node-safe.ts` holds it like
 * anything else here. Nothing in the app uses it.
 */
import { MemoryBlockFile } from './blockFile';
import type { CaptureVolume, OpenVolume } from './captureHost';
import type { CaptureFiles, DataFiles, SegmentFiles } from './captureWriter';

function emptyData(): DataFiles {
  return {
    pfx: new MemoryBlockFile(), sum: new MemoryBlockFile(),
    byt: new MemoryBlockFile(), rec: new MemoryBlockFile(),
  };
}

interface StoredCapture {
  files: CaptureFiles;
  /** The stream digest's snapshot: the capture's, beside the index, never a segment's. */
  digest: MemoryBlockFile;
  segments: Map<number, DataFiles>;
}

function emptyCapture(): StoredCapture {
  return {
    files: { index: new MemoryBlockFile(), ...emptyData() },
    digest: new MemoryBlockFile(),
    segments: new Map(),
  };
}

export class MemoryVolume implements CaptureVolume {
  readonly directory = 'C:\\memory\\captures';
  private readonly stored = new Map<string, StoredCapture>();
  /** Opens minus closes. A leaked handle is a Windows EBUSY on the next prune. */
  outstanding = 0;

  open(captureId: string): OpenVolume {
    let capture = this.stored.get(captureId);
    if (capture === undefined) {
      capture = emptyCapture();
      this.stored.set(captureId, capture);
    }
    const { segments } = capture;
    this.outstanding++;
    let closed = false;
    const segmentFiles: SegmentFiles = {
      open(n) {
        let data = segments.get(n);
        if (data === undefined) {
          data = emptyData();
          segments.set(n, data);
        }
        return data;
      },
      find: (n) => segments.get(n) ?? null,
      remove: (n) => { segments.delete(n); },
      list: () => [...segments.keys()].sort((a, b) => a - b),
    };
    return {
      ...capture.files,
      digest: capture.digest,
      segments: segmentFiles,
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
  plant(name: string): void { this.stored.set(name, emptyCapture()); }
  /** The segments a capture holds on this volume, by number. */
  segmentsOf(captureId: string): number[] {
    return [...(this.stored.get(captureId)?.segments.keys() ?? [])].sort((a, b) => a - b);
  }
}
