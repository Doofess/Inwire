/**
 * The monitoring directory, over `node:fs` (ADRs 0059, 0062).
 *
 * The adapter half of the journal and the rollup store: it holds no decisions,
 * only the files they need. `userData/monitoring/` keeps the journal's
 * segments (`journal-<first entry id>.iwmj`, and a milestone-1 `journal.iwmj`
 * where one was written), the evidence, and `rollups.iwmr`, the cache derived
 * from it. No name matches a capture's `CAPTURE_ID_PATTERN` directory, so the
 * capture prune, which only ever removes what that pattern matches, never
 * reaches here.
 *
 * Imports nothing from Electron: the root is handed in, so a script can open
 * a volume under a temp directory with plain `tsx`.
 */
import { existsSync, mkdirSync, readdirSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import type { BlockFile } from '../../src/services/capture/blockFile';
import { isSegmentFileName, type SegmentDirectory } from '../../src/services/monitoring/segments';

export const ROLLUP_FILE = 'rollups.iwmr';

/**
 * A folder of segments. It owns the handles: `open` returns the same file for
 * the same name, and `unlink` closes before it removes, which Windows requires.
 * Opening a directory creates no journal file, so an unused monitoring folder
 * holds none.
 */
export class NodeSegmentDirectory implements SegmentDirectory {
  private readonly files = new Map<string, NodeBlockFile>();

  constructor(readonly root: string) {
    mkdirSync(root, { recursive: true });
  }

  list(): string[] {
    return readdirSync(this.root).filter(isSegmentFileName).sort();
  }

  open(name: string): BlockFile {
    this.assertName(name);
    let file = this.files.get(name);
    if (file === undefined) {
      file = new NodeBlockFile(path.join(this.root, name));
      this.files.set(name, file);
    }
    return file;
  }

  create(name: string): BlockFile {
    this.assertName(name);
    const full = path.join(this.root, name);
    if (this.files.has(name) || existsSync(full)) throw new Error(`${name} already exists`);
    const file = NodeBlockFile.open(full);
    this.files.set(name, file);
    return file;
  }

  unlink(name: string): void {
    this.assertName(name);
    const file = this.files.get(name);
    if (file !== undefined) {
      this.files.delete(name);
      file.close();
    }
    unlinkSync(path.join(this.root, name));
  }

  /** Closes every handle. A file that fails to close does not keep the others open. */
  close(): void {
    let first: unknown;
    for (const file of this.files.values()) {
      try { file.close(); } catch (e) { first ??= e; }
    }
    this.files.clear();
    if (first !== undefined) throw first;
  }

  private assertName(name: string): void {
    if (!isSegmentFileName(name)) throw new RangeError(`not a segment name: ${name}`);
  }
}

export interface MonitoringVolume {
  segments: NodeSegmentDirectory;
  rollups: BlockFile;
  /** Closes both. A file that fails to close does not keep the other open. */
  close(): void;
}

export function monitoringRoot(userDataDir: string): string {
  return path.join(userDataDir, 'monitoring');
}

/** Opens (creating, with the directory) the segment folder and the rollup file under `root`. */
export function openMonitoringVolume(root: string): MonitoringVolume {
  const segments = new NodeSegmentDirectory(root);
  let rollups: NodeBlockFile;
  try {
    rollups = NodeBlockFile.open(path.join(root, ROLLUP_FILE));
  } catch (e) {
    segments.close();
    throw e;
  }
  return {
    segments,
    rollups,
    close() {
      try {
        segments.close();
      } finally {
        rollups.close();
      }
    },
  };
}
