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
import { existsSync, mkdirSync, readdirSync, readFileSync, unlinkSync } from 'node:fs';
import path from 'node:path';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import type { BlockFile } from '../../src/services/capture/blockFile';
import { ARCHIVE_NAME } from '../../src/services/monitoring/datasetPlan';
import { isSegmentFileName, type SegmentDirectory } from '../../src/services/monitoring/segments';
import { writeFileAtomic } from '../atomicWrite';

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
  archive: BlockFile;
  /** Every name in the folder, files and folders alike: what a discard and an adoption decide from. */
  names(): string[];
  /** Unlinks one file by name. Works after `close()`; the discard closes first, Windows will not unlink an open file. */
  removeFile(name: string): void;
  /** A small text file of the dataset (`dataset.json`), or null where there is none. */
  readText(name: string): string | null;
  /** Writes it atomically: a crash leaves the old text or the new, never half of one. */
  writeText(name: string, text: string): void;
  /** Closes all three. A file that fails to close does not keep the others open. */
  close(): void;
}

export function monitoringRoot(userDataDir: string): string {
  return path.join(userDataDir, 'monitoring');
}

/** A name that stays inside the folder: a bare file name, no separator, not `.` or `..`. */
function assertPlainName(name: string): void {
  if (name === '' || name === '.' || name === '..' || /[\\/]/.test(name)) throw new RangeError(`not a plain file name: ${name}`);
}

/**
 * A folder looked at, not changed: no directory or file is created, and the segment directory refuses
 * to create or unlink. What adoption reads before the user agrees to anything (ADR 0061).
 */
export function openMonitoringFolder(root: string): CollectorFolderView {
  let names: string[];
  try {
    names = readdirSync(root);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') names = [];
    else throw e;
  }
  const files = new Map<string, NodeBlockFile>();
  const refuse = (name: string): never => { throw new Error(`${name}: a folder being looked at is not written to`); };
  const segments: SegmentDirectory = {
    list: () => names.filter(isSegmentFileName).sort(),
    open(name) {
      if (!isSegmentFileName(name)) throw new RangeError(`not a segment name: ${name}`);
      let file = files.get(name);
      if (file === undefined) {
        file = new NodeBlockFile(path.join(root, name));
        files.set(name, file);
      }
      return file;
    },
    create: refuse,
    unlink: refuse,
  };
  let archive: NodeBlockFile | null = null;
  if (names.includes(ARCHIVE_NAME)) archive = new NodeBlockFile(path.join(root, ARCHIVE_NAME));
  return {
    names,
    segments,
    archive,
    readText(name) {
      assertPlainName(name);
      try {
        return readFileSync(path.join(root, name), 'utf8');
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
        throw e;
      }
    },
    close() {
      let first: unknown;
      for (const file of [...files.values(), ...(archive === null ? [] : [archive])]) {
        try { file.close(); } catch (e) { first ??= e; }
      }
      files.clear();
      if (first !== undefined) throw first;
    },
  };
}

/** `CollectorFolder` in `collector.ts`, restated here so this file imports nothing from the collector. */
export interface CollectorFolderView {
  names: string[];
  segments: SegmentDirectory;
  archive: BlockFile | null;
  readText(name: string): string | null;
  close(): void;
}

/** Opens (creating, with the directory) the segment folder, the rollup cache and the archive under `root`. */
export function openMonitoringVolume(root: string): MonitoringVolume {
  const segments = new NodeSegmentDirectory(root);
  const opened: NodeBlockFile[] = [];
  try {
    opened.push(NodeBlockFile.open(path.join(root, ROLLUP_FILE)));
    opened.push(NodeBlockFile.open(path.join(root, ARCHIVE_NAME)));
  } catch (e) {
    for (const f of opened) { try { f.close(); } catch { /* the first failure is the one to report */ } }
    segments.close();
    throw e;
  }
  const [rollups, archive] = opened;
  return {
    segments,
    rollups,
    archive,
    names: () => readdirSync(root),
    removeFile(name) {
      assertPlainName(name);
      unlinkSync(path.join(root, name));
    },
    readText(name) {
      assertPlainName(name);
      try {
        return readFileSync(path.join(root, name), 'utf8');
      } catch (e) {
        if ((e as NodeJS.ErrnoException).code === 'ENOENT') return null;
        throw e;
      }
    },
    writeText(name, text) {
      assertPlainName(name);
      writeFileAtomic(path.join(root, name), text);
    },
    close() {
      try {
        segments.close();
      } finally {
        try { rollups.close(); } finally { archive.close(); }
      }
    },
  };
}
