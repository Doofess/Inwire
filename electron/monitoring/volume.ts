/**
 * The monitoring directory, over `node:fs` (ADR 0059).
 *
 * The adapter half of the journal and the rollup store: it holds no decisions,
 * only the two files they need. `userData/monitoring/` keeps `journal.iwmj`,
 * the evidence, and `rollups.iwmr`, the cache derived from it. Neither name
 * matches a capture's `CAPTURE_ID_PATTERN` directory, so the capture prune,
 * which only ever removes what that pattern matches, never reaches here.
 *
 * Imports nothing from Electron: the root is handed in, so a script can open a
 * volume under a temp directory with plain `tsx`.
 */
import path from 'node:path';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import type { BlockFile } from '../../src/services/capture/blockFile';

export const JOURNAL_FILE = 'journal.iwmj';
export const ROLLUP_FILE = 'rollups.iwmr';

export interface MonitoringVolume {
  journal: BlockFile;
  rollups: BlockFile;
  /** Closes both. A file that fails to close does not keep the other open. */
  close(): void;
}

export function monitoringRoot(userDataDir: string): string {
  return path.join(userDataDir, 'monitoring');
}

/** Opens (creating, with the directory) both files under `root`. */
export function openMonitoringVolume(root: string): MonitoringVolume {
  const journal = NodeBlockFile.open(path.join(root, JOURNAL_FILE));
  let rollups: NodeBlockFile;
  try {
    rollups = NodeBlockFile.open(path.join(root, ROLLUP_FILE));
  } catch (e) {
    journal.close();
    throw e;
  }
  return {
    journal,
    rollups,
    close() {
      try {
        journal.close();
      } finally {
        rollups.close();
      }
    },
  };
}
