/**
 * "Save as captured": copying the agent's own pcapng files out of a capture's
 * folder (ADR 0052).
 *
 * The agent writes each capture's frames to `<capture>/pcapng/` as it reads
 * them, laid out as dumpcap lays a file out - SHB, IDBs, EPBs, ISBs. Those are
 * the capture as captured, and saving one is a copy, not an export: nothing is
 * decoded, rebuilt or re-timed, so what leaves is byte for byte what the agent
 * wrote. An export rebuilds a file from the store; this does not.
 *
 * **The renderer names a capture, never a path.** It sends a capture id, which
 * must be one this app would have made (`CAPTURE_ID_PATTERN`); the folder is
 * main's own, and the files in it are the ones whose names the agent gives -
 * nothing else there is copied. The destination is whatever the person picks
 * in a dialog they can see.
 *
 * **A copy lands whole or not at all.** Each file is copied to
 * `<target>.<random>.partial` and renamed onto its name, the rule
 * `saveSession.ts` holds an export to: a failure half way leaves no file that
 * looks finished. A ring's files go into a new folder of their own, named for
 * the capture, so they cannot land among, or over, anything already there.
 *
 * No Electron here, so `scripts/electron/captured-files.ts` drives it under
 * plain `tsx`; `saveCaptured.ts` is the adapter.
 */
import { copyFileSync, existsSync, mkdirSync, readdirSync, renameSync, rmSync } from 'node:fs';
import path from 'node:path';
import { isCaptureId } from '../src/services/capture/captureDirectory';
import { partialPath } from './atomicWrite';

/**
 * A file the agent names: `capture.pcapng`, or a ring's
 * `capture_NNNNN_YYYYMMDDhhmmss.pcapng` - with `-N` when a name was taken
 * (`agent-rs/src/capture_file.rs`, `candidate`).
 */
export const CAPTURED_FILE_PATTERN = /^capture(?:_\d{5}_\d{14})?(?:-\d{1,3})?\.pcapng$/;

/** The agent's files for this capture, in order, or none when there are none. */
export function capturedFiles(captureRoot: string, captureId: string): string[] {
  if (!isCaptureId(captureId)) return [];
  let names: string[];
  try {
    names = readdirSync(path.join(captureRoot, captureId, 'pcapng'));
  } catch {
    return [];
  }
  // Ring files sort by index then time, which is the order they were written;
  // a single file is alone.
  return names.filter((name) => CAPTURED_FILE_PATTERN.test(name)).sort();
}

/** Where a capture's files are, given its id - one of `capturedFiles`'s names. */
export function capturedFilePath(captureRoot: string, captureId: string, name: string): string {
  return path.join(captureRoot, captureId, 'pcapng', name);
}

/**
 * A folder of its own for a ring's files inside `parent`: the capture's id,
 * or the id with `-2`, `-3` and on when that is taken. Never one that exists.
 */
export function freshFolder(parent: string, captureId: string): string {
  for (let n = 1; n < 1000; n++) {
    const candidate = path.join(parent, n === 1 ? captureId : `${captureId}-${n}`);
    if (!existsSync(candidate)) return candidate;
  }
  throw new Error(`${parent} already holds a thousand folders named for ${captureId}`);
}

/**
 * Copies each source onto its target, each through a `.partial` renamed into
 * place. On a failure every file this call already finished is removed as
 * well, so a set is saved whole or not at all, and the error is thrown on.
 */
export function copyWhole(sources: readonly string[], targets: readonly string[]): void {
  if (sources.length !== targets.length) throw new Error('copyWhole: a target for each source');
  const done: string[] = [];
  let partial: string | null = null;
  try {
    for (let i = 0; i < sources.length; i++) {
      partial = partialPath(targets[i]);
      copyFileSync(sources[i], partial);
      renameSync(partial, targets[i]);
      partial = null;
      done.push(targets[i]);
    }
  } catch (error) {
    if (partial !== null) rmSync(partial, { force: true });
    for (const target of done) rmSync(target, { force: true });
    throw error;
  }
}

/** Copies a ring's files into a new folder inside `parent`, and answers the folder. */
export function copyRing(captureRoot: string, captureId: string, names: readonly string[], parent: string): string {
  const folder = freshFolder(parent, captureId);
  mkdirSync(folder);
  try {
    copyWhole(names.map((name) => capturedFilePath(captureRoot, captureId, name)),
      names.map((name) => path.join(folder, name)));
  } catch (error) {
    rmSync(folder, { recursive: true, force: true });
    throw error;
  }
  return folder;
}
