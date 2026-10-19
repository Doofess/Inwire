/**
 * Where a monitoring dataset lives and what may be done to a folder that holds
 * one (ADR 0061): which names belong to it, what a discard removes, whether a
 * folder may be adopted, and `dataset.json`.
 *
 * Decisions only. Nothing here lists a directory, deletes or writes; the
 * utility process's adapter (`electron/monitoring/collector.ts`) hands in what
 * it found and carries out what comes back. That is what lets a script run the
 * discard's guard against `[]` and against a folder with a foreign file in it
 * without a disk, as `planPrune` is held for captures
 * (`scripts/capture/prune-guard.ts`).
 *
 * No `node:*` and no Electron, like everything under `src/services/`.
 */
import { LEGACY_JOURNAL_NAME, SEGMENT_PATTERN } from './segments';
import type { RecoveryResult } from './journal';
import type { ArchiveStatus } from './archive';

/** The folder Inwire creates inside the one the user picks. */
export const DATASET_SUBFOLDER = 'Inwire Monitoring';
export const ROLLUP_NAME = 'rollups.iwmr';
export const ARCHIVE_NAME = 'archive.iwma';
export const DATASET_FILE = 'dataset.json';
export const SETTINGS_NAME = 'settings.json';

export type NameClass = 'dataset' | 'app' | 'foreign';

const PARTIAL_SUFFIX = /^(.+)\.[0-9a-f]{12}\.partial$/;
/**
 * An evidence bundle the user saved beside the dataset (ADR 0063), or one being written: `.iwmon`, its
 * `.iwmon.partial`, or the atomic write's `.iwmon.<12 hex>.partial`. The user's file, not the dataset's:
 * adoption tolerates it and a discard keeps it, so it is classed with the app's own files and never `remove`.
 * The extension is matched in any case, because Windows keeps the spelling the user typed (`Week.IWMON`); the
 * atomic write's hex stays lowercase, as the app writes it.
 */
const BUNDLE_NAME = /^[^/\\]+\.[iI][wW][mM][oO][nN](\.([0-9a-f]{12}\.)?[pP][aA][rR][tT][iI][aA][lL])?$/;
const FIXED_DATASET_NAMES: ReadonlySet<string> = new Set([LEGACY_JOURNAL_NAME, ROLLUP_NAME, ARCHIVE_NAME, DATASET_FILE]);

function classifyBase(name: string, isDefaultLocation: boolean): NameClass {
  if (FIXED_DATASET_NAMES.has(name) || SEGMENT_PATTERN.test(name)) return 'dataset';
  if (isDefaultLocation && name === SETTINGS_NAME) return 'app';
  if (BUNDLE_NAME.test(name)) return 'app';
  return 'foreign';
}

/**
 * The one place the list of a dataset folder's names lives. An interrupted atomic write
 * (`<name>.<12 hex>.partial`) is classed as its base name is. `settings.json` is the app's in the
 * default location and anything else's elsewhere.
 */
export function classifyMonitoringName(name: string, opts: { isDefaultLocation: boolean }): NameClass {
  const base = classifyBase(name, opts.isDefaultLocation);
  if (base !== 'foreign') return base;
  const partial = PARTIAL_SUFFIX.exec(name);
  return partial === null ? 'foreign' : classifyBase(partial[1], opts.isDefaultLocation);
}

export interface DiscardPlan {
  /** What a discard deletes, in the order it deletes it. `dataset.json`, where present, is last. */
  remove: string[];
  /** The app's own files in this folder; never touched. */
  keep: string[];
  /** Anything else; never touched. */
  foreign: string[];
}

function removalRank(name: string): [number, number] {
  const m = SEGMENT_PATTERN.exec(name);
  // Newest segment first, so a crash leaves a journal that still starts at its first id.
  if (m !== null) return [0, -Number(m[1])];
  if (name === LEGACY_JOURNAL_NAME) return [1, 0];
  if (name === ARCHIVE_NAME) return [2, 0];
  if (name === ROLLUP_NAME) return [3, 0];
  if (name === DATASET_FILE) return [5, 0];
  return [4, 0];
}

/** What a whole-dataset discard may remove from `present`. An empty listing removes nothing. */
export function planMonitoringDiscard(present: readonly string[], opts: { isDefaultLocation: boolean }): DiscardPlan {
  const remove: string[] = [];
  const keep: string[] = [];
  const foreign: string[] = [];
  for (const name of present) {
    const c = classifyMonitoringName(name, opts);
    (c === 'dataset' ? remove : c === 'app' ? keep : foreign).push(name);
  }
  remove.sort((a, b) => {
    const [ra, ia] = removalRank(a);
    const [rb, ib] = removalRank(b);
    return ra - rb || ia - ib || (a < b ? -1 : a > b ? 1 : 0);
  });
  return { remove, keep, foreign };
}

// --- the location -----------------------------------------------------------------------------------------

const normal = (p: string, caseInsensitive: boolean): string => {
  let q = p.replace(/\\/g, '/');
  while (q.length > 1 && q.endsWith('/')) q = q.slice(0, -1);
  return caseInsensitive ? q.toLowerCase() : q;
};

/**
 * Why `chosen` cannot hold a dataset, or null. Both paths must already be real paths (symlinks and
 * junctions resolved by the caller). A dataset folder equal to, inside or containing the captures
 * folder is refused: neither prune may be able to see the other's files (ADR 0061).
 */
export function refuseLocation(chosen: string, capturesRoot: string, opts: { caseInsensitive: boolean }): string | null {
  const a = normal(chosen, opts.caseInsensitive);
  const b = normal(capturesRoot, opts.caseInsensitive);
  if (a === b || a.startsWith(`${b}/`)) {
    return 'That folder is where Inwire keeps its captures. Monitoring files are not captures, and the two must not share a folder.';
  }
  if (b.startsWith(`${a}/`)) {
    return 'That folder contains the folder where Inwire keeps its captures. Choose one that does not, so a clean-up of captures can never reach monitoring files.';
  }
  return null;
}

// --- dataset.json -----------------------------------------------------------------------------------------

export interface DatasetFile {
  version: 1;
  /** 32 lowercase hex digits; every segment's generation must equal it. */
  generation: string;
  createdMs: number;
  /** What the last whole-dataset discard replaced, so the sheet can say so. */
  replaced: { discardedAtMs: number; previousGeneration: string; previousFromMs: number; previousThroughMs: number } | null;
  /**
   * Set before a discard deletes anything; an open that finds it finishes the deletion first. It
   * carries what the note `replaced` will say, so a crash-recovered discard reports the same range.
   */
  discarding: { generation: string; fromMs: number; throughMs: number } | null;
}

const GENERATION = /^[0-9a-f]{32}$/;
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);
const isMs = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const isGeneration = (v: unknown): v is string => typeof v === 'string' && GENERATION.test(v);

export function newDatasetFile(generation: string, createdMs: number): DatasetFile {
  return { version: 1, generation, createdMs, replaced: null, discarding: null };
}

export function encodeDatasetFile(f: DatasetFile): string {
  return JSON.stringify(f, null, 2);
}

export type DatasetFileRead = { ok: true; file: DatasetFile } | { ok: false; message: string };

/** A clean copy or a stated failure. Losing the file loses a note and nothing else (ADR 0061), but a file that lies is not trusted. */
export function readDatasetFile(text: string): DatasetFileRead {
  const bad = (why: string): DatasetFileRead => ({ ok: false, message: `dataset.json cannot be used: ${why}.` });
  let v: unknown;
  try { v = JSON.parse(text); } catch { return bad('it is not JSON'); }
  if (!isObject(v)) return bad('it is not an object');
  if (v.version !== 1) return bad(`it is version ${String(v.version)}, and this build reads version 1`);
  if (!isGeneration(v.generation)) return bad('its generation is not 32 hex digits');
  if (!isMs(v.createdMs)) return bad('its creation time is not a time');
  let replaced: DatasetFile['replaced'] = null;
  if (v.replaced !== null) {
    const r = v.replaced;
    if (!isObject(r) || !isMs(r.discardedAtMs) || !isGeneration(r.previousGeneration) || !isMs(r.previousFromMs) || !isMs(r.previousThroughMs)) {
      return bad('its note of a discarded dataset is incomplete');
    }
    replaced = { discardedAtMs: r.discardedAtMs, previousGeneration: r.previousGeneration, previousFromMs: r.previousFromMs, previousThroughMs: r.previousThroughMs };
  }
  let discarding: DatasetFile['discarding'] = null;
  if (v.discarding !== null) {
    const d = v.discarding;
    if (!isObject(d) || !isGeneration(d.generation) || !isMs(d.fromMs) || !isMs(d.throughMs)) return bad('its discard marker is incomplete');
    discarding = { generation: d.generation, fromMs: d.fromMs, throughMs: d.throughMs };
  }
  return { ok: true, file: { version: 1, generation: v.generation, createdMs: v.createdMs, replaced, discarding } };
}

// --- adoption ---------------------------------------------------------------------------------------------

export type AdoptionResult =
  | { kind: 'new' }
  | { kind: 'adopt'; truncatedTailBytes: number | null }
  | { kind: 'adopt-read-only'; problem: string }
  | { kind: 'refuse'; reason: 'refused-version' | 'foreign-files'; message: string; names?: string[] };

const MAX_NAMED = 5;

/**
 * Whether a folder may be adopted (ADR 0061's table). `recovery` is `recoverJournal` over the folder's
 * segments (null where it has none) and `archive` is the archive file as `ArchiveStore.open` read it
 * with the generation its header names (null where there is no archive). Nothing is written to decide.
 *
 * A foreign name refuses before anything else: nothing is created beside a file Inwire did not write.
 */
export function classifyAdoption(
  names: readonly string[], recovery: RecoveryResult | null,
  archive: { status: ArchiveStatus; generation: string | null } | null,
  opts: { isDefaultLocation: boolean; datasetGeneration?: string | null },
): AdoptionResult {
  const foreign = names.filter((n) => classifyMonitoringName(n, opts) === 'foreign');
  if (foreign.length > 0) {
    const named = foreign.slice(0, MAX_NAMED);
    const more = foreign.length > named.length ? ` and ${foreign.length - named.length} more` : '';
    return {
      kind: 'refuse', reason: 'foreign-files', names: named,
      message: `This folder holds files Inwire did not write (${named.join(', ')}${more}). Inwire does not create a dataset beside them, and changed nothing.`,
    };
  }
  if (recovery === null || (recovery.status === 'empty' && recovery.tornTail === null)) return { kind: 'new' };
  if (recovery.status === 'unknown-version') {
    return {
      kind: 'refuse', reason: 'refused-version',
      message: `This folder holds a dataset this build cannot read: ${recovery.problem ?? 'an unknown format'}. It was left untouched.`,
    };
  }
  if (recovery.status === 'corrupt') {
    return { kind: 'adopt-read-only', problem: recovery.problem ?? 'the journal is damaged' };
  }
  if (opts.datasetGeneration != null && recovery.generation !== null && opts.datasetGeneration !== recovery.generation) {
    return { kind: 'adopt-read-only', problem: 'dataset.json belongs to a different dataset than the journal beside it' };
  }
  if (archive !== null) {
    if (archive.status === 'corrupt' || archive.status === 'failed') {
      return { kind: 'adopt-read-only', problem: `the sealed archive cannot be read (${archive.status})` };
    }
    if (archive.generation !== null && recovery.generation !== null && archive.generation !== recovery.generation) {
      return { kind: 'adopt-read-only', problem: 'the sealed archive belongs to a different dataset than the journal beside it' };
    }
  }
  return { kind: 'adopt', truncatedTailBytes: recovery.tornTail === null ? null : recovery.tornTail.bytes };
}
