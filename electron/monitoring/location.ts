/**
 * Which folder a picked folder means for a monitoring dataset (ADR 0061), with Electron taken out so a
 * script can drive it under `tsx`: main shows the dialog and hands the answer here.
 *
 * The dialog's folder is not always the dataset's. The default root is itself; a folder that already
 * holds a journal (the legacy `journal.iwmj` or a segment) is an existing dataset and is adopted where
 * it is; any other folder gets a subfolder of its own, `Inwire Monitoring`, so the dataset never mixes
 * with what the user keeps beside it. Every path is a real path (links and junctions resolved) before
 * it is compared with the captures folder, which no dataset may equal, sit inside or contain.
 */
import path from 'node:path';
import { DATASET_SUBFOLDER, refuseLocation } from '../../src/services/monitoring/datasetPlan';
import { isSegmentFileName, LEGACY_JOURNAL_NAME } from '../../src/services/monitoring/segments';

export type { LocationReply } from '../../src/services/monitoring/control';

export interface ResolveDeps {
  /** `<userData>/monitoring`: the default location, where `settings.json` lives. */
  defaultRoot: string;
  /** `<userData>/captures`; it need not exist. */
  capturesRoot: string;
  /** Whether the file system compares names without case (Windows, default macOS). */
  caseInsensitive: boolean;
  /** The real path, or throws. */
  realpath(p: string): string;
  exists(p: string): boolean;
  /** The names in a folder, or throws. */
  list(p: string): string[];
}

export type ResolvedFolder = { ok: true; root: string; isDefaultLocation: boolean } | { ok: false; message: string };

const describe = (e: unknown): string => (e instanceof Error ? e.message : String(e));

export function resolveDatasetFolder(picked: string, opts: ResolveDeps): ResolvedFolder {
  const same = (a: string, b: string): boolean => (opts.caseInsensitive ? a.toLowerCase() === b.toLowerCase() : a === b);
  let real: string;
  let defaultReal: string;
  try {
    real = opts.realpath(picked);
    defaultReal = opts.exists(opts.defaultRoot) ? opts.realpath(opts.defaultRoot) : opts.defaultRoot;
  } catch (e) {
    return { ok: false, message: `That folder could not be read: ${describe(e)}` };
  }
  let root: string;
  let isDefaultLocation = false;
  if (same(real, defaultReal)) {
    root = defaultReal;
    isDefaultLocation = true;
  } else {
    try {
      const names = opts.list(real);
      if (names.includes(LEGACY_JOURNAL_NAME) || names.some(isSegmentFileName)) {
        root = real;
      } else {
        const sub = path.join(real, DATASET_SUBFOLDER);
        // The subfolder may be a link or a junction left by an earlier choice.
        root = opts.exists(sub) ? opts.realpath(sub) : sub;
      }
    } catch (e) {
      return { ok: false, message: `That folder could not be read: ${describe(e)}` };
    }
  }
  let captures: string;
  try {
    captures = opts.exists(opts.capturesRoot)
      ? opts.realpath(opts.capturesRoot)
      : path.join(opts.realpath(path.dirname(opts.capturesRoot)), path.basename(opts.capturesRoot));
  } catch (e) {
    return { ok: false, message: `The captures folder could not be resolved: ${describe(e)}` };
  }
  const refusal = refuseLocation(root, captures, { caseInsensitive: opts.caseInsensitive });
  if (refusal !== null) return { ok: false, message: refusal };
  return { ok: true, root, isDefaultLocation };
}
