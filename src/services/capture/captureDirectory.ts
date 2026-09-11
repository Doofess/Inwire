/**
 * What a capture directory is called, and what may be deleted.
 *
 * ## Why this is its own module
 *
 * `prune` removes every directory the app is not keeping, and while the store
 * lived in OPFS that was safe by construction: the root was the origin's
 * private filesystem, nothing else could put anything there, and an empty keep
 * list simply emptied a directory only this app had ever written to.
 *
 * On a real filesystem it is a recursive delete of a directory the user can
 * open, browse and drop things into - and it runs at startup with an **empty
 * keep list** whenever `loadSessionMeta()` returns nothing, which is the state
 * every existing user is in the first time they launch the desktop build, and
 * the state any corrupt metadata produces.
 *
 * So the generator and the guard live in one file, because the guard is only
 * as good as its agreement with the generator, and `planPrune` refuses to
 * delete anything whose name this app did not choose. `docs/decisions/0012`
 * says a capture is discarded only when the user asks; on OPFS that was a
 * policy, and here it needs a mechanism.
 */

/**
 * `cap-YYYYMMDD-HHMMSS-xxxx`.
 *
 * Anchored at both ends, and lower-case hex only. A directory the user made,
 * a file the antivirus dropped, a `.tmp`, `..` - none of them match, and
 * `planPrune` will not touch what does not match.
 */
export const CAPTURE_ID_PATTERN = /^cap-\d{8}-\d{6}-[0-9a-f]{4}$/;

export function isCaptureId(name: string): boolean {
  return CAPTURE_ID_PATTERN.test(name);
}

/** A capture's directory name: sortable, unique, and readable in a listing. */
export function newCaptureId(at: Date = new Date()): string {
  const pad = (n: number, width = 2) => String(n).padStart(width, '0');
  const stamp = `${at.getFullYear()}${pad(at.getMonth() + 1)}${pad(at.getDate())}`
    + `-${pad(at.getHours())}${pad(at.getMinutes())}${pad(at.getSeconds())}`;
  const suffix = Math.floor(Math.random() * 0xffff).toString(16).padStart(4, '0');
  return `cap-${stamp}-${suffix}`;
}

export interface PrunePlan {
  /** Directories to remove, recursively. Only ever capture directories. */
  remove: string[];
  /**
   * Entries left alone because this app did not create them.
   *
   * Reported rather than silently skipped: something unexpected sitting in the
   * capture directory is worth being able to see, and a prune that quietly
   * ignored things would hide a path misconfiguration that is writing captures
   * somewhere else entirely.
   */
  foreign: string[];
}

/**
 * What to delete, given everything present and everything to keep.
 *
 * Pure, and exported for the same reason `planRecovery` is: this is the one
 * function in the app that decides a user's captures are gone, and it should
 * be testable directly rather than only by running the app and looking at a
 * directory afterwards.
 */
export function planPrune(present: readonly string[], keep: readonly string[]): PrunePlan {
  const kept = new Set(keep);
  const remove: string[] = [];
  const foreign: string[] = [];
  for (const name of present) {
    if (!isCaptureId(name)) { foreign.push(name); continue; }
    if (kept.has(name)) continue;
    remove.push(name);
  }
  return { remove, foreign };
}
