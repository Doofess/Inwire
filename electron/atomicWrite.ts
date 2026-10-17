/**
 * Writing a file so that it is whole or absent, never half there.
 *
 * The rule `saveSession.ts` holds an export to and `capturedFiles.ts` holds a
 * copy to, in one place: the bytes go to `<target>.<random>.partial` and the
 * partial is renamed onto the target, so a crash or a full disk leaves either
 * the old file or the new one, and a failure leaves no partial behind. The
 * random part keeps two writers (or a writer and a stale partial) apart.
 *
 * No Electron here, so a script can drive it under plain `tsx`.
 */
import { randomBytes } from 'node:crypto';
import { renameSync, rmSync, writeFileSync } from 'node:fs';

/** Where `target` is written before it is renamed onto its name. */
export function partialPath(target: string): string {
  return `${target}.${randomBytes(6).toString('hex')}.partial`;
}

/**
 * Writes `data` to `path` through a partial. On any failure the partial is
 * removed (if it can be) and the error is thrown on; the target is untouched.
 */
export function writeFileAtomic(path: string, data: string | Uint8Array): void {
  const partial = partialPath(path);
  try {
    writeFileSync(partial, data);
    renameSync(partial, path);
  } catch (error) {
    // Windows can refuse this too (EPERM, EBUSY); the write's own error is the one the caller needs.
    try { rmSync(partial, { force: true }); } catch { /* the original error is thrown below */ }
    throw error;
  }
}
