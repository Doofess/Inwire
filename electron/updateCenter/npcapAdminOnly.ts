/**
 * `AdminOnly`, the value Npcap's installer writes when the box is ticked.
 *
 * Half of the driver-access answer. The other half is the device object's
 * DACL, which the agent reads because it runs as SYSTEM, and the two are
 * combined by `src/services/npcapAccess.ts` - with the DACL winning, because
 * it is what the kernel enforces. docs/decisions/0033.
 *
 * This half is here rather than there because the app can read it with no
 * agent connected at all, which is the state a machine is in while the Update
 * Center is showing somebody why capture does not work yet.
 *
 * ## Every trap `npcap.ts` documents applies to this value too
 *
 * It lives under **`WOW6432Node`**, because Npcap's installer is 32-bit - so
 * `/reg:32` is asked first and the 64-bit view is the fallback, exactly as the
 * version read does it. Measured on Windows 11 26200 with Npcap 1.88: the
 * 64-bit view of `HKLM\SOFTWARE\Npcap` does not exist, and `reg query` exits 1
 * with empty stdout, which `agentService.ts`'s `provesAbsent` would read as
 * proof of absence.
 *
 * And it is a `REG_DWORD`, not the `REG_SZ` `parseDisplayVersion` reads, so
 * that parser could not be reused - nor should it be: a value of the wrong
 * type must answer "not known" rather than be coerced into a boolean.
 */
import { execFile } from 'node:child_process';

/** Both spellings, both views. The same list `npcap.ts` probes for presence. */
const ADMIN_ONLY_KEYS = ['HKLM\\SOFTWARE\\WOW6432Node\\Npcap', 'HKLM\\SOFTWARE\\Npcap'];

const VALUE_NAME = 'AdminOnly';

/** Same budget as the version query beside it. */
const QUERY_TIMEOUT_MS = 5000;

/**
 * Reads `AdminOnly` out of `reg query` output.
 *
 * Null for "the value was not there, or was not a DWORD" - never `false`.
 * Defaulting an unreadable value to `false` would tell somebody their driver
 * is open to every account on the strength of having failed to look, and
 * defaulting it to `true` would tell them it is safe on the same strength.
 *
 * Any non-zero value is `true`. Npcap writes `0x1`, but a registry a user or
 * another tool has edited can hold anything, and "not zero" is what the
 * installer's own `IsNpcapInstalled`-style probes mean by set.
 *
 * Held to real captured output in `scripts/electron/update-center.ts`.
 */
export function parseAdminOnly(stdout: string): boolean | null {
  const match = /^\s*AdminOnly\s+REG_DWORD\s+0x([0-9a-fA-F]+)\s*$/im.exec(stdout);
  if (match === null) return null;
  return Number.parseInt(match[1], 16) !== 0;
}

function query(args: readonly string[]): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(
      'reg', [...args],
      { timeout: QUERY_TIMEOUT_MS, windowsHide: true },
      (error, stdout) => resolve(error ? null : stdout),
    );
  });
}

/**
 * What the registry records, or null when nothing readable does.
 *
 * The 32-bit view of each key first, for the reason in the header. Four spawns
 * in the worst case, which is the case where Npcap is not installed and the
 * row has nothing to say anyway; one in the ordinary case.
 */
export async function readAdminOnly(): Promise<boolean | null> {
  if (process.platform !== 'win32') return null;
  for (const key of ADMIN_ONLY_KEYS) {
    for (const view of [['/reg:32'], []]) {
      const stdout = await query(['query', key, '/v', VALUE_NAME, ...view]);
      if (stdout === null) continue;
      const value = parseAdminOnly(stdout);
      if (value !== null) return value;
    }
  }
  return null;
}
