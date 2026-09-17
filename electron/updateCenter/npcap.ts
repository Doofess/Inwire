/**
 * Which Npcap is installed, if any.
 *
 * Modelled on `electron/agentService.ts` - same `reg query` reasoning, same
 * refusal to parse localised tool output, same separation of the parser from
 * the process spawn so a script can drive it. What differs is that Npcap does
 * not make this easy, and every one of the three ways it is hard produces a
 * confident wrong answer rather than an error.
 *
 * ## Trap 1: `wpcap.dll` does not carry Npcap's version
 *
 * Measured on a machine running Npcap 1.88:
 *
 * | File | ProductName | Version |
 * |---|---|---|
 * | `System32\Npcap\wpcap.dll` | **libpcap** | **1.10.6** |
 * | `System32\Npcap\Packet.dll` | Npcap | 1.88 |
 * | `System32\drivers\npcap.sys` | Npcap | 1.88 |
 *
 * `wpcap.dll` reports the **libpcap API version it implements**, not Npcap's.
 * Reading it and comparing against a feed advertising `1.88` says "update
 * available" forever - including immediately after a successful install, which
 * is the worst available failure for a row whose only job is to say whether
 * you are current. Nothing here reads `wpcap.dll`, and that is deliberate.
 *
 * ## Trap 2: Npcap registers in the 32-bit view only
 *
 * Its installer is 32-bit, so `NpcapInst` lands under `WOW6432Node`. A plain
 * `reg query` of the 64-bit view exits **1 with empty stdout** - which is
 * exactly the shape `agentService.ts`'s `provesAbsent` reads as *proof of
 * absence*. Reusing that helper naively reports "Npcap is not installed" on a
 * machine where it is installed and the driver is RUNNING. `/reg:32` is asked
 * first, and the 64-bit view is a fallback rather than the default.
 *
 * ## Trap 3: there is no version in `HKLM\SOFTWARE\Npcap`
 *
 * That key holds `AdminOnly`, `WinPcapCompatible` and the install path, and on
 * a 64-bit machine it does not exist at all - only `WOW6432Node\Npcap` does.
 * The installer's own `IsNpcapInstalled` gets away with three presence probes
 * because it only asks "any Npcap at all?". A version has to come from the
 * uninstall entry or from `Packet.dll`. (`AdminOnly` *is* in that key, and is
 * read by `npcapAdminOnly.ts` - a different question, with the same two traps.)
 *
 * So `installed` and `version` are **separate answers**: the driver can be
 * present with its version unreadable, and that is shown as "installed,
 * version unknown" rather than being rounded to either "absent" or a guess.
 */
import { execFile } from 'node:child_process';
import { existsSync } from 'node:fs';
import { readAdminOnly } from './npcapAdminOnly';

/** Npcap's own uninstall entry. The key name, not the display name. */
const UNINSTALL_KEY =
  'HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\NpcapInst';

/** Presence, for when the uninstall entry is gone but the driver is not. */
const PRESENCE_KEYS = ['HKLM\\SOFTWARE\\WOW6432Node\\Npcap', 'HKLM\\SOFTWARE\\Npcap'];

/** Same budget as the agent's service query. */
const QUERY_TIMEOUT_MS = 5000;

export interface NpcapFacts {
  installed: boolean;
  /** Null means "installed, and we could not read a version" - never a guess. */
  version: string | null;
  /**
   * `AdminOnly` as the registry records it, or null where nothing readable
   * does. A **third** separate answer, for the same reason `version` is a
   * second one: the driver can be installed with its access mode unreadable,
   * and rounding that to either verdict is what `npcapAdminOnly.ts` refuses.
   *
   * It is only half the answer. The device object's DACL is the other half and
   * outranks it; they are combined in `src/services/npcapAccess.ts`. ADR 0033.
   */
  adminOnly: boolean | null;
}

const NPCAP_ABSENT: NpcapFacts = { installed: false, version: null, adminOnly: null };

/**
 * Reads `DisplayVersion` out of `reg query` output.
 *
 * `REG_SZ` rather than `agentService.ts`'s `REG_DWORD`, and the value is a
 * string rather than hex - which is why that parser could not simply be
 * reused. The value name and the type are not localised; the run between them
 * is spaces on some builds and tabs on others.
 *
 * Held to real captured output in `scripts/electron/update-center.ts`.
 */
export function parseDisplayVersion(stdout: string): string | null {
  const match = /^\s*DisplayVersion\s+REG_SZ\s+(\S.*?)\s*$/im.exec(stdout);
  return match === null ? null : match[1];
}

/** The driver file, which is present whenever Npcap is, whatever the registry says. */
function driverPath(): string {
  const root = process.env.SystemRoot ?? 'C:\\Windows';
  return `${root}\\System32\\drivers\\npcap.sys`;
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
 * The version, from the uninstall entry.
 *
 * 32-bit view first - see trap 2. The 64-bit view is asked second rather than
 * not at all, because a future Npcap could register there and a detector that
 * only knows today's layout would report "not installed" the day it changed.
 */
async function versionFromRegistry(): Promise<string | null> {
  for (const view of [['/reg:32'], []]) {
    const stdout = await query(['query', UNINSTALL_KEY, '/v', 'DisplayVersion', ...view]);
    if (stdout === null) continue;
    const version = parseDisplayVersion(stdout);
    if (version !== null) return version;
  }
  return null;
}

/**
 * The version, from `Packet.dll`.
 *
 * A fallback for a machine whose uninstall entry was cleaned but whose driver
 * is intact, so it costs a PowerShell start only when the cheap path already
 * failed. `Packet.dll` and not `wpcap.dll`, for the reason in the header.
 *
 * The command line is a constant - the path is built here from `SystemRoot`
 * and interpolated into no shell, because `execFile` takes an argv array.
 */
async function versionFromDriverFile(): Promise<string | null> {
  const root = process.env.SystemRoot ?? 'C:\\Windows';
  const script =
    `(Get-Item -LiteralPath "${root}\\System32\\Npcap\\Packet.dll").VersionInfo.FileVersion`;
  return new Promise((resolve) => {
    execFile(
      'powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: QUERY_TIMEOUT_MS, windowsHide: true },
      (error, stdout) => {
        if (error) { resolve(null); return; }
        const trimmed = stdout.trim();
        resolve(/^\d+(\.\d+)*$/.test(trimmed) ? trimmed : null);
      },
    );
  });
}

async function anyPresenceKey(): Promise<boolean> {
  for (const key of PRESENCE_KEYS) {
    for (const view of [['/reg:32'], []]) {
      if (await query(['query', key, ...view]) !== null) return true;
    }
  }
  return false;
}

/**
 * Everything known about the installed driver.
 *
 * A version found anywhere proves installation, so the presence probes only
 * run when no version was readable. The reverse - probing first - would cost
 * four `reg` spawns on every check for an answer the version already gave.
 */
export async function readNpcap(): Promise<NpcapFacts> {
  if (process.platform !== 'win32') return NPCAP_ABSENT;

  const registryVersion = await versionFromRegistry();
  if (registryVersion !== null) {
    return { installed: true, version: registryVersion, adminOnly: await readAdminOnly() };
  }

  const driverPresent = existsSync(driverPath());
  const present = driverPresent || await anyPresenceKey();
  if (!present) return NPCAP_ABSENT;

  return {
    installed: true,
    version: await versionFromDriverFile(),
    adminOnly: await readAdminOnly(),
  };
}
