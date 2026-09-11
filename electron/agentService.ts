/**
 * What the Windows service manager knows about the capture agent.
 *
 * The app can already see whether the pipe answers. What it cannot see from
 * the pipe alone is **why** it does not, and the four reasons want four
 * different sentences: the service was never installed, an administrator
 * disabled it, it is installed and stopped, or it is starting and dying in a
 * loop. Told apart they are actionable; run together they are "the agent is
 * not running", which is the exact wording CLAUDE.md already calls out as
 * indistinguishable from a refused handshake.
 *
 * ## Why the registry and not `sc query`
 *
 * `sc query` prints **localised** labels - `STATE`, `RUNNING`, and the error
 * text for a service that does not exist are all translated - so a parser
 * written against an English Windows quietly reports "not installed" on a
 * German one, which is the worst possible answer because it is confident and
 * wrong. `Get-Service` has the same problem one layer up and costs a
 * PowerShell start.
 *
 * A service's registry key does not move and its value names are not
 * translated. `reg query` on a single value prints `Start    REG_DWORD  0x2`
 * in every locale, and a missing key is a **non-zero exit code** rather than a
 * message anyone has to read.
 *
 * ## What this deliberately does not answer
 *
 * Whether the service is *running*. The registry does not say, and the app has
 * a better oracle than any API would give it: the pipe either accepts a
 * connection or it does not. Asking the SCM as well would introduce a second
 * source of truth that can disagree with the first - a service reported
 * RUNNING whose pipe refuses is a state the UI would have to describe, and it
 * exists only because we asked twice.
 */
import { execFile } from 'node:child_process';

/** Where the SCM keeps it. The service name, not the display name. */
const SERVICE_KEY = 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\InwireAgent';

/** Long enough for a loaded machine, short enough not to stall a UI update. */
const QUERY_TIMEOUT_MS = 5000;

/**
 * `Start`, as the SCM defines it. 0 and 1 are driver load states and cannot
 * occur for a user-mode service, so they read as `unknown` rather than being
 * given a name that would imply this code understood them.
 */
export type ServiceStartType = 'auto' | 'manual' | 'disabled' | 'unknown';

export interface AgentServiceFacts {
  /** False means the SCM has no such service - it was removed, or never installed. */
  installed: boolean;
  startType: ServiceStartType;
}

/** Nothing is known: the platform is not Windows, or the query failed. */
export const SERVICE_UNKNOWN: AgentServiceFacts = { installed: true, startType: 'unknown' };

/**
 * Reads `Start` out of `reg query` output.
 *
 * Exported for `scripts/electron/agent-service.ts`, which drives it over real
 * captured output rather than over a string this file also wrote.
 */
export function parseStartType(stdout: string): ServiceStartType {
  // `REG_DWORD` and the value name are not localised; the whitespace between
  // them is tabs on some builds and spaces on others.
  const match = /^\s*Start\s+REG_DWORD\s+0x([0-9a-f]+)\s*$/im.exec(stdout);
  if (!match) return 'unknown';
  switch (Number.parseInt(match[1], 16)) {
    case 2: return 'auto';
    case 3: return 'manual';
    case 4: return 'disabled';
    default: return 'unknown';
  }
}

/**
 * Whether a failed `reg query` PROVED the key is absent.
 *
 * The distinction this draws is the whole point of the module, so it is a
 * function rather than a condition inside a callback: telling somebody their
 * agent is not installed when it is sends them to reinstall over a working
 * install, and that is a worse outcome than saying nothing.
 *
 * Absence has to be proven, and what proves it is a **numeric exit code** with
 * no output. Measured against the real tool: a missing key gives
 * `error.code === 1` (a number) with empty stdout, and a key that exists gives
 * no error at all. Everything else - `ENOENT` because `reg` is not on PATH, a
 * timeout (`error.killed`), a denied read - carries a string code or a signal,
 * and every one of them means "we could not ask".
 *
 * The first version of this tested `error.code === undefined`, which is the
 * shape of SUCCESS, so a missing service would have read as unknown and a
 * failure to ask would have read as missing. Both backwards, and neither
 * visible without running it against a real registry.
 */
export function provesAbsent(error: unknown, stdout: string): boolean {
  if (!error || typeof error !== 'object') return false;
  const failure = error as NodeJS.ErrnoException & { killed?: boolean; signal?: string | null };
  if (failure.killed || failure.signal) return false;
  return typeof failure.code === 'number' && failure.code !== 0 && stdout.trim() === '';
}

/**
 * Asks the registry, and answers `unknown` rather than guessing.
 *
 * `installed: true` is the answer when the query failed for any reason other
 * than a proven absence - see `provesAbsent`.
 */
export function readAgentService(): Promise<AgentServiceFacts> {
  if (process.platform !== 'win32') return Promise.resolve(SERVICE_UNKNOWN);

  return new Promise((resolve) => {
    execFile(
      'reg', ['query', SERVICE_KEY, '/v', 'Start'],
      { timeout: QUERY_TIMEOUT_MS, windowsHide: true },
      (error, stdout) => {
        if (!error) {
          resolve({ installed: true, startType: parseStartType(stdout) });
          return;
        }
        resolve(provesAbsent(error, stdout)
          ? { installed: false, startType: 'unknown' }
          : SERVICE_UNKNOWN);
      },
    );
  });
}
