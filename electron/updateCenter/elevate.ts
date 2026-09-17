/**
 * Running an installer as an administrator, from an app that is not one.
 *
 * ## Why main, and why nothing else could do it
 *
 * The **renderer** has no rights and no `child_process`, and it must never get
 * either - it is the process that parses bytes an attacker put on the wire.
 *
 * The **agent** is already LocalSystem and could spawn anything, which is
 * exactly why it must not: it runs in **session 0**, which has no visible
 * desktop. An installer wizard launched from there draws onto a desktop nobody
 * is looking at and then blocks forever waiting for a click that cannot
 * happen. Silent-installing instead is not an option either - that is the
 * Npcap OEM feature this whole feature exists to stop using.
 *
 * So it is **main**, through `Start-Process -Verb RunAs`, which is the same
 * route `electron/agentPipe.ts` already takes to start the service.
 *
 * ## The command line is a constant, and the path is not on it
 *
 * `agentPipe.ts` states the invariant this file has to keep: *"The arguments
 * are constants. Nothing the renderer sends reaches this command line, because
 * a privileged command built from a message is a privileged command an
 * injected script can write."*
 *
 * An updater has to name a downloaded file, which looks like it must break
 * that. It does not. The script is fixed, encoded once as base64 UTF-16LE and
 * passed to `-EncodedCommand`, so `ELEVATE_ARGV` is **the same array on every
 * call**. The file path and its arguments travel in the child process's
 * environment and are read back by PowerShell from `$env:`. Nothing
 * interpolates, nothing is quoted, and a path containing a space, a quote or a
 * semicolon cannot become a second argument, because it never passes through
 * an argument parser at all.
 *
 * Verified before it was written down: an encoded command of this shape
 * returned `INWIRE_RESULT=ok:3010` for a process that exited 3010, and ran
 * `C:\Program Files\Npcap\NPFInstall.exe` - a path with a space - correctly.
 *
 * ## The result comes back as a marker, not as a message
 *
 * PowerShell's own errors are localised, and `Start-Process -Verb RunAs`
 * reports a declined UAC prompt by **throwing** rather than by returning a
 * code. Both are read from one machine-readable line on stdout, for the same
 * reason `electron/agentService.ts` prefers `reg` over `sc query`: a parser
 * written against English quietly gives a confident wrong answer everywhere
 * else.
 */
import type { ComponentKind } from './components';

/**
 * Set on the child, read by the script. Two names, because the arguments must
 * not be concatenated onto the path - that would put quoting back.
 */
const INSTALLER_PATH_ENV = 'INWIRE_INSTALLER';
const INSTALLER_ARGS_ENV = 'INWIRE_ARGS';

/**
 * The script, as lines. An array rather than one template literal so that no
 * `${` can appear by accident, and so the byte-for-byte assertion in
 * `scripts/electron/update-center.ts` reads the way the script does.
 *
 * `Wait` and `PassThru` together are what make `$p.ExitCode` exist. Without
 * both, the exit code is lost and every install reports success.
 *
 * ## The arguments are splatted, and omitted entirely when there are none
 *
 * `Start-Process -ArgumentList ''` does not run the program with no arguments.
 * It throws: *"Cannot validate argument on parameter 'ArgumentList'. The
 * argument is null or empty."* And the component that takes no arguments is
 * **Npcap** - deliberately, because the alternative is `/S` - so the naive
 * version failed on the one install this feature exists to perform, one second
 * after the click, with "the installer could not be started" and no prompt.
 *
 * Found by firing it at a real machine. Nothing in the pure suite could have
 * caught it: the argument list was correct, the marker parsing was correct, and
 * PowerShell's own parser accepts the line - it is the cmdlet's parameter
 * validation that rejects it, at run time, only when the variable is empty.
 *
 * A hashtable keeps the fix inside the constant. The command line is still
 * fixed and the path still travels in the environment.
 */
export const ELEVATE_SCRIPT_LINES: readonly string[] = [
  '$ErrorActionPreference = "Stop"',
  'try {',
  '  $go = @{ FilePath = $env:INWIRE_INSTALLER; Verb = "RunAs"; Wait = $true; PassThru = $true }',
  '  if ($env:INWIRE_ARGS) { $go["ArgumentList"] = $env:INWIRE_ARGS }',
  '  $p = Start-Process @go',
  '  Write-Output ("INWIRE_RESULT=ok:" + $p.ExitCode)',
  '} catch [System.ComponentModel.Win32Exception] {',
  '  Write-Output ("INWIRE_RESULT=win32:" + $_.Exception.NativeErrorCode)',
  '} catch {',
  '  Write-Output "INWIRE_RESULT=error"',
  '}',
];

/**
 * The same thing, without waiting - and this exists because waiting for our
 * own installer **deadlocks**.
 *
 * `installer/setup.iss` sets `CloseApplications=yes`, so the Inno installer
 * uses the Restart Manager to ask Inwire's window to close before it replaces
 * the payload. If we are blocked in `-Wait` at the time, the installer is
 * waiting for us to exit and we are waiting for the installer to exit, and
 * neither ever does. Nothing about that is visible: the app simply stops.
 *
 * So our own installer is **launched and not awaited**, and the app quits
 * immediately afterwards. The trade is that its exit code is unobservable -
 * the installer outlives the process that would have read it - and that is
 * the correct trade, because the alternative is a hang. What comes back here
 * is only whether the elevated process **started**, which is still enough to
 * tell a declined UAC prompt from a launch.
 *
 * Npcap does not close us and is awaited normally.
 */
export const LAUNCH_SCRIPT_LINES: readonly string[] = [
  '$ErrorActionPreference = "Stop"',
  'try {',
  '  $go = @{ FilePath = $env:INWIRE_INSTALLER; Verb = "RunAs" }',
  '  if ($env:INWIRE_ARGS) { $go["ArgumentList"] = $env:INWIRE_ARGS }',
  '  Start-Process @go',
  '  Write-Output "INWIRE_RESULT=ok:0"',
  '} catch [System.ComponentModel.Win32Exception] {',
  '  Write-Output ("INWIRE_RESULT=win32:" + $_.Exception.NativeErrorCode)',
  '} catch {',
  '  Write-Output "INWIRE_RESULT=error"',
  '}',
];

export const ELEVATE_SCRIPT = ELEVATE_SCRIPT_LINES.join('\n');
export const LAUNCH_SCRIPT = LAUNCH_SCRIPT_LINES.join('\n');

function encodedCommand(script: string): readonly string[] {
  // `-NonInteractive` matters: this PowerShell must never prompt. The only
  // prompt in the flow is the UAC one, which Windows raises itself.
  return [
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    Buffer.from(script, 'utf16le').toString('base64'),
  ];
}

/** The whole command line, and it never varies. */
export const ELEVATE_ARGV: readonly string[] = encodedCommand(ELEVATE_SCRIPT);

/** Likewise, for the installer that will close us. */
export const LAUNCH_ARGV: readonly string[] = encodedCommand(LAUNCH_SCRIPT);

/**
 * Whether this kind of installer will close Inwire, and therefore must not be
 * awaited. One predicate rather than a check at each call site, so the
 * deadlock above cannot be reintroduced by adding a third caller.
 */
export function awaitsInstaller(kind: ComponentKind): boolean {
  return kind !== 'inwire-installer';
}

/**
 * What each kind of installer is run with.
 *
 * **Npcap gets no flags at all.** Its wizard opens, shows its own licence, and
 * is answered by the person sitting in front of it. `/S` is the OEM silent
 * switch and does not appear anywhere in this codebase any more.
 *
 * Ours gets `/VERYSILENT /NORESTART`: silent because the user already agreed
 * to it in our own UI, and `/NORESTART` because deciding to reboot somebody's
 * machine mid-capture is not an installer's call. `installer/setup.iss` marks
 * the relaunch `skipifsilent`, so it will not restart us either - that is the
 * caller's job.
 */
export const INSTALLER_ARGS: Record<ComponentKind, string> = {
  'inwire-installer': '/VERYSILENT /NORESTART',
  'vendor-installer': '',
  database: '',
};

export function elevationEnv(installerPath: string, args: string): Record<string, string> {
  return { [INSTALLER_PATH_ENV]: installerPath, [INSTALLER_ARGS_ENV]: args };
}

export type ElevationOutcome =
  | { kind: 'ok' }
  | { kind: 'reboot-required' }
  /** The user answered "No", or closed the wizard. A normal outcome, never an error. */
  | { kind: 'cancelled' }
  | { kind: 'failed'; code: number | null; reason: string };

/** Codes that mean the same thing whoever produced them. */
const REBOOT_CODES = new Set([
  3010, // ERROR_SUCCESS_REBOOT_REQUIRED
  1641, // ERROR_SUCCESS_REBOOT_INITIATED
]);
const CANCEL_CODES = new Set([
  1223, // ERROR_CANCELLED - the UAC prompt was declined
  1602, // ERROR_INSTALL_USEREXIT
]);

/**
 * Inno's documented codes for "the user backed out", which we can read because
 * we own that installer.
 *
 * Npcap's non-zero codes are deliberately NOT guessed at. Its installer is
 * ours to run and not ours to interpret, so anything outside the universal set
 * above is reported with its number rather than translated into a story. A
 * wrong guess would say "cancelled" over a real failure, and a number is
 * something a person can search for.
 */
const INNO_CANCEL_CODES = new Set([2, 5]);

const MARKER = 'INWIRE_RESULT=';

/**
 * Reads the marker out of the script's stdout.
 *
 * Scans lines rather than matching the whole output, because PowerShell writes
 * a CLIXML progress preamble to stderr and may put a blank line on stdout
 * ahead of the result. No marker at all is a **failure and not a success**: a
 * script that produced no verdict did not observe one.
 */
export function readElevationResult(stdout: string, kind: ComponentKind): ElevationOutcome {
  const line = stdout
    .split(/\r?\n/)
    .map((each) => each.trim())
    .find((each) => each.startsWith(MARKER));
  if (line === undefined) {
    return { kind: 'failed', code: null, reason: 'the installer produced no result' };
  }
  const value = line.slice(MARKER.length);

  if (value === 'error') {
    return { kind: 'failed', code: null, reason: 'the installer could not be started' };
  }

  const separator = value.indexOf(':');
  const tag = separator === -1 ? value : value.slice(0, separator);
  const code = Number.parseInt(separator === -1 ? '' : value.slice(separator + 1), 10);
  if (!Number.isInteger(code) || (tag !== 'ok' && tag !== 'win32')) {
    return { kind: 'failed', code: null, reason: 'the installer produced no result' };
  }

  if (tag === 'win32') {
    // The throw path. A declined UAC prompt lands here, and it is the single
    // most likely outcome of the whole feature, so it must not be an error.
    return CANCEL_CODES.has(code)
      ? { kind: 'cancelled' }
      : { kind: 'failed', code, reason: `Windows refused to start the installer (${code})` };
  }

  if (code === 0) return { kind: 'ok' };
  if (REBOOT_CODES.has(code)) return { kind: 'reboot-required' };
  if (CANCEL_CODES.has(code)) return { kind: 'cancelled' };
  if (kind === 'inwire-installer' && INNO_CANCEL_CODES.has(code)) return { kind: 'cancelled' };
  return { kind: 'failed', code, reason: `the installer exited with code ${code}` };
}
