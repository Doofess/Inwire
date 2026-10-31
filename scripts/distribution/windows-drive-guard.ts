/**
 * The clean-machine drive's guards, run as part of `npm run check`.
 *
 *   npx tsx scripts/distribution/windows-drive-guard.ts
 *
 * `scripts/distribution/windows-drive.ps1` installs, uninstalls and edits the
 * machine PATH, so it must be impossible to run by accident on a development PC.
 * This checks the refusal paths only; nothing here ever reaches a scenario:
 *
 *   - the script parses under Windows PowerShell 5.1 with no errors;
 *   - no switch: exit 2, the output is only the refusal, no result file;
 *   - the switch without INWIRE_DISPOSABLE_MACHINE=1: exit 2, same;
 *   - -List: exit 0 and every scenario name, no guard needed (it acts on nothing).
 *
 * It never sets INWIRE_DISPOSABLE_MACHINE, and removes it from the child's
 * environment, so a developer who has it exported still cannot get past the
 * guard from here. Off Windows: SKIP.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

if (process.platform !== 'win32') {
  console.log('SKIP  windows-drive guards (not Windows)');
  process.exit(0);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const drive = path.join(root, 'scripts', 'distribution', 'windows-drive.ps1');
const SCENARIOS = [
  'fresh-install', 'uac-decline', 'launch', 'command', 'custom-path',
  'upgrade-unsaved', 'no-npcap', 'clean-trust', 'uninstall', 'reinstall',
];

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === '' ? '' : `\n${detail}`}`);
}

function ps(args: string[]) {
  const env = { ...process.env };
  delete env.INWIRE_DISPOSABLE_MACHINE;
  delete env.PSModulePath; // let 5.1 compute its own (scripts/sign/sign.ps1)
  return spawnSync('powershell.exe', ['-NoProfile', '-NonInteractive', ...args], {
    encoding: 'utf8', env, timeout: 60_000,
  });
}

if (!existsSync(drive)) {
  check('windows-drive.ps1 exists', false, drive);
  process.exit(1);
}

// Parse. The path goes in an environment variable, not into the command text.
{
  const r = spawnSync('powershell.exe', [
    '-NoProfile', '-NonInteractive', '-Command',
    "$e=$null;$t=$null;[void][System.Management.Automation.Language.Parser]::ParseFile($env:DRIVE_PATH,[ref]$t,[ref]$e);" +
      "if($e){$e|ForEach-Object{[Console]::Error.WriteLine($_.Message)}};Write-Output ('ERRORS=' + @($e).Count)",
  ], { encoding: 'utf8', env: { ...process.env, DRIVE_PATH: drive, PSModulePath: '' } });
  check('parses with 0 errors', /ERRORS=0\s*$/.test(r.stdout ?? ''), `${r.stdout}${r.stderr}`);
}

const scratch = mkdtempSync(path.join(os.tmpdir(), 'inwire-drive-guard-'));
try {
  const resultFile = path.join(scratch, 'result.jsonl');
  const base = ['-ExecutionPolicy', 'Bypass', '-File', drive, '-ResultFile', resultFile];

  const noSwitch = ps(base);
  const out1 = `${noSwitch.stdout}${noSwitch.stderr}`;
  check('no switch: exit 2', noSwitch.status === 2, `status ${noSwitch.status}\n${out1}`);
  check('no switch: refusal only', /REFUSED/.test(out1) && out1.split(/\r?\n/).filter((l) => l.trim() !== '').every((l) => l.startsWith('REFUSED')), out1);
  check('no switch: no result file', !existsSync(resultFile));

  const noEnv = ps([...base, '-IAmOnADisposableMachine']);
  const out2 = `${noEnv.stdout}${noEnv.stderr}`;
  check('switch without env var: exit 2', noEnv.status === 2, `status ${noEnv.status}\n${out2}`);
  check('switch without env var: refusal only', /INWIRE_DISPOSABLE_MACHINE/.test(out2) && out2.split(/\r?\n/).filter((l) => l.trim() !== '').every((l) => l.startsWith('REFUSED')), out2);
  check('switch without env var: no result file', !existsSync(resultFile));

  const list = ps([...base, '-List']);
  const out3 = list.stdout ?? '';
  check('-List: exit 0', list.status === 0, `status ${list.status}\n${out3}${list.stderr}`);
  check('-List: every scenario named', SCENARIOS.every((s) => out3.includes(s)),
    SCENARIOS.filter((s) => !out3.includes(s)).join(', '));
  check('-List: no result file', !existsSync(resultFile));
} finally {
  rmSync(scratch, { recursive: true, force: true });
}

if (failures > 0) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log('\nwindows-drive guards ok');
process.exit(0);
