/**
 * The PowerShell bootstrap's own tests, run as part of `npm run check`.
 *
 *   npx tsx scripts/distribution/powershell-tests.ts
 *
 * `scripts/distribution/bootstrap-tests.ps1` holds the assertions: the state
 * machine against a recording fake platform, the downloader against a fake
 * transport, the signature pin check against an in-memory certificate, and the
 * bundled script's build. They have to run under BOTH editions the bootstrap
 * supports, Windows PowerShell 5.1 (every Windows PC has it, and it is the one
 * the Bash bridge runs) and PowerShell 7 (where one is installed), because the
 * two differ in exactly the places this code leans on: JSON number types,
 * array unrolling out of `ConvertFrom-Json`, and the .NET runtime underneath.
 *
 * Off Windows there is nothing to run: CI on ubuntu prints a SKIP and passes.
 * That is not evidence the bootstrap works, only that this check has no
 * PowerShell 5.1 to ask.
 *
 * `-ExecutionPolicy Bypass` below is this runner's process-scope flag, so a
 * Restricted developer machine can run the test file. The bootstrap never sets
 * or documents an execution policy.
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const testFile = path.join(root, 'scripts', 'distribution', 'bootstrap-tests.ps1');

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === '' ? '' : `\n${detail}`}`);
}

function runUnder(label: string, exe: string): void {
  // A PSModulePath inherited from the other edition hides this edition's own
  // modules (scripts/sign/sign.ps1 records the trap); let each compute its own.
  const env = { ...process.env };
  delete env.PSModulePath;
  const r = spawnSync(exe, ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', testFile], {
    cwd: root,
    env,
    encoding: 'utf8',
    timeout: 10 * 60 * 1000,
    maxBuffer: 16 * 1024 * 1024,
  });
  const out = `${r.stdout ?? ''}${r.stderr ?? ''}`;
  const summary = /(\d+) passed, (\d+) failed(?:, (\d+) skipped)?/.exec(out);
  const ok = r.status === 0 && summary !== null && summary[2] === '0';
  const lines = out.split(/\r?\n/);
  const detail = ok
    ? ''
    : [...lines.filter((l) => l.startsWith('FAIL')), ...lines.slice(-6)].slice(0, 40).join('\n');
  check(
    `${label}: bootstrap-tests.ps1${summary ? ` (${summary[1]} passed, ${summary[2]} failed${summary[3] ? `, ${summary[3]} skipped` : ''})` : ''}`,
    ok,
    r.error ? String(r.error.message) : detail,
  );
}

function main(): void {
  if (process.platform !== 'win32') {
    console.log('SKIP  PowerShell bootstrap tests need Windows (the bootstrap installs a Windows program); nothing was run');
    process.exit(0);
  }

  const windowsPowerShell = path.join(
    process.env.SystemRoot ?? 'C:\\Windows', 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe',
  );
  if (existsSync(windowsPowerShell)) {
    runUnder('Windows PowerShell 5.1', windowsPowerShell);
  } else {
    check('Windows PowerShell 5.1 is present', false, `not found at ${windowsPowerShell}`);
  }

  const probe = spawnSync('pwsh', ['-NoProfile', '-Command', 'exit 0'], { encoding: 'utf8', timeout: 60_000 });
  if (probe.error || probe.status !== 0) {
    console.log('SKIP  PowerShell 7: pwsh is not installed here; the 5.1 run above is the one the Bash bridge uses');
  } else {
    runUnder('PowerShell 7', 'pwsh');
  }

  console.log(failures === 0 ? '\nAll PowerShell bootstrap checks passed.' : `\n${failures} PowerShell bootstrap check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

main();
