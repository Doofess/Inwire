/**
 * Builds the macOS/Linux agent tarball, and checks that it is complete.
 *
 *   npx tsx scripts/agent/package-unix.ts --build  build the tarball
 *   npx tsx scripts/agent/package-unix.ts          assert only, write nothing
 *
 * The Unix download used to be a shell script with a copy of `agent.py` pasted
 * inside it. The copy stopped being updated around 2.1 and went on being
 * downloaded: it spoke a protocol the app had stopped understanding, so the
 * app parsed zero packets and showed the "Update" pill for ever, and nothing
 * failed loudly enough for anyone to notice. Nothing here embeds a copy - the
 * tarball is built from the real sources every time.
 *
 * The check that matters is the last one: every module `agent.py` imports has
 * to be in the archive. That is the failure the old scripts had, expressed as
 * an assertion, and it runs in `npm run check` whether or not anyone is
 * packaging anything.
 */
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, copyFileSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const agentDir = join(root, 'local-agent');
const unixDir = join(agentDir, 'unix');
const downloads = join(root, 'public', 'downloads');

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

// --- what goes in ---------------------------------------------------------------

/** The agent's own modules, as opposed to its third-party dependencies. */
const LOCAL_MODULES = readdirSync(agentDir)
  .filter((f) => f.endsWith('.py') && !f.startsWith('test_') && !f.startsWith('verify_')
    // The Windows service host imports pywin32 and is imported by nothing at
    // runtime; shipping it to a Unix box would be dead weight that looks like
    // a dependency.
    && f !== 'service_windows.py')
  .sort();

const SUPPORT_FILES = ['install.sh', 'inwire-agent.service', 'com.inwire.agent.plist',
  'requirements-runtime.txt'];

// --- the completeness check the old scripts failed ---------------------------------

const agentSource = readFileSync(join(agentDir, 'agent.py'), 'utf8');
const imported = new Set<string>();
for (const match of agentSource.matchAll(/^import (\w+)$/gm)) imported.add(match[1]);
for (const match of agentSource.matchAll(/^from (\w+) import/gm)) imported.add(match[1]);

const localImports = [...imported]
  .filter((name) => existsSync(join(agentDir, `${name}.py`)))
  .sort();

console.log(`agent.py imports ${localImports.length} local modules: ${localImports.join(', ')}`);
const packagedModules = LOCAL_MODULES.map((f) => f.replace(/\.py$/, ''));
check('every module agent.py imports is packaged',
  localImports.filter((m) => !packagedModules.includes(m)), []);

// Windows-only modules would fail to import on a Unix box, so they must not be
// in the list the installer copies... except that they are never imported
// there either. service_windows is imported by nothing at runtime.
checkTrue('agent.py does not import the Windows service host',
  !localImports.includes('service_windows'));

for (const file of SUPPORT_FILES) {
  checkTrue(`${file} exists`, existsSync(join(unixDir, file)));
}

const installer = readFileSync(join(unixDir, 'install.sh'), 'utf8');
checkTrue('the installer creates a root-owned virtualenv rather than pip --user',
  installer.includes('venv') && !installer.includes('pip install --user'));
checkTrue('...and offers an uninstall verb', installer.includes('uninstall_agent'));
checkTrue('...and writes a pairing token', installer.includes('token_hex'));
checkTrue('...and does not embed a copy of the agent',
  !installer.includes('AGENT_VERSION') && !installer.includes('async def register'));

const version = /AGENT_VERSION = "([\d.]+)"/.exec(agentSource)?.[1];
checkTrue('the agent declares a version', typeof version === 'string');

// --- is the SHIPPED archive current? ---------------------------------------------
//
// Everything above checks the file list the builder WOULD use. That is not the
// same question as whether the tarball people actually download is current, and
// the difference is precisely the bug this script was written after: a copy
// that stops being rebuilt goes on being downloaded, speaking a protocol from
// before the one the app expects.
//
const building = process.argv.includes('--build');

// Caught in practice - 3.4.0 added a module and every check above passed while
// `public/downloads/` still held the 3.3.0 archive. The version is in the
// archive's top-level directory name, so reading it needs no extraction.
//
// Skipped under --build, which is the run that FIXES a stale archive: asserting
// first meant the check blocked the rebuild it was asking for, and left the
// only way out as deleting the file by hand.
{
  const archive = join(downloads, 'inwire-agent-unix.tar.gz');
  if (building) {
    console.log('SKIP  the published tarball is about to be rebuilt (--build)');
  } else if (existsSync(archive)) {
    let shipped: string | null = null;
    try {
      // A bare filename from the directory itself, for the same reason the
      // build below does it: GNU tar reads a leading `C:` as a remote host.
      const listing = execFileSync('tar', ['-tzf', 'inwire-agent-unix.tar.gz'],
        { encoding: 'utf8', cwd: downloads });
      shipped = /inwire-agent-([\d.]+)\//.exec(listing)?.[1] ?? null;
    } catch {
      // No tar on this machine is not a failing build - it is a check that
      // could not run, and saying so beats failing for the wrong reason.
      shipped = null;
    }
    if (shipped !== null) {
      check(`the published tarball is built from this version (${shipped})`, shipped, version);
    } else {
      console.log('SKIP  could not read the published tarball to compare its version');
    }
  } else {
    // Untracked by design; a clean checkout simply has not built one yet.
    console.log('SKIP  no published tarball yet (run with --build)');
  }
}

// --- build ----------------------------------------------------------------------

// Assertions run every time; the archive is only written when asked, so this
// can sit in `npm run check` without the suite having a side effect.
if (building && failures === 0) {
  const stage = join(root, 'node_modules', '.cache', `inwire-agent-${version}`);
  rmSync(stage, { recursive: true, force: true });
  mkdirSync(stage, { recursive: true });
  for (const file of LOCAL_MODULES) copyFileSync(join(agentDir, file), join(stage, file));
  for (const file of SUPPORT_FILES) copyFileSync(join(unixDir, file), join(stage, file));

  mkdirSync(downloads, { recursive: true });
  const archive = join(downloads, 'inwire-agent-unix.tar.gz');
  // Run from the staging directory's parent with relative paths. GNU tar reads
  // a leading `C:` as a remote host, so an absolute Windows path fails with a
  // message about a host name - passing it relative sidesteps the question on
  // every platform rather than adding a Windows-only flag.
  execFileSync('tar', ['-czf', relative(dirname(stage), archive).split(sep).join('/'),
    `inwire-agent-${version}`], { stdio: 'inherit', cwd: dirname(stage) });
  console.log(`\nwrote ${archive}`);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All Unix packaging checks passed.');
process.exit(0);
