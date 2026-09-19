/**
 * Runs every assertion script in this directory.
 *
 *   npm run check
 *
 * The repo has two dozen assertion scripts and, until this existed, nothing
 * that ran them as a set - so each was only as useful as whoever remembered it.
 * Adding one more to an unrun pile is not coverage.
 *
 * Discovery is by directory walk rather than a hand-maintained list, because a
 * list is the thing that silently stops including the newest script. A file
 * counts as an assertion script if it calls `process.exit`, which is how every
 * one of them signals failure.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, '..');

/**
 * Scripts that are not assertions and cannot pass on an arbitrary machine.
 *
 * Both are legitimate tools; neither is a test. Keeping them out by name - with
 * the reason attached - is better than a heuristic that might one day exclude a
 * real test for looking unusual.
 */
const NOT_TESTS: Record<string, string> = {
  'gen-oui.ts': 'generator; downloads ~5MB from IEEE',
  'electron/disk-drive.ts': 'drives a 180,000-frame capture to reach the disk path; ~2 minutes, run by hand',
  'electron/update-center-drive.ts':
    'drives the Update Center against a loopback feed in the real app; needs dist/ and ~1 minute, run by hand',
  'electron/import-drive.ts': 'imports a 400,000-frame file to reach the disk path; ~1 minute, run by hand',
  'electron/gpu-restore-drive.ts':
    'loses and restores a real WebGL context in the running app; needs dist/ and a GPU, run by hand',
  'electron/serveStub.ts': 'tool; serves the stub agent until Ctrl+C, for driving the app by hand',
  'agent/pipe-interop.ts':
    "drives the Rust agent's named pipe with the app's own client; needs "
    + '`cargo run --example pipe_serve` running beside it, and Windows',
  'parity/parity-check.ts': 'needs the untracked fixture captures and tshark ground truth (test/fixtures/README.md)',
  'tcp/reassembly.ts': 'diagnostic; needs the fixtures, and reports rather than asserts (docs/decisions/0020)',
  'perf/clone-cost.ts': 'measurement; there is no right answer to hold it to (docs/decisions/0007)',
  'perf/throughput.ts': 'measurement; needs the untracked fixture captures (test/fixtures/README.md)',
  'perf/tree-cost.ts': 'measurement; needs the untracked fixture captures (test/fixtures/README.md)',
  'perf/buffer-cost.ts': 'measurement; needs the untracked fixture captures (test/fixtures/README.md)',
  'perf/fields-cost.ts': 'measurement; needs the fixtures and --expose-gc (test/fixtures/README.md)',
  'perf/tracker-cost.ts': 'measurement; needs --expose-gc, and there is no right answer to hold it to (docs/decisions/0014)',
  'perf/color-index-cost.ts': 'measurement; needs the fixtures and --expose-gc (docs/decisions/0015)',
  'perf/record-cost.ts': 'measurement; needs the fixtures and --expose-gc (docs/decisions/0016)',
  'perf/fields-split-cost.ts': 'measurement; needs the fixtures and --expose-gc (docs/decisions/0017)',
  'perf/store-boundary.ts': 'measurement; there is no right answer to hold it to (the ADR 0028 number)',
  'perf/wire-size.ts': 'measurement; there is no right answer to hold it to (docs/decisions/0005)',
  'perf/summary-codec.ts': 'measurement; needs the fixtures, and sizes a format rather than asserting one (the disk-backed buffer plan)',
};

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

const candidates = walk(here)
  // Posix separators so the printed names match how the repo talks about
  // them, on Windows as well as elsewhere.
  .map((f) => relative(here, f).split(sep).join('/'))
  .filter((f) => f !== 'check.ts')
  .filter((f) => !(f in NOT_TESTS))
  .filter((f) => readFileSync(join(here, f), 'utf8').includes('process.exit'))
  .sort();

const skipped = Object.entries(NOT_TESTS);

console.log(`Running ${candidates.length} assertion script(s)\n`);

const failed: string[] = [];
for (const script of candidates) {
  // `shell: true` because on Windows the npx entry point is a .cmd shim, which
  // CreateProcess cannot execute directly - without it every script "fails"
  // with no output at all, which looks like a broken test rather than a broken
  // runner.
  const result = spawnSync(`npx tsx ${join('scripts', script)}`, {
    cwd: repoRoot,
    encoding: 'utf8',
    shell: true,
  });
  const ok = result.error === undefined && result.status === 0;
  if (!ok) failed.push(script);
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${script}`);
  if (!ok) {
    // Only the failing script's output, and only the tail of it - the point is
    // to name what broke, not to reprint two dozen passing assertions.
    const output = result.error
      ? `could not run it: ${result.error.message}`
      : `${result.stdout ?? ''}${result.stderr ?? ''}`.trimEnd();
    for (const line of output.split('\n').slice(-25)) console.log(`      ${line}`);
  }
}

console.log();
for (const [script, why] of skipped) console.log(`SKIP  ${script}  (${why})`);

console.log();
if (failed.length > 0) {
  console.log(`${failed.length} script(s) FAILED: ${failed.join(', ')}`);
  process.exit(1);
}
console.log(`All ${candidates.length} assertion scripts passed.`);
