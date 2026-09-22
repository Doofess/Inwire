/**
 * A CPU profile of a real dissection run, by function, descending.
 *
 *   npx tsx scripts/perf/profile.ts [--fixture inwire|bulk] [--top 30] [--trees]
 *
 * **This is the instrument ADR 0011's central finding came from, and it was
 * never committed.** That ADR put one function at *38% of the entire profile*
 * and more than half of all dissection time:
 *
 *     self%    ms     function
 *     38.34   1269     formatArrivalTime   services/pcapParser.ts
 *
 * `formatArrivalTime` built a `new Intl.DateTimeFormat(...)` on every call, at
 * ~49 us each, twice per frame - 25,716 of them constructed and thrown away on
 * a 12,858 frame capture. Fixing it took the pipeline from ~5,900 frames/s to
 * ~19,000. The profile was run by hand with `node --cpu-prof`, written up, and
 * then lost: nothing in `scripts/` could reproduce it, so the next person to
 * wonder where the time goes had to either rebuild this or guess.
 *
 * Guessing is the documented failure mode. ADR 0011's own plan *assumed* the
 * discarded protocol tree was the cost and budgeted a large refactor for it;
 * measured, the tree was **3.3%**. The assumption was wrong by an order of
 * magnitude and wrong about which function mattered.
 *
 * So: no dissector change on performance grounds until this has named the
 * function it is meant to make cheaper.
 *
 * **How it works.** `--cpu-prof` is a Node flag, not something a running
 * process can switch on, so this re-executes itself as a child with the flag
 * set and `INWIRE_PROFILE_CHILD` in the environment. The child dissects and
 * exits; V8 writes the `.cpuprofile` on exit; the parent reads it back and
 * aggregates. That indirection is why the timing you see is the child's.
 *
 * **Reading it.** `self` is time in the function's own frames, excluding
 * callees - which is what you want for "where did the milliseconds go".
 * `total` includes callees and is how you find an expensive *caller* whose own
 * body is cheap. A hot function with near-zero self time is dispatch, not work.
 *
 * Two traps, both hit while writing this:
 *
 * - **`tsx` is in the stack too.** Compiling the TypeScript is real time in the
 *   profile and has nothing to do with dissection. Frames from `node_modules`
 *   and from node's internals are folded into one `(tooling)` row rather than
 *   dropped, so the share they take is visible instead of silently inflating
 *   everybody else's percentage.
 * - **`__name` is a `tsx` artifact and is not in the shipped app.** esbuild's
 *   `keepNames` transform wraps every function definition in `__name(fn,
 *   "...")` so stack traces survive minification. Where a module creates
 *   closures per call - `quic.ts` does, once per packet - that helper is
 *   invoked per call too, and it charged **152 ms, 10% of a whole profile, to
 *   `quic.ts`** the first time this script was run. It is measured to be
 *   absent from production: `grep -c __name dist/assets/pipeline.worker-*.js`
 *   answers **0**, and no config in this repo sets `keepNames`. So it is
 *   folded into `(tooling)` by name. Deleting that fold reinstates a ghost
 *   that reads exactly like a real hot spot in the file this plan was about to
 *   optimise - which is how it nearly became work.
 * - **A profile of a run that includes file I/O is mostly file I/O.** The
 *   fixture is read and the `File` built *before* the timer region, and only
 *   the dissection is measured, so `readFileSync` does not crowd the table.
 *
 * Measurement, not an assertion - there is no right answer to hold a profile
 * to. `scripts/check.ts` lists it as skipped.
 */
import { existsSync, readFileSync, readdirSync, rmSync, mkdtempSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const FIXTURES: Record<string, string> = {
  inwire: 'test/fixtures/inwire_capture_1788478187989.pcap',
  bulk: 'test/fixtures/bulk_capture_1788426090876.pcap',
};

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const fixtureName = arg('fixture', 'inwire');
const FIXTURE = FIXTURES[fixtureName];
const TOP = Number(arg('top', '30'));
const KEEP_TREES = process.argv.includes('--trees');

// --- the child: dissect, and let V8 write the profile on exit ----------------

if (process.env.INWIRE_PROFILE_CHILD === '1') {
  const { PcapService } = await import('../../src/services/pcapParser');
  const buf = readFileSync(FIXTURE);
  const file = new File([new Uint8Array(buf)], 'fixture.pcap');
  const started = performance.now();
  const parsed = await PcapService.parseCaptureFile(file, 1_000_000, KEEP_TREES);
  const ms = performance.now() - started;
  // stdout is the parent's channel for the two numbers the profile cannot give
  // it: how many frames were dissected, and how long the run actually took.
  console.log(`__INWIRE__ ${parsed.packets.length} ${ms.toFixed(1)}`);
  process.exit(0);
}

// --- the parent --------------------------------------------------------------

if (FIXTURE === undefined) {
  console.log(`unknown fixture '${fixtureName}'; try ${Object.keys(FIXTURES).join(' or ')}.`);
  process.exit(2);
}
if (!existsSync(FIXTURE)) {
  console.log('SKIP  fixture missing: ' + FIXTURE + ' (see test/fixtures/README.md)');
  process.exit(0);
}

const outDir = mkdtempSync(join(tmpdir(), 'inwire-prof-'));
console.log(`Profiling ${fixtureName} (${KEEP_TREES ? 'trees kept' : 'trees discarded, as the Worker does'})...\n`);

const child = spawnSync(
  process.execPath,
  ['--cpu-prof', '--cpu-prof-dir', outDir, '--import', 'tsx', ...process.argv.slice(1)],
  { env: { ...process.env, INWIRE_PROFILE_CHILD: '1' }, encoding: 'utf8' },
);

if (child.status !== 0) {
  console.log('the profiled child failed:');
  console.log(child.stdout ?? '');
  console.log(child.stderr ?? '');
  rmSync(outDir, { recursive: true, force: true });
  process.exit(1);
}

const marker = /__INWIRE__ (\d+) ([\d.]+)/.exec(child.stdout ?? '');
const frames = marker ? Number(marker[1]) : 0;
const wallMs = marker ? Number(marker[2]) : 0;

const profiles = readdirSync(outDir).filter((f) => f.endsWith('.cpuprofile'));
if (profiles.length === 0) {
  console.log('no .cpuprofile was written - did the child exit cleanly?');
  rmSync(outDir, { recursive: true, force: true });
  process.exit(1);
}

interface CallFrame { functionName: string; url: string; lineNumber: number }
interface ProfileNode { id: number; callFrame: CallFrame; children?: number[]; hitCount?: number }
interface CpuProfile { nodes: ProfileNode[]; samples: number[]; timeDeltas: number[]; startTime: number; endTime: number }

const profile = JSON.parse(readFileSync(join(outDir, profiles[0]), 'utf8')) as CpuProfile;
rmSync(outDir, { recursive: true, force: true });

// --- aggregate ----------------------------------------------------------------

const byId = new Map<number, ProfileNode>();
for (const node of profile.nodes) byId.set(node.id, node);

const parentOf = new Map<number, number>();
for (const node of profile.nodes) {
  for (const childId of node.children ?? []) parentOf.set(childId, node.id);
}

/**
 * Anything that is not this repository's own source is one row.
 *
 * Folded rather than dropped: `tsx` compiling TypeScript and node's own
 * internals are real time in this process, and hiding them would inflate every
 * remaining percentage by an amount nobody could see.
 */
const TOOLING = '(tooling: tsx, node internals, GC, __name)';

function label(frame: CallFrame): string {
  const url = frame.url ?? '';
  const ours = url.includes('/src/') || url.includes('\\src\\');
  if (!ours) return TOOLING;
  // See the header: esbuild's keepNames helper, verified absent from the
  // production bundle, and it charged 152 ms to quic.ts on the first run.
  if (frame.functionName === '__name') return TOOLING;
  const short = url.replace(/^.*[/\\]src[/\\]/, 'src/').replace(/\\/g, '/');
  const name = frame.functionName || '(anonymous)';
  return `${name}  ${short}:${frame.lineNumber + 1}`;
}

// Self time: sum the deltas of samples that landed IN this node.
const selfUs = new Map<string, number>();
const sampleCount = new Map<string, number>();
for (let i = 0; i < profile.samples.length; i++) {
  const node = byId.get(profile.samples[i]);
  if (node === undefined) continue;
  const key = label(node.callFrame);
  selfUs.set(key, (selfUs.get(key) ?? 0) + (profile.timeDeltas[i] ?? 0));
  sampleCount.set(key, (sampleCount.get(key) ?? 0) + 1);
}

// Total time: a sample counts toward every frame on its stack, each frame once.
const totalUs = new Map<string, number>();
for (let i = 0; i < profile.samples.length; i++) {
  const delta = profile.timeDeltas[i] ?? 0;
  const seen = new Set<string>();
  let id: number | undefined = profile.samples[i];
  while (id !== undefined) {
    const node = byId.get(id);
    if (node === undefined) break;
    const key = label(node.callFrame);
    if (!seen.has(key)) {
      seen.add(key);
      totalUs.set(key, (totalUs.get(key) ?? 0) + delta);
    }
    id = parentOf.get(id);
  }
}

const grandTotal = [...selfUs.values()].reduce((a, b) => a + b, 0);

console.log(`${frames.toLocaleString()} frames dissected in ${wallMs.toFixed(0)} ms`
  + (frames ? ` (${(wallMs * 1000 / frames).toFixed(1)} us/frame)` : ''));
console.log(`profile covers ${(grandTotal / 1000).toFixed(0)} ms across `
  + `${profile.samples.length.toLocaleString()} samples\n`);

const rows = [...selfUs.entries()]
  .sort((a, b) => b[1] - a[1])
  .slice(0, TOP);

console.log(`${'self%'.padStart(6)} ${'self ms'.padStart(8)} ${'total ms'.padStart(9)}  function`);
console.log('-'.repeat(96));
for (const [key, us] of rows) {
  const pct = (us / grandTotal) * 100;
  const total = (totalUs.get(key) ?? 0) / 1000;
  console.log(`${pct.toFixed(2).padStart(6)} ${(us / 1000).toFixed(0).padStart(8)} `
    + `${total.toFixed(0).padStart(9)}  ${key}`);
}

const ourShare = [...selfUs.entries()]
  .filter(([k]) => !k.startsWith('(tooling'))
  .reduce((sum, [, us]) => sum + us, 0);
console.log('-'.repeat(96));
console.log(`${((ourShare / grandTotal) * 100).toFixed(1)}% of the profile is this repository's own code;`
  + ` the rest is tsx, node and GC.`);
console.log('\nself = the function\'s own frames. total = including callees.');
console.log('A hot row with near-zero self time is dispatch, not work.');
