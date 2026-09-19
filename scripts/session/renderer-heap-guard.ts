/**
 * The renderer's memory ceiling, and the buffer that sizes itself under it.
 *
 *   npx tsx scripts/session/renderer-heap-guard.ts
 *
 * Two modules, one subject: the packet buffer was capped at 1 GB because
 * nothing stopped the renderer before V8 aborted, so raising the cap needed a
 * guard first. This holds both to the rules that make that safe.
 *
 * It mirrors `scripts/capture/heap-guard.ts`, which does the same for the
 * capture store - and the reason there are two is the finding that produced
 * this work: the store got a guard when it was seen to die at 4,060 MB, and
 * **the renderer, which holds the buffer, never got one at all**.
 *
 * The rule both share, and the one worth reading twice: an unknown limit is not
 * a licence and not an alarm. A guard that stopped captures on a machine it
 * could not measure would be worse than the absence it replaced.
 */
import {
  autoBufferBudget,
  BUDGET_FLOOR_BYTES,
  BUDGET_HEAP_SHARE,
  BUDGET_MEMORY_SHARE,
  DEFAULT_BUFFER_BUDGET_BYTES,
  currentBufferBudget,
  resolveBufferBudget,
} from '../../src/services/bufferBudget';
import {
  HEAP_USABLE_RATIO,
  HEAP_WARN_RATIO,
  judgeRendererHeap,
  readHeap,
} from '../../src/services/rendererHeapGuard';
import { normalizePerformance, PERFORMANCE_DEFAULTS } from '../../src/services/interfacePrefs';

const MB = 1024 * 1024;
const GB = 1024 * MB;

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = Object.is(actual, expected);
  if (!pass) failures += 1;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${String(expected)}`);
    console.log(`        actual   ${String(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

console.log('--- the guard says nothing it cannot support ---\n');

// V8's default limit on 64-bit, which is the number every case below is really
// about: it is what the store's guard measured and what the buffer's ceiling
// is derived from.
const V8_DEFAULT = 4192 * MB;
const wall = Math.floor(V8_DEFAULT * HEAP_USABLE_RATIO);

check('an idle heap is ok', judgeRendererHeap(200 * MB, V8_DEFAULT, false).level, 'ok');
check('past the warning line it warns',
  judgeRendererHeap(Math.ceil(wall * HEAP_WARN_RATIO) + MB, V8_DEFAULT, false).level, 'warn');
check('...but only once',
  judgeRendererHeap(Math.ceil(wall * HEAP_WARN_RATIO) + MB, V8_DEFAULT, true).level, 'ok');
check('at the wall it stops', judgeRendererHeap(wall, V8_DEFAULT, true).level, 'stop');
check('...and stopping outranks having already warned',
  judgeRendererHeap(wall + MB, V8_DEFAULT, false).level, 'stop');

// The rule with the worst failure mode if it is inverted. `null` here means the
// browser would not say how big the heap is - on a machine we cannot measure,
// stopping every capture would be strictly worse than the no-guard state this
// replaced, which is what makes this an assertion rather than a comment.
check('an unknown limit says nothing', judgeRendererHeap(3 * GB, null, false).level, 'ok');
check('a zero limit says nothing', judgeRendererHeap(3 * GB, 0, false).level, 'ok');
check('an unreadable usage says nothing', judgeRendererHeap(0, V8_DEFAULT, false).level, 'ok');

// The wall is below V8's own limit, because the last tenth is where the
// collector is the whole workload. Standing down AT the limit would be standing
// down after the process had already become unusable.
checkTrue('the wall leaves V8 room to unwind', wall < V8_DEFAULT);
checkTrue('...but is most of the heap', wall > V8_DEFAULT * 0.8);

// The message is the entire reason this exists rather than letting V8 abort, so
// it has to name the ceiling and what to do. An abort says none of this.
const stopMessage = judgeRendererHeap(wall, V8_DEFAULT, true);
checkTrue('the stop message says the capture is safe on disk',
  stopMessage.level === 'stop' && /on disk/.test(stopMessage.message));
checkTrue('...and names the setting that changes the outcome',
  stopMessage.level === 'stop' && /buffer/i.test(stopMessage.message));

// Off a browser there is no `performance.memory`, and reading it must not
// throw - this script is itself the proof, since it runs under plain tsx.
const reading = readHeap();
checkTrue('readHeap answers off a browser rather than throwing',
  reading.used === null || typeof reading.used === 'number');

console.log('\n--- the buffer sizes itself to the machine ---\n');

// 16 GB: an eighth is 2 GB, and half the heap is 2,096 MB, so memory binds.
check('16 GB of RAM gives 2 GB', autoBufferBudget(16 * GB, V8_DEFAULT), 2 * GB);
// 8 GB: an eighth is 1 GB, well under the heap share.
check('8 GB gives 1 GB', autoBufferBudget(8 * GB, V8_DEFAULT), 1 * GB);
// 64 GB: an eighth is 8 GB, so the HEAP is what binds - which is the whole
// answer to "why not as much RAM as the machine has".
check('64 GB is capped by the heap, not by RAM',
  autoBufferBudget(64 * GB, V8_DEFAULT), Math.floor(V8_DEFAULT * BUDGET_HEAP_SHARE));
checkTrue('...which is less than an eighth of that machine',
  autoBufferBudget(64 * GB, V8_DEFAULT) < 64 * GB * BUDGET_MEMORY_SHARE);
// 2 GB: an eighth is 256 MB... which is above the floor. Use a smaller machine
// to reach it.
check('a 512 MB machine still gets the floor',
  autoBufferBudget(512 * MB, V8_DEFAULT), BUDGET_FLOOR_BYTES);

// The `null` rule, which is the same one `provesAbsent` keeps: not knowing how
// much memory a machine has is not knowing it has none. Multiplying a zero by a
// fraction would give a buffer that trimmed every frame it took.
check('unknown RAM falls back rather than computing from zero',
  autoBufferBudget(null, V8_DEFAULT), DEFAULT_BUFFER_BUDGET_BYTES);
check('...and so does a zero', autoBufferBudget(0, V8_DEFAULT), DEFAULT_BUFFER_BUDGET_BYTES);
// An unknown heap limit leaves the memory share and the floor in charge, rather
// than collapsing the answer - the guard is the real backstop either way.
check('unknown heap leaves RAM in charge', autoBufferBudget(8 * GB, null), 1 * GB);

checkTrue('every answer is a whole number of megabytes',
  [16 * GB, 8 * GB, 64 * GB, 3 * GB, 12345 * MB]
    .every((ram) => autoBufferBudget(ram, V8_DEFAULT) % MB === 0));

console.log('\n--- and the setting survives storage ---\n');

check("'auto' is what the app ships with", PERFORMANCE_DEFAULTS.packetBufferBytes, 'auto');
check("'auto' resolves rather than being passed through",
  resolveBufferBudget('auto', 8 * GB, V8_DEFAULT), 1 * GB);
check('an explicit choice is used as written',
  resolveBufferBudget(256 * MB, 8 * GB, V8_DEFAULT), 256 * MB);

// The trap this had to avoid: `Segmented` is a Radix RadioGroup, and the
// handler used to do `Number(v)` unconditionally - which turns 'auto' into
// `NaN`, writes `NaN` into the stored preference, and renders a control with
// nothing checked. The normalizer is the second line of defence.
check("a stored 'auto' round-trips",
  normalizePerformance({ dashboardRefreshMs: 500, packetBufferBytes: 'auto' })?.packetBufferBytes,
  'auto');
check('a stored NaN does not',
  normalizePerformance({ dashboardRefreshMs: 500, packetBufferBytes: Number.NaN })?.packetBufferBytes,
  PERFORMANCE_DEFAULTS.packetBufferBytes);
check('an unoffered number falls back',
  normalizePerformance({ dashboardRefreshMs: 500, packetBufferBytes: 777 })?.packetBufferBytes,
  PERFORMANCE_DEFAULTS.packetBufferBytes);
// A frame COUNT from before this was a budget. Reading 50000 as 50 kB would
// give somebody a buffer of about seventy frames.
check('a pre-budget frame count falls back',
  normalizePerformance({ dashboardRefreshMs: 500, packetBufferBytes: 50000 })?.packetBufferBytes,
  PERFORMANCE_DEFAULTS.packetBufferBytes);

// Off a browser, with no bridge to read, the convenience form must still answer
// a usable number rather than throwing on `window`.
check('currentBufferBudget answers off a browser',
  currentBufferBudget('auto'), DEFAULT_BUFFER_BUDGET_BYTES);
check('...and honours an explicit choice there too',
  currentBufferBudget(1024 * MB), 1024 * MB);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All renderer heap-guard and buffer-sizing checks passed.');
process.exit(0);
