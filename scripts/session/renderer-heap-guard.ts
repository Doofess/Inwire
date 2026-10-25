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
  HEAP_SAMPLE_MS,
  HEAP_UNCOLLECTED_SAMPLES,
  HEAP_USABLE_RATIO,
  HEAP_WARN_RATIO,
  HeapJudge,
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

console.log('\n--- it judges what a collection leaves, not the garbage before one ---\n');

// `usedJSHeapSize` counts garbage until a full collection runs, and V8 lets the
// heap grow to several times its live size before one: at 60,000 frames a
// second a live set of 1.1-1.9 GB read as a sawtooth up to 4.1 GB. These are the
// readings the ADR 0053 gate drives recorded (issue #15), every 2 s. A guard on
// one sample stopped those captures; nothing in them was near the wall.
function replay(samples: readonly number[], limit: number | null = V8_DEFAULT): string[] {
  const judge = new HeapJudge();
  return samples.map((used) => judge.judge(used * MB, limit).level);
}
const firstStop = (levels: string[]) => levels.indexOf('stop');

const RUN_1 = [1147, 1602, 2034, 2431, 1439, 1863, 2264, 2689, 3086, 1760, 2210, 2604, 3972, 1202, 1208, 1214];
const RUN_2 = [1814, 2217, 1398, 1813, 2271, 2666, 1518, 1996, 2415, 2841, 3236, 1805, 3277, 3839, 4128, 4109];
const RUN_3 = [2050, 2551, 1470, 2027, 2521, 3142, 1891, 2465, 3002, 3561, 1863];
check('run 1 of the 60k gate never stops: one sample at 3,972 MB, then a collection to 1,202',
  firstStop(replay(RUN_1)), -1);
check('run 2 never stops: 3,839 and 4,128 MB are garbage above a 1,805 MB trough', firstStop(replay(RUN_2)), -1);
check('run 3 never stops', firstStop(replay(RUN_3)), -1);
check('...and none of them warns, since every trough is under 2 GB',
  [RUN_1, RUN_2, RUN_3].some((run) => replay(run).includes('warn')), false);

// A live set that really does climb. Near the limit V8's peaks have little room
// above the live size, so a collection there frees under a tenth: 4,150 -> 3,800
// is still a collection, and what it leaves is past the wall.
const climbing = replay([2600, 3400, 2900, 3700, 3300, 4000, 3600, 4150, 3800]);
check('a trough past the wall stops, on the sample that shows it', firstStop(climbing), 8);
check('...after warning once, on the first trough past the warning line',
  [climbing.indexOf('warn'), climbing.filter((l) => l === 'warn').length].join(), [4, 1].join());

// A scavenge frees at most the young generation, tens of megabytes. A dip that
// small is not a collection, and must not be read as a live size at the wall.
check('a scavenge-sized dip at the wall is not a trough',
  firstStop(replay([1500, 3000, 3900, 3880, 3895, 3870])), -1);

// The fallback, for a heap past the wall that never shows a collection at all.
// After run 2 stopped, its garbage sat at 4.1 GB for seven samples (14 s) before
// one ran, so the count is well past that.
const flat = (n: number) => [1500, ...Array.from({ length: n }, () => 3900)];
check(`${HEAP_UNCOLLECTED_SAMPLES - 1} samples past the wall with no collection do not stop`,
  firstStop(replay(flat(HEAP_UNCOLLECTED_SAMPLES - 1))), -1);
check(`...the ${HEAP_UNCOLLECTED_SAMPLES}th does`, firstStop(replay(flat(HEAP_UNCOLLECTED_SAMPLES))), HEAP_UNCOLLECTED_SAMPLES);
checkTrue('...and that is longer than the 14 s plateau run 2 showed', HEAP_UNCOLLECTED_SAMPLES * HEAP_SAMPLE_MS > 14_000);
check('a collection resets the count',
  firstStop(replay([...flat(HEAP_UNCOLLECTED_SAMPLES - 1), 1500, ...Array.from({ length: HEAP_UNCOLLECTED_SAMPLES - 1 }, () => 3900)])), -1);

check('an unknown limit says nothing over a whole run either', replay([...RUN_2, ...flat(40)], null).includes('ok'), true);
checkTrue('...not one sample of it', replay([...RUN_2, ...flat(40)], null).every((l) => l === 'ok'));

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
