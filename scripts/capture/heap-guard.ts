/**
 * The capture store's memory ceiling.
 *
 *   npx tsx scripts/capture/heap-guard.ts
 *
 * `electron/store/heapGuard.ts` exists because the ceiling everyone believed
 * was in place was not: `execArgv: ['--max-old-space-size=2048']` reaches the
 * store process and V8 ignores it, so the real limit is 4192 MB and the store
 * was seen to die at 4,060 MB with a V8 abort and no explanation anywhere a
 * user could reach.
 *
 * What the replacement has to get right is small and easy to get subtly wrong,
 * which is why it is a pure function and this drives it:
 *
 *   - it must stand down **before** V8 does, including on a machine where V8's
 *     own limit is lower than ours;
 *   - it must warn once, not once per sample - a warning every two seconds is
 *     a stream, and a stream is ignored;
 *   - and a store sitting at a normal few megabytes must never hear from it.
 */
import {
  HEAP_CEILING_BYTES, HEAP_WARN_RATIO, judgeHeap,
} from '../../electron/store/heapGuard';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

const MB = 1024 * 1024;
/** What V8 actually reports in the store, measured against the running app. */
const V8_DEFAULT_LIMIT = 4192 * MB;

const level = (used: number, limit = V8_DEFAULT_LIMIT, warned = false, ceiling?: number) =>
  judgeHeap(used, limit, warned, ceiling).level;

console.log('--- a store doing its job hears nothing ---\n');

// A staging ring, one chunk being deflated, and 32 cached directories. Single
// digit megabytes, and the guard must be invisible there.
for (const used of [2 * MB, 40 * MB, 300 * MB, 1_000 * MB]) {
  check(`${used / MB} MB is fine`, level(used), 'ok');
}

console.log('\n--- the warning, once ---\n');

const wall = Math.min(HEAP_CEILING_BYTES, Math.floor(V8_DEFAULT_LIMIT * 0.9));
check('the ceiling is ours, not V8\'s, when ours is lower', wall, HEAP_CEILING_BYTES);

check('just under the warning line is silent',
  level(Math.floor(wall * HEAP_WARN_RATIO) - MB), 'ok');
check('at the warning line it says so',
  level(Math.floor(wall * HEAP_WARN_RATIO) + MB), 'warn');
check('...and does not repeat it',
  level(Math.floor(wall * HEAP_WARN_RATIO) + MB, V8_DEFAULT_LIMIT, true), 'ok');
// The stop must still fire after the warning: `warned` silences the warning,
// not the ceiling. Getting this wrong makes the guard a one-shot that never
// actually stops anything.
check('...but the ceiling still fires after it',
  level(wall + MB, V8_DEFAULT_LIMIT, true), 'stop');

console.log('\n--- the ceiling ---\n');

check('one byte under the wall is not the wall', level(wall - 1), 'warn');
check('at the wall it stops', level(wall), 'stop');
check('past the wall it stops', level(wall + 500 * MB), 'stop');

const stopped = judgeHeap(wall + MB, V8_DEFAULT_LIMIT, true);
checkTrue('...and says what happened to the capture',
  stopped.level === 'stop' && stopped.message.includes('intact'));
checkTrue('...with the number in it',
  stopped.level === 'stop' && /\d[\d,]* MB/.test(stopped.message));

console.log('\n--- when V8\'s own limit is the lower one ---\n');

// A 32-bit build, or a container with a memory cap. Standing down at 2 GB
// when V8 aborts at 1 GB is the whole failure being avoided, happening again.
const SMALL = 1_000 * MB;
const smallWall = Math.floor(SMALL * 0.9);
check('the wall follows V8 down', level(smallWall + MB, SMALL), 'stop');
check('...and 1.5 GB would have been past it', level(1_500 * MB, SMALL), 'stop');
// The contrast: the same reading is unremarkable when V8 has room for it.
check('...where against V8\'s own default the same reading is fine',
  level(1_500 * MB, V8_DEFAULT_LIMIT), 'ok');
// Ten percent of headroom, because the last tenth of a V8 heap is where the
// collector spends all its time and the process is already unusable.
checkTrue('the wall leaves V8 room to unwind', smallWall < SMALL);

console.log('\n--- the ceiling is overridable, so nothing has to allocate 2 GB ---\n');

check('a small ceiling is respected', level(60 * MB, V8_DEFAULT_LIMIT, false, 50 * MB), 'stop');
check('...and warns below it', level(41 * MB, V8_DEFAULT_LIMIT, false, 50 * MB), 'warn');

console.log(failures === 0
  ? '\nAll heap guard checks passed.'
  : `\n${failures} heap guard check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
