/**
 * Assertion tests for what main says about the page's memory.
 *
 *   npx tsx scripts/electron/heap-log.ts
 *
 * Held under plain `tsx`: the crash line names the one exit code that has been
 * measured (a forced V8 out-of-memory, `electron/heapLog.ts`) and no other,
 * the heap timeline is on only when `start.cjs` asks, and its line prints a
 * missing reading as "?" rather than 0. That the code really is the
 * out-of-memory one is a measurement, re-made by hand after an Electron upgrade.
 */
import { readFileSync } from 'node:fs';
import {
  crashCodeMeaning, crashLine, HEAP_LOG_ENV, heapLine, heapLogEnabled, RENDERER_OOM_EXIT_CODE,
} from '../../electron/heapLog';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const ok = actual === expected;
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok ? '' : `\n     expected ${JSON.stringify(expected)}\n     got      ${JSON.stringify(actual)}`}`);
}

console.log('\n--- the crash line ---\n');

check('the out-of-memory code is named on Windows',
  crashLine('crashed', RENDERER_OOM_EXIT_CODE, 'win32'), '[renderer] gone: crashed (exit code -36861: out of JavaScript heap)');
check('...and is the measured number', RENDERER_OOM_EXIT_CODE, -36861);
check('another code is printed bare', crashLine('crashed', -1073741819, 'win32'), '[renderer] gone: crashed (exit code -1073741819)');
check('the same number elsewhere is not claimed', crashCodeMeaning(RENDERER_OOM_EXIT_CODE, 'linux'), null);
check('a clean exit is printed as it is', crashLine('clean-exit', 0, 'win32'), '[renderer] gone: clean-exit (exit code 0)');

console.log('\n--- the heap timeline ---\n');

check('on for "1"', heapLogEnabled('1'), true);
check('off when unset', heapLogEnabled(undefined), false);
check('off for anything else', heapLogEnabled('true'), false);
const at = new Date(2026, 9, 30, 9, 5, 7);
check('a full sample',
  heapLine({ at, jsUsed: 1_234 * 1_048_576, jsLimit: 4_192 * 1_048_576, privateBytes: 1_890 * 1_048_576 }),
  '[heap] 09:05:07 page js 1,234 / 4,192 MB, renderer private 1,890 MB');
check('a page that did not answer shows "?", not 0',
  heapLine({ at, jsUsed: null, jsLimit: null, privateBytes: 512 * 1_048_576 }),
  '[heap] 09:05:07 page js ? / ? MB, renderer private 512 MB');

console.log('\n--- the wiring ---\n');

// Text checks, because main and start.cjs cannot load under tsx.
const main = readFileSync('electron/main.ts', 'utf8');
const start = readFileSync('electron/start.cjs', 'utf8');
check('main prints the crash through crashLine',
  /console\.error\(crashLine\(details\.reason, details\.exitCode, process\.platform\)\)/.test(main), true);
check('main logs the heap only when the variable says so',
  /if \(heapLogEnabled\(process\.env\[HEAP_LOG_ENV\]\)\) logHeap\(window\)/.test(main), true);
check('start:app sets that variable', start.includes(`${HEAP_LOG_ENV}: '1'`), true);
check('start:app waits for the pipes to close, not for the exit', /child\.on\('close'/.test(start), true);

if (failures > 0) {
  console.log(`\n${failures} failed`);
  process.exit(1);
}
console.log('\nall passed');
process.exit(0);
