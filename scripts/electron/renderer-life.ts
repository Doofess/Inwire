/**
 * Assertion tests for what main does about a page that is not there.
 *
 *   npx tsx scripts/electron/renderer-life.ts
 *
 * Two decisions in `electron/rendererLife.ts`, held under plain `tsx`: whether
 * main may send to a page at all (a crashed one keeps its webContents, and a
 * send to it only makes Electron log "Render frame was disposed"), and what
 * the box after a crash says. `smoke.ts` holds the running half: a real
 * crash, no such log line, and a page that comes back on Reload.
 */
import { readFileSync } from 'node:fs';
import {
  canSend, CRASH_BUTTONS, crashPrompt, readCrashAnswer,
} from '../../electron/rendererLife';

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

console.log('\n--- may main send ---\n');

{
  const fake = (destroyed: boolean, crashed: boolean) => {
    const asked: string[] = [];
    return {
      asked,
      isDestroyed: () => { asked.push('destroyed'); return destroyed; },
      isCrashed: () => { asked.push('crashed'); return crashed; },
    };
  };
  check('a live page can be sent to', canSend(fake(false, false)), true);
  check('a crashed page cannot', canSend(fake(false, true)), false);
  const gone = fake(true, false);
  check('a destroyed page cannot', canSend(gone), false);
  // `isCrashed` on a destroyed webContents throws, so it is never asked.
  check('...and a destroyed page is not asked whether it crashed', gone.asked, ['destroyed']);
}

console.log('\n--- what the box says ---\n');

{
  const prompt = (reason: string, exitCode = 0) => crashPrompt({ reason, exitCode });
  const FOLLOW = 'Reload brings the window back. Quit closes Inwire, and still asks first if a capture is unsaved.';
  check('a clean exit is not a crash', prompt('clean-exit'), null);
  check('crashed names the exit code',
    prompt('crashed', -1073741819)?.detail, `The page crashed (exit code -1073741819). ${FOLLOW}`);
  check('oom', prompt('oom')?.detail, `The page ran out of memory. ${FOLLOW}`);
  check('killed', prompt('killed')?.detail,
    `The page was ended by another program or by Windows. ${FOLLOW}`);
  check('launch-failed', prompt('launch-failed')?.detail, `The page could not start. ${FOLLOW}`);
  check('integrity-failure', prompt('integrity-failure')?.detail,
    `Windows refused to run the page's code. ${FOLLOW}`);
  for (const reason of ['abnormal-exit', 'memory-eviction', 'something-new']) {
    check(`${reason} falls back to the plain sentence`, prompt(reason, 7)?.detail,
      `The page exited unexpectedly (exit code 7). ${FOLLOW}`);
  }
  check('the headline', prompt('crashed')?.message, "Inwire's window stopped working");
}

console.log('\n--- the buttons ---\n');

check('Reload then Quit', [...CRASH_BUTTONS], ['Reload', 'Quit']);
// Esc and the default both pick index 0 in main; a Quit there would close the
// app on a stray key, and a dead window is the other failure.
check('Reload is index 0', CRASH_BUTTONS.indexOf('Reload'), 0);

console.log('\n--- the test launch answer ---\n');

check('reload', readCrashAnswer('reload'), 'reload');
check('quit', readCrashAnswer('quit'), 'quit');
check('unset', readCrashAnswer(undefined), null);
check('empty', readCrashAnswer(''), null);
check('case matters', readCrashAnswer('RELOAD'), null);
check('garbage', readCrashAnswer('yes please'), null);

console.log('\n--- the close path ---\n');

{
  const stripped = readFileSync('electron/main.ts', 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  checkTrue('main never calls destroy()', !/\.destroy\(/.test(stripped));
  checkTrue('a crash answer reloads or closes the window', /window\.close\(\)/.test(stripped));
}

console.log(failures === 0 ? '\nAll renderer-life checks passed.' : `\n${failures} renderer-life check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
