/**
 * Assertion tests for what main does about a page that is not there.
 *
 *   npx tsx scripts/electron/renderer-life.ts
 *
 * Held under plain `tsx`: whether main may send to a page at all (a crashed
 * one keeps its webContents, and a send to it only makes Electron log "Render
 * frame was disposed"), what main does when a page is gone (the crash screen,
 * or the OS's box when the crash screen itself died), and the crash screen's
 * wording and URL in `src/lib/crashScreen.ts`. `smoke.ts` holds the running
 * half: a real crash, no such log line, and a page that comes back on Reload.
 */
import { readFileSync } from 'node:fs';
import { canSend, crashResponse, readCrashAnswer } from '../../electron/rendererLife';
import {
  CRASH_SCREEN_PATH, CRASH_SCREEN_TEXT, crashNativeDetail, crashReasonSentence,
  crashScreenSearch, readCrashReason,
} from '../../src/lib/crashScreen';

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

console.log('\n--- what the crash screen says ---\n');

{
  const FOLLOW = 'Reload brings the window back. Quit closes Inwire, and still asks first if a capture is unsaved.';
  check('the follow-up', CRASH_SCREEN_TEXT.followUp, FOLLOW);
  check('the headline', CRASH_SCREEN_TEXT.title, "Inwire's window stopped working");
  check('crashed', crashReasonSentence('crashed'), 'The page crashed.');
  check('oom', crashReasonSentence('oom'), 'The page ran out of memory.');
  check('killed', crashReasonSentence('killed'),
    'The page was ended by another program or by Windows.');
  check('launch-failed', crashReasonSentence('launch-failed'), 'The page could not start.');
  check('integrity-failure', crashReasonSentence('integrity-failure'),
    "Windows refused to run the page's code.");
  for (const reason of ['abnormal-exit', 'memory-eviction', 'something-new', '']) {
    check(`${JSON.stringify(reason)} falls back to the plain sentence`,
      crashReasonSentence(reason), 'The page exited unexpectedly.');
  }
  // The code is for the log line in main and nowhere a reader looks.
  const everything = ['crashed', 'oom', 'killed', 'launch-failed', 'integrity-failure', 'other']
    .map(crashReasonSentence).join(' ') + JSON.stringify(CRASH_SCREEN_TEXT);
  checkTrue('no exit code appears in any wording', !/\d|exit code/i.test(everything));
  check('the native fallback detail is the sentence then the follow-up',
    crashNativeDetail('oom'), `The page ran out of memory. ${FOLLOW}`);
}

console.log('\n--- the reason travels in the URL ---\n');

{
  for (const reason of ['crashed', 'oom', 'killed', 'launch-failed', 'integrity-failure']) {
    check(`${reason} round-trips`, readCrashReason(crashScreenSearch(reason)), reason);
  }
  check('a reason with odd characters round-trips',
    readCrashReason(crashScreenSearch('a b&c=d?')), 'a b&c=d?');
  check('no query reads as the default sentence',
    crashReasonSentence(readCrashReason('')), 'The page exited unexpectedly.');
  check('a query without a reason reads as the default sentence',
    crashReasonSentence(readCrashReason('?other=1')), 'The page exited unexpectedly.');
  check('a broken escape does not throw',
    crashReasonSentence(readCrashReason('?reason=%E0%A4%A')), 'The page exited unexpectedly.');
  check('the path', CRASH_SCREEN_PATH, '/crash.html');
}

console.log('\n--- what main does with a gone renderer ---\n');

{
  const app = 'app://inwire/index.html';
  const dev = 'http://localhost:3000/';
  const details = (reason: string) => ({ reason, exitCode: -36861 });
  check('a clean exit is not a crash', crashResponse(details('clean-exit'), app), 'none');
  check('a crash shows the screen', crashResponse(details('crashed'), app), 'screen');
  check('...also from the dev server', crashResponse(details('oom'), dev), 'screen');
  check('the crash screen itself dying falls back to the OS box',
    crashResponse(details('crashed'), 'app://inwire/crash.html'), 'native');
  check('...with its reason in the query',
    crashResponse(details('crashed'), 'app://inwire/crash.html?reason=oom'), 'native');
  check('...from the dev server too',
    crashResponse(details('killed'), 'http://localhost:3000/crash.html?reason=oom'), 'native');
  check('a clean exit of the crash screen is still not a crash',
    crashResponse(details('clean-exit'), 'app://inwire/crash.html'), 'none');
  check('an unparseable URL is the app, not the crash screen',
    crashResponse(details('crashed'), ''), 'screen');
}

console.log('\n--- the buttons ---\n');

check('the labels', [CRASH_SCREEN_TEXT.buttons.reload, CRASH_SCREEN_TEXT.buttons.quit],
  ['Reload', 'Quit']);

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
