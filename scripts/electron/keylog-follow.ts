/**
 * Assertion tests for following a TLS key log.
 *
 *   npx tsx scripts/electron/keylog-follow.ts
 *
 * Two kinds of check, because the feature has two ways to be wrong.
 *
 * **The arithmetic** in `electron/keyLogTail.ts`, held under plain `tsx` the
 * way `pipeTransport.ts` is: where the next read starts, what a shrunken file
 * means, and where a line ends - since a read can stop mid-line and
 * `keyLog.add` would reject the fragment and never see its other half.
 *
 * **The boundary**, as source text. Main reads a file on the renderer's
 * behalf, and a renderer that could NAME the file would be a renderer that
 * could read any file on this machine - while parsing hostile bytes for a
 * living. So no handler reads an argument, no preload method takes one, and
 * the settings file holds a path and never a secret.
 */
import { readFileSync } from 'node:fs';
import {
  LineAssembler, MAX_READ_BYTES, parseKeyLogSettings, planRead, POLL_MS, readSpans, REARM_TICKS,
} from '../../electron/keyLogTail';

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

console.log('\n--- where the next read starts ---\n');

check('a new file is read from the top', planRead(120, 0), { kind: 'read', from: 0, to: 120, restart: false });
check('an appended file is read from where we stopped',
  planRead(500, 120), { kind: 'read', from: 120, to: 500, restart: false });
check('an unchanged file is not read at all', planRead(500, 500), { kind: 'none' });
// Truncated or replaced: the offset now points past the end of a different
// file. Reading from it would read nothing for ever while the browser wrote a
// whole new log underneath.
check('a file that SHRANK is read again from the top',
  planRead(80, 500), { kind: 'read', from: 0, to: 80, restart: true });

console.log('\n--- where a line ends ---\n');

{
  const lines = new LineAssembler();
  check('a whole line is handed on', lines.push('LABEL aa bb\n'), 'LABEL aa bb\n');
  check('half a line is held back, not handed on', lines.push('LABEL cc'), '');
  check('...and kept', lines.held, 'LABEL cc');
  // The case the class exists for: the watcher fired while the browser was
  // part-way through writing, and the rest arrives on the next read.
  check('...until its newline arrives, then handed on whole',
    lines.push(' dd\nLABEL ee'), 'LABEL cc dd\n');
  check('...keeping the new fragment behind it', lines.held, 'LABEL ee');
  lines.reset();
  check('a reset drops what belonged to the old file', lines.held, '');
}

{
  const lines = new LineAssembler();
  check('CRLF lines are handed on with their CR, which `keyLog.add` strips',
    lines.push('A b c\r\nB d e\r\n'), 'A b c\r\nB d e\r\n');
  check('several lines and a fragment in one read',
    lines.push('1\n2\n3'), '1\n2\n');
}

console.log('\n--- no single read is unbounded ---\n');

check('a small file is one read', readSpans(0, 5_000), [[0, 5_000]]);
check('a large one is several, of at most MAX_READ_BYTES each',
  readSpans(0, MAX_READ_BYTES * 2 + 10).map(([a, b]) => b - a),
  [MAX_READ_BYTES, MAX_READ_BYTES, 10]);
check('...and they tile the range exactly',
  readSpans(100, 100 + MAX_READ_BYTES + 1), [[100, 100 + MAX_READ_BYTES], [100 + MAX_READ_BYTES, 101 + MAX_READ_BYTES]]);
check('nothing to read is no reads', readSpans(40, 40), []);

console.log('\n--- a secret arrives inside the ordering window ---\n');

// The poll is the only thing that sees a browser's writes - Chrome appends
// through a handle it holds open, which raises no `fs.watch` event on Windows -
// so its interval IS the follower's latency. At one second, every
// connection's first ~100 ms of 1-RTT packets was dissected before its secret
// arrived and stayed `Protected Payload` for good. The Worker holds frames for
// `ORDERING_HOLD_MS`; the poll must fit twice inside it.
{
  const worker = readFileSync('src/workers/pipeline.worker.ts', 'utf8');
  const hold = Number(/const ORDERING_HOLD_MS = (\d+);/.exec(worker)?.[1]);
  checkTrue('the Worker\'s ordering window is readable from source', Number.isFinite(hold) && hold > 0);
  checkTrue(`the poll (${POLL_MS} ms) is at most half the ordering window (${hold} ms)`, POLL_MS * 2 <= hold);
  check('the watcher is re-armed about once a second, not every tick', REARM_TICKS * POLL_MS, 1000);
}

console.log('\n--- the remembered path ---\n');

check('no settings file means nothing chosen', parseKeyLogSettings(null), { path: null });
check('a stored path is read back', parseKeyLogSettings('{"path":"C:\\\\keys.txt"}'), { path: 'C:\\keys.txt' });
check('a corrupt file means nothing chosen, not a crash', parseKeyLogSettings('{not json'), { path: null });
check('an empty path is nothing chosen', parseKeyLogSettings('{"path":""}'), { path: null });
check('a path that is not a string is nothing chosen', parseKeyLogSettings('{"path":7}'), { path: null });

console.log('\n--- the renderer never names a file ---\n');

const main = readFileSync('electron/main.ts', 'utf8');
const preload = readFileSync('electron/preload.ts', 'utf8');
const follower = readFileSync('electron/keyLogFollower.ts', 'utf8');

// Every `ipcMain.handle(KEYLOG_...` handler, with its parameter list. The rule
// is on the SECOND parameter: the first is the event, which is main's own
// object and says only who is asking.
const handlers = [...main.matchAll(/ipcMain\.handle\((KEYLOG_[A-Z_]+),\s*\(([^)]*)\)/g)];
check('four key log handlers are registered', handlers.map((h) => h[1]).sort(),
  ['KEYLOG_ATTACH_CHANNEL', 'KEYLOG_CHOOSE_CHANNEL', 'KEYLOG_FOLLOW_SUGGESTED_CHANNEL', 'KEYLOG_FORGET_CHANNEL']);
check('...and none of them takes an argument from the page',
  handlers.filter((h) => h[2].split(',').filter((p) => p.trim().length > 0).length > 1).map((h) => h[1]), []);

// The preload's key log methods, the only way the page reaches those handlers.
const preloadMethods = [...preload.matchAll(/^\s{2}(\w*KeyLog\w*)\(([^)]*)\)/gm)]
  .filter((m) => !m[1].startsWith('on'));
check('the preload exposes four key log calls', preloadMethods.map((m) => m[1]).sort(),
  ['attachKeyLog', 'chooseKeyLog', 'followSuggestedKeyLog', 'forgetKeyLog']);
check('...and none of them takes a parameter',
  preloadMethods.filter((m) => m[2].trim().length > 0).map((m) => m[1]), []);

// Where a followed path can come from: main's own dialog, or main's own
// environment. Anything else reaching `follow(` is the hole this prevents.
const followCalls = [...follower.matchAll(/this\.follow\(([^)]*)\)/g)].map((m) => m[1].trim());
check('a path is only ever followed from the dialog or SSLKEYLOGFILE',
  followCalls.sort(), ['picked.filePaths[0]', 'suggested']);

console.log('\n--- and what is written to disk is a path, never a secret ---\n');

const writes = [...follower.matchAll(/writeFileSync\(([^;]*)\);/g)].map((m) => m[1]);
check('the follower writes one file', writes.length, 1);
checkTrue('...and it is `{ path }` and nothing else',
  writes[0] !== undefined && /JSON\.stringify\(\{\s*path:\s*this\.file\s*\}\)/.test(writes[0]));

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All key log follow checks passed.');
process.exit(0);
