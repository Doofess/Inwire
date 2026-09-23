/**
 * Assertion tests for splitting main's stdout into the store and everything else.
 *
 *   npx tsx scripts/electron/main-output.ts
 *
 * `disk-drive.ts` and `import-drive.ts` both assert the capture store stayed
 * quiet, and both are in `check.ts`'s `NOT_TESTS` - so they run when somebody
 * runs them, which historically has been long after they stopped working. The
 * classifier they share is plain string handling with no Electron in it, so it
 * can be held here on every `npm run check` even though they cannot.
 *
 * **The property under test is the silent-pass one.** Those drivers used to
 * assert that main printed *nothing at all*, which was wrong for a different
 * reason but could not miss a store message. Narrowing the check to lines
 * carrying `[capture-store:` is what made "the store complained and nobody
 * noticed" representable, and `data` events are chunks rather than lines - so
 * a marker really can arrive in two pieces. Same shape as the mistake ADR 0041
 * records: catching what a check would have thrown.
 */
import { EventEmitter } from 'node:events';
import { watchMainOutput } from './mainOutput';

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

/**
 * Feeds the watcher chunks exactly as given, with no stream in the way.
 *
 * An `EventEmitter` rather than a `PassThrough` so the chunk boundaries are the
 * ones the test wrote: a real stream is free to coalesce them, which would make
 * the split-marker case below quietly stop testing anything.
 */
function feed(...chunks: string[]) {
  const source = new EventEmitter() as unknown as NodeJS.ReadableStream;
  const out = watchMainOutput(source);
  for (const chunk of chunks) (source as unknown as EventEmitter).emit('data', chunk);
  out.flush();
  return out;
}

console.log('\n--- the ordinary case ---\n');

{
  const out = feed('[capture-store:err] append failed\n[agent-pipe] auto start: started\n');
  check('the store line is the store\'s', out.store, ['[capture-store:err] append failed']);
  check('...and the supervisor line is not', out.other, ['[agent-pipe] auto start: started']);
}

{
  const out = feed('[agent-pipe] auto start: started\n');
  check('a clean run leaves the store silent', out.store, []);
}

console.log('\n--- a marker split across two chunks ---\n');

// The failure this exists for. `data` delivers whatever the pipe had, so a
// chunk can end mid-marker; classifying each chunk's lines independently gives
// two fragments, NEITHER containing `[capture-store:`, and the complaint is
// filed as unasserted output. The assertion then passes on a store that failed.
{
  const out = feed('[capture-', 'store:err] encodeChunk threw\n');
  check('the two halves are rejoined', out.store, ['[capture-store:err] encodeChunk threw']);
  check('...and nothing leaks into the unasserted list', out.other, []);
}

{
  // Split at a worse place: inside the word, after a newline, across three.
  const out = feed('[agent-pipe] ok\n[capt', 'ure-sto', 're:out] sealed\n');
  check('a marker split three ways still lands', out.store, ['[capture-store:out] sealed']);
  check('...beside the line that really was unrelated', out.other, ['[agent-pipe] ok']);
}

console.log('\n--- a line with no trailing newline ---\n');

{
  // A process that dies mid-write leaves its last line unterminated, and that
  // line is exactly as likely to be the one that mattered. `flush()` is what
  // `feed` calls above; without it this list is empty.
  const out = feed('[capture-store:err] heap ceiling reached');
  check('the held-back last line is classified', out.store,
    ['[capture-store:err] heap ceiling reached']);
}

console.log('\n--- a multi-line store message ---\n');

// `host.ts` prefixes the whole CHUNK once - `console.log(`[capture-store:...] `
// + data.toString().trimEnd())` - so only the first line of a stack trace is
// marked. `CaptureHost` logs stacks deliberately, so without this the
// assertion trips on one line and its reason is filed elsewhere.
{
  const out = feed(
    '[capture-store:err] fieldAccess: block has no read\n'
    + '    at absorb (fieldSplit.ts:30)\n'
    + '    at encodeChunk (chunkCodec.ts:88)\n'
    + '[agent-pipe] auto start: started\n',
  );
  check('the stack stays with the message that threw', out.store, [
    '[capture-store:err] fieldAccess: block has no read',
    '    at absorb (fieldSplit.ts:30)',
    '    at encodeChunk (chunkCodec.ts:88)',
  ]);
  check('...and the next bracketed record starts a new one', out.other,
    ['[agent-pipe] auto start: started']);
}

{
  // The same rule the other way: a continuation of an UNRELATED record must not
  // be attributed to the store just because a store line came earlier.
  const out = feed(
    '[capture-store:out] ready\n[agent-pipe] failed\n    at dial (agentPipe.ts:12)\n',
  );
  check('a continuation follows its own record', out.store, ['[capture-store:out] ready']);
  check('...not the last store line', out.other,
    ['[agent-pipe] failed', '    at dial (agentPipe.ts:12)']);
}

console.log('\n--- the edges ---\n');

check('no output at all', [feed().store, feed().other], [[], []]);
check('blank lines are not output', feed('\n\n  \n').other, []);
check('CRLF is a line ending too',
  feed('[capture-store:out] a\r\n[agent-pipe] b\r\n').store, ['[capture-store:out] a']);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All main-output checks passed.');
process.exit(0);
