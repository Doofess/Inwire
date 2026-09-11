/**
 * The framing on the pipe to the capture agent.
 *
 *   npx tsx scripts/agent/pipe-framing.ts
 *
 * A wire format with two implementations agrees with itself only if something
 * makes it. `scripts/agent/binary.ts` established the convention for the
 * packet batch and states the reason: the byte vectors below are written out
 * by hand rather than produced by either implementation, "so a wire format
 * with only one implementation of itself will agree with itself no matter what
 * it does". `local-agent/test_protocol.py` asserts the identical vectors from
 * the Python side.
 *
 * This is the only new thing on the wire in the move off the WebSocket.
 * Everything above it - the 18-byte record, every control message - is
 * transport-agnostic and unchanged, which is what made a named pipe a
 * reasonable thing to do at all.
 *
 * The cases that matter are not the happy path. They are the ones a byte
 * stream produces under load and a message transport never did: a frame split
 * across reads, several frames in one read, and a header that arrives one byte
 * at a time. And the refusals, because this reader is fed by a pipe a
 * privileged service also listens on.
 */
import {
  FrameReader, FRAME_BINARY, FRAME_HEADER_BYTES, FRAME_JSON, MAX_FRAME_BYTES,
  encodeFrame, encodeJsonFrame, frameText,
} from '../../src/services/agentFraming';

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
function checkThrows(name: string, body: () => unknown): void {
  try { body(); check(name, 'did not throw', 'threw'); } catch { check(name, 'threw', 'threw'); }
}

const hex = (bytes: Uint8Array): string =>
  [...bytes].map((b) => b.toString(16).padStart(2, '0')).join(' ');

console.log('--- the bytes, written out by hand ---\n');

{
  // `{"type":"stop_capture"}` is 23 characters, so the frame declares 24 (the
  // payload plus the kind byte) and is 28 bytes on the wire.
  const frame = encodeJsonFrame({ type: 'stop_capture' });
  check('a control message frames exactly',
    hex(frame),
    '18 00 00 00 00 7b 22 74 79 70 65 22 3a 22 73 74 6f 70 5f 63 61 70 74 75 72 65 22 7d');
  check('...length little-endian, kind after it', [frame.length, frame[4]], [28, FRAME_JSON]);

  const binary = encodeFrame(FRAME_BINARY, new Uint8Array([0x49, 0x57, 0x50, 0x31]));
  check('a binary frame carries its payload untouched',
    hex(binary), '05 00 00 00 01 49 57 50 31');

  // The degenerate frame: no payload at all. The length field is 1, for the
  // kind byte, and never 0 - which is why the reader refuses a declared 0.
  check('an empty payload still declares one byte',
    hex(encodeFrame(FRAME_JSON, new Uint8Array(0))), '01 00 00 00 00');
}

console.log('\n--- a stream that arrives however it arrives ---\n');

{
  const reader = new FrameReader();
  const one = encodeJsonFrame({ type: 'start_capture' });
  const two = encodeFrame(FRAME_BINARY, new Uint8Array([1, 2, 3]));

  // Everything at once, which is the case that works by accident.
  const both = new Uint8Array([...one, ...two]);
  const frames = reader.push(both);
  check('two frames in one read come back as two',
    frames.map((f) => f.kind), [FRAME_JSON, FRAME_BINARY]);
  check('...with their payloads intact',
    [frameText(frames[0]), [...frames[1].payload]],
    ['{"type":"start_capture"}', [1, 2, 3]]);
  check('and nothing is left over', reader.pending, 0);
}

{
  // The case a message transport never produced and a pipe produces under
  // load: one byte at a time, header included.
  const reader = new FrameReader();
  const source = new Uint8Array([...encodeJsonFrame({ a: 1 }), ...encodeJsonFrame({ b: 2 })]);
  const collected: string[] = [];
  for (const byte of source) {
    for (const frame of reader.push(new Uint8Array([byte]))) collected.push(frameText(frame));
  }
  check('a stream delivered one byte at a time still frames',
    collected, ['{"a":1}', '{"b":2}']);
  check('...and holds nothing back at the end', reader.pending, 0);
}

{
  const reader = new FrameReader();
  const frame = encodeJsonFrame({ type: 'refresh_adapters' });
  // Split inside the header, which is where an implementation that read the
  // length before checking it had four bytes would fall over.
  check('half a header yields nothing', reader.push(frame.subarray(0, 3)).length, 0);
  check('...and is remembered', reader.pending, 3);
  const rest = reader.push(frame.subarray(3));
  check('the rest completes it', rest.map(frameText), ['{"type":"refresh_adapters"}']);
  check('...leaving nothing', reader.pending, 0);
}

{
  // A big one, split at an awkward point. 256 kB is the batch ceiling.
  const reader = new FrameReader();
  const payload = new Uint8Array(256 * 1024);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 7) & 0xff;
  const frame = encodeFrame(FRAME_BINARY, payload);
  reader.push(frame.subarray(0, FRAME_HEADER_BYTES + 1));
  const done = reader.push(frame.subarray(FRAME_HEADER_BYTES + 1));
  check('a full-sized batch survives a split',
    [done.length, done[0]?.payload.length], [1, payload.length]);
  let identical = true;
  for (let i = 0; i < payload.length; i++) {
    if (done[0].payload[i] !== payload[i]) { identical = false; break; }
  }
  check('...byte for byte', identical, true);
}

console.log('\n--- what it refuses, before it allocates anything ---\n');

{
  // The reason the check is on the declared length rather than on what
  // arrives: this reader is fed by a pipe that a privileged service also
  // listens on, and a five-byte header must never be able to ask for four
  // gigabytes of memory.
  const huge = new Uint8Array(FRAME_HEADER_BYTES);
  new DataView(huge.buffer).setUint32(0, MAX_FRAME_BYTES + 1, true);
  checkThrows('a frame larger than the ceiling is refused on its header alone',
    () => new FrameReader().push(huge));

  const zero = new Uint8Array(FRAME_HEADER_BYTES);
  checkThrows('a zero-length frame is refused', () => new FrameReader().push(zero));

  const unknown = encodeFrame(FRAME_JSON, new Uint8Array([1]));
  unknown[4] = 9;
  checkThrows('an unknown kind is refused rather than guessed',
    () => new FrameReader().push(unknown));

  checkThrows('...and encoding one is refused too',
    () => encodeFrame(9, new Uint8Array(0)));

  // Exactly at the ceiling is allowed: the bound is a refusal of what is past
  // it, not a margin.
  const atLimit = new Uint8Array(FRAME_HEADER_BYTES);
  new DataView(atLimit.buffer).setUint32(0, MAX_FRAME_BYTES, true);
  const reader = new FrameReader();
  check('a frame exactly at the ceiling is accepted and waited for',
    [reader.push(atLimit).length, reader.pending], [0, FRAME_HEADER_BYTES]);
}

console.log(failures === 0
  ? '\nAll pipe framing checks passed.'
  : `\n${failures} pipe framing check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
