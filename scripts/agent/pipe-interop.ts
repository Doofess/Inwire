/**
 * The Rust pipe server, driven by the app's own client.
 *
 *   cargo run --manifest-path agent-rs/Cargo.toml --example pipe_serve
 *   npx tsx scripts/agent/pipe-interop.ts
 *
 * **In `NOT_TESTS`: it needs a server running beside it**, and it is Windows
 * only. Run it by hand after anything touching `agent-rs/src/pipe.rs` or
 * `src/services/agentFraming.ts`.
 *
 * ## What it is for
 *
 * The wire vectors prove three implementations agree about bytes. They cannot
 * prove the TRANSPORT works, and the transport is where this codebase's worst
 * recorded pipe bug lives: a handle opened without `FILE_FLAG_OVERLAPPED` is
 * synchronous, so Windows serialises a write behind a blocked read. `hello` and
 * the first reply arrive and nothing after them does - it works on the
 * handshake, which is what anyone tests, and stops on the traffic, which is
 * what the pipe is for.
 *
 * So this connects the way `electron/pipeTransport.ts` connects, frames the way
 * `src/services/agentFraming.ts` frames, and then sends **more than one frame**
 * and expects every echo back. One round trip would pass against the bug.
 */
import { connect } from 'node:net';
import {
  FRAME_BINARY,
  FRAME_JSON,
  FrameReader,
  encodeFrame,
} from '../../src/services/agentFraming';

const PIPE = process.env.INWIRE_PROBE_PIPE ?? String.raw`\\.\pipe\inwire-probe`;

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

if (process.platform !== 'win32') {
  console.log('SKIP  the named pipe is Windows-only');
  process.exit(0);
}

/** The frames to send. Deliberately a mix, and deliberately more than one. */
const OUTGOING: { kind: number; payload: Uint8Array; label: string }[] = [
  { kind: FRAME_JSON, payload: new TextEncoder().encode('{"type":"hello"}'), label: 'a small json frame' },
  { kind: FRAME_BINARY, payload: Uint8Array.from({ length: 256 }, (_, i) => i), label: 'a 256-byte binary frame' },
  // Larger than READ_CHUNK (64 kB), so the server's reader has to reassemble
  // across reads - the case a single small frame would never reach.
  { kind: FRAME_BINARY, payload: Uint8Array.from({ length: 200_000 }, (_, i) => i & 0xff), label: 'a 200 kB binary frame, across several reads' },
  { kind: FRAME_JSON, payload: new TextEncoder().encode('{"type":"bye"}'), label: 'a last json frame' },
];

const socket = connect(PIPE);
const reader = new FrameReader();
const received: { kind: number; payload: Uint8Array }[] = [];

const done = new Promise<void>((resolve, reject) => {
  const timer = setTimeout(() => {
    reject(new Error(
      `timed out with ${received.length}/${OUTGOING.length} echoes. `
      + 'Is `cargo run --example pipe_serve` running? A partial count here is '
      + 'the overlapped-I/O symptom: the handshake lands and the traffic stops.',
    ));
  }, 15_000);

  socket.on('error', (e) => { clearTimeout(timer); reject(e); });
  socket.on('close', () => {
    clearTimeout(timer);
    resolve();
  });
  socket.on('data', (chunk) => {
    for (const frame of reader.push(new Uint8Array(chunk))) {
      received.push({ kind: frame.kind, payload: new Uint8Array(frame.payload) });
      if (received.length === OUTGOING.length) {
        clearTimeout(timer);
        socket.end();
        resolve();
      }
    }
  });
  socket.on('connect', () => {
    console.log(`connected to ${PIPE}`);
    for (const f of OUTGOING) socket.write(encodeFrame(f.kind, f.payload));
  });
});

try {
  await done;
} catch (e) {
  console.log(`FAIL  ${(e as Error).message}`);
  process.exit(1);
}

console.log();
check('every frame came back', received.length, OUTGOING.length);
for (const [i, sent] of OUTGOING.entries()) {
  const got = received[i];
  if (!got) { check(`${sent.label}: echoed`, false, true); continue; }
  check(`${sent.label}: kind`, got.kind, sent.kind);
  check(`${sent.label}: ${sent.payload.length} bytes, byte for byte`,
    got.payload.length === sent.payload.length
      && got.payload.every((b, j) => b === sent.payload[j]),
    true);
}
// Ordering is the property the writer's wait-per-frame exists to keep: two
// outstanding writes on one handle have no defined order, and a packet batch
// delivered out of order is a capture that lies about the wire.
check('...and in the order they were sent',
  received.map((r) => r.payload.length),
  OUTGOING.map((o) => o.payload.length));

console.log();
if (failures) {
  console.log(`${failures} pipe interop check(s) FAILED`);
  process.exit(1);
}
console.log('All pipe interop checks passed.');
process.exit(0);
