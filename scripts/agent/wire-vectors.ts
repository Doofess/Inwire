/**
 * The renderer's decoders against the golden wire vectors.
 *
 *   npx tsx scripts/agent/wire-vectors.ts
 *
 * **Three implementations of one format, one set of bytes.** `agentBinary.ts`
 * and `agentFraming.ts` here, `local-agent/packet_batch.py` and `pipe_frame.py`
 * in the Python agent, and `agent-rs/src/` in the Rust one. Until this file they
 * were kept in agreement by each asserting its OWN hand-written copy of the same
 * vector - which holds exactly until somebody edits one copy, at which point
 * every suite passes and reports that each side agrees with itself.
 *
 * So the bytes are in `wire-vectors.json` beside this file, and each
 * implementation is checked against that. Regenerating is a separate, explicit
 * verb (`python local-agent/wire_vectors.py --write`), because a fixture that
 * rewrites itself on every run cannot catch the change it exists to catch.
 *
 * `scripts/agent/binary.ts` and `pipe-framing.ts` still hold their own vectors
 * and are still worth having: they pin cases this fixture does not carry, and
 * two independent statements of the same bytes is the point rather than the
 * duplication.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  BATCH_HEADER_BYTES,
  BATCH_RECORD_BYTES,
  BATCH_VERSION,
  decodePacketBatch,
} from '../../src/services/agentBinary';
import {
  FRAME_BINARY,
  FRAME_JSON,
  FrameReader,
  MAX_FRAME_BYTES,
  encodeFrame,
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
function checkTrue(name: string, actual: boolean): void {
  check(name, actual, true);
}

interface Vectors {
  constants: {
    recordBytes: number; headerBytes: number; magic: string; version: number;
    frameJson: number; frameBinary: number; maxFrameBytes: number;
  };
  records: {
    /** Epoch nanoseconds, as a decimal string: past 2^53, a JSON number would round. */
    seq: number; iface: number; tsNs: string; origLen: number;
    dataBase64: string; encodedHex: string;
  }[];
  batchHex: string;
  frames: ({ kind: 'json'; text: string; encodedHex: string }
    | { kind: 'binary'; dataBase64: string; encodedHex: string })[];
}

const FIXTURE = join(import.meta.dirname, 'wire-vectors.json');
const vectors: Vectors = JSON.parse(readFileSync(FIXTURE, 'utf8'));

const unhex = (hex: string): Uint8Array =>
  Uint8Array.from((hex.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const unb64 = (b64: string): Uint8Array => Uint8Array.from(Buffer.from(b64, 'base64'));

console.log('--- the constants all three implementations share ---');
console.log();

check('the record is the width the fixture says', BATCH_RECORD_BYTES, vectors.constants.recordBytes);
check('...and so is the batch header', BATCH_HEADER_BYTES, vectors.constants.headerBytes);
check('the batch version agrees', BATCH_VERSION, vectors.constants.version);
check('the JSON frame kind agrees', FRAME_JSON, vectors.constants.frameJson);
check('the binary frame kind agrees', FRAME_BINARY, vectors.constants.frameBinary);
check('the frame ceiling agrees', MAX_FRAME_BYTES, vectors.constants.maxFrameBytes);

console.log();
console.log('--- the packet batch ---');
console.log();

{
  const bytes = unhex(vectors.batchHex);
  // `slice()` because decodePacketBatch takes an ArrayBuffer and the frames it
  // returns are VIEWS over it - handing it a subarray's buffer would hand it
  // the whole backing store.
  const decoded = decodePacketBatch(bytes.buffer.slice(
    bytes.byteOffset, bytes.byteOffset + bytes.byteLength,
  ) as ArrayBuffer);

  check('every record in the batch is decoded', decoded.length, vectors.records.length);
  for (const [i, want] of vectors.records.entries()) {
    const got = decoded[i];
    check(`record ${i}: seq`, got.seq, want.seq);
    check(`record ${i}: iface`, got.iface, want.iface);
    // Split into whole microseconds and a remainder by the decoder; joined
    // back here with a BigInt, which the decoder deliberately does not use.
    const ns = BigInt(want.tsNs);
    check(`record ${i}: timestamp, whole microseconds`, got.tsUs, Number(ns / 1000n));
    check(`record ${i}: timestamp, the nanoseconds past them`, got.tsNsRem, Number(ns % 1000n));
    // The half a new decoder is most likely to get wrong: the wire length is
    // RECONSTRUCTED by adding `extra` back to the captured length, because it
    // is sent as the difference. Record 3 is captured short on purpose.
    check(`record ${i}: wire length is reconstructed, not read`, got.origLen, want.origLen);
    check(`record ${i}: bytes`,
      Array.from(got.bytes), Array.from(unb64(want.dataBase64)));
  }
}

console.log();
console.log('--- the pipe framing ---');
console.log();

for (const [i, frame] of vectors.frames.entries()) {
  const payload = frame.kind === 'json'
    ? new TextEncoder().encode(frame.text)
    : unb64(frame.dataBase64);
  const kind = frame.kind === 'json' ? FRAME_JSON : FRAME_BINARY;
  check(`frame ${i} (${frame.kind}) encodes to the golden bytes`,
    Array.from(encodeFrame(kind, payload)), Array.from(unhex(frame.encodedHex)));
}

{
  // The property a pipe actually needs. A read returns whatever happened to be
  // in the buffer, so a header can arrive in two pieces and a payload in ten.
  const stream: number[] = [];
  for (const f of vectors.frames) stream.push(...unhex(f.encodedHex));

  const reader = new FrameReader();
  const oneAtATime = [];
  for (const b of stream) oneAtATime.push(...reader.push(Uint8Array.from([b])));
  check('a stream delivered one byte at a time still frames',
    oneAtATime.length, vectors.frames.length);

  const whole = new FrameReader();
  const atOnce = whole.push(Uint8Array.from(stream));
  check('...and produces the same frames as one whole read',
    atOnce.map((f) => [f.kind, Array.from(f.payload)]),
    oneAtATime.map((f) => [f.kind, Array.from(f.payload)]));
}

{
  // Refused on the declared length alone, before the payload is waited for:
  // five bytes must never be able to ask a privileged service for four
  // gigabytes. The Rust and Python readers assert the identical case.
  const header = new Uint8Array(5);
  new DataView(header.buffer).setUint32(0, MAX_FRAME_BYTES + 1, true);
  header[4] = FRAME_JSON;
  let refused = false;
  try {
    new FrameReader().push(header);
  } catch {
    refused = true;
  }
  checkTrue('a frame past the ceiling is refused on its header alone', refused);
}

console.log();
console.log('--- the Rust agent, read out of its source ---');
console.log();

{
  // **Read rather than run.** Proving the Rust agrees with the fixture is
  // `cargo test`'s job and it does it properly, by encoding. But cargo is not
  // installed on every machine this suite runs on - CI is ubuntu and the whole
  // promise of `scripts/` is plain `tsx` with no toolchain - so a Rust constant
  // could drift and nothing in `npm run check` would notice until somebody
  // happened to build it.
  //
  // So the constants are parsed out of the source, which is the same technique
  // `scripts/session/view.ts` uses to hold the rail's arithmetic to its Tailwind
  // classes. It cannot catch a wrong ENCODER; it catches the thing that goes
  // wrong silently, which is two numbers that were supposed to be one.
  const read = (rel: string): string =>
    readFileSync(join(import.meta.dirname, '..', '..', 'agent-rs', 'src', rel), 'utf8');
  const wireRs = read('wire.rs');
  const framingRs = read('framing.rs');

  const constant = (src: string, name: string): string | null => {
    const m = new RegExp(`pub const ${name}[^=]*=\\s*([^;]+);`).exec(src);
    return m ? m[1].trim() : null;
  };
  // `8 * 1024 * 1024` and friends are written as products, so the value is
  // evaluated rather than string-matched - a literal comparison would fail on a
  // formatting change and pass on a wrong number written the same way.
  //
  // **Sums of products, by hand, and deliberately not `new Function`.** The
  // input is a file in this repository rather than anything a user sends, so
  // the risk here is theoretical - but `agentPipe.ts` states the rule that
  // nothing interpolates into a constructed command, and a checker that breaks
  // the rule it exists to help keep is the wrong thing to have written. This
  // parser understands exactly what the constants need and refuses the rest.
  const numeric = (expr: string | null): number | null => {
    if (expr === null) return null;
    let total = 0;
    for (const term of expr.replace(/_/g, '').split('+')) {
      let product = 1;
      for (const factor of term.split('*')) {
        const n = Number(factor.trim());
        if (!Number.isFinite(n)) return null;
        product *= n;
      }
      total += product;
    }
    return total;
  };

  check('rust: the record is the width the fixture says',
    numeric(constant(wireRs, 'RECORD_BYTES')), vectors.constants.recordBytes);
  check('rust: ...and so is the batch header',
    numeric(constant(wireRs, 'HEADER_BYTES')), vectors.constants.headerBytes);
  check('rust: the batch version agrees',
    numeric(constant(wireRs, 'VERSION')), vectors.constants.version);
  check('rust: the magic agrees',
    constant(wireRs, 'MAGIC'), `*b"${vectors.constants.magic}"`);
  check('rust: the JSON frame kind agrees',
    numeric(constant(framingRs, 'FRAME_JSON')), vectors.constants.frameJson);
  check('rust: the binary frame kind agrees',
    numeric(constant(framingRs, 'FRAME_BINARY')), vectors.constants.frameBinary);
  check('rust: the frame ceiling agrees',
    numeric(constant(framingRs, 'MAX_FRAME_BYTES')), vectors.constants.maxFrameBytes);
}

console.log();
if (failures) {
  console.log(`${failures} wire vector check(s) FAILED`);
  console.log('If the format changed on purpose, regenerate the fixture with');
  console.log('  python local-agent/wire_vectors.py --write');
  console.log('and move Python, TypeScript and Rust in the same commit.');
  process.exit(1);
}
console.log('All wire vector checks passed.');
process.exit(0);
