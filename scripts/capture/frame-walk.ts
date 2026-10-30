/**
 * Extraction is a walk: frames come out one at a time, cut as they are asked
 * for, and the walk's totals are only claimed once a pass has reached the end.
 *
 *   npx tsx scripts/capture/frame-walk.ts
 *
 * ## Why it exists
 *
 * `extractFrames` cut every frame of a file into one array before dissection
 * saw the first, so an import held the whole file twice over: the buffer, and
 * a copy of every frame in it. `frameWalk` yields them lazily, so dissection
 * can take each as it is cut and let it go. `extractFrames` is the same walk,
 * collected - 15 scripts call it and none may notice.
 *
 * ## What is pinned
 *
 * - A walk yields exactly what `extractFrames` returns, field for field, for
 *   both formats - and facts that arrive *after* the frames (a pcapng's ISB
 *   comes last) are the walk's, not a prefix's.
 * - Passes are independent: a second `frames()` call yields everything again,
 *   and a pass abandoned early does not spoil the next one.
 * - A truncated final record ends the walk where `extractFrames` ends today.
 * - Lazy: a frame is cut when it is pulled. Proved by changing the file's own
 *   bytes between two pulls, which a walk that cut ahead cannot survive.
 * - Each frame is its own copy, never a view into the file's buffer.
 * - A pass with a limit counts past it without cutting, as the capped
 *   `extractFrames` always did.
 * - A pcapng's Decryption Secrets Block reaches the key log once per walk, not
 *   once per pass: a streamed import makes two, and the panel counts bad lines.
 */
import { pcapOf } from '../parity/synthetic';
import { DSB_SECRETS_TYPE_TLS_KEY_LOG } from '../../src/services/dissect/types';
import { PcapService } from '../../src/services/pcapParser';
import { keyLog } from '../../src/services/tls/keyLog';
import type { ExtractedFrame } from '../../src/services/pcapParser';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual, bigintSafe) === JSON.stringify(expected, bigintSafe);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected, bigintSafe)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual, bigintSafe)}`.slice(0, 300));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);
function bigintSafe(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? `${value}n` : value;
}

/** A frame whose first byte says which one it is, and whose length varies. */
const frameBytes = (n: number): Uint8Array =>
  new Uint8Array(Array.from({ length: 20 + n }, (_, i) => (i === 0 ? 0x10 + n : (n * 7 + i) & 0xff)));

const asFile = (bytes: Uint8Array, name: string): File =>
  new File([bytes as unknown as BlobPart], name);

/** The bytes as their own exact-size ArrayBuffer. */
const bufferOf = (bytes: Uint8Array): ArrayBuffer =>
  bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;

/**
 * A pcapng: SHB, one IDB, `count` EPBs, then an ISB after the last of them -
 * and, given `secrets`, a TLS key-log DSB ahead of the frames.
 */
function pcapngOf(count: number, secrets?: string): Uint8Array {
  const blocks: Uint8Array[] = [];
  const block = (type: number, body: number[]): Uint8Array => {
    const out = new Uint8Array(12 + body.length);
    const view = new DataView(out.buffer);
    view.setUint32(0, type, true);
    view.setUint32(4, out.length, true);
    out.set(body, 8);
    view.setUint32(out.length - 4, out.length, true);
    return out;
  };
  const u32 = (v: number) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
  const u16 = (v: number) => [v & 0xff, (v >>> 8) & 0xff];
  const u64 = (v: number) => [...u32(v >>> 0), ...u32(Math.floor(v / 2 ** 32))];
  const pad = (n: number) => new Array((4 - (n % 4)) % 4).fill(0);
  const option = (code: number, value: number[]) => [...u16(code), ...u16(value.length), ...value, ...pad(value.length)];

  // SHB: byte-order magic, version 1.0, unknown section length, shb_userappl.
  blocks.push(block(0x0a0d0d0a, [
    ...u32(0x1a2b3c4d), ...u16(1), ...u16(0), ...u64(0xffffffff * 2 ** 32 + 0xffffffff),
    ...option(4, [...'walker'].map((c) => c.charCodeAt(0))), ...u16(0), ...u16(0),
  ]));
  // IDB: Ethernet, snaplen 0 (whole frames), if_name.
  blocks.push(block(0x00000001, [
    ...u16(1), ...u16(0), ...u32(0),
    ...option(2, [...'eth9'].map((c) => c.charCodeAt(0))), ...u16(0), ...u16(0),
  ]));
  if (secrets !== undefined) {
    const text = [...new TextEncoder().encode(secrets)];
    blocks.push(block(0x0000000a, [
      ...u32(DSB_SECRETS_TYPE_TLS_KEY_LOG), ...u32(text.length), ...text, ...pad(text.length),
    ]));
  }
  for (let i = 0; i < count; i++) {
    const data = [...frameBytes(i)];
    blocks.push(block(0x00000006, [
      ...u32(0), ...u32(0), ...u32(1_000_000 + i), ...u32(data.length), ...u32(data.length),
      ...data, ...pad(data.length),
    ]));
  }
  // ISB, last: the interface's counters, which no frame precedes.
  blocks.push(block(0x00000005, [
    ...u32(0), ...u32(0), ...u32(0),
    ...option(4, u64(1234)), ...option(5, u64(56)), ...u16(0), ...u16(0),
  ]));

  const out = new Uint8Array(blocks.reduce((n, b) => n + b.length, 0));
  let at = 0;
  for (const b of blocks) { out.set(b, at); at += b.length; }
  return out;
}

/** Every frame of one pass, with the pass left to run to its end. */
const collect = (pass: Iterable<ExtractedFrame>): ExtractedFrame[] => [...pass];

function sameFrames(name: string, walked: ExtractedFrame[], expected: ExtractedFrame[]): void {
  check(`${name}: same count`, walked.length, expected.length);
  walked.forEach((frame, i) => {
    const want = expected[i];
    check(`${name}: frame ${i + 1} fields`, {
      raw: [...frame.rawBytes], ts: frame.tsNanos, origLen: frame.origLen,
      precision: frame.tsPrecision, linktype: frame.linktype,
    }, {
      raw: [...want.rawBytes], ts: want.tsNanos, origLen: want.origLen,
      precision: want.tsPrecision, linktype: want.linktype,
    });
  });
}

// --- classic pcap -------------------------------------------------------------

const classicBytes = pcapOf([0, 1, 2, 3, 4].map(frameBytes));
const classic = bufferOf(classicBytes);
const classicExtracted = await PcapService.extractFrames(asFile(classicBytes, 'five.pcap'), Number.POSITIVE_INFINITY);
{
  const walk = PcapService.frameWalk(classic);
  check('classic: before a pass, nothing is claimed', [walk.totalFrames, walk.facts.interfaces.length], [0, 0]);
  const frames = collect(walk.frames());
  sameFrames('classic', frames, classicExtracted.frames);
  check('classic: totalFrames', walk.totalFrames, 5);
  check('classic: facts match extractFrames', walk.facts, classicExtracted.facts);
  checkTrue('classic: no rawBytes pins the file',
    frames.every((f) => f.rawBytes.buffer !== classic));
}

// --- pcapng, with its ISB last -------------------------------------------------

const ngBytes = pcapngOf(5);
const ng = bufferOf(ngBytes);
const ngExtracted = await PcapService.extractFrames(asFile(ngBytes, 'five.pcapng'), Number.POSITIVE_INFINITY);
{
  const walk = PcapService.frameWalk(ng);
  const frames = collect(walk.frames());
  sameFrames('pcapng', frames, ngExtracted.frames);
  check('pcapng: totalFrames', walk.totalFrames, 5);
  check('pcapng: facts match extractFrames', walk.facts, ngExtracted.facts);
  // Review Focus 1: the ISB is after the last frame, so only a pass that ran to
  // the end can have read it.
  check('pcapng: the trailing ISB contributed',
    [walk.facts.interfaces[0]?.received, walk.facts.interfaces[0]?.dropped, walk.facts.application],
    [1234, 56, 'walker']);
  checkTrue('pcapng: no rawBytes pins the file', frames.every((f) => f.rawBytes.buffer !== ng));
}

// --- passes ---------------------------------------------------------------------

{
  // Review Focus 2: five frames, far below SCORING_FRAMES.
  const walk = PcapService.frameWalk(ng);
  const first = collect(walk.frames());
  const second = collect(walk.frames());
  check('two passes: both yield every frame', [first.length, second.length], [5, 5]);
  sameFrames('two passes: the second equals the first', second, first);
  check('two passes: facts are still complete', walk.facts, ngExtracted.facts);
}
{
  // A prefix pass abandoned early, then the full one.
  const walk = PcapService.frameWalk(ng);
  for (const _frame of walk.frames()) break;
  const full = collect(walk.frames());
  check('abandoned pass: the next one yields every frame', full.length, 5);
  check('abandoned pass: totalFrames', walk.totalFrames, 5);
  check('abandoned pass: facts are complete', walk.facts, ngExtracted.facts);
}

// --- a truncated trailing record -------------------------------------------------

{
  // Review Focus 4: the last header claims 1000 bytes and 10 follow.
  const good = pcapOf([0, 1, 2].map(frameBytes));
  const torn = new Uint8Array(good.length + 16 + 10);
  torn.set(good);
  const view = new DataView(torn.buffer);
  view.setUint32(good.length + 8, 1000, true);
  view.setUint32(good.length + 12, 1000, true);
  const expected = await PcapService.extractFrames(asFile(torn, 'torn.pcap'), Number.POSITIVE_INFINITY);
  const walk = PcapService.frameWalk(bufferOf(torn));
  const frames = collect(walk.frames());
  sameFrames('truncated record', frames, expected.frames);
  check('truncated record: totalFrames', [walk.totalFrames, expected.totalFrames], [3, 3]);
}

// --- laziness --------------------------------------------------------------------

{
  const three = bufferOf(pcapOf([0, 1, 2].map(frameBytes)));
  const walk = PcapService.frameWalk(three);
  const pass = walk.frames();
  const one = pass.next();
  // Frame 2's data starts after the header (24), frame 1 (16 + 20) and its own header (16).
  const secondAt = 24 + 16 + frameBytes(0).length + 16;
  const before = new Uint8Array(three)[secondAt];
  new Uint8Array(three)[secondAt] = (before + 1) & 0xff;
  const two = pass.next();
  check('lazy: frame 1 was cut before the file changed', one.value?.rawBytes[0], frameBytes(0)[0]);
  check('lazy: frame 2 is cut when it is pulled', two.value?.rawBytes[0], (before + 1) & 0xff);
}

// --- extractFrames still caps -------------------------------------------------------

{
  const capped = await PcapService.extractFrames(asFile(classicBytes, 'five.pcap'), 3);
  check('extractFrames(file, 3): three frames', capped.frames.length, 3);
  check('extractFrames(file, 3): the total is still the file\'s', capped.totalFrames, 5);
  const cappedNg = await PcapService.extractFrames(asFile(ngBytes, 'five.pcapng'), 3);
  check('extractFrames(pcapng, 3): three frames, five counted', [cappedNg.frames.length, cappedNg.totalFrames], [3, 5]);
  check('extractFrames(pcapng, 3): facts are the whole file\'s', cappedNg.facts, ngExtracted.facts);
}

// --- a limited pass cuts no frame past its limit -------------------------------------

for (const [format, buffer] of [['classic', classic], ['pcapng', ng]] as const) {
  // Counted at the cut itself: past the limit only record headers are read.
  const walk = PcapService.frameWalk(buffer);
  const slice = ArrayBuffer.prototype.slice;
  let cuts = 0;
  ArrayBuffer.prototype.slice = function (this: ArrayBuffer, ...args: [number?, number?]) {
    cuts++;
    return slice.apply(this, args);
  };
  let frames: ExtractedFrame[];
  try {
    frames = collect(walk.frames(3));
  } finally {
    ArrayBuffer.prototype.slice = slice;
  }
  check(`${format} frames(3): three yielded, three cut, five counted`,
    [frames.length, cuts, walk.totalFrames], [3, 3, 5]);
}

// --- a DSB reaches the key log once per walk ------------------------------------------

{
  // A streamed import takes a prefix pass for the host and then the full one;
  // the secrets block is ahead of both, and its malformed line counts once.
  const secrets = pcapngOf(5, 'NOT A KEY LOG LINE\n');
  keyLog.clear();
  const walk = PcapService.frameWalk(bufferOf(secrets));
  collect(walk.frames());
  collect(walk.frames());
  check('DSB: two passes over one walk count its bad line once', keyLog.stats().ignored, 1);
  keyLog.clear();
  await PcapService.streamCaptureFile(asFile(secrets, 'secrets.pcapng'), () => {});
  check('DSB: a streamed import counts its bad line once', keyLog.stats().ignored, 1);
  keyLog.clear();
}

console.log(failures === 0
  ? '\nAll frame walk checks passed.'
  : `\n${failures} frame walk check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
