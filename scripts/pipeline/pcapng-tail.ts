/**
 * The catch-up reader on its own (ADR 0053 phase 4, `pcapngTail.ts`).
 *
 *   npx tsx scripts/pipeline/pcapng-tail.ts
 *
 * Files are written here as the agent writes them - a section header, one
 * IDB, EPBs with no options - and read back in the pieces catch-up reads,
 * from one 16 MB read down to seven bytes. Every frame must come out as it
 * was written: its bytes, its lengths, and its time, which this script works
 * out with BigInt from the ticks it wrote, on both of the agent's clocks and
 * on two the agent never writes. A frame's bytes must be a view into the read
 * they came in, never a copy of their own: per-frame copies, and copying what
 * was left of a 16 MB read every megabyte, were what made catch-up slower
 * than live.
 *
 * `scripts/pipeline/catch-up.ts` reads the same reader through the whole
 * catch-up, with holes; this is the reader's arithmetic and its memory.
 */
import { PcapngTail, type TailFrame } from '../../src/services/pipeline/pcapngTail';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const MB = 1024 * 1024;

// --- writing files as the agent does ------------------------------------------------

interface Written { ticks: bigint; bytes: Uint8Array; origLen: number }

function sectionHeader(): Uint8Array {
  const out = new Uint8Array(28);
  const v = new DataView(out.buffer);
  v.setUint32(0, 0x0a0d0d0a, true); v.setUint32(4, 28, true); v.setUint32(8, 0x1a2b3c4d, true);
  v.setUint16(12, 1, true); v.setUint16(14, 0, true);
  v.setBigInt64(16, -1n, true); v.setUint32(24, 28, true);
  return out;
}

/** An Ethernet IDB; `tsresol` is the `if_tsresol` byte, or none (microseconds). */
function interfaceBlock(tsresol: number | null): Uint8Array {
  const length = 16 + (tsresol === null ? 0 : 8) + 4 + 4;
  const out = new Uint8Array(length);
  const v = new DataView(out.buffer);
  v.setUint32(0, 1, true); v.setUint32(4, length, true);
  v.setUint16(8, 1, true); v.setUint16(10, 0, true); v.setUint32(12, 0, true);
  let o = 16;
  if (tsresol !== null) { v.setUint16(o, 9, true); v.setUint16(o + 2, 1, true); v.setUint8(o + 4, tsresol); o += 8; }
  v.setUint16(o, 0, true); v.setUint16(o + 2, 0, true);
  v.setUint32(length - 4, length, true);
  return out;
}

function packetBlock(frame: Written): Uint8Array {
  const pad = (4 - (frame.bytes.length % 4)) % 4;
  const length = 32 + frame.bytes.length + pad;
  const out = new Uint8Array(length);
  const v = new DataView(out.buffer);
  v.setUint32(0, 6, true); v.setUint32(4, length, true);
  v.setUint32(8, 0, true);
  v.setUint32(12, Number(frame.ticks >> 32n), true); v.setUint32(16, Number(frame.ticks & 0xffffffffn), true);
  v.setUint32(20, frame.bytes.length, true); v.setUint32(24, frame.origLen, true);
  out.set(frame.bytes, 28);
  v.setUint32(length - 4, length, true);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) { out.set(p, at); at += p.length; }
  return out;
}

function fileOf(tsresol: number | null, frames: Written[]): { file: Uint8Array; blockEnds: number[] } {
  const parts = [sectionHeader(), interfaceBlock(tsresol)];
  let at = parts[0].length + parts[1].length;
  const blockEnds = [at];
  for (const f of frames) {
    const block = packetBlock(f);
    parts.push(block);
    at += block.length;
    blockEnds.push(at);
  }
  return { file: concat(parts), blockEnds };
}

function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 0x1_0000_0000; };
}

function bytesOf(random: () => number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = Math.floor(random() * 256);
  return out;
}

// --- reading them back ------------------------------------------------------------------

/**
 * Pushes `file` from wherever the reader says up to `end(readOffset)`, and
 * takes every frame. A block is taken only whole from one read, so a read
 * that ends inside one is read again from its start next time.
 */
function readAll(file: Uint8Array, end: (readOffset: number) => number): TailFrame[] {
  const tail = new PcapngTail(0);
  const got: TailFrame[] = [];
  for (let guard = 0; guard < 10_000_000; guard++) {
    let f;
    while ((f = tail.next()) !== null) got.push(f);
    if (tail.readOffset >= file.length) break;
    tail.push(file.subarray(tail.readOffset, Math.min(file.length, end(tail.readOffset))));
  }
  return got;
}

/**
 * The first way `got` differs from what was written, or null. The time is
 * the written ticks times the clock's nanoseconds a tick, split as the live
 * stream carries it - worked out here with BigInt, which is exact.
 */
function differs(want: Written[], nsPerTick: bigint, got: TailFrame[]): string | null {
  if (got.length !== want.length) return `${got.length} frames read, ${want.length} written`;
  for (let i = 0; i < want.length; i++) {
    const w = want[i];
    const g = got[i];
    const ns = w.ticks * nsPerTick;
    const tsUs = Number(ns / 1000n);
    const tsNsRem = Number(ns % 1000n);
    if (g.tsUs !== tsUs || g.tsNsRem !== tsNsRem) return `frame ${i}: ticks ${w.ticks} read as ${g.tsUs}.${g.tsNsRem}, written ${tsUs}.${tsNsRem}`;
    if (g.idb !== 0 || g.origLen !== w.origLen || g.capLen !== w.bytes.length) return `frame ${i}: idb ${g.idb}, origLen ${g.origLen}, capLen ${g.capLen}`;
    if (g.bytes.length !== w.bytes.length) return `frame ${i}: ${g.bytes.length} bytes, ${w.bytes.length} written`;
    for (let j = 0; j < w.bytes.length; j++) if (g.bytes[j] !== w.bytes[j]) return `frame ${i}: byte ${j} differs`;
  }
  return null;
}

// --- the time, on every clock ----------------------------------------------------------

/**
 * Ticks for a clock, each a frame: the edges of the EPB's two 32-bit words,
 * and random ticks across everything whose time fits a Number of
 * microseconds (2^53, the year 2255) - the reader is exact that far.
 */
function ticksFor(nsPerTick: bigint, around: bigint, seed: number): bigint[] {
  const most = ((1n << 53n) * 1000n) / nsPerTick;
  const high = around >> 32n;
  const out = [
    0n, 1n, 999n, 1000n, 1001n, 0xffffffffn, 0x1_0000_0000n, 0x1_0000_0001n,
    around, around - (around % 1000n), around - (around % 1000n) + 999n,
    high << 32n, (high << 32n) | 1n, (high << 32n) | 0xffffffffn,
    most - 1n,
  ];
  const random = rng(seed);
  const highMost = Number(most >> 32n);
  for (let i = 0; i < 4000; i++) {
    const h = BigInt(Math.floor(random() * highMost));
    const l = BigInt(Math.floor(random() * 0x1_0000_0000));
    out.push((h << 32n) | l);
  }
  return out;
}

const clocks: { label: string; tsresol: number | null; nsPerTick: bigint; around: bigint }[] = [
  { label: 'ns clock (if_tsresol 9)', tsresol: 9, nsPerTick: 1n, around: 1_790_000_000_123_456_789n },
  { label: 'µs clock (no if_tsresol)', tsresol: null, nsPerTick: 1000n, around: 1_790_000_000_123_456n },
  { label: 'ms clock, which the agent never writes (if_tsresol 3)', tsresol: 3, nsPerTick: 1_000_000n, around: 1_790_000_000_123n },
  // 2^-10 s: the reader rounds 1e9 / 1024 to whole nanoseconds.
  { label: 'a power-of-two clock, which the agent never writes (if_tsresol 0x8a)', tsresol: 0x8a, nsPerTick: 976_563n, around: 1_832_960_000_000n },
];
for (const [i, clock] of clocks.entries()) {
  const random = rng(100 + i);
  const frames: Written[] = ticksFor(clock.nsPerTick, clock.around, 200 + i).map((ticks) => {
    const bytes = bytesOf(random, 60);
    return { ticks, bytes, origLen: 60 };
  });
  const { file } = fileOf(clock.tsresol, frames);
  const why = differs(frames, clock.nsPerTick, readAll(file, () => file.length));
  check(`timestamps: ${clock.label} - every frame's tsUs and tsNsRem as BigInt gives them (${frames.length.toLocaleString('en-US')} frames)`, why === null, why ?? '');
}

// --- the pieces catch-up reads ---------------------------------------------------------------

// More than one 16 MB read of frames 60-1,514 bytes long, on the agent's
// nanosecond clock, a few microseconds apart.
const big: Written[] = [];
{
  const random = rng(7);
  let ticks = 1_790_000_000_000_000_000n;
  let size = 0;
  while (size < 20 * MB) {
    const length = 60 + Math.floor(random() * 1455);
    const bytes = bytesOf(random, length);
    ticks += BigInt(1 + Math.floor(random() * 20_000));
    big.push({ ticks, bytes, origLen: length + (big.length % 7 === 0 ? 40 : 0) });
    size += 32 + length;
  }
}
const { file: bigFile, blockEnds } = fileOf(9, big);
const count = `${big.length.toLocaleString('en-US')} frames, ${(bigFile.length / MB).toFixed(1)} MB`;

{
  const why = differs(big, 1n, readAll(bigFile, (at) => at + 16 * MB));
  check(`chunks: 16 MB reads, each ending inside a block - every frame once, as written (${count})`, why === null, why ?? '');
}
{
  const random = rng(8);
  const why = differs(big, 1n, readAll(bigFile, (at) => at + 1 + Math.floor(random() * 65_536)));
  check(`chunks: reads of 1-65,536 bytes, at random - every frame once, as written (${count})`, why === null, why ?? '');
}
{
  // A file growing seven bytes at a time over the first frames, read to its
  // end each time: blocks cut everywhere, each read again until it is whole.
  const few = big.slice(0, 400);
  const { file } = fileOf(9, few);
  let written = 0;
  const why = differs(few, 1n, readAll(file, () => (written += 7)));
  check('chunks: a file growing seven bytes at a time - every frame once, as written', why === null, why ?? '');
}
{
  // Whole blocks only, so the reader holds nothing between pushes; every
  // frame is compared only once the whole file is read, so a reader that
  // put a later read where an earlier one's frames still point is caught.
  const random = rng(9);
  const tail = new PcapngTail(0);
  const got: TailFrame[] = [];
  let block = 0;
  while (tail.readOffset < bigFile.length) {
    block = Math.min(blockEnds.length - 1, block + 1 + Math.floor(random() * 50));
    tail.push(bigFile.subarray(tail.readOffset, blockEnds[block]));
    let f;
    while ((f = tail.next()) !== null) got.push(f);
  }
  const why = differs(big, 1n, got);
  check(`frames stay as read: whole blocks a push, every frame compared only when all are read (${count})`, why === null, why ?? '');
}
{
  // Windows extends a file before its writer fills it: a 16 MB read can end
  // in zeros where the next frames will be. Read then, and again once
  // written, every frame comes out once, as written.
  const cut = blockEnds[Math.floor(blockEnds.length / 3)] + 37;
  const early = bigFile.slice(0, 16 * MB);
  early.fill(0, cut);
  const tail = new PcapngTail(0);
  const got: TailFrame[] = [];
  let f;
  tail.push(early);
  while ((f = tail.next()) !== null) got.push(f);
  const afterEarly = got.length;
  while (tail.readOffset < bigFile.length) {
    tail.push(bigFile.subarray(tail.readOffset, tail.readOffset + 16 * MB));
    while ((f = tail.next()) !== null) got.push(f);
  }
  const why = differs(big, 1n, got);
  check('chunks: a 16 MB read that ends in a writer\'s zeros, read again once written - every frame once, as written',
    why === null && afterEarly === Math.floor(blockEnds.length / 3), why ?? `${afterEarly} frames before the zeros`);
}

// --- what a frame costs -------------------------------------------------------------------

{
  // One read, all of whose frames are views into it: no copy a frame, and no
  // copying what is left of the read as it is consumed.
  const tail = new PcapngTail(0);
  tail.push(bigFile.subarray(0, 16 * MB));
  const got: TailFrame[] = [];
  let f;
  while ((f = tail.next()) !== null) got.push(f);
  const shared = got.length > 0 ? got[0].bytes.buffer : null;
  const own = got.filter((g) => g.bytes.buffer !== shared).length;
  check(`views: every frame of one 16 MB read is a view into one buffer, capLen long (${got.length.toLocaleString('en-US')} frames)`,
    got.length > 10_000 && own === 0 && got.every((g) => g.bytes.byteLength === g.capLen),
    `${own} of ${got.length} frames hold a buffer of their own`);
}
{
  const tail = new PcapngTail(0);
  tail.push(bigFile.subarray(0, 4 * MB));
  const got: TailFrame[] = [];
  let f;
  while ((f = tail.next(false)) !== null) got.push(f);
  check('skip: next(false) gives no bytes and the frame\'s captured length',
    got.length > 1000 && got.every((g, i) => g.bytes.length === 0 && g.capLen === big[i].bytes.length));
}

console.log(failures === 0 ? '\nAll reader checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
