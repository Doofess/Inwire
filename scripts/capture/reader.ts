/**
 * Reading frame bytes back out of a capture.
 *
 *   npx tsx scripts/capture/reader.ts
 *
 * This is the half of the disk-backed buffer that lets the RAM window let go.
 * `evictOldBytes` drops a frame's bytes only when the store can supply them
 * again, so everything downstream - the hex view, the byte-range highlighter,
 * Follow Stream, export, the detail tree's replay - rests on the read below
 * returning **the same bytes** that went in, for the right frame.
 *
 * The failure this exists to catch is not a crash. It is handing back frame
 * 14's bytes when frame 12 was asked for, which produces a hex dump that
 * dissects, an export that opens in Wireshark, and a lie. So the checks are
 * about identity as much as content:
 *
 *  - ids have **holes** (a frame that fails to dissect burns one), so a
 *    position is never `id - firstId`;
 *  - a frame the agent sent with **no bytes** is absent from the answer rather
 *    than present and empty;
 *  - and the last section reads back every frame of both fixtures and compares
 *    the bytes, which is the only check that would notice an off-by-one that
 *    happened to keep the lengths right.
 */
import { existsSync, readFileSync } from 'node:fs';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { CaptureWriter, type CaptureFiles } from '../../src/services/capture/captureWriter';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

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
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }

const deflate = (b: Uint8Array): Uint8Array => new Uint8Array(deflateRawSync(b));
const inflate = (b: Uint8Array): Uint8Array => new Uint8Array(inflateRawSync(b));

function files(): CaptureFiles & { byt: MemoryBlockFile } {
  return {
    index: new MemoryBlockFile(),
    pfx: new MemoryBlockFile(),
    sum: new MemoryBlockFile(),
    byt: new MemoryBlockFile(),
  };
}

/** A writer and a reader over the same files, as the storage Worker builds them. */
function store(options: { horizonUs?: number } = {}) {
  const f = files();
  const writer = new CaptureWriter(f, { deflate, horizonUs: options.horizonUs ?? 0 });
  return { f, writer, reader: new CaptureReader(f, writer.index, inflate) };
}

/** Bytes that identify the frame they belong to, so a mix-up is visible. */
function bytesFor(id: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = (id * 7 + i) & 0xff;
  return out;
}

function frame(id: number, length = 40, over: Partial<Packet> = {}): Packet {
  return {
    id,
    source: '10.0.0.4',
    destination: '93.184.216.34',
    protocol: 'TCP',
    info: `frame ${id}`,
    status: 'ok',
    length,
    tsUs: 1_000_000_000 + id * 1000,
    relativeTime: id / 1000,
    timeDelta: 0.001,
    interfaceName: 'eth0',
    layers: [],
    rawBytes: bytesFor(id, length),
    ...over,
  } as Packet;
}

console.log('--- the round trip, one frame at a time ---\n');

{
  const { writer, reader } = store();
  const packets = [frame(1), frame(2), frame(3)];
  writer.append(packets);

  check('nothing is readable before a chunk is sealed', reader.readBytes([1]).size, 0);
  writer.finish();

  const back = reader.readBytes([1, 2, 3]);
  check('every frame comes back', back.size, 3);
  check('...with its own bytes, not its neighbour\'s',
    [1, 2, 3].map((id) => Array.from(back.get(id) ?? []).join(',') === Array.from(bytesFor(id, 40)).join(',')),
    [true, true, true]);
  check('an id the capture never held is simply absent', reader.readBytes([99]).size, 0);
  check('an empty request costs nothing', reader.readBytes([]).size, 0);
}

console.log('\n--- ids have holes, and a hole is not a frame ---\n');

{
  const { writer, reader } = store();
  // 4 and 5 failed to dissect and burned their ids, exactly as a real capture
  // does. `id - firstId` would answer 3 for id 4, which is frame 6's row.
  writer.append([frame(1), frame(2), frame(3), frame(6), frame(7)]);
  writer.finish();

  check('the frames that exist read back', reader.readBytes([1, 2, 3, 6, 7]).size, 5);
  check('an id in a hole is absent rather than answered with a neighbour',
    reader.readBytes([4, 5]).size, 0);
  const six = reader.readBytes([6]).get(6);
  check('...and the frame after the hole still gets its own bytes',
    Array.from(six ?? []).slice(0, 4), Array.from(bytesFor(6, 40)).slice(0, 4));
}

console.log('\n--- frames of very different sizes, read out of order ---\n');

{
  const { writer, reader } = store();
  // An ACK, a full segment, an offloaded frame, and a frame the agent sent
  // with no bytes at all. Mixed sizes are what turns an offset slip into
  // garbage rather than into a plausible neighbouring frame.
  const sizes = [66, 1514, 24_000, 0, 128];
  const packets = sizes.map((n, i) => frame(i + 1, n));
  writer.append(packets);
  writer.finish();

  const back = reader.readBytes([5, 3, 1, 2]);
  check('each size comes back at its own length',
    [1, 2, 3, 5].map((id) => back.get(id)?.length),
    [66, 1514, 24_000, 128]);
  check('...and the order they were asked in does not matter',
    [1, 2, 3, 5].map((id) => {
      const want = bytesFor(id, sizes[id - 1]);
      const got = back.get(id);
      return got !== undefined && got.length === want.length
        && got.every((b, i) => b === want[i]);
    }),
    [true, true, true, true]);
  // Absent, not present-and-empty: a caller distinguishes "this frame carried
  // no bytes" from "its bytes are gone", and an empty array says neither.
  check('a frame the agent sent with no bytes is absent', back.has(4), false);
}

console.log('\n--- across chunk boundaries, which is where the offsets are ---\n');

{
  const { writer, reader } = store();
  const total = CHUNK_FRAMES * 3 + 17;
  const packets: Packet[] = [];
  // Deliberately uneven lengths, so a chunk's byte extent is never a multiple
  // of anything and an off-by-one chunk lands nowhere plausible.
  for (let i = 1; i <= total; i++) packets.push(frame(i, 40 + (i % 700)));
  writer.append(packets);
  writer.finish();

  const wanted = [1, CHUNK_FRAMES, CHUNK_FRAMES + 1, CHUNK_FRAMES * 2, total - 1, total];
  const back = reader.readBytes(wanted);
  check('a frame on each side of every boundary reads back',
    wanted.map((id) => {
      const want = bytesFor(id, 40 + (id % 700));
      const got = back.get(id);
      return got !== undefined && got.length === want.length && got.every((b, i) => b === want[i]);
    }),
    [true, true, true, true, true, true]);

  // The whole capture at once, which is what export and Follow Stream do.
  const all = reader.readBytes(packets.map((p) => p.id));
  check('every frame in the capture reads back', all.size, total);
  let exact = true;
  for (const p of packets) {
    const got = all.get(p.id);
    if (got === undefined || got.length !== p.rawBytes.length) { exact = false; break; }
    for (let i = 0; i < got.length; i++) if (got[i] !== p.rawBytes[i]) { exact = false; break; }
    if (!exact) break;
  }
  checkTrue('...byte for byte', exact);
}

console.log('\n--- the rows a restore reads ---\n');

{
  const { writer, reader } = store();
  const packets: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES + 500; i++) {
    packets.push(frame(i, 80, { info: `line ${i}`, protocol: i % 2 === 0 ? 'UDP' : 'TCP' }));
  }
  writer.append(packets);
  writer.finish();

  const first = reader.readRows(0);
  const second = reader.readRows(1);
  check('a chunk comes back whole', [first.length, second.length], [CHUNK_FRAMES, 500]);
  check('...in order, with the ids it was written with',
    [first[0].id, first[CHUNK_FRAMES - 1].id, second[0].id, second[499].id],
    [1, CHUNK_FRAMES, CHUNK_FRAMES + 1, CHUNK_FRAMES + 500]);
  check('...carrying the row the reader saw, not a re-dissection',
    [first[0].info, second[499].info],
    ['line 1', `line ${CHUNK_FRAMES + 500}`]);
  check('...and the prefix block\'s half of it', [first[0].tsUs, first[0].length],
    [packets[0].tsUs, 80]);

  // No bytes: a restored frame is inside the stored range, so `packetBytes()`
  // fetches them when something actually wants them. Sending them with every
  // row would put the whole capture's payload through a structured clone to
  // fill a buffer that drops it again on the first flush.
  check('a row carries no bytes', first[0].rawBytes.length, 0);
  check('...but the same frame\'s bytes are still readable',
    reader.readBytes([1]).get(1)?.length, 80);

  check('a chunk past the end is empty rather than an error', reader.readRows(2).length, 0);
  check('...and so is a negative one', reader.readRows(-1).length, 0);
}

console.log('\n--- what a torn tail does ---\n');

{
  const { f, writer, reader } = store();
  const packets: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES * 2; i++) packets.push(frame(i, 100));
  writer.append(packets);
  writer.finish();

  // The crash the write order permits is data missing under an index record
  // that describes it. A reader must not hand back half a frame, and must not
  // refuse the frames that ARE there because one is not.
  f.byt.truncate(f.byt.size() - 1000);
  const reread = new CaptureReader(f, writer.index, inflate);
  check('a frame inside the truncated span is refused',
    reread.readBytes([CHUNK_FRAMES * 2]).size, 0);
  check('...while a frame before it still reads',
    reread.readBytes([1]).get(1)?.length, 100);
  // Both at once is the case that matters: a Follow Stream spanning the tear.
  check('...and asking for both answers with the one that survived',
    [...reread.readBytes([1, CHUNK_FRAMES * 2]).keys()], [1]);

  // Rows are separate files from bytes, so a byte file cut short costs no rows
  // at all. That is the point of the split: scrolling wants summaries and
  // export wants bytes, and neither drags the other.
  check('a truncated byte file costs no rows', reread.readRows(1).length, CHUNK_FRAMES);
  f.sum.truncate(f.sum.size() - 10);
  check('...while a truncated summary costs that chunk\'s rows and no others',
    [new CaptureReader(f, writer.index, inflate).readRows(1).length,
      new CaptureReader(f, writer.index, inflate).readRows(0).length],
    [0, CHUNK_FRAMES]);
  void reader;
}

console.log('\n--- the bytes a real capture actually holds ---\n');

const FIXTURES: Record<string, string> = {
  inwire: 'test/fixtures/inwire_capture_1788478187989.pcap',
  bulk: 'test/fixtures/bulk_capture_1788426090876.pcap',
};

async function realFrames(): Promise<void> {
 for (const [name, path] of Object.entries(FIXTURES)) {
  if (!existsSync(path)) {
    console.log(`SKIP  ${name}: ${path} not present (test/fixtures/README.md)`);
    continue;
  }
  const buf = readFileSync(path);
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(buf)], 'fixture.pcap'), Number.POSITIVE_INFINITY,
  );
  const packets = parsed.packets;

  const { writer, reader } = store();
  // In flush-sized batches, which is how the frames actually arrive.
  for (let i = 0; i < packets.length; i += 500) writer.append(packets.slice(i, i + 500));
  writer.finish();

  const back = reader.readBytes(packets.map((p) => p.id));
  let mismatches = 0;
  let missing = 0;
  for (const p of packets) {
    if (p.rawBytes.length === 0) continue;         // absent by design, checked above
    const got = back.get(p.id);
    if (got === undefined) { missing++; continue; }
    if (got.length !== p.rawBytes.length) { mismatches++; continue; }
    for (let i = 0; i < got.length; i++) {
      if (got[i] !== p.rawBytes[i]) { mismatches++; break; }
    }
  }
  check(`${name}: every one of ${packets.length.toLocaleString()} frames reads back`, missing, 0);
  check(`${name}: ...and every one of them byte for byte`, mismatches, 0);

  // The scattered case, which is what Follow Stream and a detail-tree click
  // look like: a few hundred frames spread across every chunk.
  const byId = new Map(packets.map((p) => [p.id, p]));
  const scattered = packets.filter((_, i) => i % 97 === 0).map((p) => p.id);
  const some = reader.readBytes(scattered);
  check(`${name}: a scattered read of ${scattered.length} frames answers all of them`,
    some.size, scattered.filter((id) => byId.get(id)!.rawBytes.length > 0).length);
 }
}

async function main(): Promise<void> {
  await realFrames();
  console.log(failures === 0
    ? '\nAll capture reader checks passed.'
    : `\n${failures} capture reader check(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

void main();
