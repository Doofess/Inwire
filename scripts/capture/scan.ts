/**
 * A filter over a capture that is not in memory.
 *
 *   npx tsx scripts/capture/scan.ts
 *
 * The property that matters is not that the scan is fast. It is that it gives
 * **the same answer** as the filter the reader already trusts: the frames it
 * marks must be exactly the frames `filter/compile.ts` matches when the same
 * capture is in RAM. A scan that quietly disagreed would do so only on the
 * frames nobody can see to check, which is the worst possible place.
 *
 * So every filter below is run twice - once through `CaptureScan` over frames
 * written to disk and read back, once as a plain loop over the same packets in
 * memory - and the two ordinal lists are compared exactly. Not counts: two
 * different sets can have the same size.
 *
 * The rest is about the shape a caller depends on: a scan is sliced, so it
 * must reach the same answer however the slices fall; it is cancellable, and a
 * cancelled scan must hand back nothing rather than a partial answer that
 * looks whole; and it is a snapshot, so it must not be moved by a chunk sealed
 * after it started.
 *
 * The last section is a **measurement**, printed rather than asserted. It is
 * what decides whether the prefix-block accelerator the plan costed is worth
 * building - see the module header of `captureScan.ts` for why there is one
 * evaluator today and what the rule for a second one would have to be.
 */
import { existsSync, readFileSync } from 'node:fs';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import { CaptureWriter, type CaptureFiles } from '../../src/services/capture/captureWriter';
import { CaptureReader } from '../../src/services/capture/captureReader';
import { CaptureScan } from '../../src/services/capture/captureScan';
import { MemoryBlockFile } from '../../src/services/capture/blockFile';
import { CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { compile } from '../../src/services/filter/compile';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }

const deflate = (b: Uint8Array): Uint8Array => new Uint8Array(deflateRawSync(b));
const inflate = (b: Uint8Array): Uint8Array => new Uint8Array(inflateRawSync(b));

function files(): CaptureFiles {
  return {
    index: new MemoryBlockFile(),
    pfx: new MemoryBlockFile(),
    sum: new MemoryBlockFile(),
    byt: new MemoryBlockFile(),
    rec: new MemoryBlockFile(),
  };
}

/** Writes a capture and hands back a reader over it, as the worker builds one. */
function store(packets: readonly Packet[], batch = 1000) {
  const f = files();
  const writer = new CaptureWriter(f, { deflate, horizonUs: 0 });
  for (let i = 0; i < packets.length; i += batch) writer.append(packets.slice(i, i + batch));
  writer.finish();
  return { writer, reader: new CaptureReader(f, writer.index, inflate) };
}

/** Every ordinal a `MatchSet` holds, which is what gets compared. */
function ordinals(set: { count(): number; ordinalAt(k: number): number }): number[] {
  const out: number[] = [];
  for (let k = 0; k < set.count(); k++) out.push(set.ordinalAt(k));
  return out;
}

/** The same question asked of the packets directly. The oracle. */
function inMemory(packets: readonly Packet[], expression: string): number[] {
  const predicate = compile(expression);
  const out: number[] = [];
  for (let i = 0; i < packets.length; i++) if (predicate(packets[i])) out.push(i);
  return out;
}

function frame(id: number, over: Partial<Packet> = {}): Packet {
  return {
    id,
    source: '10.0.0.4',
    destination: '93.184.216.34',
    protocol: 'TCP',
    info: `frame ${id}`,
    status: 'ok',
    length: 100 + (id % 900),
    tsUs: 1_788_000_000_000_000 + id * 1000,
    relativeTime: id / 1000,
    timeDelta: 0.001,
    interfaceName: 'eth0',
    layers: [],
    rawBytes: new Uint8Array(8),
    frameProtocols: ['frame', 'eth', 'ip', 'tcp'],
    sourcePort: 50000 + (id % 3),
    destPort: 443,
    fields: { 'tcp.seq': id },
    ...over,
  } as Packet;
}

console.log('--- the same answer as the filter already gives ---\n');

{
  // A mix, so a filter has something to divide: two thirds TCP to 443, one
  // third UDP to 53, and one frame in fifty from a different host.
  const packets: Packet[] = [];
  for (let i = 1; i <= CHUNK_FRAMES * 2 + 501; i++) {
    packets.push(i % 3 === 0
      ? frame(i, {
          protocol: 'UDP', destPort: 53,
          frameProtocols: ['frame', 'eth', 'ip', 'udp', 'dns'],
        })
      : frame(i, {
          ...(i % 50 === 0 ? { source: '10.0.0.9' } : {}),
        }));
  }
  const { reader, writer } = store(packets);

  for (const expression of [
    'tcp',
    'udp',
    'dns',
    'ip.src == 10.0.0.9',
    'tcp.port == 443',
    'frame.len > 500',
    'tcp && ip.src == 10.0.0.9',
    '!tcp',
    'tcp.seq > 8000',
  ]) {
    const scan = new CaptureScan(reader, writer.index, compile(expression));
    const set = scan.runToCompletion();
    check(`${expression}: exactly the frames the in-memory filter matches`,
      set === null ? null : ordinals(set), inMemory(packets, expression));
  }

  // Two filters nothing and everything matches, because the bitmap's edges are
  // where an off-by-one in the tail-clearing would show.
  const none = new CaptureScan(reader, writer.index, compile('icmp')).runToCompletion();
  check('a filter matching nothing matches nothing', none?.count(), 0);
  const all = new CaptureScan(reader, writer.index, compile('frame')).runToCompletion();
  check('a filter matching everything matches every frame', all?.count(), packets.length);
  check('...including the very last one, which lives in the short tail chunk',
    all?.has(packets.length - 1), true);
  check('...and nothing past it', all?.has(packets.length), false);
}

console.log('\n--- a capture whose chunks are not all 4,096 frames ---\n');

{
  // A capture paused and resumed has a short chunk in the MIDDLE of it, so
  // every chunk after that one starts off a bitmap block boundary. Marking by
  // chunk index instead of by ordinal would not fail here - it would mark the
  // wrong frames.
  const packets = Array.from({ length: CHUNK_FRAMES + 700 }, (_, i) =>
    frame(i + 1, i % 4 === 0 ? { protocol: 'UDP', frameProtocols: ['frame', 'eth', 'ip', 'udp'] } : {}));
  const f = files();
  const writer = new CaptureWriter(f, { deflate, horizonUs: 0 });
  // Paused after 100 frames, so chunk 0 is short and chunk 1 begins at 100.
  writer.append(packets.slice(0, 100));
  writer.finish();
  writer.append(packets.slice(100));
  writer.finish();
  const reader = new CaptureReader(f, writer.index, inflate);

  checkTrue('the capture really does have a short chunk in the middle',
    writer.index.record(0).frameCount === 100 && writer.index.chunkCount > 2);
  const set = new CaptureScan(reader, writer.index, compile('udp')).runToCompletion();
  check('the frames marked are still exactly the frames that match',
    set === null ? null : ordinals(set), inMemory(packets, 'udp'));
}

console.log('\n--- sliced, and the slices cannot change the answer ---\n');

{
  const packets = Array.from({ length: CHUNK_FRAMES * 3 + 11 }, (_, i) =>
    frame(i + 1, i % 7 === 0 ? { protocol: 'UDP', frameProtocols: ['frame', 'eth', 'ip', 'udp'] } : {}));
  const { reader, writer } = store(packets);
  const expected = inMemory(packets, 'udp');

  const whole = new CaptureScan(reader, writer.index, compile('udp')).runToCompletion();
  const sliced = new CaptureScan(reader, writer.index, compile('udp'));
  let slices = 0;
  // A zero budget is the extreme: one chunk per slice, which is the guarantee
  // that a budget smaller than a chunk still makes progress rather than
  // spinning for ever.
  while (sliced.step(0)) slices++;
  check('a scan in one slice and a scan in many agree',
    [ordinals(whole!), ordinals(sliced.matches!)].map((o) => o.join(',')).reduce(
      (a, b) => (a === b ? 'same' : 'different')), 'same');
  check('...and the answer is the one the in-memory filter gives',
    ordinals(sliced.matches!), expected);
  checkTrue('a zero budget still advances a chunk at a time', slices >= 3);

  // Progress is monotonic and ends at the total. A bar that goes backwards is
  // a bar nobody believes the second time.
  const watched = new CaptureScan(reader, writer.index, compile('udp'));
  let last = -1;
  let monotonic = true;
  while (watched.step(0)) {
    const p = watched.progress;
    if (p.framesDone < last) monotonic = false;
    last = p.framesDone;
  }
  checkTrue('progress never goes backwards', monotonic);
  check('...and ends at exactly the frames the capture holds',
    [watched.progress.framesDone, watched.progress.frameCount],
    [packets.length, packets.length]);
  check('...and reports the matches it found', watched.progress.matches, expected.length);
}

console.log('\n--- cancelling, and the snapshot ---\n');

{
  const packets = Array.from({ length: CHUNK_FRAMES * 3 }, (_, i) => frame(i + 1));
  const { reader, writer } = store(packets);

  const scan = new CaptureScan(reader, writer.index, compile('frame'));
  scan.step(0);
  scan.cancel();
  // The load-bearing refusal: a cancelled scan has marked SOME frames, and
  // handing that back would be a filtered list missing everything after the
  // point somebody stopped it - with no error, and no way to tell.
  check('a cancelled scan hands back nothing rather than a partial answer',
    scan.matches, null);
  check('...and says it was cancelled', [scan.progress.done, scan.progress.cancelled], [true, true]);
  check('...and stepping again does nothing', scan.step(0), false);

  // The snapshot. A capture still running grows underneath a scan, and the
  // denominator must not move - a progress bar whose total changes is a bar
  // that can go backwards, and a bitmap sized to a smaller capture would throw
  // on the chunk that arrived after it started.
  const running = new CaptureScan(reader, writer.index, compile('frame'));
  const before = running.frameCount;
  writer.append(Array.from({ length: 50 }, (_, i) => frame(CHUNK_FRAMES * 3 + i + 1)));
  writer.finish();
  running.runToCompletion();
  check('a scan covers the capture as it was when it started',
    [before, running.frameCount, running.matches?.count()],
    [CHUNK_FRAMES * 3, CHUNK_FRAMES * 3, CHUNK_FRAMES * 3]);
}

console.log('\n--- against real frames, and what it costs ---\n');

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
    const { reader, writer } = store(packets, 500);

    for (const expression of ['tcp', 'udp', 'tls', 'dns', 'ip.src == 10.0.0.4', 'tcp.port == 443']) {
      const set = new CaptureScan(reader, writer.index, compile(expression)).runToCompletion();
      const expected = inMemory(packets, expression);
      check(`${name}: "${expression}" matches the same ${expected.length.toLocaleString()} frames`,
        set === null ? null : ordinals(set).length === expected.length
          && ordinals(set).every((o, i) => o === expected[i]), true);
    }

    // The measurement. Decode plus predicate, over every frame, which is what
    // a whole-capture filter costs today.
    const started = performance.now();
    const set = new CaptureScan(reader, writer.index, compile('tcp')).runToCompletion();
    const ms = performance.now() - started;
    const perFrame = (ms * 1000) / packets.length;
    console.log(`      (${name}: ${packets.length.toLocaleString()} frames scanned in `
      + `${ms.toFixed(0)} ms = ${perFrame.toFixed(2)} us/frame; `
      + `${(1_000_000 / perFrame / 1_000_000).toFixed(2)}M frames/s, so a 5 GB capture `
      + `[4.3M frames] is about ${(4_300_000 * perFrame / 1_000_000).toFixed(1)} s. `
      + `${set!.count().toLocaleString()} matched.)`);
  }
}

async function main(): Promise<void> {
  await realFrames();
  console.log(failures === 0
    ? '\nAll capture scan checks passed.'
    : `\n${failures} capture scan check(s) failed.`);
  process.exit(failures === 0 ? 0 : 1);
}

void main();
