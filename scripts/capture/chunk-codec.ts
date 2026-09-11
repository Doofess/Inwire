/**
 * The chunk codec round trip, held to exact equality on real frames.
 *
 *   npx tsx scripts/capture/chunk-codec.ts
 *
 * This is the decisive test of the disk-backed buffer, and it is why the codec
 * is written before anything that uses it. Everything downstream assumes a
 * summary read back from disk is **indistinguishable** from the one the
 * dissector produced - that is the whole reason summaries are persisted rather
 * than re-derived, since re-dissecting a mid-stream frame can produce a
 * *different* Info line and not merely a slower one.
 *
 * So this diffs field by field, in the spirit of `scripts/session/restore.ts`,
 * which already holds the IndexedDB round trip to the same standard. A field
 * that silently narrows - a `bigint` rounded through a f64, an `expert`
 * category dropped, a dense field lost because the codec read `packet.fields`
 * instead of `fieldEntries` - fails here, before a capture exists in the new
 * format and long before anyone has one to migrate.
 *
 * It runs on synthetic frames as well as fixture frames, because the fixtures
 * are two desktop captures and there are shapes they simply do not contain: a
 * nanosecond timestamp, an id hole, a 64 kB offloaded frame, a chunk of one.
 *
 * Skips cleanly without the fixtures (test/fixtures/README.md); the synthetic
 * half always runs.
 */
import { existsSync, readFileSync } from 'node:fs';
import { deflateRawSync, inflateRawSync } from 'node:zlib';
import {
  encodeChunk, decodeChunk, applyPrefixes, PrefixBlock, ChunkDirectory,
  DIRECTORY_BYTES, prefixBlockBytes,
  CHUNK_FRAMES, PREFIX_BYTES, ADDRESS_KIND,
} from '../../src/services/capture/chunkCodec';
import { PcapService } from '../../src/services/pcapParser';
import { fieldEntries } from '../../src/services/dissect/fieldAccess';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = show(actual) === show(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${show(expected)}`);
    console.log(`        actual   ${show(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean): void { check(name, condition, true); }
/**
 * A canonical form for comparison: object keys sorted, bigints tagged.
 *
 * Key INSERTION order is not part of the contract and comparing it is a way to
 * fail on nothing. The dissector happens to build an expert finding as
 * `{category, message}` and the decoder builds `{message, category}`; both are
 * the same finding, and a test that called that a mismatch would send whoever
 * reads it hunting for a data loss that is not there.
 */
function canon(value: unknown): unknown {
  if (typeof value === 'bigint') return `${value}n`;
  if (Array.isArray(value)) return value.map(canon);
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canon((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value;
}
const show = (v: unknown): string => JSON.stringify(canon(v));
function checkThrows(name: string, fn: () => unknown): void {
  let threw = false;
  try { fn(); } catch { threw = true; }
  check(name, threw, true);
}

/**
 * Everything the codec promises to carry.
 *
 * Listed explicitly rather than diffing the whole object, because three fields
 * deliberately do NOT survive and a blanket comparison would either fail on
 * them for ever or be loosened until it caught nothing:
 *
 *  - `layers` is rebuilt on demand (ADR 0007: 10.6 kB against the frame's own
 *    1.2 kB, and only the detail pane reads one);
 *  - `rawBytes` lives in its own stream and comes back through `packetBytes()`;
 *  - `colorSlot` is a cache whose meaning depends on the rule chain in force,
 *    so persisting it would ship a stale colour after an edit.
 */
const CARRIED = [
  'id', 'source', 'destination', 'protocol', 'protocolLabel', 'info', 'status',
  'length', 'tsUs', 'relativeTime', 'timeDelta', 'interfaceName',
  'sourcePort', 'destPort', 'streamId', 'direction', 'tsPrecision', 'tsNanos',
  'frameProtocols', 'analysisFlags', 'expert', 'resolved',
] as const;

/** The shape a round trip is compared on, fields and all. */
function shapeOf(p: Packet): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of CARRIED) out[key] = (p as unknown as Record<string, unknown>)[key];
  // Sorted, because the bag's iteration order is not part of the contract and
  // the dense/sparse split legitimately reorders it.
  out.fields = fieldEntries(p).slice().sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return out;
}

/**
 * The captured lengths a writer would have recorded.
 *
 * Passed explicitly everywhere, exactly as `CaptureWriter` passes them: a
 * packet's own `rawBytes` can be emptied in place by `evictOldBytes` after the
 * writer appended it, so the codec is never allowed to read the length off the
 * packet.
 */
function capLengths(packets: readonly Packet[]): number[] {
  return packets.map((p) => p.rawBytes.byteLength);
}

/** Encode, decode, rejoin the two blocks - the whole path a reader takes. */
function roundTrip(packets: Packet[]): Packet[] {
  const encoded = encodeChunk(packets, capLengths(packets));
  const back = decodeChunk(encoded.summary);
  applyPrefixes(back, encoded.prefix);
  return back;
}

// --- a frame built by hand, so the odd shapes are actually exercised ----------

function frame(over: Partial<Packet> = {}): Packet {
  return {
    id: 1,
    source: '10.0.0.4',
    destination: '93.184.216.34',
    protocol: 'TCP',
    info: '52372 → 443 [ACK] Seq=1 Ack=1 Win=253 Len=0',
    status: 'ok',
    length: 74,
    tsUs: 1_788_477_971_653_284,
    relativeTime: 1.25,
    timeDelta: 0.000_125,
    interfaceName: 'Ethernet 2',
    layers: [],
    rawBytes: new Uint8Array(0),
    ...over,
  } as Packet;
}

console.log('--- the fields a row carries ---\n');

{
  const original = frame();
  const [back] = roundTrip([original]);
  check('a plain frame round-trips exactly', shapeOf(back), shapeOf(original));
}

{
  // Every optional field set at once, including the ones the fixtures never
  // produce together.
  const original = frame({
    id: 40_001,
    protocolLabel: 'TLSv1.3',
    status: 'warning',
    sourcePort: 52372,
    destPort: 443,
    streamId: 17,
    direction: 0b1011,
    tsPrecision: 9,
    tsNanos: 1_788_477_971_653_284_512n,
    frameProtocols: ['frame', 'eth', 'ip', 'tcp', 'tls'],
    analysisFlags: ['retransmission', 'out_of_order'],
    expert: [
      { message: 'This frame is a (suspected) retransmission', category: 'Loss' },
      { message: 'Connection reset (RST)' },
    ],
    resolved: [{ name: 'example.com', addresses: ['93.184.216.34', '2606:2800:220:1:248:1893:25c8:1946'] }],
    fields: { 'tcp.srcport': 52372, 'tcp.flags.syn': 0, 'tls.handshake.type': 1, 'http.host': 'example.com' },
  });
  const [back] = roundTrip([original]);
  check('every optional field survives together', shapeOf(back), shapeOf(original));
  // Called out on its own because it is the one that fails silently: a f64 lane
  // would round the last three digits away and the diff above would still pass
  // on a frame whose tsNanos happened to be a round number.
  check('a nanosecond timestamp keeps all nine digits', back.tsNanos, 1_788_477_971_653_284_512n);
  check('...and is a bigint, not a number', typeof back.tsNanos, 'bigint');
}

{
  // An expert finding with no category must come back with no category, not
  // with the default filled in - the default belongs to the reader, and baking
  // it in here would make two different frames indistinguishable.
  const original = frame({ expert: [{ message: 'No category on this one' }] });
  const [back] = roundTrip([original]);
  check('an expert finding without a category stays without one',
    Object.prototype.hasOwnProperty.call(back.expert![0], 'category'), false);
}

{
  // Absent is not the same as zero, and the codec must not turn one into the
  // other. `tcp.flags.syn == 0` is a real filter and so is "this frame has no
  // ports at all".
  const original = frame({ protocol: 'ARP', source: '00:1a:2b:3c:4d:5e', destination: 'Broadcast' });
  const [back] = roundTrip([original]);
  check('a frame with no ports has no ports after the trip',
    [back.sourcePort, back.destPort, back.streamId], [undefined, undefined, undefined]);
  check('...and its MAC source is unchanged', back.source, '00:1a:2b:3c:4d:5e');
  check('...as is a destination that is a name, not an address', back.destination, 'Broadcast');
}

{
  const original = frame({ fields: { 'tcp.flags.syn': 0, 'tcp.window_size': 0, 'ip.ttl': 0 } });
  const [back] = roundTrip([original]);
  check('a field whose value is zero is still present', shapeOf(back).fields, shapeOf(original).fields);
}

console.log('\n--- chunk shapes ---\n');

{
  const one = roundTrip([frame()]);
  check('a chunk of one frame', one.length, 1);

  const full = Array.from({ length: CHUNK_FRAMES }, (_, i) => frame({ id: i + 1 }));
  const back = roundTrip(full);
  check('a chunk of exactly CHUNK_FRAMES frames', back.length, CHUNK_FRAMES);
  check('...in order, with ids intact', [back[0].id, back[CHUNK_FRAMES - 1].id], [1, CHUNK_FRAMES]);

  checkThrows('a chunk past CHUNK_FRAMES is refused rather than silently split',
    () => encodeChunk([...full, frame({ id: CHUNK_FRAMES + 1 })], new Array(CHUNK_FRAMES + 1).fill(0)));
  checkThrows('an empty chunk is refused', () => encodeChunk([], []));
}

{
  // A frame that fails to dissect burns an id, so ids have holes and nothing
  // may compute a frame's position as `firstId + n`.
  const holed = [frame({ id: 100 }), frame({ id: 101 }), frame({ id: 105 }), frame({ id: 999 })];
  const back = roundTrip(holed);
  check('ids with holes survive and are never re-derived from the first',
    back.map((p) => p.id), [100, 101, 105, 999]);
}

{
  // Segmentation offload hands the sniffer frames far past the MTU.
  const jumbo = frame({ length: 65_535, info: 'x'.repeat(4096) });
  const [back] = roundTrip([jumbo]);
  check('a 64 kB offloaded frame keeps its length', back.length, 65_535);
  check('...and a very long Info line', back.info.length, 4096);
}

console.log('\n--- the prefix block, which filters read on its own ---\n');

{
  const packets = [
    frame({ id: 1, source: '10.0.0.4', destination: '93.184.216.34', sourcePort: 52372, destPort: 443,
      frameProtocols: ['frame', 'eth', 'ip', 'tcp'], analysisFlags: ['retransmission'], status: 'warning' }),
    frame({ id: 2, source: '2606:4700::6810:f9f9', destination: 'fe80::1', protocol: 'UDP',
      frameProtocols: ['frame', 'eth', 'ipv6', 'udp', 'quic'] }),
    frame({ id: 3, source: '00:1a:2b:3c:4d:5e', destination: 'Broadcast', protocol: 'ARP',
      frameProtocols: ['frame', 'eth', 'arp'] }),
  ];
  const encoded = encodeChunk(packets, capLengths(packets));
  check('the prefix block is records then directory, both fixed width',
    encoded.prefix.length, prefixBlockBytes(packets.length));
  check('...which is the records plus DIRECTORY_BYTES a frame',
    encoded.prefix.length, packets.length * (PREFIX_BYTES + DIRECTORY_BYTES));

  const block = new PrefixBlock(encoded.prefix, packets.length);
  check('it reports its own frame count', block.frameCount, 3);
  check('ports read straight out of it', [block.srcPort(0), block.dstPort(0)], [52372, 443]);
  check('so does the status', block.status(0), 'warning');
  check('so does the timestamp', block.tsUs(0), packets[0].tsUs);

  // The bareword filter, which is the most common filter there is, answered
  // without decoding a single string.
  check('a bareword layer test is answered from the bitmap',
    [block.hasLayer(0, 'tcp'), block.hasLayer(0, 'udp'), block.hasLayer(1, 'quic')],
    [true, false, true]);
  // The network reviewer's point: without this a read-back frame does not match
  // the filter you use to FIND retransmissions.
  check('a tcp.analysis flag is answered from the bitmap',
    [block.hasAnalysisFlag(0, 'retransmission'), block.hasAnalysisFlag(0, 'out_of_order')],
    [true, false]);

  check('an IPv4 address is parsed into the accelerator',
    [block.srcKind(0), Array.from(block.address(0, 'src').subarray(0, 4))],
    [ADDRESS_KIND.IPV4, [10, 0, 0, 4]]);
  check('an IPv6 address expands its ::',
    [block.srcKind(1), Array.from(block.address(1, 'src').subarray(0, 4))],
    [ADDRESS_KIND.IPV6, [0x26, 0x06, 0x47, 0x00]]);
  check('...including the tail after the ::',
    Array.from(block.address(1, 'src').subarray(12)), [0x68, 0x10, 0xf9, 0xf9]);
  check('a MAC is recognised as a MAC, not a broken address',
    [block.srcKind(2), Array.from(block.address(2, 'src').subarray(0, 6))],
    [ADDRESS_KIND.MAC, [0x00, 0x1a, 0x2b, 0x3c, 0x4d, 0x5e]]);
  // A resolved name has nothing an address comparison can use, and saying so is
  // the difference between "no match" and "matched the wrong thing".
  check('a name is marked as text rather than parsed into nonsense',
    block.dstKind(2), ADDRESS_KIND.TEXT);
}

console.log('\n--- the byte directory, which is how a byte read finds a frame ---\n');

{
  // Real-ish lengths: an ACK, a full segment, an offloaded frame, and a frame
  // the agent sent with no bytes at all.
  const packets = [
    frame({ id: 10 }), frame({ id: 11 }), frame({ id: 14 }), frame({ id: 15 }),
  ];
  const lengths = [66, 1514, 24_000, 0];
  const encoded = encodeChunk(packets, lengths);
  const dir = new ChunkDirectory(encoded.prefix, packets.length);

  check('every captured length comes back',
    [dir.capLength(0), dir.capLength(1), dir.capLength(2), dir.capLength(3)], lengths);
  check('offsets are the running sum, because the writer appended contiguously',
    [dir.offset(0), dir.offset(1), dir.offset(2), dir.offset(3)], [0, 66, 1580, 25_580]);
  check('the extent is the whole chunk, which the index record must agree with',
    dir.totalBytes, 25_580);
  check('a frame with no bytes takes no space and does not shift the next one',
    dir.offset(3) + dir.capLength(3), dir.totalBytes);

  check('the gap lane sums back to the ids it was made from',
    [dir.id(0), dir.id(1), dir.id(2), dir.id(3)], [10, 11, 14, 15]);
  check('a frame is found by id, not by position',
    [dir.indexOfId(10), dir.indexOfId(14), dir.indexOfId(15)], [0, 2, 3]);
  // The trap the id lane exists for: `id - firstId` answers 2 for id 12, which
  // is not a frame at all, and hands back frame 14's bytes.
  check('an id in a hole is refused rather than answered with its neighbour',
    [dir.indexOfId(12), dir.indexOfId(13)], [-1, -1]);
  check('an id outside the chunk is refused at both ends',
    [dir.indexOfId(9), dir.indexOfId(16)], [-1, -1]);
}

{
  // A full chunk, which is where a u16 count or a 16-bit offset would break.
  const full = Array.from({ length: CHUNK_FRAMES }, (_, i) => frame({ id: i * 2 + 1 }));
  const lengths = full.map((_, i) => 60 + (i % 1400));
  const dir = new ChunkDirectory(encodeChunk(full, lengths).prefix, CHUNK_FRAMES);
  const expected = lengths.reduce((a, b) => a + b, 0);
  check("a full chunk's extent is exact past 64 kB", dir.totalBytes, expected);
  check('...and its last frame is where the running sum says',
    dir.offset(CHUNK_FRAMES - 1), expected - lengths[CHUNK_FRAMES - 1]);
  check('...and every id in it is findable',
    [dir.indexOfId(1), dir.indexOfId(4095), dir.indexOfId(CHUNK_FRAMES * 2 - 1)],
    [0, 2047, CHUNK_FRAMES - 1]);
  check('...while every even id is a hole', dir.indexOfId(4096), -1);
}


console.log('\n--- refusals ---\n');

{
  const encoded = encodeChunk([frame()], [0]);
  checkThrows('a summary with the wrong magic is refused',
    () => { const bad = encoded.summary.slice(); bad[0] ^= 0xff; return decodeChunk(bad); });
  checkThrows('a version this build does not read is refused',
    () => { const bad = encoded.summary.slice(); bad[4] = 99; return decodeChunk(bad); });
  checkThrows('a truncated summary is refused rather than half-decoded',
    () => decodeChunk(encoded.summary.slice(0, encoded.summary.length - 3)));
  checkThrows('trailing bytes after the last frame are refused',
    () => decodeChunk(new Uint8Array([...encoded.summary, 0])));
}

console.log('\n--- against real frames ---\n');

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

    let mismatched = 0;
    let firstBad: { id: number; expected: unknown; actual: unknown } | null = null;
    for (let start = 0; start < packets.length; start += CHUNK_FRAMES) {
      const chunk = packets.slice(start, start + CHUNK_FRAMES);
      const back = roundTrip(chunk);
      if (back.length !== chunk.length) { mismatched += Math.abs(back.length - chunk.length); continue; }
      for (let i = 0; i < chunk.length; i++) {
        const want = shapeOf(chunk[i]);
        const got = shapeOf(back[i]);
        if (show(want) !== show(got)) {
          mismatched++;
          if (firstBad === null) firstBad = { id: chunk[i].id, expected: want, actual: got };
        }
      }
    }
    check(`${name}: every one of ${packets.length.toLocaleString()} frames round-trips exactly`, mismatched, 0);
    if (firstBad !== null) {
      console.log(`        first divergence at frame ${firstBad.id}`);
      console.log(`        expected ${show(firstBad.expected).slice(0, 400)}`);
      console.log(`        actual   ${show(firstBad.actual).slice(0, 400)}`);
    }

    // The two blocks deflate independently, which is the measured reason they
    // are two. Asserted here so a future change that merges them fails.
    const sample = packets.slice(0, Math.min(CHUNK_FRAMES, packets.length));
    const encoded = encodeChunk(sample, capLengths(sample));
    const prefixDeflated = deflateRawSync(encoded.prefix, { level: 6 });
    const summaryDeflated = deflateRawSync(encoded.summary, { level: 6 });
    checkTrue(`${name}: the prefix block survives a deflate round trip`,
      Buffer.compare(Buffer.from(inflateRawSync(prefixDeflated)), Buffer.from(encoded.prefix)) === 0);
    const backFromDisk = decodeChunk(inflateRawSync(summaryDeflated));
    check(`${name}: the summary block survives a deflate round trip`,
      backFromDisk.length, sample.length);
    console.log(`      (${name}: prefix ${(prefixDeflated.length / sample.length).toFixed(1)}`
      + ` + summary ${(summaryDeflated.length / sample.length).toFixed(1)}`
      + ` = ${((prefixDeflated.length + summaryDeflated.length) / sample.length).toFixed(1)} B/frame on disk)`);
  }
}

async function main(): Promise<void> {
  await realFrames();
  console.log();
  if (failures > 0) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All chunk codec checks passed.');
  process.exit(0);
}

void main();
