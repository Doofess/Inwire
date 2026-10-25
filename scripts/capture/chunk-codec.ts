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
  encodeChunk, decodeChunk, applyPrefixes, PrefixBlock, ChunkDirectory, chunkStoresLinkType, CHUNK_VERSION,
  ROW_LAYOUT_VERSION, CHUNK_MAGIC, encodePackedChunk, selectRows, type ChunkSlot,
  DIRECTORY_BYTES, prefixBlockBytes,
  CHUNK_FRAMES, PREFIX_BYTES, ADDRESS_KIND, LAYER_BIT_ORDER,
} from '../../src/services/capture/chunkCodec';
import { LAYERS } from '../../src/services/dissect/fieldRegistry';
import { PcapService } from '../../src/services/pcapParser';
import { fieldEntries } from '../../src/services/dissect/fieldAccess';
import { packRows, unpackRows, type RowPack } from '../../src/services/pipeline/rowPack';
import { applyOverlay, type RowOverlay } from '../../src/services/pipeline/rowOverlay';
import { applyInfoPatch } from '../../src/services/dissect/infoPatch';
import type { InfoPatch } from '../../src/services/dissect/types';
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
  'frameProtocols', 'analysisFlags', 'expert', 'resolved', 'linkType',
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
  // The bits are on disk, so their order is frozen apart from LAYERS': a
  // token listed must still be a layer, and the list must fit the 64 bits.
  check('every frozen layer bit names a layer this build has',
    LAYER_BIT_ORDER.filter((t) => !(LAYERS as readonly string[]).includes(t)), []);
  check('the frozen layer bits fit the bitmap', LAYER_BIT_ORDER.length <= 64, true);
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

{
  // The container is one version above what a row is laid out in. Writers go on
  // writing rows as version 2; only a chunk of packs is a version-3 container.
  check('the row layout is 2 and the newest readable container is 3', [ROW_LAYOUT_VERSION, CHUNK_VERSION], [2, 3]);
  const encoded = encodeChunk([frame()], [0]);
  check('encodeChunk writes the row layout by default', encoded.summary[4], ROW_LAYOUT_VERSION);
  checkThrows('a version above the newest container is refused',
    () => { const bad = encoded.summary.slice(); bad[4] = CHUNK_VERSION + 1; return decodeChunk(bad); });
}

console.log('\n--- chunk version 3: shard packs as segments ---\n');

/**
 * Structural equality, written out because the two usual shortcuts both lie
 * here: `JSON.stringify` throws on a bigint and drops a key whose value is
 * undefined, and a key that is present with value undefined is exactly the
 * bug the overlay's undefined `expert` / `tsNanos` must not cause.
 */
function firstDifference(a: unknown, b: unknown, path = ''): string | null {
  if (typeof a === 'bigint' || typeof b === 'bigint') return a === b ? null : `${path}: bigint ${String(a)} vs ${String(b)}`;
  if (a instanceof Uint8Array || b instanceof Uint8Array) {
    if (!(a instanceof Uint8Array && b instanceof Uint8Array)) return `${path}: bytes vs not bytes`;
    if (a.length !== b.length) return `${path}: ${a.length} bytes vs ${b.length}`;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return `${path}[${i}]: byte differs`;
    return null;
  }
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return `${path}: array vs not an array`;
    if (a.length !== b.length) return `${path}: length ${a.length} vs ${b.length}`;
    for (let i = 0; i < a.length; i++) {
      const d = firstDifference(a[i], b[i], `${path}[${i}]`);
      if (d !== null) return d;
    }
    return null;
  }
  if (a !== null && b !== null && typeof a === 'object' && typeof b === 'object') {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    if (ka.join('\u0000') !== kb.join('\u0000')) {
      const only = ka.filter((k) => !kb.includes(k)).concat(kb.filter((k) => !ka.includes(k)));
      return `${path}: keys differ (${only.join(', ')})`;
    }
    for (const k of ka) {
      const d = firstDifference((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k], `${path}.${k}`);
      if (d !== null) return d;
    }
    return null;
  }
  return a === b || (Number.isNaN(a) && Number.isNaN(b)) ? null : `${path}: ${String(a)} vs ${String(b)}`;
}

function sameRows(name: string, actual: readonly Packet[], expected: readonly Packet[]): void {
  let bad = actual.length === expected.length ? 0 : 1;
  let first: string | null = actual.length === expected.length ? null : `length ${actual.length} vs ${expected.length}`;
  for (let i = 0; i < Math.min(actual.length, expected.length); i++) {
    const d = firstDifference(actual[i], expected[i], `row ${i}`);
    if (d !== null) { bad++; first ??= d; }
  }
  check(name, bad, 0);
  if (first !== null) console.log(`        first difference: ${first}`);
}

function sameBytes(name: string, actual: Uint8Array, expected: Uint8Array): void {
  let at = -1;
  if (actual.length !== expected.length) at = Math.min(actual.length, expected.length);
  else for (let i = 0; i < actual.length; i++) if (actual[i] !== expected[i]) { at = i; break; }
  check(name, at, -1);
  if (at >= 0) console.log(`        first differing byte ${at} (row ${Math.floor(at / PREFIX_BYTES)}, offset ${at % PREFIX_BYTES})`);
}

{
  check('the comparison sees a key that is present but undefined', firstDifference({ a: undefined }, {}) !== null, true);
  check('...a bigint that differs', firstDifference({ a: 1n }, { a: 2n }) !== null, true);
  check('...a byte that differs', firstDifference(new Uint8Array([1]), new Uint8Array([2])) !== null, true);
  check('...and calls equal things equal', firstDifference({ a: [1n, 'x', new Uint8Array([3])] }, { a: [1n, 'x', new Uint8Array([3])] }), null);
}

/** A row with a different shape for each residue, so every branch of the codec is on the path. */
function mk(id: number): Packet {
  const k = id % 7;
  const tsUs = 1_788_477_971_000_000 + id * 1_000;
  return frame({
    id,
    tsUs,
    length: 60 + (id % 1400),
    relativeTime: id * 0.001,
    timeDelta: k * 0.0001,
    source: k === 3 ? '2606:2800:220:1::1' : k === 5 ? 'router.local' : `10.0.${(id >> 8) & 255}.${id & 255}`,
    destination: k === 3 ? 'fe80::1' : k === 6 ? '00:1a:2b:3c:4d:5e' : '93.184.216.34',
    protocol: k === 2 ? 'UDP' : 'TCP',
    info: `Seq=${id} Len=${k}`,
    status: k === 4 ? 'warning' : k === 6 ? 'retransmit' : 'ok',
    ...(k === 1 ? { protocolLabel: 'TLSv1.3', direction: 3 } : {}),
    ...(k < 5 ? { sourcePort: 40_000 + k, destPort: 443 } : {}),
    ...(id % 3 === 0 ? { streamId: id } : {}),
    ...(k % 2 === 0 ? { tsNanos: BigInt(tsUs) * 1000n + BigInt(id % 1000), tsPrecision: 9 } : {}),
    ...(id % 5 === 0 ? { linkType: 101 } : {}),
    ...(k !== 3 ? { frameProtocols: ['frame', 'eth', 'ip', 'tcp'] } : {}),
    ...(k === 4 ? { analysisFlags: ['retransmission'] } : k === 0 ? {} : { analysisFlags: [] }),
    ...(k === 2 ? { expert: [{ message: 'Possible loss', category: 'Loss' as const }, { message: 'Bare finding' }] } : {}),
    ...(k === 5 ? { resolved: [{ name: 'router.local', addresses: ['10.0.0.1', 'fe80::1'] }] } : {}),
    ...(k === 0 ? {} : k === 1 ? { fields: {} } : { fields: { 'tcp.srcport': 40_000 + k, 'http.host': `h${k}.example`, 'tcp.seq': id } }),
  });
}

const OVERLAYS: RowOverlay[] = [
  { fields: { 'tls.stream': 3 } },
  { fields: { 'inwire.process.name': 'curl.exe', 'inwire.process.pid': 4242, 'tls.stream': 9 } },
  { fields: {} },
  { expert: [{ message: 'Live gap', category: 'CaptureGap' }, { message: 'Bare' }] },
  { expert: undefined },
  { expert: [] },
  { tsPrecision: 9 },
  { tsPrecision: undefined },
  { tsNanos: 1_788_477_971_653_284_512n },
  { tsNanos: undefined },
  { tsNanos: 5n },
  { tsNanos: 7_000n },
  { fields: { 'inwire.live.skipped': 12 }, expert: [{ message: 'Skipped' }], tsPrecision: 6, tsNanos: 1_788_477_971_000_000_999n },
  { expert: undefined, tsPrecision: undefined, tsNanos: undefined },
  {},
];

const PATCHES: (InfoPatch[] | null)[] = [
  [{ frameId: 0, suffix: ' [TCP PDU reassembled in 99]' }],
  [{ frameId: 0, protocolLabel: 'TLSv1.2' }],
  [{ frameId: 0, responseInFrame: 77 }],
  [{ frameId: 0, links: { 'tcp.reassembled_in': 12, 'ip.reassembled_in': 13 } }],
  [{ frameId: 0, suffix: '[A]', protocolLabel: 'L', responseInFrame: 5, links: { 'icmp.resp_in': 9 } }],
  [{ frameId: 0, suffix: '' }],
  [{ frameId: 0, suffix: ' [one]' }, { frameId: 0, links: { 'tcp.reassembled_in': 4 }, suffix: ' [two]' }],
  null,
];

/** What the writer does today: the unpacked row, its overlay, then each patch on a copy. */
function v2Rows(slots: readonly ChunkSlot[], patches: readonly (readonly InfoPatch[] | null)[]): Packet[] {
  const unpacked = new Map<number, Packet[]>();
  return slots.map((slot, i) => {
    let row: Packet;
    if ('pack' in slot) {
      let rows = unpacked.get(slot.pack.key);
      if (rows === undefined) { rows = unpackRows(slot.pack); unpacked.set(slot.pack.key, rows); }
      row = rows[slot.index];
      if (slot.overlay !== null) applyOverlay(row, slot.overlay);
    } else {
      row = { ...slot };
    }
    for (const patch of patches[i] ?? []) {
      const copy = { ...row };
      applyInfoPatch(copy, patch);
      row = copy;
    }
    return row;
  });
}

function bothWays(slots: readonly ChunkSlot[], patches: readonly (readonly InfoPatch[] | null)[], caps: number[]) {
  const v2 = encodeChunk(v2Rows(slots, patches), caps);
  const expected = decodeChunk(v2.summary);
  applyPrefixes(expected, v2.prefix);
  const v3 = encodePackedChunk(slots, caps, patches);
  const actual = decodeChunk(v3.summary);
  applyPrefixes(actual, v3.prefix);
  return { v2, v3, expected, actual };
}

/** Reads a version-3 container's layout, independently of the decoder. */
function parseContainer(s: Uint8Array) {
  const v = new DataView(s.buffer, s.byteOffset, s.byteLength);
  const frameCount = v.getUint32(8, true);
  const segCount = v.getUint16(12, true);
  const segments: { kind: number; bytes: Uint8Array }[] = [];
  let at = 14;
  for (let i = 0; i < segCount; i++) {
    const len = v.getUint32(at + 1, true);
    segments.push({ kind: s[at], bytes: s.subarray(at + 5, at + 5 + len) });
    at += 5 + len;
  }
  return { version: v.getUint16(4, true), frameCount, segCount, segments, laneAt: at, tailAt: at + frameCount * 2 };
}

const EMPTY_SECTIONS = new Uint8Array(16);

/** A container written by hand, so a malformed one can be made on purpose. */
function container(segments: { kind: number; bytes: Uint8Array }[], lane: number[], tail: Uint8Array = EMPTY_SECTIONS): Uint8Array {
  const total = 14 + segments.reduce((n, s) => n + 5 + s.bytes.length, 0) + lane.length * 2 + tail.length;
  const out = new Uint8Array(total);
  const v = new DataView(out.buffer);
  v.setUint32(0, CHUNK_MAGIC, true);
  v.setUint16(4, 3, true);
  v.setUint32(8, lane.length, true);
  v.setUint16(12, segments.length, true);
  let at = 14;
  for (const s of segments) {
    out[at] = s.kind;
    v.setUint32(at + 1, s.bytes.length, true);
    out.set(s.bytes, at + 5);
    at += 5 + s.bytes.length;
  }
  for (const l of lane) { v.setUint16(at, l, true); at += 2; }
  out.set(tail, at);
  return out;
}

{
  // Four shards' worth of packs, interleaved the way a flush interleaves them,
  // with id holes, objects and placeholders between them.
  const SCHEDULE = ['P1', 'P2', 'P2', 'O', 'P3', 'P2', 'P1', 'P4', 'P2', 'PH'] as const;
  const lanes: Record<string, Packet[]> = { P1: [], P2: [], P3: [], P4: [], O: [], PH: [] };
  for (let id = 1, n = 0; n < 400; id++) {
    if (id % 17 === 0) continue;                     // a frame that failed to dissect burns its id
    const lane = SCHEDULE[n++ % SCHEDULE.length];
    lanes[lane].push(lane === 'PH'
      ? frame({ id, source: '', destination: '', info: '', status: 'dropped', length: 0, tsUs: 1_788_477_971_000_000 + id * 1_000 })
      : mk(id));
  }
  const packs: Record<string, RowPack> = {};
  let key = 1;
  for (const name of ['P1', 'P2', 'P3', 'P4']) {
    // The pack's own directory lanes use lengths the chunk never sees.
    packs[name] = packRows(key++, lanes[name], lanes[name].map((_, i) => 9000 + i));
  }
  const used: Record<string, number[]> = {
    P1: lanes.P1.map((_, i) => i),                              // every row: the summary goes in verbatim
    P2: Array.from({ length: 60 }, (_, i) => i + 20),           // 60 of 160: a selection
    P3: [0, 8, 16, 24, 32],                                     // 5 of 40: under 16, so re-encoded
    P4: lanes.P4.map((_, i) => i),
  };
  const entries: { id: number; slot: ChunkSlot }[] = [];
  for (const name of ['P1', 'P2', 'P3', 'P4']) {
    for (const index of used[name]) {
      const id = lanes[name][index].id;
      entries.push({ id, slot: { pack: packs[name], index, overlay: id % 3 === 0 ? OVERLAYS[id % OVERLAYS.length] : null, id } });
    }
  }
  for (const name of ['O', 'PH']) for (const p of lanes[name]) entries.push({ id: p.id, slot: p });
  entries.sort((a, b) => a.id - b.id);
  const slots = entries.map((e) => e.slot);
  const patches = slots.map((_, i) => {
    if (i % 5 !== 0) return null;
    const list = PATCHES[(i / 5) % PATCHES.length];
    return list === null ? null : list.map((p) => ({ ...p, frameId: entries[i].id }));
  });
  const caps = slots.map((_, i) => 100 + (i % 37) * 3);

  const { v2, v3, expected, actual } = bothWays(slots, patches, caps);
  const layout = parseContainer(v3.summary);
  check('a chunk of packs is a version-3 container', layout.version, 3);
  check('...of three pack segments and one run', layout.segments.map((s) => s.kind), [0, 0, 0, 1]);
  // Segments are in the order the chunk first meets each pack; P2's first row here is its 21st.
  sameBytes('a whole pack goes in as its own bytes', layout.segments[0].bytes, packs.P1.summary);
  sameBytes('...and so does another used in full', layout.segments[1].bytes, packs.P4.summary);
  check('...a split pack as a selection of its rows', decodeChunk(layout.segments[2].bytes).length, 60);
  check('...and the run holds the objects, the placeholders and the demoted pieces',
    decodeChunk(layout.segments[3].bytes).length, lanes.O.length + lanes.PH.length + 5);
  check('the chunk has all its rows', [slots.length, actual.length], [slots.length, expected.length]);

  sameRows('(a) packed slots decode to what re-encoding the same rows decodes to', actual, expected);
  sameBytes('(b) the prefix block is byte-identical to the re-encoded one', v3.prefix, v2.prefix);
  check('...and so are its first and last ids and timestamps',
    [v3.frameCount, v3.firstId, v3.lastId, v3.firstTsUs, v3.lastTsUs],
    [v2.frameCount, v2.firstId, v2.lastId, v2.firstTsUs, v2.lastTsUs]);
  const dir = new ChunkDirectory(v3.prefix, slots.length);
  check('the directory lanes come from the slots, not from the packs',
    [dir.id(0), dir.id(slots.length - 1), dir.capLength(0), dir.capLength(3), dir.totalBytes],
    [entries[0].id, entries[slots.length - 1].id, caps[0], caps[3], caps.reduce((a, b) => a + b, 0)]);
  check('a v3 summary says its rows record a link type', chunkStoresLinkType(v3.summary), true);
}

{
  // (c) A selection decodes to the rows chosen, with their strings remapped.
  const rows = Array.from({ length: 64 }, (_, i) => mk(i + 1));
  const pack = packRows(1, rows, rows.map((_, i) => i));
  const decodedAll = unpackRows(pack);
  const sets: number[][] = [[0], [63], [3, 5, 6, 40], rows.map((_, i) => i), rows.map((_, i) => i).filter((i) => i % 2 === 1)];
  for (const idx of sets) {
    const selected = selectRows(pack.summary, idx);
    const got = decodeChunk(selected);
    const want = decodeChunk(encodeChunk(idx.map((i) => decodedAll[i]), idx.map(() => 0)).summary);
    sameRows(`(c) selectRows of ${idx.length} row(s) decodes to the same rows as encoding them`, got, want);
    sameBytes(`...and is the same bytes (${idx.length})`, selected, encodeChunk(idx.map((i) => decodedAll[i]), idx.map(() => 0)).summary);
  }
  checkThrows('selecting no rows is refused', () => selectRows(pack.summary, []));
  checkThrows('selecting a row past the end is refused', () => selectRows(pack.summary, [64]));
  checkThrows('selecting out of order is refused', () => selectRows(pack.summary, [5, 3]));
  checkThrows('selecting a row twice is refused', () => selectRows(pack.summary, [3, 3]));
  checkThrows('selecting from a container is refused', () => selectRows(container([{ kind: 0, bytes: pack.summary }], rows.map(() => 0)), [0]));
}

{
  // (d) Every kind of overlay, with every kind of patch, on every shape of row.
  const rows = Array.from({ length: 28 }, (_, i) => mk(i + 1));
  const pack = packRows(1, rows, rows.map(() => 0));
  let bad = 0;
  let first = '';
  OVERLAYS.forEach((overlay, c) => {
    const slots: ChunkSlot[] = rows.map((r, index) => ({ pack, index, overlay, id: r.id }));
    const patches = rows.map((r, i) => {
      const list = PATCHES[(i + c) % PATCHES.length];
      return list === null ? null : list.map((p) => ({ ...p, frameId: r.id }));
    });
    const { v2, v3, expected, actual } = bothWays(slots, patches, rows.map((_, i) => 60 + i));
    const d = firstDifference(actual, expected, `overlay ${c}`);
    if (d !== null) { bad++; first ||= d; }
    if (Buffer.compare(Buffer.from(v3.prefix), Buffer.from(v2.prefix)) !== 0) { bad++; first ||= `overlay ${c}: prefix differs`; }
    if ('expert' in overlay && overlay.expert === undefined) {
      if (actual.some((p) => 'expert' in p)) { bad++; first ||= `overlay ${c}: an undefined expert left a key behind`; }
    }
    if ('tsNanos' in overlay && overlay.tsNanos === undefined) {
      if (actual.some((p) => 'tsNanos' in p)) { bad++; first ||= `overlay ${c}: an undefined tsNanos left a key behind`; }
    }
    if ('tsPrecision' in overlay && overlay.tsPrecision === undefined) {
      if (actual.some((p) => 'tsPrecision' in p)) { bad++; first ||= `overlay ${c}: an undefined tsPrecision left a key behind`; }
    }
  });
  check(`(d) ${OVERLAYS.length} overlays x ${PATCHES.length} patch shapes x 28 row shapes decode as the re-encoded path does`, bad, 0);
  if (first) console.log(`        first difference: ${first}`);

  // The nanosecond remainder is the one prefix field an overlay can change.
  // Row 1 (id 2) carries a remainder of 2 in its pack; the overlay says 123.
  const remainder = (overlay: RowOverlay | null): number => {
    const { prefix } = encodePackedChunk([{ pack, index: 1, overlay, id: rows[1].id }], [0], [null]);
    return new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength).getUint16(64, true);
  };
  check('(d) an overlay that sets tsNanos rewrites the prefix remainder, and none leaves the pack\'s',
    [remainder({ tsNanos: 1_788_477_971_000_000_123n }), remainder(null), remainder({ tsNanos: undefined })], [123, 2, 0]);
}

{
  // (e) Older summaries still decode, and a row written today is still version 2.
  const rows = [mk(1), mk(2), mk(3)];
  const v1 = encodeChunk(rows, [0, 0, 0], 1);
  const v1Back = decodeChunk(v1.summary);
  check('(e) a version-1 chunk still decodes', v1Back.map((p) => p.id), [1, 2, 3]);
  check('...and has no link type', v1Back.some((p) => 'linkType' in p), false);
  const v2 = encodeChunk(rows, [0, 0, 0]);
  check('...a version-2 chunk decodes to its rows', roundTrip(rows).map(shapeOf), rows.map(shapeOf));
  check('...and is version 2', v2.summary[4], 2);
}

{
  // (f) A container that does not add up is refused, never partly decoded.
  const a = encodeChunk([mk(1), mk(3), mk(5)], [0, 0, 0]).summary;
  const b = encodeChunk([mk(2), mk(4), mk(6)], [0, 0, 0]).summary;
  const segs = [{ kind: 0, bytes: a }, { kind: 0, bytes: b }];
  check('(f) a well-formed container decodes in lane order', decodeChunk(container(segs, [0, 1, 0, 1, 0, 1])).map((p) => p.id), [1, 2, 3, 4, 5, 6]);
  checkThrows('(f) a lane naming a segment that is not there', () => decodeChunk(container(segs, [0, 1, 0, 1, 0, 2])));
  checkThrows('...two rows swapped across segments, so ids fall', () => decodeChunk(container(segs, [1, 0, 0, 1, 0, 1])));
  checkThrows('...a lane that leaves a segment row unplaced', () => decodeChunk(container(segs, [0, 1, 0, 1, 0, 0])));
  checkThrows('...a lane that asks a segment for a row it has not got', () => decodeChunk(container(segs, [0, 0, 0, 0, 1, 1])));
  checkThrows('...ids out of order across segments', () => decodeChunk(container(segs, [0, 0, 0, 1, 1, 1])));
  const low = encodeChunk([mk(1), mk(2), mk(3)], [0, 0, 0]).summary;
  const high = encodeChunk([mk(4), mk(5), mk(6)], [0, 0, 0]).summary;
  check('...while the same lane over segments that ascend is fine',
    decodeChunk(container([{ kind: 0, bytes: low }, { kind: 1, bytes: high }], [0, 0, 0, 1, 1, 1])).map((p) => p.id),
    [1, 2, 3, 4, 5, 6]);

  // A lane can ascend and still be wrong: rows that are all the container's, in
  // order, but not the ones the chunk was written with. The prefix's id lane is
  // the writer's own, so joining the blocks checks one against the other.
  const right = encodeChunk([mk(1), mk(2), mk(3), mk(4), mk(5), mk(7)], [0, 0, 0, 0, 0, 0]);
  const wrongRows = decodeChunk(container([{ kind: 0, bytes: low }, { kind: 1, bytes: high }], [0, 0, 0, 1, 1, 1]));
  checkThrows('(f) rows whose ids disagree with the prefix\'s directory are refused when the blocks are joined',
    () => applyPrefixes(wrongRows, right.prefix));
  const rightRows = decodeChunk(right.summary);
  applyPrefixes(rightRows, right.prefix);
  check('...while the rows the prefix was written with join it', rightRows.map((p) => p.id), [1, 2, 3, 4, 5, 7]);
}

{
  // Truncation anywhere, and bytes past the end, on a container with every section in use.
  const rows = Array.from({ length: 24 }, (_, i) => mk(i + 1));
  const pack = packRows(1, rows, rows.map(() => 0));
  const slots: ChunkSlot[] = rows.map((r, index) => ({ pack, index, overlay: OVERLAYS[index % OVERLAYS.length], id: r.id }));
  const patches = rows.map((r, i) => {
    const list = PATCHES[i % PATCHES.length];
    return list === null ? null : list.map((p) => ({ ...p, frameId: r.id }));
  });
  const { summary } = encodePackedChunk(slots, rows.map(() => 0), patches);
  decodeChunk(summary);
  let accepted = 0;
  for (let cut = 0; cut < summary.length; cut++) {
    try { decodeChunk(summary.subarray(0, cut)); accepted++; } catch { /* refused, as it must be */ }
  }
  check(`(f) every one of the ${summary.length} truncations of a container is refused`, accepted, 0);
  checkThrows('(f) a byte after the last section is refused', () => decodeChunk(new Uint8Array([...summary, 0])));
  const nested = encodePackedChunk(slots.slice(0, 3), [0, 0, 0], [null, null, null]).summary;
  checkThrows('(f) a container nested inside a segment is refused',
    () => decodeChunk(container([{ kind: 0, bytes: nested }], [0, 0, 0])));
  checkThrows('(f) a segment that is not a version-2 summary is refused',
    () => decodeChunk(container([{ kind: 0, bytes: encodeChunk([mk(1)], [0], 1).summary }], [0])));
  checkThrows('(f) a segment length that runs past the end is refused',
    () => { const bad = summary.slice(); new DataView(bad.buffer).setUint32(15, 0x7fffffff, true); return decodeChunk(bad); });
  checkThrows('(f) an unknown segment kind is refused',
    () => { const bad = summary.slice(); bad[14] = 9; return decodeChunk(bad); });
  checkThrows('encodePackedChunk refuses a row index outside its pack',
    () => encodePackedChunk([{ pack, index: 24, overlay: null, id: 99 }], [0], [null]));
  checkThrows('...ids that do not ascend',
    () => encodePackedChunk([{ pack, index: 1, overlay: null, id: 5 }, { pack, index: 2, overlay: null, id: 5 }], [0, 0], [null, null]));
  checkThrows('...a pack index that does not ascend',
    () => encodePackedChunk([{ pack, index: 3, overlay: null, id: 4 }, { pack, index: 2, overlay: null, id: 5 }], [0, 0], [null, null]));
  checkThrows('...an empty chunk', () => encodePackedChunk([], [], []));
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
    // **A chunk written before link types were stored still decodes** - a
    // capture on disk outlives the build that wrote it. Real frames, the old
    // layout written for real, and every other field still exact.
    const v1 = encodeChunk(sample, capLengths(sample), 1);
    const v1Back = decodeChunk(v1.summary);
    applyPrefixes(v1Back, v1.prefix);
    check(`${name}: a version-1 chunk decodes, every carried field but linkType exact`,
      v1Back.filter((p, i) => {
        const { linkType: _a, ...want } = shapeOf(sample[i]);
        const { linkType: _b, ...got } = shapeOf(p);
        return show(want) !== show(got);
      }).length, 0);
    check(`${name}: ...and says its rows do not record a link type`,
      [chunkStoresLinkType(v1.summary), chunkStoresLinkType(encoded.summary), ROW_LAYOUT_VERSION], [false, true, 2]);

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
