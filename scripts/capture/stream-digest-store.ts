/**
 * The capture store keeps the stream digest (ADR 0055 §5), driven through the
 * real host.
 *
 *   npx tsx scripts/capture/stream-digest-store.ts
 *
 * Modelled on `store-protocol.ts`: a `CaptureHost` over a `MemoryVolume`, every
 * row through `plainForStore` and a `v8` round trip because that is how rows
 * reach the store's process, and `host.drain()` between sends and answers.
 *
 * The snapshot file, `streams.iwdig`, is reached the way the host reaches it:
 * `volume.open(id).digest`. A `MemoryVolume`'s files outlive the handle that
 * wrapped them, so a second open of the same id is the same bytes, and closing
 * it keeps `outstanding` honest.
 */
import { CaptureHost, type CaptureHostOptions } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { plainForStore } from '../../src/services/capture/storePacket';
import { readExact } from '../../src/services/capture/blockFile';
import { decodeDigest, encodeDigest } from '../../src/services/conversation/digestCodec';
import type { StreamSummary } from '../../src/services/conversation/streamDigest';
import { RingFiling } from '../../src/services/pipeline/ringFiling';
import type { RawFrame } from '../../src/services/capture/captureWriter';
import { deflateSync, inflateSync } from 'fflate';
import { serialize, deserialize } from 'node:v8';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { Packet } from '../../src/types/packet';
import { packFrames } from '../../src/services/capture/frameSlab';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 400));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 400));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** A host with everything it said recorded, in order. */
function host(options: CaptureHostOptions = {}, volume = new MemoryVolume()) {
  const said: FromCapture[] = [];
  const store = new CaptureHost(volume, (message) => said.push(message), options);
  return {
    volume, said, store,
    send: (message: ToCapture) => store.receive(message),
    of<T extends FromCapture['type']>(type: T): Extract<FromCapture, { type: T }>[] {
      return said.filter((m) => m.type === type) as Extract<FromCapture, { type: T }>[];
    },
  };
}
type Host = ReturnType<typeof host>;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Copied from `scripts/conversation/stream-digest.ts`: a script imports no other script.
let nextId = 1;
function row(fromClient: boolean, flags: string, extra: Partial<Packet> & { seq?: number; ack?: number; len?: number } = {}): Packet {
  const { seq, ack, len, ...rest } = extra;
  const fields: Record<string, number> = {
    'tcp.flags.syn': flags.includes('S') ? 1 : 0, 'tcp.flags.ack': flags.includes('A') ? 1 : 0,
    'tcp.flags.fin': flags.includes('F') ? 1 : 0, 'tcp.flags.reset': flags.includes('R') ? 1 : 0,
    ...(seq !== undefined ? { 'tcp.seq': seq } : {}), ...(ack !== undefined ? { 'tcp.ack': ack } : {}),
    'tcp.len': len ?? 0,
  };
  const id = nextId++;
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: fromClient ? '10.0.0.2' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.2',
    sourcePort: fromClient ? 50000 : 443, destPort: fromClient ? 443 : 50000,
    protocol: 'TCP', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'], fields,
    length: 60 + (len ?? 0), info: '', status: 'ok', streamId: 7,
    interfaceName: 'eth0', layers: [], rawBytes: new Uint8Array([id & 0xff, 0, 0, 0]),
    ...rest,
  } as Packet;
}

/** A whole connection: handshake, a request, a reply, both FINs. */
function connection(): Packet[] {
  return [
    row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }), row(true, 'A', { seq: 1, ack: 1 }),
    row(true, 'A', { seq: 1, ack: 1, len: 100, protocolLabel: 'TLSv1.3' }),
    row(false, 'A', { seq: 1, ack: 101, len: 1000 }),
    row(true, 'FA', { seq: 101, ack: 1001 }), row(false, 'FA', { seq: 1001, ack: 102 }), row(true, 'A', { seq: 102, ack: 1002 }),
  ];
}

/** Rows as the store receives them: flattened, then through a structured clone. */
function crossed(packets: readonly Packet[]): Packet[] {
  return deserialize(serialize(packets.map((p) => plainForStore(p)))) as Packet[];
}

async function ask(h: Host, since: number, requestId: number) {
  h.send({ type: 'streamDigest', requestId, since });
  await h.store.drain();
  return h.of('streamDigest').find((m) => m.requestId === requestId);
}

/** Asks until the rebuild says it is done, or gives up. */
async function untilRebuilt(h: Host, firstRequestId: number, ms = 20_000) {
  const deadline = Date.now() + ms;
  let requestId = firstRequestId;
  while (Date.now() < deadline) {
    const answer = await ask(h, 0, requestId++);
    if (answer !== undefined && answer.rebuilding === null) return answer;
    await sleep(1);
  }
  return undefined;
}

function digestFile(volume: MemoryVolume, captureId: string): Uint8Array {
  const files = volume.open(captureId);
  try {
    return readExact(files.digest, 0, files.digest.size());
  } finally {
    files.close();
  }
}

function writeDigestFile(volume: MemoryVolume, captureId: string, bytes: Uint8Array): void {
  const files = volume.open(captureId);
  try {
    files.digest.truncate(0);
    if (bytes.length > 0) files.digest.write(0, bytes);
  } finally {
    files.close();
  }
}

/** A summary without its version: a poll cursor local to one digest, not a fact about the stream. */
function withoutVersion(s: StreamSummary | undefined) {
  if (s === undefined) return undefined;
  const { version: _version, ...rest } = s;
  return rest;
}

console.log('--- 1. every request answers ---\n');

{
  const h = host();
  h.send({ type: 'streamDigest', requestId: 1, since: 0 });
  h.send({ type: 'streamOrdinals', requestId: 2, streamId: 7, fromId: 1, toId: 100, startChunk: 0 });
  await h.store.drain();
  check('streamDigest with nothing open answers empty', h.of('streamDigest'), [
    { type: 'streamDigest', requestId: 1, captureId: null, version: 0, summaries: [], udp: [], quic: [], captureEnd: 0, rebuilding: null, partial: false },
  ]);
  check('streamOrdinals with nothing open answers empty', h.of('streamOrdinals'), [
    { type: 'streamOrdinals', requestId: 2, ordinals: [], nextChunk: null },
  ]);
}

const ID = 'cap-20261009-120000-dig1';
const volume = new MemoryVolume();
let original: StreamSummary | undefined;
let lastId = 0;

console.log('\n--- 2-5. fold, relabel, snapshot, restore ---\n');

{
  const h = host({}, volume);
  nextId = 1;
  const rows = connection();
  lastId = rows[rows.length - 1].id;
  h.send({ type: 'open', captureId: ID });
  h.send({ type: 'append', packets: crossed(rows) });
  const first = await ask(h, 0, 10);
  check('2. one summary after a whole connection', first?.summaries.length, 1);
  check('...closed cleanly', first?.summaries[0]?.outcome, 'closed cleanly');
  check('...answered for the open capture', first?.captureId, ID);
  check('...and since its version there is nothing new', (await ask(h, first?.version ?? 0, 11))?.summaries, []);

  h.send({ type: 'patches', patches: [{ frameId: lastId, protocolLabel: 'TLSv1.2' }] });
  const relabelled = await ask(h, first?.version ?? 0, 12);
  check('3. a protocolLabel patch relabels the summary', relabelled?.summaries[0]?.protocol, 'TLSv1.2');
  checkTrue('...and moves its version', (relabelled?.version ?? 0) > (first?.version ?? 0)
    && (relabelled?.summaries[0]?.version ?? 0) > (first?.version ?? 0));
  original = relabelled?.summaries[0];

  h.send({ type: 'finish' });
  await h.store.drain();
  const raw = digestFile(volume, ID);
  checkTrue('4. finish writes the snapshot', raw.length > 0);
  check('...and it reads back through the last appended id', decodeDigest(raw, inflateSync)?.throughId, lastId);

  h.send({ type: 'open', captureId: ID });
  const restored = await ask(h, 0, 13);
  check('5. reopening restores the summary exactly', restored?.summaries, [original]);
  check('...with no rebuild', restored?.rebuilding, null);
  h.store.close();
  check('no handle leaked', volume.outstanding, 0);
}

console.log('\n--- 6. a stale snapshot rebuilds ---\n');

{
  // Entries left empty, so a restore of it would be caught as a lost summary.
  writeDigestFile(volume, ID, encodeDigest({ throughId: lastId + 5000, version: 1, captureEnd: 0, entries: [] }, deflateSync));
  const h = host({ scanSliceMs: 0 }, volume);
  h.send({ type: 'open', captureId: ID });
  const firstAnswer = await ask(h, 0, 20);
  checkTrue('the first answer is rebuilding, or already rebuilt',
    firstAnswer?.rebuilding !== null || firstAnswer?.summaries.length === 1);
  const rebuilt = await untilRebuilt(h, 21);
  check('the rebuilt summary equals the original', withoutVersion(rebuilt?.summaries[0]), withoutVersion(original));
  checkTrue('the stale snapshot was not used', (rebuilt?.summaries.length ?? 0) === 1);
  h.send({ type: 'finish' });
  await h.store.drain();
  check('...and finish writes a fresh one', decodeDigest(digestFile(volume, ID), inflateSync)?.throughId, lastId);
  h.store.close();
}

console.log('\n--- 7. a missing snapshot rebuilds ---\n');

{
  writeDigestFile(volume, ID, new Uint8Array(0));
  const h = host({ scanSliceMs: 0 }, volume);
  h.send({ type: 'open', captureId: ID });
  const firstAnswer = await ask(h, 0, 30);
  checkTrue('the first answer is rebuilding, or already rebuilt',
    firstAnswer?.rebuilding !== null || firstAnswer?.summaries.length === 1);
  const rebuilt = await untilRebuilt(h, 31);
  check('the rebuilt summary equals the original', withoutVersion(rebuilt?.summaries[0]), withoutVersion(original));
  h.store.close();
  check('no handle leaked', volume.outstanding, 0);
}

console.log('\n--- 8. streamOrdinals pages by chunk, from the prefix ---\n');

const BIG = 'cap-20261009-120000-dig2';
const bigVolume = new MemoryVolume();
const bigRows: Packet[] = [];
{
  nextId = 1;
  for (let i = 0; i < 3 * CHUNK_FRAMES; i++) {
    const r = row(i % 2 === 0, 'A', { seq: i, ack: 1, len: 10, streamId: i % 3 === 0 ? 9 : 7 });
    bigRows.push(r);
  }
  // A UDP row carrying stream id 7: `hasLayer('tcp')` must keep it out.
  bigRows.push(row(true, '', {
    protocol: 'UDP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp'], streamId: 7,
  }));
}
const expected7 = bigRows.flatMap((r, ordinal) =>
  r.streamId === 7 && r.frameProtocols?.includes('tcp') ? [ordinal] : []);

{
  const h = host({ streamOrdinalChunks: 1, scanSliceMs: 0 }, bigVolume);
  h.send({ type: 'open', captureId: BIG });
  for (let i = 0; i < bigRows.length; i += 1000) h.send({ type: 'append', packets: crossed(bigRows.slice(i, i + 1000)) });
  h.send({ type: 'finish' });
  await h.store.drain();

  const fromId = bigRows.find((r) => r.streamId === 7)!.id;
  const toId = bigRows[bigRows.length - 1].id;
  const got: number[] = [];
  let startChunk: number | null = 0;
  let pages = 0;
  let requestId = 100;
  while (startChunk !== null && pages < 50) {
    h.send({ type: 'streamOrdinals', requestId, streamId: 7, fromId, toId, startChunk });
    await h.store.drain();
    const answer = h.of('streamOrdinals').find((m) => m.requestId === requestId);
    requestId++;
    pages++;
    if (answer === undefined) break;
    got.push(...answer.ordinals);
    startChunk = answer.nextChunk;
  }
  checkTrue(`the ordinals are exactly stream 7's TCP rows (${expected7.length})`,
    JSON.stringify(got) === JSON.stringify(expected7));
  check('...a page a chunk, four chunks', pages, 4);
  checkTrue('...and the UDP row carrying stream 7 is not among them', !got.includes(bigRows.length - 1));

  console.log('\n--- 9. the scan is untouched ---\n');

  h.said.length = 0;
  h.send({ type: 'scan', requestId: 500, filter: 'tcp' });
  h.send({ type: 'streamOrdinals', requestId: 501, streamId: 7, fromId, toId, startChunk: 0 });
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline && !h.said.some((m) => m.type === 'scanDone')) await sleep(1);
  const done = h.of('scanDone');
  check('the scan completes, not cancelled', done.map((m) => [m.requestId, m.cancelled]), [[500, false]]);
  const answeredAt = h.said.findIndex((m) => m.type === 'streamOrdinals' && m.requestId === 501);
  const doneAt = h.said.findIndex((m) => m.type === 'scanDone');
  checkTrue('...and streamOrdinals was answered while it ran', answeredAt >= 0 && answeredAt < doneAt);
  h.store.close();
}

console.log('\n--- extra: rows arriving during a rebuild are deferred, then folded ---\n');

{
  // No snapshot, four chunks, one chunk a slice: the rebuild spans several
  // slices, and an append queued behind the open lands in the middle of it.
  writeDigestFile(bigVolume, BIG, new Uint8Array(0));
  const h = host({ scanSliceMs: 0 }, bigVolume);
  h.send({ type: 'open', captureId: BIG });
  nextId = bigRows[bigRows.length - 1].id + 1;
  const late = [row(true, 'S', { seq: 0, streamId: 11 }), row(false, 'SA', { seq: 0, ack: 1, streamId: 11 })];
  h.send({ type: 'append', packets: crossed(late) });
  // A label patch for a deferred row: the writer patches its own copy, so the
  // digest has to hold the label until the row is folded.
  h.send({ type: 'patches', patches: [{ frameId: late[1].id, protocolLabel: 'HTTP' }] });
  const during = await ask(h, 0, 600);
  checkTrue('the rebuild is still running after the open', during?.rebuilding !== null && during?.rebuilding !== undefined);
  checkTrue('...and reports progress within its total',
    (during?.rebuilding?.done ?? -1) >= 0 && (during?.rebuilding?.done ?? 0) < (during?.rebuilding?.total ?? 0));
  const rebuilt = await untilRebuilt(h, 601);
  check('every stream is there once it ends', rebuilt?.summaries.map((s) => s.streamId).sort((a, b) => a - b), [7, 9, 11]);
  check('...the late rows folded after the sealed ones',
    rebuilt?.summaries.find((s) => s.streamId === 11)?.state, { client: 'SYN_SENT', server: 'SYN_RCVD' });
  check('...with the label a patch gave one of them meanwhile',
    rebuilt?.summaries.find((s) => s.streamId === 11)?.protocol, 'HTTP');
  check('...and stream 7 counts every one of its TCP rows',
    (() => { const s = rebuilt?.summaries.find((x) => x.streamId === 7); return s && s.toServer.packets + s.toClient.packets; })(),
    expected7.length);
  check('nothing failed', h.of('failure'), []);
  h.store.close();
}

console.log('\n--- I2. a rebuild of a ring capture: the removed start is not "joined" ---\n');

{
  // A ring of 1,000-frame files keeping three, fed the way the pipeline Worker
  // feeds it (`scripts/capture/segments.ts`): stream 7 opens with its handshake
  // in file 1, which the ring then deletes; stream 11 really joins mid-stream,
  // in file 5, which the ring keeps.
  const FILE_FRAMES = 1_000;
  const KEEP = 3;
  const TOTAL = 5 * FILE_FRAMES;
  nextId = 1;
  const ringRows: Packet[] = [row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }), row(true, 'A', { seq: 1, ack: 1 })];
  while (ringRows.length < TOTAL) {
    const i = ringRows.length;
    ringRows.push(i >= 4100 && i < 4103
      ? row(true, 'A', { seq: 500 + i, ack: 1, len: 10, streamId: 11 })
      : row(i % 2 === 0, 'A', { seq: i, ack: 1, len: 10 }));
  }
  const RING_ID = 'cap-20261009-120000-ring';
  const ringVolume = new MemoryVolume();
  {
    const h = host({ scanSliceMs: 0 }, ringVolume);
    const filing = new RingFiling();
    const send = (message: ToCapture) => h.send(deserialize(serialize(message)) as ToCapture);
    h.send({ type: 'open', captureId: RING_ID });
    for (let at = 0; at < TOTAL; at += 300) {
      const batch = ringRows.slice(at, at + 300);
      const frames: RawFrame[] = [];
      for (let i = 0; i < batch.length; i++) {
        const seq = at + i;
        if (seq % FILE_FRAMES === 0) {
          const file = seq / FILE_FRAMES + 1;
          if (file > KEEP) send({ type: 'ringDeleted', epoch: filing.epoch || 1, lastSeq: (file - KEEP) * FILE_FRAMES - 1 });
          filing.boundary(file, seq);
        }
        const part = filing.partOf(seq);
        const p = batch[i];
        frames.push(part === undefined
          ? { id: p.id, tsUs: p.tsUs, bytes: p.rawBytes }
          : { id: p.id, tsUs: p.tsUs, bytes: p.rawBytes, ring: part });
      }
      send({ type: 'appendBytes', slab: packFrames(frames) });
      send({ type: 'append', packets: batch.map((p) => plainForStore(p)) });
    }
    const live = await ask(h, 0, 700);
    check('live, stream 7 was seen from its handshake', live?.summaries.find((s) => s.streamId === 7)?.joinedMidStream, false);
    h.send({ type: 'finish' });
    await h.store.drain();
    h.store.close();
  }
  writeDigestFile(ringVolume, RING_ID, new Uint8Array(0));
  const h = host({ scanSliceMs: 0 }, ringVolume);
  h.send({ type: 'open', captureId: RING_ID });
  const rebuilt = await untilRebuilt(h, 710);
  checkTrue('the ring really took the first file', (h.of('ready')[0]?.floorOrdinal ?? 0) > 0);
  const s7 = rebuilt?.summaries.find((s) => s.streamId === 7);
  const s11 = rebuilt?.summaries.find((s) => s.streamId === 11);
  check('rebuilt, the stream whose handshake expired folds as joined', s7?.joinedMidStream, true);
  check('...and says the ring took its start', s7?.startExpired, true);
  check('a stream that really joined mid-stream, in a file the ring kept, is still only joined',
    [s11?.joinedMidStream, s11?.startExpired === true], [true, false]);
  h.store.close();
}

console.log('\n--- I6. a rebuild that dropped rows says so, and is never written as whole ---\n');

{
  nextId = bigRows[bigRows.length - 1].id + 3;   // past the "extra" section's two late rows
  const lastBig = nextId - 1;
  const late = [row(true, 'S', { seq: 0, streamId: 12 }), row(false, 'SA', { seq: 0, ack: 1, streamId: 12 }),
    row(true, 'A', { seq: 1, ack: 1, streamId: 12 })];

  // No snapshot, one slice a chunk, three rows queued behind the open and room for one.
  writeDigestFile(bigVolume, BIG, new Uint8Array(0));
  const h = host({ scanSliceMs: 0, digestDeferredMax: 1 }, bigVolume);
  h.send({ type: 'open', captureId: BIG });
  h.send({ type: 'append', packets: crossed(late) });
  h.send({ type: 'finish' });
  await h.store.drain();
  const during = await ask(h, 0, 800);
  checkTrue('the rebuild is still running when finish comes', during?.rebuilding !== null && during?.rebuilding !== undefined);
  check('...a rebuild under way is not partial yet', during?.partial, false);
  check('no snapshot is written while it runs', digestFile(bigVolume, BIG).length, 0);
  const done = await untilRebuilt(h, 801);
  check('overflowing the deferred rows marks the digest partial', done?.partial, true);
  checkTrue('...and says so in a failure', h.of('failure').some((m) => /missed rows/.test(m.message)));
  check('...having kept the one row that fitted', done?.summaries.find((s) => s.streamId === 12)?.toServer.packets, 1);
  h.send({ type: 'finish' });
  await h.store.drain();
  check('no snapshot is written after a partial rebuild either', digestFile(bigVolume, BIG).length, 0);
  h.store.close();
  check('...and close writes none', digestFile(bigVolume, BIG).length, 0);

  // The same capture with room for them is whole, and a whole rebuild is written.
  void lastBig;
  writeDigestFile(bigVolume, BIG, new Uint8Array(0));
  const roomy = host({ scanSliceMs: 0 }, bigVolume);
  roomy.send({ type: 'open', captureId: BIG });
  const whole = await untilRebuilt(roomy, 810);
  check('with room for every row the rebuild is whole', whole?.partial, false);
  roomy.send({ type: 'finish' });
  await roomy.store.drain();
  checkTrue('...and its snapshot is written', digestFile(bigVolume, BIG).length > 0);
  roomy.store.close();
}

console.log('\n--- 13. a missed row does not cost every open a rebuild ---\n');

{
  // The live Worker's path: rows with `bytesSent`, their bytes on the same
  // port. The newest row's bytes never come, so the writer holds it and counts
  // it missed at finish - and the digest must not have folded it, or its
  // snapshot is through an id the index never holds and no open trusts it.
  const MISS = 'cap-20261009-120000-dig9';
  const framesOf = (s: StreamSummary | undefined) => s === undefined ? undefined : s.toServer.packets + s.toClient.packets;
  const missVolume = new MemoryVolume();
  const h = host({ scanSliceMs: 0 }, missVolume);
  nextId = 1;
  const rows = connection();
  const late = row(true, 'A', { seq: 102, ack: 1002 });
  const lost = row(true, 'A', { seq: 102, ack: 1002 });
  h.send({ type: 'open', captureId: MISS });
  h.send({ type: 'appendBytes', slab: packFrames(rows.map((r) => ({ id: r.id, tsUs: r.tsUs, bytes: r.rawBytes }))) });
  h.send({ type: 'append', packets: crossed(rows), bytesSent: true });
  // A row that overtook its bytes is folded once they come; the lost one never.
  h.send({ type: 'append', packets: crossed([late, lost]), bytesSent: true });
  h.send({ type: 'appendBytes', slab: packFrames([{ id: late.id, tsUs: late.tsUs, bytes: late.rawBytes }]) });
  const live = await ask(h, 0, 900);
  check('a row whose bytes came after it is folded', framesOf(live?.summaries[0]), rows.length + 1);
  h.send({ type: 'finish' });
  await h.store.drain();
  check('...and the snapshot is through the newest stored id', decodeDigest(digestFile(missVolume, MISS), inflateSync)?.throughId, late.id);
  h.store.close();

  for (const [n, requestId] of [['second', 901], ['third', 902]] as const) {
    const again = host({ scanSliceMs: 0 }, missVolume);
    again.send({ type: 'open', captureId: MISS });
    const answer = await ask(again, 0, requestId);
    // A rebuild empties the file as it starts (and would finish within one drain here).
    checkTrue(`the ${n} open restores the snapshot, no rebuild`, answer?.rebuilding === null && digestFile(missVolume, MISS).length > 0);
    check(`...with every stored row`, framesOf(answer?.summaries[0]), rows.length + 1);
    again.store.close();
  }
  check('no handle leaked', missVolume.outstanding, 0);
}

console.log('\n--- 14. UDP and QUIC reach the answer, and survive a reopen ---\n');

{
  // Copied from `scripts/conversation/flow-digest.ts`: a script imports no other script.
  const FLOWS = 'cap-20261026-120000-dig10';
  const flowVolume = new MemoryVolume();
  const udpRow = (fromClient: boolean, time: number): Packet => {
    const id = nextId++;
    return {
      id, tsUs: id * 1000, timeDelta: 0, relativeTime: time,
      source: fromClient ? '10.0.0.2' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.2',
      sourcePort: fromClient ? 50000 : 5353, destPort: fromClient ? 5353 : 50000,
      protocol: 'UDP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp'], fields: { 'udp.stream': 3 },
      length: 80, info: '', status: 'ok', interfaceName: 'eth0', layers: [], rawBytes: new Uint8Array([id & 0xff, 0, 0, 0]),
    } as Packet;
  };
  const quicRow = (fromClient: boolean, time: number, type?: number): Packet => {
    const r = udpRow(fromClient, time);
    r.sourcePort = fromClient ? 50001 : 443; r.destPort = fromClient ? 443 : 50001;
    r.fields = { 'udp.stream': 9, 'quic.connection.number': 0, 'quic.version': 1, ...(type === undefined ? {} : { 'quic.long.packet_type': type }) };
    r.protocol = 'QUIC'; r.frameProtocols = ['eth', 'ethertype', 'ip', 'udp', 'quic'];
    return r;
  };
  nextId = 1;
  const rows = [udpRow(true, 1), udpRow(false, 2), quicRow(true, 3, 0), quicRow(false, 4, 0), quicRow(true, 12.5)];
  const h = host({}, flowVolume);
  h.send({ type: 'open', captureId: FLOWS });
  h.send({ type: 'append', packets: crossed(rows) });
  const live = await ask(h, 0, 1000);
  check('an import\'s UDP and QUIC rows reach the answer: one UDP flow, one QUIC connection',
    [live?.udp.map((s) => [s.key, s.outcome]), live?.quic.map((s) => [s.key, s.outcome])],
    [[[3, 'request/response']], [[0, 'established']]]);
  check('captureEnd rides every answer', live?.captureEnd, 12.5);
  const quiet = await ask(h, live?.version ?? 0, 1001);
  check('...including one with nothing new', [quiet?.udp, quiet?.quic, quiet?.captureEnd], [[], [], 12.5]);
  h.send({ type: 'finish' });
  await h.store.drain();
  h.send({ type: 'open', captureId: FLOWS });
  const restored = await ask(h, 0, 1002);
  check('a reopen restores UDP and QUIC from the snapshot, with no rebuild',
    [restored?.rebuilding, restored?.udp, restored?.quic, restored?.captureEnd], [null, live?.udp, live?.quic, 12.5]);
  h.store.close();
  check('no handle leaked', flowVolume.outstanding, 0);
}

console.log('\n--- 15. flowOrdinals reads a UDP flow or a QUIC connection from the rows ---\n');

{
  // Three chunks and a little: UDP stream 5 and 6, QUIC connection 2, a QUIC
  // datagram with no connection number (UDP stream 5 by the digest's rule), and
  // TCP filling the rest. `plan` is what each row is, so the expected ordinals
  // come from how the rows were made and not from the code under test.
  const FLOWS_ID = 'cap-20261026-120000-flo1';
  const total = 3 * CHUNK_FRAMES + 50;
  nextId = 1;
  const plan: string[] = [];
  const flowRows: Packet[] = [];
  const base = (fromClient: boolean, over: Partial<Packet>): Packet => {
    const id = nextId++;
    return {
      id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
      source: fromClient ? '10.0.0.2' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.2',
      sourcePort: fromClient ? 50000 : 443, destPort: fromClient ? 443 : 50000,
      length: 80, info: '', status: 'ok', interfaceName: 'eth0', layers: [], rawBytes: new Uint8Array([id & 0xff, 0, 0, 0]),
      ...over,
    } as Packet;
  };
  for (let i = 0; i < total; i++) {
    const fromClient = i % 2 === 0;
    if (i % 5 === 0) {
      plan.push('udp:5');
      flowRows.push(base(fromClient, { protocol: 'UDP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp'], fields: { 'udp.stream': 5 } }));
    } else if (i % 7 === 0) {
      plan.push('quic:2');
      flowRows.push(base(fromClient, {
        protocol: 'QUIC', frameProtocols: ['eth', 'ethertype', 'ip', 'udp', 'quic'],
        fields: { 'udp.stream': 9, 'quic.connection.number': 2 },
      }));
    } else if (i % 11 === 0) {
      plan.push('udp:6');
      flowRows.push(base(fromClient, { protocol: 'UDP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp'], fields: { 'udp.stream': 6 } }));
    } else if (i % 13 === 0) {
      plan.push('udp:5');
      flowRows.push(base(fromClient, {
        protocol: 'QUIC', frameProtocols: ['eth', 'ethertype', 'ip', 'udp', 'quic'], fields: { 'udp.stream': 5 },
      }));
    } else {
      plan.push('tcp');
      flowRows.push(row(fromClient, 'A', { seq: i, ack: 1, len: 10, streamId: 5 }));
    }
  }
  const ordinalsOf = (what: string) => plan.flatMap((p, ordinal) => (p === what ? [ordinal] : []));
  const lastId = flowRows[flowRows.length - 1].id;
  const FIRST = flowRows[0].id;

  /** Walks `flowOrdinals` page by page from chunk 0, as `loadStreamFrames` does. */
  async function walk(h: Host, kind: 'udp' | 'quic', key: number, fromId: number, toId: number, firstRequestId: number) {
    const got: number[] = [];
    let startChunk: number | null = 0;
    let pages = 0;
    let requestId = firstRequestId;
    const chunks: (number | null)[] = [];
    while (startChunk !== null && pages < 50) {
      h.send({ type: 'flowOrdinals', requestId, kind, key, fromId, toId, startChunk });
      await h.store.drain();
      const answer = h.of('flowOrdinals').find((m) => m.requestId === requestId);
      requestId++;
      pages++;
      if (answer === undefined) break;
      got.push(...answer.ordinals);
      startChunk = answer.nextChunk;
      chunks.push(startChunk);
    }
    return { got, pages, chunks };
  }

  {
    const h = host();
    h.send({ type: 'flowOrdinals', requestId: 3, kind: 'udp', key: 5, fromId: 1, toId: 100, startChunk: 0 });
    await h.store.drain();
    check('flowOrdinals answers with nothing open', h.of('flowOrdinals'), [
      { type: 'flowOrdinals', requestId: 3, ordinals: [], nextChunk: null },
    ]);
    h.store.close();
  }

  const h = host({ flowOrdinalChunks: 1, scanSliceMs: 0 });
  h.send({ type: 'open', captureId: FLOWS_ID });
  for (let i = 0; i < flowRows.length; i += 1000) h.send({ type: 'append', packets: crossed(flowRows.slice(i, i + 1000)) });
  h.send({ type: 'finish' });
  await h.store.drain();

  const udp = await walk(h, 'udp', 5, FIRST, lastId, 100);
  check('flowOrdinals returns a UDP flow\'s ordinals across chunks (the QUIC row with no connection number is UDP)',
    udp.got, ordinalsOf('udp:5'));
  const quic = await walk(h, 'quic', 2, FIRST, lastId, 200);
  check('flowOrdinals returns a QUIC connection\'s ordinals', quic.got, ordinalsOf('quic:2'));
  check('...and a UDP key of the same number is not a QUIC one', (await walk(h, 'quic', 5, FIRST, lastId, 300)).got, []);
  check('...nor a QUIC row\'s udp.stream a UDP flow\'s', (await walk(h, 'udp', 9, FIRST, lastId, 400)).got, []);
  check('flowOrdinals pages: nextChunk walks the flow\'s chunks to null',
    [udp.pages, udp.chunks], [4, [1, 2, 3, null]]);
  const second = await walk(h, 'udp', 6, flowRows[CHUNK_FRAMES].id, lastId, 500);
  check('...starting at the flow\'s first chunk, not at chunk 0',
    [second.got, second.pages], [ordinalsOf('udp:6').filter((o) => o >= CHUNK_FRAMES), 3]);
  check('nothing failed', h.of('failure'), []);

  console.log('\n--- flowOrdinals leaves a running scan alone ---\n');

  const scanBits = async (id: number, alongside: boolean) => {
    h.said.length = 0;
    h.send({ type: 'scan', requestId: id, filter: 'udp' });
    if (alongside) h.send({ type: 'flowOrdinals', requestId: id + 1, kind: 'udp', key: 5, fromId: FIRST, toId: lastId, startChunk: 0 });
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline && !h.said.some((m) => m.type === 'scanDone')) await sleep(1);
    const done = h.of('scanDone')[0];
    return {
      done: done === undefined ? null : { cancelled: done.cancelled, frameCount: done.frameCount, bits: Array.from(done.bits ?? []) },
      answeredAt: h.said.findIndex((m) => m.type === 'flowOrdinals'),
      doneAt: h.said.findIndex((m) => m.type === 'scanDone'),
    };
  };
  const alone = await scanBits(600, false);
  const beside = await scanBits(610, true);
  check('the scan alone completes whole', [alone.done?.cancelled, alone.done?.frameCount], [false, total]);
  check('flowOrdinals leaves a running scan alone: the same full result, not cancelled', beside.done, alone.done);
  checkTrue('...and flowOrdinals was answered while it ran', beside.answeredAt >= 0 && beside.answeredAt < beside.doneAt);
  h.store.close();
}

console.log(failures === 0
  ? '\nAll stream digest store checks passed.'
  : `\n${failures} stream digest store check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
