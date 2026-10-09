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
import { deflateSync, inflateSync } from 'fflate';
import { serialize, deserialize } from 'node:v8';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { Packet } from '../../src/types/packet';

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
    { type: 'streamDigest', requestId: 1, captureId: null, version: 0, summaries: [], rebuilding: null },
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
  writeDigestFile(volume, ID, encodeDigest({ throughId: lastId + 5000, version: 1, entries: [] }, deflateSync));
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

console.log(failures === 0
  ? '\nAll stream digest store checks passed.'
  : `\n${failures} stream digest store check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
