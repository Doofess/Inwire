/**
 * Reading a stream's frames back from a capture costs one decode per chunk, not
 * one per page (ADR 0055; final review I4), and starts at the stream's first
 * chunk.
 *
 *   npx tsx scripts/capture/stream-reader.ts
 *
 * Driven through the real host with an `inflate` that counts. A chunk's rows
 * cost two inflates (summary and prefix), so inflates are decodes x 2; the
 * counts printed are the ones after the ordinals were gathered.
 */
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { CHUNK_FRAMES } from '../../src/services/capture/chunkCodec';
import { plainForStore } from '../../src/services/capture/storePacket';
import { loadStreamFrames, type StreamFrameSource } from '../../src/services/conversation/streamFrames';
import type { StreamSummary } from '../../src/services/conversation/streamDigest';
import { inflateSync } from 'fflate';
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

let nextId = 1;
function row(streamId: number): Packet {
  const id = nextId++;
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: '10.0.0.2', destination: '93.184.216.34', sourcePort: 50000, destPort: 443,
    protocol: 'TCP', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'],
    fields: { 'tcp.len': 10 }, length: 70, info: '', status: 'ok', streamId,
    interfaceName: 'eth0', layers: [], rawBytes: new Uint8Array([id & 0xff, 0, 0, 0]),
  } as Packet;
}

/** A host over `rows`, its source adapter, and the inflate count. */
async function open(rows: Packet[], streamOrdinalChunks: number) {
  const counter = { inflates: 0 };
  const said: FromCapture[] = [];
  const store = new CaptureHost(new MemoryVolume(), (m) => said.push(m), {
    streamOrdinalChunks, scanSliceMs: 0,
    inflate: (bytes) => { counter.inflates++; return inflateSync(bytes); },
  });
  const send = (m: ToCapture) => store.receive(m);
  send({ type: 'open', captureId: 'cap-20261009-120000-rdr1' });
  for (let i = 0; i < rows.length; i += 1000) {
    send({ type: 'append', packets: deserialize(serialize(rows.slice(i, i + 1000).map((p) => plainForStore(p)))) as Packet[] });
  }
  send({ type: 'finish' });
  await store.drain();
  let requestId = 1000;
  const calls = { ordinalPages: 0 };
  const ask = async <T extends FromCapture['type']>(message: ToCapture, type: T) => {
    send(message);
    await store.drain();
    return said.find((m) => m.type === type && (m as { requestId?: number }).requestId === (message as { requestId?: number }).requestId) as
      Extract<FromCapture, { type: T }>;
  };
  const source: StreamFrameSource = {
    async streamOrdinals(streamId, fromId, toId, startChunk) {
      calls.ordinalPages++;
      const a = await ask({ type: 'streamOrdinals', requestId: requestId++, streamId, fromId, toId, startChunk }, 'streamOrdinals');
      return { ordinals: a.ordinals, nextChunk: a.nextChunk };
    },
    async flowOrdinals(kind, key, fromId, toId, startChunk) {
      const a = await ask({ type: 'flowOrdinals', requestId: requestId++, kind, key, fromId, toId, startChunk }, 'flowOrdinals');
      return { ordinals: a.ordinals, nextChunk: a.nextChunk };
    },
    async readRowsFor(ordinals) {
      const a = await ask({ type: 'rowsForOrdinals', requestId: requestId++, ordinals: [...ordinals] }, 'rowsByOrdinal');
      return new Map(a.rows);
    },
  };
  return { store, source, counter, calls };
}

console.log('\n--- a 20k-frame stream decodes each chunk once ---\n');
{
  nextId = 1;
  const rows = Array.from({ length: 20_000 }, () => row(7));
  const { store, source, counter } = await open(rows, 32);
  const summary = { streamId: 7, firstId: rows[0].id, lastId: rows[rows.length - 1].id } as StreamSummary;
  // Inflates spent answering readRowsFor only; the ordinal pages read prefixes too.
  let rowInflates = 0;
  let rowPages = 0;
  const counting: StreamFrameSource = {
    streamOrdinals: (...args) => source.streamOrdinals(...args),
    flowOrdinals: (...args) => source.flowOrdinals(...args),
    async readRowsFor(ordinals) {
      const before = counter.inflates;
      const rows = await source.readRowsFor(ordinals);
      rowInflates += counter.inflates - before;
      rowPages++;
      return rows;
    },
  };
  const frames = await loadStreamFrames(summary, [], counting);
  const chunks = Math.ceil(20_000 / CHUNK_FRAMES);
  check('every frame comes back', frames.length, 20_000);
  console.log(`MEASURE  20,000 frames, ${chunks} chunks, ${rowPages} row pages: ${rowInflates} inflates (${rowInflates / 2} chunk decodes)`);
  // Two inflates (summary, prefix) per chunk decoded.
  check('rows cost two inflates per chunk, not per page of 256', rowInflates, 2 * chunks);
  store.close();
}

console.log('\n--- the read starts at the stream\'s first chunk ---\n');
{
  nextId = 1;
  const rows = [
    ...Array.from({ length: 3 * CHUNK_FRAMES }, () => row(9)),
    ...Array.from({ length: 100 }, () => row(7)),
  ];
  const { store, source, calls } = await open(rows, 1);
  const first = rows.find((r) => r.streamId === 7)!;
  const summary = { streamId: 7, firstId: first.id, lastId: rows[rows.length - 1].id } as StreamSummary;
  const frames = await loadStreamFrames(summary, [], source);
  check('stream 7 is whole', frames.length, 100);
  check('one page, not three empty ones first', calls.ordinalPages, 1);
  store.close();
}

if (failures > 0) { console.log(`\n${failures} FAILED`); process.exit(1); }
console.log('\nall PASS');
