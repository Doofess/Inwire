/**
 * The RAM tail of a streamed import is bounded by the budget's bytes.
 *
 *   npx tsx scripts/capture/import-tail.ts
 *
 * The tail used to be cut at a frame COUNT, the budget divided by a fixed
 * 740 B average. A capture of fat rows kept far more bytes than the budget
 * allowed, and the renderer's heap went with it. `residentBytes` is the same
 * measure `adoptAccounting` and `planBufferTrim` use (`estimateSummaryBytes`),
 * and the trim holds both bounds at once: whichever is tighter wins, and one
 * frame always stays.
 */
import { pcapOf } from '../parity/synthetic';
import { importAnyFile } from '../../src/services/tabularImport';
import { BYTES_RESIDENT_FRAMES, estimateSummaryBytes } from '../../src/services/bufferBudget';
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

/** Ethernet/IPv4/UDP/DNS query, as import-stream.ts builds them. */
function dnsQuery(txid: number): Uint8Array {
  const name = [7, ...[...'example'].map((c) => c.charCodeAt(0)),
    3, ...[...'com'].map((c) => c.charCodeAt(0)), 0];
  const dns = [
    (txid >> 8) & 0xff, txid & 0xff, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ...name, 0x00, 0x01, 0x00, 0x01,
  ];
  const udpLen = 8 + dns.length;
  const srcPort = 0xc000 + (txid & 0x0fff);
  const udp = [
    (srcPort >> 8) & 0xff, srcPort & 0xff, 0x00, 0x35,
    (udpLen >> 8) & 0xff, udpLen & 0xff, 0x00, 0x00, ...dns,
  ];
  const total = 20 + udp.length;
  const ip = [
    0x45, 0x00, (total >> 8) & 0xff, total & 0xff,
    0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
    192, 168, 1, 42, 1, 1, 1, 1,
  ];
  const eth = [0xaa, 0xbb, 0xcc, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0, 0, 2, 0x08, 0x00];
  return new Uint8Array([...eth, ...ip, ...udp]);
}

const FRAMES = 5000;
const bytes = pcapOf(Array.from({ length: FRAMES }, (_, i) => dnsQuery(i + 1)));
const fileOf = () => new File([bytes as unknown as BlobPart], 'tail.pcap');
const sink = () => {};

async function run(options: { maxFrames?: number; residentBytes?: number; sink?: boolean }) {
  const outcome = await importAnyFile(fileOf(), {
    maxFrames: options.maxFrames,
    residentBytes: options.residentBytes,
    onBatch: options.sink === false ? undefined : sink,
  });
  if (outcome.ok !== true) throw new Error('import failed');
  return outcome;
}

async function main() {
  const everything = await run({});
  const all = everything.packets;
  const est = all.map(estimateSummaryBytes);
  const lastBytes = (n: number) => est.slice(-n).reduce((a, b) => a + b, 0);
  check('unbounded import keeps every frame', all.length, FRAMES);

  const byBytes = await run({ residentBytes: lastBytes(1000) });
  check('residentBytes = last 1,000 rows keeps 1,000', byBytes.packets.length, 1000);
  check('... the first kept is 4001', byBytes.packets[0]?.id, 4001);
  check('... the last kept is 5000', byBytes.packets.at(-1)?.id, 5000);
  check('... the note names the window',
    byBytes.notes.some((n) => n.startsWith('All 5,000 frames were imported. The newest 1,000 are in memory;')),
    true);

  const tiny = await run({ residentBytes: 1 });
  check('residentBytes = 1 still keeps one frame', tiny.packets.map((p) => p.id), [FRAMES]);

  const unset = await run({});
  check('no bounds keeps 5,000', unset.packets.length, FRAMES);

  const byCount = await run({ maxFrames: 10, residentBytes: 1e12 });
  check('maxFrames binds when bytes are loose', byCount.packets.length, 10);

  const tighter = await run({ maxFrames: FRAMES, residentBytes: lastBytes(100) });
  check('bytes bind when the count is loose', tighter.packets.length, 100);

  const noSink = await run({ residentBytes: 1, sink: false });
  check('without onBatch residentBytes is ignored', noSink.packets.length, FRAMES);

  // Raw bytes stay resident for the newest BYTES_RESIDENT_FRAMES only, as in
  // the live buffer: the budget does not count them, and a tail of full-size
  // frames held a 2.7 GB file's bytes past it (#20). Every frame reaches the
  // sink - the store - with its bytes; only the tail's own copy lets them go.
  const many = BYTES_RESIDENT_FRAMES + 1000;
  const manyBytes = pcapOf(Array.from({ length: many }, (_, i) => dnsQuery((i % 60000) + 1)));
  let sunkWithout = 0;
  const manyFile = () => new File([manyBytes as unknown as BlobPart], 'many.pcap');
  const released = await importAnyFile(manyFile(), {
    onBatch: (batch) => { for (const p of batch) if (p.rawBytes.byteLength === 0) sunkWithout++; },
    bytesStoredThrough: () => Number.POSITIVE_INFINITY,
  });
  if (released.ok !== true) throw new Error('import failed');
  const kept = released.packets;
  check('a long import keeps every frame in the tail', kept.length, many);
  check('... the sink saw every frame with its bytes', sunkWithout, 0);
  check('... the oldest 1,000 hold no bytes',
    kept.slice(0, 1000).every((p) => p.rawBytes.byteLength === 0), true);
  check('... the newest BYTES_RESIDENT_FRAMES keep theirs',
    kept.slice(1000).every((p) => p.rawBytes.byteLength > 0), true);

  // A row's bytes go only when the store holds them: the live path's rule
  // (`evictOldBytes`). Without it, a store whose port is gone would leave the
  // bytes nowhere.
  const releasedIds = async (bytesStoredThrough?: () => number, onBatch: (batch: Packet[]) => void = sink) => {
    const outcome = await importAnyFile(manyFile(), { onBatch, bytesStoredThrough });
    if (outcome.ok !== true) throw new Error('import failed');
    return outcome.packets.filter((p) => p.rawBytes.byteLength === 0).map((p) => p.id);
  };
  const idsUpTo = (last: number) => Array.from({ length: last }, (_, i) => i + 1);

  check('a store holding frames 1-500 lets only those go',
    await releasedIds(() => 500), idsUpTo(500));
  check('no bytesStoredThrough releases nothing', await releasedIds(), []);
  check('a store holding nothing releases nothing', await releasedIds(() => 0), []);
  // The store's mark trails the sink by more than the resident window, so it
  // starts below every row and rises batch by batch; at the end it stands at 500.
  let lastSeen = 0;
  check('a store whose mark rises releases up to it and no further',
    await releasedIds(
      () => lastSeen - (BYTES_RESIDENT_FRAMES + 500),
      (batch) => { lastSeen = batch[batch.length - 1].id; },
    ),
    idsUpTo(500));

  if (failures > 0) {
    console.log(`\n${failures} failed`);
    process.exit(1);
  }
  console.log('\nall passed');
}

void main();
