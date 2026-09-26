/**
 * Frame records through the capture store, end to end, on a real capture.
 *
 *   npx tsx scripts/capture/records.ts
 *
 * `pipeline/revisit.ts` proves a record can rebuild its frame's tree. This
 * proves the STORE can give that record back - with the frame's row, its
 * bytes, and the bytes of every other frame the record names - for any frame
 * of the capture, staged or sealed, after a trip through the same serialiser a
 * process boundary uses. The check is the one that matters: every frame's tree,
 * rebuilt from nothing but a `revisitKit` answer, is the tree arrival built.
 *
 * And an IMPORT, through `importAnyFile` - the entry point the import panel
 * calls - fed to the store in the order `App` feeds it. That path is its own
 * producer of records, and it once produced none: every check above passed
 * while every imported frame's tree fell back to the replay.
 *
 * Also: records arriving before their bytes and after them; a capture written
 * before records existed (index version 1), which must still open and answer
 * "no record"; and a torn records file, which recovery must cut back to the
 * last chunk it fully describes.
 *
 * The real `inwire` fixture only (test/fixtures/README.md); skips cleanly
 * without it.
 */
import { existsSync, readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { serialize, deserialize } from 'node:v8';
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { plainForStore } from '../../src/services/capture/storePacket';
import { writeIndexHeader, INDEX_HEADER_BYTES } from '../../src/services/capture/captureIndex';
import { RecordMiss } from '../../src/services/dissect/frameRecord';
import { importAnyFile } from '../../src/services/tabularImport';
import { LINKTYPE } from '../../src/services/dissect/types';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { InfoPatch } from '../../src/services/dissect/types';
import type { Packet } from '../../src/types/packet';
import { FIXTURES, arrive, firstDifference, render, revisit, type Arrival } from '../pipeline/arrival';

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
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** A message as the other side of a process boundary receives it. */
function crossed<T>(message: T): T {
  return deserialize(serialize(message)) as T;
}

function host(volume = new MemoryVolume()) {
  const said: FromCapture[] = [];
  const replies: FromCapture[] = [];
  const store = new CaptureHost(volume, (message) => said.push(crossed(message)));
  return {
    volume, said, replies, store,
    send: (message: ToCapture) => store.receive(crossed(message)),
    /** As the pipeline Worker sends, with the answer coming back down its own port. */
    ask: (message: ToCapture) => store.receive(crossed(message), (answer) => replies.push(crossed(answer))),
  };
}

type Kit = Extract<FromCapture, { type: 'revisitKit' }>;

/**
 * A frame's tree from a kit alone, the way the Worker will build it: the row
 * supplies the timing and link type, the kit the bytes, and the row's own
 * `dns.response_in` the one patch a later frame writes into a tree.
 */
function treeFromKit(kit: Kit, id: number, arrival: Arrival): string {
  if (kit.record === null || kit.row === null) throw new RecordMiss('the kit has no record');
  const bytes = new Map(kit.frames);
  const own = bytes.get(id);
  if (own === undefined) throw new RecordMiss('the kit has no bytes for the frame itself');
  const row = kit.row;
  const responseIn = row.fields?.['dns.response_in'];
  const patches: InfoPatch[] = typeof responseIn === 'number' ? [{ frameId: id, responseInFrame: responseIn }] : [];
  const layers = revisit(
    {
      bytes: own, tsUs: row.tsUs, relativeTime: row.relativeTime, timeDelta: row.timeDelta,
      origLen: row.length, linktype: row.linkType ?? LINKTYPE.ETHERNET,
    },
    id, kit.record, arrival.host, patches, (frame) => bytes.get(frame),
  );
  return render(layers);
}

async function main() {
  const fixture = FIXTURES.find((f) => f.name === 'inwire')!;
  if (!existsSync(fixture.path)) {
    console.log(`SKIP  ${fixture.path} is not present - see test/fixtures/README.md`);
    console.log('\nAll record-store checks passed (skipped).');
    return;
  }
  const arrival = await arrive(fixture.path);
  const { arrived } = arrival;
  const rows = arrived.map((a) => plainForStore(a.packet as Packet));
  const half = Math.floor(arrived.length / 2);

  console.log('--- records through the store ---\n');
  const h = host();
  h.send({ type: 'open', captureId: 'cap-20260926-120000-rec1' });
  // The first half's records overtake their frames entirely and wait for
  // them. The second half arrives the way a live capture's does: the bytes
  // first (`appendBytes`, before anything dissects them), then the record the
  // Worker made dissecting them, then the row, a flush later, from the
  // renderer. Both must end up in the right slot.
  const recordsOf = (from: number, to: number) =>
    arrived.slice(from, to).map((a) => ({ id: a.packet.id, record: a.record }));
  h.ask({ type: 'appendRecords', frames: recordsOf(0, half) });
  for (let i = 0; i < half; i += 1000) {
    h.send({ type: 'append', packets: rows.slice(i, Math.min(i + 1000, half)) });
  }
  // In flush-sized batches: the Worker posts a flush's bytes, dissects it, and
  // posts its records, all inside one 100 ms flush - so the store's 2 s horizon
  // cannot seal a chunk between a frame's bytes and its record. A 1,000-frame
  // batch across a quiet stretch of a capture spans more than 2 s, and would.
  const FLUSH = 100;
  for (let i = half; i < arrived.length; i += FLUSH) {
    const to = Math.min(i + FLUSH, arrived.length);
    h.ask({
      type: 'appendBytes',
      frames: arrived.slice(i, to).map((a) => ({ id: a.packet.id, tsUs: a.packet.tsUs, bytes: a.input.bytes })),
    });
    h.ask({ type: 'appendRecords', frames: recordsOf(i, to) });
    h.send({ type: 'append', packets: rows.slice(i, to) });
  }
  await h.store.drain();

  // Still staged: the newest frames have not sealed yet.
  const last = arrived[arrived.length - 1].packet.id;
  h.ask({ type: 'revisitKit', requestId: 1, id: last });
  await h.store.drain();
  const stagedKit = h.replies.find((r): r is Kit => r.type === 'revisitKit' && r.requestId === 1);
  checkTrue('a staged frame\'s kit comes back on the asking port', stagedKit !== undefined);
  checkTrue('...and not on the client port', !h.said.some((m) => m.type === 'revisitKit'));
  if (stagedKit !== undefined) {
    check('...and rebuilds its tree', treeFromKit(stagedKit, last, arrival), render(arrived[arrived.length - 1].packet.layers));
  }

  h.send({ type: 'finish' });
  h.send({ type: 'stats' });
  await h.store.drain();
  const stats = h.said.filter((m): m is Extract<FromCapture, { type: 'stats' }> => m.type === 'stats').pop();
  check('every record found its frame', stats?.stats.recordsAttached, arrived.length);
  check('...and none was missed', stats?.stats.recordsMissed, 0);

  // Every frame, sealed, from the kit alone.
  for (const [i, a] of arrived.entries()) h.ask({ type: 'revisitKit', requestId: 100 + i, id: a.packet.id });
  await h.store.drain();
  const kits = new Map(h.replies
    .filter((r): r is Kit => r.type === 'revisitKit' && r.requestId >= 100)
    .map((r) => [r.requestId - 100, r]));
  let equal = 0;
  const wrong: string[] = [];
  const missed: string[] = [];
  for (const [i, a] of arrived.entries()) {
    const kit = kits.get(i);
    if (kit === undefined) { missed.push(`frame ${a.packet.id}: no answer`); continue; }
    try {
      const got = treeFromKit(kit, a.packet.id, arrival);
      const want = render(a.packet.layers);
      if (got === want) equal += 1;
      else wrong.push(`frame ${a.packet.id}: ${firstDifference(want, got)}`);
    } catch (error) {
      if (!(error instanceof RecordMiss)) throw error;
      missed.push(`frame ${a.packet.id}: ${error.reason}`);
    }
  }
  console.log(`      ${equal.toLocaleString()} of ${arrived.length.toLocaleString()} frames rebuilt from the store`);
  for (const line of [...wrong, ...missed].slice(0, 5)) console.log(`        ${line}`);
  check('every frame is rebuilt from its kit into the tree arrival built', equal, arrived.length);

  const bytesOnDisk = stats?.bytesOnDisk ?? 0;
  const recBytes = h.volume.open('cap-20260926-120000-rec1').rec.size();
  console.log(`      records.iwrec ${(recBytes / arrived.length).toFixed(1)} B a frame, `
    + `${((100 * recBytes) / bytesOnDisk).toFixed(1)}% of the capture on disk`);

  console.log('\n--- a capture from before records ---\n');
  {
    const volume = new MemoryVolume();
    const id = 'cap-20260926-120000-old1';
    // An index file at version 1, as a build before ADR 0049 left it.
    const files = volume.open(id);
    const header = new Uint8Array(INDEX_HEADER_BYTES);
    writeIndexHeader(header, 1);
    files.index.write(0, header);
    files.close();

    const old = host(volume);
    old.send({ type: 'open', captureId: id });
    old.send({ type: 'append', packets: rows.slice(0, 5000) });
    old.ask({ type: 'appendRecords', frames: arrived.slice(0, 5000).map((a) => ({ id: a.packet.id, record: a.record })) });
    old.send({ type: 'finish' });
    await old.store.drain();
    old.ask({ type: 'revisitKit', requestId: 7, id: 10 });
    await old.store.drain();
    const kit = old.replies.find((r): r is Kit => r.type === 'revisitKit');
    check('a version 1 capture still opens and writes', old.said.filter((m) => m.type === 'ready').length, 1);
    check('...and answers a kit with no record', kit === undefined ? 'absent' : kit.record, null);
    checkTrue('...but with the row and the bytes', kit?.row?.id === 10 && kit.frames.some(([f]) => f === 10));
    check('...and writes nothing to a records file it does not have', volume.open(id).rec.size(), 0);
  }

  console.log('\n--- a torn records file ---\n');
  {
    const volume = h.volume;
    const id = 'cap-20260926-120000-rec1';
    const files = volume.open(id);
    const before = files.rec.size();
    // The last chunk's records half written: the index record describing them
    // exists, the bytes it points to do not all.
    files.rec.truncate(before - 1);
    files.close();

    const again = host(volume);
    again.send({ type: 'open', captureId: id });
    await again.store.drain();
    const ready = again.said.find((m): m is Extract<FromCapture, { type: 'ready' }> => m.type === 'ready');
    const lost = again.said.find((m) => m.type === 'failure');
    checkTrue('recovery drops the chunk whose records are torn', (ready?.frameCount ?? arrived.length) < arrived.length);
    checkTrue('...says so', lost !== undefined);
    const after = volume.open(id);
    checkTrue('...and cuts the records file back to the last whole chunk', after.rec.size() < before - 1);
    after.close();
    again.ask({ type: 'revisitKit', requestId: 9, id: 2 });
    await again.store.drain();
    const kit = again.replies.find((r): r is Kit => r.type === 'revisitKit');
    checkTrue('...and a surviving frame still rebuilds', kit !== undefined
      && treeFromKit(kit, 2, arrival) === render(arrived[1].packet.layers));
  }

  console.log('\n--- an import, the way the app feeds it ---\n');
  {
    const imp = host();
    imp.send({ type: 'open', captureId: 'cap-20260926-120000-rec4' });
    let batches = 0;
    let recordsMatchBatches = true;
    const file = new File([new Uint8Array(readFileSync(fixture.path))], basename(fixture.path));
    const outcome = await importAnyFile(file, {
      onBatch: (packets, records) => {
        batches += 1;
        if (JSON.stringify(records.map((r) => r.id)) !== JSON.stringify(packets.map((p) => p.id))) {
          recordsMatchBatches = false;
        }
        // `App.handleImportBatch`'s order: records, then the rows carrying
        // their bytes.
        imp.send({ type: 'appendRecords', frames: records });
        imp.send({ type: 'append', packets: packets.map((p) => plainForStore(p)) });
      },
    });
    imp.send({ type: 'finish' });
    await imp.store.drain();
    checkTrue('the import succeeded', outcome.ok === true);
    checkTrue('...in more than one batch', batches > 1);
    checkTrue('every batch carries a record for each of its frames, in order', recordsMatchBatches);

    const byId = new Map(arrived.map((a) => [a.packet.id, a] as const));
    let noRecord = 0;
    let wrong = 0;
    for (const a of arrived) imp.ask({ type: 'revisitKit', requestId: 10_000 + a.packet.id, id: a.packet.id });
    await imp.store.drain();
    for (const reply of imp.replies) {
      if (reply.type !== 'revisitKit' || reply.requestId < 10_000) continue;
      const id = reply.requestId - 10_000;
      if (reply.record === null) { noRecord += 1; continue; }
      try {
        if (treeFromKit(reply, id, arrival) !== render(byId.get(id)!.packet.layers)) wrong += 1;
      } catch (error) {
        if (!(error instanceof RecordMiss)) throw error;
        wrong += 1;
      }
    }
    check('every imported frame\'s record is in the store', noRecord, 0);
    check('...and rebuilds the tree arrival built', wrong, 0);
  }
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All record-store checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
