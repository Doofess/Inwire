/**
 * The capture store keeps a capture's packet marks (ADR 0067), driven through
 * the real host.
 *
 *   npx tsx scripts/capture/marks-store.ts
 *
 * Modelled on `stream-digest-store.ts`: a `CaptureHost` over a `MemoryVolume`,
 * every row through `plainForStore` and a `v8` round trip, `host.drain()` between
 * sends and answers. The marks file, `marks.iwmrk`, is reached the way the host
 * reaches it: `volume.open(id).marks`.
 *
 * The rows' ids are the marks' keys, and a reopened capture resumes past them
 * (`lastId`), so a mark means the same frame after Reopen.
 */
import { CaptureHost, type CaptureHostOptions } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import { plainForStore } from '../../src/services/capture/storePacket';
import { readExact } from '../../src/services/capture/blockFile';
import { MatchSet } from '../../src/services/capture/matchSet';
import { decodeMarks } from '../../src/services/marks';
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

function row(id: number): Packet {
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: '10.0.0.2', destination: '10.0.0.3', sourcePort: 50000, destPort: 443,
    protocol: 'TCP', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'], fields: {},
    length: 60, info: '', status: 'ok', interfaceName: 'eth0', layers: [],
    rawBytes: new Uint8Array([id & 0xff, 0, 0, 0]),
  } as Packet;
}

/** Rows as the store receives them: flattened, then through a structured clone. */
function crossed(packets: readonly Packet[]): Packet[] {
  return deserialize(serialize(packets.map((p) => plainForStore(p)))) as Packet[];
}

const rows = (from: number, to: number) => Array.from({ length: to - from + 1 }, (_, i) => row(from + i));

function marksFile(volume: MemoryVolume, captureId: string): Uint8Array {
  const files = volume.open(captureId);
  try {
    return readExact(files.marks, 0, files.marks.size());
  } finally {
    files.close();
  }
}

function writeMarksFile(volume: MemoryVolume, captureId: string, bytes: Uint8Array): void {
  const files = volume.open(captureId);
  try {
    files.marks.truncate(0);
    if (bytes.length > 0) files.marks.write(0, bytes);
  } finally {
    files.close();
  }
}

/** Runs a scan to its end and returns the ordinals it matched, or the message that ended it. */
async function scan(h: Host, requestId: number, filter: string): Promise<{ ordinals: number[]; message: string | null }> {
  h.send({ type: 'scan', requestId, filter });
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline && !h.of('scanDone').some((m) => m.requestId === requestId)) await sleep(1);
  const done = h.of('scanDone').find((m) => m.requestId === requestId);
  if (done === undefined || done.bits === null) return { ordinals: [], message: done?.message ?? 'no answer' };
  const set = MatchSet.fromBytes(done.frameCount, done.bits);
  const ordinals: number[] = [];
  for (let k = 0; k < set.count(); k++) ordinals.push(set.ordinalAt(k));
  return { ordinals, message: done.message };
}

const ID = 'cap-20261024-120000-mrk1';
const volume = new MemoryVolume();

console.log('--- 1. marks persist across a reopen ---\n');

{
  const h = host({}, volume);
  h.send({ type: 'open', captureId: ID });
  h.send({ type: 'append', packets: crossed(rows(1, 10)) });
  h.send({ type: 'finish' });
  await h.store.drain();
  check('a new capture starts with no marks', h.of('ready')[0]?.marks, []);

  h.send({ type: 'marks', captureId: ID, ids: [3, 1] });
  await h.store.drain();
  checkTrue('the file is written at once, not at close', marksFile(volume, ID).length > 0);
  h.store.close();
  check('no handle leaked', volume.outstanding, 0);
}

{
  const h = host({}, volume);
  h.send({ type: 'open', captureId: ID });
  await h.store.drain();
  check('1. a reopened capture reports its marks, sorted', h.of('ready')[0]?.marks, [1, 3]);
  check('...the ids it was reopened with are the ones the marks name', h.of('ready')[0]?.lastId, 10);

  console.log('\n--- 2. a marks message for another capture changes nothing ---\n');
  h.send({ type: 'marks', captureId: 'cap-20261024-120000-zzzz', ids: [9] });
  await h.store.drain();
  h.store.close();
  const again = host({}, volume);
  again.send({ type: 'open', captureId: ID });
  await again.store.drain();
  check('2. the open capture kept its own', again.of('ready')[0]?.marks, [1, 3]);
  check('...and nothing was created for the other one', volume.list().includes('cap-20261024-120000-zzzz'), false);

  console.log('\n--- 3. a scan answers frame.marked across the capture ---\n');
  const marked = await scan(again, 20, 'frame.marked == 1');
  check('3. exactly the ordinals of ids 1 and 3', marked, { ordinals: [0, 2], message: null });
  const unmarked = await scan(again, 21, 'frame.marked == 0');
  check('...and the others for == 0', unmarked.ordinals, [1, 3, 4, 5, 6, 7, 8, 9]);
  const everyone = await scan(again, 22, 'frame.marked');
  check('...and a bare frame.marked is every frame', everyone.ordinals.length, 10);

  console.log('\n--- 4. the set is replaced whole, and the next scan sees it ---\n');
  again.send({ type: 'marks', captureId: ID, ids: [5] });
  const replaced = await scan(again, 23, 'frame.marked == 1');
  check('4. the new set answers, the old one is gone', replaced.ordinals, [4]);

  console.log('\n--- 5. a mark on an expired id is harmless ---\n');
  again.send({ type: 'marks', captureId: ID, ids: [5, 999] });
  const expired = await scan(again, 24, 'frame.marked == 1');
  check('the scan does not throw, and the unknown id matches no row', expired, { ordinals: [4], message: null });
  await again.store.drain();
  check('...and the file keeps it', decodeMarks(marksFile(volume, ID)), [5, 999]);
  check('nothing failed', again.of('failure'), []);

  console.log('\n--- 6. an empty set empties the file ---\n');
  again.send({ type: 'marks', captureId: ID, ids: [] });
  await again.store.drain();
  check('6. the marks file is empty', marksFile(volume, ID).length, 0);
  again.store.close();
  const reopened = host({}, volume);
  reopened.send({ type: 'open', captureId: ID });
  await reopened.store.drain();
  check('...and a reopen has no marks', reopened.of('ready')[0]?.marks, []);
  reopened.store.close();
}

console.log('\n--- 7. a torn or foreign marks file opens with no marks ---\n');

{
  const writer = host({}, volume);
  writer.send({ type: 'open', captureId: ID });
  writer.send({ type: 'marks', captureId: ID, ids: [2, 4] });
  await writer.store.drain();
  const whole = marksFile(volume, ID);
  writer.store.close();

  for (const [name, bytes] of [
    ['truncated', whole.slice(0, whole.length - 3)],
    ['random bytes', Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0, 1, 2, 3, 4, 5])],
    ['one byte', Uint8Array.from([0x7b])],
  ] as const) {
    writeMarksFile(volume, ID, bytes);
    const h = host({}, volume);
    h.send({ type: 'open', captureId: ID });
    await h.store.drain();
    check(`7. ${name}: the capture opens`, h.of('ready').length, 1);
    check(`...with marks: []`, h.of('ready')[0]?.marks, []);
    check(`...and nothing failed`, h.of('failure'), []);
    const found = await scan(h, 30, 'frame.marked == 1');
    check(`...and the scan finds none`, found, { ordinals: [], message: null });
    h.store.close();
  }
  check('no handle leaked', volume.outstanding, 0);
}

console.log('\n--- 8. marks never leak into the next capture ---\n');

{
  const OTHER = 'cap-20261024-120000-mrk2';
  writeMarksFile(volume, ID, new TextEncoder().encode(JSON.stringify({ v: 1, ids: [1, 2] })));
  const h = host({}, volume);
  h.send({ type: 'open', captureId: ID });
  h.send({ type: 'open', captureId: OTHER });
  h.send({ type: 'append', packets: crossed(rows(1, 4)) });
  h.send({ type: 'finish' });
  await h.store.drain();
  const readies = h.of('ready');
  check('8. the first capture has its marks', readies[0]?.marks, [1, 2]);
  check('...the second starts with none', readies[1]?.marks, []);
  const found = await scan(h, 40, 'frame.marked == 1');
  check('...and a scan of the second matches nothing', found, { ordinals: [], message: null });
  h.send({ type: 'marks', captureId: ID, ids: [1] });
  await h.store.drain();
  check('a marks message naming the closed first capture is ignored',
    new TextDecoder().decode(marksFile(volume, ID)), JSON.stringify({ v: 1, ids: [1, 2] }));
  check('...and the second capture\'s file is untouched', marksFile(volume, OTHER).length, 0);
  h.store.close();
}

console.log('\n--- 9. marks go with the capture ---\n');

{
  const h = host({}, volume);
  h.send({ type: 'open', captureId: ID });
  h.send({ type: 'discard', captureId: ID });
  await h.store.drain();
  check('9. discard removes the directory, marks file and all', volume.list().includes(ID), false);
  h.send({ type: 'open', captureId: ID });
  await h.store.drain();
  check('...and a capture reusing the id starts with none', h.of('ready').at(-1)?.marks, []);
  h.store.close();
}

console.log(failures === 0
  ? '\nAll marks store checks passed.'
  : `\n${failures} marks store check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
