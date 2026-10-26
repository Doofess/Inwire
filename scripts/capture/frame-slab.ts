/**
 * `FrameSlab` (#17): a flush's frames as columns, so the store port clones five
 * buffers rather than one object and one view a frame. Round trip through the
 * serialiser a port uses, the exact sizing, the no-ring form, and the store
 * end to end - including the empty slab, which is the drain barrier.
 *
 *   npx tsx scripts/capture/frame-slab.ts
 */
import { serialize, deserialize } from 'node:v8';
import { packFrames, unpackFrames } from '../../src/services/capture/frameSlab';
import { CaptureHost } from '../../src/services/capture/captureHost';
import { MemoryVolume } from '../../src/services/capture/memoryVolume';
import type { RawFrame } from '../../src/services/capture/captureWriter';
import type { FromCapture, ToCapture } from '../../src/services/capture/captureProtocol';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n        ${detail}`}`);
  if (!ok) failures++;
}
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((v, i) => v === b[i]);

/** 300 frames of length 0-1500, views at odd offsets into one buffer with junk around them. */
function make(withRings: boolean): RawFrame[] {
  const big = new Uint8Array(300 * 1600).fill(0xa5);
  const out: RawFrame[] = [];
  let at = 7;
  for (let i = 0; i < 300; i++) {
    const len = (i * 37) % 1501;
    const view = big.subarray(at, at + len);
    for (let k = 0; k < len; k++) view[k] = (i * 31 + k) & 0xff;
    at += len + 3 + (i % 5);
    const frame: RawFrame = { id: 1000 + i, tsUs: 1_788_000_000_000_000 + i * 1234, bytes: view };
    if (withRings && i >= 10) frame.ring = { epoch: i < 120 ? 1 : 2, file: 1 + (i % 4), seq: i * 3 };
    out.push(frame);
  }
  return out;
}

{
  const input = make(true);
  const slab = packFrames(input);
  const out = unpackFrames(deserialize(serialize(slab)));
  let ok = out.length === input.length;
  let why = '';
  for (let i = 0; ok && i < input.length; i++) {
    const a = input[i], b = out[i];
    if (a.id !== b.id || a.tsUs !== b.tsUs || !same(a.bytes, b.bytes)
      || JSON.stringify(a.ring) !== JSON.stringify(b.ring)) { ok = false; why = `frame ${i}`; }
  }
  check('300 frames round trip through the serialiser', ok, why);
  check('frames 0-9 carry no ring after the round trip', out.slice(0, 10).every((f) => f.ring === undefined && !('ring' in f)));
  check('the ring changing at 120 survives', out[119].ring?.epoch === 1 && out[120].ring?.epoch === 2);
  const total = input.reduce((n, f) => n + f.bytes.length, 0);
  check('bytes is exactly sized and its length is the sum of the frames',
    slab.bytes.byteOffset === 0 && slab.bytes.byteLength === slab.bytes.buffer.byteLength && slab.bytes.length === total);
  check('ends are running end offsets', slab.ends[299] === total && slab.ends.length === 300);
  const direct = unpackFrames(slab);
  check('unpacked bytes are subarray views of the slab',
    direct.every((f) => f.bytes.buffer === slab.bytes.buffer) && direct[5].bytes.byteOffset === slab.ends[4]);
}

{
  const slab = packFrames(make(false));
  check('rings is null when no frame has a ring', slab.rings === null);
  check('...and unpacked frames have no ring', unpackFrames(slab).every((f) => f.ring === undefined));
  const empty = packFrames([]);
  check('an empty slab round trips to []', unpackFrames(deserialize(serialize(empty))).length === 0
    && empty.bytes.length === 0 && empty.rings === null);
}

{
  const volume = new MemoryVolume();
  const said: FromCapture[] = [];
  const store = new CaptureHost(volume, (m) => said.push(m));
  const send = (m: ToCapture) => store.receive(deserialize(serialize(m)) as ToCapture);
  send({ type: 'open', captureId: 'cap-20261009-010000-0001' });
  // Not the empty frame: the store has nothing to read back for one.
  const frames = make(false).filter((f) => f.bytes.length > 0).slice(0, 60);
  send({ type: 'appendBytes', slab: packFrames(frames), ack: 1 });
  const rows = frames.map((f) => ({
    id: f.id, source: 'a', destination: 'b', protocol: 'UDP', info: 'x', status: 'ok',
    length: f.bytes.length, tsUs: f.tsUs, relativeTime: 0, timeDelta: 0, interfaceName: 'eth0',
    layers: [], rawBytes: new Uint8Array(0), frameProtocols: ['frame'], fields: {},
  }) as unknown as Packet);
  send({ type: 'append', bytesSent: true, packets: rows });
  send({ type: 'appendBytes', slab: packFrames([]), ack: 2 });
  send({ type: 'finish' });
  await store.drain();
  send({ type: 'read', requestId: 7, ids: frames.map((f) => f.id) });
  await store.drain();
  const acks = said.filter((m) => m.type === 'bytesTaken').map((m) => (m as { ack: number }).ack);
  check('an append, and an empty slab, each ack', acks.join() === '1,2', `acks ${acks.join()}`);
  const reply = said.find((m) => m.type === 'bytes');
  const got = reply && reply.type === 'bytes' ? reply.frames : [];
  check('the store reads every frame back byte for byte',
    got.length === frames.length && got.every(([id, b], i) => id === frames[i].id && same(b, frames[i].bytes)),
    `got ${got.length}; said ${said.map((m) => m.type).join()}`);
}

if (failures > 0) { console.log(`\n${failures} FAILED`); process.exit(1); }
console.log('\nall passed');
