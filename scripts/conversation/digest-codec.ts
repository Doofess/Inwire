/**
 * The stream digest's snapshot file, `streams.iwdig` (ADR 0055).
 *
 *   npx tsx scripts/conversation/digest-codec.ts
 *
 * A round trip of a digest folded from a handful of rows, and every way the
 * file can be wrong, each of which must read as null rather than throw: the
 * store folds the digest again from the capture's rows in that case.
 */
import { deflateSync, inflateSync } from 'fflate';
import { StreamDigest } from '../../src/services/conversation/streamDigest';
import { decodeDigest, encodeDigest } from '../../src/services/conversation/digestCodec';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

const deflate = (b: Uint8Array): Uint8Array => deflateSync(b);
const inflate = (b: Uint8Array): Uint8Array => inflateSync(b);

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
    length: 60 + (len ?? 0), info: '', status: 'ok', streamId: 7, ...rest,
  } as Packet;
}

function sampleSnapshot() {
  nextId = 1;
  const d = new StreamDigest();
  const rows = [
    row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }), row(true, 'A', { seq: 1, ack: 1 }),
    row(true, 'A', { seq: 1, ack: 1, len: 100, protocolLabel: 'TLSv1.3' }),
    row(false, 'A', { seq: 1, ack: 101, len: 1000 }),
    row(true, 'FA', { seq: 101, ack: 1001 }), row(false, 'FA', { seq: 1001, ack: 102 }), row(true, 'A', { seq: 102, ack: 1002 }),
  ];
  for (const r of rows) d.feed(r);
  return d.snapshot();
}

const data = sampleSnapshot();
const encoded = encodeDigest(data, deflate);

// Round trip: the decoded data is the snapshot, and restores to the same digest.
const decoded = decodeDigest(encoded, inflate);
check('round trip returns the snapshot', decoded, data);
check('round trip restores a digest with the same summary', decoded && StreamDigest.restore(decoded).get(7)?.outcome, StreamDigest.restore(data).get(7)?.outcome);

// Each way the file can be wrong reads as null, and never throws.
const mustBeNull = (name: string, bytes: Uint8Array): void => {
  let result: unknown;
  let threw = false;
  try { result = decodeDigest(bytes, inflate); } catch { threw = true; }
  check(name, { threw, result: result ?? null }, { threw: false, result: null });
};

mustBeNull('an empty buffer', new Uint8Array(0));

const wrongMagic = encoded.slice();
wrongMagic[0] ^= 0xff;
mustBeNull('a wrong magic', wrongMagic);

const version2 = encoded.slice();
new DataView(version2.buffer).setUint16(4, 2, true);
mustBeNull('format version 2', version2);

mustBeNull('a body one byte short', encoded.slice(0, encoded.length - 1));

const flipped = encoded.slice();
flipped[flipped.length - 1] ^= 0x01;
mustBeNull('one flipped body byte', flipped);

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
