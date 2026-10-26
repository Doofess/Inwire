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
import { StreamDigest, type TaggedEntry } from '../../src/services/conversation/streamDigest';
import { DIGEST_FORMAT, decodeDigest, encodeDigest } from '../../src/services/conversation/digestCodec';
import { fnv1a } from '../../src/services/dissect/frameRecord';
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

const newer = encoded.slice();
new DataView(newer.buffer).setUint16(4, DIGEST_FORMAT + 1, true);
mustBeNull('a newer format', newer);

// A file written by format 1 (one deflated JSON text), byte for byte what the
// old encoder wrote: the header's checksum and length are right, only the
// version is old. It must read as null, so the store folds again.
{
  const body = deflate(new TextEncoder().encode(JSON.stringify(data)));
  const old = new Uint8Array(16 + body.length);
  const v = new DataView(old.buffer);
  v.setUint32(0, 0x47445749, true); v.setUint16(4, 1, true);
  v.setUint32(8, body.length, true); v.setUint32(12, fnv1a(body), true);
  old.set(body, 16);
  mustBeNull('an old format 1 file', old);
}

// Structure, not just bytes: a chunk that lies about its length, a count that
// does not match, and a chunk that is not an array each read as null even
// though the checksum (recomputed here) is right.
{
  const reseal = (mutate: (body: Uint8Array) => Uint8Array): Uint8Array => {
    const body = mutate(encoded.slice(16));
    const out = new Uint8Array(16 + body.length);
    const v = new DataView(out.buffer);
    v.setUint32(0, 0x47445749, true); v.setUint16(4, DIGEST_FORMAT, true);
    v.setUint32(8, body.length, true); v.setUint32(12, fnv1a(body), true);
    out.set(body, 16);
    return out;
  };
  mustBeNull('a count that does not match the entries', reseal((b) => { new DataView(b.buffer, b.byteOffset).setUint32(16, 99, true); return b; }));
  // The body's meta is throughId, version, count, captureEnd: 28 bytes.
  mustBeNull('a chunk that claims more bytes than the file has', reseal((b) => { new DataView(b.buffer, b.byteOffset).setUint32(28, 0x7fffffff, true); return b; }));
  mustBeNull('trailing bytes that are not a whole chunk', reseal((b) => { const c = new Uint8Array(b.length + 2); c.set(b); return c; }));
  mustBeNull('a chunk that inflates to something that is not an array', reseal((b) => {
    const z = deflate(new TextEncoder().encode('{"a":1}'));
    const c = new Uint8Array(28 + 4 + z.length);
    c.set(b.subarray(0, 28)); new DataView(c.buffer).setUint32(28, z.length, true); c.set(z, 32);
    return c;
  }));
}

// Stage 2: three kinds of entry, each tagged, and the capture's end carried.
function quicUdpRow(id: number, fromClient: boolean, over: Record<string, number | string>, quic: boolean): Packet {
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000 + 0.5,
    source: fromClient ? '10.0.0.2' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.2',
    sourcePort: fromClient ? 50000 : 443, destPort: fromClient ? 443 : 50000,
    protocol: quic ? 'QUIC' : 'UDP', frameProtocols: quic ? ['eth', 'ip', 'udp', 'quic'] : ['eth', 'ip', 'udp'],
    fields: over, length: 100, info: '', status: 'ok',
  } as Packet;
}
{
  nextId = 1;
  const d = new StreamDigest();
  const rows = [
    row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }),
    quicUdpRow(3, true, { 'udp.stream': 4 }, false), quicUdpRow(4, false, { 'udp.stream': 4 }, false),
    quicUdpRow(5, true, { 'udp.stream': 5, 'quic.connection.number': 0, 'quic.long.packet_type': 0, 'quic.version': 1 }, true),
    quicUdpRow(6, false, { 'udp.stream': 5, 'quic.connection.number': 0, 'quic.long.packet_type': 2, 'quic.version': 1 }, true),
  ];
  for (const r of rows) d.feed(r);
  const mixed = d.snapshot();
  // The QUIC datagrams count in their UDP flow too, so udp.stream 5 is a second UDP entry.
  check('a snapshot holds an entry per flow, a QUIC datagram\'s UDP flow too', mixed.entries.map((e) => e.kind).sort(), ['quic', 'tcp', 'udp', 'udp']);
  const bytes = encodeDigest(mixed, deflate);
  const back = decodeDigest(bytes, inflate);
  check('round-trips all three kinds', back, mixed);
  check('...with the capture\'s end', back?.captureEnd, d.captureEnd);
  const restored = back && StreamDigest.restore(back);
  check('...and restores each kind', restored && [restored.get(7)?.outcome, restored.getFlow('udp', 4)?.outcome, restored.getFlow('quic', 0)?.outcome],
    [d.get(7)?.outcome, d.getFlow('udp', 4)?.outcome, d.getFlow('quic', 0)?.outcome]);
  check('format 4 is what is written', new DataView(bytes.buffer, bytes.byteOffset).getUint16(4, true), 4);

  // A file written by stage 1: format 2, a 20-byte meta, untagged TCP entries,
  // every checksum and length right. Only its number is old, and it must read
  // as null, so the store folds the digest again rather than trust half of it.
  const tcpOnly = sampleSnapshot();
  const json = deflate(new TextEncoder().encode(JSON.stringify(tcpOnly.entries.map((e) => (e.kind === 'tcp' ? e.entry : null)))));
  const body = new Uint8Array(20 + 4 + json.length);
  const bv = new DataView(body.buffer);
  bv.setFloat64(0, tcpOnly.throughId, true); bv.setFloat64(8, tcpOnly.version, true); bv.setUint32(16, tcpOnly.entries.length, true);
  bv.setUint32(20, json.length, true); body.set(json, 24);
  const old = new Uint8Array(16 + body.length);
  const ov = new DataView(old.buffer);
  ov.setUint32(0, 0x47445749, true); ov.setUint16(4, 2, true);
  ov.setUint32(8, body.length, true); ov.setUint32(12, fnv1a(body), true);
  old.set(body, 16);
  mustBeNull('a format 2 snapshot is refused', old);
}

// Stage 3: TLS entries ride beside the TCP ones, and a format 3 file is refused.
{
  nextId = 1;
  const d = new StreamDigest();
  const tls = (fromClient: boolean, fields: Record<string, number | string>): Packet => ({
    ...row(fromClient, 'A', { seq: 1, ack: 1, len: 100 }),
    protocol: 'TCP', protocolLabel: 'TLSv1.3', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp', 'tls'],
    fields: { 'tcp.flags.ack': 1, 'tcp.len': 100, ...fields },
  });
  for (const r of [
    row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }),
    tls(true, { 'tls.record.content_type': 22, 'tls.handshake.type': 1, 'tls.handshake.ja4': 'x' }),
    tls(false, { 'tls.record.content_type': 22, 'tls.handshake.type': 2, 'tls.handshake.ja3s': 'y' }),
    tls(false, { 'tls.record.content_type': 21, 'tls.alert_message.level': 2, 'tls.alert_message.desc': 40 }),
  ]) d.feed(r);
  const withTls = d.snapshot();
  check('a snapshot holds a TLS entry beside the TCP one', withTls.entries.map((e) => e.kind).sort(), ['tcp', 'tls']);
  const bytes = encodeDigest(withTls, deflate);
  const back = decodeDigest(bytes, inflate);
  check('round-trips TLS entries', back, withTls);
  const restored = back && StreamDigest.restore(back);
  check('...and restores the TLS summary', restored?.getTls(7), d.getTls(7));
  check('...with its alert', restored?.getTls(7)?.fatalAlert, { side: 'server', name: 'Handshake Failure' });

  // Format 3, byte for byte as 6113366 wrote it: only its number is old.
  const body = bytes.slice(16);
  const old = new Uint8Array(16 + body.length);
  const v = new DataView(old.buffer);
  v.setUint32(0, 0x47445749, true); v.setUint16(4, 3, true);
  v.setUint32(8, body.length, true); v.setUint32(12, fnv1a(body), true);
  old.set(body, 16);
  mustBeNull('a format 3 snapshot is refused', old);
}

// Stage 3: a DHCP exchange rides beside the others, its xid above 2^31 intact.
{
  nextId = 1;
  const d = new StreamDigest();
  const dhcp = (type: number, fromClient: boolean, extra: Record<string, number | string> = {}): Packet => ({
    ...row(fromClient, 'A'),
    protocol: 'UDP', protocolLabel: 'DHCP', frameProtocols: ['eth', 'ethertype', 'ip', 'udp', 'dhcp'], streamId: undefined,
    sourcePort: fromClient ? 68 : 67, destPort: fromClient ? 67 : 68,
    fields: { 'udp.stream': 2, 'dhcp.id': 0xdeadbeef, 'dhcp.option.dhcp': type, 'dhcp.hw.mac_addr': '00:11:22:33:44:55', ...extra },
  });
  for (const r of [
    dhcp(1, true, { 'dhcp.option.hostname': 'laptop' }), dhcp(2, false, { 'dhcp.ip.your': '192.168.1.50' }),
    dhcp(3, true), dhcp(5, false, { 'dhcp.ip.your': '192.168.1.50', 'dhcp.option.dhcp_server_id': '192.168.1.1' }),
  ]) d.feed(r);
  const withDhcp = d.snapshot();
  check('a snapshot holds a UDP entry and a DHCP entry', withDhcp.entries.map((e) => e.kind).sort(), ['dhcp', 'udp']);
  const back = decodeDigest(encodeDigest(withDhcp, deflate), inflate);
  check('round-trips DHCP entries', back, withDhcp);
  const restored = back && StreamDigest.restore(back);
  check('...and restores the exchange, outcome and xid', [restored?.getDhcp(0xdeadbeef)?.outcome, restored?.getDhcp(0xdeadbeef)?.server.address], ['acked', '192.168.1.1']);
}

mustBeNull('a body one byte short',encoded.slice(0, encoded.length - 1));

const flipped = encoded.slice();
flipped[flipped.length - 1] ^= 0x01;
mustBeNull('one flipped body byte', flipped);

// Scale (final review I3): 500,000 streams that were a SYN answered by an RST.
// Format 1 wrote one JSON text of every entry, and V8 refuses a string past
// about 512 MB: this many threw "Invalid string length" at Stop. Entries are
// produced a thousand at a time and never held together on the way in, so
// the only thing that grows with the count is the encoder's own output.
{
  const COUNT = 500_000;
  const BATCH = 1000;
  const refusedEntries = function* (): Generator<TaggedEntry> {
    nextId = 1;
    for (let first = 1; first <= COUNT; first += BATCH) {
      const d = new StreamDigest();
      for (let s = first; s < first + BATCH; s++) {
        d.feed(row(true, 'S', { seq: 0, streamId: s, source: `10.${(s >> 16) & 255}.${(s >> 8) & 255}.${s & 255}` }));
        d.feed(row(false, 'RA', { seq: 0, ack: 1, streamId: s, destination: `10.${(s >> 16) & 255}.${(s >> 8) & 255}.${s & 255}` }));
      }
      yield* d.snapshot().entries;
    }
  };
  const input = { throughId: COUNT * 2, version: COUNT * 2, captureEnd: 1, entries: refusedEntries() };

  // The input must be big enough to have broken the old encoder, or passing
  // proves nothing: the same entries as one JSON text really do not fit.
  // 2^29 - 24 is V8's `String::kMaxLength` on 64-bit.
  let jsonLength = 0;
  for (const e of refusedEntries()) jsonLength += JSON.stringify(e).length + 1;
  check('every entry as one JSON text would exceed the longest string V8 allows',
    jsonLength > 2 ** 29 - 24, true);

  let bytes: Uint8Array | null = null;
  let error = '';
  try { bytes = encodeDigest(input, deflate); } catch (e) { error = (e as Error).message; }
  check('500,000 SYN+RST streams encode without throwing', error, '');
  const back = bytes === null ? null : decodeDigest(bytes, inflate);
  check('...and decode', back?.entries.length, COUNT);
  check('...with the same throughId and version', [back?.throughId, back?.version], [COUNT * 2, COUNT * 2]);
  let firstDifferent = -1;
  let i = 0;
  if (back !== null) {
    for (const e of refusedEntries()) {
      if (JSON.stringify(back.entries[i]) !== JSON.stringify(e)) { firstDifferent = i; break; }
      i++;
    }
  }
  check('...and every entry equals the one encoded', firstDifferent, -1);
  console.log(`      ${COUNT.toLocaleString()} streams -> ${bytes === null ? 0 : (bytes.length / 1048576).toFixed(1)} MB`);
}

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
