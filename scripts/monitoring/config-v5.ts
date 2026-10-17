/**
 * Assertion tests for the monitoring configuration and the exact NetFlow v5
 * decoder (ADRs 0058 and 0059).
 *
 *   npx tsx scripts/monitoring/config-v5.ts
 *
 * The decoder is exact where `services/flow/flowExport.ts` is lax: that one
 * serves a packet tree, where a short datagram should still show what it has;
 * this one feeds a journal-backed history, where a short datagram is evidence
 * of a problem and must be counted as one, never read as fewer flows.
 */
import assert from 'node:assert/strict';
import { LIMITS } from '../../src/services/monitoring/types';
import { DEFAULT_PORT, readSourceConfig } from '../../src/services/monitoring/config';
import { decodeV5, sourceKey } from '../../src/services/monitoring/v5';
import { EXPORTER, evidence, truncatedEvidence, v5Evidence, v5Payload } from './fixtures';

let failures = 0;
function test(name: string, fn: () => void) {
  try {
    fn();
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${e instanceof Error ? e.message.split('\n').join('\n        ') : String(e)}`);
  }
}

const config = { exporterIPv4: EXPORTER, bindIPv4: '192.0.2.50', port: 2055, storageLimitBytes: LIMITS.defaultStorageBytes };

// --- configuration ---------------------------------------------------------------

test('default port is 2055', () => assert.equal(DEFAULT_PORT, 2055));

test('a good configuration is read, and only its four fields are kept', () => {
  assert.deepEqual(readSourceConfig({ ...config, extra: 'ignored', nested: { a: 1 } }), config);
});

test('ports outside 1-65535 and non-integers are refused', () => {
  assert.equal(readSourceConfig({ ...config, port: 0 }), null);
  assert.equal(readSourceConfig({ ...config, port: 65_536 }), null);
  assert.equal(readSourceConfig({ ...config, port: -1 }), null);
  assert.equal(readSourceConfig({ ...config, port: 2055.5 }), null);
  assert.equal(readSourceConfig({ ...config, port: '2055' }), null);
  assert.equal(readSourceConfig({ ...config, port: NaN }), null);
  assert.notEqual(readSourceConfig({ ...config, port: 1 }), null);
  assert.notEqual(readSourceConfig({ ...config, port: 65_535 }), null);
});

test('a wildcard bind is refused, a specific one is not', () => {
  assert.equal(readSourceConfig({ ...config, bindIPv4: '0.0.0.0' }), null);
  assert.notEqual(readSourceConfig({ ...config, bindIPv4: '127.0.0.1' }), null);
});

test('the exporter cannot be the wildcard or the broadcast address', () => {
  assert.equal(readSourceConfig({ ...config, exporterIPv4: '0.0.0.0' }), null);
  assert.equal(readSourceConfig({ ...config, exporterIPv4: '255.255.255.255' }), null);
});

test('addresses must be strict dotted quads', () => {
  for (const bad of ['', ' 192.0.2.1', '192.0.2.1 ', '192.0.2.1\n', '192.0.2', '192.0.2.1.5', '192.0.2.256',
    '192.0.02.1', '01.2.3.4', '192.0.2.-1', '192.0.2.a', '::1', 'localhost', '192.0.2.1/24', '0x7f.0.0.1', '1e2.0.0.1']) {
    assert.equal(readSourceConfig({ ...config, exporterIPv4: bad }), null, `exporter ${JSON.stringify(bad)}`);
    assert.equal(readSourceConfig({ ...config, bindIPv4: bad }), null, `bind ${JSON.stringify(bad)}`);
  }
  assert.equal(readSourceConfig({ ...config, exporterIPv4: 42 }), null);
  assert.equal(readSourceConfig({ ...config, bindIPv4: undefined }), null);
});

test('storage limit is a safe integer at or above the minimum', () => {
  assert.equal(readSourceConfig({ ...config, storageLimitBytes: LIMITS.minStorageBytes - 1 }), null);
  assert.notEqual(readSourceConfig({ ...config, storageLimitBytes: LIMITS.minStorageBytes }), null);
  assert.equal(readSourceConfig({ ...config, storageLimitBytes: 2 ** 53 }), null);
  assert.equal(readSourceConfig({ ...config, storageLimitBytes: LIMITS.minStorageBytes + 0.5 }), null);
  assert.equal(readSourceConfig({ ...config, storageLimitBytes: '8589934592' }), null);
  assert.equal(readSourceConfig({ ...config, storageLimitBytes: Infinity }), null);
});

test('anything that is not an object is refused', () => {
  for (const v of [null, undefined, 0, 'x', [], [config], true]) assert.equal(readSourceConfig(v), null);
  const { port: _port, ...noPort } = config;
  assert.equal(readSourceConfig(noPort), null);
});

// --- source identity -------------------------------------------------------------------

test('a source is exporter + engine type + engine id', () => {
  assert.notEqual(sourceKey('192.0.2.1', 0, 1), sourceKey('192.0.2.1', 0, 2));
  assert.notEqual(sourceKey('192.0.2.1', 1, 0), sourceKey('192.0.2.1', 0, 0));
  assert.notEqual(sourceKey('192.0.2.1', 0, 0), sourceKey('192.0.2.2', 0, 0));
  assert.equal(sourceKey('192.0.2.1', 3, 4), sourceKey('192.0.2.1', 3, 4));
  // No pair of different triples may collide through the separator.
  assert.notEqual(sourceKey('192.0.2.1', 1, 23), sourceKey('192.0.2.1', 12, 3));
});

test('the key uses the configured exporter, not the datagram\'s sender or UDP port', () => {
  const a = decodeV5(v5Evidence({}, {}, { remotePort: 40_000 }), EXPORTER);
  const b = decodeV5(v5Evidence({}, {}, { remotePort: 51_234, remoteIPv4: '203.0.113.9' }), EXPORTER);
  assert.equal(a.kind, 'valid');
  assert.equal(b.kind, 'valid');
  if (a.kind === 'valid' && b.kind === 'valid') {
    assert.equal(a.flows[0].sourceKey, b.flows[0].sourceKey);
    assert.equal(a.flows[0].sourceKey, sourceKey(EXPORTER, 0, 0));
  }
});

// --- the decoder -------------------------------------------------------------------------

test('a valid datagram decodes every field', () => {
  const ev = v5Evidence(
    { src: '10.1.2.3', dst: '198.51.100.7', inputIf: 7, outputIf: 9, packets: 12, octets: 1234, srcPort: 51_000, dstPort: 53, protocol: 17, first: 100_000, last: 120_000 },
    { sequence: 77, engineType: 1, engineId: 2, uptime: 123_456 },
    { ref: { generation: '0'.repeat(32), entryId: 9 }, receivedMs: 1_760_000_123_456 },
  );
  const r = decodeV5(ev, EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind !== 'valid') return;
  assert.equal(r.engineType, 1);
  assert.equal(r.engineId, 2);
  assert.equal(r.sequence, 77);
  assert.equal(r.uptimeMs, 123_456);
  assert.equal(r.flows.length, 1);
  const f = r.flows[0];
  assert.deepEqual(f.ref, { generation: '0'.repeat(32), entryId: 9 });
  assert.equal(f.recordIndex, 0);
  assert.equal(f.sourceKey, sourceKey(EXPORTER, 1, 2));
  assert.equal(f.receivedMs, 1_760_000_123_456);
  assert.equal(f.srcAddr, '10.1.2.3');
  assert.equal(f.dstAddr, '198.51.100.7');
  assert.equal(f.srcPort, 51_000);
  assert.equal(f.dstPort, 53);
  assert.equal(f.protocol, 17);
  assert.equal(f.inputIf, 7);
  assert.equal(f.outputIf, 9);
  assert.equal(f.reportedOctets, 1234n);
  assert.equal(f.reportedPackets, 12n);
});

test('the headline assertions from the brief', () => {
  assert.equal(decodeV5(v5Evidence({ octets: 1234 }), EXPORTER).kind, 'valid');
  assert.equal(decodeV5(truncatedEvidence(), EXPORTER).kind, 'malformed');
});

test('a decoder reads through a view with a byte offset', () => {
  const inner = v5Payload({}, [{ octets: 4321 }]);
  const outer = new Uint8Array(inner.length + 10);
  outer.set(inner, 7);
  const r = decodeV5(evidence(outer.subarray(7, 7 + inner.length)), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind === 'valid') assert.equal(r.flows[0].reportedOctets, 4321n);
});

test('32-bit counters are exact as bigint, including the maximum', () => {
  const r = decodeV5(v5Evidence({ octets: 0xffff_ffff, packets: 0xffff_fffe }), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind === 'valid') {
    assert.equal(r.flows[0].reportedOctets, 4_294_967_295n);
    assert.equal(r.flows[0].reportedPackets, 4_294_967_294n);
    assert.equal(typeof r.flows[0].reportedOctets, 'bigint');
  }
});

test('a sum past 2^53 is exact', () => {
  const flows = Array.from({ length: 30 }, () => ({ octets: 0xffff_ffff }));
  const r = decodeV5(evidence(v5Payload({}, flows)), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind !== 'valid') return;
  // 2^53 / (2^32 - 1) is a little over 2^21 records; 80,000 datagrams of 30 passes it.
  let total = 0n;
  let records = 0n;
  for (let d = 0; d < 80_000; d++) {
    for (const f of r.flows) { total += f.reportedOctets; records++; }
  }
  assert.ok(total > 2n ** 53n, 'the sum passed 2^53');
  assert.equal(total, records * 4_294_967_295n, 'exactly records x (2^32 - 1)');
  assert.notEqual(BigInt(Number(total + 1n)), total + 1n, 'a double could not have held this sum');
});

test('truncated, over-long and header-short datagrams are malformed and say which', () => {
  const short = decodeV5(truncatedEvidence(), EXPORTER);
  assert.equal(short.kind, 'malformed');
  if (short.kind === 'malformed') assert.match(short.reason, /truncated/);

  const long = decodeV5(evidence(new Uint8Array([...v5Payload({}, [{}]), 0])), EXPORTER);
  assert.equal(long.kind, 'malformed');
  if (long.kind === 'malformed') assert.match(long.reason, /trailing/);

  const header = decodeV5(evidence(v5Payload({}, [{}]).slice(0, 23)), EXPORTER);
  assert.equal(header.kind, 'malformed');
  if (header.kind === 'malformed') assert.match(header.reason, /header/);

  const lies = decodeV5(evidence(v5Payload({ count: 3 }, [{}])), EXPORTER);
  assert.equal(lies.kind, 'malformed');

  const under = decodeV5(evidence(v5Payload({ count: 0 }, [{}])), EXPORTER);
  assert.equal(under.kind, 'malformed');
  if (under.kind === 'malformed') assert.match(under.reason, /trailing/);
});

test('fewer than two bytes is malformed; another version is unsupported', () => {
  assert.equal(decodeV5(evidence(new Uint8Array(0)), EXPORTER).kind, 'malformed');
  assert.equal(decodeV5(evidence(new Uint8Array([0])), EXPORTER).kind, 'malformed');
  for (const version of [0, 1, 4, 6, 7, 9, 10]) {
    const r = decodeV5(evidence(v5Payload({ version })), EXPORTER);
    assert.equal(r.kind, 'unsupported', `version ${version}`);
    if (r.kind === 'unsupported') assert.match(r.reason, new RegExp(String(version)));
  }
  // Two bytes naming another version are enough to say so.
  assert.equal(decodeV5(evidence(new Uint8Array([0, 9])), EXPORTER).kind, 'unsupported');
});

test('an empty export is valid with no flows', () => {
  const r = decodeV5(evidence(v5Payload({ sequence: 5, engineType: 2, engineId: 3 }, [])), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind === 'valid') {
    assert.deepEqual(r.flows, []);
    assert.equal(r.sequence, 5);
    assert.equal(r.engineType, 2);
    assert.equal(r.engineId, 3);
  }
});

test('records are indexed in order', () => {
  const r = decodeV5(evidence(v5Payload({}, [{ octets: 1 }, { octets: 2 }, { octets: 3 }])), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind === 'valid') {
    assert.deepEqual(r.flows.map((f) => f.recordIndex), [0, 1, 2]);
    assert.deepEqual(r.flows.map((f) => f.reportedOctets), [1n, 2n, 3n]);
  }
});

test('sampling: zero is unknown, never 1:1; anything else is reported as it is', () => {
  const zero = decodeV5(v5Evidence({}, { sampling: 0 }), EXPORTER);
  assert.equal(zero.kind, 'valid');
  if (zero.kind === 'valid') assert.deepEqual(zero.flows[0].sampling, { kind: 'unknown' });

  // mode 1 (deterministic), interval 100: 0b01 << 14 | 100
  const det = decodeV5(v5Evidence({}, { sampling: (1 << 14) | 100 }), EXPORTER);
  assert.equal(det.kind, 'valid');
  if (det.kind === 'valid') assert.deepEqual(det.flows[0].sampling, { kind: 'reported', mode: 1, interval: 100 });

  // mode 0 with an interval is still a report; the mode bits are not a switch
  const m0 = decodeV5(v5Evidence({}, { sampling: 10 }), EXPORTER);
  if (m0.kind === 'valid') assert.deepEqual(m0.flows[0].sampling, { kind: 'reported', mode: 0, interval: 10 });

  // mode 3, the largest interval
  const big = decodeV5(v5Evidence({}, { sampling: 0xffff }), EXPORTER);
  if (big.kind === 'valid') assert.deepEqual(big.flows[0].sampling, { kind: 'reported', mode: 3, interval: 0x3fff });
});

test('flow times come from the export time less the uptime elapsed since', () => {
  // exported at 1,760,000,000.250 s, uptime 600,000 ms; first 590,000, last 599,000
  const r = decodeV5(v5Evidence({ first: 590_000, last: 599_000 }), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind === 'valid') {
    const exportMs = 1_760_000_000_250;
    assert.equal(r.flows[0].startMs, exportMs - 10_000);
    assert.equal(r.flows[0].endMs, exportMs - 1_000);
  }
});

test('the 32-bit uptime wrapping between a flow and its export is handled', () => {
  // The exporter has been up 2^32 + 5,000 ms: uptime reads 5,000. A flow that
  // began 10,000 ms before the export has First = 2^32 - 5,000.
  const r = decodeV5(v5Evidence({ first: 2 ** 32 - 5_000, last: 2_000 }, { uptime: 5_000 }), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind === 'valid') {
    const exportMs = 1_760_000_000_250;
    assert.equal(r.flows[0].startMs, exportMs - 10_000);
    assert.equal(r.flows[0].endMs, exportMs - 3_000);
  }
});

test('uptime just past the wrap, with a flow that began just before it, is still valid', () => {
  // uptime has wrapped to 100; First = 2^32 - 50 is 150 ms ago, Last = 90 is 10 ms ago.
  const r = decodeV5(v5Evidence({ first: 2 ** 32 - 50, last: 90 }, { uptime: 100 }), EXPORTER);
  assert.equal(r.kind, 'valid');
  if (r.kind === 'valid') {
    const exportMs = 1_760_000_000_250;
    assert.equal(r.flows[0].startMs, exportMs - 150);
    assert.equal(r.flows[0].endMs, exportMs - 10);
  }
});

test('a First or Last later than the header uptime is malformed, never placed 49.7 days back', () => {
  const uptime = 600_000;
  const first = decodeV5(v5Evidence({ first: uptime + 1, last: uptime + 1 }, { uptime }), EXPORTER);
  assert.equal(first.kind, 'malformed');
  if (first.kind === 'malformed') assert.match(first.reason, /record 0 First/);
  // Last alone: First is fine, so it is the Last check that must catch it.
  const last = decodeV5(v5Evidence({ first: uptime - 10, last: uptime + 1 }, { uptime }), EXPORTER);
  assert.equal(last.kind, 'malformed');
  if (last.kind === 'malformed') assert.match(last.reason, /record 0 Last/);
  // The record is named, and one bad record in a later position spoils the datagram.
  const second = decodeV5(evidence(v5Payload({ uptime }, [{}, { first: uptime + 1, last: uptime + 1 }])), EXPORTER);
  assert.equal(second.kind, 'malformed');
  if (second.kind === 'malformed') assert.match(second.reason, /record 1 First/);
  // Exactly now is not the future.
  assert.equal(decodeV5(v5Evidence({ first: uptime, last: uptime }, { uptime }), EXPORTER).kind, 'valid');
});

test('times that cannot be derived make the datagram malformed, never receipt time', () => {
  // nanoseconds past a second
  const nsecs = decodeV5(v5Evidence({}, { nsecs: 1_000_000_000 }), EXPORTER);
  assert.equal(nsecs.kind, 'malformed');
  // an exporter with no clock: the flow would start before the epoch
  const noClock = decodeV5(v5Evidence({}, { secs: 0, nsecs: 0 }), EXPORTER);
  assert.equal(noClock.kind, 'malformed');
  // a flow that ends before it starts
  const backwards = decodeV5(v5Evidence({ first: 599_000, last: 590_000 }), EXPORTER);
  assert.equal(backwards.kind, 'malformed');
  if (backwards.kind === 'malformed') assert.match(backwards.reason, /before/);
  // one bad record spoils the datagram, so no half-read export is counted
  const mixed = decodeV5(evidence(v5Payload({}, [{}, { first: 599_000, last: 590_000 }])), EXPORTER);
  assert.equal(mixed.kind, 'malformed');
});

test('an empty export needs no flow time, so a bad clock does not make it malformed', () => {
  assert.equal(decodeV5(evidence(v5Payload({ secs: 0, nsecs: 0 }, [])), EXPORTER).kind, 'valid');
});

console.log(failures === 0 ? '\nall passed' : `\n${failures} FAILED`);
process.exit(failures === 0 ? 0 : 1);
