/**
 * The NetFlow v9 and IPFIX decoder of the monitoring collector (ADRs 0064,
 * 0065): what a datagram decodes to, given the templates in force.
 *
 *   npx tsx scripts/monitoring/flow-decode.ts
 *
 * Plain tsx. The messages are authored in `fixtures.ts` from the RFCs, not by
 * the decoder under test. The last tests decode what softflowd and pmacct sent
 * (`exporter-vectors.json`, tshark's totals beside it) and a few messages no
 * exporter produces; `exporter-state.ts` covers the sequence and sampling rules.
 */
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findWiresharkTool } from '../export/realCaptures';
import { pcapOf, udpFrameTo } from '../parity/synthetic';
import { ExporterState } from '../../src/services/monitoring/exporterState';
import { decodeDatagram, type FlowDecode, type NormalizedFlow } from '../../src/services/monitoring/flowDecode';
import { CollectorTemplateStore } from '../../src/services/monitoring/templates';
import { decodeV5 } from '../../src/services/monitoring/v5';
import { LIMITS, type DatagramEvidence } from '../../src/services/monitoring/types';
import {
  EXPORTER, be, dataSet, evidence, ipfixMessage, optionsTemplateRecord, optionsTemplateSet, setOf, templateRecord, templateSet, v5Payload, v9Message,
  type WireField,
} from './fixtures';

let failures = 0;
let passes = 0;
function test(name: string, fn: () => void): void {
  try {
    fn();
    passes++;
    console.log(`PASS  ${name}`);
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}`);
    console.log(`        ${String((e as Error).stack ?? e).split('\n').slice(0, 6).join('\n        ')}`.slice(0, 900));
  }
}

const SECS = 1_760_000_000;
const T0 = SECS * 1000 + 500;
const F = (type: number, length: number, pen?: number): WireField => ({ type, length, ...(pen === undefined ? {} : { pen }) });
const BASIC: WireField[] = [F(8, 4), F(12, 4), F(7, 2), F(11, 2), F(4, 1), F(1, 4), F(2, 4)];
const basicRecord = (src: string, dst: string, sp: number, dp: number, proto: number, octets: number, packets: number): number[] =>
  be.concat(be.ipv4(src), be.ipv4(dst), be.u16(sp), be.u16(dp), be.u8(proto), be.u32(octets), be.u32(packets));

let entry = 0;
const ev = (bytes: Uint8Array, over: Partial<DatagramEvidence> = {}): DatagramEvidence => {
  entry++;
  return evidence(bytes, { ref: { generation: '00112233445566778899aabbccddeeff', entryId: entry }, receivedMs: T0, ...over });
};
let v9seq = 0;
const v9m = (sets: number[][], over: { uptime?: number; sourceId?: number; count?: number } = {}): Uint8Array =>
  v9Message({ uptime: over.uptime ?? 600_000, secs: SECS, sequence: v9seq++, sourceId: over.sourceId ?? 1, ...(over.count === undefined ? {} : { count: over.count }) }, sets);
let ipfixSeq = 0;
const ipf = (sets: number[][], over: { domain?: number; length?: number } = {}): Uint8Array =>
  ipfixMessage({ secs: SECS, sequence: ipfixSeq++, domain: over.domain ?? 1, ...(over.length === undefined ? {} : { length: over.length }) }, sets);

const decode = (store: CollectorTemplateStore, bytes: Uint8Array, over: Partial<DatagramEvidence> = {}, policy = 2): FlowDecode =>
  decodeDatagram(ev(bytes, over), EXPORTER, policy, store);
function valid(d: FlowDecode): Extract<FlowDecode, { kind: 'valid' }> {
  assert.equal(d.kind, 'valid', d.kind === 'valid' ? '' : (d as { reason: string }).reason);
  return d as Extract<FlowDecode, { kind: 'valid' }>;
}
const fingerprint = (s: CollectorTemplateStore): string => JSON.stringify(s.exportScopes());

// --- policy ---------------------------------------------------------------------------------------------

test('policy-1-unsupported: v9 and IPFIX under policy 1 are decodeV5\'s own unsupported, unchanged', () => {
  const store = new CollectorTemplateStore();
  for (const bytes of [v9m([templateSet(9, [templateRecord(9, 256, BASIC)])]), ipf([templateSet(10, [templateRecord(10, 256, BASIC)])])]) {
    const e = ev(bytes);
    const expected = decodeV5(e, EXPORTER);
    assert.equal(expected.kind, 'unsupported');
    const got = decodeDatagram(e, EXPORTER, 1, store);
    assert.deepEqual(got, expected);
  }
  assert.equal(store.exportScopes().length, 0, 'nothing was read');
});

test('policy: v5 decodes under policies 1 and 2, anything else is unsupported', () => {
  const store = new CollectorTemplateStore();
  for (const policy of [1, 2]) {
    const d = valid(decode(store, v5Payload({}, [{ octets: 1000, packets: 10 }]), {}, policy));
    assert.equal(d.protocol, 'v5');
    assert.equal(d.sourceKey, `${EXPORTER}/0/0`);
    assert.equal(d.flows.length, 1);
    assert.equal(d.flows[0].reportedOctets, 1000n);
    assert.equal(d.flows[0].reportedPackets, 10n);
    assert.equal(d.dataRecords, 1);
    assert.equal(d.v5?.kind, 'valid');
  }
  assert.equal(decode(store, v5Payload(), {}, 3).kind, 'unsupported');
  assert.equal(decode(store, v5Payload(), {}, 0).kind, 'unsupported');
  const truncated = v5Payload().slice(0, 30);
  assert.deepEqual(decodeDatagram(ev(truncated), EXPORTER, 2, store), decodeV5(ev(truncated), EXPORTER), 'a malformed v5 is decodeV5\'s result');
  assert.equal(decode(store, Uint8Array.from([0, 7, 0, 0])).kind, 'unsupported', 'a version nobody reads');
});

// --- scope and order ------------------------------------------------------------------------------------

test('isolation: template 256 in (v9, A, 1) never decodes data in (v9, A, 2) or in IPFIX', () => {
  const store = new CollectorTemplateStore();
  const one = valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, BASIC)]), dataSet(256, [basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1)])])));
  assert.equal(one.flows.length, 1);
  const data = dataSet(256, [basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1)]);
  const other = valid(decode(store, v9m([data], { sourceId: 2 })));
  assert.deepEqual(other.awaiting, [{ templateId: 256, sets: 1, bytes: data.length }]);
  assert.equal(other.flows.length, 0);
  const asIpfix = valid(decode(store, ipf([data], { domain: 1 })));
  assert.equal(asIpfix.flows.length, 0);
  assert.equal(asIpfix.awaiting.length, 1);
  assert.equal(valid(decode(store, v9m([data], { sourceId: 1 }))).flows.length, 1, 'its own scope still decodes it');
});

test('same-datagram-template: a template applies to the data after it, not before it', () => {
  const store = new CollectorTemplateStore();
  const data = dataSet(256, [basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1)]);
  const before = valid(decode(store, v9m([data, templateSet(9, [templateRecord(9, 256, BASIC)])])));
  assert.equal(before.flows.length, 0, 'data before its template in the same datagram');
  assert.deepEqual(before.awaiting, [{ templateId: 256, sets: 1, bytes: data.length }]);
  const after = valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, BASIC)]), data, data])));
  assert.equal(after.flows.length, 2, 'two data sets after the template');
  assert.equal(after.awaiting.length, 0);
  assert.deepEqual(after.flows.map((f) => f.recordIndex), [0, 1]);
});

test('data-before-template: awaiting is counted per template id and never decoded later', () => {
  const store = new CollectorTemplateStore();
  const data = dataSet(300, [basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1), basicRecord('10.0.0.3', '10.0.0.4', 1, 2, 6, 100, 1)]);
  const early = valid(decode(store, ipf([data, data, dataSet(301, [[1, 2, 3, 4]])])));
  assert.deepEqual(early.awaiting, [{ templateId: 300, sets: 2, bytes: 2 * data.length }, { templateId: 301, sets: 1, bytes: 8 }]);
  assert.deepEqual(early.flows, []);
  assert.equal(early.dataRecords, 0, 'records unknown');
  const later = valid(decode(store, ipf([templateSet(10, [templateRecord(10, 300, BASIC)]), dataSet(300, [basicRecord('10.0.0.5', '10.0.0.6', 1, 2, 6, 7, 1)])])));
  assert.equal(later.flows.length, 1, 'only the new datagram\'s own record');
  assert.equal(later.flows[0].srcAddr, '10.0.0.5');
});

test('data-before-template: data for a template refused under the bounds lands in refused', () => {
  const store = new CollectorTemplateStore();
  const many = Array.from({ length: LIMITS.templatesPerScope }, (_, i) => templateRecord(10, 256 + i, [F(8, 4), F(12, 4), F(1, 4)]));
  const first = valid(decode(store, ipf([templateSet(10, many)])));
  assert.equal(first.awaiting.length, 0);
  assert.equal(store.inventory().length, LIMITS.templatesPerScope);
  const data = dataSet(900, [basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1)]);
  const second = valid(decode(store, ipf([templateSet(10, [templateRecord(10, 900, BASIC)]), data])));
  assert.deepEqual(second.refused, [{ templateId: 900, sets: 1, bytes: data.length }]);
  assert.deepEqual(second.awaiting, []);
  assert.equal(second.flows.length, 0);
  assert.equal(store.counters({ protocol: 'ipfix', exporter: EXPORTER, exporterPort: 40_000, domain: 1 }).refused, 1);
});

test('redefinition-replaces, refresh-keeps: the newest layout decodes, a refresh does not disturb it', () => {
  const store = new CollectorTemplateStore();
  const swapped: WireField[] = [F(12, 4), F(8, 4), F(11, 2), F(7, 2), F(4, 1), F(1, 4), F(2, 4)];
  const row = basicRecord('10.0.0.1', '10.0.0.2', 1000, 2000, 6, 100, 1);
  valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, BASIC)])])));
  const refreshed = valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, BASIC)]), dataSet(256, [row])])));
  assert.equal(refreshed.flows[0].srcAddr, '10.0.0.1');
  const replaced = valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, swapped)]), dataSet(256, [row])])));
  assert.equal(replaced.flows[0].srcAddr, '10.0.0.2', 'the new layout reads the same bytes the other way round');
  assert.equal(replaced.flows[0].srcPort, 2000);
});

test('withdrawal-ignored: a withdrawal and a withdraw-all change nothing and are counted', () => {
  const store = new CollectorTemplateStore();
  const row = basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1);
  valid(decode(store, ipf([templateSet(10, [templateRecord(10, 256, BASIC)])])));
  const d = valid(decode(store, ipf([
    templateSet(10, [be.concat(be.u16(256), be.u16(0))]),
    templateSet(10, [be.concat(be.u16(2), be.u16(0))]),
    optionsTemplateSet(10, [be.concat(be.u16(300), be.u16(0))]),
    optionsTemplateSet(10, [be.concat(be.u16(3), be.u16(0))]),
    dataSet(256, [row]),
  ])));
  assert.equal(d.withdrawalsIgnored, 4);
  assert.equal(d.flows.length, 1, 'the template survived');
  assert.equal(store.counters({ protocol: 'ipfix', exporter: EXPORTER, exporterPort: 40_000, domain: 1 }).withdrawalsIgnored, 4);
});

// --- restarts ---------------------------------------------------------------------------------------------

test('restart-invalidates-scope: an exporter that restarts and reuses an id with another layout', () => {
  const store = new CollectorTemplateStore();
  const swapped: WireField[] = [F(12, 4), F(8, 4), F(11, 2), F(7, 2), F(4, 1), F(1, 4), F(2, 4)];
  const row = basicRecord('10.0.0.1', '10.0.0.2', 1000, 2000, 6, 100, 1);
  valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, BASIC)])], { uptime: 600_000 })));
  // Uptime back by 5 s: reordered, not a restart.
  const reordered = valid(decode(store, v9m([dataSet(256, [row])], { uptime: 595_000 })));
  assert.equal(reordered.restart, false);
  assert.equal(reordered.flows.length, 1);
  // Back by a minute: a restart. The data of the new session is not read through the old layout.
  const restarted = valid(decode(store, v9m([dataSet(256, [row])], { uptime: 20_000 })));
  assert.equal(restarted.restart, true);
  assert.equal(restarted.flows.length, 0);
  assert.equal(restarted.awaiting.length, 1);
  const fresh = valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, swapped)]), dataSet(256, [row])], { uptime: 21_000 })));
  assert.equal(fresh.restart, false);
  assert.equal(fresh.flows[0].srcAddr, '10.0.0.2');
});

test('restart-invalidates-scope: a v9 uptime wrap is not a restart', () => {
  const store = new CollectorTemplateStore();
  const row = basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1);
  valid(decode(store, v9m([templateSet(9, [templateRecord(9, 256, BASIC)])], { uptime: 2 ** 32 - 1000 })));
  const wrapped = valid(decode(store, v9m([dataSet(256, [row])], { uptime: 4000 })));
  assert.equal(wrapped.restart, false);
  assert.equal(wrapped.flows.length, 1);
});

test('restart-invalidates-scope: an IPFIX source port change drops the old port\'s templates', () => {
  const store = new CollectorTemplateStore();
  const row = basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1);
  valid(decode(store, ipf([templateSet(10, [templateRecord(10, 256, BASIC)]), dataSet(256, [row])]), { remotePort: 40_000 }));
  const moved = valid(decode(store, ipf([dataSet(256, [row])]), { remotePort: 40_001 }));
  assert.equal(moved.restart, true);
  assert.equal(moved.flows.length, 0, 'the old port\'s templates are not used');
  assert.equal(moved.awaiting.length, 1);
  assert.equal(moved.sourceKey, `ipfix:${EXPORTER}/1`, 'the source key stays the same');
  const back = valid(decode(store, ipf([dataSet(256, [row])]), { remotePort: 40_000 }));
  assert.equal(back.flows.length, 0, 'and neither does the port that came back');
});

test('restart-invalidates-scope: an IE 160 jump invalidates earlier templates and keeps this datagram\'s', () => {
  const store = new CollectorTemplateStore();
  const row = basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1);
  const optionsTemplate = optionsTemplateRecord(10, 300, [F(143, 4)], [F(160, 8)]);
  const init = (ms: number) => be.concat(be.u32(0), be.uint(ms, 8));
  valid(decode(store, ipf([templateSet(10, [templateRecord(10, 256, BASIC)]), optionsTemplateSet(10, [optionsTemplate]), dataSet(300, [init(1_759_990_000_000)])])));
  const steady = valid(decode(store, ipf([dataSet(300, [init(1_759_990_004_000)]), dataSet(256, [row])])));
  assert.equal(steady.restart, false, 'within 10 s');
  assert.equal(steady.flows.length, 1);
  const jumped = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 257, BASIC)]), dataSet(300, [init(1_760_000_000_000)]), dataSet(256, [row]), dataSet(257, [row]),
  ])));
  assert.equal(jumped.restart, true);
  assert.deepEqual(jumped.awaiting.map((a) => a.templateId), [256], 'defined in an earlier datagram');
  assert.equal(jumped.flows.length, 1, 'defined earlier in this one');
  assert.equal(jumped.flows[0].recordIndex, 0);
});

// --- information elements ---------------------------------------------------------------------------------

test('bigint: octetDeltaCount 0xFFFFFFFFFFFFFFFF reads as 18446744073709551615n', () => {
  const store = new CollectorTemplateStore();
  const wide = [F(8, 4), F(12, 4), F(1, 8), F(2, 8)];
  const d = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 256, wide)]),
    dataSet(256, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.uint(0xffffffffffffffffn, 8), be.uint(2n ** 63n, 8))]),
  ])));
  assert.equal(d.flows[0].reportedOctets, 18446744073709551615n);
  assert.equal(d.flows[0].reportedPackets, 9223372036854775808n);
});

test('reduced-size encoding: a 2-byte octet count reads as itself', () => {
  const store = new CollectorTemplateStore();
  const d = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 256, [F(8, 4), F(12, 4), F(1, 2), F(2, 1)])]),
    dataSet(256, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u16(65_535), be.u8(200))]),
  ])));
  assert.equal(d.flows[0].reportedOctets, 65_535n);
  assert.equal(d.flows[0].reportedPackets, 200n);
});

test('total-counts: 85/86 are used only without a delta count, and say so', () => {
  const store = new CollectorTemplateStore();
  const row = (octets: number) => be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.uint(octets, 8), be.uint(7, 8));
  const totals = valid(decode(store, ipf([templateSet(10, [templateRecord(10, 256, [F(8, 4), F(12, 4), F(85, 8), F(86, 8)])]), dataSet(256, [row(5000)])])));
  assert.equal(totals.flows[0].reportedOctets, 5000n);
  assert.equal(totals.flows[0].reportedPackets, 7n);
  assert.equal(totals.flows[0].totalCounts, true);
  const both = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 257, [F(8, 4), F(12, 4), F(1, 4), F(2, 4), F(85, 8), F(86, 8)])]),
    dataSet(257, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u32(11), be.u32(3), be.uint(999_999, 8), be.uint(999, 8))]),
  ])));
  assert.equal(both.flows[0].reportedOctets, 11n, 'the delta, not the running total');
  assert.equal(both.flows[0].reportedPackets, 3n);
  assert.equal(both.flows[0].totalCounts, false);
});

test('total-counts: a template with no octet count is unsupported, its records counted and not totalled', () => {
  const store = new CollectorTemplateStore();
  const d = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 256, [F(8, 4), F(12, 4), F(7, 2)])]),
    dataSet(256, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u16(1)), be.concat(be.ipv4('10.0.0.3'), be.ipv4('10.0.0.4'), be.u16(2))]),
  ])));
  assert.deepEqual(d.unsupportedTemplates, [256]);
  assert.equal(d.dataRecords, 2);
  assert.deepEqual(d.flows, []);
  assert.equal(store.inventory()[0].unsupported, true);
});

test('biflow: PEN 29305 reverse counts are kept apart from the forward ones', () => {
  const store = new CollectorTemplateStore();
  const fields = [F(8, 4), F(12, 4), F(1, 4), F(2, 4), F(1, 4, 29305), F(2, 4, 29305)];
  const d = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 256, fields)]),
    dataSet(256, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u32(1000), be.u32(10), be.u32(70_000), be.u32(60))]),
  ])));
  const f = d.flows[0];
  assert.equal(f.reportedOctets, 1000n);
  assert.equal(f.reportedPackets, 10n);
  assert.equal(f.reverseOctets, 70_000n);
  assert.equal(f.reversePackets, 60n);
  const plain = valid(decode(store, ipf([templateSet(10, [templateRecord(10, 257, BASIC)]), dataSet(257, [basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 1, 1)])])));
  assert.equal(plain.flows[0].reverseOctets, null);
  assert.equal(plain.flows[0].reversePackets, null);
});

test('addresses, ports, protocol, interfaces, direction and flags, IPv6 included', () => {
  const store = new CollectorTemplateStore();
  const fields = [F(27, 16), F(28, 16), F(7, 2), F(11, 2), F(4, 1), F(1, 4), F(2, 4), F(10, 4), F(14, 4), F(61, 1), F(6, 2)];
  const d = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 256, fields)]),
    dataSet(256, [be.concat(be.ipv6('2001:db8::1'), be.ipv6('2001:db8:0:1::2'), be.u16(443), be.u16(50_000), be.u8(6), be.u32(9), be.u32(1), be.u32(3), be.u32(4), be.u8(1), be.u16(0x1b))]),
  ])));
  const f = d.flows[0];
  assert.deepEqual([f.srcAddr, f.dstAddr, f.srcPort, f.dstPort, f.protocol], ['2001:db8::1', '2001:db8:0:1::2', 443, 50_000, 6]);
  assert.deepEqual([f.inputIf, f.outputIf, f.direction, f.tcpFlags], [3, 4, 1, 0x1b]);
  assert.equal(f.entryId, entry);
});

test('enterprise-unknown-kept: unknown, enterprise and variable-length elements are listed, and the record still reads', () => {
  const store = new CollectorTemplateStore();
  const fields = [F(8, 4), F(12, 4), F(1, 4), F(100, 4, 9999), F(250, 4), F(300, 0xffff)];
  const d = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, 256, fields)]),
    dataSet(256, [
      be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u32(11), be.u32(1), be.u32(2), [3, 0x61, 0x62, 0x63]),
      be.concat(be.ipv4('10.0.0.3'), be.ipv4('10.0.0.4'), be.u32(22), be.u32(1), be.u32(2), [255, 0, 1, 0x7a]),
    ]),
  ])));
  assert.equal(d.flows.length, 2);
  assert.equal(d.flows[1].reportedOctets, 22n, 'the variable-length element did not misplace the next record');
  const inv = store.inventory();
  assert.equal(inv.length, 1);
  assert.deepEqual(inv[0].notInterpreted, [{ pen: 9999, ie: 100 }, { pen: null, ie: 250 }, { pen: null, ie: 300 }]);
});

// --- flow times --------------------------------------------------------------------------------------------

/** One IPFIX record with a start and an end element and a count, so it is a flow. */
function timed(store: CollectorTemplateStore, id: number, start: WireField, end: WireField, startBytes: number[], endBytes: number[], domain = 1): NormalizedFlow {
  const d = valid(decode(store, ipf([
    templateSet(10, [templateRecord(10, id, [F(8, 4), F(12, 4), F(1, 4), start, end])]),
    dataSet(id, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u32(1), startBytes, endBytes)]),
  ], { domain })));
  return d.flows[0];
}
const ntp = (unixMs: number): number[] => {
  const secs = Math.floor(unixMs / 1000);
  const frac = Math.round(((unixMs % 1000) / 1000) * 2 ** 32);
  return be.concat(be.u32(secs + 2_208_988_800), be.u32(frac));
};

test('flow-times: IPFIX absolute forms, each of 150-157', () => {
  const store = new CollectorTemplateStore();
  const start = 1_759_999_000_250;
  const end = 1_759_999_500_750;
  let f = timed(store, 256, F(150, 4), F(151, 4), be.u32(Math.floor(start / 1000)), be.u32(Math.floor(end / 1000)));
  assert.deepEqual([f.startMs, f.endMs], [Math.floor(start / 1000) * 1000, Math.floor(end / 1000) * 1000], 'seconds');
  f = timed(store, 257, F(152, 8), F(153, 8), be.uint(start, 8), be.uint(end, 8));
  assert.deepEqual([f.startMs, f.endMs], [start, end], 'milliseconds');
  f = timed(store, 258, F(154, 8), F(155, 8), ntp(start), ntp(end));
  assert.deepEqual([f.startMs, f.endMs], [start, end], 'microseconds, NTP format');
  f = timed(store, 259, F(156, 8), F(157, 8), ntp(start), ntp(end));
  assert.deepEqual([f.startMs, f.endMs], [start, end], 'nanoseconds, NTP format');
});

test('flow-times: IPFIX 158/159 are microseconds before the export time', () => {
  const store = new CollectorTemplateStore();
  const f = timed(store, 256, F(158, 4), F(159, 4), be.u32(5_000_000), be.u32(1_500_000));
  assert.deepEqual([f.startMs, f.endMs], [SECS * 1000 - 5000, SECS * 1000 - 1500]);
});

test('flow-times: IPFIX 21/22 need IE 160, and are null without it', () => {
  const store = new CollectorTemplateStore();
  const without = timed(store, 256, F(22, 4), F(21, 4), be.u32(1000), be.u32(9000), 1);
  assert.deepEqual([without.startMs, without.endMs], [null, null], 'never the receipt time');
  const init = 1_759_990_000_000;
  valid(decode(store, ipf([
    optionsTemplateSet(10, [optionsTemplateRecord(10, 300, [F(143, 4)], [F(160, 8)])]),
    dataSet(300, [be.concat(be.u32(0), be.uint(init, 8))]),
  ], { domain: 2 })));
  const known = timed(store, 257, F(22, 4), F(21, 4), be.u32(1000), be.u32(9000), 2);
  assert.deepEqual([known.startMs, known.endMs], [init + 1000, init + 9000]);
});

test('flow-times: v9 21/22 against the header\'s uptime, wrap included', () => {
  const store = new CollectorTemplateStore();
  const fields = [F(8, 4), F(12, 4), F(1, 4), F(22, 4), F(21, 4)];
  const run = (uptime: number, first: number, last: number) => valid(decode(store, v9m([
    templateSet(9, [templateRecord(9, 256, fields)]),
    dataSet(256, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u32(1), be.u32(first), be.u32(last))]),
  ], { uptime }))).flows[0];
  const plain = run(600_000, 590_000, 599_000);
  assert.deepEqual([plain.startMs, plain.endMs], [SECS * 1000 - 10_000, SECS * 1000 - 1000]);
  const wrapped = run(1000, 2 ** 32 - 4000, 500);
  assert.deepEqual([wrapped.startMs, wrapped.endMs], [SECS * 1000 - 5000, SECS * 1000 - 500], 'a flow that began before the wrap');
  const future = run(2000, 3000, 3000);
  assert.deepEqual([future.startMs, future.endMs], [null, null], 'later than the header\'s uptime cannot be derived');
});

test('flow-times: v9 may carry the absolute forms too', () => {
  const store = new CollectorTemplateStore();
  const d = valid(decode(store, v9m([
    templateSet(9, [templateRecord(9, 256, [F(8, 4), F(12, 4), F(1, 4), F(152, 8), F(153, 8)])]),
    dataSet(256, [be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u32(1), be.uint(1_759_999_000_250, 8), be.uint(1_759_999_000_750, 8))]),
  ])));
  assert.deepEqual([d.flows[0].startMs, d.flows[0].endMs], [1_759_999_000_250, 1_759_999_000_750]);
});

// --- options ------------------------------------------------------------------------------------------------

test('options: records are described, never flows, never totalled', () => {
  const store = new CollectorTemplateStore();
  const v9scope = F(1, 4); // System
  const d = valid(decode(store, v9m([
    optionsTemplateSet(9, [optionsTemplateRecord(9, 300, [v9scope], [F(34, 4), F(35, 1)])]),
    dataSet(300, [be.concat(be.u32(0), be.u32(10), be.u8(2))], 3),
  ])));
  assert.equal(d.optionsRecords, 1);
  assert.equal(d.dataRecords, 0);
  assert.deepEqual(d.flows, []);
  assert.equal(d.options.length, 1);
  assert.equal(d.options[0].templateId, 300);
  assert.equal(d.options[0].samplingInterval, 10);
  assert.equal(d.options[0].samplingAlgorithm, 2);
  assert.deepEqual(d.options[0].scope, [{ type: 1, value: 0n }]);
});

test('options: the IPFIX selector, IE 160 and an interface name', () => {
  const store = new CollectorTemplateStore();
  const d = valid(decode(store, ipf([
    optionsTemplateSet(10, [
      optionsTemplateRecord(10, 300, [F(143, 4)], [F(305, 4), F(306, 4), F(304, 2), F(160, 8)]),
      optionsTemplateRecord(10, 301, [F(10, 4)], [F(82, 0xffff)]),
    ]),
    dataSet(300, [be.concat(be.u32(0), be.u32(1), be.u32(9), be.u16(1), be.uint(1_759_990_000_000, 8))]),
    dataSet(301, [be.concat(be.u32(7), [4, 0x65, 0x74, 0x68, 0x30]), be.concat(be.u32(8), [3, 0x6c, 0x6f, 0x00])]),
  ])));
  assert.equal(d.optionsRecords, 3);
  const [selector, ifA, ifB] = d.options;
  assert.deepEqual([selector.packetInterval, selector.packetSpace, selector.selectorAlgorithm, selector.systemInitMs], [1, 9, 1, 1_759_990_000_000]);
  assert.deepEqual(ifA.interfaceName, { ifIndex: 7, name: 'eth0' });
  assert.deepEqual(ifB.interfaceName, { ifIndex: 8, name: 'lo' }, 'a trailing NUL is not part of the name');
});

// --- malformed -------------------------------------------------------------------------------------------------

test('malformed: each shape is malformed and leaves the store unchanged', () => {
  const store = new CollectorTemplateStore();
  valid(decode(store, ipf([templateSet(10, [templateRecord(10, 256, BASIC)])])));
  const before = fingerprint(store);
  const row = basicRecord('10.0.0.1', '10.0.0.2', 1, 2, 6, 100, 1);
  const cases: [string, Uint8Array][] = [
    ['set length under 4', ipf([templateSet(10, [templateRecord(10, 257, BASIC)]), setOf(256, row, 0, 3)])],
    ['a set running past the message end', ipf([templateSet(10, [templateRecord(10, 257, BASIC)]), setOf(256, row, 0, 400)])],
    ['template field count overflow', ipf([setOf(2, be.concat(be.u16(257), be.u16(40), be.u16(8), be.u16(4)))])],
    ['an IPFIX message length that differs', ipf([templateSet(10, [templateRecord(10, 257, BASIC)])], { length: 30 })],
    ['template id 255', ipf([templateSet(10, [templateRecord(10, 255, BASIC)])])],
    ['non-zero bytes after the templates', ipf([templateSet(10, [templateRecord(10, 257, BASIC)], 0), setOf(2, be.concat(templateRecord(10, 258, BASIC), [0, 0, 7]))])],
    ['more than 3 bytes after the templates', ipf([setOf(2, be.concat(templateRecord(10, 258, BASIC), [0, 0, 0, 0, 0]))])],
    ['a v9 template id under 256', v9m([templateSet(9, [templateRecord(9, 100, BASIC)])])],
    ['a v9 options field overflow', v9m([setOf(1, be.concat(be.u16(300), be.u16(40), be.u16(8), be.u16(1), be.u16(4)))])],
    ['a header cut short', ipf([]).slice(0, 12)],
  ];
  for (const [name, bytes] of cases) {
    const d = decode(store, bytes);
    assert.equal(d.kind, 'malformed', name);
    assert.equal(fingerprint(store), before, `${name}: the store changed`);
  }
});

test('malformed: what is not: padding, the v9 count, a v9 options template and a reserved set', () => {
  const store = new CollectorTemplateStore();
  assert.equal(decode(store, ipf([templateSet(10, [templateRecord(10, 256, BASIC)], 3)])).kind, 'valid', 'three bytes of zero padding');
  assert.equal(decode(store, v9m([templateSet(9, [templateRecord(9, 256, BASIC)], 2)], { count: 999 })).kind, 'valid', 'the v9 count is not checked');
  assert.equal(decode(store, v9m([setOf(7, [1, 2, 3, 4])])).kind, 'valid', 'a reserved set id is skipped');
  assert.equal(decode(store, ipf([])).kind, 'valid', 'a message of no sets');
});


// --- what the exporters sent ----------------------------------------------------------------------------

interface VectorPass {
  name: string;
  exporter: string;
  datagrams: { atMs: number; port: number; hex: string }[];
  tshark: { records: number; octets: string; packets: string; reverseOctets: string; reversePackets: string };
}
const vectorFile = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'exporter-vectors.json'), 'utf8')) as { passes: VectorPass[] };
const hexBytes = (hex: string): Uint8Array => Uint8Array.from(hex.match(/../g) ?? [], (h) => parseInt(h, 16));
const u32be = (b: Uint8Array, p: number): number => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;

/**
 * What each pass should settle to: the sequence mode and the sampling the exporter stated. A pass too short to
 * hold 8 pairs that tell the conventions apart stays learning, as does pmacct's IPFIX, which sends no options
 * records: with none, both conventions count alike and nothing tells them apart.
 */
const EXPECT: Record<string, { mode: string; sampling: string }> = {
  'softflowd-v9': { mode: 'learning', sampling: 'known:1' },
  'softflowd-v9-s10': { mode: 'learning', sampling: 'known:10' },
  'softflowd-v10': { mode: 'learning', sampling: 'known:1' },
  'softflowd-v10-b': { mode: 'learning', sampling: 'known:1' },
  'softflowd-v10-s10': { mode: 'learning', sampling: 'known:10' },
  'softflowd-v10-A-milli': { mode: 'learning', sampling: 'known:1' },
  'pmacct-v9': { mode: 'rfc', sampling: 'absent' },
  'pmacct-v10': { mode: 'learning', sampling: 'absent' },
  'refresh-softflowd-v9': { mode: 'rfc', sampling: 'known:1' },
  'refresh-softflowd-v10': { mode: 'own-records', sampling: 'known:1' },
  'refresh-pmacct-v9': { mode: 'rfc', sampling: 'absent' },
  'refresh-pmacct-v10': { mode: 'rfc', sampling: 'absent' },
};

for (const pass of vectorFile.passes) {
  test(`exporter-vectors: ${pass.name} decodes to tshark's totals`, () => {
    const store = new CollectorTemplateStore();
    const state = new ExporterState();
    const head = hexBytes(pass.datagrams[0].hex);
    const base = u32be(head, head[1] === 9 ? 8 : 4) * 1000;
    let records = 0;
    let octets = 0n;
    let packets = 0n;
    let revOctets = 0n;
    let revPackets = 0n;
    let key = '';
    pass.datagrams.forEach((d, i) => {
      const e = evidence(hexBytes(d.hex), { ref: { generation: 'g', entryId: i + 1 }, receivedMs: base + d.atMs, remotePort: d.port });
      const r = decodeDatagram(e, EXPORTER, 2, store);
      const v = valid(r);
      assert.deepEqual(v.awaiting, [], `datagram ${i}: nothing awaits a template`);
      assert.deepEqual(v.refused, [], `datagram ${i}`);
      assert.deepEqual(v.unsupportedTemplates, [], `datagram ${i}`);
      state.observe(r, e);
      key = v.sourceKey;
      records += v.flows.length;
      for (const fl of v.flows) {
        octets += fl.reportedOctets;
        packets += fl.reportedPackets;
        revOctets += fl.reverseOctets ?? 0n;
        revPackets += fl.reversePackets ?? 0n;
      }
    });
    assert.equal(records, pass.tshark.records, 'records');
    assert.equal(String(octets), pass.tshark.octets, 'octets');
    assert.equal(String(packets), pass.tshark.packets, 'packets');
    assert.equal(String(revOctets), pass.tshark.reverseOctets, 'reverse octets');
    assert.equal(String(revPackets), pass.tshark.reversePackets, 'reverse packets');
    const want = EXPECT[pass.name];
    assert.ok(want, 'a pass this test knows');
    assert.equal(state.sequence(key).suspectedGap, 0, 'no suspected gap');
    assert.equal(state.sequence(key).mode, want.mode, 'sequence mode');
    const s = state.sampling(key);
    assert.equal(s.kind === 'known' ? `known:${s.interval}` : s.kind, want.sampling, 'sampling');
  });
}

// --- messages no exporter produces, against tshark ------------------------------------------------------

test('synthetic-vs-tshark: reverse counts, totals, reduced-size, variable-length and 64-bit counters equal tshark', () => {
  const a = '10.1.1.1';
  const b = '10.1.1.2';
  const ip = (sets: number[][], domain = 7) => ipf(sets, { domain });
  const msgs: Uint8Array[] = [
    ip([
      templateSet(10, [
        templateRecord(10, 300, [F(8, 4), F(12, 4), F(1, 8), F(2, 8), F(1, 8, 29305), F(2, 8, 29305)]),
        templateRecord(10, 301, [F(8, 4), F(12, 4), F(85, 4), F(86, 4)]),
        templateRecord(10, 302, [F(8, 4), F(12, 4), F(1, 3), F(2, 2)]),
        templateRecord(10, 303, [F(8, 4), F(12, 4), F(82, 65535), F(1, 4), F(2, 4)]),
      ]),
      dataSet(300, [
        be.concat(be.ipv4(a), be.ipv4(b), be.uint(5_000_000_000n, 8), be.uint(7n, 8), be.uint(1234n, 8), be.uint(3n, 8)),
        be.concat(be.ipv4(b), be.ipv4(a), be.uint(100n, 8), be.uint(1n, 8), be.uint(0n, 8), be.uint(0n, 8)),
      ]),
      dataSet(301, [be.concat(be.ipv4(a), be.ipv4(b), be.u32(900), be.u32(9)), be.concat(be.ipv4(b), be.ipv4(a), be.u32(60), be.u32(2))]),
      dataSet(302, [be.concat(be.ipv4(a), be.ipv4(b), be.uint(70_000, 3), be.uint(50, 2))]),
      dataSet(303, [
        be.concat(be.ipv4(a), be.ipv4(b), [3, 0x65, 0x74, 0x68], be.u32(4000), be.u32(40)),
        be.concat(be.ipv4(b), be.ipv4(a), [255, 0, 4, 0x65, 0x74, 0x68, 0x30], be.u32(11), be.u32(1)),
      ]),
    ]),
    v9m([
      templateSet(9, [templateRecord(9, 256, [F(8, 4), F(12, 4), F(1, 8), F(2, 8)])]),
      dataSet(256, [be.concat(be.ipv4(a), be.ipv4(b), be.uint(6_000_000_000n, 8), be.uint(8n, 8)), be.concat(be.ipv4(b), be.ipv4(a), be.uint(1n, 8), be.uint(1n, 8))]),
    ], { sourceId: 3 }),
  ];
  const store = new CollectorTemplateStore();
  let records = 0;
  let octets = 0n;
  let packets = 0n;
  let revOctets = 0n;
  let revPackets = 0n;
  for (const m of msgs) {
    const v = valid(decode(store, m, { remotePort: 40_001 }));
    assert.deepEqual(v.awaiting, []);
    records += v.flows.length;
    for (const fl of v.flows) {
      octets += fl.reportedOctets; packets += fl.reportedPackets; revOctets += fl.reverseOctets ?? 0n; revPackets += fl.reversePackets ?? 0n;
    }
  }
  // Worked by hand, not by either decoder.
  assert.equal(records, 2 + 2 + 1 + 2 + 2);
  assert.equal(octets, 5_000_000_000n + 100n + 900n + 60n + 70_000n + 4000n + 11n + 6_000_000_000n + 1n);
  assert.equal(packets, 7n + 1n + 9n + 2n + 50n + 40n + 1n + 8n + 1n);
  assert.equal(revOctets, 1234n);
  assert.equal(revPackets, 3n);

  const tshark = findWiresharkTool('tshark');
  if (tshark === null) {
    console.log('SKIP  synthetic-vs-tshark: tshark is not installed; the hand-worked totals above were checked');
    return;
  }
  const dir = mkdtempSync(join(tmpdir(), 'inwire-flow-decode-'));
  try {
    const pcap = join(dir, 'synthetic.pcap');
    writeFileSync(pcap, pcapOf(msgs.map((m) => udpFrameTo('192.0.2.1', '192.0.2.9', 40_001, 2055, m))));
    const run = spawnSync(tshark, ['-r', pcap, '-d', 'udp.port==2055,cflow', '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=,',
      '-e', 'cflow.octets', '-e', 'cflow.packets', '-e', 'cflow.permanent_octets', '-e', 'cflow.permanent_packets'], { encoding: 'utf8', maxBuffer: 1 << 26 });
    const rows = run.stdout.trimEnd().split(/\r?\n/).filter((l) => l !== '').map((l) => l.split('\t'));
    const nums = (c: number): bigint[] => rows.flatMap((r) => (r[c] ?? '').split(',').filter((x) => x !== '')).map((x) => BigInt(x));
    const verbose = spawnSync(tshark, ['-r', pcap, '-d', 'udp.port==2055,cflow', '-V'], { encoding: 'utf8', maxBuffer: 1 << 26 }).stdout;
    let tRevOctets = 0n;
    let tRevPackets = 0n;
    for (const line of verbose.split(/\r?\n/)) {
      const m = /^\s*(?:Permanent )?(Octets|Packets): (\d+) \(Reverse Type \d+ /.exec(line);
      if (m === null) continue;
      if (m[1] === 'Octets') tRevOctets += BigInt(m[2]); else tRevPackets += BigInt(m[2]);
    }
    const sum = (xs: bigint[]): bigint => xs.reduce((x, y) => x + y, 0n);
    assert.equal(sum([...nums(0), ...nums(2)]) - tRevOctets, octets, 'octets');
    assert.equal(sum([...nums(1), ...nums(3)]) - tRevPackets, packets, 'packets');
    assert.equal(tRevOctets, revOctets, 'reverse octets');
    assert.equal(tRevPackets, revPackets, 'reverse packets');
    console.log(`        tshark agrees: ${octets} octets, ${packets} packets, reverse ${revOctets}/${revPackets}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
