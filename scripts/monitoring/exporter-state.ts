/**
 * What the collector knows about an exporter across datagrams (ADRs 0064,
 * 0065): sequence-number learning, sampling, the clock, restarts.
 *
 *   npx tsx scripts/monitoring/exporter-state.ts
 *
 * Plain tsx. The sequence cases feed `ExporterState` decodes built by hand, so
 * each convention is exactly the one named; the sampling cases go through the
 * real decoder with options records authored in `fixtures.ts`.
 */
import assert from 'node:assert/strict';
import { decodeCheckpoint, encodeCheckpoint } from '../../src/services/monitoring/checkpoint';
import { ExporterState, type ExporterEvent } from '../../src/services/monitoring/exporterState';
import { decodeDatagram, type FlowDecode, type OptionsReport } from '../../src/services/monitoring/flowDecode';
import { CollectorTemplateStore } from '../../src/services/monitoring/templates';
import { LIMITS, type DatagramEvidence } from '../../src/services/monitoring/types';
import { EXPORTER, be, dataSet, evidence, ipfixMessage, optionsTemplateRecord, optionsTemplateSet, templateRecord, templateSet, v9Message, type WireField } from './fixtures';

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
const T0 = SECS * 1000 + 400;
const KEY = `ipfix:${EXPORTER}/0`;
const KEY9 = `v9:${EXPORTER}/0`;
const F = (type: number, length: number): WireField => ({ type, length });

let entry = 0;
const ev = (over: Partial<DatagramEvidence> = {}): DatagramEvidence => {
  entry++;
  return evidence(new Uint8Array(0), { ref: { generation: '00112233445566778899aabbccddeeff', entryId: entry }, receivedMs: T0, ...over });
};

interface Msg { seq: number; records?: number; options?: number; restart?: boolean; awaiting?: number; key?: string; protocol?: 'v9' | 'ipfix'; exportMs?: number; samplers?: OptionsReport[] }
function fd(m: Msg): FlowDecode {
  const protocol = m.protocol ?? 'ipfix';
  return {
    kind: 'valid', protocol, sourceKey: m.key ?? (protocol === 'ipfix' ? KEY : KEY9), sequence: m.seq, exportMs: m.exportMs ?? T0, uptimeMs: null,
    flows: [], dataRecords: m.records ?? 0, optionsRecords: m.options ?? 0,
    awaiting: Array.from({ length: m.awaiting ?? 0 }, (_, i) => ({ templateId: 300 + i, sets: 1, bytes: 20 })), refused: [], unsupportedTemplates: [],
    options: m.samplers ?? [], withdrawalsIgnored: 0, restart: m.restart ?? false,
  };
}
const feed = (s: ExporterState, m: Msg, over: Partial<DatagramEvidence> = {}): ExporterEvent[] => s.observe(fd(m), ev(over));

/** IPFIX messages by the RFC convention: a message's number is the records sent before it. */
function rfcStream(counts: number[], start = 1000): Msg[] {
  const out: Msg[] = [];
  let seq = start;
  for (const records of counts) { out.push({ seq, records }); seq = (seq + records) % 2 ** 32; }
  return out;
}
/** softflowd's: a message's number includes its own records. */
function ownStream(counts: number[], start = 1000): Msg[] {
  const out: Msg[] = [];
  let seq = start;
  for (const records of counts) { seq = (seq + records) % 2 ** 32; out.push({ seq, records }); }
  return out;
}
const ALTERNATING = [3, 5, 3, 5, 3, 5, 3, 5, 3, 5, 3, 5];

test('sequence-learning: an RFC exporter settles into rfc after 8 discriminating pairs', () => {
  const s = new ExporterState();
  const msgs = rfcStream(ALTERNATING);
  msgs.slice(0, 8).forEach((m) => feed(s, m));
  assert.equal(s.sequence(KEY).mode, 'learning', 'seven pairs');
  feed(s, msgs[8]);
  assert.equal(s.sequence(KEY).mode, 'rfc');
  msgs.slice(9).forEach((m) => feed(s, m));
  assert.equal(s.sequence(KEY).suspectedGap, 0);
  assert.equal(s.sequence(KEY).reordered, 0);
});

test('sequence-learning: an own-records exporter settles into own-records', () => {
  const s = new ExporterState();
  ownStream(ALTERNATING).forEach((m) => feed(s, m));
  assert.equal(s.sequence(KEY).mode, 'own-records');
  assert.equal(s.sequence(KEY).suspectedGap, 0);
});

test('sequence-learning: pairs that fit both conventions do not discriminate', () => {
  const s = new ExporterState();
  // Every message carries 4 records: the two readings agree on every pair.
  rfcStream(Array(20).fill(4)).forEach((m) => feed(s, m));
  assert.equal(s.sequence(KEY).mode, 'learning');
  // A change of record count is the first discriminating pair.
  const s2 = new ExporterState();
  rfcStream([4, 4, 4, 4, 4, 4, 4, 4, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6, 4, 6]).forEach((m) => feed(s2, m));
  assert.equal(s2.sequence(KEY).mode, 'rfc');
});

test('sequence-learning: a mixed exporter is unrecognized, with no gaps, until a window settles', () => {
  const s = new ExporterState();
  const events: ExporterEvent[] = [];
  // Four RFC pairs, then the same exporter switches to counting its own records: the 8-pair window fits neither.
  const rfc = rfcStream([3, 5, 3, 5, 3], 1000);
  const own = ownStream([5, 3, 5, 3, 5, 3, 5, 3], (rfc[4].seq + 3) % 2 ** 32);
  [...rfc, ...own.slice(0, 5)].forEach((m) => events.push(...feed(s, m)));
  assert.equal(s.sequence(KEY).mode, 'unrecognized');
  own.slice(5).forEach((m) => events.push(...feed(s, m)));
  assert.equal(s.sequence(KEY).suspectedGap, 0);
  assert.equal(events.filter((x) => x.kind === 'export-gap').length, 0);
  // A later window of eight pairs that all fit own-records settles.
  const more = ownStream([4, 6, 4, 6, 4, 6, 4, 6, 4, 6], own[own.length - 1].seq);
  more.forEach((m) => feed(s, m));
  assert.equal(s.sequence(KEY).mode, 'own-records');
});

test('sequence-learning: once settled, a message ahead by d adds d and counting continues from it', () => {
  const s = new ExporterState();
  const msgs = rfcStream(ALTERNATING);
  msgs.forEach((m) => feed(s, m));
  const last = msgs[msgs.length - 1];
  const next = (last.seq + last.records!) % 2 ** 32;
  const events = feed(s, { seq: next + 40, records: 3 });
  assert.equal(s.sequence(KEY).suspectedGap, 40);
  const gap = events.find((x) => x.kind === 'export-gap');
  assert.deepEqual(gap && { ...gap, entryId: 0 }, { kind: 'export-gap', sourceKey: KEY, entryId: 0, missing: 40 });
  assert.equal(feed(s, { seq: next + 43, records: 3 }).length, 0, 'counted once: the next in-order message is no gap');
  assert.equal(s.sequence(KEY).suspectedGap, 40);
});

test('sequence-learning: a message behind is reordered or duplicate and changes nothing', () => {
  const s = new ExporterState();
  const msgs = rfcStream(ALTERNATING);
  msgs.forEach((m) => feed(s, m));
  const last = msgs[msgs.length - 1];
  const next = (last.seq + last.records!) % 2 ** 32;
  assert.equal(feed(s, { seq: msgs[3].seq, records: 3 }).length, 0);
  assert.equal(s.sequence(KEY).reordered, 1);
  assert.equal(s.sequence(KEY).suspectedGap, 0);
  feed(s, { seq: next, records: 5 });
  assert.equal(s.sequence(KEY).suspectedGap, 0, 'the reference did not move to the late message');
  assert.equal(s.sequence(KEY).reordered, 1);
});

test('sequence-learning: a wrap past 2^32 is not a gap', () => {
  const s = new ExporterState();
  rfcStream(ALTERNATING, 2 ** 32 - 20).forEach((m) => feed(s, m));
  assert.equal(s.sequence(KEY).mode, 'rfc');
  assert.equal(s.sequence(KEY).suspectedGap, 0);
  assert.equal(s.sequence(KEY).reordered, 0);
  // A number just below the wrap, after the wrap, is behind.
  feed(s, { seq: 2 ** 32 - 5, records: 3 });
  assert.equal(s.sequence(KEY).reordered, 1);
});

test('sequence-learning: a restart resets learning and says so', () => {
  const s = new ExporterState();
  rfcStream(ALTERNATING).forEach((m) => feed(s, m));
  assert.equal(s.sequence(KEY).mode, 'rfc');
  const events = feed(s, { seq: 5, records: 3, restart: true }, { ref: { generation: 'g', entryId: 999 } });
  assert.deepEqual(events.find((x) => x.kind === 'source-restart'), { kind: 'source-restart', sourceKey: KEY, entryId: 999 });
  assert.equal(s.sequence(KEY).mode, 'learning');
  assert.equal(s.sequence(KEY).suspectedGap, 0, 'the new number is the anchor, not a gap');
});

test('sequence-learning: gapEnded() re-anchors: the next message is not compared, the mode is kept', () => {
  const s = new ExporterState();
  const msgs = ownStream(ALTERNATING);
  msgs.forEach((m) => feed(s, m));
  s.gapEnded();
  feed(s, { seq: msgs[msgs.length - 1].seq + 100_000, records: 4 });
  assert.equal(s.sequence(KEY).suspectedGap, 0);
  assert.equal(s.sequence(KEY).mode, 'own-records');
  feed(s, { seq: msgs[msgs.length - 1].seq + 100_000 + 4 + 9, records: 4 });
  assert.equal(s.sequence(KEY).suspectedGap, 9, 'compared again from the anchor');
});

test('sequence-learning: v9 counts packets, and every pair counts', () => {
  const s = new ExporterState();
  for (let i = 0; i < 8; i++) feed(s, { protocol: 'v9', seq: 500 + i });
  assert.equal(s.sequence(KEY9).mode, 'learning', 'seven pairs');
  feed(s, { protocol: 'v9', seq: 508 });
  assert.equal(s.sequence(KEY9).mode, 'rfc');
  const events = feed(s, { protocol: 'v9', seq: 512 });
  assert.equal(s.sequence(KEY9).suspectedGap, 3);
  assert.equal(events.filter((x) => x.kind === 'export-gap').length, 1);
});

test('sequence-learning: RFC mode accepts either number after a message that carried options records', () => {
  const s = new ExporterState();
  const msgs = rfcStream(ALTERNATING);
  msgs.forEach((m) => feed(s, m));
  const last = msgs[msgs.length - 1];
  let seq = (last.seq + last.records!) % 2 ** 32;
  feed(s, { seq, records: 7, options: 3 });
  // Neither 7 + 3 nor 7 alone is a gap.
  seq = (seq + 10) % 2 ** 32;
  feed(s, { seq, records: 2, options: 0 });
  assert.equal(s.sequence(KEY).suspectedGap, 0);
  const s2 = new ExporterState();
  msgs.forEach((m) => feed(s2, m));
  seq = (last.seq + last.records!) % 2 ** 32;
  feed(s2, { seq, records: 7, options: 3 });
  feed(s2, { seq: (seq + 7) % 2 ** 32, records: 2 });
  assert.equal(s2.sequence(KEY).suspectedGap, 0, 'the number without the options records');
  feed(s2, { seq: (seq + 7 + 2 + 5) % 2 ** 32, records: 2 });
  assert.equal(s2.sequence(KEY).suspectedGap, 5);
});

test('sequence-learning: a message with data of unknown size is not a reference for the next', () => {
  const s = new ExporterState();
  const msgs = rfcStream(ALTERNATING);
  msgs.forEach((m) => feed(s, m));
  const last = msgs[msgs.length - 1];
  const seq = (last.seq + last.records!) % 2 ** 32;
  feed(s, { seq, records: 2, awaiting: 1 });
  feed(s, { seq: seq + 12_345, records: 3 });
  assert.equal(s.sequence(KEY).suspectedGap, 0, 'how many records the awaiting data held is unknown');
  feed(s, { seq: seq + 12_345 + 3 + 6, records: 3 });
  assert.equal(s.sequence(KEY).suspectedGap, 6);
});

// --- sampling ----------------------------------------------------------------------------------------------

/** Decodes real options messages and feeds the state; returns the events and the status after. */
function sampling() {
  const store = new CollectorTemplateStore();
  const s = new ExporterState();
  let seq = 0;
  const send = (bytes: Uint8Array, over: Partial<DatagramEvidence> = {}): ExporterEvent[] => {
    const e = ev({ bytes, ...over });
    const d = decodeDatagram(e, EXPORTER, 2, store);
    assert.equal(d.kind, 'valid', d.kind === 'valid' ? '' : d.reason);
    return s.observe(d, e);
  };
  const v9 = (sets: number[][]) => v9Message({ uptime: 600_000, secs: SECS, sequence: seq++, sourceId: 0 }, sets);
  const ipfix = (sets: number[][]) => ipfixMessage({ secs: SECS, sequence: seq++, domain: 0 }, sets);
  return { s, send, v9, ipfix };
}

test('options: IE 34 = 10 gives sampling known at 10, since the entry that said so', () => {
  const { s, send, v9 } = sampling();
  assert.deepEqual(s.sampling(KEY9), { kind: 'absent' });
  const events = send(v9([
    optionsTemplateSet(9, [optionsTemplateRecord(9, 300, [F(1, 4)], [F(34, 4), F(35, 1)])]),
    dataSet(300, [be.concat(be.u32(0), be.u32(10), be.u8(2))], 3),
  ]));
  assert.deepEqual(s.sampling(KEY9), { kind: 'known', interval: 10, sinceEntryId: entry });
  const changed = events.find((x) => x.kind === 'sampling-changed');
  assert.deepEqual(changed, { kind: 'sampling-changed', sourceKey: KEY9, entryId: entry, status: { kind: 'known', interval: 10, sinceEntryId: entry } });
  // Said again: no change, no event, still since the first statement.
  const first = entry;
  const again = send(v9([dataSet(300, [be.concat(be.u32(0), be.u32(10), be.u8(2))], 3)]));
  assert.equal(again.filter((x) => x.kind === 'sampling-changed').length, 0);
  assert.deepEqual(s.sampling(KEY9), { kind: 'known', interval: 10, sinceEntryId: first });
  // A new rate is a change.
  const changedAgain = send(v9([dataSet(300, [be.concat(be.u32(0), be.u32(100), be.u8(2))], 3)]));
  assert.equal(changedAgain.filter((x) => x.kind === 'sampling-changed').length, 1);
  assert.deepEqual(s.sampling(KEY9), { kind: 'known', interval: 100, sinceEntryId: entry });
});

test('options: 1-in-1 is known at 1, and an absent statement is absent', () => {
  const { s, send, v9, ipfix } = sampling();
  assert.deepEqual(s.sampling(KEY), { kind: 'absent' }, 'a source never heard from');
  send(v9([optionsTemplateSet(9, [optionsTemplateRecord(9, 300, [F(1, 4)], [F(34, 4), F(35, 1)])]), dataSet(300, [be.concat(be.u32(0), be.u32(1), be.u8(1))], 3)]));
  assert.deepEqual(s.sampling(KEY9), { kind: 'known', interval: 1, sinceEntryId: entry });
  // An IPFIX exporter that sends flows and no sampling options.
  send(ipfix([dataSet(300, [])]));
  assert.deepEqual(s.sampling(KEY), { kind: 'absent' }, 'absence never means 1:1');
});

test('options: IPFIX selector algorithm 1 gives N = (305 + 306) / 305', () => {
  const rec = (interval: number, space: number, algorithm: number) => be.concat(be.u32(0), be.u32(interval), be.u32(space), be.u16(algorithm));
  const cases: [number, number, number, number][] = [[1, 9, 1, 10], [1, 0, 1, 1], [2, 2, 1, 2], [10, 990, 1, 100]];
  for (const [interval, space, algorithm, n] of cases) {
    const { s, send, ipfix } = sampling();
    send(ipfix([optionsTemplateSet(10, [optionsTemplateRecord(10, 300, [F(143, 4)], [F(305, 4), F(306, 4), F(304, 2)])]), dataSet(300, [rec(interval, space, algorithm)])]));
    assert.deepEqual(s.sampling(KEY), { kind: 'known', interval: n, sinceEntryId: entry }, `${interval}+${space}`);
  }
});

test('options: a random algorithm with no interval, another selector algorithm, a fractional rate: unsupported', () => {
  {
    const { s, send, v9 } = sampling();
    send(v9([optionsTemplateSet(9, [optionsTemplateRecord(9, 300, [F(1, 4)], [F(34, 4), F(35, 1)])]), dataSet(300, [be.concat(be.u32(0), be.u32(0), be.u8(2))], 3)]));
    const st = s.sampling(KEY9);
    assert.equal(st.kind, 'unsupported');
  }
  {
    const { s, send, ipfix } = sampling();
    send(ipfix([optionsTemplateSet(10, [optionsTemplateRecord(10, 300, [F(143, 4)], [F(305, 4), F(306, 4), F(304, 2)])]), dataSet(300, [be.concat(be.u32(0), be.u32(1), be.u32(9), be.u16(3))])]));
    assert.equal(s.sampling(KEY).kind, 'unsupported', 'selector algorithm 3 is not count-based systematic');
  }
  {
    const { s, send, ipfix } = sampling();
    send(ipfix([optionsTemplateSet(10, [optionsTemplateRecord(10, 300, [F(143, 4)], [F(305, 4), F(306, 4), F(304, 2)])]), dataSet(300, [be.concat(be.u32(0), be.u32(2), be.u32(3), be.u16(1))])]));
    assert.equal(s.sampling(KEY).kind, 'unsupported', '5 / 2 is not a whole rate');
  }
});

test('options: a selector rate past 2^32 - 1 is unsupported, and the state still checkpoints and restores', () => {
  // interval 1, space 0xFFFFFFFF: (1 + 0xFFFFFFFF) / 1 is 2^32, which the checkpoint's 32-bit rate cannot hold (a spoofed datagram can send it).
  const rec = (interval: number, space: number) => be.concat(be.u32(0), be.u32(interval), be.u32(space), be.u16(1));
  const { s, send, ipfix } = sampling();
  send(ipfix([optionsTemplateSet(10, [optionsTemplateRecord(10, 300, [F(143, 4)], [F(305, 4), F(306, 4), F(304, 2)])]), dataSet(300, [rec(1, 0xffffffff)])]));
  assert.equal(s.sampling(KEY).kind, 'unsupported', 'a rate of 2^32 is not stated');
  assert.equal(s.samplerRate(KEY, 0), null, 'and the sampler the record names states none');
  const bytes = encodeCheckpoint(new CollectorTemplateStore(), s, 1, 1);
  const restored = decodeCheckpoint(bytes);
  assert.notEqual(restored, null, 'the checkpoint decodes');
  assert.equal(Buffer.from(encodeCheckpoint(restored!.store, restored!.state, 1, 1)).toString('hex'), Buffer.from(bytes).toString('hex'), 'and re-encodes to the same bytes');
  // The largest rate the checkpoint holds is still stated: (1 + 0xFFFFFFFE) / 1.
  const top = sampling();
  top.send(top.ipfix([optionsTemplateSet(10, [optionsTemplateRecord(10, 300, [F(143, 4)], [F(305, 4), F(306, 4), F(304, 2)])]), dataSet(300, [rec(1, 0xfffffffe)])]));
  assert.equal(top.s.sampling(KEY).kind, 'known');
  assert.notEqual(decodeCheckpoint(encodeCheckpoint(new CollectorTemplateStore(), top.s, 1, 1)), null);
});

test('options: a selector id past 2^32 - 1 is not filed, and the state still checkpoints and restores', () => {
  // IE 302 may be 8 bytes; the checkpoint holds a 32-bit id, so 2^32 + 1 would be written as 1 and sort before 5.
  const rec = (id: number) => be.concat(be.uint(id, 8), be.u32(1), be.u32(9), be.u16(1));
  const { s, send, ipfix } = sampling();
  send(ipfix([optionsTemplateSet(10, [optionsTemplateRecord(10, 300, [F(302, 8)], [F(305, 4), F(306, 4), F(304, 2)])]), dataSet(300, [rec(5), rec(2 ** 32 + 1)])]));
  assert.equal(s.samplerRate(KEY, 5), 10, 'the 32-bit sampler is filed');
  assert.equal(s.samplerRate(KEY, 2 ** 32 + 1), null, 'the wider one is not');
  const bytes = encodeCheckpoint(new CollectorTemplateStore(), s, 1, 1);
  const restored = decodeCheckpoint(bytes);
  assert.notEqual(restored, null, 'the checkpoint decodes');
  assert.equal(Buffer.from(encodeCheckpoint(restored!.store, restored!.state, 1, 1)).toString('hex'), Buffer.from(bytes).toString('hex'), 'and re-encodes to the same bytes');
});

test('options: data records carrying IE 48 use that sampler\'s interval (IE 50)', () => {
  const { s, send, v9 } = sampling();
  const flow: WireField[] = [F(8, 4), F(12, 4), F(1, 4), F(48, 1)];
  const record = (sampler: number) => be.concat(be.ipv4('10.0.0.1'), be.ipv4('10.0.0.2'), be.u32(5), be.u8(sampler));
  send(v9([
    optionsTemplateSet(9, [optionsTemplateRecord(9, 300, [F(1, 4)], [F(48, 1), F(49, 1), F(50, 4)])]),
    dataSet(300, [be.concat(be.u32(0), be.u8(3), be.u8(2), be.u32(20)), be.concat(be.u32(0), be.u8(4), be.u8(2), be.u32(50))], 2),
  ]));
  assert.deepEqual(s.sampling(KEY9), { kind: 'absent' }, 'a sampler table alone names no rate for the source');
  send(v9([templateSet(9, [templateRecord(9, 256, flow)])]));
  send(v9([dataSet(256, [record(3)])]));
  assert.deepEqual(s.sampling(KEY9), { kind: 'known', interval: 20, sinceEntryId: entry });
  send(v9([dataSet(256, [record(4)])]));
  assert.deepEqual(s.sampling(KEY9), { kind: 'known', interval: 50, sinceEntryId: entry });
});

test('bounds: the 17th sampler is refused and the source\'s sampling becomes unsupported', () => {
  const { s, send, v9 } = sampling();
  const tpl = optionsTemplateSet(9, [optionsTemplateRecord(9, 300, [F(1, 4)], [F(48, 1), F(49, 1), F(50, 4)])]);
  const samplers = (n: number) => Array.from({ length: n }, (_, i) => be.concat(be.u32(0), be.u8(i + 1), be.u8(2), be.u32(10)));
  send(v9([tpl, dataSet(300, samplers(LIMITS.samplersPerSource), 2)]));
  assert.notEqual(s.sampling(KEY9).kind, 'unsupported', '16 samplers are within the bound');
  send(v9([dataSet(300, [be.concat(be.u32(0), be.u8(17), be.u8(2), be.u32(10))], 2)]));
  assert.equal(s.sampling(KEY9).kind, 'unsupported');
  // A sampler already known may be updated at the bound.
  const { s: s2, send: send2, v9: v92 } = sampling();
  send2(v92([tpl, dataSet(300, samplers(LIMITS.samplersPerSource), 2)]));
  send2(v92([dataSet(300, [be.concat(be.u32(0), be.u8(1), be.u8(2), be.u32(20))], 2)]));
  assert.notEqual(s2.sampling(KEY9).kind, 'unsupported');
});

// --- the clock --------------------------------------------------------------------------------------------------

test('clock: skew is export time minus receipt, flagged past 10 s, with an event on crossing', () => {
  const s = new ExporterState();
  assert.deepEqual(s.clock(KEY), { latestSkewMs: null, minSkewMs: null, maxSkewMs: null, flagged: false });
  let events = feed(s, { seq: 1, exportMs: T0 - 600 });
  assert.deepEqual(s.clock(KEY), { latestSkewMs: -600, minSkewMs: -600, maxSkewMs: -600, flagged: false });
  assert.equal(events.filter((x) => x.kind === 'clock-skew').length, 0);
  events = feed(s, { seq: 2, exportMs: T0 + 12_000 });
  assert.equal(s.clock(KEY).flagged, true);
  assert.deepEqual(events.find((x) => x.kind === 'clock-skew'), { kind: 'clock-skew', sourceKey: KEY, entryId: entry, skewMs: 12_000 });
  events = feed(s, { seq: 3, exportMs: T0 + 13_000 });
  assert.equal(events.filter((x) => x.kind === 'clock-skew').length, 0, 'already flagged');
  events = feed(s, { seq: 4, exportMs: T0 - 100 });
  assert.equal(s.clock(KEY).flagged, false);
  assert.deepEqual([s.clock(KEY).latestSkewMs, s.clock(KEY).minSkewMs, s.clock(KEY).maxSkewMs], [-100, -600, 13_000]);
  events = feed(s, { seq: 5, exportMs: T0 - 10_000 });
  assert.equal(s.clock(KEY).flagged, false, 'exactly 10 s is not past it');
  events = feed(s, { seq: 6, exportMs: T0 - 10_001 });
  assert.equal(s.clock(KEY).flagged, true);
});

test('awaiting-template: one event per template id waiting', () => {
  const s = new ExporterState();
  const events = feed(s, { seq: 1, awaiting: 2 });
  assert.deepEqual(events.filter((x) => x.kind === 'awaiting-template').map((x) => (x as { templateId: number }).templateId), [300, 301]);
});

test('retainExporter: sources of another exporter are dropped, its own stay', () => {
  const s = new ExporterState();
  feed(s, { seq: 1, records: 1 });
  feed(s, { seq: 1, records: 1, key: 'ipfix:192.0.2.9/0' });
  feed(s, { seq: 1, records: 1, protocol: 'v9', key: 'v9:192.0.2.9/4' });
  assert.equal(s.exportSources().length, 3);
  s.retainExporter(EXPORTER);
  assert.deepEqual(s.exportSources().map((x) => x.key), [KEY]);
  s.retainExporter('192.0.2.9');
  assert.deepEqual(s.exportSources(), []);
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
