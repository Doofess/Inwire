/**
 * The template checkpoint (ADRs 0064, 0065): the byte layout, its vector, its
 * gap bits, and that a state restored from one behaves as the live state did.
 *
 *   npx tsx scripts/monitoring/checkpoint-codec.ts
 *
 * Plain tsx. The vector is read out of ADR 0064 itself, so the encoder is
 * checked against the document and not against a copy of it; the state it
 * encodes is built through the public API (`CollectorTemplateStore`,
 * `ExporterState.observe`), never through the encoder's own constructors.
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeCheckpoint, encodeCheckpoint } from '../../src/services/monitoring/checkpoint';
import { DecodeState, type DecodeStep } from '../../src/services/monitoring/decodeState';
import { ExporterState } from '../../src/services/monitoring/exporterState';
import { decodeDatagram, type FlowDecode } from '../../src/services/monitoring/flowDecode';
import { CollectorTemplateStore, type TemplateScope } from '../../src/services/monitoring/templates';
import { crc32 } from '../../src/services/monitoring/journalCodec';
import { LIMITS, type BoundaryEvidence, type Evidence } from '../../src/services/monitoring/types';
import type { FlowTemplate } from '../../src/services/flow/flowExport';
import { EXPORTER, GENERATION, evidence, be, dataSet, ipfixMessage, ipfixSample, optionsTemplateRecord, optionsTemplateSet, setOf, templateRecord, templateSet, v9Sample } from './fixtures';

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

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex').replace(/(.{2})/g, '$1 ').trim();
const here = dirname(fileURLToPath(import.meta.url));

/** The vector as ADR 0064 prints it: the first fenced block after "The test vector". */
function adrVector(): Uint8Array {
  const adr = readFileSync(join(here, '..', '..', 'docs', 'decisions', '0064-monitoring-v9-ipfix-collection.md'), 'utf8');
  const from = adr.indexOf('#### The test vector');
  const open = adr.indexOf('```\n', from);
  const close = adr.indexOf('```', open + 4);
  return Uint8Array.from(adr.slice(open + 4, close).split(/\s+/).filter(Boolean).map((h) => parseInt(h, 16)));
}

const T = 1_700_000_000_000;
const SCOPE: TemplateScope = { protocol: 'ipfix', exporter: EXPORTER, exporterPort: 50_000, domain: 0 };
const KEY = `ipfix:${EXPORTER}/0`;
const spec = (...fields: [number, number][]): FlowTemplate => ({ scopeCount: 0, fields: fields.map(([type, length]) => ({ type, length })) });

/** ADR 0064's vector state, through the public API. */
function vectorState(): { store: CollectorTemplateStore; state: ExporterState } {
  const store = new CollectorTemplateStore();
  const options: FlowTemplate = { scopeCount: 1, fields: [[143, 4], [305, 4], [306, 4], [304, 2]].map(([type, length]) => ({ type, length })) };
  const data = spec([8, 4], [12, 4], [22, 4], [21, 4], [1, 4], [2, 4]);
  // 4,090 messages; both templates defined in message 4,064 and refreshed in 4,080: 16 messages and 30 s apart.
  for (let m = 1; m <= 4090; m++) {
    const ms = m < 4064 ? T - 1_000_000 : m < 4080 ? T + 560_000 + (m - 4064) : m === 4080 ? T + 590_000 : T + 600_000;
    store.beginDatagram(SCOPE, ms, null);
    if (m === 4064) {
      assert.equal(store.define(SCOPE, 256, options, 17, T + 560_000), 'defined');
      assert.equal(store.define(SCOPE, 1024, data, 17, T - 30_000), 'defined');
    }
    if (m === 4080) {
      assert.equal(store.define(SCOPE, 256, options, 4080, T + 590_000), 'refreshed');
      assert.equal(store.define(SCOPE, 1024, data, 4080, T), 'refreshed');
    }
  }
  store.observeSystemInit(SCOPE, 1_699_990_000_000, 4090);

  const state = new ExporterState();
  const counts = [10, 20, 10, 20, 10, 20, 10, 20, 30];
  const seqs: number[] = [];
  let seq = 123_456;
  for (let i = counts.length - 1; i >= 0; i--) { seqs[i] = seq; seq -= counts[i - 1] ?? 0; }
  counts.forEach((records, i) => {
    const d: FlowDecode = {
      kind: 'valid', protocol: 'ipfix', sourceKey: KEY, sequence: seqs[i], exportMs: T, uptimeMs: null, flows: [], dataRecords: records, optionsRecords: 0,
      awaiting: [], refused: [], unsupportedTemplates: [], withdrawalsIgnored: 0, restart: false,
      options: i === 0 ? [{ templateId: 256, scope: [{ type: 143, value: 0n }], samplingInterval: 10 }] : [],
    };
    state.observe(d, evidence(new Uint8Array(0), { ref: { generation: 'g', entryId: 17 + i }, receivedMs: T }));
  });
  return { store, state };
}

test('checkpoint-vector: the state of ADR 0064 encodes to exactly its 246 bytes', () => {
  const { store, state } = vectorState();
  const bytes = encodeCheckpoint(store, state, 4096, 1_700_000_600_000);
  const expected = adrVector();
  assert.equal(expected.length, 246);
  assert.equal(hex(bytes), hex(expected));
});

test('checkpoint-vector: decode then re-encode gives identical bytes, and the state came back', () => {
  const expected = adrVector();
  const restored = decodeCheckpoint(expected);
  assert.notEqual(restored, null);
  assert.equal(restored!.throughEntryId, 4096);
  assert.equal(restored!.throughMs, 1_700_000_600_000);
  assert.equal(hex(encodeCheckpoint(restored!.store, restored!.state, 4096, 1_700_000_600_000)), hex(expected));
  assert.deepEqual(restored!.store.lookup(SCOPE, 1024)!.fields.map((f) => f.type), [8, 12, 22, 21, 1, 2]);
  assert.equal(restored!.store.lookup(SCOPE, 256)!.options, true);
  assert.equal(restored!.store.lookup(SCOPE, 256)!.scopeCount, 1);
  assert.equal(restored!.store.lookup(SCOPE, 1024)!.intervalMessages, 16);
  assert.equal(restored!.store.counters(SCOPE).messages, 4090);
  assert.deepEqual(restored!.state.sampling(KEY), { kind: 'known', interval: 10, sinceEntryId: 17 });
  assert.equal(restored!.state.sequence(KEY).mode, 'rfc');
});

test('checkpoint-vector: a flipped byte, a truncation, a bad magic, format or policy give null', () => {
  const good = adrVector();
  for (let i = 0; i < good.length; i++) {
    const bad = good.slice();
    bad[i] ^= 0x01;
    assert.equal(decodeCheckpoint(bad), null, `byte ${i} flipped`);
  }
  for (let n = 0; n < good.length; n++) assert.equal(decodeCheckpoint(good.slice(0, n)), null, `${n} bytes`);
  assert.equal(decodeCheckpoint(Uint8Array.from([...good, 0])), null, 'a trailing byte');
  // Damage that keeps the CRC valid is still refused: it is the structure that is wrong.
  const resealed = (patch: (b: Uint8Array) => void): Uint8Array => {
    const body = good.slice(0, good.length - 4);
    patch(body);
    const out = new Uint8Array(body.length + 4);
    out.set(body);
    new DataView(out.buffer).setUint32(body.length, crc32(body), true);
    return out;
  };
  assert.notEqual(decodeCheckpoint(resealed(() => undefined)), null, 'the resealing itself is sound');
  assert.equal(decodeCheckpoint(resealed((b) => { b[0] = 0x58; })), null, 'magic');
  assert.equal(decodeCheckpoint(resealed((b) => { b[8] = 2; })), null, 'format');
  assert.equal(decodeCheckpoint(resealed((b) => { b[10] = 1; })), null, 'policy');
  assert.equal(decodeCheckpoint(resealed((b) => { b[12] = 2; })), null, 'a scope count with no scope behind it');
  assert.equal(decodeCheckpoint(resealed((b) => { b[14] = 2; })), null, 'a source count with no source behind it');
  assert.equal(decodeCheckpoint(resealed((b) => { b[32] = 11; })), null, 'a protocol that is neither 9 nor 10');
  assert.equal(decodeCheckpoint(resealed((b) => { b[33] |= 0x08; })), null, 'an undefined scope flag');
  assert.equal(decodeCheckpoint(resealed((b) => { b[32 + 36 + 3] = 1; })), null, 'a reserved template byte');
  assert.equal(decodeCheckpoint(new Uint8Array(LIMITS.checkpointBytes + 1)), null, 'over the bound');
});

test('checkpoint-vector: no input makes decodeCheckpoint throw', () => {
  let seed = 0x1ee7;
  const rnd = () => (seed = (Math.imul(seed, 1103515245) + 12345) >>> 0) / 2 ** 32;
  const good = adrVector();
  for (let i = 0; i < 300; i++) {
    const bytes = new Uint8Array(Math.floor(rnd() * 300));
    for (let j = 0; j < bytes.length; j++) bytes[j] = Math.floor(rnd() * 256);
    assert.doesNotThrow(() => decodeCheckpoint(bytes));
    const mutated = good.slice();
    for (let k = 0; k < 4; k++) mutated[Math.floor(rnd() * mutated.length)] = Math.floor(rnd() * 256);
    assert.doesNotThrow(() => decodeCheckpoint(mutated));
  }
});

test('checkpoint-gap-bits: gapEnded() sets scope and template bit 2, the next datagram clears the scope\'s, restore keeps them', () => {
  const { store, state } = vectorState();
  const flags = (b: Uint8Array) => ({ scope: b[33], template: b[32 + 36 + 2] });
  assert.deepEqual(flags(encodeCheckpoint(store, state, 1, 1)), { scope: 2, template: 1 }, 'bit 1 (IE 160 known) and bit 0 (options)');
  store.gapEnded();
  state.gapEnded();
  const after = encodeCheckpoint(store, state, 1, 1);
  assert.deepEqual(flags(after), { scope: 2 | 4, template: 1 | 4 });
  const restored = decodeCheckpoint(after)!;
  assert.deepEqual(flags(encodeCheckpoint(restored.store, restored.state, 1, 1)), { scope: 6, template: 5 }, 'restore preserves them');
  assert.equal(restored.store.lookup(SCOPE, 256)!.previousSession, true);
  // The scope's next datagram spends the scope's bit; a template's bit goes at its own receipt.
  restored.store.beginDatagram(SCOPE, T + 601_000, null);
  assert.deepEqual(flags(encodeCheckpoint(restored.store, restored.state, 1, 1)), { scope: 2, template: 5 });
  restored.store.define(SCOPE, 256, { scopeCount: 1, fields: [[143, 4], [305, 4], [306, 4], [304, 2]].map(([type, length]) => ({ type, length })) }, 9, T + 601_000);
  assert.deepEqual(flags(encodeCheckpoint(restored.store, restored.state, 1, 1)), { scope: 2, template: 1 });
});

test('checkpoint-order: scopes sort by protocol, then domain (a domain has one port), whatever order they arrived in', () => {
  const store = new CollectorTemplateStore();
  const state = new ExporterState();
  const t: FlowTemplate = { scopeCount: 0, fields: [{ type: 8, length: 4 }, { type: 12, length: 4 }, { type: 1, length: 4 }] };
  // Domain 2 on the low port arrives first; sorting by port first would put it ahead of domain 1.
  const arrival: [string, number, number][] = [['ipfix', 40_000, 2], ['ipfix', 50_000, 1], ['v9', 60_000, 5]];
  for (const [protocol, port, domain] of arrival) {
    const scope: TemplateScope = { protocol: protocol as 'v9' | 'ipfix', exporter: EXPORTER, exporterPort: protocol === 'ipfix' ? port : null, domain };
    store.beginDatagram(scope, T, null, port);
    assert.equal(store.define(scope, 256, t, 1, T), 'defined');
  }
  const bytes = encodeCheckpoint(store, state, 1, 1);
  const restored = decodeCheckpoint(bytes);
  assert.notEqual(restored, null, 'the encoder wrote an order its own decoder accepts');
  assert.deepEqual(restored!.store.exportScopes().map((s) => `${s.protocol}/${s.domain}/${s.port}`), ['v9/5/60000', 'ipfix/1/50000', 'ipfix/2/40000']);
});

test('checkpoint-strict: unordered ids, unordered sources and trailing bytes are refused even with a valid CRC', () => {
  const store = new CollectorTemplateStore();
  store.beginDatagram(SCOPE, T, null);
  for (const id of [300, 301]) assert.equal(store.define(SCOPE, id, spec([8, 4], [12, 4]), 1, T), 'defined');
  const state = new ExporterState();
  for (const domain of [1, 2]) {
    const d: FlowDecode = {
      kind: 'valid', protocol: 'ipfix', sourceKey: `ipfix:${EXPORTER}/${domain}`, sequence: 5, exportMs: T, uptimeMs: null, flows: [], dataRecords: 1, optionsRecords: 0,
      awaiting: [], refused: [], unsupportedTemplates: [], withdrawalsIgnored: 0, restart: false, options: [],
    };
    state.observe(d, evidence(new Uint8Array(0), { ref: { generation: 'g', entryId: 1 }, receivedMs: T }));
  }
  const good = encodeCheckpoint(store, state, 1, T);
  assert.notEqual(decodeCheckpoint(good), null);
  const reseal = (body: Uint8Array): Uint8Array => {
    const out = new Uint8Array(body.length + 4);
    out.set(body);
    new DataView(out.buffer).setUint32(body.length, crc32(body), true);
    return out;
  };
  const patched = (patch: (b: Uint8Array) => Uint8Array | void): Uint8Array => {
    const body = good.slice(0, good.length - 4);
    return reseal(patch(body) ?? body);
  };
  // Two templates of two fields each: the second's id sits 44 + 8 bytes after the first's.
  const first = 32 + 36;
  const second = first + 44 + 8;
  assert.equal(good[first] | (good[first + 1] << 8), 300);
  assert.equal(good[second] | (good[second + 1] << 8), 301);
  assert.equal(decodeCheckpoint(patched((b) => { b[second] = 300 & 0xff; b[second + 1] = 300 >> 8; })), null, 'a duplicate template id');
  assert.equal(decodeCheckpoint(patched((b) => { b[first] = 302 & 0xff; b[first + 1] = 302 >> 8; })), null, 'descending template ids');
  // Sources: swap the last character of the two keys ("/1" and "/2").
  const at = (() => { const b = good.slice(0, good.length - 4); const s = Array.from(b).map((x) => String.fromCharCode(x)).join(''); return [s.indexOf(`/1`, s.indexOf('ipfix:')), s.lastIndexOf('/2')]; })();
  assert.ok(at[0] > 0 && at[1] > at[0]);
  assert.equal(decodeCheckpoint(patched((b) => { b[at[0] + 1] = 0x32; b[at[1] + 1] = 0x31; })), null, 'sources out of order');
  assert.equal(decodeCheckpoint(patched((b) => { b[at[1] + 1] = 0x31; })), null, 'a duplicate source');
  assert.equal(decodeCheckpoint(patched((b) => { const o = new Uint8Array(b.length + 1); o.set(b); return o; })), null, 'a trailing byte inside the CRC');
});

test('checkpoint-bound: 4,096 templates over 16 scopes and 16 samplers a source fit checkpointBytes', () => {
  const store = new CollectorTemplateStore();
  const state = new ExporterState();
  for (let d = 0; d < 16; d++) {
    const scope: TemplateScope = { protocol: 'ipfix', exporter: EXPORTER, exporterPort: 50_000 + d, domain: d };
    store.beginDatagram(scope, T, null);
    // 24 enterprise fields a template is what a 768 KiB budget allows over 4,096 of them.
    const t: FlowTemplate = { scopeCount: 0, fields: Array.from({ length: 24 }, (_, i) => ({ type: i + 1, length: 4, pen: 29305 })) };
    for (let id = 256; id < 512; id++) assert.equal(store.define(scope, id, t, 1, T), 'defined');
    for (let k = 0; k < LIMITS.samplersPerSource; k++) {
      state.observe({
        kind: 'valid', protocol: 'ipfix', sourceKey: `ipfix:${EXPORTER}/${d}`, sequence: 0, exportMs: T, uptimeMs: null, flows: [], dataRecords: 0, optionsRecords: 1,
        awaiting: [], refused: [], unsupportedTemplates: [], withdrawalsIgnored: 0, restart: false,
        options: [{ templateId: 256, scope: [], selectorAlgorithm: 1, packetInterval: 1, packetSpace: 9, samplerId: k }],
      }, evidence(new Uint8Array(0), { ref: { generation: 'g', entryId: 1 + k }, receivedMs: T }));
    }
  }
  const bytes = encodeCheckpoint(store, state, 1 << 30, T);
  assert.ok(bytes.length <= LIMITS.checkpointBytes, `${bytes.length} bytes`);
  const restored = decodeCheckpoint(bytes);
  assert.notEqual(restored, null);
  assert.equal(hex(encodeCheckpoint(restored!.store, restored!.state, 1 << 30, T)), hex(bytes));
});

// --- the exporter's own datagrams, live and restored ---------------------------------------------------------------

interface VectorPass { name: string; datagrams: { atMs: number; port: number; hex: string }[] }
const vectorPass = (name: string): VectorPass => {
  const file = JSON.parse(readFileSync(join(here, 'exporter-vectors.json'), 'utf8')) as { passes: VectorPass[] };
  const found = file.passes.find((p) => p.name === name);
  assert.ok(found, `pass ${name}`);
  return found;
};

test('checkpoint-live-equals-restored: a checkpoint at datagram 40 of refresh-softflowd-v10 carries the rest of the pass identically', () => {
  const pass = vectorPass('refresh-softflowd-v10');
  assert.equal(pass.datagrams.length, 80);
  const datagrams = pass.datagrams.map((d) => ({ ...d, bytes: Uint8Array.from(Buffer.from(d.hex, 'hex')) }));
  const base = ((datagrams[0].bytes[4] << 24) | (datagrams[0].bytes[5] << 16) | (datagrams[0].bytes[6] << 8) | datagrams[0].bytes[7]) * 1000;
  const run = (from: number, to: number, store: CollectorTemplateStore, state: ExporterState) => {
    const out: { decode: FlowDecode; events: unknown }[] = [];
    for (let i = from; i < to; i++) {
      const e = evidence(datagrams[i].bytes, { ref: { generation: 'g', entryId: i + 1 }, receivedMs: base + datagrams[i].atMs, remotePort: datagrams[i].port });
      const decode = decodeDatagram(e, EXPORTER, 2, store);
      out.push({ decode, events: state.observe(decode, e) });
    }
    return out;
  };
  // Uninterrupted.
  const liveStore = new CollectorTemplateStore();
  const liveState = new ExporterState();
  run(0, 40, liveStore, liveState);
  liveStore.gapEnded();
  liveState.gapEnded();
  const liveRest = run(40, 80, liveStore, liveState);
  // Checkpointed at 40 (after a gap ended), restored, resumed.
  const store = new CollectorTemplateStore();
  const state = new ExporterState();
  run(0, 40, store, state);
  store.gapEnded();
  state.gapEnded();
  const at40 = encodeCheckpoint(store, state, 40, base + datagrams[39].atMs);
  const restored = decodeCheckpoint(at40);
  assert.notEqual(restored, null);
  assert.equal(hex(encodeCheckpoint(restored!.store, restored!.state, 40, base + datagrams[39].atMs)), hex(at40), 'restore then re-encode');
  const restoredRest = run(40, 80, restored!.store, restored!.state);
  assert.deepEqual(restoredRest, liveRest, 'the decodes and the events');
  const end = base + datagrams[79].atMs;
  assert.equal(hex(encodeCheckpoint(restored!.store, restored!.state, 80, end)), hex(encodeCheckpoint(liveStore, liveState, 80, end)), 'the final checkpoints');
  assert.ok(liveRest.some((r) => r.decode.kind === 'valid' && r.decode.flows.length > 0), 'the rest of the pass did decode flows');
  assert.equal(liveState.sequence(`ipfix:${EXPORTER}/0`).mode, 'own-records');
});

test('malformed: a malformed datagram leaves the checkpoint\'s bytes unchanged', () => {
  const store = new CollectorTemplateStore();
  const state = new ExporterState();
  const e0 = evidence(ipfixMessage({ secs: 1_760_000_000, sequence: 0, domain: 1 }, [templateSet(10, [templateRecord(10, 256, [{ type: 8, length: 4 }])])]), { remotePort: 40_000 });
  state.observe(decodeDatagram(e0, EXPORTER, 2, store), e0);
  const before = hex(encodeCheckpoint(store, state, 1, 1));
  const cases = [
    ipfixMessage({ secs: 1, sequence: 1, domain: 1 }, [setOf(2, be.concat(be.u16(257), be.u16(40), be.u16(8), be.u16(4)))]),
    ipfixMessage({ secs: 1, sequence: 1, domain: 1, length: 99 }, [dataSet(256, [be.u32(1)])]),
    ipfixMessage({ secs: 1, sequence: 1, domain: 1 }, [templateSet(10, [templateRecord(10, 255, [{ type: 8, length: 4 }])])]),
  ];
  for (const bytes of cases) {
    const e = evidence(bytes, { remotePort: 40_000 });
    const d = decodeDatagram(e, EXPORTER, 2, store);
    assert.equal(d.kind, 'malformed');
    state.observe(d, e);
  }
  assert.equal(hex(encodeCheckpoint(store, state, 1, 1)), before);
});

// --- a decode state's checkpoint always decodes (the final review's C1 and I1) ---------------------------------------
//
// The expiry appends a checkpoint to the archive and never rewrites it, so a reachable decode state whose bytes
// `decodeCheckpoint` refuses would fail every later expiry. Each case below was such a state.

const OTHER = '192.0.2.7';
const FLOW = { src: '10.0.0.1', dst: '10.0.0.2', octets: 100, packets: 1 };
let nextEntry = 0;
const resetEntries = (): void => { nextEntry = 0; };

/** A `start` boundary naming the exporter the session listens for. */
function start(exporterIPv4: string): BoundaryEvidence {
  nextEntry++;
  return {
    kind: 'boundary', ref: { generation: GENERATION, entryId: nextEntry }, sessionId: 'a1'.repeat(16), receivedMs: 1_760_000_000_600, action: 'start',
    reason: '', droppedDatagrams: null, source: { exporterIPv4, bindIPv4: '192.0.2.50', port: 2055 }, policy: 2, segmentFirstId: 1,
  };
}
/** An IPFIX datagram (template and data) from `remoteIPv4`'s source port 40,000, in `domain`. */
function ipfixFrom(remoteIPv4: string, domain: number): Evidence {
  nextEntry++;
  return evidence(ipfixSample({ secs: 1_760_000_000, sequence: nextEntry, domain }, [FLOW], false), { ref: { generation: GENERATION, entryId: nextEntry }, remoteIPv4, remotePort: 40_000 });
}
function v9From(remoteIPv4: string, sourceId: number): Evidence {
  nextEntry++;
  return evidence(v9Sample({ uptime: 600_000, secs: 1_760_000_000, sequence: nextEntry, sourceId }, [FLOW], null), { ref: { generation: GENERATION, entryId: nextEntry }, remoteIPv4, remotePort: 40_000 });
}
/** The IPFIX selector 1-in-(1 + 0xFFFFFFFF): a rate of 2^32. */
function selectorEntry(): Evidence {
  nextEntry++;
  const msg = ipfixMessage({ secs: 1_760_000_000, sequence: 0, domain: 1 }, [
    optionsTemplateSet(10, [optionsTemplateRecord(10, 400, [{ type: 302, length: 4 }], [{ type: 304, length: 2 }, { type: 305, length: 4 }, { type: 306, length: 4 }])]),
    dataSet(400, [[...be.u32(1), ...be.u16(1), ...be.u32(1), ...be.u32(0xffffffff)]]),
  ]);
  return evidence(msg, { ref: { generation: GENERATION, entryId: nextEntry } });
}

/** The state's checkpoint is bytes `decodeCheckpoint` accepts, within the limit, and restoring then encoding gives the same bytes. */
function assertRoundTrips(state: DecodeState, what: string): Uint8Array {
  const bytes = state.checkpoint();
  assert.ok(bytes.length <= LIMITS.checkpointBytes, `${what}: ${bytes.length} bytes is over the limit`);
  const back = decodeCheckpoint(bytes);
  assert.notEqual(back, null, `${what}: the checkpoint does not decode`);
  assert.equal(hex(encodeCheckpoint(back!.store, back!.state, back!.throughEntryId, back!.throughMs)), hex(bytes), `${what}: restore then re-encode`);
  return bytes;
}

test('exporter change: a start naming another exporter drops the old exporter\'s templates and sources, and the checkpoint decodes', () => {
  for (const [name, from] of [['IPFIX', ipfixFrom], ['v9', v9From]] as const) {
    resetEntries();
    const s = DecodeState.empty();
    const protocol = name === 'IPFIX' ? 'ipfix' : 'v9';
    // Exporter A and exporter B both use Source ID / domain 0 and source port 40,000: the checkpoint orders scopes by protocol, domain and port alone.
    assert.equal(s.step(from(EXPORTER, 0))!.kind, 'datagram');
    assertRoundTrips(s, `${name} A`);
    s.step(start(OTHER));
    s.step(from(OTHER, 0));
    const bytes = assertRoundTrips(s, `${name} B after the change`);
    const held = decodeCheckpoint(bytes)!;
    assert.deepEqual(held.store.exportScopes().map((x) => x.exporter), [OTHER], `${name}: only B's scope is held`);
    assert.deepEqual(held.state.exportSources().map((x) => x.key), [`${protocol}:${OTHER}/0`], `${name}: only B's source is held`);
    // A's templates are gone: a data-only datagram of A's would now wait, which is what a fresh start would see.
    assert.equal(s.store.lookup({ protocol, exporter: EXPORTER, exporterPort: protocol === 'ipfix' ? 40_000 : null, domain: 0 }, protocol === 'ipfix' ? 300 : 256), null);
  }
});

test('exporter change: a start naming the same exporter keeps its state; a restored state drops the same way', () => {
  resetEntries();
  const s = DecodeState.empty();
  s.step(ipfixFrom(EXPORTER, 5));
  s.step(start(EXPORTER));
  assert.deepEqual(s.store.exportScopes().map((x) => [x.exporter, x.domain]), [[EXPORTER, 5]], 'the same exporter: nothing is dropped');
  assert.equal(s.store.exportScopes()[0].templates.length, 1);
  // The decision depends on the state and the entry alone: a state restored from the checkpoint and the live one end the same.
  const restored = DecodeState.fromCheckpoint(s.checkpoint())!;
  const change = start(OTHER);
  s.step(change);
  restored.step(change);
  assert.equal(hex(restored.checkpoint()), hex(s.checkpoint()));
  assert.deepEqual(s.store.exportScopes(), [], 'another exporter: A\'s scope is gone');
  assert.deepEqual(s.exporter.exportSources(), []);
});

test('bounds: an exporter holds at most enginesPerExporter scopes and sources, and a 17th identity decodes as unsupported', () => {
  resetEntries();
  const s = DecodeState.empty();
  const kinds: string[] = [];
  const N = 40;
  for (let domain = 1; domain <= N; domain++) {
    const step = s.step(ipfixFrom(EXPORTER, domain)) as DecodeStep;
    kinds.push(step.kind === 'datagram' ? step.decoded.kind : step.kind);
    assertRoundTrips(s, `after domain ${domain}`);
  }
  assert.equal(s.store.exportScopes().length, LIMITS.enginesPerExporter);
  assert.equal(s.exporter.exportSources().length, LIMITS.enginesPerExporter);
  assert.deepEqual(kinds.slice(0, LIMITS.enginesPerExporter), Array(LIMITS.enginesPerExporter).fill('valid'));
  assert.deepEqual(kinds.slice(LIMITS.enginesPerExporter), Array(N - LIMITS.enginesPerExporter).fill('unsupported'), 'the rest are refused, not malformed');
  // A domain the exporter already has still decodes.
  const again = s.step(ipfixFrom(EXPORTER, 3)) as DecodeStep;
  assert.equal(again.kind === 'datagram' && again.decoded.kind, 'valid');
  assert.ok(s.checkpoint().length <= LIMITS.checkpointBytes);
});

test('bounds: 40,000 domains from one exporter leave a checkpoint under the limit (the u16 scope count never wraps)', () => {
  resetEntries();
  const s = DecodeState.empty();
  for (let domain = 1; domain <= 40_000; domain++) s.step(ipfixFrom(EXPORTER, domain));
  assert.equal(s.store.exportScopes().length, LIMITS.enginesPerExporter);
  assertRoundTrips(s, '40,000 domains');
});

test('bounds: a checkpoint holding more than enginesPerExporter scopes, or sources, of one exporter is refused: no decode state can reach it', () => {
  const scope = (domain: number): TemplateScope => ({ protocol: 'ipfix', exporter: EXPORTER, exporterPort: 40_000, domain });
  const full = new CollectorTemplateStore();
  for (let d = 0; d < LIMITS.enginesPerExporter; d++) full.beginDatagram(scope(d), 1, null);
  assert.notEqual(decodeCheckpoint(encodeCheckpoint(full, new ExporterState(), 1, 1)), null, 'the control: 16 scopes');
  full.beginDatagram(scope(LIMITS.enginesPerExporter), 1, null);
  assert.equal(decodeCheckpoint(encodeCheckpoint(full, new ExporterState(), 1, 1)), null, '17 scopes of one exporter');
  const sources = (n: number): ExporterState => ExporterState.fromSources(Array.from({ length: n }, (_, i) => ({
    key: `ipfix:${EXPORTER}/${i}`, sampling: { kind: 'absent' as const }, samplers: [],
    sequence: { mode: 'learning' as const, seen: false, last: 0, lastRecords: 0, pairs: 0, fitRfc: 0, fitOwn: 0 },
  })));
  assert.notEqual(decodeCheckpoint(encodeCheckpoint(new CollectorTemplateStore(), sources(LIMITS.enginesPerExporter), 1, 1)), null, 'the control: 16 sources');
  assert.equal(decodeCheckpoint(encodeCheckpoint(new CollectorTemplateStore(), sources(LIMITS.enginesPerExporter + 1), 1, 1)), null, '17 sources of one exporter');
});

test('selector rate 2^32: the state through a decode state still checkpoints and restores', () => {
  resetEntries();
  const s = DecodeState.empty();
  s.step(selectorEntry());
  assert.notEqual(s.exporter.sampling(`ipfix:${EXPORTER}/1`).kind, 'known', 'a rate past 2^32 - 1 is not stated');
  assertRoundTrips(s, 'selector 1 + 0xFFFFFFFF');
});

test('property: every step of each unsafe sequence leaves a checkpoint that decodes, within the limit, byte-identical on restore', () => {
  const sequences: [string, () => Evidence[]][] = [
    ['an exporter change, both protocols', () => [v9From(EXPORTER, 0), ipfixFrom(EXPORTER, 0), start(OTHER), v9From(OTHER, 0), ipfixFrom(OTHER, 0), start(EXPORTER), ipfixFrom(EXPORTER, 0)]],
    ['unbounded identities', () => Array.from({ length: 60 }, (_, i) => (i % 2 === 0 ? ipfixFrom(EXPORTER, i + 1) : v9From(EXPORTER, i + 1)))],
    ['an unrepresentable sampling rate', () => [selectorEntry(), ipfixFrom(EXPORTER, 1)]],
  ];
  for (const [name, make] of sequences) {
    resetEntries();
    const entries = make();
    const s = DecodeState.empty();
    entries.forEach((e, i) => {
      s.step(e);
      assertRoundTrips(s, `${name}, step ${i + 1}`);
    });
  }
});

console.log(`\n${passes} passed, ${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
