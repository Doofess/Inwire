/**
 * The template checkpoint (ADRs 0064, 0065): the template store and the
 * exporter state, encoded as of one journal entry.
 *
 * Template state is derived, and a rebuild or a raw query that starts mid-journal
 * starts from a checkpoint. The encoding is therefore **deterministic** - a
 * checkpoint written live and the one a rebuild writes for the same entry are
 * byte-identical - and `decodeCheckpoint` accepts only what `encodeCheckpoint`
 * could have written, so restoring and encoding again gives the same bytes.
 *
 * Little-endian like the other monitoring formats; field specifiers are the
 * exception and keep the wire's network order. The layout is ADR 0064's, with
 * 0065's flag bit 2 (scope: a collection gap has ended since its last
 * datagram; template: last received in an earlier session).
 *
 * What a checkpoint does **not** carry: the clock, the gap, reorder, restart
 * and refusal counters, the refused template ids, the reason a sampling rate is
 * unsupported, and the options-record count of the last message (ADR 0064's
 * record has one count). The last costs one comparison: after a restore, an
 * IPFIX source in RFC mode takes its next message as the new reference rather
 * than guess whether the last one's options records were counted.
 *
 * Pure: no `node:*` and no Electron, like everything under `src/services/`.
 */
import { ExporterState, type SamplerEntry, type SamplingStatus, type SequenceMode, type SourceSnapshot } from './exporterState';
import { crc32 } from './journalCodec';
import { parseSourceKey } from './sourceKeys';
import { CollectorTemplateStore, isOptionsTemplate, type ScopeSnapshot, type StoredTemplate } from './templates';
import { LIMITS } from './types';
import type { FlowTemplateField } from '../flow/flowExport';

const MAGIC = 'INWIREMT';
const FORMAT = 1;
/** The decoder policy the state was derived under. */
const POLICY = 2;
const HEADER_BYTES = 32;
const TWO32 = 2 ** 32;

const SAMPLING_CODE = { absent: 0, known: 1, unsupported: 2 } as const;
const MODES: SequenceMode[] = ['learning', 'rfc', 'own-records', 'unrecognized'];

// --- writing ---------------------------------------------------------------------------------------------------

class Writer {
  private buf = new Uint8Array(4096);
  length = 0;
  private room(n: number): void {
    if (this.length + n <= this.buf.length) return;
    let size = this.buf.length;
    while (size < this.length + n) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buf.subarray(0, this.length));
    this.buf = next;
  }
  u8(n: number): void { this.room(1); this.buf[this.length++] = n & 0xff; }
  u16(n: number): void { this.u8(n); this.u8(n >>> 8); }
  u32(n: number): void { this.u16(n & 0xffff); this.u16(Math.floor(n / 0x10000) & 0xffff); }
  u64(n: number): void { this.u32(n % TWO32); this.u32(Math.floor(n / TWO32)); }
  /** A big-endian 16-bit value: field specifiers keep the wire's order. */
  be16(n: number): void { this.u8(n >>> 8); this.u8(n); }
  be32(n: number): void { this.be16(Math.floor(n / 0x10000) & 0xffff); this.be16(n & 0xffff); }
  bytes(b: ArrayLike<number>): void { this.room(b.length); for (let i = 0; i < b.length; i++) this.buf[this.length++] = b[i]; }
  take(): Uint8Array { return this.buf.slice(0, this.length); }
}

const clampU32 = (n: number): number => Math.min(Math.max(Math.floor(n), 0), TWO32 - 1);

function specifierBytes(protocol: 'v9' | 'ipfix', fields: FlowTemplateField[]): Uint8Array {
  const w = new Writer();
  for (const f of fields) {
    const enterprise = protocol === 'ipfix' && f.pen !== undefined;
    w.be16(enterprise ? f.type | 0x8000 : f.type);
    w.be16(f.length);
    if (enterprise) w.be32(f.pen!);
  }
  return w.take();
}

function ipv4Bytes(address: string): number[] {
  return address.split('.').map((part) => Number(part) & 0xff);
}

/** The store and the exporter state as of `throughEntryId`, received at `throughMs`. */
export function encodeCheckpoint(store: CollectorTemplateStore, state: ExporterState, throughEntryId: number, throughMs: number): Uint8Array {
  const scopes = store.exportScopes();
  const sources = state.exportSources();
  const w = new Writer();
  w.bytes(Array.from(MAGIC, (c) => c.charCodeAt(0)));
  w.u16(FORMAT); w.u16(POLICY); w.u16(scopes.length); w.u16(sources.length);
  w.u64(throughEntryId); w.u64(throughMs);
  for (const s of scopes) {
    w.u8(s.protocol === 'v9' ? 9 : 10);
    w.u8((s.uptimeMs !== null ? 1 : 0) | (s.systemInitMs !== null ? 2 : 0) | (s.gap ? 4 : 0));
    w.u16(s.port);
    w.bytes(ipv4Bytes(s.exporter));
    w.u32(s.domain); w.u32(s.uptimeMs ?? 0); w.u64(s.systemInitMs ?? 0); w.u64(s.messages); w.u16(s.templates.length); w.u16(0);
    for (const t of s.templates) {
      const specs = specifierBytes(s.protocol, t.fields);
      w.u16(t.id); w.u8((t.options ? 1 : 0) | (t.v9Options === true ? 2 : 0) | (t.previousSession ? 4 : 0)); w.u8(0);
      w.u16(t.options ? t.scopeCount : 0); w.u16(t.fields.length);
      w.u32(clampU32(t.intervalMs)); w.u32(clampU32(t.intervalMessages));
      w.u64(t.definedEntryId); w.u64(t.lastSeenMs); w.u64(t.lastSeenMessage);
      w.u32(specs.length); w.bytes(specs);
    }
  }
  for (const src of sources) {
    const key = Array.from(src.key, (c) => c.charCodeAt(0));
    w.u8(key.length); w.bytes(key);
    w.u8(SAMPLING_CODE[src.sampling.kind]); w.u8(src.sequence.seen ? 1 : 0); w.u16(src.samplers.length);
    w.u32(src.sampling.kind === 'known' ? src.sampling.interval : 0); w.u64(src.sampling.kind === 'known' ? src.sampling.sinceEntryId : 0);
    w.u8(MODES.indexOf(src.sequence.mode)); w.u8(src.sequence.pairs); w.u8(src.sequence.fitRfc); w.u8(src.sequence.fitOwn);
    w.u32(src.sequence.last); w.u32(src.sequence.lastRecords);
    for (const m of src.samplers) { w.u32(m.id); w.u16(m.algorithm); w.u16(0); w.u32(clampU32(m.interval)); w.u32(clampU32(m.space)); }
  }
  const body = w.take();
  const out = new Uint8Array(body.length + 4);
  out.set(body);
  new DataView(out.buffer).setUint32(body.length, crc32(body), true);
  return out;
}

// --- reading ---------------------------------------------------------------------------------------------------

class Malformed extends Error {}

class Reader {
  at = 0;
  private readonly v: DataView;
  constructor(private readonly b: Uint8Array, readonly end: number) { this.v = new DataView(b.buffer, b.byteOffset, b.byteLength); }
  private need(n: number): void { if (this.at + n > this.end) throw new Malformed('truncated'); }
  u8(): number { this.need(1); return this.b[this.at++]; }
  u16(): number { this.need(2); const n = this.v.getUint16(this.at, true); this.at += 2; return n; }
  u32(): number { this.need(4); const n = this.v.getUint32(this.at, true); this.at += 4; return n; }
  /** A u64 that is a safe integer. */
  u64(): number {
    const lo = this.u32();
    const hi = this.u32();
    if (hi >= 2 ** 21) throw new Malformed('a 64-bit value past 2^53');
    return hi * TWO32 + lo;
  }
  be16(): number { this.need(2); const n = this.v.getUint16(this.at, false); this.at += 2; return n; }
  be32(): number { this.need(4); const n = this.v.getUint32(this.at, false); this.at += 4; return n; }
  bytes(n: number): Uint8Array { this.need(n); const out = this.b.subarray(this.at, this.at + n); this.at += n; return out; }
}

function expect(ok: boolean, why: string): void {
  if (!ok) throw new Malformed(why);
}

/**
 * The state a checkpoint holds, or null if the bytes are not one: a bad magic,
 * format, policy, length, CRC or count, or anything the encoder would not have
 * written. It never throws.
 */
export function decodeCheckpoint(bytes: Uint8Array): { store: CollectorTemplateStore; state: ExporterState; throughEntryId: number; throughMs: number } | null {
  try {
    return read(bytes);
  } catch {
    return null;
  }
}

function read(bytes: Uint8Array): { store: CollectorTemplateStore; state: ExporterState; throughEntryId: number; throughMs: number } {
  expect(bytes.length >= HEADER_BYTES + 4 && bytes.length <= LIMITS.checkpointBytes, 'length');
  const body = bytes.length - 4;
  expect(new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(body, true) === crc32(bytes.subarray(0, body)), 'crc');
  const r = new Reader(bytes, body);
  expect(String.fromCharCode(...r.bytes(8)) === MAGIC, 'magic');
  expect(r.u16() === FORMAT, 'format');
  expect(r.u16() === POLICY, 'policy');
  const scopeCount = r.u16();
  const sourceCount = r.u16();
  const throughEntryId = r.u64();
  const throughMs = r.u64();

  const scopes: ScopeSnapshot[] = [];
  let previous: ScopeSnapshot | null = null;
  for (let i = 0; i < scopeCount; i++) {
    const protocolByte = r.u8();
    expect(protocolByte === 9 || protocolByte === 10, 'protocol');
    const protocol = protocolByte === 9 ? 'v9' : 'ipfix';
    const flags = r.u8();
    expect((flags & ~7) === 0, 'scope flags');
    const port = r.u16();
    const ip = Array.from(r.bytes(4));
    const domain = r.u32();
    const uptime = r.u32();
    const init = r.u64();
    const messages = r.u64();
    const templateCount = r.u16();
    expect(r.u16() === 0, 'reserved');
    expect((flags & 1) !== 0 || uptime === 0, 'uptime without its flag');
    expect((flags & 2) !== 0 || init === 0, 'systemInitTime without its flag');
    expect(templateCount <= LIMITS.templatesPerScope, 'templates per scope');
    const scope: ScopeSnapshot = {
      protocol, exporter: ip.join('.'), port, domain, uptimeMs: (flags & 1) !== 0 ? uptime : null, systemInitMs: (flags & 2) !== 0 ? init : null,
      gap: (flags & 4) !== 0, messages, templates: [],
    };
    if (previous !== null) {
      const order = (previous.protocol === scope.protocol ? 0 : previous.protocol === 'v9' ? -1 : 1) || previous.domain - scope.domain || previous.port - scope.port;
      expect(order < 0, 'scopes out of order');
    }
    let lastId = 255;
    for (let t = 0; t < templateCount; t++) {
      const id = r.u16();
      expect(id > lastId, 'templates out of order');
      lastId = id;
      const tflags = r.u8();
      expect((tflags & ~7) === 0, 'template flags');
      expect(r.u8() === 0, 'reserved');
      const scopeFields = r.u16();
      const fieldCount = r.u16();
      const intervalMs = r.u32();
      const intervalMessages = r.u32();
      const definedEntryId = r.u64();
      const lastSeenMs = r.u64();
      const lastSeenMessage = r.u64();
      const n = r.u32();
      expect(n <= LIMITS.templateFieldBytes, 'field bytes');
      const spec = new Reader(r.bytes(n), n);
      const fields: FlowTemplateField[] = [];
      for (let f = 0; f < fieldCount; f++) {
        const raw = spec.be16();
        const length = spec.be16();
        const enterprise = protocol === 'ipfix' && (raw & 0x8000) !== 0;
        fields.push({ type: enterprise ? raw & 0x7fff : raw, length, ...(enterprise ? { pen: spec.be32() } : {}) });
      }
      expect(spec.at === n, 'field specifiers');
      const options = (tflags & 1) !== 0;
      const v9Options = (tflags & 2) !== 0;
      expect(!v9Options || (options && protocol === 'v9'), 'v9 options flag');
      expect(options ? scopeFields <= fieldCount : scopeFields === 0, 'scope field count');
      const template: StoredTemplate = {
        scopeCount: scopeFields, fields, ...(v9Options ? { v9Options: true } : {}), id, options, definedEntryId, lastSeenMs, lastSeenMessage,
        intervalMs, intervalMessages, previousSession: (tflags & 4) !== 0,
      };
      expect(isOptionsTemplate(template) === options, 'options flag');
      scope.templates.push(template);
    }
    scopes.push(scope);
    previous = scope;
  }

  const sources: SourceSnapshot[] = [];
  let lastKey = '';
  for (let i = 0; i < sourceCount; i++) {
    const k = r.u8();
    const key = String.fromCharCode(...r.bytes(k));
    const parsed = parseSourceKey(key);
    expect(parsed !== null && parsed.protocol !== 'v5', 'source key');
    expect(i === 0 || key > lastKey, 'sources out of order');
    lastKey = key;
    const samplingCode = r.u8();
    const sflags = r.u8();
    expect((sflags & ~1) === 0, 'source flags');
    const samplerCount = r.u16();
    expect(samplerCount <= LIMITS.samplersPerSource, 'samplers');
    const interval = r.u32();
    const since = r.u64();
    let sampling: SamplingStatus;
    if (samplingCode === SAMPLING_CODE.known) {
      expect(interval >= 1, 'sampling interval');
      sampling = { kind: 'known', interval, sinceEntryId: since };
    } else {
      expect(samplingCode === SAMPLING_CODE.absent || samplingCode === SAMPLING_CODE.unsupported, 'sampling code');
      expect(interval === 0 && since === 0, 'sampling fields without a rate');
      sampling = samplingCode === SAMPLING_CODE.absent ? { kind: 'absent' } : { kind: 'unsupported', reason: 'unsupported sampling' };
    }
    const modeCode = r.u8();
    expect(modeCode < MODES.length, 'sequence mode');
    const pairs = r.u8();
    const fitRfc = r.u8();
    const fitOwn = r.u8();
    expect(fitRfc <= pairs && fitOwn <= pairs, 'sequence pairs');
    const last = r.u32();
    const lastRecords = r.u32();
    const samplers: SamplerEntry[] = [];
    let lastSampler = -1;
    for (let m = 0; m < samplerCount; m++) {
      const id = r.u32();
      expect(id > lastSampler, 'samplers out of order');
      lastSampler = id;
      const algorithm = r.u16();
      expect(r.u16() === 0, 'reserved');
      samplers.push({ id, algorithm, interval: r.u32(), space: r.u32() });
    }
    sources.push({ key, sampling, sequence: { mode: MODES[modeCode], seen: (sflags & 1) !== 0, last, lastRecords, pairs, fitRfc, fitOwn }, samplers });
  }
  expect(r.at === body, 'trailing bytes');
  const store = CollectorTemplateStore.fromScopes(scopes);
  expect(store !== null, 'bounds');
  return { store: store!, state: ExporterState.fromSources(sources), throughEntryId, throughMs };
}
