/**
 * The collector's decoder for NetFlow v5, v9 and IPFIX (ADRs 0064, 0065).
 *
 * `services/flow/flowExport.ts` reads the structure for the packet tree and is
 * lax and stateless in ways a history cannot be (it drops data that arrives
 * before its template and options data, keeps templates for ever, and reads
 * counters as `number`). This decoder reuses its readers - header, sets, data
 * records - and adds what a collector needs:
 *
 * - the whole datagram is **validated first**, and only then is the template
 *   store touched, so a malformed datagram changes no state;
 * - a template applies to the data sets after it in its own datagram and to
 *   later datagrams (ADR 0065); data with no template in scope is counted as
 *   awaiting (or refused) and never decoded later;
 * - counters are `bigint`, up to 64 bits; totals (IE 85/86) are used only when
 *   a template has no delta count; RFC 5103 reverse counts are kept apart;
 * - a flow time that cannot be derived is `null`, never the receipt time;
 * - options data is decoded into reports and is never a flow.
 *
 * Template state lives in the `CollectorTemplateStore` it is handed; sequence,
 * sampling and clock state are `exporterState.ts`'s. No `node:*` and no
 * Electron, like everything under `src/services/`.
 */
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';
import {
  readDataRecords, readFlowHeader, readFlowSets, readUint, setKind,
  type FlowSet, type FlowTemplate, type FlowTemplateField, type FlowValue,
} from '../flow/flowExport';
import { decodeV5, sourceKey as v5SourceKey } from './v5';
import { sourceKeyFor } from './sourceKeys';
import {
  CollectorTemplateStore, REVERSE_PEN, isInterpretedDataField, isInterpretedOptionsField, templateShape, type TemplateScope,
} from './templates';
import type { DatagramEvidence, DecodeResult } from './types';

export interface NormalizedFlow {
  srcAddr: string;
  dstAddr: string;
  srcPort: number | null;
  dstPort: number | null;
  protocol: number | null;
  reportedOctets: bigint;
  reportedPackets: bigint;
  /** RFC 5103 reverse counts (PEN 29305); null when the template has none. */
  reverseOctets: bigint | null;
  reversePackets: bigint | null;
  /** Epoch milliseconds, or null where the record does not let them be derived. Never the receipt time. */
  startMs: number | null;
  endMs: number | null;
  inputIf: number | null;
  outputIf: number | null;
  direction: number | null;
  tcpFlags: number | null;
  /** In-record IE 34 or IE 50 only. */
  samplingInterval: number | null;
  /** In-record IE 48 (v9) or 302 (IPFIX selectorId), for ExporterState to resolve. */
  samplerId: number | null;
  /** The counts came from IE 85/86: the template has no delta count. */
  totalCounts: boolean;
  entryId: number;
  /** Position among the datagram's data records (options records are not counted), so it names the record. */
  recordIndex: number;
}

export interface OptionsReport {
  templateId: number;
  scope: { type: number; value: bigint }[];
  samplingInterval?: number;
  samplingAlgorithm?: number;
  samplerId?: number;
  samplerMode?: number;
  samplerInterval?: number;
  selectorAlgorithm?: number;
  packetInterval?: number;
  packetSpace?: number;
  systemInitMs?: number;
  interfaceName?: { ifIndex: number | null; name: string };
}

/** Data sets whose template was not in scope: how many sets and bytes, per template id. Records are unknown. */
export interface AwaitingCount { templateId: number; sets: number; bytes: number }

export type FlowDecode =
  | {
    kind: 'valid';
    protocol: 'v5' | 'v9' | 'ipfix';
    sourceKey: string;
    sequence: number;
    exportMs: number;
    uptimeMs: number | null;
    flows: NormalizedFlow[];
    /** Data records of data templates, unsupported ones included; options records are not here. */
    dataRecords: number;
    optionsRecords: number;
    awaiting: AwaitingCount[];
    refused: AwaitingCount[];
    /** Templates in use here that have no octet count: their records are counted and not totalled. */
    unsupportedTemplates: number[];
    options: OptionsReport[];
    withdrawalsIgnored: number;
    restart: boolean;
    v5?: DecodeResult;
  }
  | { kind: 'unsupported' | 'malformed'; reason: string };

const u16 = (b: Uint8Array, p: number): number => (b[p] << 8) | b[p + 1];
const u32 = (b: Uint8Array, p: number): number => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;

/**
 * Decodes one datagram. `exporterIPv4` is the configured exporter, which names
 * the source and the template scope; `e.remoteIPv4` stays provenance.
 */
export function decodeDatagram(e: DatagramEvidence, exporterIPv4: string, policy: number, store: CollectorTemplateStore): FlowDecode {
  if (policy !== 1 && policy !== 2) return { kind: 'unsupported', reason: `decoder policy ${policy} is not read` };
  const b = e.bytes;
  const version = b.length >= 2 ? u16(b, 0) : 0;
  if (version === 5) return decodeV5Mapped(e, exporterIPv4);
  if ((version === 9 || version === 10) && policy === 2) return decodeTemplated(e, exporterIPv4, version, store);
  // Policy 1 reads v5 only, and a version nobody reads is decodeV5's to name.
  const r = decodeV5(e, exporterIPv4);
  return r.kind === 'valid' ? { kind: 'unsupported', reason: `NetFlow version ${version} is not read` } : r;
}

// --- v5 ----------------------------------------------------------------------------------------------------------

function decodeV5Mapped(e: DatagramEvidence, exporterIPv4: string): FlowDecode {
  const r = decodeV5(e, exporterIPv4);
  if (r.kind !== 'valid') return r;
  const b = e.bytes;
  const exportMs = u32(b, 8) * 1000 + Math.floor(u32(b, 12) / 1e6);
  const flows: NormalizedFlow[] = r.flows.map((f) => ({
    srcAddr: f.srcAddr, dstAddr: f.dstAddr, srcPort: f.srcPort, dstPort: f.dstPort, protocol: f.protocol,
    reportedOctets: f.reportedOctets, reportedPackets: f.reportedPackets, reverseOctets: null, reversePackets: null,
    startMs: f.startMs, endMs: f.endMs, inputIf: f.inputIf, outputIf: f.outputIf, direction: null, tcpFlags: null,
    samplingInterval: f.sampling.kind === 'reported' && f.sampling.interval > 0 ? f.sampling.interval : null,
    samplerId: null, totalCounts: false, entryId: e.ref.entryId, recordIndex: f.recordIndex,
  }));
  return {
    kind: 'valid', protocol: 'v5', sourceKey: v5SourceKey(exporterIPv4, r.engineType, r.engineId), sequence: r.sequence, exportMs,
    uptimeMs: r.uptimeMs, flows, dataRecords: flows.length, optionsRecords: 0, awaiting: [], refused: [], unsupportedTemplates: [],
    options: [], withdrawalsIgnored: 0, restart: false, v5: r,
  };
}

// --- templates, validated ----------------------------------------------------------------------------------------

interface TemplateRecord {
  id: number;
  withdrawal: boolean;
  /** An IPFIX options template with no scope field: not a template at all (RFC 7011 section 3.4.2.2). */
  ignored: boolean;
  template: FlowTemplate;
}

/**
 * The records of one template or options set, or null if it is malformed: a
 * field count that runs past the set, a template id under 256, or anything but
 * up to three zero bytes after the last record. IPFIX withdrawals are four
 * bytes in both kinds of set (RFC 7011 section 8.1), which is why this is not
 * `readTemplateSet`, whose options branch reads six.
 */
function readTemplateRecords(b: Uint8Array, version: 9 | 10, set: FlowSet, kind: 'template' | 'options'): TemplateRecord[] | null {
  const out: TemplateRecord[] = [];
  const end = set.start + set.length;
  let at = set.start + 4;
  const fields = (count: number, from: number): { fields: FlowTemplateField[]; next: number } | null => {
    const list: FlowTemplateField[] = [];
    let p = from;
    for (let i = 0; i < count; i++) {
      if (p + 4 > end) return null;
      const raw = u16(b, p);
      const enterprise = version === 10 && (raw & 0x8000) !== 0;
      if (enterprise && p + 8 > end) return null;
      list.push({ type: version === 10 ? raw & 0x7fff : raw, length: u16(b, p + 2), ...(enterprise ? { pen: u32(b, p + 4) } : {}) });
      p += enterprise ? 8 : 4;
    }
    return { fields: list, next: p };
  };
  while (at + 4 <= end) {
    const id = u16(b, at);
    if (version === 10 && u16(b, at + 2) === 0) {
      // A withdrawal names a template (id >= 256) or all of them (the set's own id).
      if (id < 256 && id !== set.id) return null;
      out.push({ id, withdrawal: true, ignored: false, template: { scopeCount: 0, fields: [] } });
      at += 4;
      continue;
    }
    if (id < 256) return null;
    if (version === 9 && kind === 'template') {
      const read = fields(u16(b, at + 2), at + 4);
      if (read === null) return null;
      out.push({ id, withdrawal: false, ignored: false, template: { scopeCount: 0, fields: read.fields } });
      at = read.next;
    } else if (version === 9) {
      if (at + 6 > end) return null;
      const scopeCount = Math.floor(u16(b, at + 2) / 4);
      const read = fields(scopeCount + Math.floor(u16(b, at + 4) / 4), at + 6);
      if (read === null) return null;
      out.push({ id, withdrawal: false, ignored: false, template: { scopeCount, fields: read.fields, v9Options: true } });
      at = read.next;
    } else if (kind === 'template') {
      const read = fields(u16(b, at + 2), at + 4);
      if (read === null) return null;
      out.push({ id, withdrawal: false, ignored: false, template: { scopeCount: 0, fields: read.fields } });
      at = read.next;
    } else {
      if (at + 6 > end) return null;
      const scopeCount = u16(b, at + 4);
      const total = u16(b, at + 2);
      const read = scopeCount > total ? null : fields(total, at + 6);
      if (read === null) return null;
      out.push({ id, withdrawal: false, ignored: scopeCount === 0, template: { scopeCount, fields: read.fields } });
      at = read.next;
    }
  }
  if (end - at > 3) return null;
  for (let i = at; i < end; i++) if (b[i] !== 0) return null;
  return out;
}

// --- records ---------------------------------------------------------------------------------------------------

const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const U32 = 2 ** 32;
/** An age at or past this is a time after the header's uptime, not a flow that old (as in `v5.ts`). */
const FUTURE_AGE = 2 ** 31;
const NTP_TO_UNIX_SECS = 2_208_988_800;

const START_RANK: Record<number, number> = { 22: 0, 150: 1, 158: 2, 152: 3, 154: 4, 156: 5 };
const END_RANK: Record<number, number> = { 21: 0, 151: 1, 159: 2, 153: 3, 155: 4, 157: 5 };

interface DataPlan {
  /** Which values the decoder reads, aligned with the template's fields. */
  read: boolean[];
  hasDelta: boolean;
  hasReverseDelta: boolean;
  hasReverse: boolean;
  totalCounts: boolean;
  unsupported: boolean;
}

const plans = new WeakMap<FlowTemplate, DataPlan>();

function planOf(t: FlowTemplate): DataPlan {
  const cached = plans.get(t);
  if (cached !== undefined) return cached;
  const read = t.fields.map(isInterpretedDataField);
  let hasDelta = false;
  let hasReverseDelta = false;
  let hasReverse = false;
  t.fields.forEach((f, i) => {
    if (!read[i]) return;
    if (f.pen === REVERSE_PEN) { hasReverse = true; if (f.type === 1 || f.type === 2) hasReverseDelta = true; return; }
    if (f.type === 1 || f.type === 2) hasDelta = true;
  });
  const shape = templateShape(t);
  const plan = { read, hasDelta, hasReverseDelta, hasReverse, totalCounts: shape.totalCounts, unsupported: shape.unsupported };
  plans.set(t, plan);
  return plan;
}

const uint = (b: Uint8Array, v: FlowValue): bigint => readUint(b, v.start, v.length);
const small = (b: Uint8Array, v: FlowValue): number => Number(uint(b, v));

function ntpMs(b: Uint8Array, at: number): number | null {
  const secs = u32(b, at);
  if (secs < NTP_TO_UNIX_SECS) return null;
  return (secs - NTP_TO_UNIX_SECS) * 1000 + Math.floor((u32(b, at + 4) * 1000) / U32);
}

interface RecordContext {
  b: Uint8Array;
  protocol: 'v9' | 'ipfix';
  exportMs: number;
  uptimeMs: number | null;
  systemInitMs: number | null;
}

function flowFrom(cx: RecordContext, values: FlowValue[], plan: DataPlan, entryId: number, recordIndex: number): NormalizedFlow {
  const { b } = cx;
  let src: string | null = null;
  let dst: string | null = null;
  let srcPort: number | null = null;
  let dstPort: number | null = null;
  let proto: number | null = null;
  let inputIf: number | null = null;
  let outputIf: number | null = null;
  let direction: number | null = null;
  let tcpFlags: number | null = null;
  let samplingInterval: number | null = null;
  let samplerId: number | null = null;
  let octets: bigint | null = null;
  let packets: bigint | null = null;
  let totalOctets: bigint | null = null;
  let totalPackets: bigint | null = null;
  let revOctets: bigint | null = null;
  let revPackets: bigint | null = null;
  let revTotalOctets: bigint | null = null;
  let revTotalPackets: bigint | null = null;
  let startMs: number | null = null;
  let endMs: number | null = null;
  let startRank = -1;
  let endRank = -1;
  const time = (isStart: boolean, ms: number | null, rank: number) => {
    if (ms === null) return;
    if (isStart) { if (rank >= startRank) { startMs = ms; startRank = rank; } } else if (rank >= endRank) { endMs = ms; endRank = rank; }
  };
  for (let i = 0; i < values.length; i++) {
    if (!plan.read[i]) continue;
    const v = values[i];
    const f = v.field;
    if (f.pen !== undefined) {
      const n = uint(b, v);
      if (f.type === 1) revOctets ??= n; else if (f.type === 2) revPackets ??= n;
      else if (f.type === 85) revTotalOctets ??= n; else revTotalPackets ??= n;
      continue;
    }
    switch (f.type) {
      case 1: octets ??= uint(b, v); break;
      case 2: packets ??= uint(b, v); break;
      case 85: totalOctets ??= uint(b, v); break;
      case 86: totalPackets ??= uint(b, v); break;
      case 4: proto ??= small(b, v); break;
      case 6: tcpFlags ??= small(b, v); break;
      case 7: srcPort ??= small(b, v); break;
      case 11: dstPort ??= small(b, v); break;
      case 8: src ??= formatIpv4Address(b, v.start); break;
      case 12: dst ??= formatIpv4Address(b, v.start); break;
      case 27: src ??= formatIpv6Address(b, v.start); break;
      case 28: dst ??= formatIpv6Address(b, v.start); break;
      case 10: inputIf ??= small(b, v); break;
      case 14: outputIf ??= small(b, v); break;
      case 61: direction ??= small(b, v); break;
      case 34: case 50: samplingInterval ??= small(b, v); break;
      case 48: case 302: samplerId ??= small(b, v); break;
      case 21: case 22: {
        const isStart = f.type === 22;
        const value = small(b, v);
        if (cx.protocol === 'v9') {
          const age = (((cx.uptimeMs ?? 0) - value) % U32 + U32) % U32;
          time(isStart, age >= FUTURE_AGE || cx.exportMs - age < 0 ? null : cx.exportMs - age, 0);
        } else {
          time(isStart, cx.systemInitMs === null ? null : cx.systemInitMs + value, 0);
        }
        break;
      }
      case 150: time(true, small(b, v) * 1000, START_RANK[150]); break;
      case 151: time(false, small(b, v) * 1000, END_RANK[151]); break;
      case 152: case 153: {
        const n = uint(b, v);
        time(f.type === 152, n > MAX_SAFE ? null : Number(n), f.type === 152 ? START_RANK[152] : END_RANK[153]);
        break;
      }
      case 154: case 155: case 156: case 157: {
        const isStart = f.type === 154 || f.type === 156;
        time(isStart, ntpMs(b, v.start), (isStart ? START_RANK : END_RANK)[f.type]);
        break;
      }
      case 158: case 159: {
        // Microseconds before the message's export time.
        const isStart = f.type === 158;
        time(isStart, cx.exportMs - Math.floor(small(b, v) / 1000), (isStart ? START_RANK : END_RANK)[f.type]);
        break;
      }
      default: break;
    }
  }
  const totals = plan.totalCounts;
  return {
    srcAddr: src ?? '', dstAddr: dst ?? '', srcPort, dstPort, protocol: proto,
    reportedOctets: (totals ? totalOctets : octets) ?? 0n, reportedPackets: (totals ? totalPackets : packets) ?? 0n,
    reverseOctets: plan.hasReverse ? (plan.hasReverseDelta ? revOctets : revTotalOctets) ?? 0n : null,
    reversePackets: plan.hasReverse ? (plan.hasReverseDelta ? revPackets : revTotalPackets) ?? 0n : null,
    startMs, endMs, inputIf, outputIf, direction, tcpFlags, samplingInterval, samplerId, totalCounts: totals, entryId, recordIndex,
  };
}

const text = new TextDecoder('utf-8');

function optionsFrom(b: Uint8Array, values: FlowValue[], template: FlowTemplate, templateId: number, protocol: 'v9' | 'ipfix'): OptionsReport {
  const r: OptionsReport = { templateId, scope: [] };
  let name: string | null = null;
  values.forEach((v, i) => {
    const n = Number(readUint(b, v.start, Math.min(v.length, 8)));
    if (i < template.scopeCount) {
      r.scope.push({ type: v.field.type, value: readUint(b, v.start, Math.min(v.length, 8)) });
      if (v.field.pen === undefined && v.field.type === 302 && protocol === 'ipfix') r.samplerId ??= n;
      return;
    }
    if (!isInterpretedOptionsField(v.field)) return;
    switch (v.field.type) {
      case 34: r.samplingInterval = n; break;
      case 35: r.samplingAlgorithm = n; break;
      case 48: case 302: r.samplerId = n; break;
      case 49: r.samplerMode = n; break;
      case 50: r.samplerInterval = n; break;
      case 304: r.selectorAlgorithm = n; break;
      case 305: r.packetInterval = n; break;
      case 306: r.packetSpace = n; break;
      case 160: if (readUint(b, v.start, 8) <= MAX_SAFE) r.systemInitMs = n; break;
      case 82: name = text.decode(b.subarray(v.start, v.start + v.length)).replace(/\0+$/, ''); break;
      default: break;
    }
  });
  if (name !== null) {
    // The interface the name belongs to is the scope's: v9's Interface scope (2), or IPFIX's ingress or egress interface.
    const scope = r.scope.find((s) => (protocol === 'v9' ? s.type === 2 : s.type === 10 || s.type === 14));
    r.interfaceName = { ifIndex: scope === undefined ? null : Number(scope.value), name };
  }
  return r;
}

const hasInformation = (r: OptionsReport): boolean =>
  r.samplingInterval !== undefined || r.samplingAlgorithm !== undefined || r.samplerId !== undefined || r.samplerMode !== undefined
  || r.samplerInterval !== undefined || r.selectorAlgorithm !== undefined || r.packetInterval !== undefined || r.packetSpace !== undefined
  || r.systemInitMs !== undefined || r.interfaceName !== undefined;

// --- v9 and IPFIX ------------------------------------------------------------------------------------------------

function decodeTemplated(e: DatagramEvidence, exporterIPv4: string, version: 9 | 10, store: CollectorTemplateStore): FlowDecode {
  const b = e.bytes;
  const header = readFlowHeader(b, 0, b.length);
  if (header === null) return { kind: 'malformed', reason: `header truncated: ${b.length} bytes, a v${version === 9 ? 9 : '10 (IPFIX)'} header is ${version === 9 ? 20 : 16}` };
  if (version === 10 && header.length !== b.length) {
    return { kind: 'malformed', reason: `the IPFIX header says ${header.length} bytes, the datagram has ${b.length}` };
  }

  // Validate everything before the store is touched.
  const sets = readFlowSets(b, header, b.length);
  const templates = new Map<FlowSet, TemplateRecord[]>();
  for (const set of sets) {
    if (set.length < 4) return { kind: 'malformed', reason: `set ${set.id} at ${set.start} has length ${set.length}, under its own 4-byte header` };
    if (set.start + set.length > b.length) {
      return { kind: 'malformed', reason: `set ${set.id} at ${set.start} runs ${set.start + set.length - b.length} bytes past the end of the message` };
    }
    const kind = setKind(version, set.id);
    if (kind === 'template' || kind === 'options') {
      const records = readTemplateRecords(b, version, set, kind);
      if (records === null) {
        return { kind: 'malformed', reason: `${kind} set at ${set.start}: a field count runs past the set, a template id is under 256, or bytes other than up to three zeros follow the records` };
      }
      templates.set(set, records);
    }
  }

  const protocol = version === 9 ? 'v9' : 'ipfix';
  const scope: TemplateScope = { protocol, exporter: exporterIPv4, exporterPort: version === 10 ? e.remotePort : null, domain: header.domain };
  const entryId = e.ref.entryId;
  const uptimeMs = version === 9 ? header.sysUptimeMs ?? null : null;
  const exportMs = header.unixSecs * 1000;
  let restart = store.beginDatagram(scope, e.receivedMs, uptimeMs, e.remotePort) === 'restart';

  const flows: NormalizedFlow[] = [];
  const awaiting = new Map<number, AwaitingCount>();
  const refused = new Map<number, AwaitingCount>();
  const unsupportedTemplates: number[] = [];
  const options: OptionsReport[] = [];
  let dataRecords = 0;
  let optionsRecords = 0;
  let withdrawalsIgnored = 0;

  for (const set of sets) {
    const kind = setKind(version, set.id);
    if (kind === 'template' || kind === 'options') {
      for (const record of templates.get(set) ?? []) {
        if (record.withdrawal) { store.withdrawalIgnored(scope); withdrawalsIgnored++; continue; }
        if (record.ignored) continue;
        store.define(scope, record.id, record.template, entryId, e.receivedMs);
      }
      continue;
    }
    if (kind !== 'data') continue;
    const template = store.lookup(scope, set.id);
    if (template === null) {
      const into = store.isRefused(scope, set.id) ? refused : awaiting;
      const count = into.get(set.id) ?? { templateId: set.id, sets: 0, bytes: 0 };
      count.sets++;
      count.bytes += set.length;
      into.set(set.id, count);
      continue;
    }
    const { records } = readDataRecords(b, { id: set.id, start: set.start, length: set.length, end: set.start + set.length }, template);
    if (template.options) {
      for (const values of records) {
        optionsRecords++;
        const report = optionsFrom(b, values, template, set.id, protocol);
        if (!hasInformation(report)) continue;
        options.push(report);
        if (report.systemInitMs !== undefined && store.observeSystemInit(scope, report.systemInitMs, entryId) === 'restart') restart = true;
      }
      continue;
    }
    const plan = planOf(template);
    if (plan.unsupported && !unsupportedTemplates.includes(set.id)) unsupportedTemplates.push(set.id);
    const cx: RecordContext = { b, protocol, exportMs, uptimeMs, systemInitMs: store.systemInitMs(scope) };
    for (const values of records) {
      if (!plan.unsupported) flows.push(flowFrom(cx, values, plan, entryId, dataRecords));
      dataRecords++;
    }
  }

  return {
    kind: 'valid', protocol, sourceKey: sourceKeyFor(protocol, exporterIPv4, header.domain), sequence: header.sequence, exportMs, uptimeMs,
    flows, dataRecords, optionsRecords, awaiting: [...awaiting.values()], refused: [...refused.values()], unsupportedTemplates, options,
    withdrawalsIgnored, restart,
  };
}
