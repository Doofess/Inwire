/**
 * NetFlow v5, NetFlow v9 (RFC 3954) and IPFIX (RFC 7011): what a router or a
 * switch sends a collector about the traffic it forwarded, one record per
 * flow - who talked to whom, on what ports, how many packets and bytes, and
 * when.
 *
 * This module reads the structure and nothing else: the header, the sets, the
 * templates, and each data record as a list of elements with their offsets.
 * Two things are built on it:
 *
 * - **the packet tree**, `dissectors/cflow.ts`, which draws every element as
 *   the reference draws it;
 * - **flow records**, `normalizeFlows` below, which turn a message into the
 *   numbers a bandwidth view wants - addresses, ports, protocol, bytes,
 *   packets, absolute start and end times - with the version's quirks (v5
 *   and v9 time a flow by the exporter's uptime, IPFIX by the wall clock)
 *   resolved.
 *
 * Templates are cross-message state - a v9 or IPFIX data record cannot be
 * read without the template an earlier message defined - so neither entry
 * point keeps any: both are handed a `FlowTemplateSource`. The tree is handed
 * the frame recorder's (ADR 0049); a collector would hand a store of its own.
 *
 * No `node:*` and no Electron, like everything under `src/services/`.
 */
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';

export const NETFLOW_PORTS: readonly number[] = [2055, 9996];
export const IPFIX_PORT = 4739;

/** One element of a template: its number, its length, and its enterprise. */
export interface FlowTemplateField {
  type: number;
  /** 65535 is IPFIX's variable length: each record says how long. */
  length: number;
  /** IPFIX's Private Enterprise Number, when the element is a vendor's. */
  pen?: number;
}

/** A template as stored: what a data set's records are made of. */
export interface FlowTemplate {
  /** The leading elements that are an options template's scope; 0 for a data template. */
  scopeCount: number;
  fields: FlowTemplateField[];
  /** v9 options templates name their scopes by a type of their own (System, Interface...). */
  v9Options?: boolean;
}

/** A stored template, and the frame that defined it. */
export interface StoredFlowTemplate extends FlowTemplate {
  frame: number;
}

/**
 * Where templates are kept: per exporter, observation domain and template id.
 * `exporter` is opaque here - the tree keys it on both ends of the datagram,
 * which is the reference's keying.
 */
export interface FlowTemplateSource {
  lookup(exporter: string, domain: number, id: number): StoredFlowTemplate | null;
  define(exporter: string, domain: number, id: number, template: FlowTemplate, frame: number): void;
}

/**
 * The simplest store: a map. **The reference keeps the first definition of a
 * template id and ignores a redefinition**, and the tree follows it so the
 * two agree; a collector wants the newest, which is `replace`.
 */
export class MemoryTemplateStore implements FlowTemplateSource {
  private readonly templates = new Map<string, StoredFlowTemplate>();
  constructor(private readonly replace = true, private readonly limit = 4096) {}
  lookup(exporter: string, domain: number, id: number): StoredFlowTemplate | null {
    return this.templates.get(`${exporter}#${domain}#${id}`) ?? null;
  }
  define(exporter: string, domain: number, id: number, template: FlowTemplate, frame: number): void {
    const key = `${exporter}#${domain}#${id}`;
    if (!this.replace && this.templates.has(key)) return;
    this.templates.delete(key);
    if (this.templates.size >= this.limit) {
      const oldest = this.templates.keys().next();
      if (!oldest.done) this.templates.delete(oldest.value);
    }
    this.templates.set(key, { ...template, frame });
  }
}

const u16 = (b: Uint8Array, p: number) => (b[p] << 8) | b[p + 1];
const u32 = (b: Uint8Array, p: number) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;

/** An unsigned big-endian integer of any length up to 8 bytes. */
export function readUint(b: Uint8Array, p: number, length: number): bigint {
  let v = 0n;
  for (let i = 0; i < length; i++) v = (v << 8n) | BigInt(b[p + i]);
  return v;
}

// --- the header --------------------------------------------------------------

export interface FlowHeader {
  version: 5 | 9 | 10;
  /** v5 and v9: records (v5) or records and templates (v9) the message says it holds. */
  count?: number;
  /** IPFIX: the message's own length. */
  length?: number;
  /** v5 and v9: milliseconds since the exporter booted, when it sent this. */
  sysUptimeMs?: number;
  /** Seconds since the epoch, when it was sent. */
  unixSecs: number;
  /** v5: the nanoseconds past `unixSecs`. */
  unixNsecs?: number;
  sequence: number;
  /** v9's source id or IPFIX's observation domain; 0 for v5. */
  domain: number;
  /** v5's engine and sampling. */
  engineType?: number;
  engineId?: number;
  samplingMode?: number;
  samplingInterval?: number;
  /** Where the first record (v5) or set begins. */
  bodyStart: number;
}

/** The versions read here, and the header lengths they need. */
const HEADER_LENGTH: Record<number, number> = { 5: 24, 9: 20, 10: 16 };

/** The header, or null for a version this module does not read or a message too short to hold one. */
export function readFlowHeader(b: Uint8Array, start: number, end: number): FlowHeader | null {
  if (end - start < 2) return null;
  const version = u16(b, start);
  const need = HEADER_LENGTH[version];
  if (need === undefined || end - start < need) return null;
  if (version === 5) {
    const sampling = u16(b, start + 22);
    return {
      version, count: u16(b, start + 2), sysUptimeMs: u32(b, start + 4), unixSecs: u32(b, start + 8),
      unixNsecs: u32(b, start + 12), sequence: u32(b, start + 16), domain: 0,
      engineType: b[start + 20], engineId: b[start + 21], samplingMode: sampling >> 14, samplingInterval: sampling & 0x3fff,
      bodyStart: start + 24,
    };
  }
  if (version === 9) {
    return {
      version, count: u16(b, start + 2), sysUptimeMs: u32(b, start + 4), unixSecs: u32(b, start + 8),
      sequence: u32(b, start + 12), domain: u32(b, start + 16), bodyStart: start + 20,
    };
  }
  return {
    version: 10, length: u16(b, start + 2), unixSecs: u32(b, start + 4), sequence: u32(b, start + 8),
    domain: u32(b, start + 12), bodyStart: start + 16,
  };
}

// --- v5 ----------------------------------------------------------------------

/** A v5 record is fixed: 48 bytes, laid out by Cisco. */
export const V5_RECORD_LENGTH = 48;

/** v5's records, as many as the count names and the datagram holds whole. */
export function v5RecordOffsets(header: FlowHeader, end: number): number[] {
  const out: number[] = [];
  for (let i = 0; i < (header.count ?? 0); i++) {
    const at = header.bodyStart + i * V5_RECORD_LENGTH;
    if (at + V5_RECORD_LENGTH > end) break;
    out.push(at);
  }
  return out;
}

// --- sets ---------------------------------------------------------------------

export interface FlowSet {
  id: number;
  /** The set's header. */
  start: number;
  /** Its declared length, which may be short (< 4) or run past the message. */
  length: number;
  /** Where its content ends: the declared end, or the message's, whichever is first. */
  end: number;
}

/**
 * The sets of a v9 or IPFIX message, in order. A set whose length is under
 * four - which would loop forever - ends the walk, and is returned so the
 * tree can say so.
 */
export function readFlowSets(b: Uint8Array, header: FlowHeader, end: number): FlowSet[] {
  const out: FlowSet[] = [];
  let at = header.bodyStart;
  while (at + 4 <= end) {
    const id = u16(b, at);
    const length = u16(b, at + 2);
    out.push({ id, start: at, length, end: Math.min(end, at + Math.max(length, 4)) });
    if (length < 4) break;
    at += length;
  }
  return out;
}

/** Which kind of set an id is, for each version. */
export function setKind(version: number, id: number): 'template' | 'options' | 'data' | 'reserved' {
  if (id >= 256) return 'data';
  if (version === 9) return id === 0 ? 'template' : id === 1 ? 'options' : 'reserved';
  return id === 2 ? 'template' : id === 3 ? 'options' : 'reserved';
}

/** One template as it lies in a template or options set. */
export interface ParsedTemplate extends FlowTemplate {
  id: number;
  start: number;
  end: number;
  /** v9 options: the two lengths the header carries. */
  scopeLength?: number;
  optionLength?: number;
  /** IPFIX options: the counts the header carries. */
  totalCount?: number;
  /** Each field's place in the set, for the tree. */
  positions: number[];
  /** IPFIX: a template with no fields - a withdrawal. */
  withdrawal: boolean;
}

/** The templates in one template or options set, and where its padding starts. */
export function readTemplateSet(b: Uint8Array, version: number, set: FlowSet): { templates: ParsedTemplate[]; padding: number } {
  const kind = setKind(version, set.id);
  const templates: ParsedTemplate[] = [];
  let at = set.start + 4;
  const end = set.end;
  // An IPFIX field is two bytes of type and two of length, and four more of
  // enterprise when the type's top bit says so.
  const readFields = (count: number, from: number, positions: number[], fields: FlowTemplateField[]): number | null => {
    let p = from;
    for (let i = 0; i < count; i++) {
      if (p + 4 > end) return null;
      const raw = u16(b, p);
      const enterprise = version === 10 && (raw & 0x8000) !== 0;
      if (enterprise && p + 8 > end) return null;
      positions.push(p);
      fields.push({ type: version === 10 ? raw & 0x7fff : raw, length: u16(b, p + 2), ...(enterprise ? { pen: u32(b, p + 4) } : {}) });
      p += enterprise ? 8 : 4;
    }
    return p;
  };
  while (true) {
    if (kind === 'template') {
      if (at + 4 > end) break;
      const id = u16(b, at);
      const count = u16(b, at + 2);
      const positions: number[] = [];
      const fields: FlowTemplateField[] = [];
      const stop = readFields(count, at + 4, positions, fields);
      if (stop === null) break;
      templates.push({ id, start: at, end: stop, scopeCount: 0, fields, positions, withdrawal: count === 0 });
      at = stop;
    } else if (version === 9) {
      // A v9 options template counts in bytes, four to a field. Scopes are
      // types of their own (System, Interface...), not elements.
      if (at + 6 > end) break;
      const id = u16(b, at);
      const scopeLength = u16(b, at + 2);
      const optionLength = u16(b, at + 4);
      const scopeCount = Math.floor(scopeLength / 4);
      const optionCount = Math.floor(optionLength / 4);
      const positions: number[] = [];
      const fields: FlowTemplateField[] = [];
      const stop = readFields(scopeCount + optionCount, at + 6, positions, fields);
      if (stop === null) break;
      templates.push({ id, start: at, end: stop, scopeCount, fields, positions, scopeLength, optionLength, v9Options: true, withdrawal: false });
      at = stop;
    } else {
      if (at + 6 > end) break;
      const id = u16(b, at);
      const totalCount = u16(b, at + 2);
      const scopeCount = u16(b, at + 4);
      const positions: number[] = [];
      const fields: FlowTemplateField[] = [];
      const stop = readFields(totalCount, at + 6, positions, fields);
      if (stop === null) break;
      templates.push({ id, start: at, end: stop, scopeCount, fields, positions, totalCount, withdrawal: totalCount === 0 });
      at = stop;
    }
  }
  return { templates, padding: at };
}

/** One element's value in a record. */
export interface FlowValue {
  field: FlowTemplateField;
  /** Where the value starts, past any variable-length prefix. */
  start: number;
  length: number;
  /** A variable-length element's prefix: where it is, and how many bytes it took (1 or 3). */
  prefixAt?: number;
  prefixLength?: number;
}

/**
 * The records of a data set, read through its template. A record that does
 * not fit whole ends the set; what is left is padding. Templates with a
 * variable-length element have no fixed record size, so each record is read
 * until one does not fit.
 */
export function readDataRecords(b: Uint8Array, set: FlowSet, template: FlowTemplate): { records: FlowValue[][]; padding: number } {
  const records: FlowValue[][] = [];
  let at = set.start + 4;
  const end = set.end;
  if (template.fields.length === 0) return { records, padding: at };
  while (at < end) {
    const record: FlowValue[] = [];
    let p = at;
    let whole = true;
    for (const field of template.fields) {
      if (field.length === 0xffff) {
        if (p + 1 > end) { whole = false; break; }
        let length = b[p];
        let prefix = 1;
        if (length === 255) {
          if (p + 3 > end) { whole = false; break; }
          length = u16(b, p + 1);
          prefix = 3;
        }
        if (p + prefix + length > end) { whole = false; break; }
        record.push({ field, start: p + prefix, length, prefixAt: p, prefixLength: prefix });
        p += prefix + length;
      } else {
        if (p + field.length > end) { whole = false; break; }
        record.push({ field, start: p, length: field.length });
        p += field.length;
      }
    }
    if (!whole || p === at) break;
    records.push(record);
    at = p;
  }
  return { records, padding: at };
}

// --- flow records ---------------------------------------------------------------

/**
 * One flow, in the units a bandwidth view wants. Counters are numbers: an
 * IPFIX 64-bit counter past 2^53 loses its last digits, which is nine
 * petabytes in one flow.
 */
export interface FlowRecord {
  /** The datagram's sender: whoever exported the record. */
  exporter: string;
  version: 5 | 9 | 10;
  /** v9's source id, IPFIX's observation domain, 0 for v5. */
  domain: number;
  srcAddr?: string;
  dstAddr?: string;
  srcPort?: number;
  dstPort?: number;
  protocol?: number;
  octets?: number;
  packets?: number;
  /** Epoch milliseconds, where the record lets them be worked out. */
  startMs?: number;
  endMs?: number;
  tcpFlags?: number;
  tos?: number;
  inputIf?: number;
  outputIf?: number;
  srcAs?: number;
  dstAs?: number;
  nextHop?: string;
  /** 0 ingress, 1 egress. */
  direction?: number;
  vlan?: number;
  /** One in this many packets was sampled; multiply the counters by it. 0 or absent: not sampled, or not said. */
  samplingInterval?: number;
  flowEndReason?: number;
}

const ipv4 = formatIpv4Address;
const ipv6 = formatIpv6Address;

/** An NTP timestamp (RFC 5905) as epoch milliseconds. */
const ntpMs = (b: Uint8Array, p: number) => (u32(b, p) - 2208988800) * 1000 + (u32(b, p + 4) / 2 ** 32) * 1000;

/**
 * The flows in one message. `exporter` names the sender; `templates` is
 * consulted for v9 and IPFIX and taught the templates the message carries.
 */
export function normalizeFlows(
  b: Uint8Array, start: number, end: number, exporter: string, templates: FlowTemplateSource, frame = 0,
): FlowRecord[] {
  const header = readFlowHeader(b, start, end);
  if (header === null) return [];
  const exportMs = header.unixSecs * 1000 + (header.unixNsecs ?? 0) / 1e6;
  // v5 and v9 time a flow by the exporter's uptime: a record's time is the
  // export time less how long before the export it happened.
  const fromUptime = (ms: number) => exportMs - (((header.sysUptimeMs ?? 0) - ms) >>> 0);
  const base = { exporter, version: header.version, domain: header.domain } as const;
  if (header.version === 5) {
    return v5RecordOffsets(header, end).map((p): FlowRecord => ({
      ...base,
      srcAddr: ipv4(b, p), dstAddr: ipv4(b, p + 4), nextHop: ipv4(b, p + 8),
      inputIf: u16(b, p + 12), outputIf: u16(b, p + 14), packets: u32(b, p + 16), octets: u32(b, p + 20),
      startMs: fromUptime(u32(b, p + 24)), endMs: fromUptime(u32(b, p + 28)),
      srcPort: u16(b, p + 32), dstPort: u16(b, p + 34), tcpFlags: b[p + 37], protocol: b[p + 38], tos: b[p + 39],
      srcAs: u16(b, p + 40), dstAs: u16(b, p + 42),
      ...(header.samplingInterval ? { samplingInterval: header.samplingInterval } : {}),
    }));
  }
  const msgEnd = header.version === 10 ? Math.min(end, start + (header.length ?? 0)) : end;
  const out: FlowRecord[] = [];
  for (const set of readFlowSets(b, header, msgEnd)) {
    const kind = setKind(header.version, set.id);
    if (kind === 'template' || kind === 'options') {
      for (const t of readTemplateSet(b, header.version, set).templates) {
        if (!t.withdrawal) templates.define(exporter, header.domain, t.id, t, frame);
      }
      continue;
    }
    if (kind !== 'data') continue;
    const template = templates.lookup(exporter, header.domain, set.id);
    // Options data describes the exporter (its sampling rate, its interfaces), not a flow.
    if (template === null || template.scopeCount > 0) continue;
    for (const record of readDataRecords(b, set, template).records) out.push(recordFrom(b, record, base, exportMs, fromUptime));
  }
  return out;
}

function recordFrom(
  b: Uint8Array, record: FlowValue[], base: Pick<FlowRecord, 'exporter' | 'version' | 'domain'>, exportMs: number, fromUptime: (ms: number) => number,
): FlowRecord {
  const r: FlowRecord = { ...base };
  const num = (v: FlowValue) => Number(readUint(b, v.start, Math.min(v.length, 8)));
  // A record may time a flow several ways; the finest one wins, whatever the order.
  let startRank = -1;
  let endRank = -1;
  const start = (ms: number, rank: number) => { if (rank >= startRank) { r.startMs = ms; startRank = rank; } };
  const end = (ms: number, rank: number) => { if (rank >= endRank) { r.endMs = ms; endRank = rank; } };
  for (const v of record) {
    if (v.field.pen !== undefined) continue;
    const n = v.length <= 8 ? num(v) : 0;
    switch (v.field.type) {
      case 1: r.octets = n; break;
      case 2: r.packets = n; break;
      case 4: r.protocol = n; break;
      case 5: r.tos = n; break;
      case 6: r.tcpFlags = n; break;
      case 7: r.srcPort = n; break;
      case 8: if (v.length === 4) r.srcAddr ??= ipv4(b, v.start); break;
      case 10: r.inputIf = n; break;
      case 11: r.dstPort = n; break;
      case 12: if (v.length === 4) r.dstAddr ??= ipv4(b, v.start); break;
      case 14: r.outputIf = n; break;
      case 15: if (v.length === 4) r.nextHop ??= ipv4(b, v.start); break;
      case 16: r.srcAs = n; break;
      case 17: r.dstAs = n; break;
      case 21: end(fromUptime(n), 0); break;
      case 22: start(fromUptime(n), 0); break;
      case 27: if (v.length === 16) r.srcAddr ??= ipv6(b, v.start); break;
      case 28: if (v.length === 16) r.dstAddr ??= ipv6(b, v.start); break;
      case 34: case 305: r.samplingInterval = n; break;
      case 58: case 243: r.vlan = n; break;
      case 61: r.direction = n; break;
      case 62: if (v.length === 16) r.nextHop ??= ipv6(b, v.start); break;
      case 85: r.octets ??= n; break;
      case 86: r.packets ??= n; break;
      case 136: r.flowEndReason = n; break;
      case 150: start(n * 1000, 1); break;
      case 151: end(n * 1000, 1); break;
      case 152: start(n, 2); break;
      case 153: end(n, 2); break;
      case 154: case 156: if (v.length === 8) start(ntpMs(b, v.start), 3); break;
      case 155: case 157: if (v.length === 8) end(ntpMs(b, v.start), 3); break;
      case 158: start(exportMs - n / 1000, 3); break;
      case 159: end(exportMs - n / 1000, 3); break;
      default: break;
    }
  }
  return r;
}
