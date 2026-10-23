/**
 * Generated NetFlow v5 payloads and journal evidence for the monitoring
 * scripts. Not a test (it is in `check.ts`'s NOT_TESTS).
 *
 * Every byte is authored here from Cisco's v5 layout - a 24-byte header and
 * 48-byte records - so the decoder is checked against an author that is not
 * the decoder. No captured file is read.
 */
import { WRITE_POLICY_VERSION, type DatagramEvidence } from '../../src/services/monitoring/types';

export const EXPORTER = '192.0.2.1';
export const COLLECTOR = '192.0.2.50';
export const GENERATION = '00112233445566778899aabbccddeeff';

export interface FlowSpec {
  src: string;
  dst: string;
  nextHop: string;
  inputIf: number;
  outputIf: number;
  packets: number;
  octets: number;
  /** sysUptime ms at the flow's first and last packet. */
  first: number;
  last: number;
  srcPort: number;
  dstPort: number;
  protocol: number;
}

export interface HeaderSpec {
  version: number;
  /** Written as the count field; defaults to the number of flows. */
  count?: number;
  uptime: number;
  secs: number;
  nsecs: number;
  sequence: number;
  engineType: number;
  engineId: number;
  /** The raw 16-bit sampling field. */
  sampling: number;
}

export const DEFAULT_HEADER: HeaderSpec = {
  version: 5, uptime: 600_000, secs: 1_760_000_000, nsecs: 250_000_000,
  sequence: 0, engineType: 0, engineId: 0, sampling: 0,
};

export const DEFAULT_FLOW: FlowSpec = {
  src: '10.0.0.1', dst: '10.0.0.2', nextHop: '0.0.0.0', inputIf: 1, outputIf: 2,
  packets: 10, octets: 1000, first: 590_000, last: 599_000,
  srcPort: 49_152, dstPort: 443, protocol: 6,
};

function ipv4Bytes(a: string): number[] {
  return a.split('.').map(Number);
}

/** A v5 datagram: header, then one 48-byte record per flow. */
export function v5Payload(header: Partial<HeaderSpec> = {}, flows: Partial<FlowSpec>[] = [{}]): Uint8Array {
  const h = { ...DEFAULT_HEADER, ...header };
  const out = new Uint8Array(24 + flows.length * 48);
  const v = new DataView(out.buffer);
  v.setUint16(0, h.version);
  v.setUint16(2, h.count ?? flows.length);
  v.setUint32(4, h.uptime);
  v.setUint32(8, h.secs);
  v.setUint32(12, h.nsecs);
  v.setUint32(16, h.sequence);
  out[20] = h.engineType;
  out[21] = h.engineId;
  v.setUint16(22, h.sampling);
  flows.forEach((partial, i) => {
    const f = { ...DEFAULT_FLOW, ...partial };
    const p = 24 + i * 48;
    out.set(ipv4Bytes(f.src), p);
    out.set(ipv4Bytes(f.dst), p + 4);
    out.set(ipv4Bytes(f.nextHop), p + 8);
    v.setUint16(p + 12, f.inputIf);
    v.setUint16(p + 14, f.outputIf);
    v.setUint32(p + 16, f.packets);
    v.setUint32(p + 20, f.octets);
    v.setUint32(p + 24, f.first);
    v.setUint32(p + 28, f.last);
    v.setUint16(p + 32, f.srcPort);
    v.setUint16(p + 34, f.dstPort);
    out[p + 37] = 0x18;
    out[p + 38] = f.protocol;
  });
  return out;
}

export function evidence(bytes: Uint8Array, over: Partial<DatagramEvidence> = {}): DatagramEvidence {
  const entryId = over.ref?.entryId ?? 1;
  return {
    kind: 'datagram',
    ref: { generation: GENERATION, entryId },
    sessionId: 'session-1',
    receivedMs: 1_760_000_000_500,
    receiveOrdinal: entryId,
    localIPv4: COLLECTOR,
    localPort: 2055,
    remoteIPv4: EXPORTER,
    remotePort: 40_000,
    bytes,
    policy: WRITE_POLICY_VERSION,
    segmentFirstId: 1,
    ...over,
  };
}

/** One valid datagram holding one flow; `octets` and friends override the flow, the rest the header. */
export function v5Evidence(
  flow: Partial<FlowSpec> = {}, header: Partial<HeaderSpec> = {}, over: Partial<DatagramEvidence> = {},
): DatagramEvidence {
  return evidence(v5Payload(header, [flow]), over);
}

/** A datagram that says it holds two records and holds one and a half. */
export function truncatedEvidence(): DatagramEvidence {
  const full = v5Payload({}, [{}, {}]);
  return evidence(full.slice(0, 24 + 48 + 24));
}

// --- NetFlow v9 and IPFIX (ADRs 0064, 0065) ------------------------------------------------------------
//
// Authored from RFC 3954 and RFC 7011: a message is a header and sets; a set is
// a four-byte header (id, length) and a body. Every length here is computed
// from what is written, except where a case asks for a lie (`count`, `length`).

export interface WireField { type: number; length: number; pen?: number }

export const be = {
  u8: (n: number): number[] => [n & 0xff],
  u16: (n: number): number[] => [(n >>> 8) & 0xff, n & 0xff],
  u32: (n: number): number[] => [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff],
  /** A value of `bytes` bytes, big-endian: how a reduced-size or 64-bit counter lies on the wire. */
  uint: (value: bigint | number, bytes: number): number[] => {
    let v = BigInt(value);
    const out: number[] = [];
    for (let i = 0; i < bytes; i++) { out.unshift(Number(v & 0xffn)); v >>= 8n; }
    return out;
  },
  ipv4: (a: string): number[] => a.split('.').map(Number),
  ipv6: (a: string): number[] => {
    const [head, tail = ''] = a.split('::');
    const groups = (s: string) => (s === '' ? [] : s.split(':'));
    const left = groups(head);
    const right = a.includes('::') ? groups(tail) : [];
    const all = a.includes('::') ? [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right] : left;
    return all.flatMap((g) => [(parseInt(g, 16) >> 8) & 0xff, parseInt(g, 16) & 0xff]);
  },
  concat: (...parts: ArrayLike<number>[]): number[] => parts.flatMap((p) => Array.from(p)),
};

/** A field specifier as the wire carries it: 4 bytes, 8 with an enterprise number (IPFIX only). */
export function fieldSpecifier(version: 9 | 10, f: WireField): number[] {
  if (f.pen !== undefined && version === 10) return [...be.u16(f.type | 0x8000), ...be.u16(f.length), ...be.u32(f.pen)];
  return [...be.u16(f.type), ...be.u16(f.length)];
}

/** A template record: id, field count, fields. */
export function templateRecord(version: 9 | 10, id: number, fields: WireField[]): number[] {
  return [...be.u16(id), ...be.u16(fields.length), ...fields.flatMap((f) => fieldSpecifier(version, f))];
}

/** An options template record. v9 counts its scope and option fields in bytes; IPFIX counts all fields, then the scope's. */
export function optionsTemplateRecord(version: 9 | 10, id: number, scope: WireField[], options: WireField[]): number[] {
  const specs = [...scope, ...options].flatMap((f) => fieldSpecifier(version, f));
  if (version === 9) return [...be.u16(id), ...be.u16(scope.length * 4), ...be.u16(options.length * 4), ...specs];
  return [...be.u16(id), ...be.u16(scope.length + options.length), ...be.u16(scope.length), ...specs];
}

/** A set: its header, the body, and `pad` zero bytes. The length covers all of it unless `length` lies. */
export function setOf(id: number, body: ArrayLike<number>, pad = 0, length?: number): number[] {
  const total = 4 + body.length + pad;
  return [...be.u16(id), ...be.u16(length ?? total), ...Array.from(body), ...Array<number>(pad).fill(0)];
}

export function templateSet(version: 9 | 10, records: number[][], pad = 0): number[] {
  return setOf(version === 9 ? 0 : 2, records.flat(), pad);
}

export function optionsTemplateSet(version: 9 | 10, records: number[][], pad = 0): number[] {
  return setOf(version === 9 ? 1 : 3, records.flat(), pad);
}

export function dataSet(id: number, records: number[][], pad = 0): number[] {
  return setOf(id, records.flat(), pad);
}

export interface V9Header { uptime: number; secs: number; sequence: number; sourceId: number; count?: number }

/** A v9 datagram. `count` is written as given: the decoder does not check it. */
export function v9Message(h: V9Header, sets: number[][]): Uint8Array {
  const body = sets.flat();
  return Uint8Array.from([...be.u16(9), ...be.u16(h.count ?? sets.length), ...be.u32(h.uptime), ...be.u32(h.secs), ...be.u32(h.sequence), ...be.u32(h.sourceId), ...body]);
}

export interface IpfixHeader { secs: number; sequence: number; domain: number; length?: number }

/** An IPFIX message. `length` is the header's own and is written as given when a case wants it wrong. */
export function ipfixMessage(h: IpfixHeader, sets: number[][]): Uint8Array {
  const body = sets.flat();
  return Uint8Array.from([...be.u16(10), ...be.u16(h.length ?? 16 + body.length), ...be.u32(h.secs), ...be.u32(h.sequence), ...be.u32(h.domain), ...body]);
}

// --- Sample exports for the sheet's drives and photographs (Task 10) ------------------------------------------

export interface SampleFlow { src: string; dst: string; octets: number; packets: number; proto?: number; sport?: number; dport?: number }

const V9_DATA: WireField[] = [
  { type: 8, length: 4 }, { type: 12, length: 4 }, { type: 7, length: 2 }, { type: 11, length: 2 }, { type: 4, length: 1 },
  { type: 1, length: 4 }, { type: 2, length: 4 }, { type: 22, length: 4 }, { type: 21, length: 4 },
];

/**
 * A v9 export as a router sends it: the data template (256) every time, an options template (257) and its
 * record stating "1 in `interval`" when an interval is given, then the data records. `uptime` is the header's.
 */
export function v9Sample(h: V9Header, flows: SampleFlow[], interval: number | null): Uint8Array {
  const sets: number[][] = [templateSet(9, [templateRecord(9, 256, V9_DATA)])];
  if (interval !== null) {
    sets.push(optionsTemplateSet(9, [optionsTemplateRecord(9, 257, [{ type: 1, length: 4 }], [{ type: 34, length: 4 }, { type: 35, length: 1 }])]));
    sets.push(dataSet(257, [[...be.u32(0), ...be.u32(interval), ...be.u8(2)]], 3));
  }
  sets.push(dataSet(256, flows.map((f) => [
    ...be.ipv4(f.src), ...be.ipv4(f.dst), ...be.u16(f.sport ?? 50_000), ...be.u16(f.dport ?? 443), ...be.u8(f.proto ?? 6),
    ...be.u32(f.octets), ...be.u32(f.packets), ...be.u32(Math.max(0, h.uptime - 20_000)), ...be.u32(Math.max(0, h.uptime - 1_000)),
  ])));
  return v9Message({ ...h, count: sets.length }, sets);
}

const IPFIX_DATA: WireField[] = [
  { type: 8, length: 4 }, { type: 12, length: 4 }, { type: 7, length: 2 }, { type: 11, length: 2 }, { type: 4, length: 1 },
  { type: 1, length: 8 }, { type: 2, length: 8 }, { type: 150, length: 4 }, { type: 151, length: 4 },
  { type: 1, length: 4, pen: 32473 },
];

/**
 * An IPFIX export with no sampling statement, one enterprise element the decoder does not interpret (PEN 32473 / IE 1;
 * 32473 is RFC 5612's documentation number, where 29305 would be RFC 5103's reverse direction, which is read), and, when `orphan` is set, a data set for template 400, which is never defined, so it waits.
 */
export function ipfixSample(h: IpfixHeader, flows: SampleFlow[], orphan: boolean): Uint8Array {
  const sets: number[][] = [templateSet(10, [templateRecord(10, 300, IPFIX_DATA)])];
  sets.push(dataSet(300, flows.map((f) => [
    ...be.ipv4(f.src), ...be.ipv4(f.dst), ...be.u16(f.sport ?? 50_000), ...be.u16(f.dport ?? 443), ...be.u8(f.proto ?? 6),
    ...be.uint(f.octets, 8), ...be.uint(f.packets, 8), ...be.u32(h.secs - 20), ...be.u32(h.secs - 1), ...be.u32(7),
  ])));
  if (orphan) sets.push(dataSet(400, [[1, 2, 3, 4, 5, 6, 7, 8]]));
  return ipfixMessage(h, sets);
}
