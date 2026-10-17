/**
 * Generated NetFlow v5 payloads and journal evidence for the monitoring
 * scripts. Not a test (it is in `check.ts`'s NOT_TESTS).
 *
 * Every byte is authored here from Cisco's v5 layout - a 24-byte header and
 * 48-byte records - so the decoder is checked against an author that is not
 * the decoder. No captured file is read.
 */
import type { DatagramEvidence } from '../../src/services/monitoring/types';

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
