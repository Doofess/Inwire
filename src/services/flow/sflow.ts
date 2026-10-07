/**
 * sFlow version 5 (sflow.org's sflow_version_5.txt), decoded into plain data.
 *
 * A switch or router running sFlow does two things, and a datagram to UDP 6343
 * carries both: it samples one packet in N and sends the first bytes of each
 * (a **flow sample**), and every few seconds it sends each interface's
 * counters - octets and packets in and out, errors, discards (a **counter
 * sample**). The first answers "what is on this link", scaled by N; the
 * second answers "how full is it", exactly. A collector needs nothing else to
 * draw a link's bandwidth and spot it overloading.
 *
 * **This module is the decode and nothing more**, so that a collector can
 * read the same datagrams without going through a protocol tree:
 * `dissectors/sflow.ts` draws the tree from what this returns. It reads
 * bytes and returns values - no names, no strings for display, no state - and
 * every position it reports is an offset into the bytes it was given, which
 * is how the tree highlights a row.
 *
 * Counters that the spec defines as 64 bits are `bigint`: an interface's
 * octet counter passes 2^53 after about a year at 100 Gb/s, and a collector
 * that subtracts two readings to get a rate must not round either.
 *
 * A sampled header is copied out of the datagram (`slice`), because a
 * collector keeps it past the frame and the frame's buffer may be moved.
 */

/** Where a decoded structure sits in the datagram: `[at, end)`. */
export interface Span { at: number; end: number }

export interface SflowDatagram extends Span {
  version: number;
  /** 1 IPv4, 2 IPv6; anything else and `agent` is null. */
  agentType: number;
  /** The agent's address as dotted quad or 16 bytes; the caller formats a v6 one. */
  agent: { v6: false; address: Uint8Array } | { v6: true; address: Uint8Array } | null;
  subAgentId: number;
  sequence: number;
  /** Milliseconds since the agent booted - the clock every sample is read against. */
  uptimeMs: number;
  /** As declared; `samples` may hold fewer if the datagram was cut short. */
  sampleCount: number;
  samples: SflowSample[];
  /** True when the datagram ended before what it declared. */
  truncated: boolean;
}

/** The format word every sample and record opens with: an enterprise and a 12-bit format. */
export interface Tagged extends Span {
  enterprise: number;
  format: number;
  /** The declared length of the body that follows the eight-byte tag. */
  length: number;
  bodyAt: number;
}

/** An interface as an expanded sample states it: format 0 is an ifIndex. */
export interface InterfaceRef { format: number; value: number }

export interface FlowSample extends Tagged {
  kind: 'flow';
  expanded: boolean;
  sequence: number;
  sourceIdType: number;
  sourceIdIndex: number;
  /** One packet in this many was sampled - the multiplier for every byte count. */
  samplingRate: number;
  samplePool: number;
  drops: number;
  /** Compact samples carry a bare ifIndex here; expanded ones a format and value. */
  input: InterfaceRef;
  /**
   * Format 0 an ifIndex, 1 a discarded packet (the value is the reason),
   * 2 several interfaces (the value is how many, or 0 when unknown).
   */
  output: InterfaceRef;
  recordCount: number;
  records: FlowRecord[];
}

export interface CounterSample extends Tagged {
  kind: 'counters';
  expanded: boolean;
  sequence: number;
  sourceIdType: number;
  sourceIdIndex: number;
  recordCount: number;
  records: CounterRecord[];
}

/** A sample of a format this module does not read; its body is skipped by its length. */
export interface UnknownSample extends Tagged { kind: 'unknown' }

export type SflowSample = FlowSample | CounterSample | UnknownSample;

// --- flow records -----------------------------------------------------------

export interface RawHeaderRecord extends Tagged {
  kind: 'rawHeader';
  /** The link type of `header`: 1 Ethernet, 11 IPv4, 12 IPv6 (the spec's header_protocol). */
  protocol: number;
  /** The sampled packet's length on the wire, before it was cut to `header`. */
  frameLength: number;
  stripped: number;
  /** The first bytes of the sampled packet, copied. */
  header: Uint8Array;
  headerAt: number;
}

export interface EthernetRecord extends Tagged {
  kind: 'ethernet';
  frameLength: number;
  src: Uint8Array;
  dst: Uint8Array;
  etherType: number;
}

export interface IpRecord extends Tagged {
  kind: 'ipv4' | 'ipv6';
  /** The IP packet's length (named apart from the record's own `length`). */
  ipLength: number;
  protocol: number;
  src: Uint8Array;
  dst: Uint8Array;
  srcPort: number;
  dstPort: number;
  tcpFlags: number;
  /** IPv4's TOS byte, or IPv6's priority. */
  tos: number;
}

export interface SwitchRecord extends Tagged {
  kind: 'switch';
  srcVlan: number;
  srcPriority: number;
  dstVlan: number;
  dstPriority: number;
}

export interface RouterRecord extends Tagged {
  kind: 'router';
  nextHop: Address | null;
  srcMask: number;
  dstMask: number;
}

export interface GatewayRecord extends Tagged {
  kind: 'gateway';
  nextHop: Address | null;
  as: number;
  srcAs: number;
  srcPeerAs: number;
  /** Each segment: 1 AS_SET, 2 AS_SEQUENCE, and its AS numbers. */
  asPath: { type: number; asns: number[]; at: number }[];
  communities: number[];
  localPref: number;
}

export interface UnknownRecord extends Tagged { kind: 'unknown' }

export type FlowRecord = RawHeaderRecord | EthernetRecord | IpRecord | SwitchRecord | RouterRecord | GatewayRecord | UnknownRecord;

/** An address with its sFlow type word: 1 IPv4, 2 IPv6. */
export interface Address { type: number; bytes: Uint8Array; at: number }

// --- counter records --------------------------------------------------------

/** RFC 2233's ifTable, the record a bandwidth graph is drawn from. */
export interface GenericInterfaceCounters extends Tagged {
  kind: 'generic';
  ifIndex: number;
  ifType: number;
  /** Bits per second. */
  ifSpeed: bigint;
  /** 1 full duplex, 2 half, 3 in, 4 out; 0 unknown. */
  ifDirection: number;
  /** Bit 0 admin up, bit 1 operationally up. */
  ifStatus: number;
  inOctets: bigint;
  inUcastPkts: number;
  inMulticastPkts: number;
  inBroadcastPkts: number;
  inDiscards: number;
  inErrors: number;
  inUnknownProtos: number;
  outOctets: bigint;
  outUcastPkts: number;
  outMulticastPkts: number;
  outBroadcastPkts: number;
  outDiscards: number;
  outErrors: number;
  promiscuous: number;
}

/** RFC 2358's dot3Stats, in the spec's order. */
export interface EthernetCounters extends Tagged {
  kind: 'ethernet';
  values: number[];
}

export interface VlanCounters extends Tagged {
  kind: 'vlan';
  vlanId: number;
  octets: bigint;
  ucastPkts: number;
  multicastPkts: number;
  broadcastPkts: number;
  discards: number;
}

export interface ProcessorCounters extends Tagged {
  kind: 'processor';
  /** Load averages in hundredths of a percent. */
  cpu5s: number;
  cpu1m: number;
  cpu5m: number;
  totalMemory: bigint;
  freeMemory: bigint;
}

export interface UnknownCounters extends Tagged { kind: 'unknown' }

export type CounterRecord = GenericInterfaceCounters | EthernetCounters | VlanCounters | ProcessorCounters | UnknownCounters;

/** The well-known port an agent sends to. */
export const SFLOW_PORT = 6343;

/** Thrown past the end of what was given; caught at each level so a cut datagram keeps what it had. */
class Short extends Error {}

class Reader {
  constructor(readonly b: Uint8Array, public at: number, readonly end: number) {}
  need(n: number): void { if (this.at + n > this.end) throw new Short(); }
  u32(): number {
    this.need(4);
    const b = this.b;
    const v = ((b[this.at] << 24) | (b[this.at + 1] << 16) | (b[this.at + 2] << 8) | b[this.at + 3]) >>> 0;
    this.at += 4;
    return v;
  }
  u64(): bigint {
    const hi = this.u32();
    const lo = this.u32();
    return (BigInt(hi) << 32n) | BigInt(lo);
  }
  bytes(n: number): Uint8Array {
    this.need(n);
    const out = this.b.slice(this.at, this.at + n);
    this.at += n;
    return out;
  }
  /** An address with its type word; an unknown type has no address to read. */
  address(): Address | null {
    const at = this.at;
    const type = this.u32();
    if (type === 1) return { type, bytes: this.bytes(4), at };
    if (type === 2) return { type, bytes: this.bytes(16), at };
    return null;
  }
}

/** The tag, and a reader limited to the body it declares (or to what is left). */
function tagged(r: Reader): { tag: Tagged; body: Reader } {
  const at = r.at;
  const word = r.u32();
  const length = r.u32();
  const bodyAt = r.at;
  const end = Math.min(r.end, bodyAt + length);
  r.at = end;
  return {
    tag: { at, end, enterprise: word >>> 12, format: word & 0xfff, length, bodyAt },
    body: new Reader(r.b, bodyAt, end),
  };
}

function flowRecord(tag: Tagged, r: Reader): FlowRecord {
  if (tag.enterprise !== 0) return { ...tag, kind: 'unknown' };
  switch (tag.format) {
    case 1: {
      const protocol = r.u32();
      const frameLength = r.u32();
      const stripped = r.u32();
      const n = r.u32();
      const headerAt = r.at;
      return { ...tag, kind: 'rawHeader', protocol, frameLength, stripped, header: r.bytes(Math.min(n, r.end - r.at)), headerAt };
    }
    case 2: {
      const frameLength = r.u32();
      const src = r.bytes(6); r.bytes(2);
      const dst = r.bytes(6); r.bytes(2);
      return { ...tag, kind: 'ethernet', frameLength, src, dst, etherType: r.u32() };
    }
    case 3: case 4: {
      const v6 = tag.format === 4;
      const ipLength = r.u32();
      const protocol = r.u32();
      const src = r.bytes(v6 ? 16 : 4);
      const dst = r.bytes(v6 ? 16 : 4);
      return { ...tag, kind: v6 ? 'ipv6' : 'ipv4', ipLength, protocol, src, dst, srcPort: r.u32(), dstPort: r.u32(), tcpFlags: r.u32(), tos: r.u32() };
    }
    case 1001:
      return { ...tag, kind: 'switch', srcVlan: r.u32(), srcPriority: r.u32(), dstVlan: r.u32(), dstPriority: r.u32() };
    case 1002: {
      const nextHop = r.address();
      return { ...tag, kind: 'router', nextHop, srcMask: r.u32(), dstMask: r.u32() };
    }
    case 1003: {
      const nextHop = r.address();
      const as = r.u32();
      const srcAs = r.u32();
      const srcPeerAs = r.u32();
      const segments = r.u32();
      const asPath: GatewayRecord['asPath'] = [];
      for (let i = 0; i < segments; i++) {
        const at = r.at;
        const type = r.u32();
        const n = r.u32();
        r.need(n * 4);
        const asns: number[] = [];
        for (let k = 0; k < n; k++) asns.push(r.u32());
        asPath.push({ type, asns, at });
      }
      const n = r.u32();
      r.need(n * 4);
      const communities: number[] = [];
      for (let k = 0; k < n; k++) communities.push(r.u32());
      return { ...tag, kind: 'gateway', nextHop, as, srcAs, srcPeerAs, asPath, communities, localPref: r.u32() };
    }
    default:
      return { ...tag, kind: 'unknown' };
  }
}

function counterRecord(tag: Tagged, r: Reader): CounterRecord {
  if (tag.enterprise !== 0) return { ...tag, kind: 'unknown' };
  switch (tag.format) {
    case 1:
      return {
        ...tag, kind: 'generic',
        ifIndex: r.u32(), ifType: r.u32(), ifSpeed: r.u64(), ifDirection: r.u32(), ifStatus: r.u32(),
        inOctets: r.u64(), inUcastPkts: r.u32(), inMulticastPkts: r.u32(), inBroadcastPkts: r.u32(),
        inDiscards: r.u32(), inErrors: r.u32(), inUnknownProtos: r.u32(),
        outOctets: r.u64(), outUcastPkts: r.u32(), outMulticastPkts: r.u32(), outBroadcastPkts: r.u32(),
        outDiscards: r.u32(), outErrors: r.u32(), promiscuous: r.u32(),
      };
    case 2: {
      r.need(13 * 4);
      const values: number[] = [];
      for (let i = 0; i < 13; i++) values.push(r.u32());
      return { ...tag, kind: 'ethernet', values };
    }
    case 5:
      return { ...tag, kind: 'vlan', vlanId: r.u32(), octets: r.u64(), ucastPkts: r.u32(), multicastPkts: r.u32(), broadcastPkts: r.u32(), discards: r.u32() };
    case 1001:
      return { ...tag, kind: 'processor', cpu5s: r.u32(), cpu1m: r.u32(), cpu5m: r.u32(), totalMemory: r.u64(), freeMemory: r.u64() };
    default:
      return { ...tag, kind: 'unknown' };
  }
}

/**
 * The records of a sample, as many as are whole. A record whose body is cut
 * short ends the list, and `cut` says so.
 */
function records<T>(r: Reader, count: number, read: (tag: Tagged, body: Reader) => T): { list: T[]; cut: boolean } {
  const list: T[] = [];
  for (let i = 0; i < count; i++) {
    if (r.at >= r.end) return { list, cut: true };
    try {
      const { tag, body } = tagged(r);
      list.push(read(tag, body));
    } catch (e) {
      if (e instanceof Short) return { list, cut: true };
      throw e;
    }
  }
  return { list, cut: false };
}

function sample(tag: Tagged, r: Reader): { sample: SflowSample; cut: boolean } {
  if (tag.enterprise !== 0) return { sample: { ...tag, kind: 'unknown' }, cut: false };
  switch (tag.format) {
    case 1: case 3: {
      const expanded = tag.format === 3;
      const sequence = r.u32();
      let sourceIdType: number;
      let sourceIdIndex: number;
      if (expanded) { sourceIdType = r.u32(); sourceIdIndex = r.u32(); } else {
        const id = r.u32();
        sourceIdType = id >>> 24;
        sourceIdIndex = id & 0xffffff;
      }
      const samplingRate = r.u32();
      const samplePool = r.u32();
      const drops = r.u32();
      let input: InterfaceRef;
      let output: InterfaceRef;
      if (expanded) {
        input = { format: r.u32(), value: r.u32() };
        output = { format: r.u32(), value: r.u32() };
      } else {
        input = { format: 0, value: r.u32() };
        const word = r.u32();
        output = { format: word >>> 30, value: word & 0x3fffffff };
      }
      const recordCount = r.u32();
      const { list, cut } = records(r, recordCount, flowRecord);
      return {
        sample: { ...tag, kind: 'flow', expanded, sequence, sourceIdType, sourceIdIndex, samplingRate, samplePool, drops, input, output, recordCount, records: list },
        cut,
      };
    }
    case 2: case 4: {
      const expanded = tag.format === 4;
      const sequence = r.u32();
      let sourceIdType: number;
      let sourceIdIndex: number;
      if (expanded) { sourceIdType = r.u32(); sourceIdIndex = r.u32(); } else {
        const id = r.u32();
        sourceIdType = id >>> 24;
        sourceIdIndex = id & 0xffffff;
      }
      const recordCount = r.u32();
      const { list, cut } = records(r, recordCount, counterRecord);
      return { sample: { ...tag, kind: 'counters', expanded, sequence, sourceIdType, sourceIdIndex, recordCount, records: list }, cut };
    }
    default:
      return { sample: { ...tag, kind: 'unknown' }, cut: false };
  }
}

/**
 * Decodes one sFlow v5 datagram, or returns null when the bytes are not one:
 * too short for the header, a version other than 5, or an agent address type
 * that is neither IPv4 nor IPv6.
 */
export function decodeSflow(b: Uint8Array, start: number, end: number): SflowDatagram | null {
  const r = new Reader(b, start, Math.min(end, b.length));
  try {
    const version = r.u32();
    if (version !== 5) return null;
    const agentType = r.u32();
    if (agentType !== 1 && agentType !== 2) return null;
    const address = r.bytes(agentType === 1 ? 4 : 16);
    const datagram: SflowDatagram = {
      at: start, end: r.end, version, agentType,
      agent: agentType === 1 ? { v6: false, address } : { v6: true, address },
      subAgentId: r.u32(), sequence: r.u32(), uptimeMs: r.u32(), sampleCount: r.u32(),
      samples: [], truncated: false,
    };
    for (let i = 0; i < datagram.sampleCount; i++) {
      if (r.at >= r.end) { datagram.truncated = true; break; }
      try {
        const { tag, body } = tagged(r);
        const read = sample(tag, body);
        datagram.samples.push(read.sample);
        if (read.cut || tag.bodyAt + tag.length > r.end) datagram.truncated = true;
      } catch (e) {
        if (!(e instanceof Short)) throw e;
        datagram.truncated = true;
        break;
      }
    }
    return datagram;
  } catch (e) {
    if (e instanceof Short) return null;
    throw e;
  }
}

/**
 * One interface's counters at one moment, as a bandwidth graph wants them:
 * two of these from the same agent and ifIndex, subtracted and divided by the
 * time between them, are the link's rate.
 */
export interface InterfaceReading {
  agent: string;
  subAgentId: number;
  ifIndex: number;
  /** The agent's clock when it read the counters, in milliseconds since boot. */
  uptimeMs: number;
  speedBps: bigint;
  inOctets: bigint;
  outOctets: bigint;
  inPackets: number;
  outPackets: number;
  inErrors: number;
  outErrors: number;
  inDiscards: number;
  outDiscards: number;
}

/**
 * Every generic interface counter record in a datagram, flattened. `agent` is
 * the caller's text for the agent address, so this module still formats
 * nothing.
 */
export function interfaceReadings(d: SflowDatagram, agent: string): InterfaceReading[] {
  const out: InterfaceReading[] = [];
  for (const s of d.samples) {
    if (s.kind !== 'counters') continue;
    for (const c of s.records) {
      if (c.kind !== 'generic') continue;
      out.push({
        agent, subAgentId: d.subAgentId, ifIndex: c.ifIndex, uptimeMs: d.uptimeMs, speedBps: c.ifSpeed,
        inOctets: c.inOctets, outOctets: c.outOctets,
        inPackets: c.inUcastPkts + c.inMulticastPkts + c.inBroadcastPkts,
        outPackets: c.outUcastPkts + c.outMulticastPkts + c.outBroadcastPkts,
        inErrors: c.inErrors, outErrors: c.outErrors, inDiscards: c.inDiscards, outDiscards: c.outDiscards,
      });
    }
  }
  return out;
}

/**
 * One sampled packet, scaled: it stands for `samplingRate` packets of about
 * `frameLength` bytes each. `header` is its first bytes when the agent sent
 * them, for a collector that dissects them to find the conversation.
 */
export interface SampledPacket {
  agent: string;
  samplingRate: number;
  /** null when the sample did not name an interface. */
  inputIfIndex: number | null;
  /** null for a dropped packet or one sent out of several interfaces. */
  outputIfIndex: number | null;
  dropped: boolean;
  frameLength: number | null;
  headerProtocol: number | null;
  header: Uint8Array | null;
}

/** Every flow sample in a datagram, one entry each. */
export function sampledPackets(d: SflowDatagram, agent: string): SampledPacket[] {
  const out: SampledPacket[] = [];
  for (const s of d.samples) {
    if (s.kind !== 'flow') continue;
    const raw = s.records.find((r): r is RawHeaderRecord => r.kind === 'rawHeader');
    const eth = s.records.find((r): r is EthernetRecord => r.kind === 'ethernet');
    out.push({
      agent,
      samplingRate: s.samplingRate,
      inputIfIndex: s.input.format === 0 && s.input.value !== 0 ? s.input.value : null,
      outputIfIndex: s.output.format === 0 && s.output.value !== 0 ? s.output.value : null,
      dropped: s.output.format === 1,
      frameLength: raw?.frameLength ?? eth?.frameLength ?? null,
      headerProtocol: raw?.protocol ?? null,
      header: raw?.header ?? null,
    });
  }
  return out;
}
