/**
 * sFlow v5 datagrams built field by field from sflow_version_5.txt, for
 * `scripts/sflow/dissect.ts`. Every field is written out, so a case reads as
 * the spec's XDR structure rather than as a call to a helper that could be
 * wrong in the same way the dissector is.
 *
 * Exports only: a helper, not a test.
 */
import { Bytes, udpFrameTo, ethernet, ipv4 } from '../parity/synthetic';

export const SFLOW_PORT = 6343;
export const AGENT = '10.0.0.1';
export const COLLECTOR = '10.0.0.9';

/** An XDR opaque: the bytes, padded to four. */
const opaque = (bytes: ArrayLike<number>) => {
  const b = new Bytes().raw(bytes);
  while (b.length % 4 !== 0) b.u8(0);
  return b.build();
};
const u64 = (b: Bytes, v: bigint) => b.u32(Number((v >> 32n) & 0xffffffffn), Number(v & 0xffffffffn));

/** A record or sample: its format word (enterprise << 12 | format), length, body. */
const tlv = (enterprise: number, format: number, body: Uint8Array) =>
  new Bytes().u32(((enterprise << 12) | format) >>> 0).u32(body.length).raw(body).build();

/** The datagram header, then the samples. */
function datagram(samples: Uint8Array[], options: { v6?: boolean; sequence?: number; uptime?: number } = {}): Uint8Array {
  const b = new Bytes().u32(5);
  if (options.v6 === true) b.u32(2).u16(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
  else b.u32(1).ipv4(AGENT);
  b.u32(0).u32(options.sequence ?? 42).u32(options.uptime ?? 3_600_123).u32(samples.length);
  for (const s of samples) b.raw(s);
  return b.build();
}

// --- flow records -----------------------------------------------------------

/** A sampled Ethernet/IPv4/TCP frame's first bytes, as an agent copies them. */
export function sampledFrame(): Uint8Array {
  const tcp = new Bytes().u16(51515, 443).u32(1000, 2000).u8(0x50, 0x18).u16(64240, 0, 0).build();
  return Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(6, Uint8Array.from([...tcp, ...new Array(20).fill(0x61)]), '192.0.2.10', '198.51.100.7')]);
}

export const rawHeader = (protocol: number, frameLength: number, stripped: number, header: Uint8Array) =>
  tlv(0, 1, new Bytes().u32(protocol, frameLength, stripped, header.length).raw(opaque(header)).build());

const ethernetData = () => tlv(0, 2, new Bytes().u32(1514)
  .mac('00:00:5e:00:53:01').u16(0).mac('00:00:5e:00:53:02').u16(0).u32(0x0800).build());

const ipv4Data = (tcpFlags = 0x12, tos = 0x10) => tlv(0, 3, new Bytes().u32(1500, 6).ipv4('192.0.2.10').ipv4('198.51.100.7')
  .u32(51515, 443, tcpFlags, tos).build());

const ipv6Data = () => tlv(0, 4, new Bytes().u32(1280, 17)
  .u16(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x10).u16(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x20)
  .u32(5353, 53, 0, 3).build());

const extendedSwitch = () => tlv(0, 1001, new Bytes().u32(10, 3, 20, 5).build());

const extendedRouter = (v6 = false) => {
  const b = new Bytes();
  if (v6) b.u32(2).u16(0xfe80, 0, 0, 0, 0, 0, 0, 1);
  else b.u32(1).ipv4('192.0.2.1');
  return tlv(0, 1002, b.u32(24, 16).build());
};

const extendedGateway = () => tlv(0, 1003, new Bytes().u32(1).ipv4('192.0.2.254')
  .u32(64500, 64501, 64502)
  // two AS path segments: an AS_SEQUENCE of two, an AS_SET of one
  .u32(2).u32(2, 2, 64510, 64511).u32(1, 1, 64520)
  .u32(2, 0xfde80001, 0xfde80002).u32(100).build());

const unknownRecord = (enterprise: number, format: number) => tlv(enterprise, format, new Bytes().u32(0xdeadbeef, 7).build());

// --- counter records --------------------------------------------------------

export const genericInterface = (direction = 1, status = 3) => {
  const b = new Bytes().u32(7, 6);
  u64(b, 1_000_000_000n);
  b.u32(direction, status);
  u64(b, 123_456_789_012n);
  b.u32(1000, 20, 30, 4, 5, 6);
  u64(b, 98_765_432_109n);
  b.u32(2000, 40, 50, 7, 8, 1);
  return tlv(0, 1, b.build());
};
const ethernetCounters = () => tlv(0, 2, new Bytes().u32(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13).build());
const vlanCounters = () => {
  const b = new Bytes().u32(100);
  u64(b, 5_000_000n);
  return tlv(0, 5, b.u32(4000, 300, 20, 1).build());
};
const processorCounters = () => {
  const b = new Bytes().u32(1234, 2345, 3456);
  u64(b, 8_589_934_592n);
  u64(b, 4_294_967_296n);
  return tlv(0, 1001, b.build());
};

// --- samples ----------------------------------------------------------------

const flowSample = (records: Uint8Array[], sourceId = 0x00000007, output = 9) => tlv(0, 1, new Bytes()
  .u32(17, sourceId, 1000, 170_000, 3, 7, output, records.length).raw(records.flatMap((r) => [...r])).build());

const expandedFlowSample = (records: Uint8Array[], outputFormat = 0, output = 9) => tlv(0, 3, new Bytes()
  .u32(18, 0, 12, 512, 51_200, 0, 0, 12, outputFormat, output, records.length).raw(records.flatMap((r) => [...r])).build());

const counterSample = (records: Uint8Array[]) => tlv(0, 2, new Bytes()
  .u32(5, 0x00000007, records.length).raw(records.flatMap((r) => [...r])).build());

const expandedCounterSample = (records: Uint8Array[]) => tlv(0, 4, new Bytes()
  .u32(6, 0, 100, records.length).raw(records.flatMap((r) => [...r])).build());

const toCollector = (payload: Uint8Array) => udpFrameTo(AGENT, COLLECTOR, 50001, SFLOW_PORT, payload);

/** One case per frame; the shape `treeOracle.ts` takes, written here so `check.ts` does not run this file. */
export const cases: { label: string; frame: Uint8Array }[] = [
  { label: 'a flow sample carrying a sampled frame and the switch record', frame: toCollector(datagram([flowSample([rawHeader(1, 1514, 4, sampledFrame()), extendedSwitch()])])) },
  { label: 'a counter sample with interface and Ethernet counters', frame: toCollector(datagram([counterSample([genericInterface(), ethernetCounters()])])) },
  {
    label: 'an expanded flow sample with Ethernet, IPv4, IPv6 data and a router record',
    frame: toCollector(datagram([expandedFlowSample([ethernetData(), ipv4Data(), ipv6Data(), extendedRouter()])])),
  },
  { label: 'an expanded counter sample with VLAN and processor counters', frame: toCollector(datagram([expandedCounterSample([vlanCounters(), processorCounters()])])) },
  { label: 'an agent with an IPv6 address', frame: toCollector(datagram([flowSample([extendedRouter(true)])], { v6: true })) },
  { label: 'a gateway record with an AS path and communities', frame: toCollector(datagram([flowSample([extendedGateway()])])) },
  {
    label: 'record formats nobody names, standard and enterprise',
    frame: toCollector(datagram([flowSample([unknownRecord(0, 4000), unknownRecord(4413, 5)]), counterSample([unknownRecord(0, 4001), unknownRecord(9, 1)])])),
  },
  {
    label: 'two samples in one datagram, flow then counters',
    frame: toCollector(datagram([flowSample([extendedSwitch()], 0x01000003), counterSample([genericInterface()])], { sequence: 43 })),
  },
  { label: 'a datagram with no samples, half a second after boot', frame: toCollector(datagram([], { uptime: 500 })) },
  { label: 'a sample format nobody names', frame: toCollector(datagram([tlv(0, 77, new Bytes().u32(1, 2).build())])) },
  { label: 'a sampled IPv4 packet with no link header', frame: toCollector(datagram([flowSample([rawHeader(11, 60, 0, sampledFrame().slice(14, 54))])])) },
  { label: 'a dropped-output flow sample with multiple outputs', frame: toCollector(datagram([flowSample([extendedSwitch()], 7, 0x40000000), flowSample([extendedSwitch()], 7, 0x80000003)])) },
  {
    label: 'expanded samples whose packet was dropped, and sent out of several ports',
    frame: toCollector(datagram([expandedFlowSample([extendedSwitch()], 1, 258), expandedFlowSample([extendedSwitch()], 2, 4)], { uptime: 90_061_001 })),
  },
  { label: 'every TCP flag and TOS bit set', frame: toCollector(datagram([flowSample([ipv4Data(0xff, 0xfe)])])) },
  { label: 'an interface down, its direction unknown', frame: toCollector(datagram([counterSample([genericInterface(0, 0)])])) },
  { label: 'an expanded counter sample with a sub-agent and source class', frame: toCollector(datagram([expandedCounterSample([genericInterface()])], { uptime: 1000 })) },
];

/**
 * A sample from another enterprise before a standard one. Not a reference
 * case: tshark reads the enterprise word and calls the rest of the datagram
 * malformed, where this build skips the sample by its length.
 */
export const otherEnterprise = toCollector(datagram([tlv(4413, 1, new Bytes().u32(1, 2, 3).build()), counterSample([vlanCounters()])]));
