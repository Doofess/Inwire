/**
 * sFlow version 5 (UDP 6343): what a switch or router sends a collector about
 * the traffic through it - one packet in N sampled, and every interface's
 * counters every few seconds. The decode is `flow/sflow.ts`, which a collector
 * reads without a tree; this draws that decode as the reference draws it.
 *
 * Shapes taken from `tshark -T pdml` on datagrams built for every branch below
 * (`scripts/sflow/dissect.ts`), including the reference's quirks:
 *
 * - Its fields live under three prefixes, `sflow_245.`, `sflow_5.` and
 *   `sflow.`, by the version that introduced each; a counter record's length
 *   is `sflow_5.flow_data_length`, "Flow data length", like a flow record's.
 * - A gateway record's communities are drawn as `sflow_245.dstAS` rows, "AS
 *   Destination", under the community count.
 * - A record of a format it does not know is "Unknown sample format" when the
 *   enterprise is sFlow's own, and "Unknown enterprise format" otherwise, with
 *   no format or length row.
 * - The RFC 1349 cost bit reads "Minimize Monetary" when set and "Normal"
 *   when not, beside delay's "Low" and throughput's "High".
 *
 * **Two deliberate differences.** A SAMPLE from another enterprise is skipped
 * by its declared length here, and the samples after it are read; the
 * reference reads its enterprise word and calls the rest of the datagram
 * malformed. And a sampled header is bytes here. The reference
 * dissects it as a frame of its own, Ethernet and IP and TCP nested inside the
 * sFlow tree - and in doing so assigns those protocols' stream indexes, so a
 * sampled TCP header from another network becomes stream 0 of this capture.
 * Doing that here would put a stranger's segments into this capture's TCP
 * trackers. The bytes are the reference's own `sflow_245.header` row, and
 * `flow/sflow.ts` hands them, copied, to anything that wants to read them.
 */
import type { ProtocolField } from '../../types/packet';
import type { LeafResult } from './dispatch';
import { formatIpv4Address, formatIpv6Address, formatMac } from '../addressFormat';
import { hexColons } from '../dissect/hexBytes';
import { describeIpProtocol } from '../dissect/ipProtocolNames';
import { describeEtherType } from './linkLayer';
import {
  decodeSflow, SFLOW_PORT,
  type Address, type CounterRecord, type FlowRecord, type SflowSample, type Tagged,
} from '../flow/sflow';
import {
  AS_PATH_TYPES, COUNTER_RECORD_FORMATS, DISCARD_REASONS, FLOW_RECORD_FORMATS, HEADER_PROTOCOLS,
  IF_DIRECTIONS, OUTPUT_FORMATS, PRECEDENCES, SAMPLE_TYPES,
} from './sflowNames';

export { SFLOW_PORT };

type Fields = Record<string, string | number>;

const named = (table: Readonly<Record<number, string>>, n: number) => `${table[n] ?? 'Unknown'} (${n})`;
/** A field of a 32-bit word, counted from its most significant bit. */
const bits = (bitOffset: number, bitLength: number) => ({ bitOffset, bitLength, totalBits: 32 });
const span = (at: number, n: number): [number, number] => [at, at + n - 1];
const setText = (on: boolean) => (on ? 'Set' : 'Not set');

/** `unsigned_time_secs_to_str`: "1 day, 2 hours, 3 minutes, 4 seconds", zero parts left out. */
function durationText(seconds: number): string {
  if (seconds === 0) return '0 seconds';
  const parts: string[] = [];
  const add = (n: number, unit: string) => { if (n > 0) parts.push(`${n} ${unit}${n === 1 ? '' : 's'}`); };
  add(Math.floor(seconds / 86400), 'day');
  add(Math.floor((seconds % 86400) / 3600), 'hour');
  add(Math.floor((seconds % 3600) / 60), 'minute');
  add(seconds % 60, 'second');
  return parts.join(', ');
}

/** A plain number row over one 32-bit word. */
function u32Row(name: string, abbrev: string, at: number, value: number | string): ProtocolField {
  return { name, value, abbrev, rawBytesRange: span(at, 4) };
}
function u64Row(name: string, abbrev: string, at: number, value: bigint): ProtocolField {
  return { name, value: value.toString(), abbrev, rawBytesRange: span(at, 8) };
}

/** Records the first value under an abbrev; a datagram carries many samples and the bag holds one. */
function first(fields: Fields, abbrev: string, value: string | number | bigint): void {
  if (!(abbrev in fields)) fields[abbrev] = typeof value === 'bigint' ? Number(value) : value;
}

/** The enterprise and format words every sample and record opens with. */
function tagRows(t: Tagged, formatAbbrev: string, formatName: string, formatValue: string, lengthAbbrev: string, lengthName: string): ProtocolField[] {
  return [
    { name: 'Enterprise', value: 'standard sFlow (0)', abbrev: 'sflow.enterprise', rawBytesRange: span(t.at, 4), bitfield: bits(0, 20) },
    { name: formatName, value: formatValue, abbrev: formatAbbrev, rawBytesRange: span(t.at, 4), bitfield: bits(20, 12) },
    u32Row(lengthName, lengthAbbrev, t.at + 4, t.length),
  ];
}

/** A sample or record from another enterprise: the reference shows its number, length and bytes. */
function enterpriseRow(b: Uint8Array, t: Tagged): ProtocolField {
  return {
    name: 'Unknown enterprise format', value: '', rawBytesRange: [t.at, Math.max(t.at, t.end - 1)],
    children: [
      { name: 'Enterprise', value: `Non-standard sFlow (${t.enterprise})`, abbrev: 'sflow.enterprise', rawBytesRange: span(t.at, 4), bitfield: bits(0, 20) },
      u32Row('Length', 'sflow.enterprise.length', t.at + 4, t.length),
      { name: 'Data', value: hexColons(b, t.bodyAt, t.end), abbrev: 'sflow.enterprise.data', rawBytesRange: [t.bodyAt, Math.max(t.bodyAt, t.end - 1)] },
    ],
  };
}

/** A standard-enterprise record of a format the reference does not read: its bytes and a note. */
function unknownFormatRows(b: Uint8Array, t: Tagged): ProtocolField[] {
  const note = 'Unknown/invalid record type';
  return [{
    name: 'Data', value: hexColons(b, t.bodyAt, t.end), abbrev: 'sflow.enterprise.data', rawBytesRange: [t.bodyAt, Math.max(t.bodyAt, t.end - 1)],
    children: [{ name: note, value: '', abbrev: 'sflow.unknown_record_format', generated: true, expertInfo: { category: 'Note', message: note } }],
  }];
}

function addressText(a: Address): string {
  return a.type === 1 ? formatIpv4Address(a.bytes, 0) : formatIpv6Address(a.bytes, 0);
}
function nextHopRow(a: Address | null): ProtocolField[] {
  if (a === null) return [];
  const v6 = a.type === 2;
  return [{ name: 'Next hop', value: addressText(a), abbrev: v6 ? 'sflow_245.nexthop.v6' : 'sflow_245.nexthop', rawBytesRange: span(a.at + 4, v6 ? 16 : 4) }];
}

const TCP_FLAGS: readonly [string, string, number][] = [
  ['sflow_245.ip.tcp_flag.cwr', 'TCP Flag (CWR)', 0x80],
  ['sflow_245.ip.tcp_flag.ece', 'TCP Flag (ECE)', 0x40],
  ['sflow_245.ip.tcp_flag.urg', 'TCP Flag (URG)', 0x20],
  ['sflow_245.ip.tcp_flag.ack', 'TCP Flag (ACK)', 0x10],
  ['sflow_245.ip.tcp_flag.psh', 'TCP Flag (PSH)', 0x08],
  ['sflow_245.ip.tcp_flag.rst', 'TCP Flag (RST)', 0x04],
  ['sflow_245.ip.tcp_flag.syn', 'TCP Flag (SYN)', 0x02],
  ['sflow_245.ip.tcp_flag.fin', 'TCP Flag (FIN)', 0x01],
];
/** RFC 1349's TOS bits under the precedence: each with the word it reads when set. */
const TOS_BITS: readonly [string, string, number, string][] = [
  ['sflow_245.ipv4_delay', 'Delay', 0x10, 'Low'],
  ['sflow_245.ipv4_throughput', 'Throughput', 0x08, 'High'],
  ['sflow_245.ipv4_reliability', 'Reliability', 0x04, 'High'],
  ['sflow_245.ipv4_cost', 'Cost (RFC1349)', 0x02, 'Minimize Monetary'],
];
const bitOf = (mask: number) => 31 - Math.log2(mask);

function flowRecordRows(b: Uint8Array, r: FlowRecord, fields: Fields): ProtocolField {
  if (r.enterprise !== 0) return enterpriseRow(b, r);
  const known = FLOW_RECORD_FORMATS[r.format] !== undefined && r.kind !== 'unknown';
  const rows = tagRows(r, 'sflow_245.flow_record_format', 'Format', named(FLOW_RECORD_FORMATS, r.format), 'sflow_5.flow_data_length', 'Flow data length (byte)');
  const at = r.bodyAt;
  switch (r.kind) {
    case 'rawHeader':
      first(fields, 'sflow_245.header_protocol', r.protocol);
      rows.push(
        u32Row('Header protocol', 'sflow_245.header_protocol', at, named(HEADER_PROTOCOLS, r.protocol)),
        u32Row('Frame Length', 'sflow_245.header.frame_length', at + 4, r.frameLength),
        u32Row('Payload stripped', 'sflow_245.header.payload_stripped', at + 8, r.stripped),
        u32Row('Sampled header length', 'sflow_245.header.sampled_header_length', at + 12, r.header.length),
        { name: 'Header of sampled packet', value: hexColons(r.header, 0, r.header.length), abbrev: 'sflow_245.header', rawBytesRange: [r.headerAt, Math.max(r.headerAt, r.headerAt + r.header.length - 1)] },
      );
      break;
    case 'ethernet':
      rows.push(
        u32Row('Length of MAC Packet', 'sflow_245.ethernet.length', at, r.frameLength),
        { name: 'Source MAC Address', value: formatMac(r.src), abbrev: 'sflow_245.ethernet.source_mac_address', rawBytesRange: span(at + 4, 6) },
        { name: 'Destination MAC Address', value: formatMac(r.dst), abbrev: 'sflow_245.ethernet.destination_mac_address', rawBytesRange: span(at + 12, 6) },
        u32Row('Ethernet Packet Type', 'sflow_245.ethernet.packet_type', at + 20, `${describeEtherType(r.etherType)} (0x${r.etherType.toString(16).padStart(8, '0')})`),
      );
      break;
    case 'ipv4': case 'ipv6': {
      const v6 = r.kind === 'ipv6';
      const n = v6 ? 16 : 4;
      const text = (x: Uint8Array) => (v6 ? formatIpv6Address(x, 0) : formatIpv4Address(x, 0));
      const after = at + 8 + 2 * n;
      first(fields, 'sflow.ip_protocol', r.protocol);
      rows.push(
        u32Row('Length of IP Packet', 'sflow_245.ip.length', at, r.ipLength),
        u32Row('IP Protocol', 'sflow.ip_protocol', at + 4, describeIpProtocol(r.protocol)),
        { name: 'Source IP address', value: text(r.src), abbrev: v6 ? 'sflow_245.ipv6_src' : 'sflow_245.ipv4_src', rawBytesRange: span(at + 8, n) },
        { name: 'Destination IP address', value: text(r.dst), abbrev: v6 ? 'sflow_245.ipv6_dst' : 'sflow_245.ipv4_dst', rawBytesRange: span(at + 8 + n, n) },
        u32Row('Source Port', 'sflow_245.ip.source_port', after, r.srcPort),
        u32Row('Destination Port', 'sflow.ip.destination_port', after + 4, r.dstPort),
        ...TCP_FLAGS.map(([abbrev, name, mask]): ProtocolField => ({
          name, value: setText((r.tcpFlags & mask) !== 0), abbrev, rawBytesRange: span(after + 8, 4), bitfield: bits(bitOf(mask), 1),
        })),
      );
      if (v6) {
        rows.push(u32Row('Priority', 'sflow_245.ipv6_priority', after + 12, r.tos));
      } else {
        rows.push(
          { name: 'Precedence', value: named(PRECEDENCES, (r.tos >> 5) & 7), abbrev: 'sflow_245.ipv4_precedence_type', rawBytesRange: span(after + 12, 4), bitfield: bits(24, 3) },
          ...TOS_BITS.map(([abbrev, name, mask, word]): ProtocolField => ({
            name, value: (r.tos & mask) !== 0 ? word : 'Normal', abbrev, rawBytesRange: span(after + 12, 4), bitfield: bits(bitOf(mask), 1),
          })),
        );
      }
      break;
    }
    case 'switch':
      first(fields, 'sflow_245.vlan.in', r.srcVlan);
      first(fields, 'sflow_245.vlan.out', r.dstVlan);
      rows.push(
        u32Row('Incoming 802.1Q VLAN', 'sflow_245.vlan.in', at, r.srcVlan),
        u32Row('Incoming 802.1p priority', 'sflow_245.pri.in', at + 4, r.srcPriority),
        u32Row('Outgoing 802.1Q VLAN', 'sflow_245.vlan.out', at + 8, r.dstVlan),
        u32Row('Outgoing 802.1p priority', 'sflow_245.pri.out', at + 12, r.dstPriority),
      );
      break;
    case 'router': {
      const after = r.nextHop === null ? at + 4 : r.nextHop.at + 4 + r.nextHop.bytes.length;
      rows.push(
        ...nextHopRow(r.nextHop),
        u32Row('Next hop source mask', 'sflow_245.nexthop.src_mask', after, r.srcMask),
        u32Row('Next hop destination mask', 'sflow_245.nexthop.dst_mask', after + 4, r.dstMask),
      );
      break;
    }
    case 'gateway': {
      let p = r.nextHop === null ? at + 4 : r.nextHop.at + 4 + r.nextHop.bytes.length;
      rows.push(
        ...nextHopRow(r.nextHop),
        u32Row('AS Router', 'sflow_245.as', p, r.as),
        u32Row('AS Source', 'sflow_245.srcAS', p + 4, r.srcAs),
        u32Row('AS Peer', 'sflow_245.peerAS', p + 8, r.srcPeerAs),
        u32Row('AS Destinations', 'sflow_245.dstASentries', p + 12, r.asPath.length),
      );
      for (const seg of r.asPath) {
        rows.push({
          name: `${AS_PATH_TYPES[seg.type] ?? 'Unknown AS type'}, (${seg.asns.length} entries)`, value: '', abbrev: 'sflow.as_type',
          rawBytesRange: span(seg.at, 8 + 4 * seg.asns.length),
          children: seg.asns.map((asn, k) => u32Row('AS Destination', 'sflow_245.dstAS', seg.at + 8 + 4 * k, asn)),
        });
        p = seg.at + 8 + 4 * seg.asns.length;
      }
      if (r.asPath.length === 0) p += 16;
      rows.push(
        {
          ...u32Row('Gateway Communities', 'sflow_245.communityEntries', p, r.communities.length),
          children: r.communities.map((c, k) => u32Row('AS Destination', 'sflow_245.dstAS', p + 4 + 4 * k, c)),
        },
        u32Row('localpref', 'sflow_245.localpref', p + 4 + 4 * r.communities.length, r.localPref),
      );
      break;
    }
    case 'unknown':
      rows.push(...unknownFormatRows(b, r));
      break;
  }
  return { name: known ? FLOW_RECORD_FORMATS[r.format] : 'Unknown sample format', value: '', rawBytesRange: [r.at, Math.max(r.at, r.end - 1)], children: rows };
}

const DOT3: readonly [string, string][] = [
  ['sflow_245.dot3StatsAlignmentErrors', 'Alignment Errors'],
  ['sflow_245.dot3StatsFCSErrors', 'FCS Errors'],
  ['sflow_245.dot3StatsSingleCollisionFrames', 'Single Collision Frames'],
  ['sflow_245.dot3StatsMultipleCollisionFrames', 'Multiple Collision Frames'],
  ['sflow_245.dot3StatsSQETestErrors', 'SQE Test Errors'],
  ['sflow_245.dot3StatsDeferredTransmissions', 'Deferred Transmissions'],
  ['sflow_245.dot3StatsLateCollisions', 'Late Collisions'],
  ['sflow_245.dot3StatsExcessiveCollisions', 'Excessive Collisions'],
  ['sflow_245.dot3StatsInternalMacTransmitErrors', 'Internal Mac Transmit Errors'],
  ['sflow_245.dot3StatsCarrierSenseErrors', 'Carrier Sense Errors'],
  ['sflow_245.dot3StatsFrameTooLongs', 'Frame Too Longs'],
  ['sflow_245.dot3StatsInternalMacReceiveErrors', 'Internal Mac Receive Errors'],
  ['sflow_245.dot3StatsSymbolErrors', 'Symbol Errors'],
];

function counterRecordRows(b: Uint8Array, r: CounterRecord, fields: Fields): ProtocolField {
  if (r.enterprise !== 0) return enterpriseRow(b, r);
  const known = COUNTER_RECORD_FORMATS[r.format] !== undefined && r.kind !== 'unknown';
  const rows = tagRows(r, 'sflow_245.counters_record_format', 'Format', named(COUNTER_RECORD_FORMATS, r.format), 'sflow_5.flow_data_length', 'Flow data length (byte)');
  const at = r.bodyAt;
  switch (r.kind) {
    case 'generic':
      first(fields, 'sflow_245.ifindex', r.ifIndex);
      first(fields, 'sflow_245.ifspeed', r.ifSpeed);
      first(fields, 'sflow_245.ifinoct', r.inOctets);
      first(fields, 'sflow_245.ifoutoct', r.outOctets);
      first(fields, 'sflow_245.ifinerr', r.inErrors);
      first(fields, 'sflow_245.ifouterr', r.outErrors);
      first(fields, 'sflow_245.ifindisc', r.inDiscards);
      first(fields, 'sflow_245.ifoutdisc', r.outDiscards);
      rows.push(
        u32Row('Interface index', 'sflow_245.ifindex', at, r.ifIndex),
        u32Row('Interface Type', 'sflow_245.iftype', at + 4, r.ifType),
        u64Row('Interface Speed', 'sflow_245.ifspeed', at + 8, r.ifSpeed),
        u32Row('Interface Direction', 'sflow_245.ifdirection', at + 16, named(IF_DIRECTIONS, r.ifDirection)),
        { name: 'IfAdminStatus', value: (r.ifStatus & 1) !== 0 ? 'Up' : 'Down', abbrev: 'sflow_245.ifadmin_status', rawBytesRange: span(at + 20, 4), bitfield: bits(31, 1) },
        { name: 'IfOperStatus', value: (r.ifStatus & 2) !== 0 ? 'Up' : 'Down', abbrev: 'sflow_245.ifoper_status', rawBytesRange: span(at + 20, 4), bitfield: bits(30, 1) },
        u64Row('Input Octets', 'sflow_245.ifinoct', at + 24, r.inOctets),
        u32Row('Input Packets', 'sflow_245.ifinpkt', at + 32, r.inUcastPkts),
        u32Row('Input Multicast Packets', 'sflow_245.ifinmcast', at + 36, r.inMulticastPkts),
        u32Row('Input Broadcast Packets', 'sflow_245.ifinbcast', at + 40, r.inBroadcastPkts),
        u32Row('Input Discarded Packets', 'sflow_245.ifindisc', at + 44, r.inDiscards),
        u32Row('Input Errors', 'sflow_245.ifinerr', at + 48, r.inErrors),
        u32Row('Input Unknown Protocol Packets', 'sflow_245.ifinunk', at + 52, r.inUnknownProtos),
        u64Row('Output Octets', 'sflow_245.ifoutoct', at + 56, r.outOctets),
        u32Row('Output Packets', 'sflow_245.ifoutpkt', at + 64, r.outUcastPkts),
        u32Row('Output Multicast Packets', 'sflow_245.ifoutmcast', at + 68, r.outMulticastPkts),
        u32Row('Output Broadcast Packets', 'sflow_245.ifoutbcast', at + 72, r.outBroadcastPkts),
        u32Row('Output Discarded Packets', 'sflow_245.ifoutdisc', at + 76, r.outDiscards),
        u32Row('Output Errors', 'sflow_245.ifouterr', at + 80, r.outErrors),
        u32Row('Promiscuous Mode', 'sflow_245.ifpromisc', at + 84, r.promiscuous),
      );
      break;
    case 'ethernet':
      rows.push(...DOT3.map(([abbrev, name], i) => u32Row(name, abbrev, at + 4 * i, r.values[i])));
      break;
    case 'vlan':
      rows.push(
        u32Row('VLAN ID', 'sflow_245.vlan_id', at, r.vlanId),
        u64Row('Octets', 'sflow_245.octets', at + 4, r.octets),
        u32Row('Unicast Packets', 'sflow_245.ucastPkts', at + 12, r.ucastPkts),
        u32Row('Multicast Packets', 'sflow_245.multicastPkts', at + 16, r.multicastPkts),
        u32Row('Broadcast Packets', 'sflow_245.broadcastPkts', at + 20, r.broadcastPkts),
        u32Row('Discards', 'sflow_245.discards', at + 24, r.discards),
      );
      break;
    case 'processor':
      rows.push(
        u32Row('5s CPU Load (100 = 1%)', 'sflow_5.cpu_5s', at, r.cpu5s),
        u32Row('1m CPU Load (100 = 1%)', 'sflow_5.cpu_1m', at + 4, r.cpu1m),
        u32Row('5m CPU Load (100 = 1%)', 'sflow_5.cpu_5m', at + 8, r.cpu5m),
        u64Row('Total Memory', 'sflow_5.total_memory', at + 12, r.totalMemory),
        u64Row('Free Memory', 'sflow_5.free_memory', at + 20, r.freeMemory),
      );
      break;
    case 'unknown':
      rows.push(...unknownFormatRows(b, r));
      break;
  }
  return { name: known ? COUNTER_RECORD_FORMATS[r.format] : 'Unknown sample format', value: '', rawBytesRange: [r.at, Math.max(r.at, r.end - 1)], children: rows };
}

/** The source ID: one word split 8/24 in a compact sample, two words in an expanded one. */
function sourceRows(prefix: 'flow_sample' | 'counters_sample', s: { expanded: boolean; sourceIdType: number; sourceIdIndex: number }, at: number): ProtocolField[] {
  if (s.expanded) {
    return prefix === 'flow_sample'
      ? [u32Row('Source ID type', 'sflow.flow_sample.source_id_type', at, s.sourceIdType), u32Row('Source ID index', 'sflow.flow_sample.source_id_index', at + 4, s.sourceIdIndex)]
      : [u32Row('Source ID type', 'sflow.counters_sample.source_id_type', at, s.sourceIdType), u32Row('Source ID index', 'sflow.counters_sample.source_id_index', at + 4, s.sourceIdIndex)];
  }
  return prefix === 'flow_sample'
    ? [
      { name: 'Source ID class', value: s.sourceIdType, abbrev: 'sflow.flow_sample.source_id_class', rawBytesRange: span(at, 4), bitfield: bits(0, 8) },
      { name: 'Index', value: s.sourceIdIndex, abbrev: 'sflow.flow_sample.index', rawBytesRange: span(at, 4), bitfield: bits(8, 24) },
    ]
    : [
      { name: 'Source ID type', value: s.sourceIdType, abbrev: 'sflow.counters_sample.source_id_type', rawBytesRange: span(at, 4), bitfield: bits(0, 8) },
      { name: 'Source ID index', value: s.sourceIdIndex, abbrev: 'sflow.counters_sample.source_id_index', rawBytesRange: span(at, 4), bitfield: bits(8, 24) },
    ];
}

function sampleRows(b: Uint8Array, s: SflowSample, fields: Fields): ProtocolField {
  if (s.enterprise !== 0) return enterpriseRow(b, s);
  const range: [number, number] = [s.at, Math.max(s.at, s.end - 1)];
  const rows = tagRows(s, 'sflow_245.sampletype', 'sFlow sample type', named(SAMPLE_TYPES, s.format), 'sflow_5.sample_length', 'Sample length (byte)');
  first(fields, 'sflow_245.sampletype', s.format);
  if (s.kind === 'unknown') return { name: 'Unknown sample format', value: '', rawBytesRange: range, children: rows };

  let at = s.bodyAt;
  if (s.kind === 'flow') {
    first(fields, 'sflow.flow_sample.sampling_rate', s.samplingRate);
    rows.push(u32Row('Sequence number', 'sflow.flow_sample.sequence_number', at, s.sequence), ...sourceRows('flow_sample', s, at + 4));
    at += s.expanded ? 12 : 8;
    rows.push(
      u32Row('Sampling rate', 'sflow.flow_sample.sampling_rate', at, `1 out of ${s.samplingRate} packets`),
      u32Row('Sample pool', 'sflow.flow_sample.sample_pool', at + 4, `${s.samplePool} total packets`),
      u32Row('Dropped packets', 'sflow.flow_sample.dropped_packets', at + 8, s.drops),
    );
    at += 12;
    if (s.expanded) {
      const out = s.output;
      const outValue: ProtocolField = out.format === 0 ? u32Row('Output interface ifIndex', 'sflow.flow_sample.output_interface_expanded.ifindex', at + 12, out.value)
        : out.format === 1 ? u32Row('Output interface packet discarded', 'sflow.flow_sample.output_interface_expanded.value_discarded', at + 12, named(DISCARD_REASONS, out.value))
          : out.format === 2 ? u32Row('Output inferface number of interfaces', 'sflow.flow_sample.output_interface_expanded.number', at + 12, out.value)
            : u32Row('Output interface expanded value', 'sflow.flow_sample.output_interface_expanded.value', at + 12, out.value);
      rows.push(
        u32Row('Input interface format', 'sflow.flow_sample.input_interface_format', at, s.input.format),
        u32Row('Input interface value', 'sflow.flow_sample.input_interface_value', at + 4, s.input.value),
        u32Row('Output interface expanded format', 'sflow.flow_sample.output_interface.expanded.format', at + 8, named(OUTPUT_FORMATS, out.format)),
        outValue,
      );
      at += 16;
    } else {
      first(fields, 'sflow.flow_sample.input_interface', s.input.value);
      const word = ((s.output.format << 30) | s.output.value) >>> 0;
      rows.push(
        u32Row('Input interface (ifIndex)', 'sflow.flow_sample.input_interface', at, s.input.value),
        {
          name: 'Output interface', value: `0x${word.toString(16).padStart(8, '0')}`, abbrev: 'sflow.flow_sample.output_interface', rawBytesRange: span(at + 4, 4),
          children: [
            { name: 'Output interface format', value: named(OUTPUT_FORMATS, s.output.format), abbrev: 'sflow.flow_sample.output_interface_format', rawBytesRange: span(at + 4, 4), bitfield: bits(0, 2) },
            {
              name: 'Output interface value', value: s.output.format === 1 ? named(DISCARD_REASONS, s.output.value) : s.output.value,
              abbrev: 'sflow.flow_sample.output_interface_value', rawBytesRange: span(at + 4, 4), bitfield: bits(2, 30),
            },
          ],
        },
      );
      at += 8;
    }
    rows.push(u32Row('Flow record', 'sflow.flow_sample.flow_record', at, s.recordCount));
    for (const r of s.records) rows.push(flowRecordRows(b, r, fields));
    return { name: `${s.expanded ? 'Expanded flow sample' : 'Flow sample'}, seq ${s.sequence}`, value: '', rawBytesRange: range, children: rows };
  }

  rows.push(u32Row('Sequence number', 'sflow.counters_sample.sequence_number', at, s.sequence), ...sourceRows('counters_sample', s, at + 4));
  at += s.expanded ? 12 : 8;
  rows.push(u32Row('Counters records', 'sflow.counters_sample.counters_records', at, s.recordCount));
  for (const r of s.records) rows.push(counterRecordRows(b, r, fields));
  return { name: `${s.expanded ? 'Expanded counters sample' : 'Counters sample'}, seq ${s.sequence}`, value: '', rawBytesRange: range, children: rows };
}

export function dissectSflow(b: Uint8Array, start: number, end: number): LeafResult | null {
  const d = decodeSflow(b, start, end);
  if (d === null || d.agent === null) return null;
  const v6 = d.agent.v6;
  const agent = v6 ? formatIpv6Address(d.agent.address, 0) : formatIpv4Address(d.agent.address, 0);
  const fields: Fields = {
    'sflow_245.version': d.version,
    'sflow_245.agenttype': d.agentType,
    [v6 ? 'sflow_245.agent.v6' : 'sflow_245.agent']: agent,
    'sflow_245.sub_agent_id': d.subAgentId,
    'sflow_245.sequence_number': d.sequence,
    'sflow_245.sysuptime': d.uptimeMs,
    'sflow_245.numsamples': d.sampleCount,
  };
  const n = v6 ? 16 : 4;
  const rows: ProtocolField[] = [
    u32Row('Datagram version', 'sflow_245.version', start, d.version),
    u32Row('Agent address type', 'sflow_245.agenttype', start + 4, named({ 1: 'IPv4', 2: 'IPv6' }, d.agentType)),
    { name: 'Agent address', value: agent, abbrev: v6 ? 'sflow_245.agent.v6' : 'sflow_245.agent', rawBytesRange: span(start + 8, n) },
    u32Row('Sub-agent ID', 'sflow_245.sub_agent_id', start + 8 + n, d.subAgentId),
    u32Row('Sequence number', 'sflow_245.sequence_number', start + 12 + n, d.sequence),
    u32Row('SysUptime', 'sflow_245.sysuptime', start + 16 + n, `${durationText(Math.floor(d.uptimeMs / 1000))} (${d.uptimeMs}ms)`),
    u32Row('NumSamples', 'sflow_245.numsamples', start + 20 + n, d.sampleCount),
    ...d.samples.map((s) => sampleRows(b, s, fields)),
  ];
  const info = `V5, agent ${agent}, sub-agent ID ${d.subAgentId}, seq ${d.sequence}, ${d.sampleCount} samples`;
  return {
    protocolLabel: 'sFlow',
    info,
    layer: { name: 'InMon sFlow', summary: info, fields: rows, rawBytesRange: [start, end - 1] },
    fields,
  };
}
