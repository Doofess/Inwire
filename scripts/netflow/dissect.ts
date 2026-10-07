/**
 * NetFlow v5, v9 and IPFIX against the reference, row for row.
 *
 *   npx tsx scripts/netflow/dissect.ts
 *
 * Every router, switch and firewall that reports traffic to a collector sends
 * one of these three, and neither fixture holds one - so they are built here
 * from Cisco's v5 layout, RFC 3954 and RFC 7011: headers, template and options
 * template sets, data read through a template defined in the same message and
 * in an earlier one, a template redefined (the reference keeps the first), a
 * withdrawal, enterprise and reverse elements, variable-length strings,
 * padding, a data set with no template, a set too short to walk, sequence
 * gaps, and one IPFIX record holding every element the generated table draws
 * plainly - so the table is checked against the reference, not trusted.
 *
 * Not compared: every absolute time (the header's timestamp, a flow's start
 * and end dates), which the reference writes in a zone name from Windows
 * ("Jerusalem Standard Time") and this build from the browser's locale data,
 * as `scripts/openvpn/dissect.ts` found; their dates are checked here instead.
 *
 * Then the flow records `flow/flowExport.ts` makes of the same messages -
 * what a bandwidth view would read - are checked by value.
 */
import { udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import { ELEMENTS } from '../../src/services/dissectors/cflowNames';
import { relativeTime } from '../../src/services/dissectors/cflow';
import { MemoryTemplateStore, normalizeFlows } from '../../src/services/flow/flowExport';

const u8 = (n: number) => [n & 255];
const u16 = (n: number) => [(n >> 8) & 255, n & 255];
const u32 = (n: number) => [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
const u64 = (n: bigint) => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(8 * (7 - i))) & 0xffn));
const ip = (s: string) => s.split('.').map(Number);
const ip6 = (s: string) => s.split(':').flatMap((g) => u16(parseInt(g, 16)));
const text = (s: string) => [...new TextEncoder().encode(s)];

// --- v5 ------------------------------------------------------------------------

function v5(records: number[][], o: { seq?: number; uptime?: number; secs?: number; nsecs?: number; engType?: number; engId?: number; sampling?: number } = {}) {
  return Uint8Array.from([
    ...u16(5), ...u16(records.length), ...u32(o.uptime ?? 3600000), ...u32(o.secs ?? 1700000000), ...u32(o.nsecs ?? 123456789),
    ...u32(o.seq ?? 1000), ...u8(o.engType ?? 0), ...u8(o.engId ?? 0), ...u16(o.sampling ?? 0), ...records.flat()]);
}
function v5rec(o: { src: string; dst: string; nh?: string; inp?: number; out?: number; pkts?: number; octets?: number; first?: number; last?: number; sport?: number; dport?: number; flags?: number; proto?: number; tos?: number; sas?: number; das?: number; smask?: number; dmask?: number }) {
  return [...ip(o.src), ...ip(o.dst), ...ip(o.nh ?? '0.0.0.0'), ...u16(o.inp ?? 1), ...u16(o.out ?? 2), ...u32(o.pkts ?? 10), ...u32(o.octets ?? 1500),
    ...u32(o.first ?? 3500000), ...u32(o.last ?? 3590000), ...u16(o.sport ?? 443), ...u16(o.dport ?? 51000), 0, ...u8(o.flags ?? 0x1b), ...u8(o.proto ?? 6), ...u8(o.tos ?? 0),
    ...u16(o.sas ?? 0), ...u16(o.das ?? 0), ...u8(o.smask ?? 24), ...u8(o.dmask ?? 16), 0, 0];
}

// --- v9 and IPFIX ----------------------------------------------------------------

/** A set: id, length, body padded to four bytes unless told not to. */
function set(id: number, body: number[], pad = true) {
  const padded = pad ? [...body, ...new Array((4 - ((body.length + 4) % 4)) % 4).fill(0)] : body;
  return [...u16(id), ...u16(4 + padded.length), ...padded];
}
function v9(sets: number[][], count: number, o: { uptime?: number; secs?: number; seq?: number; source?: number } = {}) {
  return Uint8Array.from([...u16(9), ...u16(count), ...u32(o.uptime ?? 3600000), ...u32(o.secs ?? 1700000000), ...u32(o.seq ?? 7), ...u32(o.source ?? 0), ...sets.flat()]);
}
function ipfix(sets: number[][], o: { time?: number; seq?: number; domain?: number } = {}) {
  const body = sets.flat();
  return Uint8Array.from([...u16(10), ...u16(16 + body.length), ...u32(o.time ?? 1700000000), ...u32(o.seq ?? 5), ...u32(o.domain ?? 1), ...body]);
}
/** A v9 template: id, count, (type, length)... */
const v9Template = (id: number, fields: [number, number][]) => [...u16(id), ...u16(fields.length), ...fields.flatMap(([t, l]) => [...u16(t), ...u16(l)])];
/** An IPFIX template field, an enterprise's when a PEN is given. */
const ie = (type: number, length: number, pen?: number) => (pen === undefined ? [...u16(type), ...u16(length)] : [...u16(type | 0x8000), ...u16(length), ...u32(pen)]);
const ipfixTemplate = (id: number, fields: number[][]) => [...u16(id), ...u16(fields.length), ...fields.flat()];

const ROUTER = '10.0.0.1';
const COLLECTOR = '10.0.0.9';
const netflow = (payload: Uint8Array, port = 2055, from = ROUTER) => udpFrameTo(from, COLLECTOR, 50000, port, payload);
const toIpfix = (payload: Uint8Array) => udpFrameTo(ROUTER, COLLECTOR, 50001, 4739, payload);

// The v9 template most exporters send, give or take: addresses, ports,
// protocol, flags, counters, switched times, interfaces, AS numbers, masks,
// direction, VLANs, sampling, end reason, forwarding status, ICMP and IPv6.
const V9_FIELDS: [number, number][] = [[8, 4], [12, 4], [7, 2], [11, 2], [4, 1], [6, 1], [5, 1], [1, 4], [2, 4], [22, 4], [21, 4], [10, 2], [14, 2],
  [15, 4], [16, 2], [17, 2], [9, 1], [13, 1], [61, 1], [58, 2], [59, 2], [34, 4], [35, 1], [136, 1], [89, 1], [60, 1], [32, 2], [27, 16], [28, 16]];
const v9Record = (src: string, octets: number) => [...ip(src), ...ip('8.8.8.8'), ...u16(51000), ...u16(443), 6, 0x1b, 0, ...u32(octets), ...u32(10),
  ...u32(3500000), ...u32(3590000), ...u16(3), ...u16(5), ...ip('10.0.0.254'), ...u16(64512), ...u16(15169), 24, 16, 1, ...u16(100), ...u16(200),
  ...u32(100), 2, 1, 0x40, 4, ...u16(0x0300), ...ip6('2001:db8:0:0:0:0:0:1'), ...ip6('2001:db8:0:0:0:0:0:2')];
// System and interface scopes, then the sampling interval.
const v9Options = [...u16(257), ...u16(8), ...u16(4), ...u16(1), ...u16(4), ...u16(2), ...u16(4), ...u16(34), ...u16(4)];
// Every special a v9 record has: flags in one byte and two, the forwarding
// status's three kinds, an application id, an ICMPv6 type and code, an MPLS
// label, a switched time pair split by other elements, and times with no pair.
const V9_SPECIALS: [number, number][] = [[6, 2], [89, 1], [89, 1], [89, 1], [95, 4], [139, 2], [70, 3], [22, 4], [7, 2], [21, 4], [161, 4], [162, 4], [151, 4], [152, 8], [600, 4]];
const v9Specials = [...u16(0x0b31), 0x41, 0x82, 0xc1, 3, 0, 0, 80, 1, 0, ...[0x01, 0x23, 0x45], ...u32(1000), ...u16(53), ...u32(61000), ...u32(90061001), ...u32(1500),
  ...u32(1700000005), ...u64(1700000000123n), ...[1, 2, 3, 4]];

// An IPFIX template with what v9 has not: 64-bit counters, millisecond wall
// clock times, a variable-length string, Cisco's and VMware's elements, a reverse element, and a standard number nobody has assigned.
const IPFIX_FIELDS = [ie(8, 4), ie(12, 4), ie(7, 2), ie(11, 2), ie(4, 1), ie(1, 8), ie(2, 8), ie(152, 8), ie(153, 8), ie(150, 4), ie(82, 0xffff),
  ie(100, 4, 9), ie(100, 4, 6876), ie(1, 8, 29305), ie(600, 4)];
const ipfixRecord = (name: string) => [...ip('192.168.1.10'), ...ip('8.8.8.8'), ...u16(51000), ...u16(443), 6, ...u64(1500n), ...u64(10n),
  ...u64(1700000000123n), ...u64(1700000005456n), ...u32(1700000000), name.length, ...text(name), ...u32(42), ...u32(7), ...u64(900n), ...u32(9)];
const longName = 'x'.repeat(300);
const ipfixLong = [...ip('192.168.1.11'), ...ip('1.1.1.1'), ...u16(5353), ...u16(53), 17, ...u64(80n), ...u64(1n),
  ...u64(1700000000000n), ...u64(1700000000000n), ...u32(1700000000), 255, ...u16(300), ...text(longName), ...u32(1), ...u32(2), ...u64(3n), ...u32(4)];
// Scope: the observation domain; then the sampling interval and algorithm.
const ipfixOptions = [...u16(258), ...u16(3), ...u16(1), ...ie(149, 4), ...ie(34, 4), ...ie(35, 1)];

/**
 * One record of every element the generated table draws plainly, each at its
 * natural length - the table's own check against the reference.
 */
const SWEEP_LENGTHS: Record<string, number> = { a4: 4, a6: 16, m: 6, b: 4, s: 4, B: 1, f: 4, F: 8, i4: 4, p: 1, ts: 4, tm: 8, tu: 8, tn: 8, td: 4, rm: 4, ru: 4 };
// Not the frame and MPLS sections (315-317), which the reference hands to
// the Ethernet and MPLS dissectors - four arbitrary bytes are neither, it
// throws, and draws nothing after them. This build draws a section as bytes.
const sweepIds = Object.entries(ELEMENTS).map(([id, e]) => [Number(id), e] as const)
  .filter(([id, [, , kind]]) => kind !== '-' && (id < 315 || id > 317));
const sweepLength = (kind: string) => SWEEP_LENGTHS[kind] ?? Number(kind.slice(1));
const sweepValue = (kind: string, length: number, i: number): number[] => {
  if (kind === 's') return text('abcd');
  if (kind === 'f') return u32(0x3fc00000);                           // 1.5
  if (kind === 'F') return [0x40, 0x09, 0x21, 0xfb, 0x54, 0x44, 0x2d, 0x18];  // pi
  if (kind === 'B') return [1];
  if (kind[0] === 't' || kind[0] === 'r') return length === 8 ? u64(1700000000000n + BigInt(i)) : u32(1000 * i + 7);
  if (kind[0] === 'e') return [...new Array(length - 1).fill(0), 1];
  return Array.from({ length }, (_, k) => (i * 7 + k * 13 + 1) & 0xff);
};
// The reference refuses a template of more than 60 elements (a preference),
// so the sweep is a template and a record per 60.
const sweepSets: number[][] = [];
for (let at = 0; at < sweepIds.length; at += 60) {
  const part = sweepIds.slice(at, at + 60);
  const id = 300 + at / 60;
  sweepSets.push(
    set(2, ipfixTemplate(id, part.map(([n, [, , kind]]) => ie(n, sweepLength(kind)))), false),
    set(id, part.flatMap(([, [, , kind]], i) => sweepValue(kind, sweepLength(kind), at + i))),
  );
}

const v9Message = v9([set(0, v9Template(256, V9_FIELDS)), set(1, v9Options), set(256, [...v9Record('192.168.1.10', 1500), ...v9Record('192.168.1.12', 3000)]),
  set(257, [...u32(5), ...u32(3), ...u32(1000)])], 5);
const cases: OracleCase[] = [
  // v5: two records, sampled; a message with none; one cut short.
  {
    label: 'a v5 export of two flows, sampled one in a hundred',
    frame: netflow(v5([v5rec({ src: '192.168.1.10', dst: '8.8.8.8', nh: '192.168.1.1', sas: 64512, das: 15169 }),
      v5rec({ src: '192.168.1.11', dst: '1.1.1.1', proto: 17, flags: 0, sport: 5353, dport: 53, first: 3599000, last: 3599500, smask: 0, dmask: 32 })],
    { engType: 1, engId: 2, sampling: 0x4064 })),
  },
  { label: 'a v5 export with no records', frame: netflow(v5([], { seq: 1002 }), 9996) },
  { label: 'a v5 export whose record was cut short', frame: netflow(v5([v5rec({ src: '1.1.1.1', dst: '2.2.2.2' })], { seq: 1002 }).slice(0, 40)) },
  { label: 'a v5 flow whose end wrapped past its start', frame: netflow(v5([v5rec({ src: '1.1.1.1', dst: '2.2.2.2', first: 2000, last: 1500, proto: 47, tos: 0xb8 })], { uptime: 90061001, seq: 1003, engType: 3 })) },
  // v9: a template, an options template and data in one message, then data alone.
  { label: 'a v9 export defining its templates and using them', frame: netflow(v9Message) },
  { label: 'a v9 export of data whose template came earlier, and data with none', frame: netflow(v9([set(256, v9Record('192.168.1.10', 1500)), set(300, [1, 2, 3, 4])], 2, { seq: 8 })) },
  { label: 'a v9 export that skipped sequence numbers', frame: netflow(v9([set(256, v9Record('192.168.1.13', 64))], 1, { seq: 20 })) },
  { label: 'a v9 template redefined: the first one stands', frame: netflow(v9([set(0, v9Template(256, [[2, 4]])), set(256, [...v9Record('192.168.1.14', 1)])], 2, { seq: 21 })) },
  { label: 'a v9 export saying it holds nothing', frame: netflow(v9([], 0, { seq: 22 })) },
  { label: 'a v9 set id nobody assigned', frame: netflow(v9([set(5, [1, 2, 3, 4])], 1, { seq: 23 })) },
  {
    label: 'a v9 record of every element drawn by hand',
    frame: netflow(v9([set(0, v9Template(310, V9_SPECIALS)), set(310, v9Specials)], 2, { seq: 0, source: 7 }), 9996),
  },
  // IPFIX.
  {
    label: 'an IPFIX export: templates, options, data, and a set with no template',
    frame: toIpfix(ipfix([set(2, ipfixTemplate(256, IPFIX_FIELDS), false), set(3, ipfixOptions), set(256, [...ipfixRecord('eth0'), ...ipfixLong]),
      set(258, [...u32(1), ...u32(100), 1]), set(400, [0, 0, 0, 0])])),
  },
  { label: 'an IPFIX withdrawal, and data the template still reads', frame: toIpfix(ipfix([set(2, [...u16(256), ...u16(0)], false), set(256, ipfixRecord('wan1'))], { seq: 8 })) },
  { label: 'an IPFIX export out of sequence', frame: toIpfix(ipfix([set(256, ipfixRecord('lo'))], { seq: 30 })) },
  {
    label: 'two IPFIX templates in one set, and two records of one',
    frame: toIpfix(ipfix([set(2, [...ipfixTemplate(260, [ie(1, 4), ie(8, 4)]), ...ipfixTemplate(261, [ie(2, 4)])], false),
      set(260, [0, 0, 0, 1, 1, 2, 3, 4, 0, 0, 0, 2, 5, 6, 7, 8]), set(261, [0, 0, 0, 3])], { domain: 2 })),
  },
  { label: 'an IPFIX set too short to walk', frame: toIpfix(Uint8Array.from([...ipfix([], { domain: 3 }).slice(0, 2), ...u16(20), ...ipfix([], { domain: 3 }).slice(4), 0, 2, 0, 2])) },
  { label: 'an IPFIX record of every element the table names', frame: toIpfix(ipfix(sweepSets, { domain: 4 })) },
  // Not NetFlow: a version nobody numbered is plain UDP, there and here.
  { label: 'a datagram on 2055 that is not NetFlow', frame: netflow(Uint8Array.from([0x12, 0x34, 1, 2, 3, 4, 5, 6, 7, 8])) },
];

// Absolute times are compared by date below, not here: see the header.
const absolute = new Set(['cflow.timestamp', ...Object.values(ELEMENTS).filter(([, , kind]) => kind[0] === 't').map(([abbrev]) => abbrev)]);
const rows = new RegExp(`^cflow\\.(?!(${[...absolute].map((a) => a.slice(6).replace(/\./g, '\\.')).join('|')})$)`);
const packets = await compareWithReference(cases, { rows });
await checkRevisit(cases);

const layer = (i: number) => packets[i]?.layers.find((l) => l.name === 'Cisco NetFlow/IPFIX');
const find = (i: number, abbrev: string) => {
  const out: string[] = [];
  const walk = (fields: readonly { abbrev?: string; value: unknown; children?: readonly unknown[] }[]) => {
    for (const f of fields) {
      if (f.abbrev === abbrev) out.push(String(f.value));
      if (f.children) walk(f.children as typeof fields);
    }
  };
  walk(layer(i)?.fields ?? []);
  return out;
};
check('a v5 export is the `cflow` layer over UDP', packets[0]?.frameProtocols?.slice(-2).join(':') === 'udp:cflow', packets[0]?.frameProtocols?.join(':'));
check('the header is filterable', packets[0]?.fields?.['cflow.version'] === 5 && packets[4]?.fields?.['cflow.source_id'] === 0
  && packets[11]?.fields?.['cflow.od_id'] === 1, JSON.stringify(packets[0]?.fields));
check('the v5 timestamp is drawn as a date, in November 2023', /^Nov 1[45], 2023 \d\d:13:20\.123456789 /.test(find(0, 'cflow.timestamp')[0] ?? ''), find(0, 'cflow.timestamp')[0]);
check('an IPFIX flow\'s start is a date to the millisecond', /^Nov 1[45], 2023 \d\d:13:20\.123000000 /.test(find(11, 'cflow.abstimestart')[0] ?? ''), find(11, 'cflow.abstimestart')[0]);
check('a template defined in an earlier frame is linked to it',
  layer(5)?.fields.flatMap((f) => f.children ?? []).find((f) => f.abbrev === 'cflow.template_frame')?.linkToFrame === 5);

// The reference's duration wording, case by case.
const durations: [bigint, string][] = [
  [0n, '0.000000000 seconds'], [1000n, '1.000 microseconds'], [999_000n, '999.000 microseconds'], [1_000_000n, '1.000000 milliseconds'],
  [999_999_000n, '999.999000 milliseconds'], [1_000_000_000n, '1 second'], [1_000_001_000n, '1.000001000 seconds'], [60_000_000_000n, '1 minute'],
  [3_605_000_000_000n, '1 hour, 5 seconds'], [3_660_000_001_000n, '1 hour, 1 minute, 1.000 microseconds'], [61_000_000_000n, '1 minute, 1 second'],
  [-1_717_986_918_400_000_000n, '-19884 days, 2 hours, 35 minutes, 18.400000000 seconds'],
];
for (const [ns, want] of durations) check(`a duration of ${ns} ns reads "${want}"`, relativeTime(ns) === want, relativeTime(ns));

// --- flow records -------------------------------------------------------------------

const payload = (frame: Uint8Array) => frame.subarray(42);
const v5Flows = normalizeFlows(payload(cases[0].frame), 0, payload(cases[0].frame).length, ROUTER, new MemoryTemplateStore());
const exportMs = 1700000000 * 1000 + 123.456789;
check('v5: two flows', v5Flows.length === 2);
check('v5: addresses, ports, protocol and counters', v5Flows[0]?.srcAddr === '192.168.1.10' && v5Flows[0]?.dstAddr === '8.8.8.8'
  && v5Flows[0]?.srcPort === 443 && v5Flows[0]?.dstPort === 51000 && v5Flows[0]?.protocol === 6 && v5Flows[0]?.octets === 1500 && v5Flows[0]?.packets === 10,
JSON.stringify(v5Flows[0]));
check('v5: times are the export time less the uptime they precede it by',
  v5Flows[0]?.startMs === exportMs - 100000 && v5Flows[0]?.endMs === exportMs - 10000, `${v5Flows[0]?.startMs} ${v5Flows[0]?.endMs}`);
check('v5: the header\'s sampling interval is carried', v5Flows[0]?.samplingInterval === 100);

const store = new MemoryTemplateStore();
const v9Flows = normalizeFlows(v9Message, 0, v9Message.length, ROUTER, store);
check('v9: the data records, not the options record', v9Flows.length === 2, JSON.stringify(v9Flows.map((f) => f.srcAddr)));
check('v9: fields read through the template', v9Flows[1]?.srcAddr === '192.168.1.12' && v9Flows[1]?.octets === 3000 && v9Flows[1]?.inputIf === 3
  && v9Flows[1]?.outputIf === 5 && v9Flows[1]?.direction === 1 && v9Flows[1]?.vlan === 100 && v9Flows[1]?.samplingInterval === 100, JSON.stringify(v9Flows[1]));
check('v9: switched times become wall-clock times', v9Flows[0]?.startMs === 1700000000000 - 100000 && v9Flows[0]?.endMs === 1700000000000 - 10000);
const later = v9([set(256, v9Record('192.168.1.20', 7))], 1, { seq: 8 });
const laterFlows = normalizeFlows(later, 0, later.length, ROUTER, store);
check('v9: a later message reads through the stored template', laterFlows[0]?.srcAddr === '192.168.1.20' && laterFlows[0]?.octets === 7);
check('v9: a different exporter does not share it', normalizeFlows(later, 0, later.length, '10.0.0.2', store).length === 0);

const ipfixPayload = payload(cases[11].frame);
const ipfixFlows = normalizeFlows(ipfixPayload, 0, ipfixPayload.length, ROUTER, new MemoryTemplateStore());
check('IPFIX: two flows read past a variable-length element', ipfixFlows.length === 2 && ipfixFlows[1]?.srcAddr === '192.168.1.11'
  && ipfixFlows[1]?.dstPort === 53 && ipfixFlows[1]?.protocol === 17, JSON.stringify(ipfixFlows[1]));
check('IPFIX: 64-bit counters, and millisecond times as they are', ipfixFlows[0]?.octets === 1500 && ipfixFlows[0]?.startMs === 1700000000123
  && ipfixFlows[0]?.endMs === 1700000005456, JSON.stringify(ipfixFlows[0]));
check('IPFIX: a reverse element is not the forward one', ipfixFlows[0]?.octets === 1500);
finish('netflow');
