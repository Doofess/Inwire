/**
 * DNS for the packet list and the detail tree.
 *
 *   Standard query 0x060a HTTPS ssl.gstatic.com
 *   Standard query response 0x39a2 A ssl.gstatic.com A 142.250.75.195
 *   Standard query 0x0000 PTR _spotify-connect._tcp.local, "QM" question
 *
 * The message is parsed once by `dnsRecords.ts`; this file renders it. mDNS
 * (5353), LLMNR (5355) and NBNS (137) reuse the same wire format and the same
 * dissector, each keeping its own name in the Protocol column.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import {
  DNS_OPCODE_NAMES, DNS_RCODE_NAMES, DNS_TYPE_DESCRIPTIONS,
  dnsInfoLine, dnsTypeName, parseDnsMessage,
  type DnsMessage, type DnsRecord,
} from './dnsRecords';

export { parseDnsMessage, dnsInfoLine } from './dnsRecords';
export type { DnsMessage, DnsRecord } from './dnsRecords';

/**
 * The Info column. Returns null when the bytes are not DNS, so the caller can
 * fall back to a plain UDP summary.
 */
export function dissectDns(bytes: Uint8Array, messageStart: number, multicast = false): string | null {
  const msg = parseDnsMessage(bytes, messageStart);
  return msg === null ? null : dnsInfoLine(msg, multicast);
}

/** Seconds as Wireshark writes a TTL: `4500 (1 hour, 15 minutes)`. */
function describeTtl(ttl: number): string {
  if (ttl === 0) return '0';
  const units: [number, string][] = [[86400, 'day'], [3600, 'hour'], [60, 'minute'], [1, 'second']];
  const parts: string[] = [];
  let left = ttl;
  for (const [size, name] of units) {
    const n = Math.floor(left / size);
    if (n > 0) { parts.push(`${n} ${name}${n === 1 ? '' : 's'}`); left -= n * size; }
  }
  return `${ttl} (${parts.join(', ')})`;
}

function classField(rclass: number, cacheFlush: boolean, offset: number): ProtocolField[] {
  const range: [number, number] = [offset, offset + 1];
  return [
    {
      name: 'Class', value: `${rclass === 1 ? 'IN' : 'Unknown'} (0x${rclass.toString(16).padStart(4, '0')})`,
      rawBytesRange: range, bitfield: { bitOffset: 1, bitLength: 15, totalBits: 16 },
    },
    {
      name: 'Cache flush', value: cacheFlush ? 'True' : 'False',
      rawBytesRange: range, bitfield: { bitOffset: 0, bitLength: 1, totalBits: 16 },
    },
  ];
}

/** The record data, as the rows Wireshark nests under a record. */
function rdataFields(r: DnsRecord): ProtocolField[] {
  const out: ProtocolField[] = [];
  const range: [number, number] = [r.rdataStart, r.rdataStart + Math.max(0, r.rdataLength - 1)];
  switch (r.type) {
    case 1: if (r.addresses[0]) out.push({ name: 'Address', value: r.addresses[0], rawBytesRange: range, abbrev: 'dns.a' }); break;
    case 28: if (r.addresses[0]) out.push({ name: 'AAAA Address', value: r.addresses[0], rawBytesRange: range, abbrev: 'dns.aaaa' }); break;
    case 5: if (r.target) out.push({ name: 'CNAME', value: r.target, rawBytesRange: range, abbrev: 'dns.cname' }); break;
    case 2: if (r.target) out.push({ name: 'Name Server', value: r.target, rawBytesRange: range, abbrev: 'dns.ns' }); break;
    case 12: if (r.target) out.push({ name: 'Domain Name', value: r.target, rawBytesRange: range, abbrev: 'dns.ptr.domain_name' }); break;
    case 15: if (r.target) out.push({ name: 'Mail Exchange', value: r.target, rawBytesRange: range }); break;
    case 16:
      for (const s of r.txt ?? []) out.push({ name: 'TXT', value: s, rawBytesRange: range, abbrev: 'dns.txt' });
      break;
    case 33:
      if (r.srv) out.push(
        { name: 'Priority', value: r.srv.priority, rawBytesRange: [r.rdataStart, r.rdataStart + 1] },
        { name: 'Weight', value: r.srv.weight, rawBytesRange: [r.rdataStart + 2, r.rdataStart + 3] },
        { name: 'Port', value: r.srv.port, rawBytesRange: [r.rdataStart + 4, r.rdataStart + 5], abbrev: 'dns.srv.port' },
        { name: 'Target', value: r.srv.target, rawBytesRange: [r.rdataStart + 6, range[1]], abbrev: 'dns.srv.target' },
      );
      break;
    case 6:
      if (r.soa) out.push(
        { name: 'Primary name server', value: r.soa.mname, rawBytesRange: range },
        { name: 'Responsible authority\'s mailbox', value: r.soa.rname, rawBytesRange: range },
        { name: 'Serial Number', value: r.soa.serial, rawBytesRange: range },
        { name: 'Refresh Interval', value: describeTtl(r.soa.refresh), rawBytesRange: range },
        { name: 'Retry Interval', value: describeTtl(r.soa.retry), rawBytesRange: range },
        { name: 'Expire limit', value: describeTtl(r.soa.expire), rawBytesRange: range },
        { name: 'Minimum TTL', value: describeTtl(r.soa.minimum), rawBytesRange: range },
      );
      break;
    case 64: case 65:
      if (r.svcb) {
        out.push(
          { name: 'SvcPriority', value: r.svcb.priority, rawBytesRange: [r.rdataStart, r.rdataStart + 1], abbrev: 'dns.svcb.priority' },
          { name: 'TargetName', value: r.svcb.target, rawBytesRange: range },
          ...r.svcb.params.map((param): ProtocolField => ({
            name: `SvcParam: ${param.name}${param.value ? `=${param.value}` : ''}`,
            value: '', rawBytesRange: range,
            ...(param.key === 1 ? { abbrev: 'dns.svcb.alpn' } : {}),
            ...(param.key === 5 ? { description: 'This name supports Encrypted Client Hello, so its TLS handshakes hide the real server name.' } : {}),
          })),
        );
      }
      break;
    case 41:
      if (r.edns) out.push(
        { name: 'UDP payload size', value: r.edns.udpPayloadSize, rawBytesRange: range, abbrev: 'dns.rr.udp_payload_size' },
        { name: 'Higher bits in extended RCODE', value: `0x${r.edns.extendedRcode.toString(16).padStart(2, '0')}`, rawBytesRange: range },
        { name: 'EDNS0 version', value: r.edns.version, rawBytesRange: range },
        { name: 'DO bit', value: r.edns.dnssecOk ? 'Accepts DNSSEC security RRs' : 'Cannot handle DNSSEC security RRs', rawBytesRange: range, abbrev: 'dns.resp.z.do' },
        ...r.edns.options.map((o): ProtocolField => ({ name: `Option: ${o.name}`, value: o.value, rawBytesRange: range })),
      );
      break;
    case 257:
      if (r.summary) out.push({ name: 'CAA', value: r.summary, rawBytesRange: range });
      break;
    default:
      if (r.rdataLength > 0) out.push({ name: 'Data', value: `${r.rdataLength} bytes`, rawBytesRange: range });
  }
  return out;
}

function recordField(r: DnsRecord): ProtocolField {
  const typeDesc = DNS_TYPE_DESCRIPTIONS[r.type];
  const head = r.type === 41
    ? `<Root>: type OPT`
    : `${r.name || '<Root>'}: type ${dnsTypeName(r.type)}, class ${r.rclass === 1 ? 'IN' : r.rclass}${r.summary ? `, ${r.summary}` : ''}`;
  const children: ProtocolField[] = [
    { name: 'Name', value: r.name || '<Root>', rawBytesRange: [r.start, Math.max(r.start, r.nameEnd - 1)], abbrev: 'dns.resp.name' },
    { name: 'Type', value: `${dnsTypeName(r.type)} (${r.type})${typeDesc ? ` (${typeDesc})` : ''}`, rawBytesRange: [r.nameEnd, r.nameEnd + 1], abbrev: 'dns.resp.type' },
  ];
  if (r.type !== 41) {
    children.push(...classField(r.rclass, r.cacheFlush, r.nameEnd + 2));
    children.push({ name: 'Time to live', value: describeTtl(r.ttl), rawBytesRange: [r.nameEnd + 4, r.nameEnd + 7], abbrev: 'dns.resp.ttl' });
  }
  children.push({ name: 'Data length', value: r.rdataLength, rawBytesRange: [r.nameEnd + 8, r.nameEnd + 9] });
  children.push(...rdataFields(r));
  return { name: head, value: '', rawBytesRange: [r.start, r.end - 1], children };
}

/**
 * The flags word, as the sixteen-bit rows Wireshark draws beneath it.
 *
 * The row set is conditional, not a fixed template: a query shows six rows,
 * while a response additionally carries Authoritative, Recursion available,
 * Answer authenticated and Reply code. Emitting the response-only rows on a
 * query would invent flags the message does not have.
 */
function dnsFlagFields(flags: number, flagsOffset: number): ProtocolField[] {
  const isResponse = (flags & 0x8000) !== 0;
  const opcode = (flags >> 11) & 0x0f;
  const rcode = flags & 0x0f;
  const bit = (n: number) => (flags >> (15 - n)) & 1;

  const range: [number, number] = [flagsOffset, flagsOffset + 1];
  const row = (name: string, bitOffset: number, bitLength: number, value: string, abbrev?: string): ProtocolField => ({
    name, value, rawBytesRange: range, bitfield: { bitOffset, bitLength, totalBits: 16 }, ...(abbrev ? { abbrev } : {}),
  });

  const rows: ProtocolField[] = [
    row('Response', 0, 1, isResponse ? 'Message is a response' : 'Message is a query', 'dns.flags.response'),
    row('Opcode', 1, 4, `${DNS_OPCODE_NAMES[opcode] ?? 'Unknown'} (${opcode})`, 'dns.flags.opcode'),
  ];
  if (isResponse) {
    rows.push(row('Authoritative', 5, 1, bit(5) ? 'Server is an authority for domain' : 'Server is not an authority for domain', 'dns.flags.authoritative'));
  }
  rows.push(
    row('Truncated', 6, 1, bit(6) ? 'Message is truncated' : 'Message is not truncated', 'dns.flags.truncated'),
    row('Recursion desired', 7, 1, bit(7) ? 'Do query recursively' : 'Do not query recursively', 'dns.flags.recdesired'),
  );
  if (isResponse) {
    rows.push(row('Recursion available', 8, 1, bit(8) ? 'Server can do recursive queries' : 'Server cannot do recursive queries'));
  }
  rows.push(row('Z', 9, 1, `reserved (${bit(9)})`));
  if (isResponse) {
    rows.push(row('Answer authenticated', 10, 1,
      bit(10) ? 'Answer/authority portion was authenticated by the server' : 'Answer/authority portion was not authenticated by the server'));
  }
  rows.push(row('Non-authenticated data', 11, 1, bit(11) ? 'Acceptable' : 'Unacceptable'));
  if (isResponse) {
    rows.push(row('Reply code', 12, 4, `${rcode === 0 ? 'No error' : DNS_RCODE_NAMES[rcode] ?? 'Unknown'} (${rcode})`, 'dns.flags.rcode'));
  }
  return rows;
}

function querySection(msg: DnsMessage): ProtocolField[] {
  if (msg.questions.length === 0) return [];
  return [{
    name: 'Queries', value: '',
    children: msg.questions.map((q): ProtocolField => ({
      name: q.name, value: `type ${dnsTypeName(q.type)}, class ${q.qclass === 1 ? 'IN' : q.qclass}`,
      rawBytesRange: [q.start, q.end - 1],
      children: [
        { name: 'Name', value: q.name, rawBytesRange: [q.start, Math.max(q.start, q.nameEnd - 1)], abbrev: 'dns.qry.name' },
        { name: 'Type', value: `${dnsTypeName(q.type)} (${q.type})`, rawBytesRange: [q.nameEnd, q.nameEnd + 1], abbrev: 'dns.qry.type' },
        ...classField(q.qclass, q.unicastResponse, q.nameEnd + 2),
      ],
    })),
  }];
}

function recordSection(title: string, records: DnsRecord[]): ProtocolField[] {
  if (records.length === 0) return [];
  return [{ name: title, value: '', children: records.map(recordField) }];
}

/** What the caller learned from this message and wants on the packet. */
export interface DnsDissection {
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
  /** name -> addresses, for passive name resolution. */
  resolved: { name: string; addresses: string[] }[];
  /** The first question, for query/response pairing. */
  questionName?: string;
  isResponse: boolean;
  transactionId: number;
  rcode: number;
  /** True when this response says the name does not exist. */
  nxdomain: boolean;
}

/**
 * The DNS layer, plus the facts other layers want. `pairing` is filled in by
 * the caller once the tracker has matched this frame.
 */
export function buildDnsLayer(
  bytes: Uint8Array, messageStart: number, messageEnd = bytes.length,
  pairing?: { requestFrame?: number; elapsedUs?: number; responseFrame?: number },
): DnsDissection | null {
  const msg = parseDnsMessage(bytes, messageStart, messageEnd);
  if (msg === null) return null;

  const answers = msg.records.filter((r) => r.section === 'answer');
  const authority = msg.records.filter((r) => r.section === 'authority');
  const additional = msg.records.filter((r) => r.section === 'additional');
  const rcodeName = msg.isResponse ? DNS_RCODE_NAMES[msg.rcode] : undefined;

  const fields: Record<string, string | number> = {
    'dns.id': msg.transactionId,
    'dns.flags': msg.flags,
    'dns.flags.response': msg.isResponse ? 1 : 0,
    'dns.flags.opcode': msg.opcode,
    'dns.count.queries': msg.counts[0],
    'dns.count.answers': msg.counts[1],
  };
  if (msg.isResponse) fields['dns.flags.rcode'] = msg.rcode;
  if (msg.questions.length > 0) {
    fields['dns.qry.name'] = msg.questions[0].name;
    fields['dns.qry.type'] = msg.questions[0].type;
  }
  const firstAddress = msg.records.find((r) => r.type === 1)?.addresses[0];
  if (firstAddress) fields['dns.a'] = firstAddress;
  const firstV6 = msg.records.find((r) => r.type === 28)?.addresses[0];
  if (firstV6) fields['dns.aaaa'] = firstV6;
  if (pairing?.requestFrame !== undefined) fields['dns.response_to'] = pairing.requestFrame;
  if (pairing?.responseFrame !== undefined) fields['dns.response_in'] = pairing.responseFrame;

  const generated: ProtocolField[] = [];
  if (pairing?.requestFrame !== undefined) {
    generated.push(
      { name: '[Request In]', value: pairing.requestFrame, generated: true, linkToFrame: pairing.requestFrame, abbrev: 'dns.response_to' },
      { name: '[Time]', value: `${((pairing.elapsedUs ?? 0) / 1000).toFixed(6)} milliseconds`, generated: true },
    );
  }
  if (pairing?.responseFrame !== undefined) {
    generated.push({ name: '[Response In]', value: pairing.responseFrame, generated: true, linkToFrame: pairing.responseFrame, abbrev: 'dns.response_in' });
  }
  if (msg.isResponse && msg.rcode === 3) {
    generated.push({
      name: '[Expert Info]', value: 'No such name', generated: true,
      expertInfo: { category: 'Note', message: 'DNS: the name does not exist (NXDOMAIN)' },
    });
  }

  // What passive name resolution consumes: every name that mapped to an
  // address, including the ones a CNAME chain ends at.
  const resolved = answers
    .filter((r) => r.addresses.length > 0)
    .map((r) => ({ name: r.name, addresses: r.addresses }));

  return {
    layer: {
      name: 'Domain Name System',
      summary: `Domain Name System (${msg.isResponse ? 'response' : 'query'})`,
      rawBytesRange: [messageStart, messageEnd - 1],
      fields: [
        { name: 'Transaction ID', value: `0x${msg.transactionId.toString(16).padStart(4, '0')}`, rawBytesRange: [messageStart, messageStart + 1], abbrev: 'dns.id' },
        {
          name: 'Flags',
          value: `0x${msg.flags.toString(16).padStart(4, '0')} ${DNS_OPCODE_NAMES[msg.opcode]}${msg.isResponse ? ' response' : ''}${rcodeName ? `, ${rcodeName}` : ''}`,
          rawBytesRange: [messageStart + 2, messageStart + 3],
          abbrev: 'dns.flags',
          children: dnsFlagFields(msg.flags, messageStart + 2),
        },
        { name: 'Questions', value: msg.counts[0], rawBytesRange: [messageStart + 4, messageStart + 5], abbrev: 'dns.count.queries' },
        { name: 'Answer RRs', value: msg.counts[1], rawBytesRange: [messageStart + 6, messageStart + 7], abbrev: 'dns.count.answers' },
        { name: 'Authority RRs', value: msg.counts[2], rawBytesRange: [messageStart + 8, messageStart + 9] },
        { name: 'Additional RRs', value: msg.counts[3], rawBytesRange: [messageStart + 10, messageStart + 11] },
        ...querySection(msg),
        ...recordSection('Answers', answers),
        ...recordSection('Authoritative nameservers', authority),
        ...recordSection('Additional records', additional),
        ...generated,
      ],
    },
    fields,
    resolved,
    questionName: msg.questions[0]?.name,
    isResponse: msg.isResponse,
    transactionId: msg.transactionId,
    rcode: msg.rcode,
    nxdomain: msg.isResponse && msg.rcode === 3,
  };
}
