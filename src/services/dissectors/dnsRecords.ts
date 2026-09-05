/**
 * The DNS message, parsed once into a structure that both the Info line and
 * the detail tree are built from.
 *
 * Before this existed the two were separate walks over the same bytes: the
 * Info builder rendered answers it never showed in the tree, and the tree
 * showed a Queries node and nothing else - so a response's records were
 * readable in the packet list and unreachable in the detail pane. One parse
 * also means a record type is taught to the app once rather than twice.
 *
 * Wire format: RFC 1035, with SVCB/HTTPS from RFC 9460 and EDNS(0) from
 * RFC 6891. Names may be compressed, so every offset here is absolute and the
 * message start is carried through every call.
 */
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';

export const DNS_TYPE_NAMES: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 10: 'NULL', 12: 'PTR', 13: 'HINFO', 15: 'MX',
  16: 'TXT', 17: 'RP', 24: 'SIG', 25: 'KEY', 28: 'AAAA', 29: 'LOC', 33: 'SRV',
  35: 'NAPTR', 39: 'DNAME', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC',
  48: 'DNSKEY', 50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA', 59: 'CDS', 60: 'CDNSKEY',
  64: 'SVCB', 65: 'HTTPS', 99: 'SPF', 108: 'EUI48', 109: 'EUI64', 249: 'TKEY', 250: 'TSIG',
  251: 'IXFR', 252: 'AXFR', 255: 'ANY', 256: 'URI', 257: 'CAA',
};

export const DNS_TYPE_DESCRIPTIONS: Record<number, string> = {
  1: 'Host Address', 2: 'Authoritative Name Server', 5: 'Canonical NAMe for an alias',
  6: 'Start Of a zone of Authority', 12: 'domain name PoinTeR', 15: 'Mail eXchange',
  16: 'Text strings', 28: 'IPv6 Address', 33: 'Server Selection', 41: 'EDNS0 option',
  43: 'Delegation Signer', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY',
  64: 'General Purpose Service Endpoints', 65: 'HTTPS Specific Service Endpoints',
  257: 'Certification Authority Restriction',
};

export const DNS_OPCODE_NAMES: Record<number, string> = {
  0: 'Standard query', 1: 'Inverse query', 2: 'Server status request', 4: 'Notify', 5: 'Dynamic update',
};

/**
 * Deliberately no entry for 0: the Info column must not append "No error" to a
 * successful response. The tree names it separately.
 */
export const DNS_RCODE_NAMES: Record<number, string> = {
  1: 'Format error', 2: 'Server failure', 3: 'No such name', 4: 'Not implemented',
  5: 'Refused', 6: 'Name exists when it should not', 7: 'RR set exists when it should not',
  8: 'RR set that should exist does not', 9: 'Server not authoritative for zone', 10: 'Name not in zone',
  16: 'Bad OPT version', 17: 'Key not recognized', 18: 'Signature out of time window',
  19: 'Bad TKEY mode', 20: 'Duplicate key name', 21: 'Algorithm not supported', 22: 'Bad truncation',
};

const EDNS_OPTION_NAMES: Record<number, string> = {
  3: 'NSID', 5: 'DAU', 6: 'DHU', 7: 'N3U', 8: 'Client Subnet', 9: 'Expire', 10: 'COOKIE',
  11: 'TCP Keepalive', 12: 'Padding', 13: 'CHAIN', 14: 'Key Tag', 15: 'Extended DNS Error',
};

const SVCB_PARAM_NAMES: Record<number, string> = {
  0: 'mandatory', 1: 'alpn', 2: 'no-default-alpn', 3: 'port', 4: 'ipv4hint', 5: 'ech', 6: 'ipv6hint', 7: 'dohpath',
};

export function dnsTypeName(type: number): string {
  return DNS_TYPE_NAMES[type] ?? `TYPE${type}`;
}

export interface DnsName {
  name: string;
  /** Offset just past the name as encoded here - a pointer is 2 bytes however long the name it names. */
  nextOffset: number;
}

/**
 * Reads a possibly-compressed name. A length byte with its top two bits set is
 * a 14-bit pointer back into the message rather than a label length, which is
 * how a response avoids repeating the question's domain in every record.
 * `jumps` bounds the pointer chain so a message that points at itself cannot
 * spin forever.
 */
export function readDnsName(b: Uint8Array, messageStart: number, offset: number, jumps = 0): DnsName {
  const labels: string[] = [];
  let cursor = offset;
  let nextOffset = -1;

  while (cursor < b.length) {
    const length = b[cursor];
    if (length === 0) { cursor += 1; break; }
    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= b.length || jumps >= 8) break;
      const pointer = ((length & 0x3f) << 8) | b[cursor + 1];
      if (nextOffset === -1) nextOffset = cursor + 2;
      const target = readDnsName(b, messageStart, messageStart + pointer, jumps + 1);
      if (target.name) labels.push(target.name);
      cursor += 2;
      break;
    }
    if (cursor + 1 + length > b.length) break;
    labels.push(new TextDecoder().decode(b.subarray(cursor + 1, cursor + 1 + length)));
    cursor += 1 + length;
  }
  return { name: labels.join('.'), nextOffset: nextOffset === -1 ? cursor : nextOffset };
}

export interface DnsQuestion {
  name: string;
  type: number;
  qclass: number;
  /** mDNS reuses the class's top bit to ask for a unicast reply (RFC 6762 §5.4). */
  unicastResponse: boolean;
  start: number;
  end: number;
  nameEnd: number;
}

export interface SvcbParam { key: number; name: string; value: string; values?: string[] }

export interface EdnsOption { code: number; name: string; value: string }

export interface DnsRecord {
  section: 'answer' | 'authority' | 'additional';
  name: string;
  type: number;
  rclass: number;
  /** mDNS reuses the class's top bit as a cache-flush request. */
  cacheFlush: boolean;
  ttl: number;
  rdataLength: number;
  rdataStart: number;
  start: number;
  end: number;
  nameEnd: number;
  /** How the Info column renders the record data; null when this type has no summary. */
  summary: string | null;
  /** Addresses this record maps its name to - what passive name resolution consumes. */
  addresses: string[];
  /** The name a CNAME/PTR/NS/SRV points at. */
  target?: string;
  svcb?: { priority: number; target: string; params: SvcbParam[] };
  edns?: { udpPayloadSize: number; extendedRcode: number; version: number; dnssecOk: boolean; options: EdnsOption[] };
  soa?: { mname: string; rname: string; serial: number; refresh: number; retry: number; expire: number; minimum: number };
  srv?: { priority: number; weight: number; port: number; target: string };
  txt?: string[];
}

export interface DnsMessage {
  transactionId: number;
  flags: number;
  isResponse: boolean;
  opcode: number;
  rcode: number;
  counts: [number, number, number, number];
  questions: DnsQuestion[];
  records: DnsRecord[];
  /** Where the message ends as parsed; the caller uses it for byte ranges. */
  end: number;
}

const u16 = (b: Uint8Array, p: number) => (b[p] << 8) | b[p + 1];
const u32 = (b: Uint8Array, p: number) => ((b[p] << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3]) >>> 0;

/**
 * Parses a DNS message. Returns null when the bytes are not DNS, so the caller
 * can fall back to a plain UDP summary.
 */
export function parseDnsMessage(b: Uint8Array, messageStart: number, messageEnd = b.length): DnsMessage | null {
  if (messageStart + 12 > messageEnd) return null;
  const flags = u16(b, messageStart + 2);
  const opcode = (flags >> 11) & 0x0f;
  if (DNS_OPCODE_NAMES[opcode] === undefined) return null;

  const msg: DnsMessage = {
    transactionId: u16(b, messageStart),
    flags,
    isResponse: (flags & 0x8000) !== 0,
    opcode,
    rcode: flags & 0x0f,
    counts: [u16(b, messageStart + 4), u16(b, messageStart + 6), u16(b, messageStart + 8), u16(b, messageStart + 10)],
    questions: [],
    records: [],
    end: messageEnd,
  };

  let p = messageStart + 12;
  for (let i = 0; i < msg.counts[0] && p < messageEnd; i++) {
    const start = p;
    const { name, nextOffset } = readDnsName(b, messageStart, p);
    p = nextOffset;
    if (p + 4 > messageEnd) return msg;
    const type = u16(b, p);
    const qclass = u16(b, p + 2);
    p += 4;
    msg.questions.push({ name, type, qclass: qclass & 0x7fff, unicastResponse: (qclass & 0x8000) !== 0, start, end: p, nameEnd: nextOffset });
  }

  const sections: DnsRecord['section'][] = ['answer', 'authority', 'additional'];
  for (let s = 0; s < 3; s++) {
    for (let i = 0; i < msg.counts[s + 1] && p < messageEnd; i++) {
      const record = parseRecord(b, messageStart, p, messageEnd, sections[s]);
      if (!record) return msg;
      msg.records.push(record);
      p = record.end;
    }
  }
  return msg;
}

function parseRecord(b: Uint8Array, messageStart: number, p: number, end: number, section: DnsRecord['section']): DnsRecord | null {
  const start = p;
  const { name, nextOffset } = readDnsName(b, messageStart, p);
  p = nextOffset;
  if (p + 10 > end) return null;
  const type = u16(b, p);
  const rclassRaw = u16(b, p + 2);
  const ttl = u32(b, p + 4);
  const rdataLength = u16(b, p + 8);
  const rdataStart = p + 10;
  if (rdataStart + rdataLength > end) return null;

  const record: DnsRecord = {
    section, name, type,
    rclass: type === 41 ? rclassRaw : rclassRaw & 0x7fff,
    cacheFlush: type !== 41 && (rclassRaw & 0x8000) !== 0,
    ttl, rdataLength, rdataStart, start, end: rdataStart + rdataLength, nameEnd: nextOffset,
    summary: null, addresses: [],
  };
  decodeRdata(b, messageStart, record, rclassRaw, ttl);
  return record;
}

function decodeRdata(b: Uint8Array, messageStart: number, r: DnsRecord, rclassRaw: number, ttl: number): void {
  const { rdataStart: p, rdataLength: len } = r;
  switch (r.type) {
    case 1:
      if (len >= 4) { const a = formatIpv4Address(b, p); r.summary = a; r.addresses.push(a); }
      break;
    case 28:
      if (len >= 16) { const a = formatIpv6Address(b, p); r.summary = a; r.addresses.push(a); }
      break;
    case 2: case 5: case 12: case 39: {
      const t = readDnsName(b, messageStart, p).name;
      if (t) { r.summary = t; r.target = t; }
      break;
    }
    case 6: {
      const mname = readDnsName(b, messageStart, p);
      const rname = readDnsName(b, messageStart, mname.nextOffset);
      const numbers = rname.nextOffset;
      if (numbers + 20 <= p + len) {
        r.soa = {
          mname: mname.name, rname: rname.name,
          serial: u32(b, numbers), refresh: u32(b, numbers + 4), retry: u32(b, numbers + 8),
          expire: u32(b, numbers + 12), minimum: u32(b, numbers + 16),
        };
      }
      r.summary = mname.name || null;
      break;
    }
    case 15:
      if (len >= 3) { const t = readDnsName(b, messageStart, p + 2).name; if (t) { r.summary = t; r.target = t; } }
      break;
    case 16: {
      const strings: string[] = [];
      for (let q = p; q < p + len;) {
        const n = b[q];
        if (q + 1 + n > p + len) break;
        strings.push(new TextDecoder().decode(b.subarray(q + 1, q + 1 + n)));
        q += 1 + n;
      }
      r.txt = strings;
      // Wireshark's Info shows the type alone for TXT; the strings live in the tree.
      break;
    }
    case 33: {
      if (len < 7) break;
      const target = readDnsName(b, messageStart, p + 6).name;
      r.srv = { priority: u16(b, p), weight: u16(b, p + 2), port: u16(b, p + 4), target };
      r.target = target;
      r.summary = `${r.srv.priority} ${r.srv.weight} ${r.srv.port} ${target}`;
      break;
    }
    case 41: {
      // OPT: the "class" is the sender's UDP payload size and the TTL packs
      // the extended rcode, the version and the DO bit (RFC 6891).
      const options: EdnsOption[] = [];
      for (let q = p; q + 4 <= p + len;) {
        const code = u16(b, q);
        const olen = u16(b, q + 2);
        if (q + 4 + olen > p + len) break;
        options.push({ code, name: EDNS_OPTION_NAMES[code] ?? `Unknown (${code})`, value: describeEdnsOption(b, code, q + 4, olen) });
        q += 4 + olen;
      }
      r.edns = {
        udpPayloadSize: rclassRaw,
        extendedRcode: (ttl >>> 24) & 0xff,
        version: (ttl >>> 16) & 0xff,
        dnssecOk: ((ttl >>> 15) & 1) === 1,
        options,
      };
      break;
    }
    case 64: case 65: {
      if (len < 3) break;
      const priority = u16(b, p);
      const targetName = readDnsName(b, messageStart, p + 2);
      const params: SvcbParam[] = [];
      for (let q = targetName.nextOffset; q + 4 <= p + len;) {
        const key = u16(b, q);
        const vlen = u16(b, q + 2);
        if (q + 4 + vlen > p + len) break;
        params.push(describeSvcbParam(b, key, q + 4, vlen));
        q += 4 + vlen;
      }
      r.svcb = { priority, target: targetName.name || '<Root>', params };
      for (const param of params) {
        if (param.key === 4 || param.key === 6) r.addresses.push(...(param.values ?? []));
      }
      break;
    }
    case 257: {
      if (len < 2) break;
      const tagLen = b[p + 1];
      const tag = new TextDecoder().decode(b.subarray(p + 2, p + 2 + tagLen));
      const value = new TextDecoder().decode(b.subarray(p + 2 + tagLen, p + len));
      r.summary = `${tag} ${value}`;
      break;
    }
  }
}

function describeEdnsOption(b: Uint8Array, code: number, p: number, len: number): string {
  if (code === 8 && len >= 4) {
    // Client Subnet: family, source prefix, scope prefix, then the address.
    const family = u16(b, p);
    const source = b[p + 2];
    const scope = b[p + 3];
    const addrBytes = b.subarray(p + 4, p + len);
    const padded = new Uint8Array(family === 1 ? 4 : 16);
    padded.set(addrBytes.subarray(0, padded.length));
    const addr = family === 1 ? formatIpv4Address(padded, 0) : formatIpv6Address(padded, 0);
    return `${addr}/${source} (scope ${scope})`;
  }
  if (code === 10) return len === 0 ? 'client cookie only' : `${len} bytes`;
  if (code === 12) return `${len} bytes of padding`;
  return `${len} bytes`;
}

function describeSvcbParam(b: Uint8Array, key: number, p: number, len: number): SvcbParam {
  const name = SVCB_PARAM_NAMES[key] ?? `key${key}`;
  switch (key) {
    case 1: {
      const alpns: string[] = [];
      for (let q = p; q < p + len;) {
        const n = b[q];
        if (q + 1 + n > p + len) break;
        alpns.push(new TextDecoder().decode(b.subarray(q + 1, q + 1 + n)));
        q += 1 + n;
      }
      return { key, name, value: alpns.join(','), values: alpns };
    }
    case 2: return { key, name, value: '' };
    case 3: return { key, name, value: String(u16(b, p)) };
    case 4: {
      const ips: string[] = [];
      for (let q = p; q + 4 <= p + len; q += 4) ips.push(formatIpv4Address(b, q));
      return { key, name, value: ips.join(','), values: ips };
    }
    case 6: {
      const ips: string[] = [];
      for (let q = p; q + 16 <= p + len; q += 16) ips.push(formatIpv6Address(b, q));
      return { key, name, value: ips.join(','), values: ips };
    }
    case 5: return { key, name, value: `${len} bytes` };
    default: return { key, name, value: `${len} bytes` };
  }
}

/**
 * The packet-list Info line, in Wireshark's wording.
 *
 * A response repeats its question and then names every record it carries -
 * answers, authority and additional alike - so the whole exchange is readable
 * from the list without opening the frame. `multicast` adds mDNS's
 * `"QM"/"QU" question` suffix, which is meaningless in unicast DNS because the
 * bit it reads is the class's own there.
 */
export function dnsInfoLine(msg: DnsMessage, multicast: boolean): string {
  const parts: string[] = [
    DNS_OPCODE_NAMES[msg.opcode] + (msg.isResponse ? ' response' : ''),
    `0x${msg.transactionId.toString(16).padStart(4, '0')}`,
  ];
  const rcodeName = msg.isResponse ? DNS_RCODE_NAMES[msg.rcode] : undefined;
  if (rcodeName) parts.push(rcodeName);

  for (const q of msg.questions) {
    parts.push(dnsTypeName(q.type));
    // The suffix attaches to the name with a comma, as one field.
    parts.push(multicast && !msg.isResponse
      ? `${q.name}, "${q.unicastResponse ? 'QU' : 'QM'}" question`
      : q.name);
  }
  for (const r of msg.records) {
    if (r.type === 41) continue; // OPT is transport metadata, not an answer
    parts.push(dnsTypeName(r.type));
    if (r.summary) parts.push(r.summary);
  }
  return parts.join(' ');
}
