/**
 * DNS message summaries in Wireshark's Info format:
 *
 *   Standard query 0x060a HTTPS ssl.gstatic.com
 *   Standard query response 0x39a2 A ssl.gstatic.com A 142.250.75.195
 *   Standard query response 0x060a HTTPS ssl.gstatic.com SOA ns1.google.com
 *
 * A response repeats its question and then appends each record it carries, so
 * the whole exchange is readable from the packet list without opening a frame.
 * mDNS (5353), LLMNR (5355) and NBNS (137) reuse this same wire format.
 */
import { formatIpv4Address, formatIpv6Address } from '../addressFormat';

const OPCODE_NAMES: Record<number, string> = {
  0: 'Standard query',
  1: 'Inverse query',
  2: 'Server status request',
  4: 'Notify',
  5: 'Dynamic update',
};

const RCODE_NAMES: Record<number, string> = {
  1: 'Format error',
  2: 'Server failure',
  3: 'No such name',
  4: 'Not implemented',
  5: 'Refused',
};

const TYPE_NAMES: Record<number, string> = {
  1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 13: 'HINFO', 15: 'MX',
  16: 'TXT', 17: 'RP', 24: 'SIG', 25: 'KEY', 28: 'AAAA', 29: 'LOC', 33: 'SRV',
  35: 'NAPTR', 39: 'DNAME', 41: 'OPT', 43: 'DS', 46: 'RRSIG', 47: 'NSEC',
  48: 'DNSKEY', 50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA', 64: 'SVCB',
  65: 'HTTPS', 99: 'SPF', 251: 'IXFR', 252: 'AXFR', 255: 'ANY', 257: 'CAA',
};

function typeName(type: number): string {
  return TYPE_NAMES[type] ?? `TYPE${type}`;
}

interface NameResult {
  name: string;
  /** Offset just past the name *as encoded here* - a pointer is 2 bytes however long the name it names. */
  nextOffset: number;
}

/**
 * Reads a possibly-compressed DNS name. A length byte with its top two bits
 * set is a 14-bit pointer back into the message rather than a label length,
 * which is how a response avoids repeating the question's domain in every
 * record. `jumps` bounds the pointer chain so a malicious or corrupt message
 * that points at itself can't spin forever.
 */
function readName(bytes: Uint8Array, messageStart: number, offset: number, jumps = 0): NameResult {
  const labels: string[] = [];
  let cursor = offset;
  let nextOffset = -1;

  while (cursor < bytes.length) {
    const length = bytes[cursor];

    if (length === 0) {
      cursor += 1;
      break;
    }

    if ((length & 0xc0) === 0xc0) {
      if (cursor + 1 >= bytes.length || jumps >= 8) break;
      const pointer = ((length & 0x3f) << 8) | bytes[cursor + 1];
      if (nextOffset === -1) nextOffset = cursor + 2;
      const target = readName(bytes, messageStart, messageStart + pointer, jumps + 1);
      if (target.name) labels.push(target.name);
      cursor += 2;
      break;
    }

    if (cursor + 1 + length > bytes.length) break;
    labels.push(new TextDecoder().decode(bytes.subarray(cursor + 1, cursor + 1 + length)));
    cursor += 1 + length;
  }

  return { name: labels.join('.'), nextOffset: nextOffset === -1 ? cursor : nextOffset };
}

/** Renders the record data the way Wireshark summarizes it in the Info column. */
function formatRdata(
  bytes: Uint8Array,
  messageStart: number,
  type: number,
  rdataStart: number,
  rdataLength: number
): string | null {
  const end = rdataStart + rdataLength;
  if (end > bytes.length) return null;

  switch (type) {
    case 1:
      return rdataLength >= 4 ? formatIpv4Address(bytes, rdataStart) : null;
    case 28:
      return rdataLength >= 16 ? formatIpv6Address(bytes, rdataStart) : null;
    case 2: case 5: case 12: case 39:
      return readName(bytes, messageStart, rdataStart).name || null;
    case 6:
      // SOA's summary is just its primary name server, the first of its
      // several fields.
      return readName(bytes, messageStart, rdataStart).name || null;
    case 15: {
      // MX: 2-byte preference, then the exchange host.
      return rdataLength >= 3 ? readName(bytes, messageStart, rdataStart + 2).name || null : null;
    }
    case 16: {
      // TXT: one or more length-prefixed strings.
      if (rdataLength < 1) return null;
      const textLength = Math.min(bytes[rdataStart], rdataLength - 1);
      return new TextDecoder().decode(bytes.subarray(rdataStart + 1, rdataStart + 1 + textLength));
    }
    case 33:
      // SRV: priority, weight, port, then the target host.
      return rdataLength >= 7 ? readName(bytes, messageStart, rdataStart + 6).name || null : null;
    default:
      return null;
  }
}

/**
 * Builds the Info string for a DNS message starting at `messageStart`.
 * Returns null when the bytes don't parse as DNS, so the caller can fall back
 * to a plain UDP summary.
 */
export function dissectDns(bytes: Uint8Array, messageStart: number): string | null {
  if (messageStart + 12 > bytes.length) return null;

  const transactionId = (bytes[messageStart] << 8) | bytes[messageStart + 1];
  const flags = (bytes[messageStart + 2] << 8) | bytes[messageStart + 3];
  const isResponse = (flags & 0x8000) !== 0;
  const opcode = (flags >> 11) & 0x0f;
  const rcode = flags & 0x0f;
  const questionCount = (bytes[messageStart + 4] << 8) | bytes[messageStart + 5];
  const answerCount = (bytes[messageStart + 6] << 8) | bytes[messageStart + 7];
  const authorityCount = (bytes[messageStart + 8] << 8) | bytes[messageStart + 9];

  const opcodeName = OPCODE_NAMES[opcode];
  if (opcodeName === undefined) return null;

  const parts = [opcodeName + (isResponse ? ' response' : ''), `0x${transactionId.toString(16).padStart(4, '0')}`];

  const rcodeName = isResponse ? RCODE_NAMES[rcode] : undefined;
  if (rcodeName) parts.push(rcodeName);

  let cursor = messageStart + 12;

  // The question section, repeated verbatim by the response.
  for (let i = 0; i < questionCount && cursor < bytes.length; i++) {
    const { name, nextOffset } = readName(bytes, messageStart, cursor);
    cursor = nextOffset;
    if (cursor + 4 > bytes.length) return null;
    const qtype = (bytes[cursor] << 8) | bytes[cursor + 1];
    cursor += 4;
    parts.push(typeName(qtype), name);
  }

  // Answers, then authority records - a negative answer carries its SOA in the
  // authority section, and Wireshark still shows it.
  for (let i = 0; i < answerCount + authorityCount && cursor < bytes.length; i++) {
    const { nextOffset } = readName(bytes, messageStart, cursor);
    cursor = nextOffset;
    if (cursor + 10 > bytes.length) break;
    const type = (bytes[cursor] << 8) | bytes[cursor + 1];
    const rdataLength = (bytes[cursor + 8] << 8) | bytes[cursor + 9];
    const rdataStart = cursor + 10;
    cursor = rdataStart + rdataLength;

    // OPT is the EDNS pseudo-record carrying transport hints, not an answer.
    if (type === 41) continue;

    const rdata = formatRdata(bytes, messageStart, type, rdataStart, rdataLength);
    if (rdata) parts.push(typeName(type), rdata);
  }

  return parts.join(' ');
}
