/**
 * NBNS - the NetBIOS Name Service (RFC 1001/1002), UDP 137.
 *
 *   Name query NB WORKGROUP<00>
 *   Name query response NB 192.0.2.10
 *   Registration NB MYPC<20>
 *
 * It is DNS's wire format with three differences, and every one of them is why
 * this file exists rather than the DNS dissector simply being pointed at
 * port 137 - which is what happened before, and produced
 * `Standard query 0x8f8e TYPE32 FHEPFCELEHFCEPFFFACACACACACACAAA`:
 *
 *   1. **Names are encoded**, RFC 1001 §14.1: sixteen bytes become thirty-two
 *      letters, each nibble added to `A`. So `WORKGROUP` reaches the wire as
 *      `FHEPFCELEHFCEPFFFACACACACACACAAA` and reads as line noise undecoded.
 *      The sixteenth byte is not part of the name at all - it is the **suffix**,
 *      which says what the name IS (`<00>` workstation, `<20>` file server),
 *      and it is the half a reader actually wants.
 *   2. **Its own opcodes.** 5, 6, 7 and 8 are registration, release, WACK and
 *      refresh; DNS has nothing at those numbers, so they printed as
 *      "Dynamic update".
 *   3. **Its own record types**, NB (32) and NBSTAT (33), which DNS renders as
 *      `TYPE32` and whose RDATA - a flags word and an address, repeated - it
 *      does not read, so the addresses never reached name resolution.
 *
 * That third point is why `nbns` was already a `NameSource` in
 * `services/nameResolution.ts` with rank 30 and **no producer anywhere**: the
 * source was declared for a dissector that did not exist yet.
 *
 * Info text and tree rows are matched against `tshark -V` frame by frame in
 * `scripts/nbns/dissect.ts`, which builds its frames from RFC 1002's own
 * layouts and asks tshark what they say.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address } from '../addressFormat';
import { parseDnsMessage, type DnsMessage } from './dnsRecords';

export interface NbnsResult {
  /** Protocol column text. Always `NBNS`. */
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
  /** name -> addresses, for the passive resolution map. */
  resolved: { name: string; addresses: string[] }[];
}

/** RFC 1002 §4.2.1.1. DNS's opcode table means something else at these numbers. */
const OPCODE_NAMES: Record<number, string> = {
  0: 'Name query',
  5: 'Registration',
  6: 'Release',
  7: 'Wait for acknowledgment',
  8: 'Refresh',
};

/** RFC 1002 §4.2.1.2, and Wireshark's spelling of each. */
const RCODE_NAMES: Record<number, string> = {
  0: 'No error',
  1: 'Request was invalidly formatted',
  2: 'Server failure',
  4: 'Unsupported request',
  5: 'Refused',
  6: 'Name is owned by another node',
  7: 'Name is in conflict',
};

/** NBNS's opcodes, for the structural parse. See `parseDnsMessage`'s parameter. */
const isNbnsOpcode = (opcode: number): boolean => OPCODE_NAMES[opcode] !== undefined;

const TYPE_NAMES: Record<number, string> = { 32: 'NB', 33: 'NBSTAT' };

/**
 * What a name's sixteenth byte says the name is for.
 *
 * Wireshark's table, read from tshark one suffix at a time; anything else is
 * `Unknown`, as there. `0x02` really is Workstation/Redirector in it.
 */
const SUFFIX_NAMES: Record<number, string> = {
  0x00: 'Workstation/Redirector', 0x01: 'Browser', 0x02: 'Workstation/Redirector',
  0x03: 'Messenger service/Main name', 0x05: 'Forwarded name', 0x06: 'RAS Server service',
  0x1b: 'Domain Master Browser', 0x1c: 'Domain Controllers', 0x1d: 'Local Master Browser',
  0x1e: 'Browser Election Service', 0x1f: 'Net DDE Service', 0x20: 'Server service', 0x21: 'RAS client service',
  0x22: 'Exchange Interchange (MSMail Connector)', 0x23: 'Exchange Store', 0x24: 'Exchange Directory',
  0x2b: 'Lotus Notes Server service', 0x30: 'Modem sharing server service', 0x31: 'Modem sharing client service',
  0x43: 'SMS Clients Remote Control', 0x44: 'SMS Administrators Remote Control Tool',
  0x45: 'SMS Clients Remote Chat', 0x46: 'SMS Clients Remote Transfer',
  0x4c: 'DEC Pathworks TCP/IP Service on Windows NT', 0x52: 'DEC Pathworks TCP/IP Service on Windows NT',
  0x6a: 'Microsoft Exchange IMC', 0x87: 'Microsoft Exchange MTA', 0xbe: 'Network Monitor Agent',
  0xbf: 'Network Monitor Analyzer',
};

/** What a name's suffix says it is for, in the reference's words. */
export const netbiosSuffixName = (suffix: number): string => SUFFIX_NAMES[suffix] ?? 'Unknown';

export interface NetbiosName {
  /** The trimmed name, without its suffix: `WORKGROUP`. */
  name: string;
  suffix: number;
  /** How it is written everywhere a person reads it: `WORKGROUP<00>`. */
  display: string;
  /** The scope after the first label, when there is one. */
  scope?: string;
}

/**
 * Undoes RFC 1001 §14.1 first-level encoding.
 *
 * Returns null rather than a mangled string when the label is not 32 valid
 * characters - a name that is not encoded this way is not a NetBIOS name, and
 * saying so is what lets the caller decline the whole message.
 */
export function decodeNetbiosName(encoded: string): NetbiosName | null {
  const [label, ...scopeParts] = encoded.split('.');
  if (label.length !== 32) return null;

  const bytes: number[] = [];
  for (let i = 0; i < 32; i += 2) {
    const hi = label.charCodeAt(i) - 0x41;
    const lo = label.charCodeAt(i + 1) - 0x41;
    if (hi < 0 || hi > 15 || lo < 0 || lo > 15) return null;
    bytes.push((hi << 4) | lo);
  }

  const suffix = bytes[15];
  // Trailing spaces are padding to fifteen, not part of the name. Trailing
  // NULs too: some stacks pad with those instead.
  let end = 15;
  while (end > 0 && (bytes[end - 1] === 0x20 || bytes[end - 1] === 0x00)) end--;
  // A byte that does not print is written as its hex in angle brackets, as
  // the reference writes `<01><02>__MSBROWSE__<02>`; so is the suffix, in
  // lower case.
  const name = bytes.slice(0, end).map((c) => (c >= 0x20 && c < 0x7f
    ? String.fromCharCode(c) : `<${c.toString(16).padStart(2, '0')}>`)).join('');
  const scope = scopeParts.length > 0 ? scopeParts.join('.') : undefined;
  const suffixHex = suffix.toString(16).padStart(2, '0');
  return {
    name,
    suffix,
    display: `${name}<${suffixHex}>${scope ? `.${scope}` : ''}`,
    ...(scope ? { scope } : {}),
  };
}

/** The addresses in an NB record: a 2-byte flags word then an address, repeated. */
function nbAddresses(bytes: Uint8Array, start: number, length: number): { flags: number; address: string }[] {
  const out: { flags: number; address: string }[] = [];
  for (let p = start; p + 6 <= start + length && p + 6 <= bytes.length; p += 6) {
    out.push({ flags: (bytes[p] << 8) | bytes[p + 1], address: formatIpv4Address(bytes, p + 2) });
  }
  return out;
}

/** `0x6000, ONT: Unknown (H-node, unique)`, the way Wireshark writes it. */
function nameFlagsSummary(flags: number): string {
  const group = (flags & 0x8000) !== 0;
  const ont = (flags >> 13) & 0x03;
  const ONT = ['B-node', 'P-node', 'M-node', 'Unknown'];
  return `0x${flags.toString(16).padStart(4, '0')}, ONT: ${ONT[ont] === 'Unknown' ? 'Unknown' : ONT[ont]}`
    + ` (${ONT[ont] === 'Unknown' ? 'H-node' : ONT[ont]}, ${group ? 'group' : 'unique'})`;
}

/**
 * True when these bytes are an NBNS message.
 *
 * Structure first, then the encoding: a DNS-shaped header whose first question
 * or record carries a name that decodes as NetBIOS. Both halves are needed -
 * the header alone matches ordinary DNS, and the encoding alone would accept
 * any thirty-two-letter label.
 */
export function looksLikeNbns(bytes: Uint8Array, start: number, end: number): boolean {
  const msg = parseDnsMessage(bytes, start, end, isNbnsOpcode);
  if (msg === null) return false;
  const first = msg.questions[0]?.name ?? msg.records[0]?.name;
  return first !== undefined && decodeNetbiosName(first) !== null;
}

export function dissectNbns(bytes: Uint8Array, start: number, end: number): NbnsResult | null {
  const msg = parseDnsMessage(bytes, start, end, isNbnsOpcode);
  if (msg === null) return null;

  const opcodeName = OPCODE_NAMES[msg.opcode] ?? `Unknown operation (${msg.opcode})`;
  const fields: Record<string, string | number> = {
    'nbns.id': msg.transactionId,
    'nbns.flags': msg.flags,
    'nbns.flags.opcode': msg.opcode,
    'nbns.flags.response': msg.isResponse ? 1 : 0,
    'nbns.flags.rcode': msg.rcode,
    'nbns.count.queries': msg.counts[0],
    'nbns.count.answers': msg.counts[1],
    'nbns.count.auth_rr': msg.counts[2],
    'nbns.count.add_rr': msg.counts[3],
  };

  const resolved: { name: string; addresses: string[] }[] = [];
  // NB or NBSTAT, taken from the message rather than assumed: a node status
  // query is `Name query NBSTAT *<00>`, and hard-coding NB reads as a name
  // lookup for a message that is asking something else entirely.
  const recordType = msg.questions[0]?.type ?? msg.records[0]?.type ?? 32;
  const recordTypeName = TYPE_NAMES[recordType] ?? `Unknown (${recordType})`;
  const layerFields: ProtocolField[] = [
    { name: 'Transaction ID', value: `0x${msg.transactionId.toString(16).padStart(4, '0')}`,
      abbrev: 'nbns.id', rawBytesRange: [start, start + 1] },
    ...flagRows(msg, start),
    { name: 'Questions', value: msg.counts[0], abbrev: 'nbns.count.queries', rawBytesRange: [start + 4, start + 5] },
    { name: 'Answer RRs', value: msg.counts[1], abbrev: 'nbns.count.answers', rawBytesRange: [start + 6, start + 7] },
    { name: 'Authority RRs', value: msg.counts[2], abbrev: 'nbns.count.auth_rr', rawBytesRange: [start + 8, start + 9] },
    { name: 'Additional RRs', value: msg.counts[3], abbrev: 'nbns.count.add_rr', rawBytesRange: [start + 10, start + 11] },
  ];

  // --- questions -----------------------------------------------------------
  const questionRows: ProtocolField[] = [];
  let firstQuestion: NetbiosName | null = null;
  for (const q of msg.questions) {
    const nb = decodeNetbiosName(q.name);
    firstQuestion ??= nb;
    const label = nb?.display ?? q.name;
    const typeName = TYPE_NAMES[q.type] ?? `Unknown (${q.type})`;
    questionRows.push({
      name: `${label}: type ${typeName}, class IN`,
      value: '',
      rawBytesRange: [q.start, Math.max(q.start, q.end - 1)],
      children: [
        { name: 'Name', value: `${label}${nb ? ` (${netbiosSuffixName(nb.suffix)})` : ''}`,
          abbrev: 'nbns.name', rawBytesRange: [q.start, Math.max(q.start, q.nameEnd - 1)] },
        { name: 'Type', value: `${typeName} (${q.type})`, abbrev: 'nbns.type' },
        { name: 'Class', value: `IN (${q.qclass})`, abbrev: 'nbns.class' },
      ],
    });
  }
  if (questionRows.length > 0) {
    layerFields.push({ name: 'Queries', value: '', children: questionRows });
  }
  if (firstQuestion) fields['nbns.name'] = firstQuestion.display;

  // --- answers -------------------------------------------------------------
  const answerRows: ProtocolField[] = [];
  let firstAnswerAddress: string | undefined;
  for (const record of msg.records) {
    const nb = decodeNetbiosName(record.name);
    const label = nb?.display ?? record.name;
    const typeName = TYPE_NAMES[record.type] ?? `Unknown (${record.type})`;
    const children: ProtocolField[] = [
      { name: 'Name', value: `${label}${nb ? ` (${netbiosSuffixName(nb.suffix)})` : ''}`,
        abbrev: 'nbns.name', rawBytesRange: [record.start, Math.max(record.start, record.nameEnd - 1)] },
      { name: 'Type', value: `${typeName} (${record.type})`, abbrev: 'nbns.type' },
      { name: 'Class', value: `IN (${record.rclass})`, abbrev: 'nbns.class' },
      { name: 'Time to live', value: record.ttl, abbrev: 'nbns.ttl' },
      { name: 'Data length', value: record.rdataLength, abbrev: 'nbns.data_length' },
    ];

    if (record.type === 32) {
      const entries = nbAddresses(bytes, record.rdataStart, record.rdataLength);
      for (const entry of entries) {
        children.push(
          { name: 'Name flags', value: nameFlagsSummary(entry.flags), abbrev: 'nbns.nb_flags' },
          { name: 'Addr', value: entry.address, abbrev: 'nbns.addr' },
        );
      }
      if (entries.length > 0) {
        firstAnswerAddress ??= entries[0].address;
        fields['nbns.addr'] = entries[0].address;
        // The whole point of the `nbns` NameSource: a machine answering for its
        // own name, which is a stronger claim than a DNS answer about somebody
        // else's (see the ranking in services/nameResolution.ts).
        if (nb) resolved.push({ name: nb.name, addresses: entries.map((e) => e.address) });
      }
    }

    answerRows.push({
      name: `${label}: type ${typeName}, class IN`,
      value: '',
      rawBytesRange: [record.start, Math.max(record.start, record.end - 1)],
      children,
    });
  }
  if (answerRows.length > 0) {
    layerFields.push({ name: 'Answers', value: '', children: answerRows });
  }

  // A response's name is in its answer; a query's is in its question. Without
  // the second half the field was undefined on every response, which is most
  // of the traffic that carries an address worth resolving.
  if (fields['nbns.name'] === undefined && msg.records.length > 0) {
    const answerName = decodeNetbiosName(msg.records[0].name);
    if (answerName) fields['nbns.name'] = answerName.display;
  }

  return {
    protocolLabel: 'NBNS',
    info: infoLine(msg, opcodeName, recordTypeName, firstQuestion, firstAnswerAddress),
    fields,
    resolved,
    layer: {
      name: 'NetBIOS Name Service',
      summary: 'NetBIOS Name Service',
      rawBytesRange: [start, Math.max(start, Math.min(msg.end, end) - 1)],
      fields: layerFields,
    },
  };
}

/**
 * The Info column.
 *
 * A response names the ADDRESS it answered with, a request names the NAME it
 * asked about - which reads oddly until you notice it is the half that is new
 * in each: the querier already knows the name it sent.
 */
function infoLine(
  msg: DnsMessage,
  opcodeName: string,
  typeName: string,
  question: NetbiosName | null,
  answerAddress: string | undefined,
): string {
  if (msg.isResponse) {
    // The reply code is inserted, not substituted: a refusal still names the
    // address it refused about, which is the half that identifies the clash.
    const head = msg.rcode === 0
      ? `${opcodeName} response`
      : `${opcodeName} response, ${RCODE_NAMES[msg.rcode] ?? `Unknown error (${msg.rcode})`}`;
    return answerAddress !== undefined ? `${head} ${typeName} ${answerAddress}` : head;
  }
  return question !== null ? `${opcodeName} ${typeName} ${question.display}` : opcodeName;
}

/** The Flags word and its bits, in Wireshark's order and wording. */
function flagRows(msg: DnsMessage, start: number): ProtocolField[] {
  const f = msg.flags;
  const bit = (mask: number, label: string, set: string, clear: string): ProtocolField => ({
    name: label, value: (f & mask) !== 0 ? set : clear,
  });
  const parts = [
    msg.isResponse ? 'Response' : 'Request',
    `Opcode: ${OPCODE_NAMES[msg.opcode] ?? `Unknown (${msg.opcode})`}`,
    ...((f & 0x0400) !== 0 ? ['Authoritative'] : []),
    ...((f & 0x0200) !== 0 ? ['Truncated'] : []),
    ...((f & 0x0100) !== 0 ? ['Recursion desired'] : []),
    ...((f & 0x0080) !== 0 ? ['Recursion available'] : []),
    ...((f & 0x0010) !== 0 ? ['Broadcast'] : []),
    `Reply code: ${RCODE_NAMES[msg.rcode] ?? `Unknown (${msg.rcode})`}`,
  ];
  return [{
    name: 'Flags',
    value: `0x${f.toString(16).padStart(4, '0')}, ${parts.join(', ')}`,
    abbrev: 'nbns.flags',
    rawBytesRange: [start + 2, start + 3],
    children: [
      bit(0x8000, 'Response', 'Message is a response', 'Message is a query'),
      { name: 'Opcode', value: `${OPCODE_NAMES[msg.opcode] ?? 'Unknown'} (${msg.opcode})`,
        abbrev: 'nbns.flags.opcode' },
      bit(0x0400, 'Authoritative', 'Server is an authority for domain', 'Server is not an authority for domain'),
      bit(0x0200, 'Truncated', 'Message is truncated', 'Message is not truncated'),
      bit(0x0100, 'Recursion desired', 'Do query recursively', 'Do not do query recursively'),
      bit(0x0080, 'Recursion available', 'Server can do recursive queries', "Server can't do recursive queries"),
      bit(0x0010, 'Broadcast', 'Broadcast packet', 'Not a broadcast packet'),
      { name: 'Reply code', value: `${RCODE_NAMES[msg.rcode] ?? 'Unknown'} (${msg.rcode})`,
        abbrev: 'nbns.flags.rcode' },
    ],
  }];
}
