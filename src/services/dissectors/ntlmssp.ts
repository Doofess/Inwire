/**
 * NTLMSSP (MS-NLMP): how a Windows machine signs in to a file server, a web
 * proxy or an RPC service when Kerberos is not available - a workgroup, an
 * address instead of a name, a machine outside the domain. Three messages:
 *
 *   NTLMSSP_NEGOTIATE                  the client's capabilities
 *   NTLMSSP_CHALLENGE                  the server's challenge, and who it is
 *   NTLMSSP_AUTH, User: CORP\\alice    the client's answer, and who it is
 *
 * It never travels alone. SMB2 carries it in a Session Setup's security blob,
 * usually inside SPNEGO (`dissectors/gssapi.ts`); HTTP in an `Authorization:
 * NTLM` or `Negotiate` header, base64; DCE/RPC in a PDU's auth verifier. Each
 * carrier appends this file's Info to its own, as the reference does.
 *
 * Every row's name, order and format is the reference's, checked against
 * `tshark -T pdml` by `scripts/ntlmssp/dissect.ts`. Four of its rules are not
 * in the specification and were found by asking it:
 *
 * - a string or blob's position is read before its bytes, and where the
 *   first payload begins decides what sits between the fixed fields and it:
 *   a Version only when there is room AND the flags say so, and in an
 *   AUTHENTICATE message eight bytes it calls `Z` when they do not, then a
 *   MIC only when there is room for one;
 * - a Lan Manager response whose bytes 8-24 are zero is an NTLM2 session
 *   response, and its first eight bytes are drawn again as the client's
 *   challenge;
 * - strings are UTF-16 only when the message's own flags say Unicode - a
 *   NEGOTIATE's are always OEM - and an OEM string ends at its first NUL;
 * - a message that ends before a field it declares stops there, and the Info
 *   column says `[Malformed Packet]`.
 *
 * What is shown is what the reference shows. Nothing here derives a key or
 * re-forms a response into anything a password cracker reads.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatArrivalTime } from '../dissect/arrivalTime';
import { hexColons } from '../dissect/hexBytes';

const LAYER_NAME = 'NTLM Secure Service Provider';
const SIGNATURE = [0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00];        // "NTLMSSP\0"

const NEGOTIATE_UNICODE = 0x00000001;
const NEGOTIATE_VERSION = 0x02000000;

const MESSAGE_TYPES: Record<number, string> = {
  1: 'NTLMSSP_NEGOTIATE', 2: 'NTLMSSP_CHALLENGE', 3: 'NTLMSSP_AUTH', 4: 'NTLMSSP_UNKNOWN',
};

type Flag = [mask: number, abbrev: string, name: string];
/** Every bit of the negotiate flags, highest first, as the reference names them. */
const FLAGS: readonly Flag[] = [
  [0x80000000, 'ntlmssp.negotiate56', 'Negotiate 56'],
  [0x40000000, 'ntlmssp.negotiatekeyexch', 'Negotiate Key Exchange'],
  [0x20000000, 'ntlmssp.negotiate128', 'Negotiate 128'],
  [0x10000000, 'ntlmssp.unused10000000', 'Negotiate 0x10000000'],
  [0x08000000, 'ntlmssp.unused08000000', 'Negotiate 0x08000000'],
  [0x04000000, 'ntlmssp.unused04000000', 'Negotiate 0x04000000'],
  [0x02000000, 'ntlmssp.negotiateversion', 'Negotiate Version'],
  [0x01000000, 'ntlmssp.unused01000000', 'Negotiate 0x01000000'],
  [0x00800000, 'ntlmssp.negotiatetargetinfo', 'Negotiate Target Info'],
  [0x00400000, 'ntlmssp.requestnonntsessionkey', 'Request Non-NT Session Key'],
  [0x00200000, 'ntlmssp.unused00200000', 'Negotiate 0x00200000'],
  [0x00100000, 'ntlmssp.negotiateidentify', 'Negotiate Identify'],
  [0x00080000, 'ntlmssp.negotiateextendedsessionsecurity', 'Negotiate Extended Session Security'],
  [0x00040000, 'ntlmssp.unused00040000', 'Negotiate 0x00040000'],
  [0x00020000, 'ntlmssp.targettypeserver', 'Target Type Server'],
  [0x00010000, 'ntlmssp.targettypedomain', 'Target Type Domain'],
  [0x00008000, 'ntlmssp.negotiatealwayssign', 'Negotiate Always Sign'],
  [0x00004000, 'ntlmssp.unused00004000', 'Negotiate 0x00004000'],
  [0x00002000, 'ntlmssp.negotiateoemworkstationsupplied', 'Negotiate OEM Workstation Supplied'],
  [0x00001000, 'ntlmssp.negotiateoemdomainsupplied', 'Negotiate OEM Domain Supplied'],
  [0x00000800, 'ntlmssp.negotiateanonymous', 'Negotiate Anonymous'],
  [0x00000400, 'ntlmssp.unused00000400', 'Negotiate 0x00000400'],
  [0x00000200, 'ntlmssp.negotiatentlm', 'Negotiate NTLM key'],
  [0x00000100, 'ntlmssp.unused00000100', 'Negotiate 0x00000100'],
  [0x00000080, 'ntlmssp.negotiatelmkey', 'Negotiate Lan Manager Key'],
  [0x00000040, 'ntlmssp.negotiatedatagram', 'Negotiate Datagram'],
  [0x00000020, 'ntlmssp.negotiateseal', 'Negotiate Seal'],
  [0x00000010, 'ntlmssp.negotiatesign', 'Negotiate Sign'],
  [0x00000008, 'ntlmssp.unused00000008', 'Request 0x00000008'],
  [0x00000004, 'ntlmssp.requesttarget', 'Request Target'],
  [0x00000002, 'ntlmssp.negotiateoem', 'Negotiate OEM'],
  [0x00000001, 'ntlmssp.negotiateunicode', 'Negotiate UNICODE'],
];

/** AV pair ids (MS-NLMP 2.2.2.1), by the reference's names. */
const AV_NAMES = [
  'End of list', 'NetBIOS computer name', 'NetBIOS domain name', 'DNS computer name', 'DNS domain name',
  'DNS tree name', 'Flags', 'Timestamp', 'Restrictions', 'Target Name', 'Channel Bindings',
];

/**
 * The two places an AV pair list appears, each with its own names for the
 * same eleven fields - written out whole, because every name must be a
 * literal for `scripts/dissect/registry.ts` to find it.
 */
interface AvNames {
  type: string; length: string; typeLabel: string; lengthLabel: string;
  values: Record<number, string>; unknown: string;
}
const TARGET_INFO_NAMES: AvNames = {
  type: 'ntlmssp.challenge.target_info.item.type',
  length: 'ntlmssp.challenge.target_info.item.length',
  typeLabel: 'Target Info Item Type', lengthLabel: 'Target Info Item Length',
  values: {
    1: 'ntlmssp.challenge.target_info.nb_computer_name', 2: 'ntlmssp.challenge.target_info.nb_domain_name',
    3: 'ntlmssp.challenge.target_info.dns_computer_name', 4: 'ntlmssp.challenge.target_info.dns_domain_name',
    5: 'ntlmssp.challenge.target_info.dns_tree_name', 6: 'ntlmssp.challenge.target_info.flags',
    7: 'ntlmssp.challenge.target_info.timestamp', 8: 'ntlmssp.challenge.target_info.restrictions',
    9: 'ntlmssp.challenge.target_info.target_name', 10: 'ntlmssp.challenge.target_info.channel_bindings',
  },
  unknown: 'ntlmssp.target_info_attr.unknown',
};
const RESPONSE_NAMES: AvNames = {
  type: 'ntlmssp.ntlmv2_response.item.type',
  length: 'ntlmssp.ntlmv2_response.item.length',
  typeLabel: 'NTLMV2 Response Item Type', lengthLabel: 'NTLMV2 Response Item Length',
  values: {
    1: 'ntlmssp.ntlmv2_response.nb_computer_name', 2: 'ntlmssp.ntlmv2_response.nb_domain_name',
    3: 'ntlmssp.ntlmv2_response.dns_computer_name', 4: 'ntlmssp.ntlmv2_response.dns_domain_name',
    5: 'ntlmssp.ntlmv2_response.dns_tree_name', 6: 'ntlmssp.ntlmv2_response.flags',
    7: 'ntlmssp.ntlmv2_response.timestamp', 8: 'ntlmssp.ntlmv2_response.restrictions',
    9: 'ntlmssp.ntlmv2_response.target_name', 10: 'ntlmssp.ntlmv2_response.channel_bindings',
  },
  unknown: 'ntlmssp.target_info_attr.unknown',
};
/** The value rows' labels, the same in both lists. */
const AV_LABELS: Record<number, string> = {
  1: 'NetBIOS Computer Name', 2: 'NetBIOS Domain Name', 3: 'DNS Computer Name', 4: 'DNS Domain Name',
  5: 'DNS Tree Name', 6: 'Flags', 7: 'Timestamp', 8: 'Restrictions', 9: 'Target Name', 10: 'Channel Bindings',
};
const AV_TEXT = new Set([1, 2, 3, 4, 5, 9]);

const u16 = (b: Uint8Array, p: number) => b[p] | (b[p + 1] << 8);
const u32 = (b: Uint8Array, p: number) => (b[p] | (b[p + 1] << 8) | (b[p + 2] << 16) | (b[p + 3] << 24)) >>> 0;
const hex = (v: number, digits: number) => `0x${v.toString(16).padStart(digits, '0')}`;

/** A field the message declares and does not hold: the reference's exception. */
class Truncated extends Error {}

function utf16(b: Uint8Array, from: number, length: number): string {
  let out = '';
  for (let p = from; p + 1 < from + length; p += 2) out += String.fromCharCode(u16(b, p));
  return out;
}
/** An OEM string, which ends at its first NUL. */
function oem(b: Uint8Array, from: number, length: number): string {
  let out = '';
  for (let p = from; p < from + length && b[p] !== 0; p++) out += String.fromCharCode(b[p]);
  return out;
}

/** 100 ns since 1601, as a date - UTC or the machine's own zone. */
export function fileTime(b: Uint8Array, p: number, utc: boolean): string {
  const ticks = (BigInt(u32(b, p + 4)) << 32n) | BigInt(u32(b, p));
  const since1970 = ticks - 116_444_736_000_000_000n;
  const us = since1970 / 10n;
  return formatArrivalTime(Number(us), utc, Number(since1970 % 10n) * 100);
}

/** Reads one message, row by row, within `[m, end)`. */
class Reader {
  readonly rows: ProtocolField[] = [];
  readonly fields: Record<string, string | number> = {};
  constructor(readonly b: Uint8Array, readonly m: number, readonly end: number) {}

  need(from: number, length: number): void {
    if (from < this.m || from + length > this.end) throw new Truncated();
  }
  u16(p: number): number { this.need(p, 2); return u16(this.b, p); }
  u32(p: number): number { this.need(p, 4); return u32(this.b, p); }
  bytes(p: number, length: number): string { this.need(p, length); return hexColons(this.b, p, p + length); }

  /** The negotiate flags, each bit a row. */
  flags(p: number): ProtocolField {
    const v = this.u32(p);
    const set = FLAGS.filter(([mask]) => (v & mask) !== 0).map(([, , name]) => `, ${name}`).join('');
    this.fields['ntlmssp.negotiateflags'] = v;
    return {
      name: 'Negotiate Flags', value: `${hex(v, 8)}${set}`, abbrev: 'ntlmssp.negotiateflags', rawBytesRange: [p, p + 3],
      children: FLAGS.map(([mask, abbrev, name]): ProtocolField => ({
        name, value: (v & mask) !== 0 ? 'Set' : 'Not set', abbrev, rawBytesRange: [p, p + 3],
        bitfield: { bitOffset: 31 - Math.log2(mask), bitLength: 1, totalBits: 32 },
      })),
    };
  }

  /**
   * A string named by its (length, maxlen, offset) at `p`. `start` is where
   * its bytes begin, or where they would - the end of the fixed part, for an
   * empty one - which is what decides whether a Version fits before them.
   */
  string(p: number, abbrev: string, label: string, unicode: boolean): { row: ProtocolField; start: number; text: string } {
    const length = this.u16(p);
    const maxlen = this.u16(p + 2);
    const offset = this.u32(p + 4);
    const start = Math.max(offset, p + 8 - this.m);
    if (length === 0) return { row: { name: label, value: 'NULL', abbrev, rawBytesRange: [p, p + 7] }, start, text: '' };
    this.need(this.m + offset, length);
    const text = unicode ? utf16(this.b, this.m + offset, length) : oem(this.b, this.m + offset, length);
    return {
      row: {
        name: label, value: text, abbrev, rawBytesRange: [this.m + offset, this.m + offset + length - 1],
        children: [
          { name: 'Length', value: length, abbrev: 'ntlmssp.string.length', rawBytesRange: [p, p + 1] },
          { name: 'Maxlen', value: maxlen, abbrev: 'ntlmssp.string.maxlen', rawBytesRange: [p + 2, p + 3] },
          { name: 'Offset', value: offset, abbrev: 'ntlmssp.string.offset', rawBytesRange: [p + 4, p + 7] },
        ],
      },
      start, text,
    };
  }

  /** A byte buffer named by its (length, maxlen, offset) at `p`. */
  blob(p: number, abbrev: string, label: string): { row: ProtocolField; start: number; at: number; length: number } {
    const length = this.u16(p);
    const maxlen = this.u16(p + 2);
    const offset = this.u32(p + 4);
    const start = Math.max(offset, p + 8 - this.m);
    if (length === 0) return { row: { name: label, value: 'Empty', abbrev, rawBytesRange: [p, p + 7] }, start, at: this.m + offset, length };
    const at = this.m + offset;
    this.need(at, length);
    return {
      row: {
        name: label, value: hexColons(this.b, at, at + length), abbrev, rawBytesRange: [at, at + length - 1],
        children: [
          { name: 'Length', value: length, abbrev: 'ntlmssp.blob.length', rawBytesRange: [p, p + 1] },
          { name: 'Maxlen', value: maxlen, abbrev: 'ntlmssp.blob.maxlen', rawBytesRange: [p + 2, p + 3] },
          { name: 'Offset', value: offset, abbrev: 'ntlmssp.blob.offset', rawBytesRange: [p + 4, p + 7] },
        ],
      },
      start, at, length,
    };
  }

  version(p: number): ProtocolField {
    this.need(p, 8);
    const [major, minor, build, revision] = [this.b[p], this.b[p + 1], u16(this.b, p + 2), this.b[p + 7]];
    return {
      name: `Version ${major}.${minor} (Build ${build}); NTLM Current Revision ${revision}`, value: '',
      abbrev: 'ntlmssp.version', rawBytesRange: [p, p + 7],
      children: [
        { name: 'Major Version', value: major, abbrev: 'ntlmssp.version.major', rawBytesRange: [p, p] },
        { name: 'Minor Version', value: minor, abbrev: 'ntlmssp.version.minor', rawBytesRange: [p + 1, p + 1] },
        { name: 'Build Number', value: build, abbrev: 'ntlmssp.version.build_number', rawBytesRange: [p + 2, p + 3] },
        { name: 'NTLM Current Revision', value: revision, abbrev: 'ntlmssp.version.ntlm_current_revision', rawBytesRange: [p + 7, p + 7] },
      ],
    };
  }

  /** An AV pair list in `[p, end)`, one heading per pair, through its End of list. */
  avPairs(p: number, end: number, names: AvNames): ProtocolField[] {
    const rows: ProtocolField[] = [];
    while (p + 4 <= end) {
      const type = this.u16(p);
      const length = this.u16(p + 2);
      const typeName = AV_NAMES[type] ?? 'Unknown';
      const children: ProtocolField[] = [
        { name: names.typeLabel, value: `${typeName} (${hex(type, 4)})`, abbrev: names.type, rawBytesRange: [p, p + 1] },
        { name: names.lengthLabel, value: length, abbrev: names.length, rawBytesRange: [p + 2, p + 3] },
      ];
      const at = p + 4;
      if (at + length > end) {
        children.push({
          name: 'Invalid NTLMSSP Target Info AvPairs', value: '', abbrev: 'ntlmssp.target_info_attr.invalid', generated: true,
          expertInfo: { category: 'Note', message: 'Invalid NTLMSSP Target Info AvPairs' },
        });
        rows.push({ name: `Attribute: ${typeName}`, value: '', rawBytesRange: [p, end - 1], children });
        break;
      }
      let heading = `Attribute: ${typeName}`;
      const abbrev = names.values[type];
      const label = AV_LABELS[type];
      if (abbrev !== undefined && label !== undefined) {
        let value: string | number;
        if (AV_TEXT.has(type)) {
          value = utf16(this.b, at, length);
          heading += `: ${value}`;
        } else if (type === 6) value = hex(this.u32(at), 8);
        else if (type === 7) { this.need(at, 8); value = fileTime(this.b, at, false); }
        else value = hexColons(this.b, at, at + length);
        children.push({ name: label, value, abbrev, rawBytesRange: [at, Math.max(at, at + length - 1)] });
      } else if (type !== 0) {
        children.push({
          name: 'Unknown NTLMSSP Target Info Attribute', value: '', abbrev: names.unknown, generated: true,
          expertInfo: { category: 'Note', message: 'Unknown NTLMSSP Target Info Attribute' },
        });
      }
      rows.push({ name: heading, value: '', rawBytesRange: [p, at + length - 1], children });
      p = at + length;
      if (type === 0) break;
    }
    return rows;
  }
}

export interface NtlmsspResult {
  /** What the carrier appends to its Info, after `, `. */
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** Whether a message starts at `start`: the eight-byte signature and a type. */
export function looksLikeNtlmssp(b: Uint8Array, start: number, end: number): boolean {
  if (end - start < 12) return false;
  for (let i = 0; i < SIGNATURE.length; i++) if (b[start + i] !== SIGNATURE[i]) return false;
  return true;
}

/** One NTLMSSP message in `[start, end)`, or null when it is not one. */
export function dissectNtlmssp(b: Uint8Array, start: number, end: number): NtlmsspResult | null {
  if (!looksLikeNtlmssp(b, start, end)) return null;
  const r = new Reader(b, start, end);
  const type = u32(b, start + 8);
  const typeName = MESSAGE_TYPES[type];
  r.fields['ntlmssp.messagetype'] = type;
  r.rows.push(
    { name: 'NTLMSSP identifier', value: 'NTLMSSP', abbrev: 'ntlmssp.identifier', rawBytesRange: [start, start + 7] },
    {
      name: 'NTLM Message Type', value: `${typeName ?? 'Unknown'} (${hex(type, 8)})`, abbrev: 'ntlmssp.messagetype',
      rawBytesRange: [start + 8, start + 11],
      ...(type < 1 || type > 3 ? {
        children: [{
          name: 'Unrecognized NTLMSSP Message', value: '', abbrev: 'ntlmssp.messagetype.unknown', generated: true,
          expertInfo: { category: 'Note', message: 'Unrecognized NTLMSSP Message' },
        }],
      } : {}),
    },
  );
  let info = typeName ?? 'Unknown NTLMSSP message type';
  try {
    if (type === 1) negotiate(r);
    else if (type === 2) challenge(r);
    else if (type === 3) info = authenticate(r);
  } catch (error) {
    if (!(error instanceof Truncated)) throw error;
    info += '[Malformed Packet]';
    r.rows.push({
      name: '[Malformed Packet: NTLMSSP]', value: '', generated: true,
      expertInfo: { category: 'Broken', message: 'Malformed Packet (Exception occurred)' },
    });
  }
  return {
    info,
    fields: r.fields,
    layer: { name: LAYER_NAME, summary: LAYER_NAME, rawBytesRange: [start, end - 1], fields: r.rows },
  };
}

function negotiate(r: Reader): void {
  const m = r.m;
  const flags = r.u32(m + 12);
  r.rows.push(r.flags(m + 12));
  // A NEGOTIATE's two strings are OEM whatever the flags say.
  const domain = r.string(m + 16, 'ntlmssp.negotiate.domain', 'Calling workstation domain', false);
  r.rows.push(domain.row);
  const host = r.string(m + 24, 'ntlmssp.negotiate.callingworkstation', 'Calling workstation name', false);
  r.rows.push(host.row);
  if (32 < Math.min(domain.start, host.start) && (flags & NEGOTIATE_VERSION) !== 0) r.rows.push(r.version(m + 32));
}

function challenge(r: Reader): void {
  const m = r.m;
  const flags = r.u32(m + 20);
  const target = r.string(m + 12, 'ntlmssp.challenge.target_name', 'Target Name', (flags & NEGOTIATE_UNICODE) !== 0);
  r.rows.push(target.row);
  if (target.text !== '') r.fields['ntlmssp.challenge.target_name'] = target.text;
  let dataStart = target.start;
  r.rows.push(r.flags(m + 20));
  r.rows.push({ name: 'NTLM Server Challenge', value: r.bytes(m + 24, 8), abbrev: 'ntlmssp.ntlmserverchallenge', rawBytesRange: [m + 24, m + 31] });
  r.rows.push({ name: 'Reserved', value: r.bytes(m + 32, 8), abbrev: 'ntlmssp.reserved', rawBytesRange: [m + 32, m + 39] });
  let offset = 40;
  if (offset < dataStart) {
    const p = m + 40;
    const length = r.u16(p);
    const maxlen = r.u16(p + 2);
    const at = r.u32(p + 4);
    r.need(m + at, length);
    dataStart = Math.min(dataStart, Math.max(at, 48));
    r.rows.push({
      name: 'Target Info', value: '', abbrev: 'ntlmssp.challenge.target_info', rawBytesRange: [p, p + 7],
      children: [
        { name: 'Length', value: length, abbrev: 'ntlmssp.challenge.target_info.length', rawBytesRange: [p, p + 1] },
        { name: 'Maxlen', value: maxlen, abbrev: 'ntlmssp.challenge.target_info.maxlen', rawBytesRange: [p + 2, p + 3] },
        { name: 'Offset', value: at, abbrev: 'ntlmssp.challenge.target_info.offset', rawBytesRange: [p + 4, p + 7] },
        ...r.avPairs(m + at, m + at + length, TARGET_INFO_NAMES),
      ],
    });
    offset = 48;
  }
  if (offset < dataStart && (flags & NEGOTIATE_VERSION) !== 0) r.rows.push(r.version(m + offset));
}

/** Returns the Info: the message type and who signed in. */
function authenticate(r: Reader): string {
  const m = r.m;
  const flags = r.u32(m + 60);
  const unicode = (flags & NEGOTIATE_UNICODE) !== 0;
  const lm = r.blob(m + 12, 'ntlmssp.auth.lmresponse', 'Lan Manager Response');
  r.rows.push(lm.row);
  // An NTLM2 session response: the client's challenge, then sixteen zeros.
  if (lm.length > 0 && lm.at + 24 <= r.end && r.b.subarray(lm.at + 8, lm.at + 24).every((x) => x === 0)) {
    r.rows.push({ name: 'LMv2 Client Challenge', value: hexColons(r.b, lm.at, lm.at + 8), abbrev: 'ntlmssp.ntlmclientchallenge', rawBytesRange: [lm.at, lm.at + 7] });
  }
  const nt = r.blob(m + 20, 'ntlmssp.auth.ntresponse', 'NTLM Response');
  if (nt.length > 24) nt.row.children!.push(ntlmv2Response(r, nt.at, nt.length));
  r.rows.push(nt.row);
  const domain = r.string(m + 28, 'ntlmssp.auth.domain', 'Domain name', unicode);
  r.rows.push(domain.row);
  const user = r.string(m + 36, 'ntlmssp.auth.username', 'User name', unicode);
  r.rows.push(user.row);
  const host = r.string(m + 44, 'ntlmssp.auth.hostname', 'Host name', unicode);
  r.rows.push(host.row);
  const key = r.blob(m + 52, 'ntlmssp.auth.sesskey', 'Session Key');
  r.rows.push(key.row);
  r.fields['ntlmssp.auth.domain'] = domain.text;
  r.fields['ntlmssp.auth.username'] = user.text;
  r.fields['ntlmssp.auth.hostname'] = host.text;
  const info = `NTLMSSP_AUTH, User: ${domain.text}\\\\${user.text}`;
  r.rows.push(r.flags(m + 60));
  const dataStart = Math.min(lm.start, nt.start, domain.start, user.start, host.start, key.start);
  let offset = 64;
  if (offset < dataStart) {
    r.rows.push((flags & NEGOTIATE_VERSION) !== 0
      ? r.version(m + offset)
      : { name: 'Z', value: r.bytes(m + offset, 8), abbrev: 'ntlmssp.ntlmv2_response.z', rawBytesRange: [m + offset, m + offset + 7] });
    offset += 8;
  }
  if (offset < dataStart) {
    r.rows.push({ name: 'MIC', value: r.bytes(m + offset, 16), abbrev: 'ntlmssp.authenticate.mic', rawBytesRange: [m + offset, m + offset + 15] });
  }
  return info;
}

/** An NTLMv2 response: the proof, then the client's blob and its AV pairs. */
function ntlmv2Response(r: Reader, at: number, length: number): ProtocolField {
  const end = at + length;
  r.need(at, 44);
  const children: ProtocolField[] = [
    { name: 'NTProofStr', value: hexColons(r.b, at, at + 16), abbrev: 'ntlmssp.ntlmv2_response.ntproofstr', rawBytesRange: [at, at + 15] },
    { name: 'Response Version', value: r.b[at + 16], abbrev: 'ntlmssp.ntlmv2_response.rversion', rawBytesRange: [at + 16, at + 16] },
    { name: 'Hi Response Version', value: r.b[at + 17], abbrev: 'ntlmssp.ntlmv2_response.hirversion', rawBytesRange: [at + 17, at + 17] },
    { name: 'Z', value: hexColons(r.b, at + 18, at + 24), abbrev: 'ntlmssp.ntlmv2_response.z', rawBytesRange: [at + 18, at + 23] },
    { name: 'Time', value: fileTime(r.b, at + 24, true), abbrev: 'ntlmssp.ntlmv2_response.time', rawBytesRange: [at + 24, at + 31] },
    { name: 'NTLMv2 Client Challenge', value: hexColons(r.b, at + 32, at + 40), abbrev: 'ntlmssp.ntlmv2_response.chal', rawBytesRange: [at + 32, at + 39] },
    { name: 'Z', value: hexColons(r.b, at + 40, at + 44), abbrev: 'ntlmssp.ntlmv2_response.z', rawBytesRange: [at + 40, at + 43] },
  ];
  const pairs = r.avPairs(at + 44, end, RESPONSE_NAMES);
  children.push(...pairs);
  const last = pairs.at(-1)?.rawBytesRange?.[1];
  const after = last === undefined ? at + 44 : last + 1;
  if (after < end) {
    children.push({ name: 'padding', value: hexColons(r.b, after, end), abbrev: 'ntlmssp.ntlmv2_response.pad', rawBytesRange: [after, end - 1] });
  }
  return { name: 'NTLMv2 Response', value: hexColons(r.b, at, end), abbrev: 'ntlmssp.ntlmv2_response', rawBytesRange: [at, end - 1], children };
}

/**
 * A sixteen-byte NTLMSSP signature - what follows a signed DCE/RPC PDU, and
 * SPNEGO's mechListMIC once NTLM was chosen: version 1, then the checksum and
 * sequence number, which the reference draws as one body.
 */
export function ntlmsspVerifier(b: Uint8Array, start: number, end: number): ProtocolField | null {
  if (end - start !== 16 || u32(b, start) !== 1) return null;
  return {
    name: 'NTLMSSP Verifier', value: '', abbrev: 'ntlmssp.verf', rawBytesRange: [start, end - 1],
    children: [
      { name: 'Version Number', value: 1, abbrev: 'ntlmssp.verf.vers', rawBytesRange: [start, start + 3] },
      { name: 'Verifier Body', value: hexColons(b, start + 4, end), abbrev: 'ntlmssp.verf.body', rawBytesRange: [start + 4, end - 1] },
    ],
  };
}
