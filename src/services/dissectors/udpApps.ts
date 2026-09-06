/**
 * NTP and STUN, and recognising them by what they are rather than where they are.
 *
 * Both are dispatched by port everywhere else in this file's neighbours, and
 * both routinely appear somewhere else. STUN in particular is the protocol a
 * WebRTC call uses to find itself, and it runs on whatever port the ICE
 * candidate happened to get - a port-only dispatch labels every one of those
 * frames "UDP" and shows a length. STUN is trivial to recognise by content: RFC
 * 5389 put a fixed 32-bit magic cookie in the header precisely so that a
 * middlebox could tell STUN from anything else sharing its port.
 *
 * NTP is recognised more cautiously. It has no magic number, so the check is a
 * conjunction of things that are individually weak - an exact length, a version
 * in range, a mode that is one of the defined ones, a plausible stratum - and
 * it is only consulted when the port already suggests NTP or nothing else has
 * claimed the payload.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

/**
 * One decoder, not one per call. `new TextDecoder()` is not free, and these
 * sites are per-field / per-frame - a CPU profile put TextDecoder construction
 * at 8% of a dissection run. It carries no state across `decode()` calls unless
 * `{stream: true}` is used, which nothing here does, so a shared instance is
 * exactly equivalent. `new TextDecoder()` and
 * `new TextDecoder('utf-8', {fatal: false})` are the same thing: utf-8,
 * non-fatal, is the default.
 */
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

export interface UdpAppResult {
  protocolLabel: string;
  info: string;
  fields: Record<string, string | number>;
  layer: ProtocolLayer;
  /** The frameProtocols token this contributes. */
  token: string;
}

// --- NTP -----------------------------------------------------------------------

const NTP_MODES: Record<number, string> = {
  0: 'reserved',
  1: 'symmetric active',
  2: 'symmetric passive',
  3: 'client',
  4: 'server',
  5: 'broadcast',
  6: 'reserved for NTP control message',
  7: 'reserved for private use',
};

const LEAP_INDICATOR: Record<number, string> = {
  0: 'no warning',
  1: 'last minute of the day has 61 seconds',
  2: 'last minute of the day has 59 seconds',
  3: 'unknown (clock unsynchronized)',
};

/** The NTP era began on 1 Jan 1900; the Unix epoch is 70 years later. */
const NTP_EPOCH_OFFSET_SECONDS = 2_208_988_800;

function ntpTimestamp(bytes: Uint8Array, at: number): string {
  const seconds = ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
  const fraction = ((bytes[at + 4] << 24) | (bytes[at + 5] << 16) | (bytes[at + 6] << 8) | bytes[at + 7]) >>> 0;
  if (seconds === 0 && fraction === 0) return 'NULL';
  const millis = (seconds - NTP_EPOCH_OFFSET_SECONDS) * 1000 + Math.round((fraction / 2 ** 32) * 1000);
  return new Date(millis).toISOString().replace('T', ' ').replace('Z', ' UTC');
}

/** A 16.16 or 32.32 fixed-point field, as seconds. */
function shortFixed(bytes: Uint8Array, at: number): number {
  const whole = (bytes[at] << 8) | bytes[at + 1];
  const frac = (bytes[at + 2] << 8) | bytes[at + 3];
  return whole + frac / 65536;
}

/**
 * True when these bytes could plausibly be an NTP message.
 *
 * Deliberately strict, because NTP has no magic number and the alternative to
 * strictness is labelling arbitrary UDP payloads "NTP".
 */
export function looksLikeNtp(bytes: Uint8Array, start: number, end: number): boolean {
  if (end - start !== 48) return false; // a mode 1-5 message is exactly 48 bytes
  const first = bytes[start];
  const version = (first >> 3) & 0x7;
  const mode = first & 0x7;
  if (version < 1 || version > 4) return false;
  if (mode < 1 || mode > 5) return false;
  const stratum = bytes[start + 1];
  return stratum <= 16;
}

export function dissectNtp(bytes: Uint8Array, start: number, end: number): UdpAppResult | null {
  if (end - start < 48 || start + 48 > bytes.length) return null;
  const first = bytes[start];
  const leap = (first >> 6) & 0x3;
  const version = (first >> 3) & 0x7;
  const mode = first & 0x7;
  const stratum = bytes[start + 1];
  const poll = bytes[start + 2] > 127 ? bytes[start + 2] - 256 : bytes[start + 2];
  const precision = bytes[start + 3] > 127 ? bytes[start + 3] - 256 : bytes[start + 3];

  // The reference id is four ASCII characters on stratum 0 and 1 ("GPS", "PPS",
  // "INIT") and an IPv4 address above that.
  const refBytes = bytes.slice(start + 12, start + 16);
  const referenceId = stratum <= 1
    ? Array.from(refBytes).filter((b) => b !== 0).map((b) => String.fromCharCode(b)).join('')
    : `${refBytes[0]}.${refBytes[1]}.${refBytes[2]}.${refBytes[3]}`;

  const modeName = NTP_MODES[mode] ?? `unknown (${mode})`;
  const info = `NTP Version ${version}, ${modeName}`;

  const fields: ProtocolField[] = [
    {
      name: 'Flags',
      value: `0x${first.toString(16).padStart(2, '0')}`,
      rawBytesRange: [start, start],
      children: [
        { name: 'Leap Indicator', value: `${LEAP_INDICATOR[leap]} (${leap})`, rawBytesRange: [start, start] },
        { name: 'Version number', value: `NTP Version ${version}`, abbrev: 'ntp.flags.vn', rawBytesRange: [start, start] },
        { name: 'Mode', value: `${modeName} (${mode})`, abbrev: 'ntp.flags.mode', rawBytesRange: [start, start] },
      ],
    },
    { name: 'Peer Clock Stratum', value: stratumName(stratum), abbrev: 'ntp.stratum', rawBytesRange: [start + 1, start + 1] },
    { name: 'Peer Polling Interval', value: `${poll} (${2 ** poll} seconds)`, rawBytesRange: [start + 2, start + 2] },
    { name: 'Peer Clock Precision', value: `${precision} (${(2 ** precision).toExponential(3)} seconds)`, rawBytesRange: [start + 3, start + 3] },
    { name: 'Root Delay', value: `${shortFixed(bytes, start + 4).toFixed(6)} seconds`, rawBytesRange: [start + 4, start + 7] },
    { name: 'Root Dispersion', value: `${shortFixed(bytes, start + 8).toFixed(6)} seconds`, rawBytesRange: [start + 8, start + 11] },
    { name: 'Reference ID', value: referenceId, rawBytesRange: [start + 12, start + 15] },
    { name: 'Reference Timestamp', value: ntpTimestamp(bytes, start + 16), rawBytesRange: [start + 16, start + 23] },
    { name: 'Origin Timestamp', value: ntpTimestamp(bytes, start + 24), rawBytesRange: [start + 24, start + 31] },
    { name: 'Receive Timestamp', value: ntpTimestamp(bytes, start + 32), rawBytesRange: [start + 32, start + 39] },
    { name: 'Transmit Timestamp', value: ntpTimestamp(bytes, start + 40), rawBytesRange: [start + 40, start + 47] },
  ];

  return {
    protocolLabel: 'NTP',
    info,
    fields: { 'ntp.flags.mode': mode, 'ntp.flags.vn': version, 'ntp.stratum': stratum },
    token: 'ntp',
    layer: {
      name: 'Network Time Protocol',
      summary: `Network Time Protocol (${modeName})`,
      rawBytesRange: [start, start + 47],
      fields,
    },
  };
}

function stratumName(stratum: number): string {
  if (stratum === 0) return 'unspecified or invalid (0)';
  if (stratum === 1) return 'primary reference (1)';
  if (stratum <= 15) return `secondary reference (${stratum})`;
  return `unsynchronized (${stratum})`;
}

// --- STUN ------------------------------------------------------------------------

/** RFC 5389's fixed cookie, which is what makes STUN recognisable at all. */
const STUN_MAGIC_COOKIE = 0x2112a442;

const STUN_METHODS: Record<number, string> = {
  0x001: 'Binding',
  0x003: 'Allocate',
  0x004: 'Refresh',
  0x006: 'Send',
  0x007: 'Data',
  0x008: 'CreatePermission',
  0x009: 'ChannelBind',
};

const STUN_CLASSES = ['Request', 'Indication', 'Success Response', 'Error Response'];

const STUN_ATTRIBUTES: Record<number, string> = {
  0x0001: 'MAPPED-ADDRESS',
  0x0006: 'USERNAME',
  0x0008: 'MESSAGE-INTEGRITY',
  0x0009: 'ERROR-CODE',
  0x000a: 'UNKNOWN-ATTRIBUTES',
  0x0014: 'REALM',
  0x0015: 'NONCE',
  0x0020: 'XOR-MAPPED-ADDRESS',
  0x0024: 'PRIORITY',
  0x0025: 'USE-CANDIDATE',
  0x8022: 'SOFTWARE',
  0x8023: 'ALTERNATE-SERVER',
  0x8028: 'FINGERPRINT',
  0x8029: 'ICE-CONTROLLED',
  0x802a: 'ICE-CONTROLLING',
};

/**
 * True when these bytes are STUN.
 *
 * Three independent checks, which is why this one can be trusted on any port:
 * the two most significant bits of the message type are zero, the magic cookie
 * is exactly right, and the declared length agrees with what is present and is
 * a multiple of four.
 */
export function looksLikeStun(bytes: Uint8Array, start: number, end: number): boolean {
  if (end - start < 20 || start + 20 > bytes.length) return false;
  if ((bytes[start] & 0xc0) !== 0) return false;
  const cookie = ((bytes[start + 4] << 24) | (bytes[start + 5] << 16)
    | (bytes[start + 6] << 8) | bytes[start + 7]) >>> 0;
  if (cookie !== STUN_MAGIC_COOKIE) return false;
  const length = (bytes[start + 2] << 8) | bytes[start + 3];
  return length % 4 === 0 && start + 20 + length <= end;
}

export function dissectStun(bytes: Uint8Array, start: number, end: number): UdpAppResult | null {
  if (!looksLikeStun(bytes, start, end)) return null;

  const messageType = (bytes[start] << 8) | bytes[start + 1];
  const length = (bytes[start + 2] << 8) | bytes[start + 3];
  // The method and the class are interleaved through the 14 type bits, which
  // is the price RFC 5389 paid for keeping the two leading zero bits.
  const method = ((messageType & 0x3e00) >> 2) | ((messageType & 0x00e0) >> 1) | (messageType & 0x000f);
  const messageClass = ((messageType & 0x0100) >> 7) | ((messageType & 0x0010) >> 4);
  const transactionId = Array.from(bytes.slice(start + 8, start + 20))
    .map((b) => b.toString(16).padStart(2, '0')).join('');

  const methodName = STUN_METHODS[method] ?? `Unknown (0x${method.toString(16)})`;
  const info = `${methodName} ${STUN_CLASSES[messageClass]}`;

  const fields: ProtocolField[] = [
    { name: 'Message Type', value: `0x${messageType.toString(16).padStart(4, '0')} (${info})`, abbrev: 'stun.type', rawBytesRange: [start, start + 1] },
    { name: 'Message Length', value: length, rawBytesRange: [start + 2, start + 3] },
    { name: 'Message Cookie', value: '2112a442', rawBytesRange: [start + 4, start + 7] },
    { name: 'Message Transaction ID', value: transactionId, rawBytesRange: [start + 8, start + 19] },
  ];

  // Attributes are TLVs padded to a 4-byte boundary. Only the addresses are
  // opened up - they are the ones that say what the exchange discovered.
  const attributes: ProtocolField[] = [];
  let at = start + 20;
  const attrEnd = Math.min(end, start + 20 + length, bytes.length);
  while (at + 4 <= attrEnd) {
    const type = (bytes[at] << 8) | bytes[at + 1];
    const attrLen = (bytes[at + 2] << 8) | bytes[at + 3];
    const valueEnd = at + 4 + attrLen;
    if (valueEnd > attrEnd) break;
    const name = STUN_ATTRIBUTES[type] ?? `Unknown (0x${type.toString(16).padStart(4, '0')})`;
    const attribute: ProtocolField = {
      name,
      value: `${attrLen} byte${attrLen === 1 ? '' : 's'}`,
      rawBytesRange: [at, valueEnd - 1],
    };

    if ((type === 0x0020 || type === 0x0001) && attrLen >= 8) {
      // XOR-MAPPED-ADDRESS hides the address behind the cookie, so that a NAT
      // rewriting payloads by pattern-matching its own addresses would not
      // silently corrupt it. Unmasking it is the whole point of reading it.
      const family = bytes[at + 5];
      const xor = type === 0x0020;
      const port = ((bytes[at + 6] << 8) | bytes[at + 7]) ^ (xor ? 0x2112 : 0);
      let address = '';
      if (family === 0x01) {
        const cookieBytes = [0x21, 0x12, 0xa4, 0x42];
        address = Array.from(bytes.slice(at + 8, at + 12))
          .map((b, i) => b ^ (xor ? cookieBytes[i] : 0)).join('.');
      } else if (family === 0x02 && attrLen >= 20) {
        const mask = bytes.slice(start + 4, start + 20); // cookie + transaction id
        const raw = Array.from(bytes.slice(at + 8, at + 24)).map((b, i) => b ^ (xor ? mask[i] : 0));
        address = raw.reduce((acc: string[], b, i) => {
          if (i % 2 === 0) acc.push(b.toString(16).padStart(2, '0'));
          else acc[acc.length - 1] += b.toString(16).padStart(2, '0');
          return acc;
        }, []).join(':');
      }
      attribute.value = `${address}:${port}`;
      attribute.children = [
        { name: 'Protocol Family', value: family === 0x01 ? 'IPv4 (0x01)' : 'IPv6 (0x02)', rawBytesRange: [at + 5, at + 5] },
        { name: 'Port', value: port, rawBytesRange: [at + 6, at + 7] },
        { name: 'IP', value: address, rawBytesRange: [at + 8, valueEnd - 1] },
      ];
    } else if (type === 0x8022 || type === 0x0006 || type === 0x0014) {
      attribute.value = utf8Decoder.decode(bytes.slice(at + 4, valueEnd)).replace(/\0+$/, '');
    }

    attributes.push(attribute);
    at = valueEnd + ((4 - (attrLen % 4)) % 4);
  }
  if (attributes.length > 0) {
    fields.push({ name: 'Attributes', value: '', rawBytesRange: [start + 20, attrEnd - 1], children: attributes });
  }

  return {
    protocolLabel: 'STUN',
    info,
    fields: { 'stun.type': messageType },
    token: 'stun',
    layer: {
      name: 'Session Traversal Utilities for NAT',
      summary: `Session Traversal Utilities for NAT, ${info}`,
      rawBytesRange: [start, Math.min(bytes.length, start + 20 + length) - 1],
      fields,
    },
  };
}

// `dissectUdpByContent` used to live here as a two-line `if` chain over STUN
// and NTP - the whole of this app's content-based dispatch. It is
// `dissectors/heuristics.ts` now, which holds seven detectors and, more to the
// point, an assertion that each rejects every other's payloads.

