/**
 * RADIUS (RFC 2865/2866), UDP 1812/1813 and the older 1645/1646.
 *
 *   Access-Request id=42
 *   Access-Accept id=42
 *
 * Who was allowed onto the network, and who was not. On a capture from a
 * wireless controller or a VPN concentrator this is the authentication story,
 * and it was reaching the list as `50000 → 1812 Len=45`.
 *
 * The header is fixed and tiny - code, identifier, length, and a 16-byte
 * authenticator - followed by type/length/value attributes. Two things about
 * those attributes are worth knowing:
 *
 *   - **The length byte counts itself and the type byte**, so the value is
 *     `length - 2` bytes. Reading it as the value's own length walks the
 *     parser two bytes further every attribute and turns a well-formed packet
 *     into garbage a third of the way in.
 *   - **User-Password is encrypted** with the shared secret and the request
 *     authenticator, so its bytes are not a password and must not be rendered
 *     as text. It is shown as its length only. Nothing here can decrypt it and
 *     nothing here pretends to.
 */
import { ProtocolField, ProtocolLayer } from '../../types/packet';
import { formatIpv4Address, toHex } from '../addressFormat';

export interface RadiusResult {
  protocolLabel: string;
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** RFC 2865 §3 and RFC 2866 §3, in Wireshark's spelling. */
const CODE_NAMES: Record<number, string> = {
  1: 'Access-Request',
  2: 'Access-Accept',
  3: 'Access-Reject',
  4: 'Accounting-Request',
  5: 'Accounting-Response',
  11: 'Access-Challenge',
  12: 'Status-Server',
  13: 'Status-Client',
  40: 'Disconnect-Request',
  41: 'Disconnect-ACK',
  42: 'Disconnect-NAK',
  43: 'CoA-Request',
  44: 'CoA-ACK',
  45: 'CoA-NAK',
};

/** The attributes worth naming. Anything else renders as its number. */
const ATTRIBUTE_NAMES: Record<number, string> = {
  1: 'User-Name', 2: 'User-Password', 3: 'CHAP-Password', 4: 'NAS-IP-Address',
  5: 'NAS-Port', 6: 'Service-Type', 7: 'Framed-Protocol', 8: 'Framed-IP-Address',
  9: 'Framed-IP-Netmask', 11: 'Filter-Id', 12: 'Framed-MTU', 18: 'Reply-Message',
  24: 'State', 25: 'Class', 26: 'Vendor-Specific', 27: 'Session-Timeout',
  28: 'Idle-Timeout', 30: 'Called-Station-Id', 31: 'Calling-Station-Id',
  32: 'NAS-Identifier', 40: 'Acct-Status-Type', 44: 'Acct-Session-Id',
  61: 'NAS-Port-Type', 79: 'EAP-Message', 80: 'Message-Authenticator',
  87: 'NAS-Port-Id',
};

/** Attributes whose value is a 32-bit integer rather than text or an address. */
const INTEGER_ATTRIBUTES = new Set([5, 6, 7, 12, 27, 28, 40, 61]);
/** Attributes whose value is an IPv4 address. */
const ADDRESS_ATTRIBUTES = new Set([4, 8, 9]);
/**
 * Attributes whose bytes must never be rendered as text.
 *
 * User-Password and CHAP-Password are the credential; State and Class are
 * opaque server cookies that are frequently binary. Showing a length is the
 * whole of what is safe and the whole of what is useful.
 */
const OPAQUE_ATTRIBUTES = new Set([2, 3, 24, 25, 80]);

const utf8 = new TextDecoder('utf-8', { fatal: false });

const RADIUS_HEADER_BYTES = 20;

/**
 * True when these bytes are a RADIUS message.
 *
 * A known code, and a length field that matches the payload exactly. The
 * length check is what makes this specific: a random datagram whose first byte
 * happens to be 1 will almost never also declare its own size correctly.
 */
export function looksLikeRadius(bytes: Uint8Array, start: number, end: number): boolean {
  if (end - start < RADIUS_HEADER_BYTES) return false;
  if (CODE_NAMES[bytes[start]] === undefined) return false;
  const declared = (bytes[start + 2] << 8) | bytes[start + 3];
  return declared === end - start && declared >= RADIUS_HEADER_BYTES;
}

export function dissectRadius(bytes: Uint8Array, start: number, end: number): RadiusResult | null {
  if (end - start < RADIUS_HEADER_BYTES) return null;
  const code = bytes[start];
  const identifier = bytes[start + 1];
  const declared = (bytes[start + 2] << 8) | bytes[start + 3];
  if (declared < RADIUS_HEADER_BYTES) return null;

  const codeName = CODE_NAMES[code] ?? `Unknown (${code})`;
  const messageEnd = Math.min(end, start + declared);
  const authenticator = toHex(bytes.subarray(start + 4, start + 20));

  const fields: Record<string, string | number> = {
    'radius.code': code,
    'radius.id': identifier,
    'radius.length': declared,
    'radius.authenticator': authenticator,
  };

  const attributeRows: ProtocolField[] = [];
  let p = start + RADIUS_HEADER_BYTES;
  while (p + 2 <= messageEnd) {
    const type = bytes[p];
    // Counts the type and length bytes themselves - see the header comment.
    const length = bytes[p + 1];
    if (length < 2 || p + length > messageEnd) break;
    const valueStart = p + 2;
    const valueEnd = p + length;
    const name = ATTRIBUTE_NAMES[type] ?? `Unknown Attribute (${type})`;
    attributeRows.push({
      name: `AVP: t=${name}(${type}) l=${length}`,
      value: describeValue(bytes, type, valueStart, valueEnd),
      rawBytesRange: [p, valueEnd - 1],
      children: [
        { name: 'Type', value: `${name} (${type})`, abbrev: 'radius.avp.type' },
        { name: 'Length', value: length, abbrev: 'radius.avp.length' },
      ],
    });
    // The first User-Name is what makes a RADIUS capture readable at a glance.
    if (type === 1 && fields['radius.username'] === undefined) {
      fields['radius.username'] = utf8.decode(bytes.subarray(valueStart, valueEnd));
    }
    p = valueEnd;
  }

  const layerFields: ProtocolField[] = [
    { name: 'Code', value: `${codeName} (${code})`, abbrev: 'radius.code', rawBytesRange: [start, start] },
    { name: 'Packet identifier', value: `0x${identifier.toString(16).padStart(2, '0')} (${identifier})`,
      abbrev: 'radius.id', rawBytesRange: [start + 1, start + 1] },
    { name: 'Length', value: declared, abbrev: 'radius.length', rawBytesRange: [start + 2, start + 3] },
    { name: 'Authenticator', value: authenticator, abbrev: 'radius.authenticator',
      rawBytesRange: [start + 4, start + 19] },
  ];
  if (attributeRows.length > 0) {
    layerFields.push({ name: 'Attribute Value Pairs', value: '', children: attributeRows });
  }

  return {
    protocolLabel: 'RADIUS',
    info: `${codeName} id=${identifier}`,
    fields,
    layer: {
      name: 'RADIUS Protocol',
      summary: `RADIUS Protocol (${codeName})`,
      rawBytesRange: [start, Math.max(start, messageEnd - 1)],
      fields: layerFields,
    },
  };
}

function describeValue(bytes: Uint8Array, type: number, start: number, end: number): string {
  if (OPAQUE_ATTRIBUTES.has(type)) return `${end - start} bytes`;
  if (ADDRESS_ATTRIBUTES.has(type) && end - start === 4) return formatIpv4Address(bytes, start);
  if (INTEGER_ATTRIBUTES.has(type) && end - start === 4) {
    return String(((bytes[start] << 24) | (bytes[start + 1] << 16)
      | (bytes[start + 2] << 8) | bytes[start + 3]) >>> 0);
  }
  return utf8.decode(bytes.subarray(start, end));
}
