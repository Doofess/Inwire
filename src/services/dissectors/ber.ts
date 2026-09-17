/**
 * BER - the encoding half of ASN.1, as used by SNMP, LDAP and Kerberos.
 *
 * X.509 is the fourth protocol built on it and does **not** come through here:
 * `dissectors/x509.ts` keeps its own walker, because `berChildren`'s 128-child
 * cap would truncate a certificate's subjectAltName list. That file's `readTlv`
 * says so; the two must not diverge on OIDs or on lengths.
 *
 * A reader, not a schema engine. Every value is a tag, a length and a body,
 * and this walks that structure and nothing else: it does not know what an
 * SNMP PDU is, and it will not tell you whether a message is well-formed
 * against a module definition. Its callers know their own grammar.
 *
 * The pieces that are easy to get subtly wrong, and are therefore what
 * `scripts/snmp/dissect.ts` pins:
 *
 *   - **Long-form lengths.** A length byte under 0x80 is the length. `0x80|n`
 *     means the next `n` bytes are, big-endian. A reader that handles only the
 *     short form is right for every value under 128 bytes and wrong for the
 *     first large OCTET STRING it meets, which on SNMP is a system description
 *     and on LDAP is most of the traffic.
 *   - **Object identifiers.** Every group is base-128 with a continuation bit,
 *     and the FIRST group is then split into two arcs as `40 * x + y`. The
 *     first group is one byte on almost every OID in practice, so reading it
 *     as a single byte is right until it is not: `2.100.3` encodes its first
 *     group as 180 across two bytes and decodes to `2.49.52` that way - a
 *     plausible OID that is not the one on the wire.
 *   - **Integers are signed and minimal.** A leading `0x00` is padding that
 *     keeps a large positive value from reading as negative, and dropping it
 *     turns `0x00ff` into -1.
 *
 * Indefinite lengths (`0x80` with no count, terminated by two zero bytes) are
 * deliberately **not** supported: BER permits them, DER forbids them, and none
 * of the protocols here emit them. A reader that guessed at them would be
 * guessing on the one input where being wrong is silent.
 */

/** Universal tag numbers worth naming. The rest are reported as their number. */
export const BER_TAG = {
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  OID: 0x06,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

export interface BerValue {
  /** The whole first byte: class, constructed bit and number together. */
  tag: number;
  /** True for SEQUENCE, SET and any context-specific constructed value. */
  constructed: boolean;
  /** Where the body starts, and where it ends, absolute into the buffer. */
  contentStart: number;
  contentEnd: number;
  /** Where the next value begins - past this one's body. */
  end: number;
}

/**
 * Reads one TLV at `offset`.
 *
 * Returns null on anything malformed rather than throwing: these bytes come
 * off a wire and a dissector's answer to "this is not what it claimed" is to
 * decline, not to fail the frame.
 */
export function readBer(bytes: Uint8Array, offset: number, end: number): BerValue | null {
  if (offset >= end) return null;
  const tag = bytes[offset];
  // A tag number of 31 means the number continues in following bytes. None of
  // the protocols here use one, and accepting it silently would mean accepting
  // a length read from the wrong offset.
  if ((tag & 0x1f) === 0x1f) return null;

  let p = offset + 1;
  if (p >= end) return null;
  let length = bytes[p++];
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0) return null;          // indefinite - see the header note
    if (count > 4 || p + count > end) return null;
    length = 0;
    for (let i = 0; i < count; i++) length = (length << 8) | bytes[p++];
  }
  const contentEnd = p + length;
  if (contentEnd > end || contentEnd < p) return null;
  return {
    tag,
    constructed: (tag & 0x20) !== 0,
    contentStart: p,
    contentEnd,
    end: contentEnd,
  };
}

/** Every TLV directly inside a constructed value, in order. */
export function berChildren(bytes: Uint8Array, value: BerValue, limit = 128): BerValue[] {
  const out: BerValue[] = [];
  let p = value.contentStart;
  while (p < value.contentEnd && out.length < limit) {
    const child = readBer(bytes, p, value.contentEnd);
    if (child === null) break;
    out.push(child);
    // A zero-length value is legal (NULL is one); without this guard a
    // malformed run of them would spin.
    p = child.end > p ? child.end : p + 1;
  }
  return out;
}

/**
 * A signed integer.
 *
 * Two's complement, big-endian, and the leading byte carries the sign - so the
 * first byte is sign-extended and the rest are not. Values wider than 48 bits
 * lose precision in a JS number and are clamped rather than silently wrapped;
 * SNMP's Counter64 is the only such type here and it is rendered from bytes.
 */
export function berInteger(bytes: Uint8Array, value: BerValue): number {
  let n = 0;
  for (let p = value.contentStart; p < value.contentEnd; p++) {
    n = p === value.contentStart ? (bytes[p] << 24) >> 24 : n * 256 + bytes[p];
  }
  return n;
}

/** An unsigned integer, for the tags where the encoding is defined that way. */
export function berUnsigned(bytes: Uint8Array, value: BerValue): number {
  let n = 0;
  for (let p = value.contentStart; p < value.contentEnd; p++) n = n * 256 + bytes[p];
  return n;
}

const utf8 = new TextDecoder('utf-8', { fatal: false });

/** An OCTET STRING as text. Callers that must not render bytes as text do not call this. */
export function berString(bytes: Uint8Array, value: BerValue): string {
  return utf8.decode(bytes.subarray(value.contentStart, value.contentEnd));
}

/**
 * An object identifier, in dotted form.
 *
 * Base-128 groups, most significant first, with the top bit set on every byte
 * but a group's last. The first group is then two arcs, `40 * x + y`, which is
 * why `1.3.6.1.2.1` starts `0x2b`: 1*40 + 3.
 */
export function berOid(bytes: Uint8Array, value: BerValue): string {
  if (value.contentStart >= value.contentEnd) return '';

  // Every group is base-128, INCLUDING the first - which is the part that is
  // easy to get wrong, because the first group is usually one byte and so a
  // decoder that reads a single byte there is right on almost everything.
  // `1.3.6.1` starts 0x2b and works either way; `2.100.3` encodes its first
  // group as 180, which needs two bytes (0x81 0x34), and a single-byte read
  // turns it into `2.49.52` - a plausible OID that is not the one on the wire.
  const groups: number[] = [];
  let acc = 0;
  for (let p = value.contentStart; p < value.contentEnd; p++) {
    acc = acc * 128 + (bytes[p] & 0x7f);
    if ((bytes[p] & 0x80) === 0) {
      groups.push(acc);
      acc = 0;
    }
  }
  if (groups.length === 0) return '';

  // The first group is two arcs: `40 * x + y`. x is capped at 2 rather than
  // divided out, because an OID under 2.x may have a second arc above 39 and
  // the division would carry the excess into the wrong place.
  const first = groups[0];
  const x = Math.min(2, Math.floor(first / 40));
  return [x, first - x * 40, ...groups.slice(1)].join('.');
}

/** Hex, for the values that must not be rendered as text. */
export function berHex(bytes: Uint8Array, value: BerValue): string {
  let out = '';
  for (let p = value.contentStart; p < value.contentEnd; p++) {
    out += bytes[p].toString(16).padStart(2, '0');
  }
  return out;
}
