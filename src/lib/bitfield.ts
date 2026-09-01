/**
 * The reference analyzer's dotted-binary rendering for sub-byte protocol fields.
 *
 * A header field narrower than a byte is unreadable as a decoded value alone:
 * `Version: 6` says nothing about where those bits sit. The reference analyzer draws the
 * containing word in binary with everything outside the field replaced by
 * dots, so the field's position and width are visible at a glance:
 *
 *     0110 .... = Version: 6
 *     .... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00
 *
 * Pure presentation. Dissectors emit only the three numbers; this computes
 * the dots, so the rule lives in one place rather than in every dissector.
 */

export interface BitfieldSpec {
  /** Bits from the start of the drawn window to the start of the field. */
  bitOffset: number;
  bitLength: number;
  /**
   * Width of the binary string to draw. Emitted per field by the dissector,
   * because it is a property of the protocol's own presentation, not of the
   * field: IPv6 draws three different widths inside one 4-byte word.
   */
  totalBits: number;
  /**
   * Where the drawn window begins inside the first byte. Almost always 0, but
   * TCP's flags are drawn as a 12-bit window starting 4 bits into the byte -
   * the low nibble of the data-offset byte plus all of the next one - so the
   * window cannot always be assumed to start on a byte boundary.
   */
  windowStartBit?: number;
}

/**
 * Builds the binary string, e.g. `.... 0101 1010`.
 *
 * `byteOffset` is where the rendered window starts in the frame, which is the
 * field's own `rawBytesRange[0]`. Bits beyond the end of the buffer render as
 * dots rather than throwing: a truncated capture should show a short field,
 * not break the whole detail pane.
 */
export function renderBitfield(
  bytes: Uint8Array,
  byteOffset: number,
  { bitOffset, bitLength, totalBits, windowStartBit = 0 }: BitfieldSpec,
): string {
  const out: string[] = [];

  for (let i = 0; i < totalBits; i++) {
    // A space every 4 bits, matching the reference analyzer's nibble grouping.
    if (i > 0 && i % 4 === 0) out.push(' ');

    if (i < bitOffset || i >= bitOffset + bitLength) {
      out.push('.');
      continue;
    }

    // bitOffset/bitLength are window-relative because that is what the drawn
    // string shows; only the byte lookup needs the absolute position.
    const absoluteBit = windowStartBit + i;
    const byte = bytes[byteOffset + Math.floor(absoluteBit / 8)];
    if (byte === undefined) {
      out.push('.');
      continue;
    }
    // Bit 0 of each byte is its most significant bit, which is how protocol
    // specifications number them - the opposite of the usual shift direction.
    out.push(((byte >> (7 - (absoluteBit % 8))) & 1).toString());
  }

  return out.join('');
}

/**
 * The full row text: `0110 .... = Version: 6`.
 *
 * Kept next to the binary builder so the ` = ` separator - which is part of
 * The reference analyzer's format and gets compared character-for-character against
 * `tshark -V` during verification - is defined once.
 */
export function renderBitfieldRow(
  bytes: Uint8Array,
  byteOffset: number,
  spec: BitfieldSpec,
  name: string,
  value: string | number | boolean,
): string {
  return `${renderBitfield(bytes, byteOffset, spec)} = ${name}: ${value}`;
}
