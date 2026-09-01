/**
 * Assertion tests for the dotted-binary bitfield renderer.
 *
 *   npx tsx scripts/bitfield/render.ts
 *
 * Expected strings are taken from the reference analyzer's own output for the same fields,
 * so a failure here means NetView would disagree with `tshark -V`.
 */
import { renderBitfield, renderBitfieldRow } from '../../src/lib/bitfield';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- IPv6 first word: 0x60 0x08 5a a1 -> version 6, TC 0x00, flow 0x85aa1 ---
// The reference case: three different render widths inside one 4-byte word,
// which is why totalBits cannot be derived from the field.
const ipv6 = new Uint8Array([0x60, 0x08, 0x5a, 0xa1]);

check(
  'IPv6 Version renders over 8 bits',
  renderBitfield(ipv6, 0, { bitOffset: 0, bitLength: 4, totalBits: 8 }),
  '0110 ....',
);
check(
  'IPv6 Traffic Class renders over 32 bits',
  renderBitfield(ipv6, 0, { bitOffset: 4, bitLength: 8, totalBits: 32 }),
  '.... 0000 0000 .... .... .... .... ....',
);
check(
  'IPv6 Flow Label renders over 24 bits from the second byte',
  renderBitfield(ipv6, 1, { bitOffset: 4, bitLength: 20, totalBits: 24 }),
  '.... 1000 0101 1010 1010 0001',
);

// DSCP and ECN nest under Traffic Class and are drawn at the same 32-bit
// width as their parent, not at their own. Expected strings copied from
// `tshark -V` on the user's own capture.
check(
  'IPv6 DSCP renders at the parent 32-bit width',
  renderBitfield(ipv6, 0, { bitOffset: 4, bitLength: 6, totalBits: 32 }),
  '.... 0000 00.. .... .... .... .... ....',
);
check(
  'IPv6 ECN renders at the parent 32-bit width',
  renderBitfield(ipv6, 0, { bitOffset: 10, bitLength: 2, totalBits: 32 }),
  '.... .... ..00 .... .... .... .... ....',
);

// --- boundary shapes ---
const b = new Uint8Array([0b10110101, 0b11001010]);

check(
  'a full byte renders every bit',
  renderBitfield(b, 0, { bitOffset: 0, bitLength: 8, totalBits: 8 }),
  '1011 0101',
);
check(
  'a sub-byte field at bit 0',
  renderBitfield(b, 0, { bitOffset: 0, bitLength: 3, totalBits: 8 }),
  '101. ....',
);
check(
  'a sub-byte field at a non-zero bit offset',
  renderBitfield(b, 0, { bitOffset: 5, bitLength: 3, totalBits: 8 }),
  '.... .101',
);
check(
  'a field spanning a byte boundary',
  renderBitfield(b, 0, { bitOffset: 6, bitLength: 5, totalBits: 16 }),
  '.... ..01 110. ....',
);
check(
  'a single bit',
  renderBitfield(b, 0, { bitOffset: 2, bitLength: 1, totalBits: 8 }),
  '..1. ....',
);

// --- Ethernet LG/IG bits: rendered over 24 bits (the MAC's first 3 bytes) ---
const mac = new Uint8Array([0x44, 0x15, 0x24]);
check(
  'Ethernet LG bit over 24 bits',
  renderBitfield(mac, 0, { bitOffset: 6, bitLength: 1, totalBits: 24 }),
  '.... ..0. .... .... .... ....',
);
check(
  'Ethernet IG bit over 24 bits',
  renderBitfield(mac, 0, { bitOffset: 7, bitLength: 1, totalBits: 24 }),
  '.... ...0 .... .... .... ....',
);

// --- TCP flags: a 12-bit window starting 4 bits into the byte ---
// Byte 12 is [data offset:4][reserved:3][AE:1], byte 13 is the 8 flag bits, and
// The reference analyzer draws the low 12 bits of that pair. Expected strings from
// `tshark -V` on a plain ACK (0x010).
const tcpFlagBytes = new Uint8Array([0x50, 0x10]); // data offset 5, ACK set
const TCP_WINDOW = { totalBits: 12, windowStartBit: 4 };

check(
  'TCP Reserved renders over the 12-bit window',
  renderBitfield(tcpFlagBytes, 0, { ...TCP_WINDOW, bitOffset: 0, bitLength: 3 }),
  '000. .... ....',
);
check(
  'TCP Acknowledgment bit is set in the right column',
  renderBitfield(tcpFlagBytes, 0, { ...TCP_WINDOW, bitOffset: 7, bitLength: 1 }),
  '.... ...1 ....',
);
check(
  'TCP Fin bit is the last column',
  renderBitfield(tcpFlagBytes, 0, { ...TCP_WINDOW, bitOffset: 11, bitLength: 1 }),
  '.... .... ...0',
);
check(
  'TCP Push bit sits at the start of the third nibble',
  renderBitfield(tcpFlagBytes, 0, { ...TCP_WINDOW, bitOffset: 8, bitLength: 1 }),
  '.... .... 0...',
);

// --- truncation must degrade, not throw ---
check(
  'bits past the end of the buffer render as dots',
  renderBitfield(new Uint8Array([0xff]), 0, { bitOffset: 0, bitLength: 16, totalBits: 16 }),
  '1111 1111 .... ....',
);
check(
  'an out-of-range byteOffset renders all dots rather than throwing',
  renderBitfield(new Uint8Array([0xff]), 9, { bitOffset: 0, bitLength: 8, totalBits: 8 }),
  '.... ....',
);

// --- the full row, including the " = " separator tshark output is matched on ---
check(
  'full row matches the reference analyzer formatting',
  renderBitfieldRow(ipv6, 0, { bitOffset: 0, bitLength: 4, totalBits: 8 }, 'Version', 6),
  '0110 .... = Version: 6',
);
check(
  'full row for a hex-valued field',
  renderBitfieldRow(ipv6, 1, { bitOffset: 4, bitLength: 20, totalBits: 24 }, 'Flow Label', '0x85aa1'),
  '.... 1000 0101 1010 1010 0001 = Flow Label: 0x85aa1',
);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
