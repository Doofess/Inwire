/**
 * The vendor tables against the reference analyzer's own.
 *
 *   npx tsx scripts/dissect/mac-vendors.ts
 *
 * `macVendors.ts` is generated from IEEE's registries by `scripts/gen-oui.ts`
 * and resolves a MAC by its longest assigned prefix: 36 bits (MA-S and IAB),
 * then 28 (MA-M), then 24 (MA-L). This holds that against `tshark -G manuf`,
 * which is the same three registries as Wireshark compiled them in - so it
 * checks reference data, never a made-up frame.
 *
 * For every block the reference knows, an address inside it must resolve here
 * to a block of the SAME size, printed the way Wireshark prints it:
 * "Name_cc:dd:ee" at 24 bits, "Name_d:ee:ff" at 28 and "Name_e:ff" at 36, the
 * single digit being the low nibble the block leaves free
 * (`eth_resolved_name_fill` in epan/addr_resolv.c). A block resolved at a
 * shorter prefix is one this table lacks; before the 28- and 36-bit tables,
 * that was all 18,000 of them, each naming IEEE rather than the device's maker.
 *
 * Floors are counts, not ratios, for tree-coverage's reason: the denominator
 * is the reference's vocabulary, and a Wireshark upgrade that adds blocks must
 * not fail a build that changed nothing. They may only rise. The registries
 * move under both tools - IEEE assigns weekly - so the two never hold exactly
 * the same set, and the misses are printed rather than required to be zero.
 *
 * Short names are this project's own derivation (gen-oui.ts says why), so how
 * often they equal the reference's is printed and never enforced.
 *
 * Skips cleanly without tshark.
 */
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveMacName } from '../../src/services/macVendors';
import { findWiresharkTool, runTool } from '../export/realCaptures';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${String(expected)}`);
    console.log(`        actual   ${String(actual)}`);
  }
}

// --- the packed tables' own shape, which needs no reference ------------------

const source = readFileSync(
  join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'src', 'services', 'macVendors.ts'), 'utf8');

for (const [table, digits] of [['OUI28_BLOCKS', 7], ['OUI36_BLOCKS', 9]] as const) {
  const body = new RegExp(`const ${table} = \`\\n([\\s\\S]*?)\`;`).exec(source)?.[1] ?? '';
  const lines = body.split('\n').filter(Boolean);
  const shape = new RegExp(`^[0-9A-F]{${digits}} [\\p{L}\\p{N}]{1,12}$`, 'u');
  check(`${table} is not empty`, lines.length > 0, true);
  check(`every ${table} line is ${digits} hex digits and a short name`,
    lines.filter((line) => !shape.test(line)).slice(0, 3).join(' | '), '');
  const keys = lines.map((line) => line.slice(0, digits));
  check(`${table} is sorted and holds each block once`,
    keys.every((key, i) => i === 0 || keys[i - 1] < key), true);
}

// --- against the reference ----------------------------------------------------

const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('\nSKIP  the reference comparison: tshark not found');
  finish();
}

/** Counts of reference blocks this table resolves at the same size, by size. */
const FLOORS: Record<number, number> = { 24: 39_958, 28: 6_593, 36: 11_768 };

interface Tally { blocks: number; same: number; coarser: number; unknown: number; nameAgrees: number }
const tallies = new Map<number, Tally>();
const misses: string[] = [];

for (const line of runTool(tshark!, ['-G', 'manuf']).split(/\r?\n/)) {
  const [prefix, name] = line.split('\t').map((cell) => cell?.trim());
  if (!prefix || !name) continue;
  const [address, maskText] = prefix.split('/');
  const bits = maskText === undefined ? 24 : Number(maskText);
  if (bits !== 24 && bits !== 28 && bits !== 36) continue;

  // An address inside the block: its prefix, then 0xa5 in every free bit
  // position the block leaves - a nibble of 5 where the prefix ends mid-octet.
  const octets = address.split(':').map((o) => Number.parseInt(o, 16));
  const bytes = [0, 1, 2, 3, 4, 5].map((i) => {
    const fixed = Math.max(0, Math.min(8, bits - i * 8));
    const keep = fixed === 0 ? 0 : (0xff << (8 - fixed)) & 0xff;
    return ((octets[i] ?? 0) & keep) | (0xa5 & ~keep & 0xff);
  });
  if (bytes[0] & 0x01) continue; // a group address - resolved by the reserved names, not a vendor
  const mac = bytes.map((b) => b.toString(16).padStart(2, '0')).join(':');
  const hex = (b: number) => b.toString(16).padStart(2, '0');
  const expectedSuffix = bits === 24
    ? `${hex(bytes[3])}:${hex(bytes[4])}:${hex(bytes[5])}`
    : bits === 28
      ? `${(bytes[3] & 0x0f).toString(16)}:${hex(bytes[4])}:${hex(bytes[5])}`
      : `${(bytes[4] & 0x0f).toString(16)}:${hex(bytes[5])}`;

  const tally = tallies.get(bits) ?? { blocks: 0, same: 0, coarser: 0, unknown: 0, nameAgrees: 0 };
  tallies.set(bits, tally);
  tally.blocks++;
  const ours = resolveMacName(mac);
  if (ours === mac) {
    tally.unknown++;
    if (misses.length < 5) misses.push(`${prefix} ${name}: unknown here`);
  } else if (ours.endsWith(`_${expectedSuffix}`)) {
    tally.same++;
    if (ours.slice(0, -expectedSuffix.length - 1) === name) tally.nameAgrees++;
  } else {
    tally.coarser++;
    if (misses.length < 5) misses.push(`${prefix} ${name}: resolved here as ${ours}`);
  }
}

console.log('\n--- blocks the reference knows, resolved here at the same size ---\n');
for (const bits of [24, 28, 36]) {
  const t = tallies.get(bits) ?? { blocks: 0, same: 0, coarser: 0, unknown: 0, nameAgrees: 0 };
  console.log(`      ${bits}-bit: ${t.same.toLocaleString()} of ${t.blocks.toLocaleString()} `
    + `(${t.coarser} at a shorter prefix, ${t.unknown} unknown); `
    + `short name equal to the reference's on ${t.nameAgrees.toLocaleString()}`);
  check(`${bits}-bit blocks resolved at their own size >= ${FLOORS[bits].toLocaleString()}`,
    t.same >= FLOORS[bits], true);
}
if (misses.length > 0) console.log(`\n      first misses:\n        ${misses.join('\n        ')}`);

finish();

function finish(): never {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All MAC vendor checks passed.');
  process.exit(0);
}
