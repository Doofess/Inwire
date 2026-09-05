/**
 * Assertion tests for the column block.
 *
 *   npx tsx scripts/dissect/field-block.ts
 *
 * The block stores the field values most frames carry as typed columns rather
 * than as object properties - 81 B a frame for 33 keys against roughly 1,900 B
 * as properties (`docs/decisions/0017`).
 *
 * Storing a value in fewer bits is only worth anything if it comes back out
 * unchanged, so these are about exactness rather than size:
 *
 *   - absence is not falsity, and zero is a value someone filters on;
 *   - a row cannot read its neighbour's value, or its neighbour's presence;
 *   - a column widens rather than truncating, because the starting widths come
 *     from the protocols and the computed fields have no protocol to ask;
 *   - a string column's table is shared, which is most of why it is 2 B.
 */
import { FieldBlock, type DenseKey } from '../../src/services/dissect/fieldBlock';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const KEYS: DenseKey[] = [
  { abbrev: 'tcp.flags.syn', width: 'u8' },
  { abbrev: 'tcp.srcport', width: 'u16' },
  { abbrev: 'tcp.seq', width: 'u32' },
  { abbrev: 'tcp.analysis.ack_rtt', width: 'f64' },
  { abbrev: 'eth.src', width: 'str' },
];

// --- Values survive the round trip, and absence is its own answer -------------
{
  const block = new FieldBlock(KEYS, 8);
  const row = block.claimRow();
  block.write(row, 'tcp.srcport', 443);
  block.write(row, 'eth.src', 'aa:bb:cc:dd:ee:ff');
  block.write(row, 'tcp.analysis.ack_rtt', 0.002153);
  check('a number reads back', block.read(row, 'tcp.srcport'), 443);
  check('a string reads back', block.read(row, 'eth.src'), 'aa:bb:cc:dd:ee:ff');
  check('a float keeps its fraction', block.read(row, 'tcp.analysis.ack_rtt'), 0.002153);

  // The distinction the whole split rests on. A filter naming a field the frame
  // does not carry must not match it, and `tcp.flags.syn == 0` is a filter
  // people write - so absence cannot be encoded as a value.
  check('a key never written is absent', block.read(row, 'tcp.seq'), undefined);
  const zeroRow = block.claimRow();
  block.write(zeroRow, 'tcp.seq', 0);
  check('...and zero is present, and zero', block.read(zeroRow, 'tcp.seq'), 0);

  check('a key this block does not carry is absent', block.read(row, 'udp.srcport'), undefined);
  checkTrue('...and it says so', !block.has('udp.srcport'));
  checkTrue('...while a declared one is carried', block.has('tcp.seq'));
}

// --- Rows do not bleed into each other ------------------------------------------
{
  const block = new FieldBlock(KEYS, 4);
  const a = block.claimRow();
  const b = block.claimRow();
  block.write(a, 'tcp.srcport', 1);
  block.write(b, 'tcp.srcport', 2);
  check('each row keeps its own value',
    [block.read(a, 'tcp.srcport'), block.read(b, 'tcp.srcport')], [1, 2]);

  block.write(a, 'tcp.flags.syn', 1);
  check('presence is per row, not per column', block.read(b, 'tcp.flags.syn'), undefined);
  check('...and the row that has it still does', block.read(a, 'tcp.flags.syn'), 1);
}

// --- A column widens rather than truncating ---------------------------------------
//
// The starting widths are the fields' own sizes in their protocols, which no
// valid frame exceeds - but several dense fields are COMPUTED rather than read
// off the wire, and no protocol bounds those. Truncating would report a
// plausible wrong number: 65,536 written to a u16 column reads back as 0.
{
  const block = new FieldBlock([{ abbrev: 'x', width: 'u8' }], 8);
  const r0 = block.claimRow();
  block.write(r0, 'x', 200);
  const r1 = block.claimRow();
  block.write(r1, 'x', 65_000);
  check('the larger value is exact', block.read(r1, 'x'), 65_000);
  check('...and the earlier small one survived the widening', block.read(r0, 'x'), 200);

  const r2 = block.claimRow();
  block.write(r2, 'x', 5_000_000_000);
  check('it widens again as far as needed', block.read(r2, 'x'), 5_000_000_000);
  check('...still keeping the first', block.read(r0, 'x'), 200);
  check('...and the second', block.read(r1, 'x'), 65_000);

  const r3 = block.claimRow();
  block.write(r3, 'x', 1.5);
  check('a fractional value widens to f64', block.read(r3, 'x'), 1.5);
  check('...and the integers are still exact', block.read(r2, 'x'), 5_000_000_000);

  const r4 = block.claimRow();
  block.write(r4, 'x', -7);
  check('a negative value widens too', block.read(r4, 'x'), -7);
  check('...leaving the rest alone', block.read(r0, 'x'), 200);
}

// --- String columns share one table ------------------------------------------------
{
  const block = new FieldBlock([{ abbrev: 'eth.src', width: 'str' }], 100);
  const rows = [block.claimRow(), block.claimRow(), block.claimRow()];
  block.write(rows[0], 'eth.src', 'aa:bb');
  block.write(rows[1], 'eth.src', 'aa:bb');
  block.write(rows[2], 'eth.src', 'cc:dd');
  check('repeated strings read back',
    rows.map((r) => block.read(r, 'eth.src')), ['aa:bb', 'aa:bb', 'cc:dd']);
  checkTrue('...and are one object, not two',
    block.read(rows[0], 'eth.src') === block.read(rows[1], 'eth.src'));

  // An empty string is a value like any other, and must not read as absent.
  const empty = block.claimRow();
  block.write(empty, 'eth.src', '');
  check('an empty string is present', block.read(empty, 'eth.src'), '');
}

// --- Overwriting a row's value -------------------------------------------------------
{
  const block = new FieldBlock(KEYS, 4);
  const row = block.claimRow();
  block.write(row, 'tcp.srcport', 80);
  block.write(row, 'tcp.srcport', 443);
  check('the last write wins', block.read(row, 'tcp.srcport'), 443);
}

// --- Capacity --------------------------------------------------------------------------
{
  const block = new FieldBlock(KEYS, 2);
  const a = block.claimRow();
  checkTrue('a block with room is not full', !block.full);
  const b = block.claimRow();
  checkTrue('a block at capacity says so', block.full);
  check('...and refuses another row', block.claimRow(), -1);
  check('...without disturbing the rows it has', [a, b], [0, 1]);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All field-block checks passed.');
process.exit(0);
