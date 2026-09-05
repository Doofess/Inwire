/**
 * Assertion tests for reading a frame's fields.
 *
 *   npx tsx scripts/dissect/field-access.ts
 *
 * A frame's fields live in two places once the dense ones move into columns
 * (`services/dissect/fieldBlock.ts`, `docs/decisions/0017`), and
 * `services/dissect/fieldAccess.ts` is the only code that knows that. Every
 * reader in the app - the filter engine, the colour chain, Apply as Column,
 * Statistics, the pcapng writer - goes through it.
 *
 * What these hold is the distinction the whole split rests on: **absent is not
 * the same as falsy.** A filter naming a field the frame does not carry must
 * not match it under any operator, and zero is a legitimate value for half the
 * dense keys - `tcp.flags.syn == 0` is a filter people write. Any scheme that
 * encodes absence as a sentinel value fails here.
 */
import { fieldEntries, fieldValue } from '../../src/services/dissect/fieldAccess';
import type { Packet } from '../../src/types/packet';

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

// --- Reading from the bag, which is every frame until the split lands ---------
{
  const frame = {
    fields: { 'tcp.srcport': 443, 'eth.src': 'aa:bb:cc:dd:ee:ff', 'tcp.flags.syn': 0 },
  } as unknown as Packet;

  check('reads a number', fieldValue(frame, 'tcp.srcport'), 443);
  check('reads a string', fieldValue(frame, 'eth.src'), 'aa:bb:cc:dd:ee:ff');
  check('a zero is a value, not an absence', fieldValue(frame, 'tcp.flags.syn'), 0);
  check('a key the frame lacks is undefined', fieldValue(frame, 'tcp.dstport'), undefined);
}

// --- A frame with no fields at all --------------------------------------------
//
// Every consumer used to write `packet.fields?.[k]`, so a frame with no bag was
// already a case they handled. It still has to be.
{
  check('a packet with no bag reads undefined', fieldValue({} as Packet, 'tcp.srcport'), undefined);
  check('...and enumerates to nothing', fieldEntries({} as Packet), []);
}

// --- Enumeration, for the readers that walk rather than ask -------------------
{
  const frame = { fields: { 'eth.src': 'aa:bb', 'tcp.srcport': 80 } } as unknown as Packet;
  check('enumerates every entry',
    fieldEntries(frame).sort(), [['eth.src', 'aa:bb'], ['tcp.srcport', 80]]);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All field-access checks passed.');
process.exit(0);
