/**
 * Assertion tests for column visibility and the sort fallback.
 *
 *   npx tsx scripts/packet-list/columns.ts
 *
 * The sort fallback is the rule worth pinning. A user can sort by Protocol and
 * then hide Protocol, and if nothing catches that, the list stays in an order
 * with no visible explanation - rows that look shuffled and no header carrying
 * an arrow to say why. There is no error, no warning, and nothing on screen
 * that would lead anyone to the cause.
 */
import {
  HIDEABLE_COLUMNS,
  defaultColumnVisibility,
  normalizeColumnVisibility,
  visibleSortField,
  type ColumnVisibility,
} from '../../src/lib/packetColumns';

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

const all = defaultColumnVisibility();

// --- The fallback -----------------------------------------------------------

check('a visible column is sorted by as asked', visibleSortField('protocol', all), 'protocol');

check(
  'sorting by a hidden column falls back to id',
  visibleSortField('protocol', { ...all, protocol: false }),
  'id',
);

check(
  'info is always sortable, because it is never hideable',
  visibleSortField('info', { ...all, protocol: false }),
  'info',
);

{
  // The awkward one: the fallback target is itself hidden. `id` is restored by
  // the validator in that case, so this pairs the two rules together.
  const hidden = normalizeColumnVisibility(
    Object.fromEntries(HIDEABLE_COLUMNS.map((c) => [c, false])),
  ) as ColumnVisibility;
  check('hiding every column leaves id showing', hidden.id, true);
  check('...so the fallback still lands somewhere visible',
    visibleSortField('protocol', hidden), 'id');
}

// --- The validator ----------------------------------------------------------

check('every column starts visible',
  defaultColumnVisibility(),
  {
    id: true, relativeTime: true, source: true, destination: true,
    protocol: true, length: true,
  });

{
  // Field by field, so a column added in a later build keeps its default rather
  // than the whole stored value being discarded.
  const out = normalizeColumnVisibility({ protocol: false, nonsense: true });
  check('an unknown key is ignored and known ones keep their defaults', out, {
    ...defaultColumnVisibility(),
    protocol: false,
  });
}

check('a non-boolean value keeps the default rather than being coerced',
  normalizeColumnVisibility({ protocol: 'no' })?.protocol, true);

for (const junk of [null, undefined, 'x', 7, []]) {
  const out = normalizeColumnVisibility(junk);
  const ok = junk === null || junk === undefined || typeof junk !== 'object'
    ? out === null
    : out !== null;
  check(`${JSON.stringify(junk) ?? 'undefined'} is handled without throwing`, ok, true);
}

{
  // An array IS an object, so it reaches the field loop and comes back as
  // defaults rather than null. Asserted so the behaviour is deliberate.
  check('an array yields defaults rather than null',
    normalizeColumnVisibility([]), defaultColumnVisibility());
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
