/**
 * The filter field's memory: the recent list, and the match chip's words.
 *
 *   npx tsx scripts/filter/recent-filters.ts
 *
 * The list is stored, so its loader is the half that matters most: whatever
 * is in storage - an old shape, a hand edit, junk - must load as a list the
 * field can draw, never as a crash or a row of blanks.
 */
import { normalizeRecentFilters, pushRecentFilter, RECENT_FILTERS_MAX } from '../../src/services/recentFilters';
import { filterChipLabel, type PacketCounts } from '../../src/services/packetCounts';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

check('re-applying a filter moves it to the front, trimmed', pushRecentFilter(['a', 'b'], ' b '), ['b', 'a']);
const eight = ['1', '2', '3', '4', '5', '6', '7', '8'];
check('the cap is eight', RECENT_FILTERS_MAX, 8);
check('a ninth entry drops the oldest', pushRecentFilter(eight, '9'), ['9', '1', '2', '3', '4', '5', '6', '7']);
const kept = ['a'];
check('an empty expression is not remembered', pushRecentFilter(kept, '   '), kept);

check('a stored non-list loads as the default', normalizeRecentFilters('x'), null);
check('a stored list keeps trimmed, distinct, non-empty strings',
  normalizeRecentFilters([1, ' a ', 'a', '', 'b']), ['a', 'b']);
check('a stored list longer than the cap is cut to it',
  normalizeRecentFilters(Array.from({ length: 12 }, (_, i) => `f${i}`))?.length, 8);

const counts: PacketCounts = { filtered: 44, total: 178200, scan: null, uncovered: 0 };
check('the chip reads matches of total', filterChipLabel(counts, 'udp'), '44 of 178,200');
check('no filter, no chip', filterChipLabel(counts, '  '), null);

console.log(failures === 0 ? '\nAll recent-filter checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
