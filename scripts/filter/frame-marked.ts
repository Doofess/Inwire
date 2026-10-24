/**
 * `frame.marked` and the marks set (ADR 0067).
 *
 *   npx tsx scripts/filter/frame-marked.ts
 *
 * `frame.marked` is a boolean present on every frame, as in Wireshark, read
 * through a filter context rather than through `Packet`: a mark is the
 * capture's, not the frame's, and a row cannot carry a fact the user changes
 * after it was stored.
 */
import { compile, type FilterContext } from '../../src/services/filter/compile';
import { FilterEngine } from '../../src/services/filterEngine';
import { knownFieldNames } from '../../src/services/filter/fields';
import {
  decodeMarks, encodeMarks, nextMarked, toggleMark, type Marks,
} from '../../src/services/marks';
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

function packet(id: number): Packet {
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: '10.0.0.2', destination: '10.0.0.3', protocol: 'TCP', length: 60, info: '',
    status: 'ok', interfaceName: 'eth0', layers: [], rawBytes: new Uint8Array(0),
  } as Packet;
}
const two = packet(2);
const three = packet(3);

console.log('--- the filter field ---\n');

const withMarks: FilterContext = { marked: new Set([2]) };
check('frame.marked == 1 matches a marked frame', compile('frame.marked == 1', withMarks)(two), true);
check('...and not an unmarked one', compile('frame.marked == 1', withMarks)(three), false);
check('frame.marked == 0 matches the unmarked one', compile('frame.marked == 0', withMarks)(three), true);
check('a bare frame.marked is present on every frame',
  [two, three].map(compile('frame.marked', withMarks)), [true, true]);
check('without a context nothing is marked', [two, three].map(compile('frame.marked == 1')), [false, false]);
check('...and a bare frame.marked still matches every frame', [two, three].map(compile('frame.marked')), [true, true]);
check('not frame.marked == 1 is the unmarked frames',
  [two, three].map(compile('!(frame.marked == 1)', withMarks)), [false, true]);

// The matcher holds the context, not the set: a caller that replaces
// `context.marked` is read by a matcher compiled before it did.
{
  const context: FilterContext = { marked: new Set<number>() };
  const matcher = compile('frame.marked == 1', context);
  check('a matcher compiled early reads the set the context holds now (before)', matcher(two), false);
  context.marked = new Set([2]);
  check('...and after the caller replaced it', matcher(two), true);
}

console.log('\n--- the engine ---\n');

check('FilterEngine.validateFilter no longer calls frame.marked tree-only',
  FilterEngine.validateFilter('frame.marked == 1'), { isValid: true });
check('...and it still calls frame.ignored tree-only',
  FilterEngine.validateFilter('frame.ignored == 1').warnings?.length, 1);
check('frame.marked is a name the bar completes', knownFieldNames().includes('frame.marked'), true);
check('...once', knownFieldNames().filter((n) => n === 'frame.marked').length, 1);
check('filterPackets takes the context',
  FilterEngine.filterPackets([two, three], 'frame.marked == 1', withMarks).map((p) => p.id), [2]);
check('compileFilter takes the context', FilterEngine.compileFilter('frame.marked == 1', withMarks)(two), true);

console.log('\n--- the set ---\n');

{
  const empty: Marks = new Set();
  const one = toggleMark(empty, 5);
  check('toggleMark adds', [...one], [5]);
  check('...leaves its argument alone', [...empty], []);
  check('...and removes on the second toggle', [...toggleMark(one, 5)], []);
  check('...returning a new set each time', one !== toggleMark(one, 6), true);
}

const all = () => true;
check('nextMarked walks forward', nextMarked([2, 5, 9], 5, 1, all), 9);
check('...wraps at the end', nextMarked([2, 5, 9], 9, 1, all), 2);
check('...walks backward', nextMarked([2, 5, 9], 5, -1, all), 2);
check('...wraps at the start', nextMarked([2, 5, 9], 2, -1, all), 9);
check('...skips what is not eligible', nextMarked([2, 5, 9], 5, 1, (id) => id !== 9), 2);
check('...skips them going back too', nextMarked([2, 5, 9], 5, -1, (id) => id !== 2), 9);
check('...from nothing it starts at the first', nextMarked([2, 5, 9], null, 1, all), 2);
check('...and backward from nothing at the last', nextMarked([2, 5, 9], null, -1, all), 9);
check('...from an id that is not marked it goes to the next one after it', nextMarked([2, 5, 9], 6, 1, all), 9);
check('...and the previous one before it', nextMarked([2, 5, 9], 6, -1, all), 5);
check('...nothing eligible is null', nextMarked([2, 5, 9], 5, 1, () => false), null);
check('...an empty list is null', nextMarked([], null, 1, all), null);
check('...the only eligible one is itself, after the wrap', nextMarked([2, 5, 9], 5, 1, (id) => id === 5), 5);

console.log('\n--- the file ---\n');

check('decodeMarks(encodeMarks(...)) is sorted', decodeMarks(encodeMarks(new Set([1, 7, 4]))), [1, 4, 7]);
check('...and an empty set round trips', decodeMarks(encodeMarks(new Set())), []);
const good = encodeMarks(new Set([1, 7, 4]));
check('a truncated file is null', decodeMarks(good.slice(0, good.length - 2)), null);
check('...an empty one is null', decodeMarks(new Uint8Array(0)), null);
check('...random bytes are null', decodeMarks(Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 1, 2, 3])), null);
check('...another version is null',
  decodeMarks(new TextEncoder().encode(JSON.stringify({ v: 2, ids: [1] }))), null);
check('...ids that are not ids are null',
  decodeMarks(new TextEncoder().encode(JSON.stringify({ v: 1, ids: [1, -3, 'x'] }))), null);
check('...a fraction is not an id',
  decodeMarks(new TextEncoder().encode(JSON.stringify({ v: 1, ids: [1.5] }))), null);

console.log(failures === 0 ? '\nAll frame.marked checks passed.' : `\n${failures} frame.marked check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
