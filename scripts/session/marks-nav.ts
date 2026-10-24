/**
 * Marks in the app: the commands, where Next / Previous lands, and what a
 * change of the set does to a filter that names `frame.marked` (ADR 0067).
 *
 *   npx tsx scripts/session/marks-nav.ts
 *
 * App's handlers are unreachable from a script (`scripts/CLAUDE.md`), so what
 * is worth asserting lives in `markNav.ts` and `incrementalFilter.ts`, and App's
 * wiring is held by source checks on its switch, as `digest-rows.ts` does.
 */
import { readFileSync } from 'node:fs';
import {
  availableCommands, COMMANDS, commandById, formatChord, matchChord, type CommandContext,
} from '../../src/lib/commands';
import { filterIncrementally } from '../../src/services/incrementalFilter';
import { filterNamesMarked, markTarget, withMarkedRow } from '../../src/services/markNav';
import { toggleMark } from '../../src/services/marks';
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

const key = (k: string, mods: { ctrl?: boolean; shift?: boolean } = {}) => ({
  key: k, ctrlKey: mods.ctrl ?? false, shiftKey: mods.shift ?? false, altKey: false, metaKey: false,
});

console.log('--- the commands ---\n');

check('mark.toggle is Ctrl+M', commandById('mark.toggle')?.keys && formatChord(commandById('mark.toggle')!.keys!), 'Ctrl+M');
check('mark.next is Ctrl+Shift+N', commandById('mark.next')?.keys && formatChord(commandById('mark.next')!.keys!), 'Ctrl+Shift+N');
check('mark.prev is Ctrl+Shift+B', commandById('mark.prev')?.keys && formatChord(commandById('mark.prev')!.keys!), 'Ctrl+Shift+B');
check('mark.clearAll has no chord', commandById('mark.clearAll')?.keys, undefined);
check('Ctrl+M matches mark.toggle', matchChord(key('m', { ctrl: true }))?.id, 'mark.toggle');
check('Ctrl+Shift+N matches mark.next', matchChord(key('N', { ctrl: true, shift: true }))?.id, 'mark.next');
check('Ctrl+Shift+B is mark.prev, not the side bar', matchChord(key('B', { ctrl: true, shift: true }))?.id, 'mark.prev');
check('Ctrl+B is still the side bar', matchChord(key('b', { ctrl: true }))?.id, 'sidebar.toggle');
const chords = COMMANDS.filter((c) => c.keys && !c.id.startsWith('capture.')).map((c) => formatChord(c.keys!));
check('no two commands share a chord, bar the capture pair', chords.length, new Set(chords).size);

const base: CommandContext = {
  capturing: false, canStartCapture: false, packetCount: 10, filterApplied: false, sideBarOpen: false,
  hasSelection: false, markCount: 0,
};
const offered = (ctx: CommandContext) => availableCommands(ctx).map((c) => c.id).filter((id) => id.startsWith('mark.'));
check('nothing selected, nothing marked: no mark command', offered(base), []);
check('a selection offers Mark', offered({ ...base, hasSelection: true }), ['mark.toggle']);
check('marks offer next, previous and Unmark all',
  offered({ ...base, markCount: 2 }), ['mark.next', 'mark.prev', 'mark.clearAll']);

console.log('\n--- the wiring ---\n');

const app = readFileSync('src/App.tsx', 'utf8');
const hook = readFileSync('src/hooks/useKeyboardNavigation.ts', 'utf8');
for (const id of ['mark.toggle', 'mark.next', 'mark.prev', 'mark.clearAll']) {
  check(`App's command switch handles ${id}`, app.includes(`case '${id}'`), true);
}
for (const id of ['mark.toggle', 'mark.next', 'mark.prev']) {
  check(`the keyboard hook dispatches ${id}`, hook.includes(`case '${id}'`), true);
}
check('App sends every change of the set to the store', /captureStore\.setMarks\(/.test(app), true);
check('the placeholders are gone', /NO_MARKS|noMarkToggle/.test(app), false);
// No command exists only in the palette (d3b4326's rule, `src/components/CLAUDE.md`):
// every mark command has an item in the row menu, wired through `onMarkCommand`.
const list = readFileSync('src/components/packet-list/PacketList.tsx', 'utf8');
for (const id of ['mark.next', 'mark.prev', 'mark.clearAll']) {
  check(`the row menu offers ${id}`, list.includes(`onMarkCommand('${id}')`), true);
}
check('App hands the row menu its mark commands', /onMarkCommand=\{handleMarkCommand\}/.test(app), true);
check('the display filter compiles with the marks', /filterIncrementally\([^)]*marked/.test(app), true);

console.log('\n--- where Next and Previous land ---\n');

function packet(id: number): Packet {
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: '10.0.0.2', destination: '10.0.0.3', protocol: id % 2 ? 'TCP' : 'UDP', length: 60, info: '',
    status: 'ok', interfaceName: 'eth0', layers: [], rawBytes: new Uint8Array(0),
  } as Packet;
}
const held = Array.from({ length: 12 }, (_, i) => packet(i + 1));
const marks = new Set([3, 7, 11]);

check('next from 1 is 3', markTarget(marks, 1, 1, held, 0), 3);
check('next from 3 is 7', markTarget(marks, 3, 1, held, 0), 7);
check('next from the last wraps to the first', markTarget(marks, 11, 1, held, 0), 3);
check('previous from 3 wraps to 11', markTarget(marks, 3, -1, held, 0), 11);
check('nothing marked: null', markTarget(new Set(), 3, 1, held, 0), null);
// Review Focus 1: a mark on a frame the ring expired.
check('a mark below the ring floor is skipped', markTarget(marks, 1, 1, held, 5), 7);
check('...and so is one the buffer no longer holds',
  markTarget(new Set([2, 99]), 2, 1, held, 0), 2);
check('only expired marks: null', markTarget(new Set([2, 4]), 6, 1, held, 5), null);
// The current filter: only the frames it shows are eligible.
const shown = held.filter((p) => p.protocol === 'TCP');
check('a mark the filter hides is skipped (7 is TCP, 3 and 11 too: all shown)', markTarget(marks, 1, 1, shown, 0), 3);
check('...a UDP mark is hidden by a TCP filter', markTarget(new Set([4, 7]), 1, 1, shown, 0), 7);

console.log('\n--- a filter that names frame.marked ---\n');

check('frame.marked == 1 names the marks', filterNamesMarked('frame.marked == 1'), true);
check('a bare frame.marked does too', filterNamesMarked('tcp && frame.marked'), true);
check('tcp does not', filterNamesMarked('tcp'), false);
check('frame.number does not', filterNamesMarked('frame.number == 3'), false);

// Review Focus 2: toggling a mark while the filter is applied must change the
// list, so the cache cannot be reused across a change of the set.
{
  const filter = 'frame.marked == 1';
  const first = filterIncrementally(held, filter, null, undefined, { marked: new Set([3, 7]) });
  check('two marked frames show', first.result.map((p) => p.id), [3, 7]);
  const second = filterIncrementally(held, filter, first.cache, undefined, { marked: new Set([3]) });
  check('unmarking 7 drops it from the cached result', second.result.map((p) => p.id), [3]);
  const threeAndFive = new Set([3, 5]);
  const third = filterIncrementally(held, filter, second.cache, undefined, { marked: threeAndFive });
  check('marking 5 adds it', third.result.map((p) => p.id), [3, 5]);
  const same = filterIncrementally(held, filter, third.cache, undefined, { marked: threeAndFive });
  check('the same set reuses the cache', same.result === third.result, true);
  const grown = held.concat([packet(13)]);
  const withNew = filterIncrementally(grown, filter, same.cache, undefined, { marked: new Set([3, 5, 13]) });
  check('a new frame that is marked is found', withNew.result.map((p) => p.id), [3, 5, 13]);
}
{
  // A filter that does not name the marks is untouched by them.
  const tcp = filterIncrementally(held, 'tcp', null, undefined, { marked: new Set([3]) });
  const again = filterIncrementally(held, 'tcp', tcp.cache, undefined, { marked: new Set([3, 5]) });
  check('marking under `tcp` reuses the cached result', again.result === tcp.result, true);
}
check('toggleMark makes a new set', (() => {
  const before = new Set([1]);
  const after = toggleMark(before, 2);
  return [before === after, [...after]];
})(), [false, [1, 2]]);

console.log('\n--- the tree\'s Frame is marked row ---\n');

{
  const row = (value: string) => ({ name: '[Frame is marked]', value, generated: true, abbrev: 'frame.marked' });
  const withTree = {
    ...packet(3),
    layers: [{ name: 'Frame', summary: '', fields: [{ name: 'Frame 3', value: '', children: [row('False')] }] }],
  } as Packet;
  const read = (p: Packet | null) => p?.layers[0].fields[0].children?.[0].value;
  check('an unmarked frame keeps False and the same object', [read(withMarkedRow(withTree, false)), withMarkedRow(withTree, false) === withTree], ['False', true]);
  check('a marked frame reads True', read(withMarkedRow(withTree, true)), 'True');
  check('...without changing the original', read(withTree), 'False');
  check('null stays null', withMarkedRow(null, true), null);
  check('a frame with no such row is returned as it is', (() => { const p = packet(4); return withMarkedRow(p, true) === p; })(), true);
}

console.log(failures === 0 ? '\nAll marks-nav checks passed.' : `\n${failures} marks-nav check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
