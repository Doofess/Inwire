/**
 * The command registry: one list the palette, the window's keys and every keyed
 * tooltip read (ADR 0057).
 *
 *   npx tsx scripts/commands/registry.ts
 *
 * What it guards is drift. A shortcut used to be written three times - in the
 * hook that handles it, in the tooltip that advertises it and in whatever doc
 * listed it - and a key that changed in one place kept its old name in the
 * other two. The registry is data only, so this script can import it; the
 * `run` for each id is bound in `App.tsx`, which no script can reach.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import {
  availableCommands, commandById, COMMANDS, formatChord, matchChord, titleWithKeys,
  type CommandContext,
} from '../../src/lib/commands';
import { fuzzyScore, rankByFuzzy } from '../../src/lib/fuzzy';
import { APP_VIEWS } from '../../src/services/viewPrefs';

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
const checkTrue = (name: string, condition: boolean): void => check(name, condition, true);

const key = (k: string, mods: { ctrl?: boolean; shift?: boolean; alt?: boolean; meta?: boolean } = {}) => ({
  key: k, ctrlKey: mods.ctrl ?? false, shiftKey: mods.shift ?? false,
  altKey: mods.alt ?? false, metaKey: mods.meta ?? false,
});

const ctx: CommandContext = {
  capturing: false, canStartCapture: true, packetCount: 10, filterApplied: false, sideBarOpen: false,
};

// --- identity -------------------------------------------------------------
const ids = COMMANDS.map((c) => c.id);
check('command ids are unique', ids.length, new Set(ids).size);

// Ctrl+E is the one shared chord, and only because its two owners can never
// both be available: a capture is running or it is not.
const SHARED = new Set(['capture.start', 'capture.stop']);
const chords = COMMANDS.filter((c) => c.keys && !SHARED.has(c.id)).map((c) => formatChord(c.keys!));
check('chords are unique, bar the capture pair', chords.length, new Set(chords).size);
check(
  'the capture pair shares exactly Ctrl+E',
  COMMANDS.filter((c) => SHARED.has(c.id)).map((c) => c.keys && formatChord(c.keys)),
  ['Ctrl+E', 'Ctrl+E'],
);

check(
  'view commands are APP_VIEWS, in its order, on Ctrl+1..5',
  COMMANDS.filter((c) => c.id.startsWith('view.')).map((c) => [c.id, c.title, c.keys && formatChord(c.keys)]),
  APP_VIEWS.map((v, i) => [`view.${v.id}`, v.label, `Ctrl+${i + 1}`]),
);

// --- formatting -----------------------------------------------------------
check('formatChord with shift', formatChord({ key: 'p', ctrl: true, shift: true }), 'Ctrl+Shift+P');
check('formatChord of a symbol', formatChord({ key: '/', ctrl: true }), 'Ctrl+/');
check('titleWithKeys of a keyed command', titleWithKeys('view.packets'), 'Packets (Ctrl+1)');
check('titleWithKeys with its own title', titleWithKeys('sidebar.toggle', 'Hide side bar'), 'Hide side bar (Ctrl+B)');
check('titleWithKeys of an unkeyed command', titleWithKeys('settings.open'), 'Open settings');
check('commandById of an unknown id', commandById('nope'), undefined);

// --- matching -------------------------------------------------------------
check('Ctrl+K opens the palette', matchChord(key('k', { ctrl: true }))?.id, 'palette.open');
check('an upper-case key still matches', matchChord(key('K', { ctrl: true }))?.id, 'palette.open');
check('Meta counts as Ctrl', matchChord(key('k', { meta: true }))?.id, 'palette.open');
check('Alt never matches', matchChord(key('k', { ctrl: true, alt: true })), undefined);
check('Ctrl+Shift+P is the command list', matchChord(key('P', { ctrl: true, shift: true }))?.id, 'palette.commands');
check('Ctrl+P alone is nothing', matchChord(key('p', { ctrl: true })), undefined);
check('Ctrl+Shift+K is not Ctrl+K', matchChord(key('K', { ctrl: true, shift: true })), undefined);
check('a bare k is nothing', matchChord(key('k')), undefined);
check('Ctrl+/ focuses the filter', matchChord(key('/', { ctrl: true }))?.id, 'filter.focus');
check('Ctrl+3 is Statistics', matchChord(key('3', { ctrl: true }))?.id, 'view.statistics');

// --- availability ---------------------------------------------------------
const live = availableCommands({ ...ctx, capturing: true }).map((c) => c.id);
checkTrue('while capturing, Stop is offered', live.includes('capture.stop'));
checkTrue('while capturing, Start is not', !live.includes('capture.start'));
const idle = availableCommands(ctx).map((c) => c.id);
checkTrue('idle with an adapter, Start is offered', idle.includes('capture.start') && !idle.includes('capture.stop'));
checkTrue('an empty buffer has no Go to packet', !availableCommands({ ...ctx, packetCount: 0 }).some((c) => c.id === 'packet.goto'));
checkTrue('no filter, no Clear filter', !idle.includes('filter.clear'));
checkTrue('a filter, a Clear filter', availableCommands({ ...ctx, filterApplied: true }).some((c) => c.id === 'filter.clear'));

// --- fuzzy ----------------------------------------------------------------
check('gtp hits Go to packet at its word starts', fuzzyScore('gtp', 'Go to packet…')?.hits, [0, 3, 6]);
check('a missing letter is no match', fuzzyScore('xyz', 'Packets'), null);
check('case is ignored', fuzzyScore('PKT', 'packets')?.hits, [0, 3, 5]);
checkTrue(
  'a word-start hit outranks a mid-word one',
  (fuzzyScore('st', 'Start capture')?.score ?? 0) > (fuzzyScore('st', 'Toggle side bar (last)')?.score ?? 0),
);
check('st ranks Statistics first', rankByFuzzy('st', COMMANDS, (c) => c.title)[0]?.item.id, 'view.statistics');
check('an empty query keeps input order', rankByFuzzy('  ', ['b', 'a', 'c'], (s) => s).map((r) => r.item), ['b', 'a', 'c']);
check('no match drops the item', rankByFuzzy('zz', ['a', 'b'], (s) => s).length, 0);

// --- the hook handles every keyed command ----------------------------------
const hook = readFileSync('src/hooks/useKeyboardNavigation.ts', 'utf8');
for (const command of COMMANDS) {
  if (!command.keys) continue;
  // The view commands share one case, generated from APP_VIEWS, so the hook
  // names their prefix rather than five ids.
  const needle = command.id.startsWith('view.') ? "case 'view'" : `case '${command.id}'`;
  checkTrue(`the hook dispatches ${command.id}`, hook.includes(needle));
}

// --- no component spells a key -----------------------------------------------
// A tooltip's "(Ctrl+B)" is written once, in the registry, and read through
// `titleWithKeys`. The title row's side-bar toggle kept its own copy of the
// chord for as long as the key was a hook's private business, which is exactly
// how a rebound key ends up advertised under its old name. Comments are
// stripped first: prose explaining a shortcut is documentation, and the
// literal that matters is the one a user can hover.
function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sourceFiles(path);
    return /\.tsx?$/.test(name) ? [path] : [];
  });
}
// `(?<!:)` keeps the `//` of a URL from reading as the start of a comment.
const stripComments = (code: string): string =>
  code.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(?<!:)\/\/.*$/gm, '');
const spelledKeys = sourceFiles('src/components')
  .filter((path) => stripComments(readFileSync(path, 'utf8')).includes('(Ctrl+'))
  .map((path) => path.replaceAll('\\', '/'));
check('no component spells a "(Ctrl+" tooltip itself', spelledKeys, []);

console.log(failures === 0 ? '\nAll registry checks passed.' : `\n${failures} registry check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
