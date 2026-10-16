/**
 * What the command palette lists for what was typed.
 *
 *   npx tsx scripts/commands/palette-model.ts
 *
 * The component only draws `paletteRows`; every decision about which rows, in
 * which order, under which prefix, is made here where a script can see it.
 */
import { paletteRows, type PaletteRow } from '../../src/lib/paletteModel';
import { COMMANDS, availableCommands, type CommandContext } from '../../src/lib/commands';

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
function checkTrue(name: string, ok: boolean): void { check(name, ok, true); }

const capturing: CommandContext = { capturing: true, canStartCapture: false, packetCount: 40, filterApplied: false, sideBarOpen: false };
const empty = { recent: [], presets: [] };

const ids = (rows: PaletteRow[]): string[] => rows.map((r) => (r.kind === 'command' ? r.id : r.kind));

const commands = paletteRows('>', capturing, empty);
checkTrue('> lists commands only', commands.every((r) => r.kind === 'command'));
check('> keeps registry order, offering only what applies', ids(commands), availableCommands(capturing).map((c) => c.id));
checkTrue('no Start capture while capturing', !ids(commands).includes('capture.start'));
checkTrue('> ignores the filter suggestions', paletteRows('>tcp', capturing, { recent: ['tcp'], presets: ['tcp'] }).every((r) => r.kind === 'command'));

const search = paletteRows('tcp', capturing, { recent: ['tcp.port == 443'], presets: ['tcp'] });
const filters = search.filter((r): r is Extract<PaletteRow, { kind: 'filter' }> => r.kind === 'filter');
check('search offers both filters, recent first', filters.map((f) => [f.source, f.expression]), [['recent', 'tcp.port == 443'], ['preset', 'tcp']]);
check('a filter both recent and preset is listed once',
  paletteRows('tcp', capturing, { recent: ['tcp'], presets: ['tcp'] }).filter((r) => r.kind === 'filter').length, 1);
check('at most six filter rows',
  paletteRows('a', capturing, { recent: [], presets: ['a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8'] }).filter((r) => r.kind === 'filter').length, 6);

const help = paletteRows('?', capturing, empty);
check('? opens with the three prefixes', help.slice(0, 3).map((r) => r.kind === 'prefix' ? r.prefix : r.kind), ['>', ':', '?']);
const keys = help.flatMap((r) => (r.kind === 'shortcut' ? [r.keys] : []));
for (const k of ['Ctrl+K', 'Ctrl+Shift+P', 'Ctrl+/', 'Ctrl+G', 'Ctrl+E', 'Space']) {
  checkTrue(`? lists ${k}`, keys.includes(k));
}
check('? lists Ctrl+E once, for both its commands', keys.filter((k) => k === 'Ctrl+E').length, 1);
check('? lists every keyed command, whatever applies now',
  help.filter((r) => r.kind === 'shortcut').length >= COMMANDS.filter((c) => c.keys).length - 1, true);

check(': hands the frame number to the component', paletteRows(':12', capturing, empty), []);
check('a query that matches nothing lists nothing', paletteRows('zzzz', capturing, empty), []);

const hits = paletteRows('gtp', capturing, empty).find((r) => r.kind === 'command' && r.id === 'packet.goto');
check('a command row carries its hits, for highlighting', hits && hits.kind === 'command' ? hits.hits : null, [0, 3, 6]);
const settings = paletteRows('preferences', capturing, empty);
checkTrue('a keyword finds its command', ids(settings).includes('settings.open'));

console.log(failures === 0 ? '\nAll palette-model checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
