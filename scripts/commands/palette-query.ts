/**
 * The palette's prefixes, and the one rule for when a key may start a capture.
 *
 *   npx tsx scripts/commands/palette-query.ts
 *
 * `captureKeyAction` is Space's old inline branch, lifted so that Ctrl+E can
 * share it: two keys with two copies of "may this start a capture?" is how one
 * of them comes to discard a finished buffer in a single keystroke.
 */
import { parsePaletteQuery, PALETTE_PREFIXES } from '../../src/lib/paletteQuery';
import { captureKeyAction, type CaptureKeyState } from '../../src/lib/captureKey';

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

check('> is commands, the space after it dropped', parsePaletteQuery('>  sta'), { mode: 'commands', query: 'sta' });
check(': is go to', parsePaletteQuery(':120'), { mode: 'goto', query: '120' });
check('? is help', parsePaletteQuery('?'), { mode: 'help', query: '' });
check('no prefix is search', parsePaletteQuery('tcp'), { mode: 'search', query: 'tcp' });
check('empty is search', parsePaletteQuery(''), { mode: 'search', query: '' });
check('a prefix only counts first', parsePaletteQuery('a>b'), { mode: 'search', query: 'a>b' });
check('the three prefixes, in order', PALETTE_PREFIXES.map((p) => p.prefix), ['>', ':', '?']);

const ready: CaptureKeyState = { capturing: false, adapterCount: 1, packetCount: 0, canCapture: true, blocked: false };
check('ready starts', captureKeyAction(ready), 'start');
check('capturing always stops, even with no adapter', captureKeyAction({ ...ready, capturing: true, adapterCount: 0, blocked: true }), 'stop');
check('no adapter does nothing', captureKeyAction({ ...ready, adapterCount: 0 }), null);
check('a full buffer is never discarded by a key', captureKeyAction({ ...ready, packetCount: 5 }), null);
check('a blocked start does nothing', captureKeyAction({ ...ready, blocked: true }), null);
check('no agent, no start', captureKeyAction({ ...ready, canCapture: false }), null);

console.log(failures === 0 ? '\nAll palette-query checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
