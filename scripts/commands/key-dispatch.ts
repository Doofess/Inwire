/**
 * Which window chords act while a text field has focus.
 *
 *   npx tsx scripts/commands/key-dispatch.ts
 *
 * Focus usually sits in the display filter, so a palette key that stood down
 * for every input would be a key that never works. A view digit must stand
 * down: Ctrl+1 typed into a field belongs to the field.
 */
import { CHORDS_BEFORE_INPUT_GUARD, chordBeforeInputGuard } from '../../src/hooks/useKeyboardNavigation';
import { commandById } from '../../src/lib/commands';

let failures = 0;
function checkTrue(name: string, ok: boolean): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
}

checkTrue('Ctrl+K works from inside a field', chordBeforeInputGuard('palette.open'));
checkTrue('Ctrl+Shift+P works from inside a field', chordBeforeInputGuard('palette.commands'));
checkTrue('Ctrl+/ works from inside a field', chordBeforeInputGuard('filter.focus'));
checkTrue('Ctrl+E works from inside a field', chordBeforeInputGuard('capture.start') && chordBeforeInputGuard('capture.stop'));
checkTrue('a view digit in a field stays the field\'s', !chordBeforeInputGuard('view.packets'));
checkTrue('Ctrl+B in a field stays the field\'s', !chordBeforeInputGuard('sidebar.toggle'));
for (const id of CHORDS_BEFORE_INPUT_GUARD) {
  checkTrue(`${id} is a keyed command`, commandById(id)?.keys !== undefined);
}

console.log(failures === 0 ? '\nAll key-dispatch checks passed.' : `\n${failures} check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
