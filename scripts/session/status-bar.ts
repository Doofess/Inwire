/**
 * Assertion tests for the application status bar.
 *
 *   npx tsx scripts/session/status-bar.ts
 *
 * **This bar existed once and was deleted, and every check here is the shape of
 * something that went wrong.** `components/status/StatusBar.tsx` carries the
 * full account; the two failures in a line each:
 *
 * 1. It carried the byte inspector, whose subject is a pane that starts a
 *    pane-width in from the window's left edge - so its text was pushed
 *    sideways with a CSS length built from `--details-pane-size`, and the bar
 *    became two blocks so a percentage would resolve against `<main>`. A bar
 *    that has to be inset to look like it belongs somewhere narrower belongs
 *    there instead.
 * 2. It could not read the dump's local hover, so it was fed a byte derived in
 *    `App` from `activeByteRange` - which the protocol TREE also publishes. The
 *    bar answered "this byte" for a hover in a pane that was not the dump.
 *
 * The fix for the first is a rule - items group by priority, never by
 * correspondence with what sits above them - and a rule needs checking, which
 * is what the third section does. The fix for the second is a store carrying
 * the byte's VALUE rather than its index, so the only code that can publish one
 * is code that already had the bytes in hand. The second section proves the
 * ownership rule that makes two mounted dumps safe; the fourth proves there are
 * exactly two publishers and that neither is `App`.
 *
 * `scripts/session/view.ts` owns the height arithmetic - the bar's 24px comes
 * out of the rail's slack, not out of the window minimum - and
 * `scripts/electron/window-chrome.ts` owns the drag regions. Nothing here
 * duplicates either.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import {
  clearHoveredByte,
  describeByte,
  publishHoveredByte,
  readHoveredByte,
  subscribeHoveredByte,
} from '../../src/services/hoveredByte';
import { STATUS_BAR_HEIGHT } from '../../electron/window';

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

/**
 * Comments stripped, the same way `view.ts` does it.
 *
 * This one is not a nicety. `StatusBar.tsx` discusses `--details-pane-size` at
 * length in order to say that it never reads it, so a check that cannot tell
 * prose from code would fail on the very paragraph explaining why it passes.
 */
function code(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

/** Every .ts/.tsx file under a directory, posix-separated. */
function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const rel = `${dir}/${entry}`;
    if (statSync(rel).isDirectory()) out.push(...walk(rel));
    else if (/\.tsx?$/.test(entry)) out.push(rel);
  }
  return out;
}

const BAR = 'src/components/status/StatusBar.tsx';

console.log('--- one byte, formatted ---\n');

{
  check('a printable byte', describeByte(31, 0x42),
    { offset: '0x001F', dec: '66', hex: '0x42', bits: '01000010', ascii: 'B' });

  // The inline formatting this replaced padded the value and not the offset, so
  // byte 10 of a frame read `@0xA` beside `0x0A`.
  check('the offset is padded like the value', describeByte(10, 0x0a).offset, '0x000A');
  check('...and so is the value', describeByte(10, 0x0a).hex, '0x0A');

  // The printable range at both ends. A control character rendered raw moves
  // the cursor or eats the line it is on.
  check('31 is not printable', describeByte(0, 31).ascii, '.');
  check('32 is a space', describeByte(0, 32).ascii, ' ');
  check('126 is a tilde', describeByte(0, 126).ascii, '~');
  check('127 is not printable', describeByte(0, 127).ascii, '.');

  check('zero is eight bits, not one', describeByte(0, 0).bits, '00000000');
  check('255 fills them', describeByte(0, 255).bits, '11111111');
}

console.log('\n--- the store, and the rule that makes two mounted dumps safe ---\n');

{
  // Both dumps can be mounted at once: the packets section stays mounted behind
  // `display: none` while Frame Detail is up. So a clear from the pane that is
  // LEAVING must not blank a byte the other one just published. That is this
  // check, and it is the reason `clear` takes a source instead of the store
  // having one `set(value | null)`.
  publishHoveredByte({ source: 'packets-hex', index: 4, value: 0x41, frameId: 7 });
  clearHoveredByte('frame-detail-hex');
  check('a clear from the pane that does not own it is ignored',
    readHoveredByte(),
    { source: 'packets-hex', index: 4, value: 0x41, frameId: 7 });

  clearHoveredByte('packets-hex');
  check('...and a clear from the owner lands', readHoveredByte().source, null);

  // The other dump may take over without the first one clearing first, which is
  // what happens when a pointer crosses from one view to the other.
  publishHoveredByte({ source: 'packets-hex', index: 1, value: 1, frameId: 1 });
  publishHoveredByte({ source: 'frame-detail-hex', index: 2, value: 2, frameId: 2 });
  check('the other dump can take ownership directly', readHoveredByte().source, 'frame-detail-hex');
  clearHoveredByte('frame-detail-hex');

  // The field compare, for the reason `packetCounts` has one: a dump rebuilds
  // this object on every pointer move inside a single cell, so the identity
  // always differs and an unguarded store would wake every subscriber.
  let woken = 0;
  const stop = subscribeHoveredByte(() => { woken += 1; });
  publishHoveredByte({ source: 'packets-hex', index: 1, value: 2, frameId: 3 });
  publishHoveredByte({ source: 'packets-hex', index: 1, value: 2, frameId: 3 });
  stop();
  check('an identical republish does not wake a subscriber', woken, 1);
  clearHoveredByte('packets-hex');
}

console.log('\n--- the indent cannot come back ---\n');

{
  const bar = code(BAR);

  // The machinery's tombstone. `--details-pane-size` is still on the root
  // element and the panes still read it; what must never happen again is the
  // BAR reading it, because wanting to is the symptom of an item that belongs
  // in a pane.
  checkTrue('the bar reads no pane-sized custom property',
    !bar.includes('--details-pane-size') && !bar.includes('--bottom-pane-height'));

  // The other half of the same apparatus: an inline length of any kind is how a
  // window-spanning strip gets pushed sideways.
  checkTrue('...and carries no inline width', !/w-\[/.test(bar));

  checkTrue(`the bar is ${STATUS_BAR_HEIGHT}px`, bar.includes(`h-${STATUS_BAR_HEIGHT / 4}`));

  // One `--secondary` surface with the rail and the title row. The outline
  // that separates them is a line, not a second ground.
  checkTrue('...on the chrome own ground', bar.includes('bg-secondary'));

  // **This bar draws no line, and there is one above it.** The cluster band
  // sits on it: two cards, each with its own `border-b`, held 4px clear by the
  // band's `pb-1`. So the edge above this strip is the cards' own outline
  // rather than a rule this element owns - and a `border-t` here would draw a
  // second line 4px below the first AND make the bar 23px, because
  // `border-box` takes it out of the height.
  checkTrue('...and drawing no line of its own', !bar.includes('border-t'));
  checkTrue('...because the cluster above it closes its own bottom edge',
    code('src/components/common/ActivityRail.tsx').includes('border border-border'));

  // The shell draws no corner of its own; the window's bottom-left is Windows'.
  checkTrue('...and no radius of its own', !/\brounded/.test(bar));

  // Not a drag region, by never opting in rather than by opting out per item. A
  // control inside one that forgets `app-no-drag` has exactly one symptom: a
  // click that does nothing.
  checkTrue('the bar is not a drag region', !/\bapp-drag\b/.test(bar));

  checkTrue('...and <main> closes its own, being the other card in that band',
    code('src/App.tsx').includes('border border-border rounded-lg'));
}

console.log('\n--- one publisher per dump, and none anywhere else ---\n');

{
  const sources = walk('src');

  // The store itself is excluded, and only the store: it DECLARES the function,
  // which is not a call site. Every other file that names it is one.
  const STORE = 'src/services/hoveredByte.ts';
  const publishers = sources
    .filter((f) => f !== STORE)
    .filter((f) => code(f).includes('publishHoveredByte('));

  check('exactly the two hex dumps publish a hovered byte',
    publishers.sort(),
    [
      'src/components/packet-details/HexViewer.tsx',
      'src/components/packet-details/PacketDetailPane.tsx',
    ]);

  // The original bug, named. `App` derived the byte from a range the protocol
  // tree also published. It may EXTINGUISH the bar's byte and may never light
  // one, which is a rule about a file rather than about a function - so it is
  // checked here rather than expressed in a type.
  checkTrue('App does not publish one', !code('src/App.tsx').includes('publishHoveredByte'));

  // The tree has a RANGE and no value, and that is what makes the conflation
  // unrepresentable rather than merely avoided. This asserts it stays that way.
  const trees = sources.filter((f) => /Tree\.tsx$/.test(f));
  checkTrue('no protocol tree publishes one',
    trees.length > 0 && trees.every((f) => !code(f).includes('publishHoveredByte')));
}

console.log();
if (failures) {
  console.log(`${failures} status bar check(s) FAILED`);
  process.exit(1);
}
console.log('All status bar checks passed.');
process.exit(0);
