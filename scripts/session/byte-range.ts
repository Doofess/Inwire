/**
 * The cross-pane byte highlight, and the boundary that keeps App off its path.
 *
 *   npx tsx scripts/session/byte-range.ts
 *
 * **This was a performance bug and it looked like nothing.** The highlighted
 * range is the link between the packets view's two bottom panes - hover a field
 * in the tree and its bytes light up in the dump, hover a byte and its field
 * lights up in the tree - and it was `useState` in `App`, which is exactly where
 * state shared by two siblings belongs. Correct, idiomatic, and it meant every
 * pointer move over a byte re-rendered the entire application: the packet list,
 * the status bar, both panes.
 *
 * On a 54-byte frame that is four rows of dump and nobody notices. On a 64KB
 * frame the dump mounts around 79 virtualized rows of 32 spans each, and moving
 * the pointer across it rebuilt all of that, plus everything else `App`
 * renders, once per byte.
 *
 * So the checks here are in two halves. The first is the store's behaviour -
 * ownership, and the compare that stops an identical republish waking a
 * subscriber. The second is structural, and it is the half with teeth: `App`
 * must not import this store's publishers and must not render either pane
 * directly, because the fix is only a fix while the state stays out of that
 * file. Re-adding a `useState` there would restore the bug with nothing failing
 * anywhere - which is the whole reason this script exists rather than a comment.
 *
 * `scripts/session/status-bar.ts` covers the OTHER byte store, and the two are
 * easy to confuse: that one carries a byte's value so that only a dump can
 * publish it, this one carries a range so that the tree can. Neither replaces
 * the other.
 */
import { readFileSync } from 'node:fs';
import {
  clearByteRange,
  publishByteRange,
  readByteRange,
  resetByteRange,
  subscribeByteRange,
} from '../../src/services/byteRange';

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

/** Comments stripped, so a paragraph explaining a rule cannot fail its check. */
function code(file: string): string {
  return readFileSync(file, 'utf8')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/(^|[^:])\/\/.*$/gm, '$1');
}

console.log('--- ownership, with both panes mounted ---\n');

{
  resetByteRange();

  publishByteRange('packets-tree', [4, 9]);
  check('the tree can publish a field range', readByteRange(),
    { source: 'packets-tree', range: [4, 9] });

  // The case that made `clear` take a source. Both panes are mounted at once,
  // so the pane the pointer LEAVES fires its clear after the pane it entered
  // has already published - and an unconditional clear would blank the new
  // highlight a moment after drawing it.
  clearByteRange('packets-hex');
  check('a clear from the pane that does not own it is ignored', readByteRange(),
    { source: 'packets-tree', range: [4, 9] });

  clearByteRange('packets-tree');
  check('...and a clear from the owner lands', readByteRange(),
    { source: null, range: null });

  // Crossing from one pane to the other with no clear in between.
  publishByteRange('packets-tree', [4, 9]);
  publishByteRange('packets-hex', [7, 7]);
  check('the other pane can take ownership directly', readByteRange(),
    { source: 'packets-hex', range: [7, 7] });

  // Clear and Discard drop the selection, so there is no frame for any range to
  // describe and no owner to ask.
  resetByteRange();
  check('reset does not care who holds it', readByteRange(), { source: null, range: null });
}

console.log('\n--- the compare that keeps a pointer move cheap ---\n');

{
  resetByteRange();
  let woken = 0;
  const stop = subscribeByteRange(() => { woken += 1; });

  // A range is a fresh array on every `onMouseEnter`, so an identity compare
  // would wake both panes on every move inside a single byte cell. This is the
  // same field-by-field rule `packetCounts.ts` and `hoveredByte.ts` follow.
  publishByteRange('packets-hex', [7, 7]);
  publishByteRange('packets-hex', [7, 7]);
  publishByteRange('packets-hex', [7, 7]);
  check('an identical republish does not wake a subscriber', woken, 1);

  publishByteRange('packets-hex', [7, 8]);
  check('...and a real change does', woken, 2);

  // Same range, different owner: the subscribers render identically either way,
  // but the OWNER decides whose clear is honoured, so it has to count as a
  // change or a clear from the wrong pane starts landing.
  publishByteRange('packets-tree', [7, 8]);
  check('...and so does the same range from the other pane', woken, 3);

  stop();
  publishByteRange('packets-hex', [1, 2]);
  check('unsubscribing stops the notifications', woken, 3);
  resetByteRange();
}

console.log('\n--- App is not on the path, and must not get back onto it ---\n');

{
  const app = code('src/App.tsx');

  // The bug, named. `App` may RESET the highlight - Clear and Discard throw the
  // selection away - but it must never publish one, because publishing is what
  // a pointer move does and this file re-renders the world.
  checkTrue('App never publishes a range', !app.includes('publishByteRange'));
  checkTrue('...nor clears one by source', !app.includes('clearByteRange'));
  checkTrue('...and resets it where the selection goes', app.includes('resetByteRange('));

  // The state itself. A `useState` back in this file is the whole regression,
  // and it would type-check, render correctly, and look like a tidy-up.
  checkTrue('there is no byte-range state in App', !/activeByteRange.*useState/s.test(app)
    && !app.includes('setActiveByteRange'));

  // And the route around it: rendering the panes directly means threading the
  // range as a prop again, which means holding it here again.
  checkTrue('App renders the linked panes rather than the panes themselves',
    app.includes('LinkedDetailsTree') && app.includes('LinkedHexViewer')
      && !/<HexViewer\b/.test(app) && !/<PacketDetailsTree\b/.test(app));
}

console.log('\n--- what the memo boundary rests on ---\n');

{
  const app = code('src/App.tsx');
  const linked = code('src/components/packet-details/LinkedDetailPanes.tsx');

  // `React.memo` on the dump is only a boundary while every prop crossing it is
  // stable. `permissions` was an object literal rebuilt on every render, which
  // is a changed prop, which is a memo that never hits - and nothing about that
  // failure is visible: the app is correct and merely slow.
  checkTrue('permissions is memoized, or the dump memo never holds',
    /const permissions: Capabilities = useMemo\(/.test(app));
  checkTrue('the dump pane is the memo boundary', linked.includes('React.memo('));

  // The tree deliberately is not one. `onSelectFrame` closes over `packets`, so
  // its identity changes on every flush during a capture; a memo there would
  // cost a comparison to always miss, and would read as a guarantee it cannot
  // give.
  check('...and it is the only one', linked.split('React.memo(').length - 1, 1);
}

console.log('\n--- the two byte stores stay distinct ---\n');

{
  // They are opposites and look alike. `hoveredByte` carries a VALUE so that
  // only code holding the bytes can publish - which keeps the tree out. This
  // one carries a RANGE precisely so the tree can publish. Merging them would
  // silently undo the status bar's whole design, so this asserts the tree still
  // reaches exactly one of them.
  const linked = code('src/components/packet-details/LinkedDetailPanes.tsx');
  checkTrue('the linked panes use the range store', linked.includes('publishByteRange'));
  checkTrue('...and not the value store', !linked.includes('publishHoveredByte'));

  const store = code('src/services/byteRange.ts');
  checkTrue('the range store carries no byte value',
    !store.includes('value') && !store.includes('hoveredByte'));
}

console.log();
if (failures) {
  console.log(`${failures} byte range check(s) FAILED`);
  process.exit(1);
}
console.log('All byte range checks passed.');
process.exit(0);
