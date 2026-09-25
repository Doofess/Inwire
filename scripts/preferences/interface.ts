/**
 * Assertion tests for the Interface tab's preference validators.
 *
 *   npx tsx scripts/preferences/interface.ts
 *
 * These are the part of the feature that can silently corrupt a workspace. A
 * stored preference is untrusted input - hand-editable, and left behind by
 * older builds - so the contract is that a bad value produces a default and
 * never a crash, and that one bad FIELD never takes its siblings with it.
 *
 * That last property is the one worth testing hardest. It is easy to write a
 * validator that returns null the moment anything is wrong, and the result is a
 * user who loses every setting on the tab because one of them was mistyped.
 */
import {
  LAYOUT_DEFAULTS,
  MOTION_DEFAULT,
  PACKET_LIST_DEFAULTS,
  PERFORMANCE_DEFAULTS,
  normalizeLayout,
  normalizeMinimap,
  normalizeMotion,
  normalizePacketList,
  normalizePerformance,
} from '../../src/services/interfacePrefs';
import { readFileSync } from 'node:fs';
import { ALIGNABLE_COLUMNS, DEFAULT_COLUMN_ALIGN } from '../../src/lib/packetColumns';

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

// --- Nothing that comes out of storage may throw ---------------------------

const HOSTILE: unknown[] = [null, undefined, 7, 'x', [], true, { __proto__: null }, NaN];

for (const [name, fn] of [
  ['normalizeLayout', normalizeLayout],
  ['normalizePacketList', normalizePacketList],
  ['normalizePerformance', normalizePerformance],
  ['normalizeMotion', normalizeMotion],
  ['normalizeMinimap', normalizeMinimap],
] as const) {
  let threw = false;
  for (const value of HOSTILE) {
    try {
      fn(value);
    } catch {
      threw = true;
    }
  }
  check(`${name} never throws on junk`, threw, false);
}

// --- Field-by-field defaulting ---------------------------------------------

{
  // The case that matters most: three bad fields, one good one, and the good
  // one must survive.
  const out = normalizeLayout({
    bottomPaneHeight: 'tall',
    detailsPaneRatio: null,
    panes: 'yes',
    arrangement: 'stacked',
  });
  check('one good field survives three bad siblings', out, {
    ...LAYOUT_DEFAULTS,
    arrangement: 'stacked',
  });
}

{
  // Asserted field by field rather than against the whole object: this shape
  // gains fields over time, and a whole-object expectation would fail every
  // time one is added while telling you nothing about the property under test.
  const out = normalizePacketList({ follow: 'nonsense', density: 'comfortable' });
  check('a bad follow mode defaults', out?.follow, PACKET_LIST_DEFAULTS.follow);
  check('...while density beside it survives', out?.density, 'comfortable');
  check('...and the fields the value never mentioned get their defaults', {
    timeFormat: out?.timeFormat,
    protocolColumn: out?.columns.protocol,
  }, {
    timeFormat: PACKET_LIST_DEFAULTS.timeFormat,
    protocolColumn: true,
  });
}

{
  // Alignment is a map now - one position per column - stored in the same
  // object as the columns, so the sibling-survival property applies to it too.
  check('a bad alignment defaults while a good column set survives', {
    align: normalizePacketList({ align: 'justified', columns: { length: false } })?.align,
    length: normalizePacketList({ align: 'justified', columns: { length: false } })?.columns.length,
  }, { align: DEFAULT_COLUMN_ALIGN, length: false });

  check('a column set to a position that does not exist falls back to its default', {
    ...normalizePacketList({ align: { source: 'justified', protocol: 'center' } })?.align,
  }, { ...DEFAULT_COLUMN_ALIGN, protocol: 'center' });

  /**
   * The migration, which is the part worth checking.
   *
   * `align` used to be ONE string covering every text column, with No., Time
   * and Length pinned right and excluded. Anyone who had chosen centred or
   * right has that single string in storage, and dropping it would silently
   * reset them with nothing on screen to explain why - so a stored string is
   * spread over exactly the columns it used to govern, and the numeric three
   * keep their own defaults. That reproduces what the old setting did.
   */
  check('an old single-value alignment is spread over the columns it used to govern',
    normalizePacketList({ align: 'center' })?.align,
    { ...DEFAULT_COLUMN_ALIGN, source: 'center', destination: 'center', protocol: 'center', info: 'center' });

  // The numeric columns default right and the rest left - which is what the
  // list drew before any of this existed. A default of anything else silently
  // rearranges every existing user's packet list on upgrade.
  check('the defaults are what the list already showed', PACKET_LIST_DEFAULTS.align, {
    id: 'right',
    relativeTime: 'right',
    length: 'right',
    source: 'left',
    destination: 'left',
    protocol: 'left',
    info: 'left',
  });

  // **Direction has no position to choose.** It is one glyph, centred always,
  // so it is not in the map at all - and a position stored for it by an older
  // build is dropped on load rather than carried, or it would sit in storage
  // governing nothing.
  check('Direction is not alignable', ALIGNABLE_COLUMNS.includes('direction' as never), false);
  check('...and a stored position for it is dropped on load',
    'direction' in (normalizePacketList({ align: { direction: 'left', source: 'right' } })?.align ?? {}), false);
  check('...while the rest of that stored map survives',
    normalizePacketList({ align: { direction: 'left', source: 'right' } })?.align.source, 'right');
  // The right-click menu opens only for a column with a position to choose.
  const list = readFileSync('src/components/packet-list/PacketList.tsx', 'utf8');
  check('the header menu is gated on an alignable column',
    list.includes('setAlignColumn(isAlignableColumn(column) ? column : null)'), true);
  check('...and the Direction cell is centred with no setting behind it',
    /cellAlign\('direction'\)/.test(list), false);
  // **Source's position moved nothing.** Its content is a flex row (the address
  // and the program that sent it), and a flex row ignores `text-align` - so
  // the cell's `text-*` class was stored, shown as chosen, and inert. The row
  // has to take the matching `justify-*` itself.
  check('the Source cell\'s flex row follows the chosen position',
    list.includes('min-w-0 ${COLUMN_JUSTIFY_CLASS[listPrefs.align.source]}'), true);
}

{
  // One bad field does not take the other down with it.
  const out = normalizePerformance({
    dashboardRefreshMs: 1234, packetBufferBytes: 256 * 1024 * 1024,
  });
  check('an unoffered refresh rate defaults while the budget survives', out, {
    dashboardRefreshMs: PERFORMANCE_DEFAULTS.dashboardRefreshMs,
    packetBufferBytes: 256 * 1024 * 1024,
  });
}

// --- Clamping, not rejecting -----------------------------------------------

{
  // A height stored on a much taller window must not leave the pane occupying a
  // screen it no longer fits - but it also must not throw the value away and
  // lose the user's other layout settings with it.
  const out = normalizeLayout({ ...LAYOUT_DEFAULTS, bottomPaneHeight: 99999 });
  check('an out-of-range height is clamped to the maximum', out?.bottomPaneHeight, 900);
  const low = normalizeLayout({ ...LAYOUT_DEFAULTS, bottomPaneHeight: -40 });
  check('...and a negative one to the minimum', low?.bottomPaneHeight, 100);
}

{
  // 0.9, and back to 0.9: it was 0.5 for as long as the map was a third pane
  // in that row, because a details pane at 0.9 would then have left a tenth of
  // the row for the dump AND the map together. The map is a view and nothing
  // else now, so the ceiling is the hex dump's tenth again.
  //
  // There were three more checks here and they went with the map: the same
  // clamp on `geoPaneRatio` at both ends, and the rule that the two shares are
  // stored INDEPENDENTLY with the interaction applied at the point of use. One
  // share has no interaction, so the ceiling is the whole clamp.
  const out = normalizeLayout({ ...LAYOUT_DEFAULTS, detailsPaneRatio: 4 });
  check('a details ratio beyond the split limits is clamped', out?.detailsPaneRatio, 0.9);
  const small = normalizeLayout({ ...LAYOUT_DEFAULTS, detailsPaneRatio: 0 });
  check('...at the bottom end too', small?.detailsPaneRatio, 0.1);
}

{
  // The buffer budget is SNAPPED rather than clamped: it is a choice between
  // the offered values, and an arbitrary number would render a segmented
  // control with nothing selected.
  //
  // **Compared against the DEFAULT rather than against a constant.** These two
  // pinned `DEFAULT_BUFFER_BUDGET_BYTES`, which was the default until ADR 0036
  // made it `'auto'` - and then they failed against correct code, asserting
  // yesterday's default rather than the rule, which is that an unreadable value
  // falls back to whatever the app ships with.
  const odd = normalizePerformance({ ...PERFORMANCE_DEFAULTS, packetBufferBytes: 33333 });
  check('an unoffered buffer budget falls back rather than clamping',
    odd?.packetBufferBytes, PERFORMANCE_DEFAULTS.packetBufferBytes);

  // The setting used to be a frame count, and a stored one has to fall back
  // rather than be read as bytes. 50,000 was the old default; taken as a
  // budget it is 50 kB, which is about seventy frames - a buffer that would
  // look broken and that nobody chose.
  const legacy = normalizePerformance({ dashboardRefreshMs: 500, packetBufferCap: 50000 });
  check('a buffer cap stored before this was a budget falls back',
    legacy?.packetBufferBytes, PERFORMANCE_DEFAULTS.packetBufferBytes);

  // And the value that default now IS, which nothing above would catch if
  // `'auto'` stopped being accepted: it would fall back to itself and pass.
  const auto = normalizePerformance({ dashboardRefreshMs: 500, packetBufferBytes: 'auto' });
  check("'auto' is a value the store accepts, not a fallback", auto?.packetBufferBytes, 'auto');

  const offered = normalizePerformance({
    ...PERFORMANCE_DEFAULTS, packetBufferBytes: 128 * 1024 * 1024,
  });
  check('an offered budget is kept', offered?.packetBufferBytes, 128 * 1024 * 1024);
}

// --- Motion is the one that must not drift ---------------------------------

{
  // Someone who set "never" did so because motion makes them ill. Anything
  // unrecognised has to land on the system setting, never on "always".
  check('motion accepts its three values', [
    normalizeMotion('system'), normalizeMotion('always'), normalizeMotion('never'),
  ], ['system', 'always', 'never']);
  check('an unrecognised motion value is rejected, not guessed', normalizeMotion('sometimes'), null);
  check('...and the caller falls back to following the system', MOTION_DEFAULT, 'system');
}

// --- Booleans are booleans -------------------------------------------------

{
  check('the minimap flag accepts true and false', [
    normalizeMinimap(true), normalizeMinimap(false),
  ], [true, false]);
  // "false" the string is the classic way a boolean preference goes wrong, and
  // it must not read as true.
  check('the string "false" is rejected rather than coerced', normalizeMinimap('false'), null);
  check('0 is rejected rather than coerced', normalizeMinimap(0), null);
}

// --- A round trip changes nothing ------------------------------------------

{
  const value = {
    bottomPaneHeight: 341, detailsPaneRatio: 0.42,
    panes: false, arrangement: 'stacked',
  };
  check('a valid layout survives a round trip unchanged',
    normalizeLayout(JSON.parse(JSON.stringify(value))), value);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
