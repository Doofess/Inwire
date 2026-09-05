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
import { DEFAULT_COLUMN_ALIGN } from '../../src/lib/packetColumns';

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
}

{
  const out = normalizePerformance({ dashboardRefreshMs: 1234, packetBufferCap: 25000 });
  check('an unoffered refresh rate defaults while the cap survives', out, {
    dashboardRefreshMs: PERFORMANCE_DEFAULTS.dashboardRefreshMs,
    packetBufferCap: 25000,
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
  const out = normalizeLayout({ ...LAYOUT_DEFAULTS, detailsPaneRatio: 4 });
  check('a ratio beyond the split limits is clamped', out?.detailsPaneRatio, 0.9);
}

{
  // The buffer cap is SNAPPED rather than clamped: it is a choice between three
  // offered values, and an arbitrary number would render a segmented control
  // with nothing selected.
  const out = normalizePerformance({ ...PERFORMANCE_DEFAULTS, packetBufferCap: 33333 });
  check('an unoffered buffer cap falls back rather than clamping', out?.packetBufferCap, 50000);
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
  const value = { bottomPaneHeight: 341, detailsPaneRatio: 0.42, panes: false, arrangement: 'stacked' };
  check('a valid layout survives a round trip unchanged',
    normalizeLayout(JSON.parse(JSON.stringify(value))), value);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
