/**
 * The dock's stored shape, its repairs, and the migration out of the old key.
 *
 *   npx tsx scripts/session/dock.ts
 *
 * The migration is the reason this script is worth more than most. It runs
 * **once per user**, on the first launch of the build that carries it, reading a
 * key the previous build wrote and writing one nothing has ever written. If it
 * is wrong there is no second chance: the old key is still there, but the new one
 * exists now, so the seed never runs again and whatever it produced is what that
 * person has. Every other preference bug is a bad default somebody can correct.
 *
 * The width arithmetic is here for a smaller reason: it is the one part of the
 * dock that depends on the window, and a window is exactly what an assertion
 * script does not have.
 */
import {
  clampDockWidth, defaultItems, dockOrder, maxDockWidth, migrateFromDashboard,
  normalizeDockPrefs, normalizeItems, reorderItems,
  DOCK_DEFAULTS, DOCK_DEFAULT_WIDTH, DOCK_MAX_WIDTH, DOCK_MIN_WIDTH, LIST_RESERVE, RAIL_WIDTH,
} from '../../src/services/dockPrefs';
import { WIDGET_TYPE_IDS } from '../../src/services/dashboardPrefs';
import { MIN_WINDOW_WIDTH } from '../../electron/window';

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

const types = (items: { type: string }[]): string[] => items.map((i) => i.type);
const open = (items: { type: string; open: boolean }[]): string[] =>
  items.filter((i) => i.open).map((i) => i.type);

console.log('--- the list is always every type, exactly once ---\n');

{
  check('a fresh dock lists every widget', types(defaultItems()), [...WIDGET_TYPE_IDS]);
  // Discoverability without stealing width: an empty dock does not teach a rail
  // group whose semantics are novel, and all five takes 260px before anybody
  // asked. The timeline is the one useful continuously while capturing.
  check('...with Traffic Timeline open and nothing else', open(defaultItems()), ['timeseries']);

  check('garbage is a fresh dock', types(normalizeItems('nonsense')), [...WIDGET_TYPE_IDS]);
  check('...and so is null', types(normalizeItems(null)), [...WIDGET_TYPE_IDS]);

  // A build that had a sixth widget. Dropping it must not drop its neighbours.
  const withUnknown = normalizeItems([
    { type: 'alerts', open: true }, { type: 'geo', open: true },
  ]);
  check('an unknown type is dropped', types(withUnknown).includes('alerts'), false);
  check('...and the rest is repaired to the full set', types(withUnknown).length,
    WIDGET_TYPE_IDS.length);
  check('...keeping what it could read', open(withUnknown), ['geo']);

  // Order is the payload here, so a repeat must not double an entry.
  const repeated = normalizeItems([
    { type: 'sizes', open: true }, { type: 'sizes', open: false },
  ]);
  check('a repeat is ignored rather than duplicated',
    types(repeated).filter((t) => t === 'sizes').length, 1);
  check('...and the first wins', open(repeated), ['sizes']);

  // Missing entries are appended in registry order, so a widget added in a later
  // build shows up at the bottom rather than making the key unreadable.
  const partial = normalizeItems([{ type: 'talkers', open: true }]);
  check('a partial list is completed', types(partial),
    ['talkers', ...WIDGET_TYPE_IDS.filter((t) => t !== 'talkers')]);

  // Field by field, the house rule: an unreadable flag must not discard its
  // siblings, and `open` defaults CLOSED because opening something nobody asked
  // for is the more intrusive way to be wrong.
  const junk = normalizeItems([{ type: 'geo', open: 'yes', pinned: 1 }]);
  check('a non-boolean open is closed, not opened', junk[0].open, false);
  check('...and a non-boolean pinned is unpinned', junk[0].pinned, false);
  check('...and the entry survives', junk[0].type, 'geo');
}

console.log('\n--- pinned items lead, and order is otherwise kept ---\n');

{
  const items = [
    { type: 'geo' as const, open: true, pinned: false },
    { type: 'timeseries' as const, open: false, pinned: true },
    { type: 'breakdown' as const, open: true, pinned: true },
    { type: 'sizes' as const, open: true, pinned: false },
  ];
  check('only open items are shown', types(dockOrder(items)), ['breakdown', 'geo', 'sizes']);
  // A pinned item that is CLOSED is not shown - pin holds a position, it does
  // not open anything. The two are separate switches and stay separate.
  checkTrue('a pinned but closed item stays closed',
    !types(dockOrder(items)).includes('timeseries'));
  check('...and unpinned items keep their relative order',
    types(dockOrder(items)).slice(1), ['geo', 'sizes']);
}

console.log('\n--- a drag-reorder lands on the open slots ---\n');

{
  // Four open, one closed and deliberately immovable: a widget closed and
  // reopened has to come back where it was, so `breakdown` keeps slot 2 through
  // every reorder below.
  const items = [
    { type: 'timeseries' as const, open: true, pinned: false },
    { type: 'geo' as const, open: true, pinned: false },
    { type: 'breakdown' as const, open: false, pinned: false },
    { type: 'sizes' as const, open: true, pinned: false },
    { type: 'talkers' as const, open: true, pinned: false },
    { type: 'counts' as const, open: false, pinned: false },
  ];
  const visible = types(dockOrder(items));
  check('the visible list is the open ones in stored order', visible,
    ['timeseries', 'geo', 'sizes', 'talkers']);

  // The regression. The version of this in `App.tsx` shifted a queue from inside
  // a `find` predicate, so the queue drained once per COMPARISON rather than once
  // per slot - `undefined` went into the list, the renderer read `undefined.open`
  // and died. Any reorder that moves the first element reproduced it, so that is
  // what this is.
  //
  // Checked by putting the bug back: the next check FAILS, and then `types()`
  // throws `Cannot read properties of undefined`, which is the renderer's own
  // crash reproduced in a script that needs neither Electron nor a browser. The
  // throw is left unguarded deliberately - the named failure comes first, and an
  // assertion suite that swallowed a hole in the list would be describing the
  // defect instead of refusing it.
  const moved = reorderItems(items, ['talkers', 'timeseries', 'geo', 'sizes']);
  check('a reorder contains no holes',
    moved.every((i) => i !== undefined && typeof i === 'object'), true);
  check('...and is still every type exactly once', types(moved).slice().sort(),
    [...WIDGET_TYPE_IDS].slice().sort());
  check('...with the new order in the open slots',
    types(dockOrder(moved)), ['talkers', 'timeseries', 'geo', 'sizes']);
  check('...and the closed item still in its own',
    moved.findIndex((i) => i.type === 'breakdown'), 2);
  check('...carrying its flags across', moved.map((i) => i.open),
    [true, true, false, true, true, false]);

  // Both ends, because an off-by-one in the insertion shows up there and nowhere
  // else.
  check('the first can move to the back',
    types(dockOrder(reorderItems(items, ['geo', 'sizes', 'talkers', 'timeseries']))),
    ['geo', 'sizes', 'talkers', 'timeseries']);
  check('an unchanged order is a no-op', types(reorderItems(items, visible)), types(items));

  // Every refusal returns the list UNCHANGED rather than asserting. A drop that
  // does nothing can be retried; a list with a hole in it crashed the renderer
  // and was persisted.
  check('a short order is refused', reorderItems(items, ['geo']), items);
  check('a long order is refused',
    reorderItems(items, ['timeseries', 'geo', 'sizes', 'talkers', 'breakdown']), items);
  check('a repeat is refused', reorderItems(items, ['geo', 'geo', 'sizes', 'talkers']), items);
  check('an unknown type is refused',
    reorderItems(items, ['alerts', 'geo', 'sizes', 'talkers']), items);
  // A closed type in the sequence means the caller built it from something other
  // than `dockOrder` - the one refusal where the open count can still match.
  check('a closed type in the order is refused',
    reorderItems(items, ['breakdown', 'geo', 'sizes', 'talkers']), items);
  const allClosed = items.map((i) => ({ ...i, open: false }));
  check('an empty dock is unchanged by a reorder', reorderItems(allClosed, []), allClosed);

  // A pin holds the top of the stack, so a drag that tries to push one down is
  // undone on the next render. That is the intended meaning of the flag, and it is
  // asserted so a later session does not read it as an off-by-one.
  const pinned = items.map((i) => (i.type === 'geo' ? { ...i, pinned: true } : i));
  check('a pinned item leads', types(dockOrder(pinned)),
    ['geo', 'timeseries', 'sizes', 'talkers']);
  check('...and cannot be dragged out of the lead',
    types(dockOrder(reorderItems(pinned, ['timeseries', 'geo', 'sizes', 'talkers']))),
    ['geo', 'timeseries', 'sizes', 'talkers']);
  check('...while the unpinned reorder around it',
    types(dockOrder(reorderItems(pinned, ['geo', 'talkers', 'sizes', 'timeseries']))),
    ['geo', 'talkers', 'sizes', 'timeseries']);
}

console.log('\n--- the width rule, against the window ---\n');

{
  // The reserve is derived from the packet list's columns, and the three numbers
  // have to add up at the minimum window or the dock has no room to exist.
  check('the minimum window fits a rail, a floor dock and the list reserve',
    RAIL_WIDTH + DOCK_MIN_WIDTH + LIST_RESERVE <= MIN_WINDOW_WIDTH, true);

  check('at the minimum window the dock maxes at 328', maxDockWidth(1024), 328);
  // The point of the reserve being 640 rather than 768: 88px of real travel at
  // the smallest supported window, so there is no degenerate case where min
  // equals max and a resize handle accepts a drag it cannot honour.
  checkTrue('...which leaves real travel', maxDockWidth(1024) - DOCK_MIN_WIDTH > 64);
  check('the stored maximum is reachable from 1336 up', maxDockWidth(1336), DOCK_MAX_WIDTH);
  check('...and not below it', maxDockWidth(1335), 639);

  check('a huge window still stops at the maximum', maxDockWidth(3840), DOCK_MAX_WIDTH);
  // Never below the floor, whatever the window says - a window narrower than the
  // app's own minimum is not a state the layout has to render well, but it must
  // not produce a negative width.
  check('an impossibly narrow window still yields the floor', maxDockWidth(200), DOCK_MIN_WIDTH);

  check('a drag past the right edge clamps', clampDockWidth(5000, 1920), DOCK_MAX_WIDTH);
  check('a drag past the left edge clamps', clampDockWidth(10, 1920), DOCK_MIN_WIDTH);
  check('NaN falls back to the default', clampDockWidth(Number.NaN, 1920), DOCK_DEFAULT_WIDTH);
  check('a fractional drag lands on a whole pixel', clampDockWidth(301.6, 1920), 302);

  // The one that would show as a dock opening narrower than its own default on a
  // fresh install: if `DOCK_DEFAULT_WIDTH` were ever raised above what the
  // minimum window allows, the first launch at 1024 would clamp it, and the
  // stored width would disagree with the one on screen from the start.
  check('the default is reachable at the minimum window',
    clampDockWidth(DOCK_DEFAULT_WIDTH, MIN_WINDOW_WIDTH), DOCK_DEFAULT_WIDTH);

  // Narrowing the window shrinks an open dock rather than squeezing the list -
  // and the STORED width is untouched, so widening gives back what the user
  // chose. That pair is the whole width contract, and neither half is observable
  // from inside the other.
  check('narrowing the window shrinks the dock', clampDockWidth(600, 1024), 328);
  check('...and widening it gives the chosen width back', clampDockWidth(600, 1336), 600);

  // The degenerate window, below the app's own minimum: min and max are both the
  // floor, so every drag resolves to the floor. It must not produce something
  // between them, and it must not go negative.
  check('below the app minimum every drag resolves to the floor',
    [clampDockWidth(500, 200), clampDockWidth(240, 200), clampDockWidth(1, 200)],
    [DOCK_MIN_WIDTH, DOCK_MIN_WIDTH, DOCK_MIN_WIDTH]);

  // Walked one pixel at a time across the whole supported range, because the
  // three constants and the reserve are four numbers whose relationship only has
  // to be wrong once. A clamp that can return less than the floor is a dock the
  // widgets do not fit; one that can exceed the window is a packet list pushed
  // off the right edge.
  const outOfRange: string[] = [];
  for (let windowWidth = MIN_WINDOW_WIDTH; windowWidth <= 3840; windowWidth++) {
    for (const asked of [0, 1, 239, 240, 260, 328, 639, 640, 641, 5000]) {
      const got = clampDockWidth(asked, windowWidth);
      const fits = got >= DOCK_MIN_WIDTH
        && got <= DOCK_MAX_WIDTH
        && got <= Math.max(DOCK_MIN_WIDTH, windowWidth - RAIL_WIDTH - LIST_RESERVE);
      if (!fits) outOfRange.push(`${asked}@${windowWidth} -> ${got}`);
    }
  }
  check('every clamp across every supported window lands in range',
    outOfRange.slice(0, 5), []);
}

console.log('\n--- hidden, which changes what a rail icon does ---\n');

{
  // The flag is persisted rather than local because it changes what the rail's
  // widget icons MEAN - toggle in the dock, or open in a window - and which one
  // is in force has to survive a restart, or the first click after every launch
  // is a surprise.
  check('a fresh dock is shown', DOCK_DEFAULTS.minimized, false);
  check('hidden survives the read', normalizeDockPrefs({ minimized: true, items: [] })?.minimized, true);
  check('shown survives the read', normalizeDockPrefs({ minimized: false, items: [] })?.minimized, false);

  // Defaults to SHOWN for anything unreadable, which is the less surprising way
  // to be wrong: a dock that is there when it should not be is one click from
  // correct, and one that is missing reads as a widget that stopped working.
  check('a missing flag is shown', normalizeDockPrefs({ items: [] })?.minimized, false);
  check('a string is shown', normalizeDockPrefs({ minimized: 'yes', items: [] })?.minimized, false);
  check('null is shown', normalizeDockPrefs({ minimized: null, items: [] })?.minimized, false);
  check('the number 1 is shown', normalizeDockPrefs({ minimized: 1, items: [] })?.minimized, false);

  // One bad field never discards its siblings - the house rule, applied to the
  // newest field.
  check('an unreadable flag keeps the items',
    open(normalizeDockPrefs({ minimized: 'x', items: [{ type: 'geo', open: true }] })?.items ?? []),
    ['geo']);
}

console.log('\n--- what is stored, and what is not ---\n');

{
  // Stored UNCLAMPED, deliberately: a width clamped to yesterday's narrow window
  // would never grow back when the window does.
  check('a stored width wider than today\'s window survives the read',
    normalizeDockPrefs({ width: 600, items: [] })?.width, 600);
  check('a missing width is the default',
    normalizeDockPrefs({ items: [] })?.width, DOCK_DEFAULT_WIDTH);
  check('a non-numeric width is the default',
    normalizeDockPrefs({ width: 'wide', items: [] })?.width, DOCK_DEFAULT_WIDTH);
  check('a non-object is refused whole', normalizeDockPrefs('nope'), null);
  // One bad field never discards its siblings.
  check('a bad width keeps the items',
    open(normalizeDockPrefs({ width: null, items: [{ type: 'geo', open: true }] })?.items ?? []),
    ['geo']);
}

console.log('\n--- the one-time migration out of inwire.dashboard ---\n');

{
  const widgets = [
    { type: 'sizes', enabled: true }, { type: 'geo', enabled: false },
    { type: 'talkers', enabled: true },
  ];

  // `full` means the column was on screen, so `enabled` is a real statement
  // about what the user wanted to see and carries across exactly.
  const shown = migrateFromDashboard({ mode: 'full', widgets })!;
  check('a full column carries its enabled widgets across', open(shown), ['sizes', 'talkers']);
  check('...and its order', types(shown).slice(0, 3), ['sizes', 'geo', 'talkers']);
  check('...completing the set', types(shown).length, WIDGET_TYPE_IDS.length);
  check('...with nothing pinned, because pinning did not exist',
    shown.some((i) => i.pinned), false);

  // The decision worth pinning down. `icons` and `hidden` meant the user was
  // not looking at any of them, so honouring the list would open up to five
  // widgets into a dock they never asked for on first launch.
  check('a collapsed column opens nothing', open(migrateFromDashboard({ mode: 'icons', widgets })!), []);
  check('...and neither does a hidden one',
    open(migrateFromDashboard({ mode: 'hidden', widgets })!), []);
  check('...but the order is still carried',
    types(migrateFromDashboard({ mode: 'icons', widgets })!).slice(0, 3),
    ['sizes', 'geo', 'talkers']);

  // Absent `mode` is an old enough key to predate it; the column was the only
  // thing there, so it was showing.
  check('a key with no mode is treated as showing',
    open(migrateFromDashboard({ widgets })!), ['sizes', 'talkers']);
  // Matches the old normaliser: absent meant on.
  check('an absent enabled means it was on',
    open(migrateFromDashboard({ mode: 'full', widgets: [{ type: 'geo' }] })!), ['geo']);

  check('nothing to migrate returns null', migrateFromDashboard(null), null);
  check('...and so does a key with no widgets', migrateFromDashboard({ mode: 'full' }), null);
  check('...and so does one whose widgets are all unknown',
    migrateFromDashboard({ mode: 'full', widgets: [{ type: 'alerts', enabled: true }] }), null);
}

console.log(failures === 0
  ? '\nAll dock checks passed.'
  : `\n${failures} dock check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
