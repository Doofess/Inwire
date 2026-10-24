/**
 * Assertion tests for the first-run tour's anchors.
 *
 *   npx tsx scripts/accessibility/tour.ts
 *
 * A tour step finds its target with `document.querySelector('[data-tour="..."]')`.
 * That is the right trade - the alternative threads a ref from the step list
 * down into the header, the packet pane and the details pane, putting a
 * tour-shaped prop on four component signatures that have nothing to do with
 * the tour - but it buys the flexibility with a string that the compiler cannot
 * check.
 *
 * So this checks it. Someone edits the header, the attribute goes with the
 * rewrite, and nothing anywhere raises a word: the step quietly measures null,
 * the overlay advances past it, and the one part of the app written for people
 * who have never seen it before is a step shorter for everybody. That is the
 * bug this file exists for.
 *
 * Both directions matter. An anchor with no attribute is a dead step; an
 * attribute no step claims is a marker left behind by a deleted step, which is
 * the kind of thing that gets "tidied up" by someone who cannot tell whether it
 * is load-bearing.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TOUR_STEPS, tourSteps } from '../../src/components/tour/tourSteps';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

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

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

// The tour's own files are excluded from the scan. `TourOverlay` builds the
// selector and `tourSteps` documents it, so counting either as a placed anchor
// would let the tour satisfy itself.
const TOUR_DIR = join(root, 'src', 'components', 'tour');
const sources = walk(join(root, 'src')).filter((f) => !f.startsWith(TOUR_DIR));

const placed = new Set<string>();
for (const file of sources) {
  for (const m of readFileSync(file, 'utf8').matchAll(/data-tour="([a-z-]+)"/g)) {
    placed.add(m[1]);
  }
}

const wanted = TOUR_STEPS.map((s) => s.anchor);

check('every tour step has a data-tour anchor in the app',
  wanted.filter((a) => !placed.has(a)), []);

check('...and every data-tour anchor is claimed by a step',
  [...placed].filter((a) => !wanted.includes(a as (typeof wanted)[number])), []);

// --- The steps themselves ----------------------------------------------------

// It used to start on the menu, because installing the driver from there was
// the thing nothing else worked without. The agent ships with the app now, so
// a first-run user has nothing to do before capturing and the tour opens on
// their first actual decision instead.
check('the tour starts where the first action is - choosing an adapter',
  TOUR_STEPS[0]?.anchor, 'interfaces');

// The step that told people to download a driver is gone, and its wording must
// not come back by way of a copy edit: there is nothing to download and no menu
// entry to choose.
check('no step tells anybody to install or download anything',
  TOUR_STEPS.filter((s) => /download|install/i.test(`${s.title} ${s.body}`)).map((s) => s.anchor),
  []);

check('no step is listed twice', wanted.length, new Set(wanted).size);

check('every step says something',
  TOUR_STEPS.filter((s) => !s.title.trim() || s.body.trim().length < 20).map((s) => s.anchor), []);

// The tour is asked for, never sprung. It used to open on first run over three
// empty states; the welcome is the front door now, and the tour is its
// "Take the tour" link and the palette's `help.tour`.
const app = readFileSync(join(root, 'src', 'App.tsx'), 'utf8');
const commands = readFileSync(join(root, 'src', 'lib', 'commands.ts'), 'utf8');
check('the overlay is shown only when the tour was asked for',
  [/\{tourOpen && \(\s*<TourOverlay/.test(app), app.includes('!tour.completed &&')], [true, false]);
check('the palette lists help.tour', /id: 'help\.tour'/.test(commands), true);
check('App binds help.tour', /case 'help\.tour':/.test(app), true);

// Taken from the welcome - its main way in - there is no list and no detail
// pane on screen. The list step must describe what IS there, and the detail
// step goes, rather than measuring nothing and ending the tour unannounced.
const onWelcome = tourSteps(true);
const listOnWelcome = onWelcome.find((s) => s.anchor === 'list');
check('from the welcome the tour has no detail step',
  onWelcome.map((s) => s.anchor).includes('detail'), false);
check('...and its list step does not describe rows that are not there',
  /each row/i.test(listOnWelcome?.body ?? 'each row'), false);
check('...and it ends on the rail', onWelcome[onWelcome.length - 1]?.anchor, 'rail');
check('with packets on screen it is the full tour', tourSteps(false), TOUR_STEPS);
check('App hands the overlay the steps for what is on screen',
  /<TourOverlay\s+steps=\{tourSteps\(showWelcome\)\}/.test(app), true);

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All tour checks passed.');
process.exit(0);
