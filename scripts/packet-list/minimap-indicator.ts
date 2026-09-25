/**
 * Assertion tests for where the packet map's "you are here" box sits.
 *
 *   npx tsx scripts/packet-list/minimap-indicator.ts
 *
 * Reported as "the minimap is too long so it goes under the ui when it's all
 * the way down". Measured in the running app on a real 3,714-frame capture:
 * the map ended at 635 px and the box, scrolled to the bottom, ran 631-639 -
 * past the end, under whatever sat below the list. The box has an 8 px floor so
 * it stays grabbable, and it was POSITIONED as if it had its proportional
 * height, which on a long capture is a fraction of a pixel. The first run at
 * 514 frames looked fine for exactly that reason: there the proportional
 * height was 28 px and the floor never applied.
 *
 * Put the old placement back - `top = scrollTop / scrollHeight * track` - and
 * the "flush with the end" checks fail.
 */
import { minimapIndicator, MIN_INDICATOR_HEIGHT } from '../../src/lib/minimapIndicator';

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
const round = (box: { top: number; height: number }) => ({ top: Math.round(box.top * 100) / 100, height: Math.round(box.height * 100) / 100 });

// The measured case: 3,714 frames, a 602 px list over a 567 px map.
const track = 567;
const client = 602;
const long = 87_836;
{
  const bottom = minimapIndicator(long - client, long, client, track);
  check('a long capture\'s box is held at its floor', bottom.height, MIN_INDICATOR_HEIGHT);
  check('...and at the bottom of the list it ends exactly where the map does',
    Math.round((bottom.top + bottom.height) * 100) / 100, track);
  check('...at the top of the list it starts where the map does',
    minimapIndicator(0, long, client, track).top, 0);
}

// Every position in between stays inside the map, not just the two ends.
{
  let escaped = 0;
  for (let scrollTop = 0; scrollTop <= long - client; scrollTop += 997) {
    const box = minimapIndicator(scrollTop, long, client, track);
    if (box.top < 0 || box.top + box.height > track + 1e-9) escaped++;
  }
  check('no scroll position puts the box outside the map', escaped, 0);
}

// Where the floor does not apply, the box is the proportional one - which is
// what it always was, so a short capture looks as it did.
{
  const short = 12_186;                                     // the 514-frame run
  const box = round(minimapIndicator(short - client, short, client, track));
  check('a short capture\'s box keeps its proportional height', box.height, Math.round((client / short) * track * 100) / 100);
  check('...and still ends flush at the bottom', Math.round((box.top + box.height) * 100) / 100, track);
}

check('a list that does not scroll fills the map', minimapIndicator(0, 400, 602, track), { top: 0, height: track });
check('an overscrolled position is clamped rather than overhanging',
  round(minimapIndicator(long, long, client, track)), round(minimapIndicator(long - client, long, client, track)));

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All minimap indicator checks passed.');
process.exit(0);
