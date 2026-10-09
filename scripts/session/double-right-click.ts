/**
 * The globe's double right-click, told apart from its right-drag.
 *
 *   npx tsx scripts/session/double-right-click.ts
 */
import {
  createDoubleRightClick, DOUBLE_RIGHT_CLICK_MS, RIGHT_CLICK_MAX_MS, type RightRelease,
} from '../../src/lib/doubleRightClick';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`}`);
}
/** Presses and releases, each [x, y, downAt, upAt, upX?, upY?]. */
function run(clicks: [number, number, number, number, number?, number?][]): RightRelease[] {
  const c = createDoubleRightClick();
  return clicks.map(([x, y, down, up, ux, uy]) => {
    c.press({ x, y, at: down });
    return c.release({ x: ux ?? x, y: uy ?? y, at: up });
  });
}

check('two quick clicks in one place are a double', run([[100, 100, 0, 80], [101, 100, 200, 280]]), ['click', 'double']);
check('a third click starts a new pair', run([[100, 100, 0, 80], [100, 100, 200, 280], [100, 100, 400, 480]]), ['click', 'double', 'click']);
check('clicks too far apart in time are two singles',
  run([[100, 100, 0, 80], [100, 100, 80 + DOUBLE_RIGHT_CLICK_MS + 1, 80 + DOUBLE_RIGHT_CLICK_MS + 60]]), ['click', 'click']);
check('clicks too far apart in place are two singles', run([[100, 100, 0, 80], [140, 100, 200, 280]]), ['click', 'click']);
check('a press held too long is a drag, not a click', run([[100, 100, 0, RIGHT_CLICK_MAX_MS + 1]]), ['drag']);
check('a press that moved is a drag', run([[100, 100, 0, 80, 130, 100]]), ['drag']);
check('a drag between two clicks breaks the pair',
  run([[100, 100, 0, 80], [100, 100, 150, 200, 160, 100], [100, 100, 260, 300]]), ['click', 'drag', 'click']);
check('a short rotate then a click is not a double', run([[100, 100, 0, 80, 120, 110], [100, 100, 150, 220]]), ['drag', 'click']);

console.log(failures === 0 ? '\nAll double-right-click checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
