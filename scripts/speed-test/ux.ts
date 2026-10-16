/**
 * The pure arithmetic behind the speed test sheet's small UX rules: where the
 * bracket's label sits so it never clips, the history strip's shared track,
 * the sentences a screen reader hears.
 *
 *   npx tsx scripts/speed-test/ux.ts
 */
import {
  bracketLabelPlacement, loadedOfHistory, monoTextWidth, pingStripDomain, pingStripLabel, pingStripX,
  rampTickLabel, resultAnnouncement,
} from '../../src/services/speedTest/stats';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`}`);
}
const checkTrue = (name: string, v: boolean) => check(name, v, true);

console.log('--- the bracket label stays inside the drawing ---');
{
  const text = '+398 ms under load';
  const w = monoTextWidth(text, 11);
  checkTrue('a mono string is wider the more characters it has', monoTextWidth('+1 ms', 11) < w);
  const bounds = { min: 0, max: 688 };
  const inside = (p: ReturnType<typeof bracketLabelPlacement>, width: number) => {
    const left = p.anchor === 'start' ? p.x : p.anchor === 'end' ? p.x - width : p.x - width / 2;
    return left >= bounds.min && left + width <= bounds.max;
  };
  const cases: [string, number, number][] = [
    ['room on the right', 120, 200],
    ['bracket near the right end', 200, 630],
    ['bracket spanning the whole axis', 90, 632],
    ['bracket at the far left', 90, 110],
    ['bracket at the far right', 600, 632],
    ['bracket at the very right edge of the drawing', 640, 688],
  ];
  for (const [name, x1, x2] of cases) {
    const p = bracketLabelPlacement({ x1, x2, width: w, ...bounds });
    checkTrue(`${name}: the label is fully inside`, inside(p, w));
  }
  const right = bracketLabelPlacement({ x1: 120, x2: 200, width: w, ...bounds });
  check('room on the right: starts just past the bracket', [right.anchor, right.x, right.below], ['start', 206, false]);
  const left = bracketLabelPlacement({ x1: 400, x2: 630, width: w, ...bounds });
  check('no room on the right: ends just before it', [left.anchor, left.below], ['end', false]);
  const both = bracketLabelPlacement({ x1: 90, x2: 632, width: w, ...bounds });
  check('no room either side: centred under the bracket', [both.anchor, both.below], ['middle', true]);
}

console.log('\n--- the history strip shares one track that holds every dot ---');
{
  const rows = [3, 12, 48, 180, 2, 900];
  const dom = pingStripDomain(rows);
  checkTrue('the domain contains every value, extremes included', dom[0] <= 2 && dom[1] >= 900);
  for (const v of rows) {
    const x = pingStripX(v, dom, 48, 4);
    checkTrue(`${v} ms lands on the track, clear of the ends`, x >= 4 && x <= 44);
  }
  checkTrue('...in order', pingStripX(2, dom) < pingStripX(12, dom) && pingStripX(12, dom) < pingStripX(900, dom));
  check('the smallest sits at the left pad, the largest at the right pad',
    [pingStripX(2, dom), pingStripX(900, dom)], [4, 44]);
  const flat = pingStripDomain([10, 10, 10]);
  checkTrue('identical values still get a real domain', flat[1] > flat[0]);
  check('...and sit in the middle of the track', pingStripX(10, flat), 24);
  check('nothing yet: a default domain', pingStripDomain([]), [1, 100]);
  check('zero and junk are ignored', pingStripDomain([0, -3, NaN, 5, 50]), [5, 50]);
  checkTrue('a value outside the domain clamps, never NaN', Number.isFinite(pingStripX(0, dom)) && pingStripX(1e9, dom) === 44);
}

console.log('\n--- an entry from before loaded latency says so ---');
{
  check('both loaded fields undefined: nothing loaded', loadedOfHistory(undefined, undefined), null);
  check('null is nothing too', loadedOfHistory(null, null), null);
  check('a zero is not a measurement', loadedOfHistory(0, 0), null);
  check('the worse one is taken', loadedOfHistory(40, 90), 90);
  check('one phase is enough', loadedOfHistory(undefined, 25), 25);
  check('label with loaded data', pingStripLabel(12, 48), 'Idle 12 ms, loaded 48 ms');
  check('label without it says so, never 0', pingStripLabel(12, null), 'Idle 12 ms, no loaded data');
  checkTrue('...and mentions no zero', !/\b0\b/.test(pingStripLabel(12, null)));
  check('fractions under ten ms', pingStripLabel(2.46, 26), 'Idle 2.5 ms, loaded 26 ms');
}

console.log('\n--- phase strip ticks ---');
{
  check('a tick says what it is and when', rampTickLabel(4200), 'More connections added at 4.2 s');
  check('...to one decimal', rampTickLabel(1000), 'More connections added at 1.0 s');
  checkTrue('a nonsense time does not print NaN', !/NaN|undefined/.test(rampTickLabel(NaN)));
}

console.log('\n--- what the live region says when the test is done ---');
{
  check('everything known',
    resultAnnouncement({ downMbps: 412.3, upMbps: 38.1, idleMs: 14.2, rpm: 640, grade: 'B' }),
    'Test complete. Download 412 megabits per second, upload 38.1, ping 14 milliseconds, responsiveness 640 RPM, medium, bufferbloat grade B.');
  const bare = resultAnnouncement({ downMbps: 412.3, upMbps: 38.1, idleMs: 14.2, rpm: null, grade: null });
  check('no loaded data: RPM and grade are left out',
    bare, 'Test complete. Download 412 megabits per second, upload 38.1, ping 14 milliseconds.');
  checkTrue('...and nothing says 0, null or undefined', !/\b0\b|null|undefined|NaN/.test(bare));
  check('a grade without RPM',
    resultAnnouncement({ downMbps: 100, upMbps: 20, idleMs: 9, rpm: null, grade: 'A+' }),
    'Test complete. Download 100 megabits per second, upload 20.0, ping 9 milliseconds, bufferbloat grade A+.');
  check('RPM without a grade',
    resultAnnouncement({ downMbps: 100, upMbps: 20, idleMs: 9, rpm: 250, grade: null }),
    'Test complete. Download 100 megabits per second, upload 20.0, ping 9 milliseconds, responsiveness 250 RPM, low.');
  check('a zero RPM is not a measurement',
    resultAnnouncement({ downMbps: 100, upMbps: 20, idleMs: 9, rpm: 0, grade: null }),
    'Test complete. Download 100 megabits per second, upload 20.0, ping 9 milliseconds.');
}

console.log(failures === 0 ? '\nAll speed-test UX checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
