/**
 * The live capture pill: its two pure helpers and the source it is built from.
 *
 *   npx tsx scripts/session/live-pill.ts
 */
import { readFileSync } from 'node:fs';
import { formatRate, packetRate } from '../../src/lib/packetRate';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const rate = (a: [number, number], b: [number, number]): number =>
  packetRate({ total: a[0], at: a[1] }, { total: b[0], at: b[1] });

check('100 packets in a second is 100/s', rate([0, 0], [100, 1000]) === 100);
check('100 packets in 500 ms is 200/s', rate([0, 0], [100, 500]) === 200);
check('a total that goes down (a buffer reset) is 0', rate([500, 0], [10, 1000]) === 0);
check('the same timestamp is 0, not Infinity', rate([0, 1000], [100, 1000]) === 0);
check('a timestamp that goes back is 0', rate([0, 2000], [100, 1000]) === 0);

const cases: Array<[number, string]> = [
  [0, '0/s'], [950, '950/s'], [1234, '1.2k/s'], [36000, '36k/s'], [1_234_567, '1.2M/s'],
  [Number.NaN, '0/s'], [-5, '0/s'],
];
for (const [input, want] of cases) {
  const got = formatRate(input);
  check(`formatRate(${input}) is ${want}`, got === want, `got ${got}`);
}

const pill = readFileSync('src/components/common/CaptureLivePill.tsx', 'utf8');
check('the pill opts out of the drag region', pill.includes('app-no-drag'));
check('the stop button names itself', pill.includes('aria-label="Stop capture"'));
check('the pill has no font-mono', !pill.includes('font-mono'));
// Its clock and rate change every second. A live region (role="status" is one,
// polite and atomic) would have a screen reader read the whole pill out every
// second for as long as the capture runs.
check('the pill is not a live region',
  !/role="(status|log|alert|timer)"/.test(pill) && !/aria-live="(polite|assertive)"/.test(pill));
const titleRow = readFileSync('src/components/common/TitleRow.tsx', 'utf8');
check('TitleRow renders {live}', titleRow.includes('{live}'));
const status = readFileSync('src/components/status/SessionStatus.tsx', 'utf8');
check('SessionStatus exports useElapsed', /export function useElapsed\b/.test(status));

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
