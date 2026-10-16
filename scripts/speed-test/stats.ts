/**
 * What a finished speed test summarises to - spreads, responsiveness, the mean
 * past warm-up - and the log axis the latency boxes are drawn on.
 *
 *   npx tsx scripts/speed-test/stats.ts
 */
import { latencyDomain, logScale, meanPastWarmup, spread, summarise } from '../../src/services/speedTest/stats';
import { rpmBand } from '../../src/services/speedTest/method';
import type { LatencySample, SpeedTransfer } from '../../src/services/speedTest/protocol';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`}`);
}

const samples = (rtts: number[]): LatencySample[] => rtts.map((ms, i) => ({ tMs: i * 150, rttMs: ms, ttfbMs: ms + 1 }));
const transfer = (loaded: LatencySample[], trace: number[] = []): SpeedTransfer => ({
  mbps: 100, p10: 90, p90: 110, slices: trace.length, bytes: 0,
  loadedLatencyMs: null, connections: 12, trace, loaded, rampsAtMs: [],
});

console.log('--- spread ---');
{
  const s = spread([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])!;
  check('the median of one to ten', s.p50, 5.5);
  check('...counted', s.n, 10);
  check('...in order', s.p10 <= s.p25 && s.p25 <= s.p50 && s.p50 <= s.p75 && s.p75 <= s.p90, true);
  check('nothing has no spread', spread([]), null);
}

console.log('\n--- summarise ---');
{
  const empty = summarise({ idle: samples([3, 3, 3]), download: transfer([]), upload: transfer([]) }, 1500);
  check('empty phase: no spread, and no responsiveness to claim', [empty.download, empty.upload, empty.rpm], [null, null, null]);
  check('...while idle still has one', empty.idle?.n, 3);
  const s = summarise({ idle: samples([3]), download: transfer(samples([20, 20, 20])), upload: transfer(samples([40, 40, 40])) }, 1500);
  check('responsiveness is taken from the worse loaded median, as the grade is', s.rpm, 1500);
  check('the spread is of time to first byte, not the smoothed round trip', s.download?.p50, 21);
  const one = summarise({ idle: [], download: transfer(samples([30])), upload: transfer([]) }, 1500);
  check('one loaded phase is enough for responsiveness', one.rpm, 2000);
}

console.log('\n--- responsiveness bands ---');
check('299 RPM is Low', rpmBand(299), 'Low');
check('300 RPM is Medium', rpmBand(300), 'Medium');
check('1000 RPM is Medium', rpmBand(1000), 'Medium');
check('1001 RPM is High', rpmBand(1001), 'High');

console.log('\n--- mean past warm-up ---');
check('the warm-up slices are not counted', meanPastWarmup([10, 10, 10, 10, 100, 100, 100, 100], 400, 100), 100);
check('short transfer mean: the second half, as the figure falls back', meanPastWarmup([50, 70], 1500, 100), 70);
check('no slices, no mean', meanPastWarmup([], 1500, 100), null);

console.log('\n--- the log axis ---');
{
  const x = logScale(1, 100, 500);
  check('log axis: a decade is half of two', x(10), 250);
  check('log axis clamps below', x(0.01), 0);
  check('log axis clamps above', x(1e6), 500);
  check('...and a zero is not a NaN', x(0), 0);
  check('nothing measured yet: one to a hundred', latencyDomain([null]), [1, 100]);
  check('a domain is whole decades around what was measured',
    latencyDomain([{ n: 3, p10: 2, p25: 3, p50: 4, p75: 6, p90: 26 }]), [1, 100]);
  check('...floored at half a millisecond',
    latencyDomain([{ n: 3, p10: 0.3, p25: 0.4, p50: 0.5, p75: 0.6, p90: 0.7 }]), [0.5, 5]);
  check('...and never a sliver: at least a decade wide',
    latencyDomain([{ n: 3, p10: 10, p25: 10, p50: 10, p75: 10, p90: 10 }]), [10, 100]);
}

console.log(failures === 0 ? '\nAll speed-test summary checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
