/**
 * The speed test's arithmetic and its history; the state is `state.ts`.
 *
 *   npx tsx scripts/speed-test/method.ts
 */
import {
  bloatGrade, formatMbps, GAUGE_MARKS, gaugeFraction, resultGrade, jitter, median, netLatency, quantile, rpm,
  serverRttVarMs, serverTimeMs, shouldRamp, SliceCounter, transferFigure, MAX_CONNECTIONS, TEST_CAP_MB, TEST_CAP_TEXT,
} from '../../src/services/speedTest/method';
import { HISTORY_LIMIT, historyEntry, normalizeHistory, normalizeLastTrace } from '../../src/services/speedTest/history';
import type { SpeedResult } from '../../src/services/speedTest/protocol';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`}`);
}
const near = (a: number | null, b: number, eps = 1e-6) => a !== null && Math.abs(a - b) < eps;

console.log('--- statistics ---');
check('median of an odd count', median([5, 1, 3]), 3);
check('median of an even count interpolates', median([1, 2, 3, 4]), 2.5);
check('quantile 0.9', near(quantile([0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100], 0.9), 90), true);
check('nothing has no median', median([]), null);
check('jitter is the mean successive difference', jitter([10, 12, 11, 15]), (2 + 1 + 4) / 3);
check('one sample has no jitter', jitter([10]), null);

console.log('\n--- slices and the figure ---');
{
  const c = new SliceCounter(100);
  // 1 MB every 100 ms for 3 s = 80 Mb/s, then a partial last slice.
  for (let t = 0; t < 3000; t += 100) c.add(t + 50, 1_000_000);
  c.add(3010, 10);
  const f = transferFigure(c, 2000)!;
  check('a steady 1 MB per slice reads 80 Mb/s', near(f.mbps, 80), true);
  check('...the warm-up slices and the partial last one are dropped', f.slices, 10);
  check('...all bytes are counted', f.bytes, 30_000_010);
  check('mbpsOver a window', near(c.mbpsOver(1000, 2000), 80), true);
}
{
  const c = new SliceCounter(100);
  // Slow start: nothing like the link, then the link, with one stall.
  for (let t = 0; t < 2000; t += 100) c.add(t, 100_000);
  // Four stalled slices of thirty.
  const stalls = new Set([2500, 3000, 3500, 4000]);
  for (let t = 2000; t < 5000; t += 100) c.add(t, stalls.has(t) ? 0 : 1_250_000);
  c.add(5000, 1);
  const f = transferFigure(c, 2000)!;
  check('slow start does not drag the figure down', near(f.mbps, 100), true);
  check('...stalled slices move the median not at all, and show in p10', f.p10 < f.mbps, true);
}
{
  const c = new SliceCounter(100);
  for (let t = 0; t < 800; t += 100) c.add(t, 1_000_000);
  c.add(800, 5);
  check('a transfer too short for warm-up falls back to its second half', transferFigure(c, 2000)!.slices, 4);
}
{
  const c = new SliceCounter(100);
  c.add(20, 30_000_000);
  check('over inside one slice: bytes over the time taken', near(transferFigure(c, 2000, 40)!.mbps, 6000), true);
  check('...and with no time given there is no figure', transferFigure(c, 2000), null);
}
check('nothing moved, no figure', transferFigure(new SliceCounter(100), 2000, 1000), null);

console.log('\n--- ramping ---');
check('rising by 5% ramps', shouldRamp(12, 105, 100), true);
check('rising by less does not', shouldRamp(12, 103, 100), false);
check('never past the most connections', shouldRamp(MAX_CONNECTIONS, 500, 100), false);
check('not from nothing', shouldRamp(4, 100, 0), false);

console.log('\n--- latency ---');
check('the edge and the speed Worker are the server\'s time', serverTimeMs('cfSpeedEdge;dur=4, cfSpeedWorker;dur=26'), 30);
check('the server\'s TCP round trip wins when it is sent',
  netLatency(41, 'cfSpeedEdge;dur=6, cfSpeedWorker;dur=30, cfL4;desc="?proto=TCP&rtt=3412&min_rtt=2624&rtt_var=923"'), 3.412);
check('...and min_rtt is not mistaken for it', netLatency(41, 'cfL4;desc="?proto=TCP&min_rtt=2624&rtt=5000"'), 5);
check('the server\'s RTT variation is read as jitter', serverRttVarMs('cfL4;desc="?proto=TCP&rtt=3412&min_rtt=2624&rtt_var=923"'), 0.923);
check('...and nothing without it', serverRttVarMs('cfSpeedWorker;dur=26'), null);
check('cfRequestDuration wins where it is sent', serverTimeMs('cfRequestDuration;dur=3.5, cfSpeedWorker;dur=26'), 3.5);
check('no header, no server time', serverTimeMs(undefined), 0);
check('latency is net of the server', netLatency(30, 'cfSpeedWorker;dur=26'), 4);
check('...and never below a tenth of a millisecond', netLatency(20, 'cfSpeedWorker;dur=26'), 0.1);
check('RPM', rpm(10), 6000);

console.log('\n--- bufferbloat ---');
check('the bands', [[10, 12], [10, 30], [10, 60], [10, 150], [10, 300], [10, 500]].map(([i, l]) => bloatGrade(i, l)),
  ['A+', 'A', 'B', 'C', 'D', 'F']);
check('latency that fell under load is A+', bloatGrade(20, 10), 'A+');
check('a test graded on the worse loaded phase', resultGrade(10, 25, 80), 'C');
check('...or the one phase that answered', [resultGrade(10, null, 80), resultGrade(10, 80, null)], ['C', 'C']);
check('no loaded probe answered: no grade, not idle against idle', resultGrade(10, null, null), null);

console.log('\n--- the dial ---');
check('every mark is an equal step of arc', GAUGE_MARKS.map((m) => Math.round(gaugeFraction(m) * 8 * 1000) / 1000), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
check('between marks is linear', near(gaugeFraction(75), 3.5 / 8), true);
check('past the last mark the needle is pinned', gaugeFraction(2500), 1);
check('nothing, or nonsense, is zero', [0, -5, NaN].map(gaugeFraction), [0, 0, 0]);

console.log('\n--- formatting ---');
check('three significant figures', [0, 0.456, 5.678, 56.78, 567.8, 1234.5].map(formatMbps), ['0', '0.46', '5.68', '56.8', '568', '1235']);
check('the cap the consent copy quotes', [TEST_CAP_MB, TEST_CAP_TEXT], [2000, '2 GB']);

console.log('\n--- history ---');
const result: SpeedResult = {
  at: 1_791_550_000_000,
  server: { colo: 'TLV', coloCity: 'Tel Aviv', coloLat: 32.01, coloLon: 34.89, isp: 'Bezeq', asn: 6810, ip: '192.0.2.1', city: 'Petah Tikva' },
  latency: { idleMs: 3.2, jitterMs: 0.4, samples: 20, idle: [] },
  download: { mbps: 940, p10: 900, p90: 960, slices: 80, bytes: 1e9, loadedLatencyMs: 12, connections: 6, trace: [], loaded: [], rampsAtMs: [] },
  upload: { mbps: 41, p10: 38, p90: 43, slices: 80, bytes: 5e7, loadedLatencyMs: 30, connections: 4, trace: [], loaded: [], rampsAtMs: [] },
  grade: 'A',
  summary: { idle: null, download: null, upload: null, rpm: 2000, downMeanMbps: 935, upMeanMbps: 40 },
  bytesMoved: 1.05e9,
};
const entry = historyEntry(result);
check('a result as history keeps it', entry, {
  at: result.at, downMbps: 940, upMbps: 41, pingMs: 3.2, jitterMs: 0.4, grade: 'A', server: 'Tel Aviv', isp: 'Bezeq', colo: 'TLV', lat: 32.01, lon: 34.89,
  rpm: 2000, loadedDownMs: 12, loadedUpMs: 30,
});
check('history keeps no address', JSON.stringify(entry).includes('192.0.2.1'), false);
check('a stored history reads back', normalizeHistory([entry]), [entry]);
check('newest first, however it was stored', normalizeHistory([{ ...entry, at: 1 }, entry])!.map((e) => e.at), [result.at, 1]);
check('a damaged entry is dropped, not zeroed', normalizeHistory([entry, { at: 5, downMbps: 'fast' }, null, 7]), [entry]);
check('an unknown grade reads as ?', normalizeHistory([{ ...entry, grade: 'Z' }])![0].grade, '?');
check('not a list, no history', normalizeHistory({}), null);
check('no more than the limit', normalizeHistory(Array.from({ length: 80 }, (_, i) => ({ ...entry, at: i })))!.length, HISTORY_LIMIT);
check('old entry keeps no rpm, and no loaded latency: a dash, never a zero',
  (({ rpm, loadedDownMs, loadedUpMs }) => [rpm, loadedDownMs, loadedUpMs])(normalizeHistory([{ at: 1, downMbps: 10, upMbps: 2, pingMs: 5 }])![0]),
  [null, null, null]);
check('a result as history carries its responsiveness and loaded medians',
  [entry.rpm, entry.loadedDownMs, entry.loadedUpMs], [2000, 12, 30]);
check('damaged last trace is dropped', normalizeLastTrace({ at: 1, download: [1, 'x'], upload: [], warmupMs: 1500 }), null);
check('...a sound one reads back', normalizeLastTrace({ at: 1, download: [1, 2], upload: [3], warmupMs: 1500 }),
  { at: 1, download: [1, 2], upload: [3], warmupMs: 1500 });
check('...and an overlong one is refused', normalizeLastTrace({ at: 1, download: Array(401).fill(1), upload: [], warmupMs: 1500 }), null);

console.log(failures === 0 ? '\nAll speed-test method checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
