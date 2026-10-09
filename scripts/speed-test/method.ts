/**
 * The speed test's arithmetic, its history and the state its surfaces draw.
 *
 *   npx tsx scripts/speed-test/method.ts
 */
import {
  bloatGrade, formatMbps, GAUGE_MARKS, gaugeFraction, jitter, median, netLatency, quantile, rpm,
  serverTimeMs, shouldRamp, SliceCounter, transferFigure, MAX_CONNECTIONS, TEST_CAP_MB,
} from '../../src/services/speedTest/method';
import { HISTORY_LIMIT, historyEntry, normalizeHistory } from '../../src/services/speedTest/history';
import { IDLE, livePing, reduceSpeed, STARTING, type SpeedState } from '../../src/services/speedTest/state';
import type { SpeedEvent, SpeedResult } from '../../src/services/speedTest/protocol';

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
check('rising by 10% ramps', shouldRamp(4, 110, 100), true);
check('rising by less does not', shouldRamp(4, 105, 100), false);
check('never past the most connections', shouldRamp(MAX_CONNECTIONS, 500, 100), false);
check('not from nothing', shouldRamp(4, 100, 0), false);

console.log('\n--- latency ---');
check('the speed Worker\'s time is the server\'s', serverTimeMs('cfSpeedEdge;dur=4, cfSpeedWorker;dur=26'), 26);
check('cfRequestDuration wins where it is sent', serverTimeMs('cfRequestDuration;dur=3.5, cfSpeedWorker;dur=26'), 3.5);
check('no header, no server time', serverTimeMs(undefined), 0);
check('latency is net of the server', netLatency(30, 'cfSpeedWorker;dur=26'), 4);
check('...and never below a tenth of a millisecond', netLatency(20, 'cfSpeedWorker;dur=26'), 0.1);
check('RPM', rpm(10), 6000);

console.log('\n--- bufferbloat ---');
check('the bands', [[10, 12], [10, 30], [10, 60], [10, 150], [10, 300], [10, 500]].map(([i, l]) => bloatGrade(i, l)),
  ['A+', 'A', 'B', 'C', 'D', 'F']);
check('latency that fell under load is A+', bloatGrade(20, 10), 'A+');

console.log('\n--- the gauge ---');
check('every mark is an equal step of arc', GAUGE_MARKS.map((m) => Math.round(gaugeFraction(m) * 8 * 1000) / 1000), [0, 1, 2, 3, 4, 5, 6, 7, 8]);
check('between marks is linear', near(gaugeFraction(75), 3.5 / 8), true);
check('past the last mark the needle is pinned', gaugeFraction(2500), 1);
check('nothing, or nonsense, is zero', [0, -5, NaN].map(gaugeFraction), [0, 0, 0]);
check('three significant figures', [0, 0.456, 5.678, 56.78, 567.8, 1234.5].map(formatMbps), ['0', '0.46', '5.68', '56.8', '568', '1235']);
check('the cap the consent copy quotes', TEST_CAP_MB, 1300);

console.log('\n--- history ---');
const result: SpeedResult = {
  at: 1_791_550_000_000,
  server: { colo: 'TLV', coloCity: 'Tel Aviv', isp: 'Bezeq', asn: 6810, ip: '192.0.2.1', city: 'Petah Tikva' },
  latency: { idleMs: 3.2, jitterMs: 0.4, samples: 20 },
  download: { mbps: 940, p10: 900, p90: 960, slices: 80, bytes: 1e9, loadedLatencyMs: 12, connections: 6 },
  upload: { mbps: 41, p10: 38, p90: 43, slices: 80, bytes: 5e7, loadedLatencyMs: 30, connections: 4 },
  grade: 'A',
  bytesMoved: 1.05e9,
};
const entry = historyEntry(result);
check('a result as history keeps it', entry, {
  at: result.at, downMbps: 940, upMbps: 41, pingMs: 3.2, jitterMs: 0.4, grade: 'A', server: 'Tel Aviv', isp: 'Bezeq',
});
check('history keeps no address', JSON.stringify(entry).includes('192.0.2.1'), false);
check('a stored history reads back', normalizeHistory([entry]), [entry]);
check('newest first, however it was stored', normalizeHistory([{ ...entry, at: 1 }, entry])!.map((e) => e.at), [result.at, 1]);
check('a damaged entry is dropped, not zeroed', normalizeHistory([entry, { at: 5, downMbps: 'fast' }, null, 7]), [entry]);
check('an unknown grade reads as ?', normalizeHistory([{ ...entry, grade: 'Z' }])![0].grade, '?');
check('not a list, no history', normalizeHistory({}), null);
check('no more than the limit', normalizeHistory(Array.from({ length: 80 }, (_, i) => ({ ...entry, at: i })))!.length, HISTORY_LIMIT);

console.log('\n--- the state the surfaces draw ---');
{
  const events: SpeedEvent[] = [
    { type: 'phase', phase: 'connecting' },
    { type: 'server', server: result.server },
    { type: 'phase', phase: 'latency' },
    { type: 'latency', ms: 4 }, { type: 'latency', ms: 2 }, { type: 'latency', ms: 3 },
    { type: 'phase', phase: 'download' },
    { type: 'progress', phase: 'download', mbps: 500, elapsedMs: 100, connections: 4 },
    { type: 'progress', phase: 'download', mbps: 900, elapsedMs: 200, connections: 6 },
  ];
  let s: SpeedState = STARTING;
  for (const e of events) s = reduceSpeed(s, e);
  check('running, in the download, with the server', [s.status, s.phase, s.server?.isp], ['running', 'download', 'Bezeq']);
  check('the ping tile shows the median so far', livePing(s), 3);
  check('the dial follows the last progress', [s.liveMbps, s.connections, s.spark], [900, 6, [500, 900]]);
  s = reduceSpeed(s, { type: 'figure', phase: 'download', figure: result.download });
  check('a finished download fills its tile', s.downloadMbps, 940);
  s = reduceSpeed(s, { type: 'phase', phase: 'upload' });
  check('the upload starts its dial and sparkline from nothing', [s.liveMbps, s.spark.length], [0, 0]);
  s = reduceSpeed(s, { type: 'done', result });
  check('done', [s.status, s.phase, s.result?.grade], ['done', null, 'A']);
  check('the ping tile shows the result once there is one', livePing(s), 3.2);
  check('a failure says which phase and whether it was the rate limit',
    reduceSpeed(STARTING, { type: 'failed', phase: 'download', message: 'x', rateLimited: true }).error,
    { phase: 'download', message: 'x', rateLimited: true });
  check('cancelled', reduceSpeed(s, { type: 'cancelled' }).status, 'cancelled');
  check('idle before anything', IDLE.status, 'idle');
}

console.log(failures === 0 ? '\nAll speed-test method checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
