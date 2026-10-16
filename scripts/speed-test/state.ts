/**
 * The state the speed test's surfaces draw: the reducer over the engine's
 * events, the live trace and the loaded samples it keeps.
 *
 *   npx tsx scripts/speed-test/state.ts
 */
import { IDLE, livePing, reduceSpeed, SAMPLE_POINTS, STARTING, TRACE_POINTS, type SpeedState } from '../../src/services/speedTest/state';
import type { SpeedEvent, SpeedResult, SpeedTransfer } from '../../src/services/speedTest/protocol';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`}`);
}

const transfer = (mbps: number): SpeedTransfer => ({
  mbps, p10: mbps * 0.95, p90: mbps * 1.02, slices: 80, bytes: 1e9, loadedLatencyMs: 12, connections: 6,
  trace: [], loaded: [], rampsAtMs: [],
});
const result: SpeedResult = {
  at: 1_791_550_000_000,
  server: { colo: 'TLV', coloCity: 'Tel Aviv', coloLat: 32.01, coloLon: 34.89, isp: 'Bezeq', asn: 6810, ip: '192.0.2.1', city: 'Petah Tikva' },
  latency: { idleMs: 3.2, jitterMs: 0.4, samples: 20, idle: [] },
  download: transfer(940),
  upload: transfer(41),
  grade: 'A',
  summary: { idle: null, download: null, upload: null, rpm: 2000, downMeanMbps: 935, upMeanMbps: 40 },
  bytesMoved: 1.05e9,
};
const progress = (mbps: number, sliceMbps: number, elapsedMs: number, connections: number, phase: 'download' | 'upload' = 'download'): SpeedEvent =>
  ({ type: 'progress', phase, mbps, sliceMbps, elapsedMs, connections });
const fold = (from: SpeedState, events: SpeedEvent[]) => events.reduce(reduceSpeed, from);

console.log('--- the run ---');
{
  let s = fold(STARTING, [
    { type: 'phase', phase: 'connecting' },
    { type: 'server', server: result.server },
    { type: 'phase', phase: 'latency' },
    { type: 'latency', ms: 4, jitterMs: null, ttfbMs: 4.5, tMs: 0 }, { type: 'latency', ms: 2, jitterMs: 2, ttfbMs: 2.5, tMs: 5 },
    { type: 'latency', ms: 3, jitterMs: 1.5, ttfbMs: 3.5, tMs: 10 },
    { type: 'phase', phase: 'download' },
    progress(500, 500, 100, 4),
    progress(700, 900, 200, 6),
  ]);
  check('running, in the download, with the server', [s.status, s.phase, s.server?.isp], ['running', 'download', 'Bezeq']);
  check('the ping tile shows the median so far', livePing(s), 3);
  check('...and the jitter tile the engine\'s estimate', s.liveJitterMs, 1.5);
  check('a latency event is an idle sample', s.loaded.idle.map((x) => x.ttfbMs), [4.5, 2.5, 3.5]);
  check('the figure follows the last progress', [s.liveMbps, s.connections], [700, 6]);
  check('the trace is the slice speeds, on the phase\'s clock', s.trace.download, [{ tMs: 100, mbps: 500 }, { tMs: 200, mbps: 900 }]);
  check('connections rising is a ramp step', s.rampsAtMs.download, [200]);
  s = fold(s, [10, 20, 30].map((ms, i): SpeedEvent => ({ type: 'loaded', phase: 'download', ms, ttfbMs: ms + 1, tMs: 300 + i * 150 })));
  check('loaded probes are kept in order', s.loaded.download.map((x) => x.rttMs), [10, 20, 30]);
  s = reduceSpeed(s, { type: 'figure', phase: 'download', figure: result.download });
  check('a finished download fills its tile', s.downloadMbps, 940);
  s = reduceSpeed(s, { type: 'phase', phase: 'upload' });
  check('the upload starts its figure from nothing', [s.liveMbps, s.connections], [0, 0]);
  check('...and keeps the download\'s trace, for the done view', s.trace.download.length, 2);
  s = fold(s, [progress(30, 30, 100, 12, 'upload'), progress(35, 40, 200, 14, 'upload')]);
  check('12 to 14 connections is one ramp step, and the first progress none', s.rampsAtMs.upload, [200]);
  s = reduceSpeed(s, { type: 'done', result });
  check('done', [s.status, s.phase, s.result?.grade], ['done', null, 'A']);
  check('the ping tile shows the result once there is one', livePing(s), 3.2);
  check('cancelled', reduceSpeed(s, { type: 'cancelled' }).status, 'cancelled');

  const again = reduceSpeed(s, { type: 'phase', phase: 'connecting' });
  check('a new run clears the trace, the samples and the ramps',
    [again.trace, again.loaded, again.rampsAtMs], [STARTING.trace, STARTING.loaded, STARTING.rampsAtMs]);
}

console.log('\n--- bounds ---');
{
  const many = fold({ ...STARTING, phase: 'download' }, Array.from({ length: 300 }, (_, i) => progress(i, i, (i + 1) * 100, 12)));
  check('the trace keeps TRACE_POINTS, the newest', [many.trace.download.length, many.trace.download[0].mbps], [TRACE_POINTS, 100]);
  const probes = fold({ ...STARTING, phase: 'download' },
    Array.from({ length: 300 }, (_, i): SpeedEvent => ({ type: 'loaded', phase: 'download', ms: i, ttfbMs: i, tMs: i })));
  check('the samples keep SAMPLE_POINTS, the newest', [probes.loaded.download.length, probes.loaded.download[0].rttMs], [SAMPLE_POINTS, 100]);
}

console.log('\n--- endings ---');
check('a failure says which phase and whether it was the rate limit',
  reduceSpeed(STARTING, { type: 'failed', phase: 'download', message: 'x', rateLimited: true }).error,
  { phase: 'download', message: 'x', rateLimited: true });
check('idle before anything', IDLE.status, 'idle');

console.log(failures === 0 ? '\nAll speed-test state checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
