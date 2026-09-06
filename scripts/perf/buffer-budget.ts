/**
 * Does the buffer budget's estimate match the memory frames actually take?
 *
 *   node --expose-gc --import tsx scripts/perf/buffer-budget.ts
 *
 * The packet buffer is limited by a memory budget the user sets, and the app
 * decides when to trim by **estimating** what each frame costs
 * (`services/bufferBudget.ts`). That puts a model behind a number the user
 * believes: ask for 512 MB and an estimator out by a factor of two gives you a
 * gigabyte or a quarter of one, with nothing on screen to say so.
 *
 * So the estimate is only worth having if its error is known, and this is what
 * knows it. It dissects both fixtures, sums the estimator over every frame, and
 * compares that against the heap those same frames actually occupy - measured
 * the way `record-cost.ts` measures it, with `arrayBuffers` counted as well as
 * `heapUsed`, because the column blocks are typed arrays and live outside the
 * JS heap.
 *
 * **It is an assertion, not a measurement**: past `MAX_ERROR` it fails. That is
 * the difference between a calibrated model and a plausible number, and this
 * work has produced several of the latter.
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { clearAddressPool } from '../../src/services/addressFormat';
import { estimateSummaryBytes } from '../../src/services/bufferBudget';
import type { Packet } from '../../src/types/packet';

const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/bulk_capture_1788426090876.pcap',
];

/** How far the estimate may be from the measurement before this fails. */
const MAX_ERROR = 0.15;

const EMPTY = new Uint8Array(0);

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

function heap(): number {
  if (global.gc) for (let i = 0; i < 6; i++) global.gc();
  const usage = process.memoryUsage();
  // The column blocks are typed arrays, whose bytes are not on the JS heap.
  // Counting only `heapUsed` is how ADR 0017 came to report them at 47 B a
  // frame when they were 243.
  return usage.heapUsed + usage.arrayBuffers;
}

async function main() {
  const missing = FIXTURES.filter((f) => !existsSync(f));
  if (missing.length > 0) {
    console.log('SKIP  fixture missing: ' + missing[0] + ' (see test/fixtures/README.md)');
    process.exit(0);
  }
  if (!global.gc) {
    // Skipped rather than failed, so `npm run check` can carry it - but said
    // plainly, because a check that quietly passes without checking anything is
    // worse than one that is absent.
    console.log('SKIP  the calibration was NOT verified: this needs --expose-gc.');
    console.log('      node --expose-gc --import tsx scripts/perf/buffer-budget.ts');
    process.exit(0);
  }

  // Dissected and held, exactly as the buffer holds them: raw bytes shared to
  // one empty array, since the budget deliberately does not govern them - they
  // are bounded separately at 25,000 frames.
  clearAddressPool();
  const before = heap();
  let held: Packet[] | undefined = [];
  for (const path of FIXTURES) {
    const parsed = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(path))], 'fixture.pcap'), 1_000_000,
    );
    for (const packet of parsed.packets) {
      packet.rawBytes = EMPTY;
      held.push(packet);
    }
  }
  const measured = heap() - before;
  const frames = held.length;

  let estimated = 0;
  let minEstimate = Infinity;
  let maxEstimate = 0;
  for (const packet of held) {
    const bytes = estimateSummaryBytes(packet);
    estimated += bytes;
    if (bytes < minEstimate) minEstimate = bytes;
    if (bytes > maxEstimate) maxEstimate = bytes;
  }
  // Read after measuring so nothing is collected early.
  if (held.length !== frames) throw new Error('lost frames');
  held = undefined;
  void held;

  const error = (estimated - measured) / measured;

  console.log(frames.toLocaleString() + ' dissected frames, raw bytes excluded');
  console.log();
  console.log('  measured            ' + (measured / frames).toFixed(0).padStart(6) + ' B/frame   '
    + (measured / 1024 / 1024).toFixed(1) + ' MB');
  console.log('  estimated           ' + (estimated / frames).toFixed(0).padStart(6) + ' B/frame   '
    + (estimated / 1024 / 1024).toFixed(1) + ' MB');
  console.log('  error               ' + (error * 100).toFixed(1).padStart(6) + ' %'
    + '   (allowed +/-' + (MAX_ERROR * 100).toFixed(0) + '%)');
  console.log();
  console.log('  per frame, spread   ' + minEstimate + ' B min, ' + maxEstimate + ' B max');
  console.log('  a 512 MB budget holds about '
    + Math.floor((512 * 1024 * 1024) / (estimated / frames)).toLocaleString() + ' frames');
  console.log();

  check('the estimate is within ' + (MAX_ERROR * 100).toFixed(0) + '% of the measurement',
    Math.abs(error) <= MAX_ERROR, true);

  // A frame's estimate must never be zero or negative: the running total would
  // stop rising and the buffer would never trim.
  check('every frame estimates to something positive', minEstimate > 0, true);

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    console.log('Recalibrate BASE / PER_SPARSE_KEY in services/bufferBudget.ts from the');
    console.log('numbers above rather than from an older document.');
    process.exit(1);
  }
  console.log('All buffer-budget calibration checks passed.');
  process.exit(0);
}

main();
