/**
 * The import in progress, kept outside React, and the line that reports it.
 *
 *   npx tsx scripts/capture/import-job.ts
 *
 * `ImportPanel` is unmounted whenever the side bar shows another panel, and an
 * import of a large file now spans many turns of the renderer. The running
 * flag has to outlive the panel, or a closed and reopened side bar would offer
 * a second import over the first.
 */
import { importProgressPercent, importProgressSizes } from '../../src/lib/importProgress';
import {
  beginImportJob, endImportJob, getImportJob, importJobProgress, subscribeImportJob,
} from '../../src/services/importJob';
import {
  beginCaptureStart, endCaptureStart, importRefusal, isCaptureStarting, subscribeCaptureStarting,
} from '../../src/services/captureStarting';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- the line ---------------------------------------------------------------

// The zone shows the name on its own line and these sizes beneath the bar.
check('GB, one decimal, percentage floored',
  importProgressSizes(1_288_490_189, 2_682_861_736), '1.2 of 2.5 GB (48%)');
check('the owner\'s example: 1.2 of 2.7 GB (44%)',
  importProgressSizes(1.2 * 1024 ** 3 + 1, 2.7 * 1024 ** 3), '1.2 of 2.7 GB (44%)');
check('below 1 GiB: MB with no decimal',
  importProgressSizes(340 * 1024 * 1024, 812 * 1024 * 1024), '340 of 812 MB (41%)');
check('0 of 0 reads 0%, not NaN', importProgressSizes(0, 0), '0 of 0 MB (0%)');
check('the percentage never exceeds 100',
  importProgressSizes(2 * 1024 * 1024, 1024 * 1024), '2 of 1 MB (100%)');
check('the bar\'s percent is the same number, as a number',
  [importProgressPercent(1_288_490_189, 2_682_861_736), importProgressPercent(0, 0), importProgressPercent(9, 3)], [48, 0, 100]);

// --- the store --------------------------------------------------------------

let heard = 0;
const stop = subscribeImportJob(() => { heard++; });

check('starts idle', getImportJob(), { status: 'idle' });
importJobProgress(5);
check('progress while idle is ignored', [getImportJob(), heard], [{ status: 'idle' }, 0]);

check('begin succeeds', beginImportJob('cap.pcapng', 1000), true);
check('running state', getImportJob(), { status: 'running', fileName: 'cap.pcapng', readBytes: 0, totalBytes: 1000 });
check('a second begin is refused while running', beginImportJob('other.pcap', 5), false);
check('the refused begin changed nothing', (getImportJob() as { fileName?: string }).fileName, 'cap.pcapng');
const afterBegin = heard;
importJobProgress(400);
check('progress is published', [getImportJob(), heard], [
  { status: 'running', fileName: 'cap.pcapng', readBytes: 400, totalBytes: 1000 }, afterBegin + 1,
]);
endImportJob();
check('end returns to idle', getImportJob(), { status: 'idle' });
check('listeners heard begin, progress and end', heard, 3);
check('a new begin succeeds after the end', beginImportJob('b.pcap', 10), true);
endImportJob();

// --- the last result outlives the panel ----------------------------------------

const RESULT = { message: 'Imported 12 packets from a.pcap', notes: ['One row was skipped.'] };
beginImportJob('a.pcap', 10);
endImportJob(RESULT);
check('a finished import leaves its result in the idle state', getImportJob(), { status: 'idle', result: RESULT });
endImportJob();
check('a second end changes nothing', getImportJob(), { status: 'idle', result: RESULT });
const beforeSecond = heard;
importJobProgress(3);
check('progress while idle keeps the result and publishes nothing', [getImportJob(), heard], [
  { status: 'idle', result: RESULT }, beforeSecond,
]);
beginImportJob('b.pcap', 10);
check('the next import clears the result as it begins', getImportJob(), {
  status: 'running', fileName: 'b.pcap', readBytes: 0, totalBytes: 10,
});
endImportJob();
check('an import that ends with no result leaves none', getImportJob(), { status: 'idle' });

stop();
const quiet = heard;
beginImportJob('c.pcap', 1);
endImportJob();
check('an unsubscribed listener hears nothing', heard, quiet);

// --- an import and a Start: the first to begin wins -----------------------------
//
// `handleStartCapture` awaits twice before it opens its capture. An import
// pressed in those awaits found no live capture and no import, and the two
// interleaved on the one store. The decisions below are the two gates, called
// in the bad order with the module stores `App` and the panel read live.

/**
 * `ImportPanel.handleFile`'s head, as its source reads: refuse on the gate,
 * else begin the job. Returns whether the import began.
 */
function pressImport(file: string, blockedBy: string | null = null): { began: boolean; why: string | null } {
  const why = importRefusal({
    importRunning: getImportJob().status === 'running',
    captureStarting: isCaptureStarting(),
    blockedBy,
  });
  if (why !== null) return { began: false, why };
  return { began: beginImportJob(file, 100), why: null };
}

/** `handleStartCapture`'s head: refuse while an import runs, else mark the Start. */
function pressStart(): boolean {
  if (getImportJob().status === 'running') return false;
  beginCaptureStart();
  return true;
}

check('idle: an import may begin', pressImport('first.pcap').began, true);
endImportJob();

{
  // The bad order: Start is past its first line and in its awaits.
  check('Start begins when no import runs', pressStart(), true);
  check('...and an import pressed in its awaits is refused, with the reason',
    pressImport('late.pcap'), { began: false, why: 'Not while a capture is starting.' });
  check('...it never began the job', getImportJob().status, 'idle');
  check('...and the panel\'s own reason, when it has one, is shown instead', pressImport('late.pcap', 'Not while an export is running.').why,
    'Not while an export is running.');
  endCaptureStart();
  check('once Start has ended, the import may begin', pressImport('after.pcap').began, true);
  endImportJob();
}

{
  // The other order: the import is first, and Start must stay refused.
  pressImport('first.pcap');
  check('an import that is running refuses a Start, and marks nothing', [pressStart(), isCaptureStarting()], [false, false]);
  check('...and a second import is refused', pressImport('second.pcap').began, false);
  endImportJob();
}

{
  // Every exit of Start clears the mark: a throw must not shut imports for good.
  const run = async (body: () => Promise<void>) => {
    if (!pressStart()) return;
    try { await body(); } finally { endCaptureStart(); }
  };
  await run(async () => { await Promise.resolve(); });
  check('a Start that finishes clears the mark', isCaptureStarting(), false);
  await run(async () => { await Promise.resolve(); throw new Error('clearSession failed'); }).catch(() => {});
  check('a Start that throws clears the mark', isCaptureStarting(), false);
  check('...so an import may begin after it', pressImport('after-throw.pcap').began, true);
  endImportJob();
}

{
  // Two Starts in flight (a double press, a schedule under a press): the first
  // to end must not reopen the gate under the second.
  pressStart();
  pressStart();
  endCaptureStart();
  check('one of two Starts ended: still starting', isCaptureStarting(), true);
  check('...and the import is still refused', pressImport('x.pcap').began, false);
  endCaptureStart();
  check('both ended: not starting', isCaptureStarting(), false);
  endCaptureStart();
  check('an extra end does not go negative', [isCaptureStarting(), (beginCaptureStart(), isCaptureStarting())], [false, true]);
  endCaptureStart();

  let rang = 0;
  const unsubscribe = subscribeCaptureStarting(() => { rang++; });
  beginCaptureStart();
  beginCaptureStart();
  endCaptureStart();
  endCaptureStart();
  unsubscribe();
  check('listeners hear the edges only: on once, off once', rang, 2);
}

if (failures > 0) {
  console.log(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll import job checks passed.');
