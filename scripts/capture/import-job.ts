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
import { importProgressText } from '../../src/lib/importProgress';
import {
  beginImportJob, endImportJob, getImportJob, importJobProgress, subscribeImportJob,
} from '../../src/services/importJob';

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

check('GB, one decimal, percentage floored',
  importProgressText('cap.pcapng', 1_288_490_189, 2_682_861_736), 'Importing cap.pcapng: 1.2 of 2.5 GB (48%)');
check('below 1 GiB: MB with no decimal',
  importProgressText('cap.pcap', 340 * 1024 * 1024, 812 * 1024 * 1024), 'Importing cap.pcap: 340 of 812 MB (41%)');
check('0 of 0 reads 0%, not NaN', importProgressText('a.pcap', 0, 0), 'Importing a.pcap: 0 of 0 MB (0%)');
check('the percentage never exceeds 100',
  importProgressText('a.pcap', 2 * 1024 * 1024, 1024 * 1024), 'Importing a.pcap: 2 of 1 MB (100%)');

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

stop();
const quiet = heard;
beginImportJob('c.pcap', 1);
endImportJob();
check('an unsubscribed listener hears nothing', heard, quiet);

if (failures > 0) {
  console.log(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll import job checks passed.');
