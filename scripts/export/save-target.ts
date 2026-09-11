/**
 * Where an export goes, and how the answer comes back.
 *
 *   npx tsx scripts/export/save-target.ts
 *
 * Two halves of one boundary. `electron/saveTarget.ts` decides what the save
 * dialog is asked for; `src/lib/saveFile.ts` decides what its answer means.
 * Both are pure, and both are places where being wrong is silent: a filter
 * Electron cannot parse produces a dialog that matches no files, and a result
 * shape read loosely turns a cancel into a success.
 *
 * The dialog itself and the write are not here and cannot be - they are
 * `electron/saveFile.ts`, which imports `electron`. That split is the same one
 * `pipeTransport.ts` makes, and for the same reason.
 */
import { FALLBACK_NAME, filtersFor, safeName } from '../../electron/saveTarget';
import { narrowSaveResult } from '../../src/lib/saveFile';

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

console.log('--- the name the dialog opens with ---\n');

check('an ordinary export name passes through',
  safeName('inwire_capture_1725300000000.pcapng'), 'inwire_capture_1725300000000.pcapng');

// The renderer supplies this string. A dialog that opens where the page chose
// is a dialog that can be aimed - not a write anybody performs unknowingly,
// since the person still picks the path, but not something to hand over either.
check('a relative escape is reduced to its last segment',
  safeName('..\\..\\Windows\\System32\\drivers\\etc\\hosts'), 'hosts');
check('...and a POSIX one too, on every platform',
  safeName('../../etc/passwd'), 'passwd');
check('an absolute Windows path keeps only the name',
  safeName('C:\\Users\\someone\\Desktop\\evil.pcapng'), 'evil.pcapng');

// An empty `defaultPath` reads as "no suggestion" on one platform and as a
// directory on another, so it is never passed through.
check('an empty suggestion becomes the fallback', safeName(''), FALLBACK_NAME);
check('so does whitespace', safeName('   '), FALLBACK_NAME);
check('so does a bare dot', safeName('.'), FALLBACK_NAME);
check('so does a bare double dot', safeName('..'), FALLBACK_NAME);
// A trailing separator is not a reason to fall back: `basename` gives `dir`,
// which is a perfectly good filename, and substituting our own would discard
// something the caller meant.
check('a trailing separator still yields its last segment', safeName('some/dir/'), 'dir');
check('and so does a non-string', safeName(undefined), FALLBACK_NAME);

// A leading dot is a legitimate filename, not an escape.
check('a dotfile is a filename, not a traversal', safeName('.inwirerc'), '.inwirerc');

console.log('\n--- the type dropdown ---\n');

check('the requested type leads and "all files" follows',
  filtersFor({ suggestedName: 'x.pcapng', extensions: ['pcapng'], description: 'Capture file' }),
  [{ name: 'Capture file', extensions: ['pcapng'] }, { name: 'All files', extensions: ['*'] }]);

// Electron wants `pcapng`. Given `.pcapng` it builds a filter that matches
// nothing - not an error, just a dialog showing no files, which reads as "the
// folder is empty" rather than as a bug.
check('a leading dot is stripped rather than passed on',
  filtersFor({ suggestedName: 'x.pcap', extensions: ['.pcap'] })[0].extensions, ['pcap']);
check('...and the case is normalised',
  filtersFor({ suggestedName: 'x.PCAP', extensions: ['PCAP'] })[0].extensions, ['pcap']);

// The first entry is the DEFAULT. "All files" first would mean an export whose
// suggested name the person edits comes out with no extension at all.
check('"all files" is never the default',
  filtersFor({ suggestedName: 'x.zip', extensions: ['zip'] })[0].name !== 'All files', true);
check('...but is always offered, so nobody is trapped by our list',
  filtersFor({ suggestedName: 'x' }).some((f) => f.extensions[0] === '*'), true);
check('no extension means the dropdown is just "all files"',
  filtersFor({ suggestedName: 'x' }), [{ name: 'All files', extensions: ['*'] }]);
check('...and so does a list of empty strings',
  filtersFor({ suggestedName: 'x', extensions: ['', '.'] }),
  [{ name: 'All files', extensions: ['*'] }]);

console.log('\n--- reading the answer back ---\n');

// This is the half where being loose is dangerous. The bridge is typed
// `Promise<unknown>` because `desktop.d.ts` cannot import from `electron/`,
// so this function is the only thing standing between an unexpected shape and
// the app reporting a file it never wrote.
check('a real save comes back as one',
  narrowSaveResult({ saved: true, path: 'C:\\Users\\x\\capture.pcapng' }),
  { saved: true, path: 'C:\\Users\\x\\capture.pcapng' });
check('a cancel is a cancel',
  narrowSaveResult({ saved: false, canceled: true }), { saved: false, canceled: true });
check('a write failure carries its message',
  narrowSaveResult({ saved: false, canceled: false, error: 'EACCES: permission denied' }),
  { saved: false, canceled: false, error: 'EACCES: permission denied' });

// Everything below would, read loosely, become a success. Each must not.
const notSaved = (value: unknown) => narrowSaveResult(value).saved === false;
check('`saved: true` with no path is not a save', notSaved({ saved: true }), true);
check('...nor with a non-string path', notSaved({ saved: true, path: 42 }), true);
check('a truthy-but-wrong value is not a save', notSaved('ok'), true);
check('null is not a save', notSaved(null), true);
check('undefined is not a save', notSaved(undefined), true);
check('an empty object is not a save', notSaved({}), true);

// And a failure with no usable message still says something, because an error
// banner rendering an empty string reads as a rendering bug.
{
  const outcome = narrowSaveResult({ saved: false, canceled: false });
  check('a failure with no message still has one',
    outcome.saved === false && outcome.canceled === false && outcome.error.length > 0, true);
}

// The one that would be worst: a cancel must never be reported as an error,
// because pressing Cancel is the most common way this ends and is not a
// problem at all.
{
  const outcome = narrowSaveResult({ saved: false, canceled: true });
  check('a cancel carries no error for the UI to show',
    outcome.saved === false && outcome.canceled === true && !('error' in outcome), true);
}

console.log(failures === 0
  ? '\nAll save target checks passed.'
  : `\n${failures} save target check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
