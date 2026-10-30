/**
 * While a file is imported, nothing that replaces the capture may run.
 *
 *   npx tsx scripts/session/import-gate.ts
 *
 * An import reads its file a window at a time, so the renderer runs between
 * windows and a press made then is a real press. Start, a scheduled start,
 * Reopen, Clear View, Discard and an export would each change the capture the
 * import is writing into. `App.tsx` and `ImportPanel` are components this
 * script cannot mount, so it reads their source, function body by function
 * body (between two known ends, not a character window).
 *
 * The running flag is `importJob.ts`'s and not the panel's: the side bar can be
 * closed and reopened mid-import, which unmounts the panel.
 */
import { readFileSync } from 'node:fs';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== '') console.log(`        ${detail}`);
}

const app = readFileSync('src/App.tsx', 'utf8');
const panel = readFileSync('src/components/export/ImportPanel.tsx', 'utf8');
const transfer = readFileSync('src/components/sidebar/TransferPanel.tsx', 'utf8');
const welcome = readFileSync('src/components/packet-list/Welcome.tsx', 'utf8');
const settings = readFileSync('src/components/common/SettingsPane.tsx', 'utf8');
const job = readFileSync('src/services/importJob.ts', 'utf8');

/** The text between two known ends of `source`. */
function between(source: string, from: string, to: string): string {
  const start = source.indexOf(from);
  if (start === -1) throw new Error(`no "${from}"`);
  const end = source.indexOf(to, start + from.length);
  if (end === -1) throw new Error(`no "${to}" after "${from}"`);
  return source.slice(start, end);
}

const SCHEDULE_NOTICE = 'Scheduled capture skipped: a file was being imported.';
const RUNNING = "getImportJob().status === 'running'";

// --- the copy ---------------------------------------------------------------

check('the two reasons are the agreed words',
  job.includes("'Not while a file is being imported.'")
  && job.includes("'Importing a file - Start waits for it.'"));

// --- the panel --------------------------------------------------------------

const handleFile = between(panel, 'const handleFile = async', 'const onInputChange');
const beforeAwait = handleFile.slice(0, handleFile.indexOf('await'));
check('handleFile refuses while the job runs', beforeAwait.includes(RUNNING));
check('handleFile no longer keys its refusal on a local busy flag', !handleFile.includes('busy'));
check('handleFile begins the job before its first await', beforeAwait.includes('beginImportJob(file.name, file.size)'));
check('handleFile ends the job in finally', handleFile.slice(handleFile.indexOf('finally')).includes('endImportJob()'));
check('handleFile hands the progress callback to the import', handleFile.includes('onProgress: importJobProgress'));
check('the panel renders from useImportJob, so a remount shows the running import',
  panel.includes('useImportJob()') && panel.includes('importProgressText('));
check('the panel keeps no running flag of its own', !panel.includes('setBusy'));

// --- App --------------------------------------------------------------------

const startReason = between(app, 'const startBlockedReason =', 'const startBlockedRef');
check('Start waits while a file is imported', startReason.includes('IMPORT_RUNNING_START'));

const scheduled = between(app, 'const scheduledStart = ', 'const { now: scheduleNow }');
check('a scheduled start checks the job', scheduled.includes('getImportJob()'));
check('a scheduled start says why it was skipped', scheduled.includes(SCHEDULE_NOTICE));
check('the check comes before the capture is cleared',
  scheduled.indexOf('getImportJob()') < scheduled.indexOf('handleClearPackets()'));

const reopenHead = between(app, 'const reopenLastCapture = async', 'restoringRef.current = true');
check('Reopen refuses while the job runs', reopenHead.includes(RUNNING));

const clearView = between(app, 'const handleClearView = () =>', 'const handleDiscardCapture');
check('Clear View refuses while the job runs', clearView.includes(RUNNING));
check('...before it touches the list', clearView.indexOf(RUNNING) < clearView.indexOf('handleClearPackets()'));

const discard = between(app, 'const handleDiscardCapture = useCallback', '}, [adoptMarks]);');
check('Discard refuses while the job runs', discard.includes(RUNNING));
check('...before it cancels an export or clears the session',
  discard.indexOf(RUNNING) < discard.indexOf('cancelExportForChange'));

check('App reads the job for render-time reasons', app.includes('useImportJob()'));
check('Settings is told why Clear View and Discard are shut',
  between(app, '<SettingsPane', 'onFilterPresetLibraryChange').includes('importBlockedBy'));
check('both Reopen buttons carry the reason',
  (app.match(/blockedBy: importBlockedReason/g) ?? []).length === 2);

// --- the controls -----------------------------------------------------------

check('Settings disables Clear View and Discard on the reason',
  settings.includes('importBlockedBy') && (settings.match(/importBlockedBy !== null/g) ?? []).length >= 2
  && settings.includes('title={importBlockedBy'));
check('the welcome disables Reopen on the reason',
  between(welcome, 'onClick={previousCapture.onReopen}', 'Reopen the last capture').includes('previousCapture.blockedBy'));

const start = between(transfer, 'const start = async', 'const formats:');
check('export start refuses while the job runs', start.includes(RUNNING));
check('export controls are disabled while the job runs',
  between(transfer, 'const canExport =', 'const start = async').includes('importing'));
check('export rows say why', between(transfer, 'const formatRow =', 'return (').includes('IMPORT_RUNNING_REASON'));

if (failures > 0) {
  console.log(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll import gate checks passed.');
