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
check('handleFile ends the job in finally, with the result', handleFile.slice(handleFile.indexOf('finally')).includes('endImportJob(result)'));
check('handleFile awaits the lifecycle\'s begin before it reads the file',
  handleFile.indexOf('await onImportBegin?.()') !== -1
  && handleFile.indexOf('await onImportBegin?.()') < handleFile.indexOf('importAnyFile('));
check('a refusal and a throw both undo a begun import, before the dialog',
  (handleFile.match(/if \(begun\) onImportFailed\?\.\(\);\s+onFailure\(/g) ?? []).length === 2);
check('the import is handed the store\'s reach for its tail', handleFile.includes('bytesStoredThrough,'));
check('the last result is the job\'s, so a remounted panel still shows it',
  panel.includes('job.result?.message') && panel.includes('job.result?.notes') && !panel.includes('setStatus'));
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

const startCapture = between(app, 'const handleStartCapture = async () => {', 'await cancelExportForChange');
check('handleStartCapture refuses while the job runs, before anything else',
  startCapture.includes(RUNNING));
check('...a palette command and Ctrl+E reach it with only a render-time ref to stop them',
  app.includes("case 'capture.start': void handleStartCapture(); return;"));

const rail = readFileSync('src/components/common/ActivityRail.tsx', 'utf8');
const confirmEffect = between(rail, 'React.useEffect(() => {\n    if (isCapturing || !restartDiscards', '}, [isCapturing');
check('the rail\'s "Discard and start" confirm closes when Start becomes blocked',
  confirmEffect.includes('gate.blocked !== null') && rail.includes('[isCapturing, restartDiscards, gate.blocked]'));

// --- the import's order, bound in App ---------------------------------------------

check('stopCaptureAndSeal hands back the drain it started',
  app.includes('const stopCaptureAndSeal = (tellAgent: boolean): Promise<void> => {'));
check('...resolved at once when the capture is already sealed',
  between(app, 'const stopCaptureAndSeal =', 'stopCaptureRef.current = stopCaptureAndSeal').includes('?? Promise.resolve()'));
const lifecycleBegin = between(app, 'const importLifecycleEffects', 'const handleImportBatch');
check('the lifecycle seals through stopCaptureAndSeal(true) and not the bare stop',
  /stopAndSeal: \(\) => \(isCapturingRef\.current\s+\? stopCaptureAndSeal\(true\)/.test(lifecycleBegin));
check('...and empties the view with handleClearPackets, bypassing the Clear View gate',
  lifecycleBegin.includes('handleClearPackets()') && !lifecycleBegin.includes('handleClearView'));
check('...keeping the offer, so the view\'s offer stays null for the import',
  lifecycleBegin.includes('offeredCapture(sessionMetaNow())') && lifecycleBegin.includes('setLastCapture(null)'));
check('a failure re-offers the kept capture as Clear View does',
  lifecycleBegin.includes('setLastCapture(kept)') && lifecycleBegin.includes('void saveSessionMeta(kept)'));
check('a failure discards the import\'s directory and drops its derived answers',
  lifecycleBegin.includes('captureStore.discard(captureId)') && lifecycleBegin.includes('importDerivedRef.current = null'));
const batch = between(app, 'const handleImportBatch', 'const handleImportPackets');
check('the first batch opens the store through the lifecycle, and no longer stops the capture itself',
  batch.includes('importLifecycle.onBatch()') && !batch.includes('stopCaptureForImportRef'));
check('the success path takes the capture id from the lifecycle',
  between(app, 'const handleImportPackets', 'adoptMarks(EMPTY_MARKS)').includes('importLifecycle.succeed()'));
check('App hands the panel the lifecycle and the store\'s reach',
  app.includes('onImportBegin={handleImportBegin}') && app.includes('onImportFailed={handleImportFailed}')
  && app.includes('bytesStoredThrough={bytesStoredThrough}')
  && app.includes('captureStore.storedRange?.last ?? 0'));

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
