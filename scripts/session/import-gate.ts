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
// The phases' order moved to `importFlow.ts` (a script can run it, which it cannot
// do to the panel); the panel hands it the lifecycle's begin and failed.
const earlyFlow = readFileSync('src/services/importFlow.ts', 'utf8');
check('handleFile hands the flow the lifecycle\'s begin and failed, and the flow awaits begin before it reads the file',
  handleFile.includes('begin: onImportBegin') && handleFile.includes('failed: onImportFailed')
  && earlyFlow.indexOf('await deps.begin?.()') !== -1
  && earlyFlow.indexOf('await deps.begin?.()') < earlyFlow.indexOf('await deps.read()'));
check('a refusal and a throw both undo a begun import, before the dialog (the flow runs `failed` before it returns)',
  (earlyFlow.match(/deps\.failed\?\.\(\);\s+return \{ status: 'failed'/g) ?? []).length === 1
  && /if \(begun\) deps\.failed\?\.\(\);\s+return \{\s+status: 'failed'/.test(earlyFlow)
  && handleFile.indexOf('await runImportFlow(') < handleFile.indexOf('onFailure('));
// The tail's byte release used to be a callback handed down to the walk on this
// thread; the Worker route writes to the store itself and learns the store's reach
// from App's `storedThrough` (checked below), so the panel hands over the route.
check('the import is handed the Worker route, which keeps the tail and its byte release',
  handleFile.includes('worker: onImportWorker'));
check('the last result is the job\'s, so a remounted panel still shows it',
  panel.includes('job.result?.message') && panel.includes('job.result?.notes') && !panel.includes('setStatus'));
check('handleFile hands the progress callback to the import', handleFile.includes('onProgress: importJobProgress'));
check('the panel renders from useImportJob, so a remount shows the running import',
  panel.includes('useImportJob()') && panel.includes('importProgressSizes('));
check('the panel keeps no running flag of its own', !panel.includes('setBusy'));
check('handleFile asks the one pure gate, with the job and the Start read live, before its first await',
  beforeAwait.includes('importRefusal({') && beforeAwait.includes('captureStarting: isCaptureStarting()')
  && beforeAwait.includes('blockedBy,'));
check('the progress is in the zone: a bar with its values, no separate line under the card',
  panel.includes("role={busy ? 'progressbar' : undefined}") && panel.includes('aria-valuenow=') && panel.includes('aria-valuemin=') && panel.includes('aria-valuemax=')
  && !panel.includes('importProgressText'));
const zone = between(panel, '<label', '</label>');
// The zone is as tall busy as idle at every width because both bodies share a
// grid cell; the one not showing is `invisible`, which also drops its text from
// the accessibility tree and from innerText (the drive asserts the latter).
const idleBody = between(zone, "${busy ? 'invisible' : ''}", "${busy ? '' : 'invisible'}");
const busyBody = zone.slice(zone.indexOf("${busy ? '' : 'invisible'}"));
check('the zone shows the invitation and the formats only while idle, the progress only while busy',
  idleBody.includes('Click to upload') && idleBody.includes('.pcapng')
  && !busyBody.includes('Click to upload') && !busyBody.includes('.pcapng') && busyBody.includes('Importing'));
check('...in one grid cell, so the zone keeps its height',
  zone.includes('grid w-full') && (zone.match(/col-start-1 row-start-1/g) ?? []).length === 2);
check('the name truncates with the full name in a title',
  busyBody.includes('truncate') && busyBody.includes('title={'));
check('the result and notes sit above the help card',
  panel.indexOf('{status && !cancelled && (') !== -1
  && panel.indexOf('{status && !cancelled && (') < panel.indexOf('Spreadsheets and tables are checked')
  && panel.indexOf('{notes.length > 0 && (') < panel.indexOf('Spreadsheets and tables are checked'));

// --- Cancel -----------------------------------------------------------------

// A cancelled import is the user's own act: no error dialog, on either branch of
// handleFile (a refusal the flow reports, or a throw it catches), and no success
// line - the quiet "Import cancelled" one.
check('a cancelled import shows no error dialog',
  (handleFile.match(/onFailure\(/g) ?? []).length === 1
  && /flow\.status === 'failed'\)\s*\{?\s*onFailure\(/.test(handleFile)
  && /flow\.status === 'cancelled'/.test(handleFile));
const flowSource = earlyFlow;
check('the flow maps a cancelled outcome, or a requested cancel, to `cancelled`, never to a failure',
  /kind === 'cancelled' \|\| deps\.cancelRequested\(\)/.test(flowSource)
  && /status: 'cancelled'/.test(flowSource));
check('the Cancel button is outside the drop zone\'s label, which would open the file picker',
  panel.indexOf('aria-label="Cancel import"') > panel.indexOf('</label>')
  && !zone.includes('Cancel import') && !zone.includes('cancelImportJob'));
const cancelButton = between(panel, '<button', '</button>');
check('...it is a plain button named for what it does, calling the job\'s cancel',
  cancelButton.includes('type="button"') && cancelButton.includes('aria-label="Cancel import"')
  && cancelButton.includes('onClick={() => cancelImportJob()}'));
// The request waits behind a live capture's seal (up to a 3 s drain) or a CSV
// parse, so the press must show at once: the job publishes it, the button says so.
check('a requested Cancel reads Cancelling… and is disabled',
  /disabled=\{job\.cancelRequested\}/.test(cancelButton)
  && /job\.cancelRequested \? 'Cancelling…' : 'Cancel'/.test(cancelButton)
  && cancelButton.includes('aria-label="Cancel import"')
  && cancelButton.includes('disabled:opacity-40 disabled:cursor-not-allowed'));
check('...shown only while the job is running and can still be cancelled; its row is kept while busy so the cards do not move',
  /\{busy && \(/.test(panel) && /\{job\.status === 'running' && job\.cancellable && \(/.test(panel));
check('the cancelled result is a muted line, not the success one',
  panel.includes('job.result?.cancelled === true')
  && /\{status && cancelled && \(\s*<div className="text-muted-foreground/.test(panel));
check('handleFile hands the run\'s cancel to the job, and locks Cancel before the adoption (in the flow)',
  handleFile.includes('onCancelHandle: setImportJobCancel') && handleFile.includes('lockCancel: lockImportCancel')
  && flowSource.indexOf('deps.lockCancel()') < flowSource.indexOf('await deps.adopt('));

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

// --- a Start and an import: the first to begin wins (captureStarting.ts) --------
const startWhole = between(app, 'const handleStartCapture = async () => {', 'const startCaptureUnguarded');
check('Start marks itself before its first await, after the import check',
  startWhole.indexOf(RUNNING) < startWhole.indexOf('beginCaptureStart();')
  && startWhole.indexOf('beginCaptureStart();') < startWhole.indexOf('await '));
check('...and clears the mark in a finally, so a throw cannot shut imports for good',
  /try \{\s*await startCaptureUnguarded\(\);\s*\} finally \{\s*endCaptureStart\(\);/.test(startWhole));
const unguarded = between(app, 'const startCaptureUnguarded = async () => {', 'const handlePauseCapture');
check('the capture is flagged running in the ref, not a render later, right before the state',
  /isCapturingRef\.current = true;\s*setIsCapturing\(true\);/.test(unguarded));
check('the import panel is told why, from the rendered store',
  app.includes('useCaptureStarting()') && app.includes('captureStarting ? CAPTURE_STARTING_REASON : null'));

const rail = readFileSync('src/components/common/ActivityRail.tsx', 'utf8');
const confirmEffect = between(rail, 'React.useEffect(() => {\n    if (isCapturing || !restartDiscards', '}, [isCapturing');
check('the rail\'s "Discard and start" confirm closes when Start becomes blocked',
  confirmEffect.includes('gate.blocked !== null') && rail.includes('[isCapturing, restartDiscards, gate.blocked]'));

// --- the import's order, bound in App ---------------------------------------------

check('stopCaptureAndSeal hands back the drain it started',
  app.includes('const stopCaptureAndSeal = (tellAgent: boolean): Promise<void> => {'));
check('...resolved at once when the capture is already sealed',
  between(app, 'const stopCaptureAndSeal =', 'stopCaptureRef.current = stopCaptureAndSeal').includes('?? Promise.resolve()'));
const lifecycleBegin = between(app, 'const importLifecycleEffects', 'const handleImportOpening');
check('the lifecycle seals through stopCaptureAndSeal(true) and not the bare stop',
  /stopAndSeal: \(\) => \(isCapturingRef\.current\s+\? stopCaptureAndSeal\(true\)/.test(lifecycleBegin));
check('...and empties the view with handleClearPackets, bypassing the Clear View gate',
  lifecycleBegin.includes('handleClearPackets()') && !lifecycleBegin.includes('handleClearView'));
check('...keeping the offer, so the view\'s offer stays null for the import',
  lifecycleBegin.includes('offeredCapture(sessionMetaNow())') && lifecycleBegin.includes('setLastCapture(null)'));
check('a failure re-offers the kept capture as Clear View does',
  lifecycleBegin.includes('setLastCapture(kept)') && lifecycleBegin.includes('void saveSessionMeta(kept)'));
// The decrypted answers used to wait in an App ref that a failure had to empty;
// they now come back in the Worker's `done` and reach `handleImportPackets` only on
// success, so a failure has nothing of them to drop.
check('a failure discards the import\'s directory',
  lifecycleBegin.includes('captureStore.discard(captureId)') && !lifecycleBegin.includes('importDerivedRef'));
const batch = between(app, 'const handleImportOpening', 'const importWorkerRoute');
check('the Worker\'s first batch opens the store through the lifecycle - awaited - and no longer stops the capture itself',
  batch.includes('importLifecycle.onBatch()') && batch.includes('await opened') && !batch.includes('stopCaptureForImportRef'));
check('the open is awaited from the lifecycle\'s own effect, not a second open',
  lifecycleBegin.includes('captureStore.beginAwaited(captureId)') && lifecycleBegin.includes('captureStore.begin(captureId)'));
check('the Worker route is given what the store holds (for the tail\'s byte release) and the pipeline\'s derived budget',
  between(app, 'const importWorkerRoute', 'const handleImportPackets').includes('storedThrough: bytesStoredThrough')
  && between(app, 'const importWorkerRoute', 'const handleImportPackets').includes('derivedBudget: derivedBudgetRef.current'));
check('the import\'s derived answers come from the Worker\'s done, after the pipeline reset',
  /pipeline\.reset\(.*\);[\s\S]*?pipeline\.keepDerived\(info\.derived\)/.test(between(app, 'const handleImportPackets', 'deriveForBuffer(imported)'))
  && between(app, 'const handleImportPackets', 'deriveForBuffer(imported)').includes('info?.estimates'));
check('the success path takes the capture id from the lifecycle',
  between(app, 'const handleImportPackets', 'adoptMarks(EMPTY_MARKS)').includes('importLifecycle.succeed()'));
// The offer's "it got a frame" mark is `lastPacketMs`. An import that left it
// null was offered by nothing - a failed import after it, Clear View, a
// relaunch - so a failed second import left an empty view and no Reopen.
const imported = between(app, 'const handleImportPackets', 'deriveForBuffer(imported)');
check('a stored import records its last frame\'s time, so it can be offered again',
  /if \(storedImport !== null && imported\.length > 0\)\s*\{?\s*lastPacketTimeRef\.current = imported\[imported\.length - 1\]\.tsUs/
    .test(imported)
  && imported.lastIndexOf('lastPacketTimeRef.current = imported') > imported.lastIndexOf('lastPacketTimeRef.current = null'));
check('App hands the panel the lifecycle and the Worker route, and reads the store\'s reach',
  app.includes('onImportBegin={handleImportBegin}') && app.includes('onImportFailed={handleImportFailed}')
  && app.includes('onImportWorker={importWorkerRoute}')
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

// App hands a finished import to the list a slice a task (`adoptSlices.ts`).
// The job must stay running until the last slice is in, or a Start or a second
// import pressed between two slices would find a half-adopted buffer.
check('the panel awaits the adoption before the job ends',
  /await onImportPackets\(/.test(between(panel, 'const handleFile = async', 'endImportJob(result)')));
check('App adopts an import in slices and derives after the last',
  /adoptInSlices\(/.test(between(app, 'const handleImportPackets = ', 'const deriveForBuffer'))
  && /if \(whole\) deriveForBuffer\(imported\)/.test(app));
// The strip waits for the last slice: a repaint per slice decided up to 50,000
// colours inside the slice's task (~160 ms, profiled on the burst).
const handler = between(app, 'const handleImportPackets = ', 'const deriveForBuffer');
const minimap = readFileSync('src/components/packet-list/PacketListMinimap.tsx', 'utf8');
const list = readFileSync('src/components/packet-list/PacketList.tsx', 'utf8');
check('App holds the minimap strip while the slices go in, and lets go only for its own run',
  handler.indexOf('setAdopting(true)') !== -1
  && handler.indexOf('setAdopting(true)') < handler.indexOf('adoptInSlices(')
  && /const whole = await sliced;\s*if \(adoptRunRef\.current === run\) setAdopting\(false\);/.test(handler)
  && /holdStrip=\{adopting\}/.test(app) && /hold=\{holdStrip\}/.test(list)
  && /if \(!hold\) heldRef\.current = packets;\s*const paintedPackets = useThrottledValue\(heldRef\.current,/.test(minimap));
// The list mounts with an import's first slice (the welcome stood in before it),
// so a ref seeded from `packets` painted that slice anyway.
check('a strip mounted held starts empty, not on the first slice',
  /useRef<Packet\[\]>\(hold \? NO_PACKETS : packets\)/.test(minimap));

if (failures > 0) {
  console.log(`\n${failures} check(s) failed.`);
  process.exit(1);
}
console.log('\nAll import gate checks passed.');
