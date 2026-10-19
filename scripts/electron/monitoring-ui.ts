/**
 * NetFlow v5 monitoring through the real app, against datagrams this script
 * sends itself to a loopback port.
 *
 *   npx tsx scripts/electron/monitoring-ui.ts
 *
 * What plain `tsx` cannot reach: the sheet's two ways in (the Network panel's
 * section and the palette), its three ways out, the module client surviving a
 * close, main's collector bound to a real UDP socket, the Worker's history read
 * back into the chart and the tables, and the pivot into the capture's filter.
 * Skips like `speed-test-ui.ts` without a build or Playwright.
 */
import { createSocket } from 'node:dgram';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent, type StubAgent } from './stubAgent';
import { launchApp } from './launchApp';
import { EXPORTER, v5Payload } from '../monitoring/fixtures';
import { BUNDLE_FRAMING } from '../../src/services/monitoring/bundle';
import { FOREIGN_NAME, seedAged, seedEmpty, seedExpired, seedForeign, seedIncomplete, seedReadOnly, stubDialogs } from './monitoringSeed';

let failures = 0;
function checkTrue(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}
function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}
if (process.platform !== 'win32') skip('the desktop app is Windows-only - nothing to launch here');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'monitoring', 'monitoring.cjs'))) {
  skip('no build with monitoring to launch - run `npm run build` first');
}
try {
  await import('playwright');
} catch {
  skip('playwright is not installed');
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A UDP port nothing holds on 127.0.0.1 right now. */
async function freePort(): Promise<number> {
  const s = createSocket('udp4');
  await new Promise<void>((resolve) => s.bind(0, '127.0.0.1', resolve));
  const port = s.address().port;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}

const PIPE = String.raw`\\.\pipe\inwire-monui-` + process.pid;
const SHEET = '[data-testid="monitoring-sheet"]';
let agent: StubAgent | null = null;
let profile: string | null = null;
let seeds: string | null = null;
let app: Awaited<ReturnType<typeof launchApp>> | null = null;
const sender = createSocket('udp4');

try {
  const port = await freePort();
  agent = await startStubAgent(PIPE, 5);
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-monui-'));
  app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE },
  });
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  const visible = (t: string | RegExp) => p.getByText(t).first().isVisible().catch(() => false);
  const until = async (cond: () => Promise<boolean>, ms: number) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { if (await cond()) return true; await sleep(200); }
    return false;
  };
  const sheetOpen = () => p.locator(SHEET).count().then((n) => n > 0);
  const sheetClosed = () => sheetOpen().then((o) => !o);
  const viewPressed = (label: string) =>
    p.getByRole('button', { name: label, exact: true }).getAttribute('aria-pressed').then((v) => v === 'true').catch(() => false);

  // The panel's section is the first way in.
  await p.getByRole('button', { name: 'Statistics', exact: true }).click();
  await p.getByRole('button', { name: 'Network', exact: true }).click();
  checkTrue('the Network panel has a Monitoring section', await until(() => visible('Open monitoring'), 10_000));
  checkTrue('...which says Not started before the history is asked for', await visible('Not started'));
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  checkTrue('Open monitoring opens the sheet', await until(sheetOpen, 10_000));
  checkTrue('...and connects: the opening note goes and the history block arrives',
    await until(() => visible(/No history yet|No received traffic records yet/), 60_000));

  // Three ways out, each back to the view underneath.
  await p.keyboard.press('Escape');
  checkTrue('Escape closes the sheet', await until(sheetClosed, 5_000));
  checkTrue('...back to the view underneath', await until(() => viewPressed('Statistics'), 5_000));

  // The palette is the second way in.
  await p.keyboard.press('Control+K');
  await p.locator('[role="dialog"][aria-label="Command palette"] input').fill('netflow');
  await sleep(300);
  checkTrue('the palette finds Open monitoring by a keyword', await visible('Open monitoring'));
  await p.keyboard.press('Enter');
  checkTrue('...and Enter opens the sheet', await until(sheetOpen, 5_000));
  await p.getByRole('button', { name: 'Back to Statistics' }).click();
  checkTrue('Back closes the sheet', await until(sheetClosed, 5_000));
  checkTrue('...back to the view underneath', await until(() => viewPressed('Statistics'), 5_000));

  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await until(sheetOpen, 5_000);
  await p.getByRole('button', { name: 'Routing Map', exact: true }).click();
  checkTrue('choosing a view closes the sheet', await until(sheetClosed, 5_000));
  checkTrue('...on the view chosen', await until(() => viewPressed('Routing Map'), 5_000));

  // Ctrl+1..5 are unchanged, and each leaves the sheet as the rail does.
  const keys: [string, string][] = [['1', 'Packets'], ['2', 'Frame Detail'], ['3', 'Statistics'], ['4', 'Routing Map']];
  for (const [digit, label] of keys) {
    await p.getByRole('button', { name: 'Open monitoring' }).click();
    await until(sheetOpen, 5_000);
    await p.locator(SHEET).click({ position: { x: 5, y: 60 } }).catch(() => {});
    await p.keyboard.press(`Control+${digit}`);
    checkTrue(`Ctrl+${digit} leaves the sheet for ${label}`,
      await until(async () => (await sheetClosed()) && (await viewPressed(label)), 5_000));
  }
  // Ctrl+5 follows the selection's stream, and with no frame selected there is
  // none: it must do what it did before monitoring existed, which is nothing.
  await p.keyboard.press('Control+5');
  await sleep(500);
  checkTrue('Ctrl+5 with no stream selected still goes nowhere', await viewPressed('Routing Map'));

  // A source on loopback, and datagrams from it.
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await until(sheetOpen, 5_000);
  checkTrue('before the first Start, the sheet says the firewall will ask', await until(() => visible(/Windows will ask whether Inwire may receive/), 10_000),
    'expected the firewall note');
  await p.getByRole('textbox', { name: 'Exporter', exact: true }).fill('127.0.0.1');
  await p.getByRole('textbox', { name: 'Listen on', exact: true }).fill('127.0.0.1');
  await p.getByRole('textbox', { name: 'Port', exact: true }).fill(String(port));
  await p.getByRole('button', { name: 'Start', exact: true }).click();
  checkTrue('Start listens', await until(() => visible(/Listening, nothing received yet/), 15_000));

  const secs = Math.floor(Date.now() / 1000);
  for (let i = 0; i < 6; i++) {
    const bytes = v5Payload(
      { sequence: i * 2, secs, nsecs: 0, uptime: 600_000 },
      [
        { src: '127.0.0.1', dst: '10.0.0.2', octets: 4000 + i * 500, packets: 4 + i },
        { src: '10.0.0.3', dst: '127.0.0.1', octets: 1500, packets: 2 },
      ],
    );
    await new Promise<void>((resolve, reject) => sender.send(bytes, port, '127.0.0.1', (e) => (e ? reject(e) : resolve())));
    await sleep(50);
  }
  checkTrue('datagrams read as Receiving', await until(() => visible('Receiving'), 15_000));
  checkTrue('the history draws a chart', await until(() => p.locator(`${SHEET} svg[role="img"]`).count().then((n) => n > 0), 20_000));
  // The chart follows the window once data has arrived (the measuring node
  // must survive the no-data to data switch).
  const chartWidth = () => p.locator(`${SHEET} svg[role="img"]`).first()
    .evaluate((el) => el.getBoundingClientRect().width).catch(() => 0);
  const wide = await chartWidth();
  await app!.evaluate(({ BrowserWindow }) => {
    const win = BrowserWindow.getAllWindows()[0];
    win.unmaximize();
    const [w, h] = win.getSize();
    win.setSize(Math.max(1024, w - 300), h);
  });
  checkTrue(`the chart follows the window (was ${Math.round(wide)}px)`,
    await until(async () => (await chartWidth()) < wide - 100, 10_000));
  checkTrue('...and the top endpoints list the exporter\'s hosts',
    await until(() => p.getByRole('button', { name: '127.0.0.1', exact: true }).count().then((n) => n > 0), 20_000));

  // Leaving does not stop collection, and the client is the same one.
  await p.keyboard.press('Escape');
  await until(sheetClosed, 5_000);
  checkTrue('the panel keeps reporting while the sheet is closed', await until(() => visible('Receiving'), 5_000));
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await until(sheetOpen, 5_000);
  checkTrue('reopening finds the same client: still listening, history already there',
    await p.getByRole('button', { name: 'Stop', exact: true }).isVisible().catch(() => false)
      && await until(() => p.getByRole('button', { name: '127.0.0.1', exact: true }).count().then((n) => n > 0), 5_000));

  // A selection, its references, one opened.
  await p.getByRole('button', { name: '127.0.0.1', exact: true }).first().click();
  checkTrue('selecting a host counts its supporting references', await until(() => visible(/Supporting references: \d+ of \d+/), 10_000));
  await p.locator('[aria-label="Supporting references"] button').first().click();
  checkTrue('a reference opens its datagram', await until(() => p.locator('[aria-label="Datagram detail"]').count().then((n) => n > 0), 10_000));

  // The pivot into the capture.
  await p.getByRole('button', { name: 'Filter capture by this host' }).click();
  checkTrue('the pivot closes the sheet', await until(sheetClosed, 5_000));
  const filter = await p.locator('input[placeholder="e.g. tcp.port == 443"]').inputValue().catch(() => '');
  checkTrue('...and filters the capture by that host', filter === 'ip.addr == 127.0.0.1', JSON.stringify(filter));
  checkTrue('...on Packets', await until(() => viewPressed('Packets'), 5_000));

  // Stop before closing, so the app quits with nothing listening.
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await until(sheetOpen, 5_000);
  await p.getByRole('button', { name: 'Stop', exact: true }).click();
  checkTrue('Stop stops the listener', await until(() => visible(/Stopped/), 10_000));

  // --- Storage, retention, discard and expired evidence (ADRs 0061-0063), on seeded folders ---------------
  // Main's dialogs are replaced from main: the open dialog answers with the folder the script names, and the
  // message box records its options, answers "Discard" (button 1) and counts. Neither stub knows about windows:
  // main calls each with or without one.
  const sheet = p.locator(SHEET);
  const nowMs = Date.now();
  seeds = mkdtempSync(path.join(tmpdir(), 'inwire-monseed-'));
  const empty = await seedEmpty(seeds);
  const foreign = await seedForeign(seeds, { nowMs });
  const readOnly = await seedReadOnly(seeds, { nowMs });
  const expired = await seedExpired(seeds, { nowMs });
  const incomplete = await seedIncomplete(seeds, { nowMs });
  const aged = await seedAged(seeds, { nowMs });
  checkTrue('the seeds classify as intended (new, refused, read-only, adopt, adopt)',
    empty.inspect.ok && empty.inspect.kind === 'new' && !foreign.inspect.ok && foreign.inspect.reason === 'foreign-files'
    && readOnly.inspect.ok && readOnly.inspect.kind === 'adopt-read-only'
    && expired.inspect.ok && expired.inspect.kind === 'adopt' && incomplete.inspect.ok && incomplete.inspect.kind === 'adopt');
  const { pick, boxes, allBoxes, answer, saveTo } = await stubDialogs(app);
  const change = async (folder: string) => {
    await pick(folder);
    await sheet.getByRole('button', { name: 'Change…' }).click();
  };
  const scopeRange = (label: string) => sheet.getByRole('button', { name: label, exact: true }).click();

  checkTrue('Storage: "Kept in" the default folder, marked (default)',
    await visible('Kept in') && await sheet.getByText('(default)').first().isVisible().catch(() => false));
  checkTrue('Storage: with retention off it says nothing expires unless turned on',
    await visible('Nothing expires unless you turn this on.'));

  // Retention: check it, 30 days, Save; it survives closing and reopening the sheet.
  await sheet.getByRole('checkbox', { name: 'Keep raw evidence for' }).check();
  await sheet.getByLabel('Days of raw evidence').fill('30');
  await sheet.getByRole('button', { name: 'Save', exact: true }).click();
  checkTrue('Retention: Save says Saved.', await until(() => visible('Saved.'), 10_000));
  checkTrue('...and a policy that expires nothing asks nothing', (await boxes()).n === 0);
  await p.keyboard.press('Escape');
  await until(sheetClosed, 5_000);
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await until(sheetOpen, 5_000);
  checkTrue('Retention: the policy persists on reopening (box checked, 30 days)',
    await until(async () => await sheet.getByRole('checkbox', { name: 'Keep raw evidence for' }).isChecked().catch(() => false)
      && await sheet.getByLabel('Days of raw evidence').inputValue().catch(() => '') === '30', 10_000));

  // Change... onto an empty folder, then a refused one, then a read-only one.
  await change(empty.folder);
  checkTrue('Change... onto an empty folder says new monitoring data will be kept there',
    await until(() => visible('New monitoring data will be kept here.'), 10_000));
  checkTrue('...and offers "Use the default folder"',
    await sheet.getByRole('button', { name: 'Use the default folder' }).isVisible().catch(() => false));
  await change(foreign.folder);
  checkTrue('Change... onto a folder with a foreign file shows an alert naming it',
    await until(async () => (await sheet.locator('[role="alert"]').allTextContents()).some((t) => t.includes(FOREIGN_NAME)), 10_000));
  await change(readOnly.folder);
  checkTrue('Change... onto a damaged dataset shows the read-only note',
    await until(() => visible(/open read-only: history up to the damage is shown, Start is off/), 10_000));
  checkTrue('...and Start is disabled',
    await sheet.getByRole('button', { name: 'Start', exact: true }).isDisabled().catch(() => false));
  checkTrue('...and the firewall note, which is about a Start, is not shown',
    !(await visible(/Windows will ask whether Inwire may receive/)));

  // The sheet's History over the seeded datasets (6 h reaches all of them).
  await change(expired.folder);
  checkTrue('Change... onto a dataset in use says so',
    await until(() => visible('The monitoring data already in this folder is in use.'), 10_000));
  checkTrue('...and Start is enabled again',
    await until(() => sheet.getByRole('button', { name: 'Start', exact: true }).isEnabled().catch(() => false), 10_000));
  await scopeRange('6 h');
  const aggregateBars = () => sheet.locator('svg[role="img"] rect[data-coverage="aggregate-only"]').count().catch(() => 0);
  const rawBars = () => sheet.locator('svg[role="img"] rect[data-coverage="observed-records"]').count().catch(() => 0);
  checkTrue('an expired range: the chart has aggregate-only buckets, marked apart from the raw ones',
    await until(async () => (await aggregateBars()) > 0 && (await rawBars()) > 0, 30_000),
    `aggregate ${await aggregateBars()}, raw ${await rawBars()}`);
  // `visible()` takes the first match, and the first is a bucket's <title> (it says "evidence expired, totals only").
  checkTrue('...the legend reads "Evidence expired"',
    await sheet.locator('figcaption').getByText('Evidence expired', { exact: true }).isVisible().catch(() => false));
  checkTrue('...and the host over the expired part is in the tables',
    await until(() => sheet.getByRole('button', { name: expired.host, exact: true }).count().then((n) => n > 0), 20_000));
  await sheet.getByRole('button', { name: expired.host, exact: true }).first().click();
  const selection = sheet.locator('section[aria-label="Selection"]');
  checkTrue('Focus over expired evidence says so under the retention policy, as a status',
    await until(() => selection.locator('[role="status"]').filter({ hasText: /under the retention policy/ }).count().then((n) => n > 0), 20_000));
  checkTrue('...and not as an alert', await selection.locator('[role="alert"]').count() === 0);
  await selection.getByRole('button', { name: 'Clear the selection' }).click();

  // Export buttons share a row.
  const csv = await sheet.getByRole('button', { name: 'Export CSV' }).boundingBox();
  const bundle = await sheet.getByRole('button', { name: 'Export evidence bundle' }).boundingBox();
  checkTrue('"Export evidence bundle" is in the same row as "Export CSV"',
    csv !== null && bundle !== null && Math.abs(csv.y - bundle.y) < 4 && bundle.x > csv.x, JSON.stringify({ csv, bundle }));

  // The bundle through the sheet, into the file main's save dialog answers with.
  const bundleFile = path.join(seeds, 'expired.iwmon');
  await saveTo(bundleFile);
  await sheet.getByRole('button', { name: 'Export evidence bundle' }).click();
  checkTrue('Export evidence bundle saves to the chosen file and says where',
    await until(() => visible(`Saved to ${bundleFile}`), 30_000));
  checkTrue('...and the file is a bundle (it starts with the bundle magic)',
    existsSync(bundleFile) && readFileSync(bundleFile).subarray(0, 8).toString('latin1') === BUNDLE_FRAMING.magic);

  // Discard acts at once, so it sits below Start and Save rather than among the drafts they save.
  const startBox = await sheet.getByRole('button', { name: 'Start', exact: true }).boundingBox();
  const discardBox = await sheet.getByRole('button', { name: 'Discard…' }).boundingBox();
  checkTrue('Discard sits below Start and Save',
    startBox !== null && discardBox !== null && discardBox.y > startBox.y + startBox.height, JSON.stringify({ startBox, discardBox }));

  // --- Start and a retention save each ask first when they would change what is recorded or kept -----------
  // The stub answers button 1 (the confirming one) unless `answer(0)` queues a Cancel for the next box.
  const startButton = sheet.getByRole('button', { name: 'Start', exact: true });
  const stopButton = sheet.getByRole('button', { name: 'Stop', exact: true });
  const listening = () => stopButton.isVisible().catch(() => false);
  const stopListening = async () => {
    await stopButton.click();
    return until(async () => !(await listening()), 10_000);
  };
  const status = (text: string) => sheet.locator('[role="status"]').filter({ hasText: text }).count().then((n) => n > 0).catch(() => false);
  const notSaved = () => sheet.getByText('Not saved', { exact: false }).count().then((n) => n > 0).catch(() => false);

  // The open dataset (the seeded expired one) was recorded from EXPORTER.
  await sheet.getByRole('textbox', { name: 'Exporter', exact: true }).fill(EXPORTER);
  const startBefore = (await boxes()).n;
  await startButton.click();
  checkTrue('Start with the exporter the history was recorded from listens', await until(listening, 15_000));
  checkTrue('...and shows no start confirmation', (await boxes()).n === startBefore, `calls ${(await boxes()).n - startBefore}`);
  checkTrue('...and Stop stops it', await stopListening());

  await sheet.getByRole('textbox', { name: 'Exporter', exact: true }).fill('127.0.0.1');
  await answer(0);
  const differing = (await boxes()).n;
  await startButton.click();
  checkTrue('Start with a different exporter, declined: the sheet says "Not started." as a neutral status',
    await until(() => status('Not started.'), 15_000));
  const declinedStart = await allBoxes();
  const startDialog = declinedStart[declinedStart.length - 1] ?? {};
  checkTrue('...main asked exactly once, naming both exporters, in startConfirmation\'s words',
    declinedStart.length - differing === 1 && startDialog.title === 'Start with a different exporter'
    && startDialog.message === 'Record a different exporter into this history?'
    && String(startDialog.detail).includes(`recorded from ${EXPORTER}.`) && String(startDialog.detail).includes('record 127.0.0.1 into the same history'),
    JSON.stringify(startDialog).slice(0, 400));
  checkTrue('...Cancel is the default and the cancel button',
    JSON.stringify(startDialog.buttons) === JSON.stringify(['Cancel', 'Start recording']) && startDialog.defaultId === 0 && startDialog.cancelId === 0);
  checkTrue('...nothing listens, and the declined answer is not "Not saved"', !(await listening()) && !(await notSaved()));

  await startButton.click();
  checkTrue('Start with a different exporter, confirmed: it listens', await until(listening, 15_000));
  checkTrue('...after exactly one more confirmation', (await boxes()).n - differing === 2, `calls ${(await boxes()).n - differing}`);
  checkTrue('...and Stop stops it', await stopListening());

  // A retention save that expires segments at once. The aged seed was recorded three days ago.
  await change(aged.folder);
  checkTrue('Change... onto the aged dataset adopts it',
    await until(() => sheet.getByRole('button', { name: 'Start', exact: true }).isEnabled().catch(() => false), 10_000));
  await sheet.getByLabel('Days of raw evidence').fill('1');
  await answer(0);
  const retentionBefore = (await boxes()).n;
  await sheet.getByRole('button', { name: 'Save', exact: true }).click();
  checkTrue('A retention save that expires segments, declined: "Retention not changed." as a neutral status',
    await until(() => status('Retention not changed.'), 15_000));
  const declinedRetention = await allBoxes();
  const retentionBox = declinedRetention[declinedRetention.length - 1] ?? {};
  const retentionDetail = String(retentionBox.detail ?? '');
  checkTrue('...main asked exactly once, in retentionConfirmation\'s words',
    declinedRetention.length - retentionBefore === 1 && retentionBox.title === 'Expire raw evidence now'
    && /^Keeping raw evidence for 1 day expires the raw evidence of \d+ segments? now\.$/.test(String(retentionBox.message))
    && retentionDetail.includes('What goes:') && retentionDetail.includes('What stays:')
    && retentionDetail.includes('"Evidence expired"') && retentionDetail.includes('This cannot be undone.'),
    JSON.stringify(retentionBox).slice(0, 500));
  checkTrue('...Cancel is the default and the cancel button',
    JSON.stringify(retentionBox.buttons) === JSON.stringify(['Cancel', 'Expire evidence']) && retentionBox.defaultId === 0 && retentionBox.cancelId === 0);
  checkTrue('...and the declined answer is not "Not saved"', !(await notSaved()));
  await p.keyboard.press('Escape');
  await until(sheetClosed, 5_000);
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await until(sheetOpen, 5_000);
  checkTrue('...and the policy was not written: reopening still says 30 days',
    await until(async () => await sheet.getByLabel('Days of raw evidence').inputValue().catch(() => '') === '30', 10_000));

  await sheet.getByLabel('Days of raw evidence').fill('1');
  await sheet.getByRole('button', { name: 'Save', exact: true }).click();
  checkTrue('The same save, confirmed: it says Saved.', await until(() => status('Saved.'), 15_000));
  checkTrue('...after exactly one more confirmation', (await boxes()).n - retentionBefore === 2, `calls ${(await boxes()).n - retentionBefore}`);

  await change(incomplete.folder);
  await scopeRange('6 h'); // reopening the sheet above reset the range
  checkTrue('an incomplete expired minute: the tables say why it is not available',
    await until(() => visible('Not available: this minute exceeded the key budget, and its evidence has expired.'), 30_000));

  // Discard "All monitoring data" in the default folder, which holds the datagrams sent above.
  await sheet.getByRole('button', { name: 'Use the default folder' }).click();
  await until(() => visible(/The monitoring data already in this folder is in use\./), 10_000);
  const before = (await boxes()).n;
  await sheet.getByRole('button', { name: 'Discard…' }).click();
  checkTrue('Discard: the segment count is reported ("Discarded N segment(s).")',
    await until(() => visible(/Discarded \d+ segments?\./), 20_000));
  const after = await boxes();
  const box = after.last ?? {};
  checkTrue('Discard: main\'s confirmation is shown exactly once', after.n - before === 1, `calls ${after.n - before}`);
  const detail = String(box.detail ?? '');
  checkTrue('...it names what goes and what stays, in discardConfirmation\'s words',
    box.title === 'Discard all monitoring data' && box.message === 'Discard the whole monitoring dataset?'
    && detail.includes('What goes:') && detail.includes('What stays:') && detail.includes('The app\'s settings.')
    && detail.includes('this cannot be undone'), JSON.stringify(box).slice(0, 400));
  checkTrue('...Cancel is the default and the cancel button',
    JSON.stringify(box.buttons) === JSON.stringify(['Cancel', 'Discard']) && box.defaultId === 0 && box.cancelId === 0);
  checkTrue('...and the sheet adds no dialog of its own',
    await sheet.locator('[role="dialog"], [role="alertdialog"]').count() === 0);
  await p.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (v: boolean) => void } })
    .inwire?.setUnsavedCapture?.(false));
} finally {
  sender.close();
  await app?.evaluate(() => {}).catch(() => {});
  await app?.close().catch(() => {});
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    if (seeds) rmSync(seeds, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0 ? '\nAll monitoring UI checks passed.' : `\n${failures} monitoring UI check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
