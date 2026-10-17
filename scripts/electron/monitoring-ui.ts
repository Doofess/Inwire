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
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent, type StubAgent } from './stubAgent';
import { launchApp } from './launchApp';
import { v5Payload } from '../monitoring/fixtures';

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
  await p.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (v: boolean) => void } })
    .inwire?.setUnsavedCapture?.(false));
} finally {
  sender.close();
  await app?.evaluate(() => {}).catch(() => {});
  await app?.close().catch(() => {});
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0 ? '\nAll monitoring UI checks passed.' : `\n${failures} monitoring UI check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
