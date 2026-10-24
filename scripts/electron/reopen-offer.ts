/**
 * The previous capture is offered at launch, never loaded unasked.
 *
 *   npx tsx scripts/electron/reopen-offer.ts
 *
 * The app used to load the last capture on every launch: its newest chunks
 * streamed into the list for as long as they took - 1.36 million rows and
 * fifteen seconds after a real burst - which looked exactly like a capture
 * nobody had started. And Start was not blocked while it ran, so a capture
 * started under it deleted the directory the restore was still reading, then
 * had its numbering and clock moved onto the old capture's.
 *
 * Two launches against one temporary profile and the stub agent: the first
 * captures and stops, the second must open with an EMPTY list, say what it is
 * keeping and offer to reopen it, send the agent no `start_capture`, and ask
 * before a Start deletes it. Reopen must then bring the frames back. Skips like
 * `smoke.ts` without a build or Playwright.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent, type StubAgent } from './stubAgent';
import { launchApp } from './launchApp';

let failures = 0;
function checkTrue(name: string, condition: boolean, detail = ''): void {
  if (!condition) failures++;
  console.log(`${condition ? 'PASS' : 'FAIL'}  ${name}${!condition && detail ? `\n        ${detail}` : ''}`);
}
function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

if (process.platform !== 'win32') skip('the desktop app is Windows-only - nothing to launch here');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}
try {
  await import('playwright');
} catch {
  skip('playwright is not installed');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(condition: () => Promise<boolean>, ms = 20_000): Promise<boolean> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await condition().catch(() => false)) return true;
    if (Date.now() > deadline) return false;
    await sleep(200);
  }
}
async function clicks(what: string, act: () => Promise<void>): Promise<boolean> {
  try {
    await act();
    return true;
  } catch (error) {
    console.log(`        could not click ${what}: ${error instanceof Error ? error.message.split('\n')[0] : String(error)}`);
    return false;
  }
}

const PIPE = `\\\\.\\pipe\\inwire-reopen-${process.pid}`;
let agent: StubAgent | null = null;
let profile: string | null = null;
type App = Awaited<ReturnType<typeof launchApp>>;
type Page = Awaited<ReturnType<App['firstWindow']>>;
let app: App | null = null;
let page: Page | null = null;

async function launch(): Promise<Page> {
  app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile!, INWIRE_AGENT_PIPE: PIPE },
  });
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0, undefined, { timeout: 30_000 });
  page = p;
  return p;
}
async function close(): Promise<void> {
  await page?.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
  await app?.close().catch(() => {});
  app = null;
  page = null;
}
const counted = (p: Page) => p.evaluate(
  () => Number(document.querySelector('[data-packet-counts]')?.textContent?.match(/([\d,]+)/)?.[1]?.replace(/,/g, '') ?? '0'));

try {
  agent = await startStubAgent(PIPE);
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-reopen-'));

  console.log('--- the first launch captures and stops ---\n');
  let p = await launch();
  checkTrue('the app connected to the stub', await until(async () => agent!.received.length > 0));
  await clicks('Interfaces', () => p.getByRole('button', { name: 'Interfaces' }).click());
  await clicks('the stub adapter', () => p.getByText('Ethernet', { exact: true }).first().click());
  checkTrue('Start can be pressed', await clicks('Start capture', () => p.getByLabel('Start capture').click()));
  checkTrue('frames arrive', await until(async () => (await counted(p)) > 200));
  checkTrue('the capture can be stopped', await clicks('Stop capture', () => p.getByLabel('Stop capture').first().click()));
  // Read once the count has settled, not at the click: Stop drains the frames
  // still in the pipeline into the list after it is pressed (under a loaded
  // gate, 280 at the click and 360 sealed). The session's metadata is written
  // on a two-second throttle.
  let firstCount = -1;
  await until(async () => {
    const now = await counted(p);
    const settled = now === firstCount;
    firstCount = now;
    if (settled) await sleep(2_500);
    return settled && (await counted(p)) === now;
  }, 20_000);
  await sleep(2_500);
  await close();

  console.log('\n--- the second launch offers it ---\n');
  const before = agent.received.length;
  p = await launch();
  checkTrue('the app connected again', await until(async () => agent!.received.length > before));
  const offered = await until(async () => (await p.getByText(/is still on disk/).count()) > 0);
  checkTrue('the empty list offers the last capture', offered);
  // Long enough for the old restore to have filled the list.
  await sleep(3_000);
  checkTrue('...and nothing was loaded into the list unasked', (await counted(p)) === 0, `counted ${await counted(p)}`);
  checkTrue('no capture was started', !agent.received.slice(before).some((m) => m.includes('start_capture')));
  checkTrue('Start asks before deleting it',
    (await p.getByLabel('Start a new capture, discarding the current one').count()) === 1);

  checkTrue('Reopen can be pressed', await clicks('Reopen', () => p.getByRole('button', { name: 'Reopen' }).click()));
  checkTrue('Reopen brings the frames back', await until(async () => (await counted(p)) > 0, 30_000));
  checkTrue('...as many as were captured', await until(async () => (await counted(p)) === firstCount, 30_000),
    `captured ${firstCount}, reopened ${await counted(p)}`);
  checkTrue('...and the offer is gone', (await p.getByText(/is still on disk/).count()) === 0);
  checkTrue('...and still no capture was started', !agent.received.slice(before).some((m) => m.includes('start_capture')));

  // Clear View frees the list and keeps the capture on disk (ADR 0012). The
  // empty list is then the welcome, and a Start from it deletes that capture,
  // so it must be offered again - otherwise Start has nothing to ask about.
  console.log('\n--- Clear View keeps it offered ---\n');
  await clicks('Settings', () => p.getByRole('button', { name: 'Settings' }).first().click());
  await clicks('Capture Health', () => p.getByRole('tab', { name: 'Capture Health' }).or(
    p.getByRole('button', { name: 'Capture Health', exact: true })).first().click());
  checkTrue('Clear View can be pressed', await clicks('Clear View',
    () => p.getByRole('button', { name: 'Clear View' }).click()));
  await p.keyboard.press('Escape');
  checkTrue('Clear View empties the list', await until(async () => (await counted(p)) === 0));
  checkTrue('...and offers the capture it cleared',
    await until(async () => (await p.getByText(/is still on disk/).count()) > 0));
  checkTrue('...so Start asks before deleting it',
    (await p.getByLabel('Start a new capture, discarding the current one').count()) === 1);
  checkTrue('...and Reopen brings it back again', await clicks('Reopen',
    () => p.getByRole('button', { name: 'Reopen' }).click())
    && await until(async () => (await counted(p)) === firstCount, 30_000), `reopened ${await counted(p)}`);
  checkTrue('...and still no capture was started', !agent.received.slice(before).some((m) => m.includes('start_capture')));
} finally {
  await close();
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0 ? '\nAll reopen-offer checks passed.' : `\n${failures} reopen-offer check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
