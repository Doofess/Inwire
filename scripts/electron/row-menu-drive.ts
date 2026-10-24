/**
 * The packet list's row menu, in the real app.
 *
 *   npx tsx scripts/electron/row-menu-drive.ts
 *
 * The menu is the shared Radix `ContextMenu`, wrapped around the table body,
 * with the right-clicked row recorded on `contextmenu` because the rows are
 * virtualised. One launch against the stub agent: capture, stop, then
 *
 *   - right-click a row: Prepare as Filter > Source > Selected leaves the term
 *     in the filter field and applies nothing (no match chip);
 *   - Apply as Filter > Protocol > Selected narrows the list (the chip appears
 *     and every visible row shows that protocol);
 *   - Escape closes the menu, and a second Escape leaves the selection alone.
 *
 * Skips like `reopen-offer.ts` without a build or Playwright.
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

const PIPE = `\\\\.\\pipe\\inwire-rowmenu-${process.pid}`;
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
  // A capture with frames in the buffer opens the quit confirm and waits.
  await page?.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
  await app?.close().catch(() => {});
  app = null;
  page = null;
}
const counted = (p: Page) => p.evaluate(
  () => Number(document.querySelector('[data-packet-counts]')?.textContent?.match(/([\d,]+)/)?.[1]?.replace(/,/g, '') ?? '0'));

try {
  agent = await startStubAgent(PIPE);
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-rowmenu-'));

  console.log('--- capture some frames and stop ---\n');
  const p = await launch();
  checkTrue('the app connected to the stub', await until(async () => agent!.received.length > 0));
  await clicks('Interfaces', () => p.getByRole('button', { name: 'Interfaces' }).click());
  await clicks('the stub adapter', () => p.getByText('Ethernet', { exact: true }).first().click());
  checkTrue('Start can be pressed', await clicks('Start capture', () => p.getByLabel('Start capture').click()));
  checkTrue('frames arrive', await until(async () => (await counted(p)) > 50));
  checkTrue('the capture can be stopped', await clicks('Stop capture', () => p.getByLabel('Stop capture').first().click()));
  let last = -1;
  await until(async () => {
    const now = await counted(p);
    const settled = now === last;
    last = now;
    return settled;
  }, 20_000);

  const rows = p.locator('tbody tr[role="row"]');
  const filter = p.getByPlaceholder('e.g. tcp.port == 443');
  const chip = p.locator('[aria-label^="Matches:"]');
  const menu = p.locator('[data-slot="context-menu-content"]');
  checkTrue('the list has rows', await until(async () => (await rows.count()) > 0));

  // The row's own cells, read before anything is filtered. The Protocol cell is
  // the sixth column with the default set (No., direction, time, source,
  // destination, protocol).
  const first = rows.first();
  const sourceText = ((await first.locator('td').nth(3).innerText()) ?? '').trim();

  async function openMenu(): Promise<boolean> {
    await first.click({ button: 'right' });
    return until(async () => (await menu.count()) > 0, 5_000);
  }
  async function pick(top: string, which: RegExp): Promise<boolean> {
    return (
      (await clicks(top, () => p.getByRole('menuitem', { name: top, exact: true }).click()))
      && (await clicks(String(which), () => p.getByRole('menuitem', { name: which }).first().click()))
      && (await clicks('Selected', () => p.getByRole('menuitem', { name: 'Selected', exact: true }).click()))
    );
  }

  console.log('\n--- Prepare as Filter > Source > Selected ---\n');
  checkTrue('right-click opens the row menu', await openMenu());
  checkTrue('the menu lists the marking and follow items',
    (await p.getByRole('menuitem', { name: /Mark packet/ }).count()) === 1
    && (await p.getByRole('menuitem', { name: 'Copy Raw Hex Stream' }).count()) === 1);
  checkTrue('Prepare > Source > Selected can be picked', await pick('Prepare as Filter', /^Source/));
  const prepared = await filter.inputValue();
  checkTrue('the filter field holds the source term', /^(ipv6\.src|ip\.src|eth\.src) == "/.test(prepared)
    && prepared.includes(sourceText), `field holds ${JSON.stringify(prepared)}`);
  checkTrue('...and it was not applied', (await chip.count()) === 0);
  checkTrue('...and the menu closed', await until(async () => (await menu.count()) === 0, 5_000));

  console.log('\n--- Apply as Filter > Protocol > Selected ---\n');
  checkTrue('right-click opens the menu again', await openMenu());
  checkTrue('Apply > Protocol > Selected can be picked', await pick('Apply as Filter', /^Protocol/));
  const applied = await filter.inputValue();
  checkTrue('the field holds the protocol term', applied.length > 0 && applied !== prepared, `field holds ${JSON.stringify(applied)}`);
  checkTrue('...and it was applied: the match chip shows', await until(async () => (await chip.count()) > 0));
  const protocolCell = (await rows.first().locator('td').nth(5).innerText()).trim();
  const shown = await rows.evaluateAll((trs) => trs.map((tr) => tr.querySelectorAll('td')[5]?.textContent?.trim() ?? ''));
  checkTrue('...and every row on screen is that protocol', shown.length > 0 && shown.every((s) => s === protocolCell),
    `first row ${protocolCell}, saw ${JSON.stringify([...new Set(shown)])}`);

  console.log('\n--- Escape ---\n');
  checkTrue('right-click opens the menu a third time', await openMenu());
  await p.keyboard.press('Escape');
  checkTrue('Escape closes the menu', await until(async () => (await menu.count()) === 0, 5_000));
  checkTrue('...and the filter is still applied', (await chip.count()) > 0);
} finally {
  await close();
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0 ? '\nAll row-menu checks passed.' : `\n${failures} row-menu check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
