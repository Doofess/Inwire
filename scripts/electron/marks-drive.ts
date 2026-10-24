/**
 * Packet marks in the real app (ADR 0067).
 *
 *   npx tsx scripts/electron/marks-drive.ts
 *
 * One profile, the stub agent, background windows. It captures about thirty
 * frames and stops, then:
 *
 *   - Ctrl+M on frames 3 and 7: both rows are drawn with the marked fill, and a
 *     marked row that is also selected stays the accent (selection beats mark);
 *   - applying `frame.marked == 1` shows two rows, and unmarking 7 with that
 *     filter applied drops the list to one (Review Focus 2);
 *   - with the filter cleared, Ctrl+Shift+N from frame 1 selects 3, and the
 *     tree's "Frame is marked" row reads True there and False on frame 4;
 *   - quit, relaunch on the same profile and Reopen: frame 3 is still marked,
 *     and the filter still finds it;
 *   - Start a new capture, accepting the delete: no row is marked and the
 *     filter finds none (Review Focus 3).
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

const PIPE = `\\\\.\\pipe\\inwire-marks-${process.pid}`;
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

/** Waits for the frame count to stop moving: Stop drains the pipeline into the list after the click. */
async function settled(p: Page): Promise<number> {
  let last = -1;
  await until(async () => {
    const now = await counted(p);
    const done = now === last;
    last = now;
    return done;
  }, 20_000);
  return last;
}

try {
  agent = await startStubAgent(PIPE);
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-marks-'));

  console.log('--- capture some frames and stop ---\n');
  let p = await launch();
  checkTrue('the app connected to the stub', await until(async () => agent!.received.length > 0));
  await clicks('Interfaces', () => p.getByRole('button', { name: 'Interfaces' }).click());
  await clicks('the stub adapter', () => p.getByText('Ethernet', { exact: true }).first().click());
  checkTrue('Start can be pressed', await clicks('Start capture', () => p.getByLabel('Start capture').click()));
  // Enough to overflow the list, which the half-shown-row check needs.
  checkTrue('frames arrive', await until(async () => (await counted(p)) >= 120));
  checkTrue('the capture can be stopped', await clicks('Stop capture', () => p.getByLabel('Stop capture').first().click()));
  const total = await settled(p);
  checkTrue('there are enough frames to mark', total >= 12, `counted ${total}`);

  // Everything below goes through these, so a reopened page re-resolves them.
  const rowsOf = (q: Page) => q.locator('tbody tr[role="row"]');
  const rowOf = (q: Page, n: number) => rowsOf(q).filter({ has: q.locator('td:first-child', { hasText: new RegExp(`^${n}$`) }) });
  const filterOf = (q: Page) => q.getByPlaceholder('e.g. tcp.port == 443');
  const bgOf = (q: Page, n: number) => rowOf(q, n).first().evaluate((tr) => getComputedStyle(tr).backgroundColor);
  const resolved = (q: Page, token: string) => q.evaluate((t) => {
    const probe = document.createElement('div');
    probe.style.backgroundColor = `var(${t})`;
    document.body.appendChild(probe);
    const colour = getComputedStyle(probe).backgroundColor;
    probe.remove();
    return colour;
  }, token);

  /** Brings frame `n` into view through Go to packet, then selects its row. */
  async function select(q: Page, n: number): Promise<boolean> {
    await q.keyboard.press('Control+g');
    await q.keyboard.type(String(n));
    await q.keyboard.press('Enter');
    return (
      await until(async () => (await rowOf(q, n).count()) > 0, 10_000)
      && await clicks(`row ${n}`, () => rowOf(q, n).first().locator('td').nth(0).click())
    );
  }
  /**
   * Types an expression and applies it. The pause between the two is not for
   * the app's sake: a clear that follows its own typing inside the preference
   * debounce (250 ms) is not persisted, because the stored-value check sees the
   * cleared state equal to the one loaded and leaves the pending write of the
   * intermediate state to land (`services/preferences.ts`). A person cannot type
   * and press Enter that fast; Playwright can.
   */
  async function applyFilterText(q: Page, text: string): Promise<void> {
    await filterOf(q).fill(text);
    await sleep(400);
    await filterOf(q).press('Enter');
  }
  const selectedId = (q: Page) => q.evaluate(
    () => document.querySelector('tbody tr[aria-selected="true"] td')?.textContent?.trim() ?? '');

  console.log('\n--- a click on a half-shown row leaves the list where it is ---\n');
  // The list scrolls a selection made from OUTSIDE it into view (Go to packet,
  // Next marked). A click on the list's own bottom row, half cut off, is not
  // one: centring it moved the list half a screen under the pointer, and the
  // second click of a double-click opened a different frame.
  // Off a row boundary, then a pause: the list is virtualised, and the rows at
  // the new position exist only once it has rendered for the scroll.
  await p.evaluate(() => {
    let box = document.querySelector('tbody')?.parentElement ?? null;
    while (box && box.scrollHeight <= box.clientHeight) box = box.parentElement;
    if (box) box.scrollTop = Math.floor((box.scrollHeight - box.clientHeight) / 2) + 7;
  });
  await sleep(500);
  const edge = await p.evaluate(() => {
    let box = document.querySelector('tbody')?.parentElement ?? null;
    while (box && box.scrollHeight <= box.clientHeight) box = box.parentElement;
    if (!box) return null;
    const bottom = box.getBoundingClientRect().bottom;
    const cut = [...document.querySelectorAll('tbody tr[role="row"]')].find((tr) => {
      const r = tr.getBoundingClientRect();
      return r.top < bottom - 4 && r.bottom > bottom;
    });
    if (!cut) return null;
    const r = cut.getBoundingClientRect();
    return { x: r.left + 20, y: Math.floor((r.top + bottom) / 2), id: cut.querySelector('td')?.textContent?.trim() ?? '' };
  });
  checkTrue('the list overflows with a row cut off at its foot', edge !== null);
  if (edge) {
    await sleep(300);
    const scrollOf = () => p.evaluate(() => {
      let box = document.querySelector('tbody')?.parentElement ?? null;
      while (box && box.scrollHeight <= box.clientHeight) box = box.parentElement;
      return box?.scrollTop ?? -1;
    });
    const before = await scrollOf();
    await p.mouse.click(edge.x, edge.y);
    checkTrue('the half-shown row is selected', await until(async () => (await selectedId(p)) === edge.id, 5_000),
      `selected ${await selectedId(p)}, clicked ${edge.id}`);
    await sleep(300);
    const after = await scrollOf();
    checkTrue('...and the list did not move under the pointer', after === before, `scrollTop ${before} -> ${after}`);
  }

  console.log('\n--- Ctrl+M marks, and selection beats mark ---\n');
  const marked = await resolved(p, '--marked');
  const accent = await resolved(p, '--primary');
  checkTrue('the marked fill is not the accent', marked !== accent, `both ${marked}`);
  checkTrue('frame 3 can be selected', await select(p, 3));
  await p.keyboard.press('Control+m');
  checkTrue('a marked row that is selected stays the accent fill', await until(async () => (await bgOf(p, 3)) === accent, 5_000),
    `row 3 is ${await bgOf(p, 3)}, accent ${accent}`);
  checkTrue('frame 7 can be selected', await select(p, 7));
  await p.keyboard.press('Control+m');
  checkTrue('frame 5 can be selected', await select(p, 5));
  checkTrue('frame 3, no longer selected, is drawn marked', await until(async () => (await bgOf(p, 3)) === marked, 5_000),
    `row 3 is ${await bgOf(p, 3)}, marked ${marked}`);
  checkTrue('frame 7 is drawn marked once the selection moved', await until(async () => (await bgOf(p, 7)) === marked, 5_000),
    `row 7 is ${await bgOf(p, 7)}, marked ${marked}`);
  checkTrue('frame 4, never marked, is not', (await bgOf(p, 4)) !== marked);

  console.log('\n--- frame.marked == 1, and unmarking under it ---\n');
  const chip = p.locator('[aria-label^="Matches:"]');
  await applyFilterText(p, 'frame.marked == 1');
  checkTrue('the filter is applied', await until(async () => (await chip.count()) > 0));
  checkTrue('two rows show', await until(async () => (await rowsOf(p).count()) === 2, 10_000), `rows ${await rowsOf(p).count()}`);
  checkTrue('frame 7 is selectable under the filter', await clicks('row 7', () => rowOf(p, 7).first().locator('td').nth(0).click()));
  await p.keyboard.press('Control+m');
  checkTrue('unmarking 7 drops it from the list at once', await until(async () => (await rowsOf(p).count()) === 1, 10_000),
    `rows ${await rowsOf(p).count()}`);
  checkTrue('...leaving frame 3', (await rowOf(p, 3).count()) === 1);

  console.log('\n--- next marked, and the tree ---\n');
  await applyFilterText(p, '');
  checkTrue('the filter is cleared', await until(async () => (await chip.count()) === 0));
  checkTrue('frame 1 can be selected', await select(p, 1));
  await p.keyboard.press('Control+Shift+N');
  checkTrue('Ctrl+Shift+N from frame 1 selects 3', await until(async () => (await selectedId(p)) === '3', 5_000),
    `selected ${await selectedId(p)}`);
  const treeRow = (q: Page) => q.evaluate(() => {
    const label = [...document.querySelectorAll('span, div')].find(
      (el) => el.children.length === 0 && /Frame is marked/.test(el.textContent ?? ''));
    let row: Element | null = label ?? null;
    while (row && !/True|False/.test(row.textContent ?? '')) row = row.parentElement;
    return row?.textContent?.replace(/\s+/g, ' ').trim() ?? '';
  });
  checkTrue('the tree reads True on the marked frame', await until(async () => /True/.test(await treeRow(p)), 10_000),
    `row says ${JSON.stringify(await treeRow(p))}`);
  checkTrue('frame 4 can be selected', await select(p, 4));
  checkTrue('...and its tree reads False', await until(async () => /False/.test(await treeRow(p)), 10_000),
    `row says ${JSON.stringify(await treeRow(p))}`);
  await p.keyboard.press('Control+Shift+B');
  checkTrue('Ctrl+Shift+B from frame 4 goes back to 3 (the only mark)', await until(async () => (await selectedId(p)) === '3', 5_000),
    `selected ${await selectedId(p)}`);

  // The store writes the file on every change, but the session metadata that
  // makes Reopen available is throttled to two seconds.
  await sleep(2_500);
  await close();

  console.log('\n--- quit, relaunch, Reopen ---\n');
  const before = agent.received.length;
  p = await launch();
  checkTrue('the app connected again', await until(async () => agent!.received.length > before));
  checkTrue('the empty list offers the last capture',
    await until(async () => (await p.getByText(/is still on disk/).count()) > 0));
  checkTrue('Reopen can be pressed', await clicks('Reopen', () => p.getByRole('button', { name: 'Reopen' }).click()));
  checkTrue('Reopen brings the frames back', await until(async () => (await counted(p)) === total, 30_000), `reopened ${await counted(p)}`);
  const markedAgain = await resolved(p, '--marked');
  checkTrue('frame 5 can be selected', await select(p, 5));
  checkTrue('frame 3 is still marked', await until(async () => (await bgOf(p, 3)) === markedAgain, 10_000),
    `row 3 is ${await bgOf(p, 3)}, marked ${markedAgain}`);
  checkTrue('frame 7, unmarked before the quit, is not', (await bgOf(p, 7)) !== markedAgain);
  await applyFilterText(p, 'frame.marked == 1');
  checkTrue('the filter finds exactly the one mark', await until(async () => (await rowsOf(p).count()) === 1, 10_000),
    `rows ${await rowsOf(p).count()}`);
  await applyFilterText(p, '');

  console.log('\n--- a new capture starts unmarked ---\n');
  checkTrue('Start asks before discarding', await clicks('Start',
    () => p.getByLabel('Start a new capture, discarding the current one').click()));
  checkTrue('...and the discard is accepted', await clicks('Discard and start',
    () => p.getByRole('button', { name: 'Discard and start' }).click()));
  checkTrue('frames arrive in the new capture', await until(async () => (await counted(p)) >= 12, 30_000));
  checkTrue('the new capture can be stopped', await clicks('Stop capture', () => p.getByLabel('Stop capture').first().click()));
  await settled(p);
  checkTrue('frame 3 of the new capture can be selected', await select(p, 3));
  checkTrue('frame 5 can be selected', await select(p, 5));
  checkTrue('no row is drawn marked', await p.evaluate(
    (fill) => ![...document.querySelectorAll('tbody tr[role="row"]')].some((tr) => getComputedStyle(tr).backgroundColor === fill),
    markedAgain));
  await applyFilterText(p, 'frame.marked == 1');
  checkTrue('...and the filter finds none', await until(async () => (await rowsOf(p).count()) === 0, 10_000),
    `rows ${await rowsOf(p).count()}`);
} finally {
  await close();
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0 ? '\nAll marks checks passed.' : `\n${failures} marks check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
