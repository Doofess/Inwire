/**
 * The disk half of the app, driven until it is doing something.
 *
 *   npm run build && npx tsx scripts/electron/disk-drive.ts
 *
 * ## Why this exists
 *
 * Everything the capture store is for only happens once a capture is **bigger
 * than memory**: the rows below the RAM window, the restore, and the
 * whole-capture filter. Nothing exercised that. `smoke.ts` captures a few
 * thousand frames, which fit in the buffer, so the disk path is never reached;
 * every assertion script hands the store objects in its own process, so no
 * frame ever crosses a boundary.
 *
 * Between those two gaps a real bug lived for the whole migration. A buffered
 * `Packet` carries its dense fields in a `FieldBlock` **class instance**, a
 * structured clone drops prototypes, and so `encodeChunk` threw
 * `block.read is not a function` on every chunk the store tried to seal - for
 * the life of every capture. The directory filled with raw frame bytes and
 * **zero rows**. `ordinalOf` answered -1, the app read that as "the window is
 * the whole capture", and everything looked normal.
 *
 * `scripts/capture/store-protocol.ts` now clones every frame it appends, which
 * catches that class of bug in a second. This is the other half: proof that
 * the whole path works in the real app, which is the only place the RAM
 * budget, the trim, the store process and the filter bar are all present at
 * once.
 *
 * ## Not in `npm run check`
 *
 * It fills a 128 MB buffer to make the window trim, which is ~112,000 frames,
 * and then keeps going until the capture is well past it. That is about two
 * minutes. `check.ts` lists it under NOT_TESTS; run it by hand after touching
 * anything on the store path.
 *
 * ## What it asserts
 *
 * That the capture outgrows the window at all - which is the bug above, and
 * the one thing that cannot be faked. Then that a filter matching one frame in
 * 4,096 finds them across the whole capture rather than across the window, and
 * that the top of the filtered list is a frame from the very beginning, read
 * back off disk.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent, type StubAgent } from './stubAgent';

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
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

if (process.platform !== 'win32') skip('the desktop app is Windows-only');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}

let electron: typeof import('playwright')['_electron'];
try {
  ({ _electron: electron } = await import('playwright'));
} catch {
  skip('playwright is not installed');
}

/**
 * Frames per 100 ms tick.
 *
 * Well under what the app ingests, on purpose: the point is a capture that
 * outgrows memory, not a load test. Faster and the renderer sheds frames,
 * which makes the run longer rather than shorter.
 */
const PER_TICK = 300;
/** How far past the window the capture must get before filtering. */
const BELOW_WINDOW = 60_000;
/** The stub's source port cycles over this many frames. */
const FILTER_PERIOD = 4096;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(condition: () => Promise<boolean>, ms: number): Promise<boolean> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await condition()) return true;
    if (Date.now() > deadline) return false;
    await sleep(1500);
  }
}

let agent: StubAgent | null = null;
let profile: string | null = null;
/**
 * A pipe of this run's own, rather than the name the installed service holds.
 *
 * The same fix `smoke.ts` got, and for the same reason: a development machine
 * has the real `InwireAgent` service running, the service owns the production
 * pipe name, and a stub that cannot bind it had nothing honest to do but SKIP -
 * so the one script that reaches the DISK path was silently not running on the
 * machine that most needed it.
 */
const DRIVE_PIPE = `\\\\.\\pipe\\inwire-disk-${process.pid}`;

let app: Awaited<ReturnType<typeof electron.launch>> | null = null;
let mainWindow: Awaited<ReturnType<Awaited<ReturnType<typeof electron.launch>>['firstWindow']>> | null = null;

try {
  try {
    agent = await startStubAgent(DRIVE_PIPE, PER_TICK);
  } catch (error) {
    if ((error as NodeJS.ErrnoException)?.code === 'EADDRINUSE') {
      skip(`something else is already serving ${DRIVE_PIPE}, which should be impossible`);
    }
    throw error;
  }

  profile = mkdtempSync(path.join(tmpdir(), 'inwire-disk-'));
  app = await electron.launch({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: DRIVE_PIPE },
  });
  const page = await app.firstWindow();
  mainWindow = page;
  page.setDefaultTimeout(30_000);

  // Anything the store says goes to main's stdout. A silent run is part of
  // what is being asserted: the bug this exists for reported itself here, over
  // and over, and nothing was listening.
  /**
   * What the STORE said, which is not everything main printed.
   *
   * This collected every line on main's stdout and asserted the list was
   * empty, under the name "the store never complained" - so on any machine
   * with the agent service installed it failed twice per run on
   * `[agent-pipe] auto start: started`, which is the supervisor reporting
   * normal operation. A by-hand driver that fails every run on something
   * unrelated is a by-hand driver nobody runs.
   *
   * `[capture-store:` is the prefix `electron/store/host.ts` puts on both of
   * the child's streams, and it is the reason `stdio: 'pipe'` exists at all -
   * a packaged GUI app has no console to inherit, so every `fail()` the store
   * protocol calls "never silent" arrives here or nowhere. Everything else is
   * printed rather than asserted: still visible, never the reason this fails.
   */
  const complaints: string[] = [];
  const otherOutput: string[] = [];
  app.process().stdout?.on('data', (data) => {
    for (const line of String(data).split(/\r?\n/)) {
      const text = line.trim();
      if (!text) continue;
      if (text.includes('[capture-store:')) complaints.push(text);
      else otherOutput.push(text);
    }
  });
  const rendererErrors: string[] = [];
  page.on('pageerror', (error) => rendererErrors.push(error.message));

  await page.waitForLoadState('domcontentloaded');
  // The smallest offered budget, so the window trims at ~112,000 frames rather
  // than ~450,000. Set through the same preference the settings panel writes.
  await page.evaluate(() => localStorage.setItem('inwire.performance',
    JSON.stringify({ dashboardRefreshMs: 2000, packetBufferBytes: 128 * 1024 * 1024 })));
  await page.reload();
  await page.waitForLoadState('domcontentloaded');
  await sleep(1500);

  /** The filter bar's two counts: rows shown, and rows in the capture. */
  const counts = () => page.evaluate(() => {
    // `[data-packet-counts]` is exactly the two numbers and the slash - the
    // row around it also carries the scan badge, whose percentage would run on
    // to the total with no separator ("44 / 178,200" "0.0%" -> 178,2000).
    const text = document.querySelector('[data-packet-counts]')?.textContent ?? '';
    const m = text.match(/([\d,]+)\s*\/\s*([\d,]+)/);
    return m ? [Number(m[1].replace(/,/g, '')), Number(m[2].replace(/,/g, ''))] : [0, 0];
  });
  // The scan badge is a SIBLING of the counts span, inside the readout's row -
  // so this reads the parent deliberately, which is the one case where running
  // the badge on to the numbers does not matter: it only ever asks whether the
  // word SCANNING is present.
  const badge = () => page.evaluate(
    () => document.querySelector('[data-packet-counts]')?.parentElement?.textContent ?? '');

  await page.getByRole('button', { name: 'Interfaces' }).click();
  await page.getByText('Ethernet', { exact: true }).first().click();
  await page.getByLabel('Start capture').click();

  console.log(`--- capturing until ${BELOW_WINDOW.toLocaleString()} rows are below the window ---\n`);
  const outgrew = await until(async () => {
    const [shown, total] = await counts();
    process.stdout.write(`\r      ${shown.toLocaleString()} in memory, `
      + `${total.toLocaleString()} captured   `);
    return total - shown > BELOW_WINDOW;
  }, 240_000);
  console.log();

  // THE assertion. The two counts diverging is the whole disk path working:
  // the buffer trimmed, the store sealed chunks, and `ordinalOf` placed the
  // window's oldest frame in them. When the field block was crossing unflattened
  // this stayed equal for ever, however long the capture ran.
  checkTrue('the capture outgrows the RAM window', outgrew);
  check('the store never complained', complaints, []);
  if (otherOutput.length > 0) {
    console.log(`      ${otherOutput.length} other line(s) from main, reported not asserted:`);
    for (const line of otherOutput.slice(0, 5)) console.log(`        ${line.slice(0, 120)}`);
  }

  await page.getByLabel('Stop capture').click().catch(() => { /* already stopped */ });
  await sleep(3000);
  const [, captured] = await counts();

  console.log('\n--- filtering the whole capture ---\n');
  // `e.g. tcp.port == 443`, which is what the field says since the display
  // filter moved into the title row. It used to read `ip.addr ==`, and this
  // locator went on naming that for as long as the script was SKIPping on a
  // pipe collision - a stale selector in a test nobody could run.
  const input = page.getByPlaceholder(/tcp\.port ==/).first();
  await input.fill('udp.srcport == 49152');
  await input.press('Enter');
  await sleep(700);
  await until(async () => !(await badge()).includes('SCANNING'), 120_000);
  await sleep(1200);

  const [matched] = await counts();
  const expected = Math.round(captured / FILTER_PERIOD);
  // Within one, because where the cycle falls at each end depends on exactly
  // where the capture stopped.
  checkTrue(`the filter matched the whole capture, not the window `
    + `(${matched} against ~${expected})`, Math.abs(matched - expected) <= 1);

  // Scrolled to the very top, the first row must be a frame from the start of
  // the capture - which is only reachable through the bitmap and a scattered
  // read off disk.
  await page.evaluate(() => {
    const scroller = [...document.querySelectorAll('div')].find(
      (d) => d.scrollHeight > d.clientHeight + 200 && d.querySelector('tbody tr'));
    if (scroller) scroller.scrollTop = 0;
  });
  await sleep(2500);

  const top = await page.evaluate(() =>
    [...document.querySelectorAll('tbody tr')].slice(0, 3).map(
      (tr) => Number(tr.querySelector('td')?.textContent?.replace(/[^\d]/g, '') ?? -1)));
  console.log(`      the top three rows are frames ${top.join(', ')}`);
  checkTrue('the first row is a frame from the start of the capture',
    top[0] > 0 && top[0] < FILTER_PERIOD * 2);
  checkTrue('...and they are one filter period apart, read off disk in order',
    top.length === 3 && top[1] - top[0] === FILTER_PERIOD && top[2] - top[1] === FILTER_PERIOD);

  check('nothing threw in the renderer', rendererErrors, []);
  check('...and the store stayed quiet throughout', complaints, []);
} finally {
  // See `smoke.ts`: closing with frames in the buffer opens a native modal no
  // test can answer.
  await mainWindow?.evaluate(() => window.inwire?.setUnsavedCapture?.(false))
    .catch(() => { /* already gone */ });
  await app?.close().catch(() => { /* likewise */ });
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0
  ? '\nAll disk drive checks passed.'
  : `\n${failures} disk drive check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
