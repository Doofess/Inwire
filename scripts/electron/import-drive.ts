/**
 * Importing a capture file bigger than the RAM buffer, through the real UI.
 *
 *   npm run build && npx tsx scripts/electron/import-drive.ts
 *
 * ## Why by hand and not in `npm run check`
 *
 * The behaviour only exists past the buffer's frame cap, which at the smallest
 * offered budget is about 181,000 frames. Generating and dissecting 400,000 is
 * most of a minute, so `check.ts` lists this under NOT_TESTS beside
 * `disk-drive.ts`; the two together are what cover the store from the app's
 * side, and `disk-drive.ts`'s header says why that mattered.
 *
 * ## What it asserts
 *
 * That the import is **whole**. It used to stop at the cap and put a note on
 * screen saying the rest had not been loaded - which was honest, and was also
 * the only thing the app could say while every frame had to fit in one array.
 * Now the frames stream to the capture store as they are dissected and the
 * buffer keeps the newest, so the two counts in the filter bar disagree and
 * the list scrolls back to frame 1.
 *
 * The frames are DNS queries built by hand, for the same reason
 * `stubAgent.ts` builds its own: a dissected result that can be predicted
 * exactly is worth more than a realistic one that cannot.
 */
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { dnsQuery } from './stubAgent';

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
 * Comfortably past the cap.
 *
 * 128 MB over the measured mean summary cost is about 181,000 frames, so this
 * leaves well over 200,000 that can only be reached from disk.
 */
const FRAMES = 400_000;

/** A classic libpcap file. Written here so the writer under test is not the oracle. */
function pcapOf(frames: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(24 + frames.reduce((n, f) => n + 16 + f.length, 0));
  const view = new DataView(out.buffer);
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true);
  view.setUint16(6, 4, true);
  view.setUint32(16, 262144, true);
  view.setUint32(20, 1, true);                       // Ethernet
  let at = 24;
  frames.forEach((frame, i) => {
    // A millisecond apart, so the capture spans real time and the writer's
    // patch horizon behaves the way it does on a live one.
    view.setUint32(at, 1_700_000_000 + Math.floor(i / 1000), true);
    view.setUint32(at + 4, (i % 1000) * 1000, true);
    view.setUint32(at + 8, frame.length, true);
    view.setUint32(at + 12, frame.length, true);
    out.set(frame, at + 16);
    at += 16 + frame.length;
  });
  return out;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const files = mkdtempSync(path.join(tmpdir(), 'inwire-import-'));
const pcapPath = path.join(files, 'big.pcap');
writeFileSync(pcapPath, pcapOf(Array.from({ length: FRAMES }, (_, i) => dnsQuery(i & 0xffff))));
console.log(`      wrote ${FRAMES.toLocaleString()} frames to a ${
  (existsSync(pcapPath) ? Math.round(FRAMES * 87 / 1e6) : 0)} MB file\n`);

let profile: string | null = null;
let app: Awaited<ReturnType<typeof electron.launch>> | null = null;
let mainWindow: Awaited<ReturnType<Awaited<ReturnType<typeof electron.launch>>['firstWindow']>> | null = null;

try {
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-importp-'));
  app = await electron.launch({ args: ['.'], env: { ...process.env, INWIRE_USER_DATA: profile } });
  const page = await app.firstWindow();
  mainWindow = page;
  page.setDefaultTimeout(30_000);

  // What the STORE said, which is not everything main printed. Same split and
  // same reason as `disk-drive.ts`: this asserted main's whole stdout was
  // empty under the name "the store stayed quiet", so on any machine with the
  // agent service installed it failed on `[agent-pipe] auto start: started` -
  // the supervisor reporting normal operation. `[capture-store:` is the prefix
  // `electron/store/host.ts` puts on both of the child's streams.
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
  await page.evaluate(() => localStorage.setItem('inwire.performance',
    JSON.stringify({ dashboardRefreshMs: 2000, packetBufferBytes: 128 * 1024 * 1024 })));
  /*
   * **And the first-run tour, which made this script unrunnable.**
   *
   * A temporary profile is a first run, so `TourOverlay` opens over everything
   * and its popover intercepts pointer events. The first click this script
   * makes is the rail's Export/Import button, so every run ended in a
   * `TimeoutError` naming `Choose what to listen on` - a tour step - rather
   * than anything to do with importing. Reproduced at the commit before this
   * one, so it is not new; it is just that a driver in `check.ts`'s
   * `NOT_TESTS` only fails when somebody runs it, which is the second time
   * that has bitten this exact file.
   *
   * `update-center-drive.ts` clicks Skip. This sets the preference instead,
   * one line above a `reload()` that was already here: a click depends on a
   * button's label and on the overlay having finished animating in, and both
   * of those have already moved once in this file's history.
   */
  await page.evaluate(() => localStorage.setItem('inwire.tour',
    JSON.stringify({ completed: true })));
  await page.reload();
  await page.waitForLoadState('domcontentloaded');
  await sleep(1500);

  const counts = () => page.evaluate(() => {
    // `[data-packet-counts]` is exactly the two numbers and the slash; the row
    // around it also carries the scan badge, whose percentage would run on to
    // the total with no separator.
    const text = document.querySelector('[data-packet-counts]')?.textContent ?? '';
    const m = text.match(/([\d,]+)\s*\/\s*([\d,]+)/);
    return m ? [Number(m[1].replace(/,/g, '')), Number(m[2].replace(/,/g, ''))] : [0, 0];
  });

  // The rail's Export/Import button, by its accessible name.
  //
  // This was two clicks - `getByRole('button', { name: /menu/i })` and then
  // `getByText('Export / Import PCAP')` - and BOTH stopped resolving when the
  // hamburger drawer was deleted. There is no control named "menu" anywhere in
  // the app now, and the rail button that took over is a glyph with no text
  // node at all: `Export / Import PCAP` is its `title`, which `getByText` does
  // not read. So this script could not reach the panel it exists to drive, and
  // nothing said so - it is in `check.ts`'s NOT_TESTS, so it only runs when
  // somebody runs it.
  //
  // `getByLabel` rather than `getByRole(..., { name })` because the button
  // carries both an `aria-label` and a `title`: the label wins for the
  // accessible name, and naming the attribute that decides is what stops the
  // next edit silently changing which string this depends on.
  await page.getByLabel('Export or import a capture').click();
  await sleep(600);
  // The Import tab inside the modal, which does have a text node.
  await page.getByRole('button', { name: /^import$/i }).click().catch(() => { /* already there */ });
  await sleep(400);

  console.log('--- importing ---\n');
  await page.locator('input[type="file"]').first().setInputFiles(pcapPath);

  const deadline = Date.now() + 240_000;
  let seen: number[] = [0, 0];
  while (Date.now() < deadline) {
    seen = await counts();
    process.stdout.write(`\r      ${seen[0].toLocaleString()} in memory, `
      + `${seen[1].toLocaleString()} in the capture   `);
    if (seen[1] >= FRAMES) break;
    await sleep(2000);
  }
  console.log();

  // The whole file, not the cap. This is the assertion: the import used to
  // stop at whatever the buffer could hold and say so.
  check('every frame in the file was imported', seen[1], FRAMES);
  checkTrue(`...and only the newest are resident (${seen[0].toLocaleString()})`,
    seen[0] > 0 && seen[0] < FRAMES);

  const note = await page.evaluate(() => [...document.querySelectorAll('p,li,span,div')]
    .map((e) => (e.childElementCount === 0 ? (e.textContent ?? '') : ''))
    .find((t) => t.includes('were imported')) ?? '');
  checkTrue('the note says where the rest of them are', note.includes('on disk'));

  await page.keyboard.press('Escape');
  await sleep(800);
  await page.evaluate(() => {
    const scroller = [...document.querySelectorAll('div')].find(
      (d) => d.scrollHeight > d.clientHeight + 200 && d.querySelector('tbody tr'));
    if (scroller) scroller.scrollTop = 0;
  });
  await sleep(2500);

  const top = await page.evaluate(() => [...document.querySelectorAll('tbody tr')].slice(0, 4)
    .map((tr) => Number(tr.querySelector('td')?.textContent?.replace(/[^\d]/g, '') ?? -1)));
  console.log(`      the top of the list reads ${top.join(', ')}`);
  // Frame 1 is a quarter of a million frames below the resident window, so it
  // can only have come off disk.
  check('the list scrolls back to the first frame in the file', top, [1, 2, 3, 4]);

  check('nothing threw in the renderer', rendererErrors, []);
  check('the store stayed quiet', complaints, []);
  if (otherOutput.length > 0) {
    console.log(`      ${otherOutput.length} other line(s) from main, reported not asserted:`);
    for (const line of otherOutput.slice(0, 5)) console.log(`        ${line.slice(0, 120)}`);
  }
} finally {
  await mainWindow?.evaluate(() => window.inwire?.setUnsavedCapture?.(false))
    .catch(() => { /* already gone */ });
  await app?.close().catch(() => { /* likewise */ });
  for (const dir of [profile, files]) {
    try {
      if (dir) rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
    } catch {
      console.log(`      note: could not remove ${dir}`);
    }
  }
}

console.log(failures === 0
  ? '\nAll import drive checks passed.'
  : `\n${failures} import drive check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
