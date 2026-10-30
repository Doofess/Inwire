/**
 * A large capture-file import, and the renderer's heap after it (#19).
 *
 *   npm run build && npx tsx scripts/electron/import-heap-drive.ts --pcap <file> [--buffer-mb 1024] [--app <dir>]
 *
 * An import dissects on the renderer's thread and keeps a RAM tail of rows. It
 * used to keep every frame: 2.4M frames cut to 128 B (a 343 MB file) ended the
 * renderer 37 s in with exit code -36861, V8 out of heap. This imports a file
 * through the Export/Import panel of the built app and waits for the panel's
 * own "Imported N packets" line (a count that holds still also does so during a
 * long GC). While it runs, main reports each process's private bytes every five
 * seconds; the renderer's thread is busy and cannot answer. Then it visits the
 * views a person would, printing the live heap after a forced GC at each step.
 *
 * The live heap is Chromium's `usedJSHeapSize`, which includes ArrayBuffer
 * backing stores - the rows' raw bytes, as `estimateSummaryBytes` counts them.
 * V8's 4 GB limit applies only to the heap proper, so the drive prints that
 * split too.
 *
 * Fails (exit 1) if main logs `[renderer] gone`, if the app answers the import
 * with its error dialog (printed: a file over 2 GB did, until #20), or if the live heap after the
 * import is past the buffer budget plus 512 MiB. The 512 MiB stands for the
 * app's own baseline and its trackers: an assumption, printed as one, not a
 * measurement. Without `--buffer-mb` the profile keeps the app's default,
 * `auto`, and the budget is resolved here from the same two facts the preload
 * hands the app. `--app` launches another checkout's build, to record the
 * failure this replaces.
 *
 * Not in `npm run check` (`check.ts`'s NOT_TESTS): it needs a big file and a
 * build, and takes minutes.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { autoBufferBudget } from '../../src/services/bufferBudget';
import { launchApp } from './launchApp';
import { startStubAgent } from './stubAgent';

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const FILE = arg('pcap', '');
const BUFFER_MB = arg('buffer-mb', 'auto');
const APP = arg('app', '');
const MIB = 1024 * 1024;
const HEADROOM = 512 * MIB;
const VIEWS = ['Packets', 'Frame Detail', 'Statistics', 'Routing Map', 'Packets'];

if (!FILE || !existsSync(FILE)) {
  console.error('usage: import-heap-drive.ts --pcap <file> [--buffer-mb <MB>] [--app <dir>]');
  process.exit(2);
}

// Playwright asserts on a target that dies under it and throws outside any
// promise this awaits; the renderer's death is reported from main's log below.
process.on('uncaughtException', (error) => console.log(`(playwright: ${String(error).split('\n')[0]})`));
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const mb = (bytes: number) => `${Math.round(bytes / MIB).toLocaleString()} MB`;
const PIPE = `\\\\.\\pipe\\inwire-import-heap-${process.pid}`;
const agent = await startStubAgent(PIPE, 0);
const profile = mkdtempSync(path.join(tmpdir(), 'inwire-import-heap-'));
const app = await launchApp({
  args: ['--js-flags=--expose-gc', '.'],
  ...(APP ? { cwd: APP } : {}),
  env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE, INWIRE_CRASH_ANSWER: 'quit' },
});
let log = '';
app.process().stdout?.on('data', (d) => { log += String(d); });
app.process().stderr?.on('data', (d) => { log += String(d); });
const gone = () => /\[renderer\] gone/.test(log);

const failures: string[] = [];
try {
  const page = await app.firstWindow();
  page.setDefaultTimeout(30_000);
  // tsx compiles with keepNames; a string evaluate defines the helper it wraps functions in.
  await page.evaluate('window.__name = (f) => f');
  await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await page.evaluate(({ buffer }) => {
    localStorage.setItem('inwire.tour', JSON.stringify({ completed: true }));
    if (buffer !== 'auto') localStorage.setItem('inwire.performance', JSON.stringify({ packetBufferBytes: buffer }));
  }, { buffer: BUFFER_MB === 'auto' ? 'auto' : Number(BUFFER_MB) * MIB });
  await page.reload();
  await page.evaluate('window.__name = (f) => f');
  await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await page.getByRole('button', { name: 'Skip' }).click({ timeout: 2000 }).catch(() => {});

  const host = await page.evaluate(() => {
    const w = window as unknown as { inwire?: { systemMemoryBytes?: number; heapLimitBytes?: number } };
    return { memory: w.inwire?.systemMemoryBytes ?? null, heap: w.inwire?.heapLimitBytes ?? null };
  });
  const budget = BUFFER_MB === 'auto' ? autoBufferBudget(host.memory, host.heap) : Number(BUFFER_MB) * MIB;
  console.log(`packet buffer: ${BUFFER_MB === 'auto' ? `auto, resolved to ${mb(budget)}` : mb(budget)}; ` +
    `limit ${mb(budget + HEADROOM)} (budget + 512 MB assumed for the app itself)`);

  const liveHeap = (): Promise<number> => page.evaluate(() => {
    const collect = (globalThis as unknown as { gc?: () => void }).gc;
    collect?.(); collect?.();
    return (performance as unknown as { memory: { usedJSHeapSize: number } }).memory.usedJSHeapSize;
  });
  const total = (): Promise<number> => page.evaluate(() => {
    const m = (document.querySelector('[data-packet-counts]')?.textContent ?? '').match(/([\d,]+)\s*\/\s*([\d,]+)/);
    return m ? Number(m[2].replace(/,/g, '')) : 0;
  }).catch(() => -1);

  console.log(`start: ${mb(await liveHeap())} live`);
  await page.getByLabel('Export or import a capture').click();
  await page.getByRole('button', { name: /^import$/i }).click({ timeout: 2000 }).catch(() => {});
  const started = Date.now();
  await page.locator('input[type="file"]').first().setInputFiles(FILE);
  // Done is the panel's own "Imported N packets from" line, not a count that
  // held still: a long GC pause mid-import holds the count still too.
  // Every five seconds while it runs, from main, which answers while the
  // renderer's thread is busy dissecting: each process's private bytes, which
  // see memory the JS heap does not.
  const sampler = setInterval(() => {
    void app.evaluate(({ app: electronApp }) => electronApp.getAppMetrics()
      .map((m) => ({ type: m.type, privateKb: m.memory.privateBytes ?? 0 })))
      .then((metrics) => console.log(`  ${Math.round((Date.now() - started) / 1000)} s: ` +
        metrics.filter((m) => m.privateKb > 100 * 1024)
          .map((m) => `${m.type} ${mb(m.privateKb * 1024)}`).join(', ')), () => {});
  }, 5000);
  // An import the app refuses ends in its error dialog, not the line above:
  // before #20 a file over 2 GB did, and the drive waited out its 15 minutes.
  // The longest the progress line held one value is printed as a hint at how
  // long the renderer went without painting; it is not asserted.
  let done = '';
  let refused: { heading: string; message: string } | null = null;
  let progress = '';
  let progressSince = Date.now();
  let longestHold = 0;
  try {
    while (Date.now() - started < 900_000 && !gone() && !done && !refused) {
      const seen = await page.evaluate(() => {
        // Visible only: the quit confirm is a closed <dialog role="alertdialog">
        // that stays mounted for the app's whole life.
        const dialog = [...document.querySelectorAll<HTMLElement>('[role="alertdialog"]')]
          .find((el) => el.getClientRects().length > 0) ?? null;
        return {
          done: (document.body.innerText.match(/Imported [\d,]+ packets from [^\n]+/) ?? [''])[0],
          progress: (document.body.innerText.match(/Importing [^\n]+ of [^\n]+\(\d+%\)/) ?? [''])[0],
          dialog: dialog === null ? null : {
            heading: dialog.querySelector('h1, h2, h3, [role="heading"]')?.textContent?.trim() ?? '',
            message: dialog.innerText.trim(),
          },
        };
      }).catch(() => ({ done: '', progress: '', dialog: null }));
      done = seen.done;
      refused = seen.dialog;
      if (seen.progress !== progress) {
        if (progress) longestHold = Math.max(longestHold, Date.now() - progressSince);
        progress = seen.progress;
        progressSince = Date.now();
      }
      if (!done && !refused) await sleep(500);
    }
  } finally {
    clearInterval(sampler);
  }
  if (gone()) throw new Error('renderer gone during the import');
  if (refused) throw new Error(`the app refused the import: ${refused.heading} - ${refused.message.replace(/\s+/g, ' ')}`);
  if (!done) throw new Error('the import did not finish in 15 minutes');
  const seconds = Math.round((Date.now() - started) / 1000);
  console.log(`progress line: longest unchanged ${(longestHold / 1000).toFixed(1)} s (a hint, not asserted)`);
  const note = await page.evaluate(() =>
    (document.body.innerText.match(/All [\d,]+ frames were imported[^\n]*/) ?? [''])[0]).catch(() => '');
  if (note) console.log(`note: ${note}`);
  await page.keyboard.press('Escape').catch(() => {});
  const frames = await total();
  const after = await liveHeap();
  console.log(`import: ${frames.toLocaleString()} frames in ${seconds} s (${done}), ${mb(after)} live`);
  // V8's own split: what is in the heap proper, and the ArrayBuffer backing
  // stores (the rows' raw bytes), which live outside the heap's limit.
  const cdp = await page.context().newCDPSession(page);
  const usage = await cdp.send('Runtime.getHeapUsage') as { usedSize: number; backingStorageSize?: number };
  console.log(`  of which V8 heap ${mb(usage.usedSize)}, ArrayBuffer backing stores ${usage.backingStorageSize === undefined ? '?' : mb(usage.backingStorageSize)}`);
  await cdp.detach();
  if (after > budget + HEADROOM) failures.push(`live heap after the import ${mb(after)} is past ${mb(budget + HEADROOM)}`);

  for (const view of VIEWS) {
    if (gone()) break;
    const clicked = await page.getByRole('button', { name: new RegExp(`^${view}`) }).first()
      .click({ timeout: 5000 }).then(() => true, () => false);
    await sleep(3000);
    console.log(`  ${view.padEnd(13)} ${clicked ? '' : '(no button) '}${mb(await liveHeap())} live`);
  }
  if (!gone()) {
    await page.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (b: boolean) => void } })
      .inwire?.setUnsavedCapture?.(false));
  }
} catch (error) {
  failures.push(gone() ? 'renderer gone' : `driver: ${String(error).split('\n')[0]}`);
} finally {
  await app.close().catch(() => {});
  await agent.close();
  rmSync(profile, { recursive: true, force: true });
}

const goneLine = log.split('\n').find((line) => /\[renderer\] gone/.test(line));
if (goneLine) {
  console.log(goneLine.trim());
  if (!failures.includes('renderer gone')) failures.push('renderer gone');
}
if (failures.length) {
  console.log(`FAIL: ${failures.join('; ')}`);
  process.exit(1);
}
console.log('PASS');
process.exit(0);
