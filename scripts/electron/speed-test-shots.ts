/**
 * Every state of the speed test, photographed - for looking at, not asserting.
 *
 *   npx tsx scripts/electron/speed-test-shots.ts <out-dir> [--widths 1024,1600] [--themes dark,light]
 *
 * Launches the built app against the stub agent and a local speed server
 * (`scripts/speed-test/stubServer.ts`, through `INWIRE_SPEEDTEST_TARGET`), so
 * no byte goes to Cloudflare. For each theme and width it photographs the
 * Network panel's section never tested, every phase of a test, the result, the
 * panel with a result, the sheet idle with history, a cancel, a rate limit, an
 * unreachable server, and a test running beside a capture.
 *
 * In `check.ts`'s NOT_TESTS: it has no right answer, only pictures, and a run
 * takes a few minutes.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent } from './stubAgent';
import { startSpeedStub } from '../speed-test/stubServer';

const OUT = process.argv[2];
if (!OUT) { console.log('usage: speed-test-shots.ts <out-dir>'); process.exit(2); }
const arg = (name: string, fallback: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const WIDTHS = arg('widths', '1024,1600').split(',').map(Number);
const THEMES = arg('themes', 'dark,light').split(',');
mkdirSync(OUT, { recursive: true });

const { _electron: electron } = await import('playwright');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const PIPE = String.raw`\\.\pipe\inwire-speedshots-` + process.pid;
const agent = await startStubAgent(PIPE, 5);
const stub = await startSpeedStub({ downMbps: 420, upMbps: 48 });

for (const theme of THEMES) {
  for (const width of WIDTHS) {
    const height = width <= 1024 ? 700 : 1000;
    const profile = mkdtempSync(path.join(tmpdir(), 'inwire-speedshots-'));
    const app = await electron.launch({
      args: ['.'],
      env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE, INWIRE_SPEEDTEST_TARGET: stub.url },
    });
    const p = await app.firstWindow();
    p.setDefaultTimeout(30_000);
    await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
    await p.evaluate((t) => localStorage.setItem('theme', t), theme);
    await p.reload();
    await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
    await app.evaluate(({ BrowserWindow }, [w, h]) => {
      const win = BrowserWindow.getAllWindows()[0];
      win.unmaximize();
      win.setSize(w, h);
    }, [width, height] as [number, number]);
    await sleep(800);
    await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
    const tag = `${theme}-${width}`;
    const shot = async (name: string) => {
      await p.screenshot({ path: path.join(OUT, `${tag}-${name}.png`) });
      console.log(`  ${tag}-${name}`);
    };
    const until = async (cond: () => Promise<boolean>, ms = 30_000) => {
      const end = Date.now() + ms;
      while (Date.now() < end) { if (await cond().catch(() => false)) return true; await sleep(150); }
      return false;
    };
    const text = (t: string | RegExp) => p.getByText(t).first().isVisible().catch(() => false);
    // Which transfer the dial is on, by its own label - the tiles carry the
    // words "Download" and "Upload" all the time.
    const dialOn = (phase: 'Download' | 'Upload') =>
      p.locator(`svg[aria-label^="${phase}:"]`).count().then((n) => n > 0).catch(() => false);

    stub.set({ mode: 'ok' });
    await p.getByRole('button', { name: 'Network' }).click();
    await sleep(600);
    await shot('01-panel-never-tested');

    await p.getByRole('button', { name: 'Run test' }).click();
    await until(() => text('Measuring ping'), 10_000);
    await shot('02-ping');
    await until(() => dialOn('Download'), 15_000);
    await sleep(4_000);
    await shot('03-download');
    await until(() => dialOn('Upload'), 20_000);
    await sleep(4_000);
    await shot('04-upload');
    await until(() => text('Test again'), 30_000);
    await sleep(500);
    await shot('05-done');

    // Escape leaves the sheet, as it leaves Settings; the panel keeps the result.
    console.log(`    focus before Escape: ${await p.evaluate(() => document.activeElement?.outerHTML.slice(0, 80) ?? 'none')}`);
    await p.keyboard.press('Escape');
    await sleep(500);
    console.log(`    Escape left the sheet: ${!(await text('Test again'))}`);
    await shot('06-panel-with-result');
    await p.getByRole('button', { name: /Results and history/ }).click();
    await sleep(500);
    await shot('07-sheet-reopened');

    // A cancel, mid-download.
    await p.getByRole('button', { name: 'Test again' }).click();
    await until(() => dialOn('Download'), 15_000);
    await sleep(1500);
    await p.getByRole('button', { name: 'Cancel' }).click();
    await until(() => text('Test cancelled'), 10_000);
    await shot('08-cancelled');

    // Rate limited.
    stub.set({ mode: 'down429' });
    await p.getByRole('button', { name: 'Start the speed test' }).click();
    await until(() => text(/limiting tests/), 15_000);
    await shot('09-rate-limited');

    // A server that fails mid-upload.
    stub.set({ mode: 'up500' });
    await p.getByRole('button', { name: 'Try again' }).click();
    await until(() => text(/stopped during upload/), 40_000);
    await shot('10-failed-upload');

    // Unreachable: every connection dropped.
    stub.set({ mode: 'reset' });
    await p.getByRole('button', { name: 'Try again' }).click();
    await until(() => text(/Could not reach/), 20_000);
    await shot('10b-unreachable');

    // A test beside a running capture.
    stub.set({ mode: 'ok' });
    await p.getByRole('button', { name: 'Interfaces' }).click();
    await p.getByText('Ethernet', { exact: true }).first().click();
    await p.getByLabel('Start capture').click();
    await sleep(800);
    await p.getByRole('button', { name: 'Network' }).click();
    await sleep(400);
    await p.getByRole('button', { name: 'Run again' }).click();
    await until(() => dialOn('Download'), 15_000);
    await sleep(2500);
    await shot('11-running-beside-capture');
    await p.getByRole('button', { name: 'Cancel' }).click();
    await sleep(800);
    await p.getByLabel('Stop capture').click().catch(() => {});

    await p.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
    const firstPid = app.process().pid;
    await app.close();
    // The app holds a single-instance lock per profile: a relaunch before the
    // first process has gone hands the window back to it, and the photo is of
    // the old instance. Wait for it to be gone.
    for (let i = 0; i < 50; i++) {
      try { process.kill(firstPid!, 0); await sleep(200); } catch { break; }
    }
    await sleep(500);

    // A fresh launch with history: the sheet idle, GO and the past results.
    {
      const again = await electron.launch({
        args: ['.'],
        env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE, INWIRE_SPEEDTEST_TARGET: stub.url },
      });
      const q = await again.firstWindow();
      q.setDefaultTimeout(30_000);
      await q.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
      await again.evaluate(({ BrowserWindow }, [w, h]) => {
        const win = BrowserWindow.getAllWindows()[0];
        win.unmaximize();
        win.setSize(w, h);
      }, [width, height] as [number, number]);
      await sleep(800);
      await q.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
      const net = q.getByRole('button', { name: 'Network' });
      if (!(await q.getByText('Results and history').first().isVisible().catch(() => false))) await net.click();
      await sleep(400);
      await q.screenshot({ path: path.join(OUT, `${tag}-12-panel-after-relaunch.png`) });
      await q.getByRole('button', { name: /Results and history/ }).click();
      await sleep(500);
      await q.screenshot({ path: path.join(OUT, `${tag}-13-sheet-idle-with-history.png`) });
      console.log(`  ${tag}-12/13 after relaunch`);
      await again.close();
    }
    rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }
}
await stub.close();
await agent.close();
console.log(`shots in ${OUT}`);
