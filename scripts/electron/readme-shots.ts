/**
 * The README's pictures of the capture view, taken against the stub agent.
 *
 *   npx tsx scripts/electron/readme-shots.ts <out-dir> [--themes dark,light]
 *
 * Launches the built app in the background against `stubAgent.ts`, so every
 * frame in a picture is a synthetic DNS query and no real capture is ever
 * photographed, and in UTC so no picture names the machine's time zone. For
 * each theme it captures a few seconds, stops, selects a row and writes
 * `capture-<theme>.png` at 1600x1000. The monitoring sheet's
 * pictures come from `monitoring-shots.ts`, which sends its own v5 datagrams.
 *
 * In `check.ts`'s NOT_TESTS: it has no right answer, only pictures.
 */
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent } from './stubAgent';
import { launchApp } from './launchApp';

const OUT = process.argv[2];
if (!OUT || OUT.startsWith('--')) { console.log('usage: readme-shots.ts <out-dir> [--themes dark,light]'); process.exit(2); }
const i = process.argv.indexOf('--themes');
const THEMES = (i > 0 ? process.argv[i + 1] : 'dark,light').split(',');
mkdirSync(OUT, { recursive: true });

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const PIPE = String.raw`\\.\pipe\inwire-readmeshots-` + process.pid;
const agent = await startStubAgent(PIPE, 5);

for (const theme of THEMES) {
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-readmeshots-'));
  const app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE, TZ: 'UTC' },
  });
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  // Not waitForFunction with a string: that evaluates it in the page, which the CSP forbids.
  const ready = async () => {
    const end = Date.now() + 30_000;
    while (Date.now() < end) {
      if (await p.evaluate('(document.getElementById("root")?.childElementCount ?? 0) > 0').catch(() => false)) return;
      await sleep(150);
    }
    throw new Error('the app never rendered');
  };
  await ready();
  // A string, not a function: tsx's esbuild wraps a function in `__name`, which the page does not have.
  await p.evaluate(`localStorage.setItem('theme', ${JSON.stringify(theme)});`);
  await p.reload();
  await ready();
  await app.evaluate(({ BrowserWindow }) => {
    const w = BrowserWindow.getAllWindows()[0];
    w.unmaximize();
    w.setSize(1600, 1000);
  });
  await sleep(800);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});

  await p.getByRole('button', { name: 'Interfaces' }).click();
  await p.getByText('Ethernet', { exact: true }).first().click();
  await p.keyboard.press('Escape');
  await p.getByLabel('Start capture').click();
  await sleep(4000);
  await p.getByLabel('Stop capture').click();
  await sleep(1000);
  await p.locator('[role="row"]').nth(6).click();
  await sleep(1000);
  await p.screenshot({ path: path.join(OUT, `capture-${theme}.png`) });
  console.log(`wrote capture-${theme}.png`);

  // Nothing is worth keeping, and an unsaved capture would hold the close on its confirm.
  await p.evaluate('window.inwire?.setUnsavedCapture?.(false)').catch(() => {});
  await app.close().catch(() => {});
  rmSync(profile, { recursive: true, force: true });
}

await agent.close?.();
