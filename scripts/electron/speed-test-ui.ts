/**
 * The speed test through the real app, against a speed server on this machine.
 *
 *   npx tsx scripts/electron/speed-test-ui.ts
 *
 * What plain `tsx` cannot reach: the preload's two calls, main's IPC, the
 * engine's own utilityProcess forked from the bundled `speedTest.cjs`, the
 * events relayed back, the sheet that draws them and the history that keeps
 * them. One test end to end, a cancel, and a refusal - against
 * `scripts/speed-test/stubServer.ts` through `INWIRE_SPEEDTEST_TARGET`, so no
 * byte goes to Cloudflare and the answer does not depend on the network.
 * Skips like `smoke.ts` without a build or Playwright.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent, type StubAgent } from './stubAgent';
import { startSpeedStub, type SpeedStub } from '../speed-test/stubServer';
import { launchApp } from './launchApp';

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
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'speedTest', 'speedTest.cjs'))) {
  skip('no build with the speed test to launch - run `npm run build` first');
}
try {
  await import('playwright');
} catch {
  skip('playwright is not installed');
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const PIPE = String.raw`\\.\pipe\inwire-speedui-` + process.pid;
let agent: StubAgent | null = null;
let stub: SpeedStub | null = null;
let profile: string | null = null;
let app: Awaited<ReturnType<typeof launchApp>> | null = null;

try {
  agent = await startStubAgent(PIPE, 5);
  stub = await startSpeedStub({ downMbps: 100, upMbps: 30 });
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-speedui-'));
  app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE, INWIRE_SPEEDTEST_TARGET: stub.url },
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

  await p.getByRole('button', { name: 'Network' }).click();
  checkTrue('the Network panel offers the speed test', await until(() => visible('Run test'), 10_000));
  checkTrue('...and says who sees the address before the first test', await visible(/Cloudflare sees this machine/));
  await p.getByRole('button', { name: 'Run test' }).click();
  checkTrue('running a test opens the sheet with its charts', await until(() => p.locator('svg[role="img"][aria-label]').count().then((n) => n > 0), 10_000));
  checkTrue('the running test shows the dial', await until(() => p.locator('svg[role="img"][aria-label*="megabits per second"]').count().then((n) => n > 0), 10_000));
  checkTrue('the server and ISP show before the numbers', await until(() => visible(/Example Networks/), 10_000));
  checkTrue('the download trace draws', await until(() => p.locator('svg[aria-label^="Download trace:"]').count().then((n) => n > 0), 15_000));
  checkTrue('the upload follows it', await until(() => p.locator('svg[aria-label^="Upload trace:"]').count().then((n) => n > 0), 20_000));
  checkTrue('the test finishes with a result and Test again', await until(() => visible('Test again'), 30_000));
  checkTrue('the latency boxes draw', await p.locator('svg[aria-label^="Latency:"]').count() > 0);
  checkTrue('responsiveness is labelled approximate', await visible(/Responsiveness \(approx\.\)/));
  // The history is written as the result lands, and read back here off the
  // same storage the app restores it from.
  const stored = () => p.evaluate(() => {
    const raw = localStorage.getItem('inwire.speedTestHistory');
    return raw ? (JSON.parse(raw) as { downMbps: number; upMbps: number }[]) : [];
  });
  await until(async () => (await stored()).length > 0, 5_000);
  const down = await stored();
  checkTrue('...recorded in this machine\'s history', down.length === 1, JSON.stringify(down));
  checkTrue('...at about the speed the server allowed', down.length === 1 && down[0].downMbps > 70 && down[0].downMbps < 115,
    `${down[0]?.downMbps} Mb/s against a 100 Mb/s server`);

  // A cancel mid-download records nothing and leaves the app able to test again.
  await p.getByRole('button', { name: 'Test again' }).click();
  await until(() => p.locator('svg[aria-label^="Download trace:"]').count().then((n) => n > 0), 15_000);
  await sleep(1000);
  await p.getByRole('button', { name: 'Cancel' }).click();
  checkTrue('Cancel ends the test', await until(() => visible('Test cancelled'), 10_000));
  const afterCancel = await p.evaluate(() => JSON.parse(localStorage.getItem('inwire.speedTestHistory') ?? '[]').length);
  checkTrue('...and records nothing', afterCancel === 1, `${afterCancel} entries`);

  // A refusal is said, with a way to try again - never a trace left hanging.
  stub.set({ mode: 'down429' });
  await p.getByRole('button', { name: 'Start the speed test' }).click();
  checkTrue('a rate limit is said as one', await until(() => visible(/limiting tests/), 15_000));
  checkTrue('...with Try again', await visible('Try again'));

  // Escape leaves the sheet, as it leaves Settings.
  await p.keyboard.press('Escape');
  checkTrue('Escape leaves the sheet', await until(async () => !(await visible('Try again')), 5_000));
} finally {
  await app?.evaluate(() => {}).catch(() => {});
  await app?.close().catch(() => {});
  await stub?.close();
  await agent?.close();
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0 ? '\nAll speed-test UI checks passed.' : `\n${failures} speed-test UI check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
