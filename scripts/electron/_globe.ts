// Throwaway: the speed test's server on the globe, both themes.
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent } from './stubAgent';
import { startSpeedStub } from '../speed-test/stubServer';
const OUT = process.argv[2];
const { _electron: electron } = await import('playwright');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const PIPE = String.raw`\\.\pipe\inwire-globe-` + process.pid;
const agent = await startStubAgent(PIPE, 0);
const stub = await startSpeedStub({ downMbps: 380, upMbps: 45 });
for (const theme of ['dark', 'light']) {
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-globe-'));
  const app = await electron.launch({ args: ['.'], env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE, INWIRE_SPEEDTEST_TARGET: stub.url } });
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  const errors: string[] = [];
  p.on('pageerror', (e) => errors.push(String(e)));
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await p.evaluate((t) => {
    localStorage.setItem('theme', t);
    localStorage.setItem('inwire.nameResolution', JSON.stringify({ network: true, transport: true, geoIp: true, reverseDns: false }));
  }, theme);
  await p.reload();
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await app.evaluate(({ BrowserWindow }) => { const w = BrowserWindow.getAllWindows()[0]; w.unmaximize(); w.setSize(1400, 900); });
  await sleep(800);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  await p.getByRole('button', { name: 'Network' }).click();
  await p.getByRole('button', { name: 'Run test' }).click();
  const end = Date.now() + 45_000;
  while (Date.now() < end && !(await p.getByText('Test again').first().isVisible().catch(() => false))) await sleep(300);
  await p.screenshot({ path: path.join(OUT, `${theme}-done-with-map-link.png`) });
  await p.getByRole('button', { name: /Show the server on the map/ }).click();
  await sleep(9000);
  await p.screenshot({ path: path.join(OUT, `${theme}-globe.png`) });
  const chip = p.locator('[aria-label^="Speed test"]').first();
  console.log(`${theme}: chip present ${await chip.count()}`);
  await chip.hover().catch((e) => console.log(`hover failed ${e}`));
  await sleep(600);
  await p.screenshot({ path: path.join(OUT, `${theme}-globe-hover.png`) });
  console.log(`${theme}: page errors ${errors.length} ${errors.slice(0, 2).join(' | ')}`);
  await app.close();
  rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
await stub.close();
await agent.close();
console.log('done');
