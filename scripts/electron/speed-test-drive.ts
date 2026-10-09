/**
 * One real speed test, against Cloudflare, in the built app - and its numbers.
 *
 *   npx tsx scripts/electron/speed-test-drive.ts
 *
 * Presses Run in the Network panel, waits for the result, and prints it with
 * the server and the ISP Cloudflare reported - beside main's event-loop delay
 * while the test ran, which is the number that put the engine in a process of
 * its own (ADR 0054). Compare the figures with a test at speed.cloudflare.com
 * in a browser, run straight after.
 *
 * In `check.ts`'s NOT_TESTS: it reaches the internet by design, the network
 * decides the answer, and Cloudflare rate-limits an address that tests often.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent } from './stubAgent';

const { _electron: electron } = await import('playwright');
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const PIPE = String.raw`\\.\pipe\inwire-speeddrive-` + process.pid;
const agent = await startStubAgent(PIPE, 0);
const profile = mkdtempSync(path.join(tmpdir(), 'inwire-speeddrive-'));
const env: Record<string, string> = { ...process.env as Record<string, string>, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE };
delete env.INWIRE_SPEEDTEST_TARGET;
const app = await electron.launch({ args: ['.'], env });
try {
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});

  // Main's event loop, sampled while the test runs.
  await app.evaluate(() => {
    const { monitorEventLoopDelay } = process.getBuiltinModule('node:perf_hooks') as typeof import('node:perf_hooks');
    const h = monitorEventLoopDelay({ resolution: 5 });
    h.enable();
    (globalThis as { __speedLag?: typeof h }).__speedLag = h;
  });

  await p.getByRole('button', { name: 'Network' }).click();
  const started = Date.now();
  await p.getByRole('button', { name: 'Run speed test' }).click();
  const end = Date.now() + 90_000;
  let outcome = 'timed out';
  while (Date.now() < end) {
    if (await p.getByText('Test again').first().isVisible().catch(() => false)) { outcome = 'done'; break; }
    if (await p.getByRole('alert').first().isVisible().catch(() => false)) {
      outcome = `failed: ${await p.getByRole('alert').first().innerText()}`;
      break;
    }
    await sleep(250);
  }
  const lag = await app.evaluate(() => {
    const h = (globalThis as { __speedLag?: import('node:perf_hooks').IntervalHistogram }).__speedLag!;
    h.disable();
    return { p50: h.percentile(50) / 1e6, p99: h.percentile(99) / 1e6, max: h.max / 1e6 };
  });
  console.log(`outcome: ${outcome.replace(/\s+/g, ' ')} after ${((Date.now() - started) / 1000).toFixed(1)} s`);
  if (outcome === 'done') {
    const history = await p.evaluate(() => JSON.parse(localStorage.getItem('inwire.speedTestHistory') ?? '[]'));
    const r = history[0];
    console.log(`download ${r.downMbps.toFixed(1)} Mb/s, upload ${r.upMbps.toFixed(1)} Mb/s, ping ${r.pingMs.toFixed(1)} ms, jitter ${r.jitterMs.toFixed(1)} ms, grade ${r.grade}`);
    console.log(`server: Cloudflare ${r.server}; ISP: ${r.isp}`);
    const loaded = await p.getByText(/^↓ .* ms · ↑ .* ms$/).first().innerText().catch(() => '?');
    console.log(`loaded latency: ${loaded}`);
  }
  console.log(`main's event-loop delay during the test: p50 ${lag.p50.toFixed(1)} ms, p99 ${lag.p99.toFixed(1)} ms, max ${lag.max.toFixed(1)} ms`);
} finally {
  await app.close().catch(() => {});
  await agent.close();
  rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
process.exit(0);
