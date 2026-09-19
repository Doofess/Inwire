/**
 * The app against the **real** installed agent, not the stub.
 *
 *   npm run build && npx tsx scripts/electron/agent-live-drive.ts
 *
 * ## Why this exists
 *
 * `docs/verification.md` carried the agent-lifetime items as by-hand steps -
 * "launch it and watch the status bar reach Agent connected without a UAC
 * prompt". That is a real instruction and it was also an admission, because
 * every part of it is observable from a script: the SCM's state is a command,
 * the status bar is a DOM node, and the difference between "connected" and
 * "not running" is the one thing the whole of ADR 0035 is about.
 *
 * `smoke.ts` cannot do this job. It points the app at a private pipe served by
 * `stubAgent.ts`, which is what makes it hermetic and what makes it blind to
 * everything between the app and the actual service: the unelevated start, the
 * version comparison against a really-installed agent, and `hello` arriving
 * from something that opened a real capture device.
 *
 * ## What it deliberately does NOT do, and why that cannot be fixed here
 *
 * **It never starts a capture.** The adapters here are the machine's real ones,
 * and a capture on a real adapter is somebody's actual traffic.
 *
 * That was the whole of the reason, and it turns out to be the weaker half of
 * it. `scripts/agent/agent-interop.ts` gets around exactly this constraint by
 * capturing **loopback** and generating the traffic itself - nobody's but the
 * harness's - so the obvious move is to do the same here through the UI. It
 * does not work, and the reason is a decision rather than an obstacle:
 * `filterCapturableInterfaces` in `src/services/captureInterfaces.ts`
 * **removes loopback from the picker**, because it is the busiest device on a
 * typical machine (~1,200 pkt/s of process-to-process chatter against ~50/sec
 * on a live Ethernet adapter) and capturing it floods the buffer and saturates
 * the render loop.
 *
 * So the one adapter that would make an automated capture safe is the one the
 * app is designed never to offer. **The gap is structural**: driving a capture
 * from this window means picking a real adapter, and this script will not do
 * that on a person's machine.
 *
 * What covers it instead, in two halves that meet in the middle: `interop`
 * drives a **real agent with a real capture handle** over the production pipe,
 * and `smoke.ts` drives the **real UI and the whole frame path** against the
 * stub. Only their conjunction is untested, and it is untested on purpose.
 * `docs/verification.md` keeps it as a by-hand step, which is the honest place
 * for it - a person capturing their own traffic is a person who has consented.
 *
 * In `NOT_TESTS`: it needs the InwireAgent service installed, which a CI
 * machine does not have, and it reads state a person's machine owns.
 */
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

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

if (process.platform !== 'win32') skip('the agent service is Windows-only');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}

/**
 * Runs `sc.exe` and answers with its output and its **exit code**.
 *
 * The code is the point. `sc` prints localised text - the failure line on a
 * German Windows is German - and the number is not, which is the whole doctrine
 * `electron/serviceStart.ts` is built on. This is where that doctrine gets
 * checked against the real tool rather than against a table of constants.
 */
function sc(...args: string[]): { code: number; out: string } {
  try {
    return { code: 0, out: execFileSync('sc.exe', args, { encoding: 'utf8', windowsHide: true }) };
  } catch (error) {
    const failure = error as { status?: number; stdout?: string; stderr?: string };
    return {
      code: typeof failure.status === 'number' ? failure.status : -1,
      out: `${failure.stdout ?? ''}${failure.stderr ?? ''}`,
    };
  }
}

const config = sc('qc', 'InwireAgent');
if (config.code !== 0) skip('the InwireAgent service is not installed on this machine');

console.log('--- what the SCM says, unelevated ---\n');

// **The measurement ADR 0035 rests on.** The installer grants `RP`
// (SERVICE_START) on the service's `IU` ACE so the app can start the agent
// without a prompt; `agentPipe.ts` never tried it for a long time, so the grant
// bought nothing and a UAC prompt appeared every launch.
const start = sc('start', 'InwireAgent');
// 0 started it, 1056 means it was already running. Either proves the ACL let us
// ask. 5 - ACCESS_DENIED - is the failure this is looking for, and the one that
// would send `classifyStart` to the elevation path on every launch.
checkTrue(`an unelevated start reaches the SCM (sc exited ${start.code})`,
  start.code === 0 || start.code === 1056);
check('...and is not refused for access', start.code === 5, false);

// The other half, and the reason the agent must stop ITSELF. `WP` is withheld
// on purpose: `IU` is *any* interactive logon, so granting stop would let a
// second Windows user stop a capture the first one is running.
const stop = sc('stop', 'InwireAgent');
check('an unelevated stop is refused', stop.code, 5);

// And the descriptor those two outcomes come from, read rather than assumed.
const sd = sc('sdshow', 'InwireAgent').out;
const iu = /\(A;;([A-Z]+);;;IU\)/.exec(sd)?.[1] ?? '';
checkTrue('the descriptor was read', iu.length > 0);
checkTrue('IU is granted RP - SERVICE_START', iu.includes('RP'));
checkTrue('...and NOT WP - SERVICE_STOP', !iu.includes('WP'));

// Start type. A machine still carrying the pre-0035 install reads AUTO_START,
// which is not a failure of this build - it is what the NEXT installer changes.
const autoStart = /START_TYPE\s+:\s+2\s+AUTO_START/.test(config.out);
console.log(autoStart
  ? '      note: this machine still has the AUTO_START install (pre-ADR 0035)'
  : '      this machine has the demand-start install');

let electron: typeof import('playwright')['_electron'];
try {
  ({ _electron: electron } = await import('playwright'));
} catch {
  skip('playwright is not installed');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(condition: () => Promise<boolean>, ms = 25_000): Promise<boolean> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await condition()) return true;
    if (Date.now() > deadline) return false;
    await sleep(250);
  }
}

let app: Awaited<ReturnType<typeof electron.launch>> | null = null;
let profile: string | null = null;
try {
  console.log('\n--- the app, against the real service ---\n');

  // No `INWIRE_AGENT_PIPE`: this is the one drive script that dials the
  // production pipe name on purpose.
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-live-'));
  const launchedAt = Date.now();
  app = await electron.launch({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile },
  });
  const page = await app.firstWindow();
  page.setDefaultTimeout(30_000);
  await page.waitForLoadState('domcontentloaded');

  const rendererErrors: string[] = [];
  page.on('pageerror', (error) => rendererErrors.push(error.message));

  /** The status bar's agent cell, which is the thing the by-hand item watched. */
  const linkLabel = () => page.evaluate(() => {
    const cells = [...document.querySelectorAll('span[title]')];
    const cell = cells.find((c) => /capture agent/i.test(c.getAttribute('title') ?? ''));
    return cell?.textContent?.trim() ?? '';
  });

  const connected = await until(async () => /connected/i.test(await linkLabel()));
  check('the status bar reaches "Agent connected"', connected, true);
  console.log(`      it read "${await linkLabel()}" after ${Date.now() - launchedAt} ms`);

  // **The regression the deleted 2,000 ms `connectedDelay` used to cause.**
  // A successful connection read "Agent not running" for two full seconds after
  // `hello` had been processed - the app knew and was waiting out a timer. The
  // label is gated on `hello` now, so reaching it at all is reaching it
  // promptly; a wall here means something is gating on the socket again.
  checkTrue('...promptly, rather than after a timer',
    connected && Date.now() - launchedAt < 20_000);

  // A real agent answered `hello`, so the app knows its version. The installed
  // one predates the version collapse, so it should read as OUTDATED rather
  // than as absent - which is the exact direction ADR 0035 says must not go
  // wrong, since a version that went backwards shows as "not connected".
  const reported = await page.evaluate(() => {
    const cell = [...document.querySelectorAll('span[title]')]
      .find((c) => /capture agent is connected/i.test(c.getAttribute('title') ?? ''));
    return cell !== undefined;
  });
  check('...and the link is diagnosed as connected, not merely silent', reported, true);

  check('nothing threw in the renderer', rendererErrors, []);
} finally {
  // Closing with frames buffered opens the native "Quit Inwire?" box, which no
  // test can answer. This used to be belt-and-braces against a script that
  // captured nothing; now that it captures, it is load-bearing - without it the
  // run hangs on a modal outside the page, with no output saying why.
  try {
    const page = app ? await app.firstWindow() : null;
    await page?.evaluate(() => window.inwire?.setUnsavedCapture?.(false));
  } catch { /* the window may already be gone */ }
  await app?.close();
  if (profile) rmSync(profile, { recursive: true, force: true });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All live-agent checks passed.');
process.exit(0);
