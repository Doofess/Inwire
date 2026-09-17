/**
 * The app, launched and driven, end to end.
 *
 *   npm run build && npx tsx scripts/electron/smoke.ts
 *
 * ## Why this exists
 *
 * Three of the worst bugs in the Electron migration were invisible to every
 * one of the assertion scripts beside this one, and all three were found by
 * hand in a running app:
 *
 *   - maplibre resolved its worker URL to `""` under `app://` and loaded
 *     `index.html` as a module worker. The map reported nothing; tiles stayed
 *     `loading` forever.
 *   - `node:os` in the sandboxed preload made the preload throw while loading,
 *     so `exposeInMainWorld` never ran and `window.inwire` was `undefined`.
 *     No store, no agent, no save dialog, nothing in any console.
 *   - COEP on the document blocked `pipeline.worker` - no dissection at all -
 *     because a worker script must carry the header itself.
 *
 * Every one type-checked and bundled cleanly. They are runtime facts about
 * Chromium and Electron, and the only thing that observes those is a running
 * app. That is this file's whole job.
 *
 * ## What it drives
 *
 * A real Electron process over a real named pipe against `stubAgent.ts`, which
 * speaks the production protocol. It picks an adapter, starts a capture, waits
 * for rows, and reads the Info column - so a pass means bytes went from a
 * socket through main, a MessagePort, the pipeline Worker, the dissector and
 * React onto the screen.
 *
 * ## What it is not
 *
 * Not a UI test. It asserts nothing about layout, colour or wording beyond the
 * one dissected string it can predict exactly. Everything visual stays with a
 * person looking at it.
 */
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
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
  // Exit 0. `scripts/check.ts` treats a non-zero exit as a failure, and a
  // machine without the build output has not failed anything.
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

if (process.platform !== 'win32') {
  // The transport is a named pipe and the app is Windows-only. `stubAgent`
  // would serve a Unix socket happily; the app would not dial one.
  skip('the desktop app is Windows-only - nothing to launch here');
}
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}

// Which build is being tested, and how old it is.
//
// The hazard this addresses is a pass that means nothing: `npm run check` does
// not build, so a stale `dist/` tests code that is no longer there and reports
// success. Printing the age does not prevent it - nothing cheap does - but it
// puts the fact in front of whoever reads the output.
{
  const built = statSync(path.join('dist-electron', 'main.cjs')).mtime;
  const minutes = Math.round((Date.now() - built.getTime()) / 60_000);
  const age = minutes < 60 ? `${minutes} min` : `${Math.round(minutes / 60)} h`;
  console.log(`      testing the build from ${built.toISOString()} (${age} old)`);
  if (minutes > 120) {
    console.log('      NOTE: that build is over two hours old - `npm run build` if it should not be');
  }
}

let electron: typeof import('playwright')['_electron'];
try {
  ({ _electron: electron } = await import('playwright'));
} catch {
  skip('playwright is not installed');
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Clicks something, and says whether it was there rather than throwing.
 *
 * A locator that times out throws a Playwright error out of the whole script,
 * which prints a stack trace from inside Playwright and no `FAIL` line. The
 * useful output is "this control was not there", named.
 */
async function clicks(what: string, act: () => Promise<void>): Promise<boolean> {
  try {
    await act();
    return true;
  } catch (error) {
    console.log(`        could not click ${what}: `
      + `${error instanceof Error ? error.message.split('\n')[0] : String(error)}`);
    return false;
  }
}

/** Polls until true or the budget runs out. Returns whether it got there. */
async function until(condition: () => Promise<boolean>, ms = 20_000): Promise<boolean> {
  const deadline = Date.now() + ms;
  for (;;) {
    if (await condition()) return true;
    if (Date.now() > deadline) return false;
    await sleep(200);
  }
}

let agent: StubAgent | null = null;
let profile: string | null = null;
let app: Awaited<ReturnType<typeof electron.launch>> | null = null;
/**
 * Hoisted out of the try, because the cleanup below has to talk to it.
 *
 * Not called `window`: that shadows the global the `page.evaluate` callbacks
 * below are written against, and every one of them silently starts reading
 * this Playwright handle instead of the page's own `window`.
 */
let mainWindow: Awaited<ReturnType<Awaited<ReturnType<typeof electron.launch>>['firstWindow']>> | null = null;

try {
  try {
    agent = await startStubAgent();
  } catch (error) {
    // Almost always a `serveStub.ts` left running from driving the app by
    // hand. The raw `EADDRINUSE` stack out of `node:net` says none of that,
    // and inside `npm run check` it appears as a bare FAIL with a page of
    // Playwright-adjacent noise - which cost an afternoon of thinking a real
    // regression had landed.
    if ((error as NodeJS.ErrnoException)?.code === 'EADDRINUSE') {
      skip('something else is already serving \\\\.\\pipe\\inwire-agent - '
        + 'stop `serveStub.ts`, or the InwireAgent service, and run this again');
    }
    throw error;
  }
  console.log('--- launching ---\n');

  // A profile of its own, and this is load-bearing rather than tidy. The app
  // PRUNES its capture directory at startup, so a test launched against the
  // real profile deletes whatever capture the developer had stored - every
  // time `npm run check` runs. `main.ts` honours `INWIRE_USER_DATA` for
  // exactly this.
  profile = mkdtempSync(path.join(tmpdir(), 'inwire-smoke-'));
  app = await electron.launch({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile },
  });

  const page = await app.firstWindow();
  mainWindow = page;

  // Playwright's default action timeout is **none**, and `_electron.launch`
  // has no config file to set one. So a locator that never matches - a button
  // that did not render, an adapter list that stayed empty - waits for ever,
  // and `npm run check` stops rather than failing. This ran clean, then hung
  // twice on a slower boot with no output at all, which is the worst possible
  // shape for a test: a suite that never finishes tells you less than one that
  // fails.
  page.setDefaultTimeout(30_000);

  await page.waitForLoadState('domcontentloaded');

  // Collected from here on. A page error is a thrown exception the app did not
  // catch, which is the shape three of the four bugs above took.
  const pageErrors: string[] = [];
  const consoleErrors: string[] = [];
  const failedRequests: string[] = [];
  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text());
  });
  page.on('requestfailed', (request) => {
    failedRequests.push(`${request.failure()?.errorText ?? '?'} ${request.url()}`);
  });

  check('the window serves itself from app://',
    new URL(page.url()).protocol, 'app:');

  console.log('\n--- the things that fail silently ---\n');

  // The preload. `undefined` here is the `node:os` bug and every one like it:
  // no store, no agent link, no save dialog, and nothing in any log.
  const bridge = await page.evaluate(() => ({
    present: typeof window.inwire,
    save: typeof window.inwire?.saveFile,
    agentPort: typeof window.inwire?.requestAgentPort,
    storePort: typeof window.inwire?.requestCaptureStorePort,
    // The window's own four. It is frameless, so without `windowControl` there
    // is no way to close it short of Alt+F4 - and these fail the same silent
    // way the rest of this object exists to catch: the preload throws while
    // loading, `window.inwire` is undefined, and nothing says so.
    windowTheme: typeof window.inwire?.setWindowTheme,
    windowControl: typeof window.inwire?.windowControl,
    windowTitle: typeof window.inwire?.setWindowTitle,
    windowState: typeof window.inwire?.onWindowState,
  }));
  check('the preload bridge is exposed', bridge, {
    present: 'object', save: 'function', agentPort: 'function', storePort: 'function',
    windowTheme: 'function', windowControl: 'function', windowTitle: 'function',
    windowState: 'function',
  });

  // Cross-origin isolation, which nothing depends on yet - so this is the
  // assertion that has to exist BEFORE anything does.
  check('the renderer is cross-origin isolated',
    await page.evaluate(() => crossOriginIsolated), true);

  console.log('\n--- a capture, end to end ---\n');

  // The agent is reached over the pipe; the app should be connected without
  // anyone asking it to be.
  checkTrue('the app connected to the agent and said hello back',
    await until(async () => agent!.received.length > 0));

  // Pick an adapter. The label is shortened by `shortInterfaceLabel`, which
  // splits on the first " (" - so "Ethernet (stub)" is offered as "Ethernet".
  //
  // Each click is reported rather than thrown, so a control that never appears
  // names itself instead of taking the suite down with a stack trace from
  // inside Playwright.
  checkTrue('the interface picker opens',
    await clicks('the Interfaces button',
      () => page.getByRole('button', { name: 'Interfaces' }).click()));
  checkTrue('an adapter can be chosen',
    await clicks('the stub adapter',
      () => page.getByText('Ethernet', { exact: true }).first().click()));
  checkTrue('choosing an adapter reaches the agent',
    await until(async () => agent!.received.some((m) => m.includes('set_interfaces'))));

  checkTrue('Start can be pressed',
    await clicks('Start capture', () => page.getByLabel('Start capture').click()));
  checkTrue('Start reaches the agent',
    await until(async () => agent!.received.some((m) => m.includes('start_capture'))));

  // The whole point. Frames left the stub, crossed the pipe, crossed main,
  // crossed a MessagePort into the Worker, were dissected, and reached React.
  //
  // Read through `[data-packet-counts]`, not by matching a label in
  // `document.body.innerText`. It matched `PACKETS:`, which this readout
  // rendered while it was a dock widget and stopped rendering when it became
  // the title row's - so the match found nothing, this returned `'0'`, and the
  // assertion below failed as "frames arrive and are counted", pointing at the
  // pipe and the Worker rather than at its own locator.
  const rows = () => page.evaluate(
    () => document.querySelector('[data-packet-counts]')?.textContent?.match(/([\d,]+)/)?.[1] ?? '0');
  checkTrue('frames arrive and are counted',
    await until(async () => Number((await rows()).replace(/,/g, '')) > 100));

  // Dissected, not merely counted. The stub sends a DNS query it built byte by
  // byte, so the Info column is predictable exactly.
  const info = await page.evaluate(
    () => document.body.innerText.match(/Standard query 0x[0-9a-f]{4} A example\.com/)?.[0] ?? null);
  checkTrue('...and are dissected, not just counted', info !== null);
  if (info) console.log(`      Info column reads: ${info}`);

  // The map's worker. `setWorkerUrl` must run before `setRTLTextPlugin`, and
  // when it does not the worker dies before registering a handler and maplibre
  // says nothing at all - so the canvas existing is not evidence and the
  // absence of a failed request for the worker script is.
  console.log('\n--- what the run turned up ---\n');
  check('no request failed', failedRequests, []);
  check('nothing threw', pageErrors, []);
  // Console errors are reported rather than asserted: a third-party tile
  // server being unreachable on a build machine is not this app's failure.
  if (consoleErrors.length > 0) {
    console.log(`      ${consoleErrors.length} console error(s), not asserted:`);
    for (const error of consoleErrors.slice(0, 5)) console.log(`        ${error.slice(0, 140)}`);
  } else {
    console.log('      no console errors');
  }
} finally {
  // Closing with frames in the buffer opens `guardClose`'s native "Quit
  // Inwire?" message box, and a native modal is not in the page: Playwright
  // cannot see it, cannot answer it, and `app.close()` waits for ever - with
  // the output buffered, so the script looks busy long after its last
  // assertion. That is what used to hang this.
  //
  // So the test says what is true - this capture is about to be deleted with
  // its temporary profile - through the same bridge the app uses, and then
  // closes properly. Killing the process instead was tried and is worse:
  // `kill()` reaches the main process and leaves the GPU, renderer, store and
  // crashpad children running, five orphans per run.
  await mainWindow?.evaluate(() => window.inwire?.setUnsavedCapture?.(false))
    .catch(() => { /* the app may already be gone */ });
  await app?.close().catch(() => { /* likewise */ });
  await agent?.close();
  // A temp directory that outlives the run is untidy, not a failure - and
  // throwing here would replace a clean pass with a stack trace.
  try {
    if (profile) rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  } catch {
    console.log(`      note: could not remove the temporary profile at ${profile}`);
  }
}

console.log(failures === 0
  ? '\nAll smoke checks passed.'
  : `\n${failures} smoke check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
