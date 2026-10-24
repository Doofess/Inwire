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
import {
  closeSync, existsSync, mkdtempSync, openSync, rmSync, statSync, writeFileSync, writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { startStubAgent, type StubAgent } from './stubAgent';
import { launchApp } from './launchApp';

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

try {
  await import('playwright');
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

/**
 * The URL the CSP probe asks for, which the policy must refuse.
 *
 * Declared here because two places need it and they must not drift: the probe
 * itself, and the `requestfailed` filter - a request this run makes ON PURPOSE
 * so that it will be blocked is not a failure, and without the exclusion the
 * probe would fail the "no request failed" check it has nothing to do with.
 *
 * `example.com` because RFC 2606 reserves it for exactly this and it can never
 * become somebody's real host. Nothing is sent: `default-src 'none'` refuses it
 * before a connection is opened, which is also why this works on a machine with
 * no outbound route at all.
 */
const CSP_PROBE_URL = 'https://example.com/inwire-csp-probe.png';

let agent: StubAgent | null = null;
let profile: string | null = null;
/** The key log this run seeds into its profile and then appends to. */
let keyLogFile: string | null = null;

/**
 * One well-formed key log line for a made-up connection.
 *
 * Nothing here decrypts anything - the stub sends DNS - so the values mean
 * nothing. What is under test is that lines reach the app, counted by the
 * Decryption panel, and a line has to be well-formed for `keyLog.add` to count
 * it: 64 hex characters of client random, a known label.
 */
const keyLogLine = (random: string) =>
  `CLIENT_TRAFFIC_SECRET_0 ${random.repeat(32)} ${'ee'.repeat(32)}`;
let app: Awaited<ReturnType<typeof launchApp>> | null = null;
/** Everything main wrote to stdout and stderr. */
let mainOutput = '';
/**
 * Hoisted out of the try, because the cleanup below has to talk to it.
 *
 * Not called `window`: that shadows the global the `page.evaluate` callbacks
 * below are written against, and every one of them silently starts reading
 * this Playwright handle instead of the page's own `window`.
 */
let mainWindow: Awaited<ReturnType<Awaited<ReturnType<typeof launchApp>>['firstWindow']>> | null = null;

/**
 * A pipe of this run's own, rather than the name the installed service holds.
 *
 * This is what stopped the smoke test being a SKIP on the one machine it most
 * needed to run on. A development machine has the real `InwireAgent` service
 * installed, the service owns `\\.\pipe\inwire-agent`, and a stub that cannot
 * bind it had nothing honest to do but skip - so the script that exists to
 * catch the three bugs nothing else here can catch was silently not running.
 *
 * The pid makes it unique, so two checks at once do not collide either.
 */
const SMOKE_PIPE = `\\\\.\\pipe\\inwire-smoke-${process.pid}`;

try {
  try {
    agent = await startStubAgent(SMOKE_PIPE);
  } catch (error) {
    // Almost always a `serveStub.ts` left running from driving the app by
    // hand. The raw `EADDRINUSE` stack out of `node:net` says none of that,
    // and inside `npm run check` it appears as a bare FAIL with a page of
    // Playwright-adjacent noise - which cost an afternoon of thinking a real
    // regression had landed.
    if ((error as NodeJS.ErrnoException)?.code === 'EADDRINUSE') {
      // Now genuinely unexpected: the name carries this process's own pid, so
      // nothing else should ever hold it. Kept because the raw `EADDRINUSE`
      // stack out of `node:net` names nothing, and a bare FAIL with a page of
      // Playwright-adjacent noise once cost an afternoon of thinking a real
      // regression had landed.
      skip(`something else is already serving ${SMOKE_PIPE}, which should be impossible`);
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
  // A key log the app was told to follow in an earlier session - written the
  // way `electron/keyLogFollower.ts` writes it, before the app starts, so the
  // launch has to pick it up from disk with nobody clicking anything. That is
  // the "remember the path" half; the section near the end appends to the file
  // and is the "follow it" half.
  keyLogFile = path.join(profile, 'sslkeylog.txt');
  writeFileSync(keyLogFile, `${keyLogLine('a1')}\n`);
  writeFileSync(path.join(profile, 'keylog.json'), JSON.stringify({ path: keyLogFile }));
  const launchedAt = Date.now();
  app = await launchApp({
    args: ['.'],
    // `INWIRE_AGENT_PIPE` points the app at this run's stub instead of the
    // installed service's pipe - the other half of the SKIP this deleted.
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: SMOKE_PIPE },
  });

  // Main's own output, for the crashed-renderer section at the end.
  app.process().stdout?.on('data', (chunk) => { mainOutput += String(chunk); });
  app.process().stderr?.on('data', (chunk) => { mainOutput += String(chunk); });
  const page = await app.firstWindow();
  mainWindow = page;
  /**
   * How long the app took to put something on screen.
   *
   * A MEASUREMENT, never a gate, and the distinction is ADR 0021's: a launch
   * time is a property of this machine - its disk, its antivirus, whether the
   * profile is warm - so a ceiling on it would fail for reasons that have
   * nothing to do with the build. `scripts/perf/bundle-size.ts` is the gate,
   * because a byte count is a property of the build and is the same everywhere.
   *
   * Printed because nothing else in this repository could see startup at all,
   * and every argument about it was therefore an argument rather than a number.
   * Read it against another run on the same machine, not against this comment.
   */
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  const domReadyMs = Date.now() - launchedAt;
  /*
   * A background launch (launchApp's default) is parked off-screen, not hidden,
   * and must have kept the size it was created with: a DPI rescale on the move
   * would show up as a changed size between two reads, or as bounds that no
   * longer match the restored (normal) bounds.
   */
  const readBounds = () => app!.evaluate(({ BrowserWindow }) => {
    const w = BrowserWindow.getAllWindows()[0]!;
    return { b: w.getBounds(), n: w.getNormalBounds(), focused: w.isFocused() };
  });
  // Parking happens on `ready-to-show`, which can follow DOMContentLoaded.
  let parked = await readBounds();
  for (let i = 0; i < 40 && parked.b.x !== -20000; i++) { await sleep(250); parked = await readBounds(); }
  await sleep(500);
  const parkedLater = await readBounds();
  check('background window is parked off-screen', [parked.b.x, parked.b.y], [-20000, -20000]);
  check('background window never took focus', parked.focused || parkedLater.focused, false);
  check('parked window keeps its requested size', [parked.b.width, parked.b.height], [parked.n.width, parked.n.height]);
  check('parked window size is stable (no DPI rescale)',
    [parkedLater.b.width, parkedLater.b.height], [parked.b.width, parked.b.height]);
  /*
   * To the first thing a person can see, not just to a document. React mounting
   * is downstream of the whole entry chunk parsing and executing, so this is
   * the number that would move if the bundle were the cost.
   *
   * **A function predicate, never a string.** `waitForFunction` given a string
   * builds its polling predicate with `eval` INSIDE the page, and this app's
   * production CSP is `script-src 'self' 'unsafe-inline'` with no
   * 'unsafe-eval' - so the string form throws `EvalError` on the first poll.
   * The first version of this used a string behind a `.catch(() => {})`, which
   * swallowed that and reported a number ~215 ms above the document time that
   * was Playwright retrying a forbidden eval rather than React mounting. A
   * measurement that silently measures something else is worse than none.
   *
   * The `catch` is gone with it: a predicate that cannot run should fail the
   * run, not quietly publish a different number.
   */
  await page.waitForFunction(() => {
    const root = document.getElementById('root');
    return !!root && root.childElementCount > 0;
  }, undefined, { timeout: 30_000 });
  console.log(`      document in ${domReadyMs} ms, first painted UI in `
    + `${Date.now() - launchedAt} ms `
    + '(measurements, not budgets: this machine, not this build)');

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
    // A request this run deliberately aborted is not a failure. See
    // OUTBOUND_BLOCKED below for why they are aborted at all.
    if (OUTBOUND_BLOCKED.some((host) => request.url().includes(host))) return;
    // The CSP probe's own request. Being refused IS the assertion.
    if (request.url() === CSP_PROBE_URL) return;
    failedRequests.push(`${request.failure()?.errorText ?? '?'} ${request.url()}`);
  });

  // **Every host `electron/csp.ts` lets the renderer reach, refused here.**
  //
  // The geo section below turns location lookup on, which is consent this app
  // asks a person for - and a suite that grants it on every `npm run check`
  // would make the build machine dial four third parties to test a React
  // render. Aborting them keeps `npm run check` offline, which is the product
  // invariant, and costs the test nothing: the bug it exists for throws before
  // a single request is made.
  const OUTBOUND_BLOCKED = [
    'get.geojs.io', 'ipapi.co', 'tiles.openfreemap.org', 'cloudflare-dns.com',
  ];
  await page.route('**/*', async (route) => {
    if (OUTBOUND_BLOCKED.some((host) => route.request().url().includes(host))) {
      await route.abort();
      return;
    }
    await route.continue();
  });

  check('the window serves itself from app://',
    new URL(page.url()).protocol, 'app:');

  console.log('\n--- the things that fail silently ---\n');

  // The preload. `undefined` here is the `node:os` bug and every one like it:
  // no store, no agent link, no save dialog, and nothing in any log.
  const bridge = await page.evaluate(() => ({
    present: typeof window.inwire,
    save: typeof window.inwire?.saveFile,
    saveStreamOpen: typeof window.inwire?.openSaveStream,
    saveStreamWrite: typeof window.inwire?.writeSaveStream,
    saveStreamClose: typeof window.inwire?.closeSaveStream,
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
    present: 'object', save: 'function',
    saveStreamOpen: 'function', saveStreamWrite: 'function', saveStreamClose: 'function',
    agentPort: 'function', storePort: 'function',
    windowTheme: 'function', windowControl: 'function', windowTitle: 'function',
    windowState: 'function',
  });

  // Cross-origin isolation, which nothing depends on yet - so this is the
  // assertion that has to exist BEFORE anything does.
  check('the renderer is cross-origin isolated',
    await page.evaluate(() => crossOriginIsolated), true);

  /**
   * The CSP is not merely correct, it is actually APPLIED.
   *
   * `scripts/electron/shell.ts` asserts what the policy SAYS. Nothing asserted
   * that it reaches the document, and the failure mode is silent in the worst
   * direction: a policy that stops being applied removes a restriction, so
   * every other check in this file keeps passing and the app keeps working.
   * This check exists because `onHeadersReceived` gained a URL filter, and if
   * Electron had not matched `app://` against it the policy would have vanished
   * with nothing to notice.
   *
   * **The probe has to be one the PAGE performs.** Two obvious tests do not
   * work and both were tried:
   *
   * - `page.evaluate(() => eval('1+1'))` runs through CDP's `Runtime.evaluate`,
   *   which is exempt from page CSP. It reported `eval` running with the policy
   *   correctly applied, which reads exactly like a missing CSP.
   * - `fetch()` to a blocked host fails with `TypeError: Failed to fetch`,
   *   which is also what a machine with no outbound route says. Indistinguishable.
   *
   * An `<img>` the page appends is loaded by the browser under the page's own
   * policy, and `securitypolicyviolation` fires only for a policy refusal - a
   * network error raises `error` instead. So the event is decisive where the
   * other two are not, and `default-src 'none'` with no `img-src` means any
   * origin at all is a violation, with no request made and no network needed.
   */
  /*
   * Passed as a STRING, and that is not a style choice.
   *
   * `tsx` transforms this file with esbuild's `keepNames` on, which wraps every
   * named function - including a `const done = () => ...` inside a callback -
   * in `__name(fn, "done")`. Playwright serialises the callback's source and
   * evaluates it in the PAGE, where no `__name` exists, so the probe died with
   * `ReferenceError: __name is not defined` before it could test anything. A
   * string is never transformed. (The same helper charged 152 ms to `quic.ts`
   * in `scripts/perf/profile.ts`; it is worth knowing it has two ways to bite.)
   */
  const CSP_PROBE = `new Promise((resolve) => {
    let settled = false;
    document.addEventListener('securitypolicyviolation', (event) => {
      if (settled) return;
      settled = true;
      resolve('enforced:' + event.violatedDirective);
    }, { once: true });
    const probe = document.createElement('img');
    probe.onerror = () => setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve('not enforced: the load failed with no violation');
    }, 400);
    probe.onload = () => {
      if (settled) return;
      settled = true;
      resolve('not enforced: the image loaded');
    };
    probe.src = '${CSP_PROBE_URL}';
    probe.style.display = 'none';
    document.body.appendChild(probe);
    setTimeout(() => {
      if (settled) return;
      settled = true;
      resolve('inconclusive: nothing fired');
    }, 5000);
  })`;
  check('the content security policy is actually enforced on the document',
    await page.evaluate(CSP_PROBE), 'enforced:img-src');

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

  /*
   * **The Frame layer names the adapter, on the EAGER path.**
   *
   * The interface rows were wrong for every live capture -
   * `Interface description: Imported capture` - and this is deliberately only
   * half the check for it. Which half is worth stating, because the obvious
   * reading of these three assertions is wrong:
   *
   * The Worker keeps the tree it built during ingest for the newest
   * `DETAIL_CACHE_FRAMES` (4,000) frames. This run has a few thousand, and the
   * row clicked below is a recent one, so the tree drawn is that cached eager
   * tree and **nothing is replayed**. These assertions therefore prove the
   * live ingest path labels a frame correctly - which is worth proving and is
   * not where the bug was. Verified by reintroducing it: all three still pass.
   *
   * The replay half is the block after these, which pushes the capture past
   * the cache and opens the oldest row.
   *
   * The stub's adapter is the device name `\Device\NPF_{STUB-0}` under the
   * label `Ethernet (stub)`, so both rows are predictable exactly.
   */
  /*
   * **Scrolled up first, as a person reading a live capture does, and on a
   * renderer slowed twentyfold.**
   *
   * The list follows the tail while the capture runs: every flush, ten a
   * second, scrolls it and swaps the rows under the pointer. Playwright clicks
   * only an element that holds still across two animation frames, so on a
   * loaded machine - a game running beside the suite, seen - frames come
   * slower than flushes, every row detaches before it settles, and the click
   * timed out on four checks that had nothing wrong with them. A covered
   * window is NOT the cause: run under a full-screen window, this passed.
   *
   * So the test does what a reader does - a wheel gesture upward, which in
   * the default `reading` follow mode stops the tail - and checks that the
   * list then holds still, which is the behaviour being relied on. The
   * slowdown is Chromium's own CPU throttle, around this block only, so
   * every run proves the click on the machine it was failing on.
   */
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: 20 });
  const listCentre = await page.evaluate(() => {
    const scroller = [...document.querySelectorAll('div')].find(
      (d) => d.scrollHeight > d.clientHeight + 200 && d.querySelector('[role="row"]'));
    const box = scroller?.getBoundingClientRect();
    return box ? { x: box.x + box.width / 2, y: box.y + box.height / 2 } : null;
  });
  if (listCentre) {
    // Raw mouse input, which waits for nothing - unlike hover(), which would
    // wait on the same moving row this block exists to avoid.
    await page.mouse.move(listCentre.x, listCentre.y);
    await page.mouse.wheel(0, -400);
  }
  await sleep(500);
  const firstRowId = () => page.locator('[role="row"]').nth(1).evaluate((row) => row.id).catch(() => '');
  const before = await firstRowId();
  await sleep(1_000);
  const after = await firstRowId();
  const heldStill = before !== '' && before === after;
  checkTrue('scrolling up stops the live list following the tail', heldStill);
  if (!heldStill) console.log(`        the first row was ${before || 'missing'}, then ${after || 'missing'}`);
  checkTrue('a frame can be selected', await clicks('the first packet row',
    () => page.locator('[role="row"]').nth(1).click()));
  await cdp.send('Emulation.setCPUThrottlingRate', { rate: 1 });
  const frameLayer = await until(async () => (await page.evaluate(
    () => document.body.innerText)).includes('Interface description:'), 10_000);
  checkTrue('...and its tree is drawn', frameLayer);
  const tree = await page.evaluate(() => document.body.innerText);
  // Named as the thing it must NOT say, because that is the defect: an
  // assertion that only checked for the label would pass on a tree that
  // happened to contain it somewhere else.
  check('the live frame is not described as an imported capture',
    tree.includes('Imported capture'), false);
  // Whitespace-collapsed, because the tree draws a row's name and its value as
  // two elements: `innerText` puts them on separate lines, so a match on
  // "Interface description: Ethernet (stub)" finds nothing while the row reads
  // exactly that on screen. The negative check above does not need this - a
  // substring of one element is still a substring of the page.
  const flat = tree.replace(/\s+/g, ' ');
  checkTrue('...it names the adapter the capture is running on',
    flat.includes('Interface description: Ethernet (stub)'));
  checkTrue('...and the device name beside it',
    flat.includes(String.raw`Interface name: \Device\NPF_{STUB-0}`));

  /*
   * **And on the REPLAY path, which is where the bug actually was.**
   *
   * The three assertions above read a cached eager tree and pass with the bug
   * in. What a person sees for any frame older than the Worker's
   * `DETAIL_CACHE_FRAMES` (4,000) is a tree rebuilt by `dissectReplay`, and
   * that is the path which passed `undefined` as the capture interface.
   *
   * So the capture is pushed past the cache and the OLDEST row is opened. The
   * stub runs at its gentle default for everything above, because that is
   * what exercises the ordering window and the flush; only now is it raised,
   * so this costs about two seconds on a five-second run rather than ten.
   *
   * The wait is on `Frame <n>:` for the row actually clicked, not on
   * `Interface description:` - the tree above is still on screen until the
   * new one lands, and waiting on a string both trees contain would read the
   * old one and pass.
   */
  const PAST_THE_CACHE = 5_000;
  agent!.setPerTick(400);
  checkTrue(`the capture passes the ${PAST_THE_CACHE.toLocaleString()}-frame mark`,
    await until(async () => Number((await rows()).replace(/,/g, '')) > PAST_THE_CACHE));
  agent!.setPerTick(40);
  // **Stopped before scrolling, and that is what makes the next four lines
  // deterministic.** With the capture still running, the list's follow-the-tail
  // autoscroll can land between setting `scrollTop` and the scroll event that
  // would have disarmed it - so the list snaps back to the bottom, the row
  // under the click is a recent frame, and the wait for `Frame 2:` times out.
  // Seen once in five runs before this line existed. It is also the order a
  // person does it in: stop, scroll back, open something old.
  checkTrue('the capture can be stopped', await clicks('Stop capture',
    () => page.getByLabel('Stop capture').click()));
  await sleep(300);
  // Scrolled to the top the way `disk-drive.ts` does it.
  await page.evaluate(() => {
    const scroller = [...document.querySelectorAll('div')].find(
      (d) => d.scrollHeight > d.clientHeight + 200 && d.querySelector('[role="row"]'));
    if (scroller) scroller.scrollTop = 0;
  });
  await sleep(500);
  const oldest = page.locator('[role="row"]').nth(1);
  // The first CELL, not the row's text: a row's `textContent` runs its cells
  // together with no separator, so frame 2 followed by a Time of `0.000000`
  // reads as "20.000000" and a leading-digits match answers 20. That sent the
  // wait below looking for a `Frame 20:` that was never going to be drawn.
  const oldestId = Number(await oldest.evaluate(
    (row) => row.firstElementChild?.textContent?.trim() ?? '').catch(() => '-1'));
  checkTrue(`the oldest row is a frame the tree cache has dropped (frame ${oldestId})`,
    oldestId > 0 && oldestId < 100);
  checkTrue('...and it can be selected', await clicks('the oldest row', () => oldest.click()));
  const rebuilt = await until(async () => (await page.evaluate(
    () => document.body.innerText)).includes(`Frame ${oldestId}:`), 15_000);
  checkTrue('...and its tree is rebuilt and drawn', rebuilt);
  const replayed = (await page.evaluate(() => document.body.innerText)).replace(/\s+/g, ' ');
  if (!rebuilt) {
    // Said, not guessed at: which frame the pane is actually showing, and
    // which row the list thinks is selected. A wait that times out with no
    // account of what it found instead is how the first version of this block
    // spent an hour looking for a `Frame 20:` that the parsing had invented.
    const header = replayed.match(/Frame \d+: \d+ bytes on wire/)?.[0] ?? 'no Frame header at all';
    const selected = await page.evaluate(() =>
      document.querySelector('[role="row"][aria-selected="true"]')?.firstElementChild?.textContent ?? 'none');
    console.log(`        the pane shows "${header}"; the selected row is frame ${selected}`);
  }
  // **Gated on `rebuilt`, because without it these pass on the wrong tree.**
  // If the replayed tree never lands, the pane is still showing the RECENT
  // frame selected above - a cached eager tree whose interface rows are
  // right - so all three would pass having tested nothing. Seen: a timeout on
  // the line above, followed by three PASSes.
  check('a REPLAYED live frame is not described as an imported capture',
    rebuilt && !replayed.includes('Imported capture'), true);
  checkTrue('...it names the adapter',
    rebuilt && replayed.includes('Interface description: Ethernet (stub)'));
  checkTrue('...and the device name',
    rebuilt && replayed.includes(String.raw`Interface name: \Device\NPF_{STUB-0}`));

  // **Turning location lookup on, which once took the whole window with it.**
  //
  // `GeoMap` returns early when the setting is off, and two `useMemo` calls sat
  // below that return - 45 hooks off, 47 hooks on. React throws error #310 when
  // the count grows, and the throw unmounts the tree, so the window went black
  // on the one click the off state exists to invite.
  //
  // Nothing here could see it. This script never turned the setting on, and
  // `gpu-restore-drive.ts` - the only other script that reaches this component
  // - skips outright when no map is on screen, which it is until geo-IP has
  // been consented to. A test that does not enable the feature beside a test
  // that requires it already enabled is a gap, and this closes it.
  //
  // The assertion is that the tree is still mounted. `pageErrors` below would
  // catch the throw too, but "nothing threw" names the symptom of every bug in
  // this file; an empty `#root` names this one.
  console.log('\n--- the setting that unmounted the app ---\n');
  checkTrue('the map pane opens',
    await clicks('Routing Map', () => page.getByRole('button', { name: 'Routing Map' }).click()));
  const geoButton = page.getByRole('button', { name: /Turn on location lookup/i });
  // **The pane is lazy now, so this locator has to retry.** `GeoMap` sits
  // behind `React.lazy` with a launch-time warm (`geoMapLoader.tsx`), so the
  // click above commits a Suspense fallback and the pane's own first render is
  // at least one tick later. `isVisible()` does **not** retry - it is a
  // snapshot - so it answered `false` against a chunk that was already in the
  // module registry, and the branch below then reported a race as "the button
  // is not on screen". Every other locator in this file gets Playwright's
  // 30-second retry; this one was the exception and had no reason to be.
  const paneAt = Date.now();
  const paneShown = await geoButton.waitFor({ state: 'visible' }).then(() => true).catch(() => false);
  if (paneShown) {
    // A measurement, not a budget (ADR 0021), and it is the number that says
    // whether the warm is doing its job: a warmed chunk makes this React's
    // commit, an unwarmed one adds an `app://` fetch and a 1.5 MB parse.
    console.log(`      map pane on screen ${Date.now() - paneAt} ms after the click`);
    checkTrue('location lookup can be turned on',
      await clicks('Turn on location lookup', () => geoButton.click()));
    // Long enough for the render that used to throw. The lookups it would
    // normally fire are aborted, so nothing here waits on a network.
    await page.waitForTimeout(2_000);
    check('...and the app is still mounted',
      await page.evaluate(() => document.getElementById('root')?.childElementCount ?? -1) > 0, true);
  } else {
    // Not a pass. The button is the only way into the branch under test, and a
    // run that never found it has tested nothing while looking like it did.
    check('the "Turn on location lookup" button is on screen', false, true);
  }

  /*
   * **A followed key log: remembered across launches, and read as it grows.**
   *
   * Live decryption did not work, and the reason was not the decryptor: the key
   * log was taken through a file picker, which reads a snapshot, and a browser
   * appends each connection's secrets the moment it starts that connection. A
   * snapshot taken before a capture holds nothing for any connection in it. The
   * fix is main following the file - and remembering which one, so it resumes
   * at launch - which is two claims, and this checks both through the real app:
   *
   * - the path seeded into the profile BEFORE launch is being followed, with
   *   its one line loaded, and nobody clicked anything;
   * - two lines appended while the app runs arrive without a click either.
   */
  console.log('\n--- the key log it was told to follow last time ---\n');
  checkTrue('Settings opens', await clicks('Settings',
    () => page.getByRole('button', { name: 'Settings', exact: true }).click()));
  checkTrue('...on its Decryption section', await clicks('Decryption',
    () => page.getByRole('button', { name: 'Decryption' }).first().click()));
  const followState = () => page.evaluate(
    () => document.querySelector('[data-keylog-follow]')?.getAttribute('data-keylog-follow') ?? 'absent');
  const secretsShown = () => page.evaluate(
    () => Number(document.querySelector('[data-keylog-secrets]')?.getAttribute('data-keylog-secrets') ?? -1));
  checkTrue('the remembered key log is being followed at launch',
    await until(async () => (await followState()) === 'following', 10_000));
  checkTrue('...and its line was loaded without a click',
    await until(async () => (await secretsShown()) === 1, 10_000));
  // Timed, because the latency is the whole question for live traffic. A
  // secret has to reach the Worker before the packets it opens are dissected,
  // and the Worker's 100 ms ordering window is the only slack there is.
  // A function predicate polled per frame: `until`'s 200 ms step would hide
  // the number, and a string predicate is an `eval` this app's CSP refuses
  // (ADR 0041's broken measurement). Printed, never asserted - it is this
  // machine's disk and scheduler, not the build's.
  //
  // Written the way a browser writes: through a handle held open, not
  // `appendFileSync`. On Windows a write through an open handle raises no
  // `fs.watch` event, so an open-append-close here was timing the watcher -
  // 3-11 ms - while every real browser was being seen by the one-second poll,
  // and live QUIC lost each connection's first burst to it.
  const writer = openSync(keyLogFile!, 'a');
  const appendedAt = Date.now();
  writeSync(writer, `${keyLogLine('b2')}\n${keyLogLine('c3')}\n`);
  const grew = await page.waitForFunction(
    () => document.querySelector('[data-keylog-secrets]')?.getAttribute('data-keylog-secrets') === '3',
    undefined, { polling: 'raf', timeout: 10_000 },
  ).then(() => true, () => false);
  const followMs = Date.now() - appendedAt;
  closeSync(writer);
  checkTrue('lines appended while it runs are picked up as they are written', grew);
  if (grew) {
    console.log(`      appended to the file -> counted in the panel: ${followMs} ms`
      + ' (a measurement: the Worker gets it one postMessage after this)');
  } else {
    console.log(`        the panel shows ${await secretsShown()} secret(s), expected 3`);
  }
  // Back out, so the remaining checks see the workspace rather than the sheet.
  await page.getByRole('button', { name: 'Settings', exact: true }).click().catch(() => {});

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

  // Last, because the page does not come back. A renderer that crashed leaves
  // its window and webContents alive, and every send to it made Electron log
  // "Render frame was disposed" - the key log's 25 ms poll once per write, the
  // window state once per focus change - while nothing said the page had died.
  console.log('\n--- after the renderer crashes ---\n');
  // Cleared first: with frames buffered, the close below would ask, and a
  // dead page cannot answer, so the OS's box would wait for ever.
  await page.evaluate(() => window.inwire?.setUnsavedCapture?.(false));
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].webContents.forcefullyCrashRenderer());
  const crashWriter = openSync(keyLogFile!, 'a');
  for (let i = 0; i < 20; i++) {
    writeSync(crashWriter, `${keyLogLine((i + 16).toString(16))}\n`);
    await new Promise((resolve) => setTimeout(resolve, 2 * 25));
  }
  closeSync(crashWriter);
  await app.evaluate(({ BrowserWindow }) => { BrowserWindow.getAllWindows()[0].emit('blur'); });
  await new Promise((resolve) => setTimeout(resolve, 200));
  check('main sends nothing to a crashed page',
    (mainOutput.match(/Render frame was disposed/g) ?? []).length, 0);
  checkTrue('main says the renderer is gone, and why', /\[renderer\] gone: \w+/.test(mainOutput));
} finally {
  // Closing with frames in the buffer opens the "Quit Inwire?" confirm - the
  // page's own dialog, or the OS's box when the page does not answer within a
  // second, which Playwright cannot see or answer - and `app.close()` waits
  // for ever on either - with
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
