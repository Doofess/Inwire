/**
 * The Update Center against a real feed, in the real app.
 *
 *   npm run build && npx tsx scripts/electron/update-center-drive.ts
 *
 * `update-center.ts` proves every decision without a network or a machine.
 * This proves the parts that only exist when there is both: that `net.fetch`
 * in main reaches a feed, that the manifest survives the round trip, that the
 * registry read finds the Npcap actually installed here, and that the snapshot
 * arrives over IPC in a shape the renderer accepts.
 *
 * It stands up an HTTP server on a loopback port and points `INWIRE_UPDATE_FEED`
 * at it, so the feed is real without anything being published. The manifest it
 * serves is **built from this machine's own installed version**, which is what
 * lets the central assertion be exact rather than approximate: told the
 * version it has, the Npcap row must read `up-to-date`, and told one digit
 * more it must read `update-available`. That pair is the whole `wpcap.dll`
 * trap - a build that reads the libpcap version instead fails the first half
 * on any machine with Npcap on it.
 *
 * In `NOT_TESTS`: it needs `dist/`, a loopback port and about a minute, and on
 * a machine with no Npcap at all it can only check the failure direction. Run
 * it by hand after anything on the update path.
 *
 * It never installs anything. Nothing here raises a UAC prompt - pressing
 * Update is the one step that stays with a person, and it is the last item on
 * the verification list in CLAUDE.md.
 */
import { createServer, type Server } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { _electron as electron, type ElectronApplication, type Page } from 'playwright';
import { normalizeSnapshot, type UpdateSnapshot } from '../../src/services/updateCenter';

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

/** The body the server answers with, swapped between checks. */
let body = '';

function manifest(npcapVersion: string): string {
  return JSON.stringify({
    schema: 1,
    generated: new Date().toISOString(),
    components: {
      npcap: {
        version: npcapVersion,
        kind: 'vendor-installer',
        minAppVersion: '1.0.0',
        // The real URL. Nothing here downloads it, but the manifest is held to
        // the same host allowlist a published one would be, so a rule that
        // rejected npcap.com would fail here rather than in front of a user.
        url: `https://npcap.com/dist/npcap-${npcapVersion}.exe`,
        sha256: 'a95577ebbc67fc45b319e2ef3a55f4e9b211fe82ed4cb9d8be6b1a9e2425ce53',
        size: 1320424,
      },
    },
  });
}

/** One digit more than what is installed, without assuming the shape. */
function bumped(version: string): string {
  const parts = version.split('.');
  parts[parts.length - 1] = String(Number.parseInt(parts[parts.length - 1] ?? '0', 10) + 1);
  return parts.join('.');
}

let app: ElectronApplication | undefined;
let page: Page | undefined;
let server: Server | undefined;
let profile: string | undefined;

try {
  server = createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(body);
  });
  const listening = server;
  await new Promise<void>((resolve) => listening.listen(0, '127.0.0.1', resolve));
  const port = (listening.address() as { port: number }).port;
  const feed = `http://127.0.0.1:${port}/manifest.json`;
  console.log(`--- serving a feed at ${feed} ---\n`);

  profile = mkdtempSync(path.join(tmpdir(), 'inwire-updates-'));
  app = await electron.launch({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_UPDATE_FEED: feed },
  });
  page = await app.firstWindow();
  page.setDefaultTimeout(30_000);
  await page.waitForLoadState('domcontentloaded');
  await page.waitForTimeout(2500);

  const driven = page;
  const state = async (): Promise<UpdateSnapshot> => {
    const raw = await driven.evaluate(() => window.inwire?.getUpdateState?.());
    const snapshot = normalizeSnapshot(raw);
    if (snapshot === null) throw new Error('main sent a snapshot the renderer will not accept');
    return snapshot;
  };
  const recheck = () => driven.evaluate(() => window.inwire?.checkForUpdates?.());
  const npcap = (snapshot: UpdateSnapshot) =>
    snapshot.components.find((component) => component.id === 'npcap');

  console.log('--- what is on this machine ---\n');

  const initial = await state();
  const installed = npcap(initial)?.installed ?? null;
  console.log(`      this machine has Npcap ${installed ?? '(none)'}`);

  checkTrue('the snapshot survives IPC in a shape the renderer accepts',
    initial.components.length > 0);
  check('nothing is claimed before a check has happened', initial.lastChecked, null);
  check('...and no row pretends to be up to date', npcap(initial)?.state.kind, 'unknown');

  if (installed === null) {
    console.log('\n      Npcap is not installed here, so the version pair cannot be driven.');
  } else {
    console.log('\n--- told exactly what is installed ---\n');
    body = manifest(installed);
    await recheck();
    const same = await state();

    // The `wpcap.dll` trap, and the only place a running machine can catch it.
    // A build that read the libpcap version would compare 1.10.6 against the
    // installed 1.88 and answer `update-available` here, for ever.
    check('the installed version reads as up to date', npcap(same)?.state.kind, 'up-to-date');
    checkTrue('a check that reached the feed is recorded', same.lastChecked !== null);

    console.log('\n--- told there is one more ---\n');
    const newer = bumped(installed);
    body = manifest(newer);
    await recheck();
    const offered = await state();
    check('a newer version is offered', npcap(offered)?.state.kind, 'update-available');
    check('...and named', npcap(offered)?.available?.version, newer);
    check('...from npcap.com and nowhere else',
      new URL(npcap(offered)?.available?.url ?? 'https://x.invalid').hostname, 'npcap.com');

    console.log('\n--- told nonsense ---\n');
    const before = offered.lastChecked;
    body = '{ this is not json';
    await recheck();
    const garbled = await state();

    // A feed we cannot read is a feed we have no answer from. Treating it as
    // "no updates available" would be a confident lie, and clearing the rows
    // would throw away an answer that was true when it arrived.
    check('a malformed feed changes nothing', npcap(garbled)?.state.kind, 'update-available');
    check('...and does not count as a check', garbled.lastChecked, before);

    console.log('\n--- and then nothing at all ---\n');
    await new Promise<void>((resolve) => listening.close(() => resolve()));
    server = undefined;
    await recheck();
    const offline = await state();
    check('an unreachable feed changes nothing', npcap(offline)?.state.kind, 'update-available');
    check('...and does not move "last checked"', offline.lastChecked, before);
  }

  console.log('\n--- and the panel renders it ---\n');

  // The fresh profile opens the first-run tour over everything.
  await driven.getByRole('button', { name: 'Skip' }).first().click().catch(() => {});
  await driven.waitForTimeout(500);
  await driven.keyboard.press('Control+k');
  await driven.waitForTimeout(500);
  await driven.getByText('Settings', { exact: true }).first().click();
  await driven.waitForTimeout(800);
  await driven.getByRole('button', { name: 'Updates' }).click();
  await driven.waitForTimeout(800);

  const labels = await driven.locator('button').evaluateAll(
    (nodes) => nodes.map((node) => (node.textContent ?? '').trim()),
  );
  checkTrue('the Updates section exists in Settings', labels.includes('Updates'));
  checkTrue('Check now is offered', labels.includes('Check now'));
  checkTrue('the one-time consent prompt is shown on a fresh profile',
    labels.includes('Check automatically') && labels.includes('Only when I ask'));

  const text = await driven.locator('body').innerText();
  checkTrue('the driver row names Npcap', text.includes('Npcap capture driver'));

  // The bug a screenshot found: the agent reports its version over the pipe,
  // so before it connects there is no version - and the row said "Not
  // installed" about a service that was installed and running.
  checkTrue('no row claims something absent that is only unheard-from',
    !text.includes('Capture agent\nNot installed'));
} catch (error) {
  if ((error as NodeJS.ErrnoException)?.code === 'ENOENT') {
    skip('the app is not built - run `npm run build` first');
  }
  failures++;
  console.log('FAIL  the run itself');
  console.log(`        ${error instanceof Error ? error.message : String(error)}`);
} finally {
  // Cleared before closing: with frames in the buffer, `guardClose` opens a
  // native "Quit Inwire?" box that is not in the page and no test can answer.
  await page?.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
  await app?.close().catch(() => {});
  server?.close();
  if (profile !== undefined) rmSync(profile, { recursive: true, force: true });
}

console.log(failures === 0
  ? '\nAll update center drive checks passed.'
  : `\n${failures} update center drive check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
