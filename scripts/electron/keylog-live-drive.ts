/**
 * Live decryption with the key log the page holds and the shards read in
 * place (ADR 0073).
 *
 *   npm run build && npx tsx scripts/electron/keylog-live-drive.ts [--app <dir>]
 *
 * The key-log fixture's frames are streamed through the stub agent as a live
 * capture, with the fixture's `.keys` followed from a fresh profile the way a
 * browser's `SSLKEYLOGFILE` is. Its HTTP/2 and HTTP/3 exist only decrypted, so
 * the display filter `http2 || http3` counts frames the app could open, and
 * that count must equal what the dissector finds in process with the same keys:
 * at one thread (the Worker reads the page's store) and at Auto (every shard
 * does, and the shards are started after the key log loaded). With no key log
 * followed the count must be 0, or the check does not discriminate.
 *
 * And once with the keys appended to the followed file after Start, while the
 * stub holds its frames: the shards are running by then and have adopted the
 * page's buffer, so the lines reach them with no message (Review Focus 1).
 *
 * Not in `npm run check` (`check.ts`'s NOT_TESTS): it needs a build and the
 * private key-log fixture, and skips cleanly without the fixture.
 */
import { appendFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { arrive, FIXTURES } from '../pipeline/arrival';
import { compile } from '../../src/services/filter/compile';
import { keyLog, KeyLogStore } from '../../src/services/tls/keyLog';
import { launchApp } from './launchApp';
import { startStubAgent } from './stubAgent';

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const APP = arg('app', '');
const FILTER = 'http2 || http3';
const PER_TICK = 100;

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) console.log(`        expected ${JSON.stringify(expected)}\n        actual   ${JSON.stringify(actual)}`);
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

const fixture = FIXTURES.find((f) => f.name === 'keyLog')!;
const keysPath = fixture.path.replace(/\.pcapng$/, '.keys');
if (!existsSync(fixture.path) || !existsSync(keysPath)) {
  console.log(`SKIP  the key-log fixture or its .keys is not present (${fixture.path}); see test/fixtures/README.md`);
  process.exit(0);
}

// The expected answer, in process: the same frames, the same keys, the same filter.
keyLog.clear();
keyLog.add(readFileSync(keysPath, 'latin1'));
const secrets = keyLog.stats().secrets;
const { arrived } = await arrive(fixture.path);
keyLog.clear();
if (arrived.some((a) => a.input.linktype !== 1)) {
  console.log('SKIP  the key-log fixture is not all Ethernet frames, which is all the stub agent sends');
  process.exit(0);
}
const matches = compile(FILTER);
const expected = arrived.filter((a) => matches(a.packet)).length;
const frames = arrived.map((a) => a.input.bytes);
console.log(`fixture: ${frames.length.toLocaleString()} frames, ${expected.toLocaleString()} match "${FILTER}" in process; ` +
  `key log ${secrets.toLocaleString()} secrets`);

/**
 * `before`: the fixture's keys followed from launch. `after`: an empty file
 * followed, the keys appended once the capture has started and the stub is
 * holding its frames. `none`: no key log.
 */
async function live(label: string, threads: 'auto' | number, keys: 'before' | 'after' | 'none'): Promise<number> {
  console.log(`\n--- ${label} ---\n`);
  const pipe = `\\\\.\\pipe\\inwire-keylog-live-${process.pid}-${label.replace(/\W+/g, '-')}`;
  const agent = await startStubAgent(pipe, keys === 'after' ? 0 : PER_TICK, frames);
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-keylog-live-'));
  // A copy of the fixture's keys, in the throwaway profile, removed with it.
  const followed = keys === 'after' ? path.join(profile, 'sslkeylog.txt') : path.resolve(keysPath);
  if (keys === 'after') writeFileSync(followed, '');
  if (keys !== 'none') writeFileSync(path.join(profile, 'keylog.json'), JSON.stringify({ path: followed }));
  const app = await launchApp({
    args: ['.'],
    ...(APP ? { cwd: APP } : {}),
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: pipe, INWIRE_CRASH_ANSWER: 'quit' },
  });
  let shown = -1;
  try {
    const page = await app.firstWindow();
    page.setDefaultTimeout(30_000);
    await page.evaluate('window.__name = (f) => f');
    await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
    await page.evaluate((count) => {
      localStorage.setItem('inwire.tour', JSON.stringify({ completed: true }));
      localStorage.setItem('inwire.performance', JSON.stringify({ dashboardRefreshMs: 500, packetBufferBytes: 'auto', dissectionThreads: count }));
    }, threads);
    await page.reload();
    await page.evaluate('window.__name = (f) => f');
    await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
    await page.getByRole('button', { name: 'Skip' }).click({ timeout: 2000 }).catch(() => {});

    // The key log is loaded before the first frame, as a browser's is before
    // the connections it opens.
    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await page.getByRole('button', { name: 'Decryption' }).first().click();
    const counted = (n: number) => page.waitForFunction((m) =>
      Number(document.querySelector('[data-keylog-secrets]')?.getAttribute('data-keylog-secrets') ?? -1) === m,
    n, { timeout: 20_000 }).then(() => true, () => false);
    const want = keys === 'before' ? secrets : 0;
    checkTrue(`${label}: the panel counts ${want} secrets before the capture`, await counted(want));
    await page.keyboard.press('Escape');

    await page.getByRole('button', { name: 'Interfaces' }).click();
    await page.getByText('Ethernet', { exact: true }).first().click();
    await page.keyboard.press('Escape');
    await page.getByLabel('Start capture').click();
    if (keys === 'after') {
      // The shards exist now and hold the page's (empty) buffer. The lines go
      // into it in place; nothing tells the shards.
      await sleep(1500);
      appendFileSync(followed, readFileSync(keysPath));
      await page.getByRole('button', { name: 'Settings', exact: true }).click();
      await page.getByRole('button', { name: 'Decryption' }).first().click();
      checkTrue(`${label}: the panel counts ${secrets} secrets after the append`, await counted(secrets));
      await page.keyboard.press('Escape');
      agent.setPerTick(PER_TICK);
    }
    const total = () => page.evaluate(() => {
      const text = document.querySelector('[data-packet-counts]')?.textContent ?? '';
      const m = text.match(/\/\s*([\d,]+)/) ?? text.match(/([\d,]+)/);
      return m ? Number(m[1].replace(/,/g, '')) : 0;
    });
    const until = Date.now() + 120_000;
    while (Date.now() < until && (agent.sent() < frames.length || (await total()) < frames.length)) await sleep(250);
    check(`${label}: every frame arrived`, await total(), frames.length);
    await page.getByLabel('Stop capture').first().click();

    const input = page.getByPlaceholder('e.g. tcp.port == 443');
    await input.click();
    await input.fill(FILTER);
    await input.press('Enter');
    // Done is a shown count that has held still for two seconds.
    let last = -2;
    let steadySince = Date.now();
    const filterUntil = Date.now() + 60_000;
    while (Date.now() < filterUntil) {
      const now = await page.evaluate(() => {
        const m = (document.querySelector('[data-packet-counts]')?.textContent ?? '').match(/([\d,]+)\s*\//);
        return m ? Number(m[1].replace(/,/g, '')) : -1;
      });
      if (now !== last) { last = now; steadySince = Date.now(); }
      if (now >= 0 && Date.now() - steadySince > 2000) break;
      await sleep(250);
    }
    shown = last;
    console.log(`      "${FILTER}" shows ${shown.toLocaleString()} of ${frames.length.toLocaleString()}`);
    await page.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (b: boolean) => void } })
      .inwire?.setUnsavedCapture?.(false)).catch(() => {});
  } finally {
    await app.close().catch(() => {});
    await agent.close();
    rmSync(profile, { recursive: true, force: true });
  }
  return shown;
}

checkTrue('the fixture has frames to decrypt at all', expected > 0);
{
  // The appended run proves "with no message" only if the keys fit the empty
  // table: a growth would post a snapshot, and the run would test that path.
  const probe = new KeyLogStore();
  probe.share();
  let snapshots = 0;
  probe.onSnapshot(() => { snapshots++; });
  probe.add(readFileSync(keysPath, 'latin1'));
  check('the fixture\'s keys fit an empty table, so the append posts no snapshot', snapshots, 0);
}
check('threads 1: live decrypts the same frames as in process', await live('one thread', 1, 'before'), expected);
check('threads auto: live decrypts the same frames as in process', await live('auto threads', 'auto', 'before'), expected);
check('threads auto, keys appended after Start: the running shards read them with no message',
  await live('auto threads, appended after Start', 'auto', 'after'), expected);
check('with no key log followed, none decrypt (the check discriminates)', await live('no key log', 1, 'none'), 0);

console.log(failures === 0 ? '\nAll live key-log checks passed.' : `\n${failures} live key-log check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
