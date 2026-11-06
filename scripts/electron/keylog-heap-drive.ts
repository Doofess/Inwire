/**
 * A big followed key log, in the real app: the crash of 2026-11-05 (ADR 0073).
 *
 *   npm run build && npx tsx scripts/electron/keylog-heap-drive.ts [--app <dir>] [--connections N]
 *
 * The owner's browser had written 217 MB of `SSLKEYLOGFILE` since September.
 * Main sent all of it at launch, and the page, the pipeline Worker and every
 * shard each parsed a copy into one ~4 GB heap: the renderer died with
 * -36861 eight seconds after the window opened, every launch, with nothing
 * clicked. This writes a synthetic log of the same shape and size (random hex,
 * a temp file, deleted after), follows it from a fresh profile the way the
 * owner's was, starts a capture on the stub so the shards run, and asserts the
 * window lives, counts every secret, and holds them once.
 *
 * "Once" is measured against the same run following an empty file, because
 * the renderer's own cost moves with the thread count (419 MB at Auto, 643 MB
 * at 16, before any key log). The key log's share is checked twice: its peak,
 * which carries the load's transient, and what is left after a GC in the page
 * and every Worker. The second is needed because an idle shard allocates
 * nothing and so never collects the buffers growth retired; left alone it holds
 * about twice the table until it next does, which a GC tells apart from a copy.
 *
 * Then the cap, through main's test hook: `INWIRE_KEYLOG_CAP_BYTES` at 64 MiB
 * against the same file must load only its newest 64 MiB and say so.
 *
 * `--app` launches another checkout's build, to watch the old code fail.
 * `--keylog <file>` follows a real log in place instead (the owner's, for the
 * gate), checks the count against this process's own, and prints only counts.
 * Not in `npm run check` (`check.ts`'s NOT_TESTS): it needs a build, writes
 * ~215 MB and takes a few minutes.
 */
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { KeyLogStore } from '../../src/services/tls/keyLog';
import { launchApp } from './launchApp';
import { startStubAgent } from './stubAgent';
import { writeSyntheticKeyLog } from './syntheticKeyLog';

const arg = (name: string, fallback: string): string => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const APP = arg('app', '');
const CONNECTIONS = Number(arg('connections', '260000'));
/** A real key log to follow instead of the synthetic one. Only counts are printed, never a line. */
const KEYLOG = arg('keylog', '');
const MIB = 1024 * 1024;
const CAP = 64 * MIB;
const ALIVE_MS = 30_000;

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) console.log(`        expected ${JSON.stringify(expected)}\n        actual   ${JSON.stringify(actual)}`);
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
// Playwright throws outside any awaited promise when its target dies under it;
// the renderer's death is read from main's log instead.
process.on('uncaughtException', (error) => console.log(`(playwright: ${String(error).split('\n')[0]})`));

interface Run {
  alive: boolean;
  secrets: number;
  skipped: number;
  rendererPrivateMB: number;
  /** The last sample taken while the renderer lived, near 30 s. */
  rendererPrivateEndMB: number;
  /** One sample a second from the launch, MB, for where a peak falls. */
  timeline: number[];
  /** Workers Playwright saw at the end: the evidence the thread count took. */
  workers: number;
  /**
   * After a forced GC in the page and every Worker: what is held rather than
   * waiting to be collected. An idle shard allocates nothing, so it never
   * collects the buffers growth retired; on its own it would hold them.
   */
  rendererPrivateHeldMB: number;
  pageHeapMB: number;
  /** Launch to every secret counted in the panel; -1 when never. */
  loadedMs: number;
}

/**
 * Writes the thread count and a finished tour into a fresh profile from a
 * launch that follows nothing, so the measured launch follows the key log from
 * its first page and never reloads, as the owner's did. Setting them in the
 * measured launch took a reload, and the first page's half-done load was still
 * in the renderer while the second ran: a peak no real launch has.
 */
async function primeProfile(profile: string, threads: 'auto' | number): Promise<void> {
  const app = await launchApp({
    args: ['.'],
    ...(APP ? { cwd: APP } : {}),
    // A pipe nobody serves: this launch only writes settings.
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: `\\\\.\\pipe\\inwire-keylog-prime-${process.pid}`, INWIRE_CRASH_ANSWER: 'quit' },
  });
  try {
    const page = await app.firstWindow();
    page.setDefaultTimeout(30_000);
    await page.evaluate('window.__name = (f) => f');
    await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
    await page.evaluate((count) => {
      localStorage.setItem('inwire.tour', JSON.stringify({ completed: true }));
      localStorage.setItem('inwire.performance', JSON.stringify({ dashboardRefreshMs: 500, packetBufferBytes: 'auto', dissectionThreads: count }));
    }, threads);
  } finally {
    await app.close().catch(() => {});
  }
}

async function run(label: string, keyLogFile: string, expectSecrets: number, threads: 'auto' | number,
  env: Record<string, string> = {}): Promise<Run> {
  console.log(`\n--- ${label} ---\n`);
  const pipe = `\\\\.\\pipe\\inwire-keylog-heap-${process.pid}-${label.replace(/\W+/g, '-')}`;
  const agent = await startStubAgent(pipe, 40);
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-keylog-heap-'));
  await primeProfile(profile, threads);
  writeFileSync(path.join(profile, 'keylog.json'), JSON.stringify({ path: keyLogFile }));
  const result: Run = {
    alive: false, secrets: -1, skipped: -1, rendererPrivateMB: -1, rendererPrivateEndMB: -1, timeline: [], workers: -1,
    rendererPrivateHeldMB: -1, pageHeapMB: -1, loadedMs: -1,
  };
  const tabMB = async (): Promise<number> => {
    const metrics = await app.evaluate(({ app: electronApp }) => electronApp.getAppMetrics()
      .map((m) => ({ type: m.type, privateKb: m.memory.privateBytes ?? 0 })));
    const tab = metrics.find((m) => m.type === 'Tab');
    return tab ? Math.round(tab.privateKb / 1024) : -1;
  };
  const launched = Date.now();
  const app = await launchApp({
    args: ['--js-flags=--expose-gc', '.'],
    ...(APP ? { cwd: APP } : {}),
    env: { ...process.env, ...env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: pipe, INWIRE_CRASH_ANSWER: 'quit' },
  });
  let log = '';
  app.process().stdout?.on('data', (d) => { log += String(d); });
  app.process().stderr?.on('data', (d) => { log += String(d); });
  const gone = () => /\[renderer\] gone/.test(log);
  // The renderer's peak, not its state at 30 s: the old code died on the way
  // up. Only samples taken while it lived count; after a crash the Tab is the
  // crash page.
  let sampling = true;
  const sampler = setInterval(() => {
    void tabMB().then((mb) => {
      if (gone() || !sampling || mb < 0) return;
      result.rendererPrivateMB = Math.max(result.rendererPrivateMB, mb);
      result.rendererPrivateEndMB = mb;
      result.timeline.push(mb);
    }).catch(() => {});
  }, 1000);
  try {
    const page = await app.firstWindow();
    page.setDefaultTimeout(30_000);
    await page.evaluate('window.__name = (f) => f');
    await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
    await page.getByRole('button', { name: 'Skip' }).click({ timeout: 2000 }).catch(() => {});

    // A capture, so the Worker starts its shards: they are what held the copies.
    await page.getByRole('button', { name: 'Interfaces' }).click();
    await page.getByText('Ethernet', { exact: true }).first().click();
    await page.keyboard.press('Escape');
    await page.getByLabel('Start capture').click();

    await page.getByRole('button', { name: 'Settings', exact: true }).click();
    await page.getByRole('button', { name: 'Decryption' }).first().click();
    const read = () => page.evaluate(() => ({
      secrets: Number(document.querySelector('[data-keylog-secrets]')?.getAttribute('data-keylog-secrets') ?? -1),
      skipped: Number(document.querySelector('[data-keylog-skipped]')?.getAttribute('data-keylog-skipped') ?? -1),
    }));
    // Without a count to wait for (the capped run), done is a count that has
    // held still for three seconds.
    let steadySince = Date.now();
    while (Date.now() - launched < 120_000 && !gone()) {
      const now = await read().catch(() => ({ secrets: -1, skipped: -1 }));
      if (now.secrets !== result.secrets) steadySince = Date.now();
      result.secrets = now.secrets;
      result.skipped = now.skipped;
      // At least, not equal: a real log a browser is writing can grow mid-run.
      const done = expectSecrets >= 0 ? now.secrets >= expectSecrets
        : now.secrets > 0 && Date.now() - steadySince > 3000;
      if (done) { result.loadedMs = Date.now() - launched; break; }
      await sleep(250);
    }
    while (Date.now() - launched < ALIVE_MS && !gone()) await sleep(500);
    result.pageHeapMB = Math.round(await page.evaluate(() => {
      const collect = (globalThis as unknown as { gc?: () => void }).gc;
      collect?.(); collect?.();
      return (performance as unknown as { memory: { usedJSHeapSize: number } }).memory.usedJSHeapSize;
    }).catch(() => -MIB) / MIB);
    // The timeline ends here; what follows is forced and would read as a drop.
    sampling = false;
    const workers = page.workers();
    result.workers = workers.length;
    let collected = 0;
    for (const worker of workers) {
      const ran = await worker.evaluate(() => {
        const collect = (globalThis as unknown as { gc?: () => void }).gc;
        collect?.(); collect?.();
        return collect !== undefined;
      }).catch(() => false);
      if (ran) collected++;
    }
    await page.evaluate(() => { (globalThis as unknown as { gc?: () => void }).gc?.(); }).catch(() => {});
    await sleep(3000);
    result.rendererPrivateHeldMB = gone() ? -1 : await tabMB().catch(() => -1);
    result.alive = !gone() && result.pageHeapMB >= 0;
    console.log(`      ${threads} threads: secrets ${result.secrets.toLocaleString()} (all counted at ${result.loadedMs} ms), ` +
      `skipped ${result.skipped.toLocaleString()} B, renderer peak ${result.rendererPrivateMB} MB private ` +
      `(${result.rendererPrivateEndMB} MB at ${ALIVE_MS / 1000} s, ${result.rendererPrivateHeldMB} MB after a GC in the page ` +
      `and ${collected} of ${workers.length} Workers), page heap ${result.pageHeapMB} MB`);
    console.log(`      private MB, a sample a second: ${result.timeline.join(' ')}`);
    await page.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (b: boolean) => void } })
      .inwire?.setUnsavedCapture?.(false)).catch(() => {});
  } catch (error) {
    // The old build's window dies mid-step; that is the result, not an error.
    console.log(`      (drive: ${String(error).split('\n')[0]})`);
    result.alive = false;
  } finally {
    clearInterval(sampler);
    if (gone()) console.log(`      main said: ${log.split('\n').filter((l) => /gone/.test(l)).join(' | ')}`);
    await app.close().catch(() => {});
    await agent.close();
    rmSync(profile, { recursive: true, force: true });
  }
  return result;
}

/**
 * The secrets the store accepts from the file as it is now, and the size of
 * the table that holds them, counted in this process. Reserved for the file's
 * length first, as the app's follower now does before its read from the top.
 */
function tableOf(file: string): { secrets: number; tableMB: number } {
  const store = new KeyLogStore();
  const text = readFileSync(file, 'latin1');
  store.reserve(text.length);
  store.add(text);
  return { secrets: store.stats().secrets, tableMB: Math.round(store.share().buffer.byteLength / MIB) };
}

/**
 * The key log's share of the renderer: a run following it less the same run
 * following an empty file, so what the renderer costs at that thread count
 * with no key log (643 MB peak at 16 threads, 419 at Auto, measured) is not
 * charged to it. The peak carries the load's transient; the held figure is
 * after a GC of every context, which is what a copy per shard would raise.
 */
interface Share { peakMB: number; endMB: number; heldMB: number }
const shareOf = (r: Run, empty: Run): Share => ({
  peakMB: r.rendererPrivateMB - empty.rendererPrivateMB,
  endMB: r.rendererPrivateEndMB - empty.rendererPrivateEndMB,
  heldMB: r.rendererPrivateHeldMB - empty.rendererPrivateHeldMB,
});

const dir = mkdtempSync(path.join(tmpdir(), 'inwire-keylog-synthetic-'));
const emptyFile = path.join(dir, 'empty.txt');
writeFileSync(emptyFile, '');

/**
 * Alive, every secret, and the key log held once: the checks for one thread
 * count. `sized` adds the pre-sizing ceilings (ADR 0073, amendment 2026-11-06),
 * measured on the synthetic log only: the table moves once, so the peak stays
 * near the table and no retired buffer waits in an idle shard. Before it, the
 * peak was +384 MB on a 107 MB table and the 30 s share sat 228 MB above the
 * held one.
 */
function checkShare(label: string, r: Run, empty: Run, tableMB: number, sized: boolean): Share {
  const share = shareOf(r, empty);
  const measured = r.alive && empty.alive && r.rendererPrivateHeldMB >= 0 && empty.rendererPrivateHeldMB >= 0
    && r.rendererPrivateEndMB >= 0 && empty.rendererPrivateEndMB >= 0;
  console.log(`      the key log's share: peak +${share.peakMB} MB, at ${ALIVE_MS / 1000} s +${share.endMB} MB, held +${share.heldMB} MB; its table is ${tableMB} MB; ` +
    `the renderer's peak ${r.rendererPrivateMB} MB, held ${r.rendererPrivateHeldMB} MB (empty: ${empty.rendererPrivateMB}, ${empty.rendererPrivateHeldMB})`);
  // A dead renderer's numbers are the crash page's: they count only alive.
  if (sized) {
    checkTrue(`${label}: the key log's peak share of the renderer's private bytes is under 2.25 times its table (${Math.round(2.25 * tableMB)} MB)`,
      measured && share.peakMB < 2.25 * tableMB);
    checkTrue(`${label}: ...and its share at ${ALIVE_MS / 1000} s is within a quarter of its table of what a GC leaves (${Math.round(tableMB / 4)} MB): no retired buffers`,
      measured && share.endMB - share.heldMB < tableMB / 4);
  } else {
    checkTrue(`${label}: the key log's peak share of the renderer's private bytes is under 1,024 MB`,
      measured && share.peakMB < 1024);
  }
  checkTrue(`${label}: ...and what it holds after a GC is under twice its table (${2 * tableMB} MB)`,
    measured && share.heldMB < 2 * tableMB);
  checkTrue(`${label}: ...and the page's usedJSHeapSize is under 512 MB`, r.alive && r.pageHeapMB >= 0 && r.pageHeapMB < 512);
  return share;
}

if (KEYLOG) {
  // The owner's own file, followed in place: a browser may append while this
  // runs, so the app's count must sit between a count before and one after.
  try {
    const before = tableOf(KEYLOG);
    console.log(`key log: ${before.secrets.toLocaleString()} secrets, ${Math.round(statSync(KEYLOG).size / MIB)} MB`);
    const empty = await run('an empty key log at auto threads', emptyFile, 0, 'auto');
    const r = await run('following the given key log at auto threads', KEYLOG, before.secrets, 'auto');
    const after = tableOf(KEYLOG);
    checkTrue(`real log: the renderer is alive ${ALIVE_MS / 1000} s after the launch`, r.alive);
    checkTrue(`real log: Decryption shows the secrets an in-process store counts (${before.secrets.toLocaleString()} to ${after.secrets.toLocaleString()})`,
      r.secrets >= before.secrets && r.secrets <= after.secrets);
    checkShare('real log', r, empty, after.tableMB, false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  console.log(failures === 0 ? '\nAll key-log heap checks passed.' : `\n${failures} key-log heap check(s) FAILED.`);
  process.exit(failures === 0 ? 0 : 1);
}

const file = path.join(dir, 'sslkeylog.txt');
try {
  const made = await writeSyntheticKeyLog(file, CONNECTIONS);
  const { tableMB } = tableOf(file);
  console.log(`synthetic key log: ${made.lines.toLocaleString()} lines, ${Math.round(made.bytes / MIB)} MB, ` +
    `a ${tableMB} MB table${APP ? `; app ${APP}` : ''}`);

  const shares: Partial<Record<'auto' | 16, Share>> = {};
  const workers: Partial<Record<'auto' | 16, number>> = {};
  for (const threads of ['auto', 16] as const) {
    const empty = await run(`an empty key log at ${threads} threads`, emptyFile, 0, threads);
    const r = await run(`following it at ${threads} threads`, file, made.lines, threads);
    checkTrue(`${threads}: the renderer is alive ${ALIVE_MS / 1000} s after the launch`, r.alive);
    check(`${threads}: Decryption shows every secret`, r.secrets, made.lines);
    shares[threads] = checkShare(String(threads), r, empty, tableMB, true);
    workers[threads] = r.workers;
  }
  // The setting is written by a launch before the measured one; a profile
  // that lost it would run both at the default and compare nothing.
  checkTrue(`16 threads ran more Workers than Auto (${workers[16]} against ${workers.auto}): the setting took`,
    (workers[16] ?? -1) > (workers.auto ?? -1) && (workers.auto ?? -1) > 2);
  // The shards read the page's buffer: ten more of them hold nothing more. A
  // compact copy each would add a table apiece.
  const auto = shares.auto;
  const sixteen = shares[16];
  checkTrue('16 threads hold no more of the key log than Auto (within 64 MB)',
    auto !== undefined && sixteen !== undefined && Math.abs(sixteen.heldMB - auto.heldMB) < 64);

  // The cap. Lines are all much the same length, so the newest 64 MiB holds
  // about that share of them; 1% covers the TLS 1.2 lines being longer.
  const expectCapped = Math.round(made.lines * CAP / made.bytes);
  const capped = await run('the cap, at 64 MiB', file, -1, 'auto', { INWIRE_KEYLOG_CAP_BYTES: String(CAP) });
  checkTrue('capped: the renderer is alive', capped.alive);
  checkTrue('the follow card reports the skipped bytes', Math.abs(capped.skipped - (made.bytes - CAP)) < 256);
  checkTrue('...and loaded about 64 MiB of lines', Math.abs(capped.secrets - expectCapped) < made.lines * 0.01);
} finally {
  rmSync(dir, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nAll key-log heap checks passed.' : `\n${failures} key-log heap check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
