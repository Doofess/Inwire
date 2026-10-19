/**
 * Every state of NetFlow v5 monitoring, photographed - for looking at, not
 * asserting.
 *
 *   npx tsx scripts/electron/monitoring-shots.ts <out-dir> [--widths 1024,1600]
 *     [--themes light,dark,dim,contrast] [--only 02,storage,history-]
 *
 * Launches the built app against the stub agent and sends it v5 datagrams over
 * loopback (`scripts/monitoring/fixtures.ts`'s `v5Payload`), so every number in
 * a photo is one this script sent. One launch per width; each state is shot in
 * every theme by switching the theme in place (the `storage` event next-themes
 * listens for), because the states that matter most - nothing arriving and a
 * stale source - each cost a real minute of waiting, and a launch per theme
 * would pay it four times.
 *
 * The states: the panel never started, the sheet empty, the first Start, a
 * source listening, nothing arriving, refused senders, live with a selection,
 * its references and a datagram opened, the panel receiving, stale, stopped, a
 * bind that fails, and - after a relaunch with the rollup file deleted - the
 * summaries rebuilding, if the rebuild is slow enough to be seen.
 *
 * In `check.ts`'s NOT_TESTS: it has no right answer, only pictures, and a run
 * takes several minutes.
 */
import { createSocket, type Socket } from 'node:dgram';
import { existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Page } from 'playwright';
import { startStubAgent } from './stubAgent';
import { launchApp } from './launchApp';
import { v5Payload, type FlowSpec } from '../monitoring/fixtures';
import { FOREIGN_NAME, seedAged, seedEmpty, seedExpired, seedForeign, seedIncomplete, seedReadOnly, stubDialogs } from './monitoringSeed';

const OUT = process.argv[2];
if (!OUT) { console.log('usage: monitoring-shots.ts <out-dir> [--widths 1024,1600] [--themes light,dark,dim,contrast]'); process.exit(2); }
const arg = (name: string, fallback: string) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : fallback;
};
const WIDTHS = arg('widths', '1024,1600').split(',').map(Number);
const THEMES = arg('themes', 'light,dark,dim,contrast').split(',');
/** `--only 02,storage,history-`: the states whose names start with one of these; the default is every state. */
const ONLY = arg('only', '') === '' ? null : arg('only', '').split(',');
const wanted = (name: string) => ONLY === null || ONLY.some((prefix) => name.startsWith(prefix));
/** The numbered states are one long run (two waits of a minute and a rebuild); skip it when only the newer ones are asked for. */
const legacy = ONLY === null || ONLY.some((prefix) => /^\d/.test(prefix));
const fresh = ONLY === null || ONLY.some((prefix) => !/^\d/.test(prefix));
mkdirSync(OUT, { recursive: true });

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const PIPE = String.raw`\\.\pipe\inwire-monshots-` + process.pid;
const SHEET = '[data-testid="monitoring-sheet"]';
const agent = await startStubAgent(PIPE, 5);

async function freePort(): Promise<number> {
  const s = createSocket('udp4');
  await new Promise<void>((resolve) => s.bind(0, '127.0.0.1', resolve));
  const port = s.address().port;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}
async function socketFrom(address: string): Promise<Socket> {
  const s = createSocket('udp4');
  await new Promise<void>((resolve) => s.bind(0, address, resolve));
  return s;
}
const send = (s: Socket, bytes: Uint8Array, port: number) =>
  new Promise<void>((resolve, reject) => s.send(bytes, port, '127.0.0.1', (e) => (e ? reject(e) : resolve())));

/** A small office's worth of hosts, so the tables have something to rank. */
const HOSTS = ['192.168.1.20', '192.168.1.31', '192.168.1.44', '192.168.1.57', '192.168.1.63', '10.20.0.8'];
const REMOTES = ['142.250.74.110', '151.101.1.69', '104.16.132.229', '13.107.42.14', '52.97.146.178', '1.1.1.1', '8.8.8.8'];
const PROTOS: [number, number][] = [[6, 443], [6, 443], [17, 443], [6, 80], [17, 53], [6, 22]];

function flowsFor(i: number, n: number): Partial<FlowSpec>[] {
  const out: Partial<FlowSpec>[] = [];
  for (let k = 0; k < n; k++) {
    const h = HOSTS[(i + k * 3) % HOSTS.length];
    const r = REMOTES[(i * 7 + k) % REMOTES.length];
    const [protocol, dstPort] = PROTOS[(i + k) % PROTOS.length];
    const weight = 1 + ((i * 13 + k * 5) % 9);
    out.push({
      src: k % 2 === 0 ? h : r, dst: k % 2 === 0 ? r : h,
      protocol, srcPort: 49_152 + ((i + k) % 2000), dstPort,
      packets: 4 * weight, octets: 1_400 * weight * (protocol === 6 ? 3 : 1),
    });
  }
  return out;
}

class Exporter {
  private sequence = new Map<string, number>();
  constructor(private readonly socket: Socket, private readonly port: number) {}
  async datagram(i: number, engine: [number, number] = [0, 0], records = 10): Promise<void> {
    const key = engine.join('/');
    const sequence = this.sequence.get(key) ?? 0;
    const flows = flowsFor(i, records);
    this.sequence.set(key, sequence + flows.length);
    const now = Date.now();
    await send(this.socket, v5Payload({
      sequence, engineType: engine[0], engineId: engine[1],
      secs: Math.floor(now / 1000), nsecs: (now % 1000) * 1e6, uptime: 3_600_000,
    }, flows.map((f) => ({ ...f, first: 3_590_000, last: 3_599_000 }))), this.port);
  }
  skip(engine: [number, number], by: number): void {
    const key = engine.join('/');
    this.sequence.set(key, (this.sequence.get(key) ?? 0) + by);
  }
}

async function launch(profile: string, width: number) {
  const height = width <= 1024 ? 700 : 1000;
  const app = await launchApp({ args: ['.'], env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE } });
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await app.evaluate(({ BrowserWindow }, [w, h]) => {
    const win = BrowserWindow.getAllWindows()[0];
    win.unmaximize();
    win.setSize(w, h);
  }, [width, height] as [number, number]);
  await sleep(800);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  return { app, p };
}

async function close(app: Awaited<ReturnType<typeof launchApp>>, p: Page): Promise<void> {
  await p.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
  const pid = app.process().pid;
  await app.close();
  // One instance per profile: a relaunch before this one has gone hands the
  // window back to it.
  for (let i = 0; i < 50; i++) {
    try { process.kill(pid!, 0); await sleep(200); } catch { break; }
  }
  await sleep(500);
}

const port = await freePort();
for (const width of WIDTHS) {
  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-monshots-'));
  let { app, p } = await launch(profile, width);
  const until = async (cond: () => Promise<boolean>, ms = 30_000) => {
    const end = Date.now() + ms;
    while (Date.now() < end) { if (await cond().catch(() => false)) return true; await sleep(150); }
    return false;
  };
  const text = (t: string | RegExp) => p.getByText(t).first().isVisible().catch(() => false);
  /** One state, every theme. */
  const shot = async (name: string) => {
    if (!wanted(name)) return;
    for (const theme of THEMES) {
      await p.evaluate((t) => {
        localStorage.setItem('theme', t);
        window.dispatchEvent(new StorageEvent('storage', { key: 'theme', newValue: t, storageArea: localStorage }));
      }, theme);
      await sleep(350);
      await p.screenshot({ path: path.join(OUT, `${theme}-${width}-${name}.png`) });
    }
    console.log(`  ${width}-${name}`);
  };
  const openSheet = async () => {
    if (await p.locator(SHEET).count() > 0) return;
    if (!(await text('Open monitoring'))) await p.getByRole('button', { name: 'Network', exact: true }).click();
    await p.getByRole('button', { name: 'Open monitoring' }).click();
    await until(() => p.locator(SHEET).count().then((n) => n > 0), 5_000);
    await sleep(400);
  };
  const toPanel = async () => {
    await p.keyboard.press('Escape');
    await until(() => p.locator(SHEET).count().then((n) => n === 0), 5_000);
    await sleep(300);
  };
  const scrollTo = (selector: string) =>
    // Scroll the sheet's own scroller only: scrollIntoView also scrolls every
    // overflow-hidden ancestor, which at a short window shifts the whole shell.
    p.locator(selector).first().evaluate((el) => {
      const sc = el.closest('.overflow-y-auto');
      if (!sc) return;
      sc.scrollTop += el.getBoundingClientRect().top - sc.getBoundingClientRect().top - 8;
    }).catch(() => {});
  const field = (name: string) => p.getByRole('textbox', { name, exact: true });

  if (legacy) {
    await p.getByRole('button', { name: 'Network', exact: true }).click();
    await until(() => text('Open monitoring'), 10_000);
    await sleep(400);
    await shot('01-panel-not-started');

    await openSheet();
    await until(() => text(/No history yet/), 60_000);
    await sleep(400);
    await shot('02-sheet-empty');

    await field('Exporter').fill('127.0.0.1');
    await field('Listen on').fill('127.0.0.1');
    await field('Port').fill(String(port));
    await p.locator(SHEET).click({ position: { x: 4, y: 80 } }).catch(() => {});
    await sleep(200);
    await shot('03-first-start');

    await p.getByRole('button', { name: 'Start', exact: true }).click();
    await until(() => text(/Listening, nothing received yet/), 15_000);
    await sleep(400);
    await shot('04-listening');

    console.log('    waiting a minute for "nothing arriving"');
    await until(() => text('Nothing has arrived for a minute'), 75_000);
    await sleep(300);
    await shot('05-nothing-arriving');

    const stranger = await socketFrom('127.0.0.2');
    const other = new Exporter(stranger, port);
    for (let i = 0; i < 3; i++) await other.datagram(i);
    await until(() => text(/were refused/), 10_000);
    await sleep(400);
    await shot('06-rejected-senders');
    stranger.close();

    // Live: one engine busy, a second quieter one with a sequence jump.
    const sock = await socketFrom('127.0.0.1');
    const exporter = new Exporter(sock, port);
    for (let i = 0; i < 300; i++) {
      await exporter.datagram(i);
      if (i % 25 === 0) await exporter.datagram(i, [1, 1], 4);
      if (i === 150) exporter.skip([1, 1], 40);
      if (i % 20 === 0) await sleep(20);
    }
    await until(() => text('Receiving'), 15_000);
    await until(() => p.locator(`${SHEET} svg[role="img"]`).count().then((n) => n > 0), 20_000);
    await sleep(5_500); // one refresh past the last datagram
    await shot('07-live-top');
    await scrollTo(`${SHEET} [aria-labelledby="monitoring-history"]`);
    await sleep(300);
    await shot('08-live-history');

    await p.getByRole('button', { name: HOSTS[0], exact: true }).first().click();
    await until(() => text(/Supporting references: \d+ of \d+/), 10_000);
    await sleep(300);
    await scrollTo(`${SHEET} [aria-label="Selection"]`);
    await sleep(300);
    await shot('09-selection');
    await p.locator('[aria-label="Supporting references"] button').first().click();
    await until(() => p.locator('[aria-label="Datagram detail"]').count().then((n) => n > 0), 10_000);
    await sleep(300);
    await scrollTo(`${SHEET} [aria-label="Datagram detail"]`);
    await sleep(300);
    await shot('10-datagram-detail');

    await toPanel();
    await shot('11-panel-receiving');

    console.log('    waiting a minute for "stale"');
    await openSheet();
    await p.locator(`${SHEET} .overflow-y-auto`).first().evaluate((el) => el.scrollTo(0, 0)).catch(() => {});
    await until(() => text(/No recent export/), 80_000);
    await sleep(300);
    await shot('12-stale');
    await toPanel();
    await shot('13-panel-stale');
    await openSheet();

    await p.getByRole('button', { name: 'Stop', exact: true }).click();
    await until(() => text('Stopped.'), 10_000);
    await sleep(300);
    await shot('14-stopped');

    await field('Listen on').fill('192.0.2.1');
    await p.getByRole('button', { name: 'Start', exact: true }).click();
    await until(() => text(/socket failed/), 15_000);
    await sleep(400);
    await shot('15-bind-failed');
    await field('Listen on').fill('0.0.0.0');
    await p.locator(SHEET).click({ position: { x: 4, y: 80 } }).catch(() => {});
    await sleep(300);
    await shot('16-any-address-refused');
    await field('Listen on').fill('127.0.0.1');

    // A journal large enough that rebuilding its summaries takes a moment.
    await p.getByRole('button', { name: 'Start', exact: true }).click();
    await until(() => text(/Listening|Receiving/), 15_000);
    console.log('    filling the journal for the rebuild');
    for (let i = 0; i < 40_000; i++) {
      await exporter.datagram(i, [0, 0], 30);
      if (i % 200 === 0) await sleep(30);
    }
    await sleep(3_000);
    await p.getByRole('button', { name: 'Stop', exact: true }).click();
    await until(() => text('Stopped.'), 10_000);
    sock.close();
    await close(app, p);

    const rollups = path.join(profile, 'monitoring', 'rollups.iwmr');
    if (existsSync(rollups)) rmSync(rollups);
    ({ app, p } = await launch(profile, width));
    await p.getByRole('button', { name: 'Network', exact: true }).click();
    await until(() => text('Open monitoring'), 10_000);
    await p.getByRole('button', { name: 'Open monitoring' }).click();
    const seen = await until(() => text(/Rebuilding summaries/), 60_000);
    if (seen) await shot('17-rebuilding');
    else console.log('    the rebuild finished before it could be photographed');
    await until(() => text(/Received traffic records/), 5_000);
    await sleep(6_000);
    await shot('18-after-relaunch');
  }

  if (fresh) {
    // Storage, retention, discard and expired evidence (ADRs 0061-0063) on real seeded folders. Main's dialogs
    // are stubbed, so "Change..." lands on the folder this script names. Nothing here is saved: the retention
    // draft stays a draft, so no policy ever runs over a seed.
    const seeds = mkdtempSync(path.join(tmpdir(), 'inwire-monseed-'));
    const nowMs = Date.now();
    const empty = await seedEmpty(seeds);
    const foreign = await seedForeign(seeds, { nowMs });
    const readOnly = await seedReadOnly(seeds, { nowMs });
    const expired = await seedExpired(seeds, { nowMs });
    const incomplete = await seedIncomplete(seeds, { nowMs });
    const aged = await seedAged(seeds, { nowMs });
    const { pick, saveTo, answer } = await stubDialogs(app);
    const sheet = p.locator(SHEET);
    const change = async (folder: string) => {
      await pick(folder);
      await sheet.getByRole('button', { name: 'Change…' }).click();
    };
    const toStorage = async () => { await scrollTo(`${SHEET} h3:text-is("Storage")`); await sleep(300); };
    const sixHours = () => sheet.getByRole('button', { name: '6 h', exact: true }).click();
    const bars = (kind: string) => sheet.locator(`svg[role="img"] rect[data-coverage="${kind}"]`).count();

    console.log('    storage, expiry and the bundle');
    await openSheet();
    await until(() => text(/No history yet|No received traffic records yet|Received traffic records/), 60_000);
    await field('Exporter').fill('127.0.0.1');
    await field('Listen on').fill('127.0.0.1');
    await field('Port').fill(String(port));
    await p.locator(SHEET).click({ position: { x: 4, y: 80 } }).catch(() => {});
    await sleep(300);

    await toStorage();
    await shot('storage-default');

    await change(empty.folder);
    await until(() => text('New monitoring data will be kept here.'), 10_000);
    await toStorage();
    await shot('storage-custom');

    await change(foreign.folder);
    await until(() => sheet.locator('[role="alert"]').filter({ hasText: FOREIGN_NAME }).count().then((n) => n > 0), 10_000);
    await toStorage();
    await shot('storage-refused');

    await change(readOnly.folder);
    await until(() => text(/open read-only/), 10_000);
    await toStorage();
    await shot('storage-read-only');

    // A discard before a date, filled in and not pressed.
    await change(expired.folder);
    await until(() => text('The monitoring data already in this folder is in use.'), 10_000);
    const day = new Date(Date.now() - 86_400_000);
    const two = (n: number) => String(n).padStart(2, '0');
    await sheet.getByLabel('Discard', { exact: true }).selectOption('before');
    await sheet.getByLabel('Discard evidence before').fill(
      `${day.getFullYear()}-${two(day.getMonth() + 1)}-${two(day.getDate())}T${two(day.getHours())}:${two(day.getMinutes())}`);
    await toStorage();
    await shot('storage-discard');

    await sheet.getByRole('checkbox', { name: 'Keep raw evidence for' }).check();
    await sheet.getByLabel('Days of raw evidence').fill('30');
    await sheet.getByRole('radio', { name: 'Expire the oldest raw evidence' }).check();
    await toStorage();
    await shot('storage-retention-on');

    await sixHours();
    await until(async () => (await bars('aggregate-only')) > 0 && await sheet.locator('figcaption').getByText('Evidence expired', { exact: true }).isVisible(), 30_000);
    await sleep(400);
    await scrollTo(`${SHEET} [aria-labelledby="monitoring-history"]`);
    await sleep(300);
    await shot('history-expired');

    await sheet.getByRole('button', { name: expired.host, exact: true }).first().click();
    await until(() => sheet.locator('section[aria-label="Selection"] [role="status"]').filter({ hasText: /under the retention policy/ }).count().then((n) => n > 0), 20_000);
    await scrollTo(`${SHEET} [aria-label="Selection"]`);
    await sleep(300);
    await shot('focus-expired');
    await sheet.getByRole('button', { name: 'Clear the selection' }).click();

    await change(incomplete.folder);
    await until(() => text('Not available: this minute exceeded the key budget, and its evidence has expired.'), 30_000);
    await sleep(400);
    await scrollTo(`${SHEET} >> text=Not available: this minute`);
    await sleep(300);
    await shot('history-incomplete');

    // The bundle saved through the sheet: the line under the buttons says where.
    const bundleFile = path.join(seeds, 'incomplete.iwmon');
    await saveTo(bundleFile);
    await sheet.getByRole('button', { name: 'Export evidence bundle' }).click();
    await until(() => text(`Saved to ${bundleFile}`), 30_000);
    await scrollTo(`${SHEET} >> button:has-text("Export evidence bundle")`);
    await sleep(300);
    await shot('bundle-export');

    // A retention save that would expire the aged seed's segments, declined in main's dialog.
    await change(aged.folder);
    await until(() => sheet.getByRole('button', { name: 'Start', exact: true }).isEnabled().catch(() => false), 10_000);
    const keep = sheet.getByRole('checkbox', { name: 'Keep raw evidence for' });
    if (!(await keep.isChecked())) await keep.check();
    await sheet.getByLabel('Days of raw evidence').fill('1');
    await answer(0);
    await sheet.getByRole('button', { name: 'Save', exact: true }).click();
    await until(() => text('Retention not changed.'), 15_000);
    await toStorage();
    await shot('storage-retention-declined');
    rmSync(seeds, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
  }

  await close(app, p);
  rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });
}
await agent.close();
console.log(`shots in ${OUT}`);
