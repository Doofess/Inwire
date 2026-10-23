/**
 * NetFlow v5 monitoring under fault, through the real built app, against
 * datagrams this script sends itself to loopback ports.
 *
 *   npx tsx scripts/electron/monitoring-drive.ts
 *
 * `monitoring-ui.ts` proves the sheet works when nothing goes wrong. This
 * proves what happens when something does, in twelve scenarios:
 *
 *    1. golden path: exact totals, the source's bytes, Stop releases the port
 *    2. reopen the same profile: history restored once, nothing bound, the
 *       rollup answer equal to the raw one
 *    3. the monitoring Worker terminated: intake goes on, nothing is lost
 *    4. the utility process killed: the exit is reported, nothing journaled is lost
 *    5. the page reloaded: intake goes on, the UI reconnects
 *    6. the port held by another program: a stated error, nothing journaled
 *    7. an unsaved capture, then the window closed: Keep capturing / Quit
 *    8. the sheet closed and the page reloaded repeatedly: no duplicate feed
 *    9. the rollup sidecar deleted: history rebuilt identically
 *   10. the storage limit reached: a stated stop, not silent continuation
 *   11. a capture started, cleared and imported: monitoring totals untouched
 *   12. the Focus pivot: the capture's filter becomes `ip.addr == <host>`
 *
 * Exact totals come from two places that do not share code with the thing
 * under test: the ledger of flows this script itself sent, and, with the app
 * closed, the journal on disk read back with the repo's codecs.
 *
 * A scenario the app has no seam for prints `NOT RUN  <scenario>: <why>`, which
 * is never a pass. Skips like `monitoring-ui.ts` without a build or Playwright.
 * Launches go through `launchApp`, so the window is in the background.
 */
import { createSocket, type Socket } from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import type { ElectronApplication, Page } from 'playwright';
import { startStubAgent, dnsQuery, type StubAgent } from './stubAgent';
import { launchApp } from './launchApp';
import { v5Payload } from '../monitoring/fixtures';
import { formatBytes } from '../../src/lib/formatBytes';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import { MonitoringJournal } from '../../src/services/monitoring/journal';
import { NodeSegmentDirectory } from '../../electron/monitoring/volume';
import { LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { runHistoryQuery } from '../../src/services/monitoring/queries';
import { RollupStore } from '../../src/services/monitoring/rollupStore';
import { type Evidence, type HistoryResult, type QuerySpec } from '../../src/services/monitoring/types';
import { decodeV5, sourceKey } from '../../src/services/monitoring/v5';

let failures = 0;
const notRun: string[] = [];
function checkTrue(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}
function notRan(scenario: string, why: string): void {
  notRun.push(scenario);
  console.log(`NOT RUN  ${scenario}: ${why}`);
}
function note(text: string): void { console.log(`      ${text}`); }
function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}
if (process.platform !== 'win32') skip('the desktop app is Windows-only - nothing to launch here');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'monitoring', 'monitoring.cjs'))) {
  skip('no build with monitoring to launch - run `npm run build` first');
}
try {
  await import('playwright');
} catch {
  skip('playwright is not installed');
}
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const msg = (e: unknown): string => (e instanceof Error ? e.message : String(e));

// --- plumbing -----------------------------------------------------------------------------------------------

const PIPE = String.raw`\\.\pipe\inwire-mondrive-` + process.pid;
const SHEET = '[data-testid="monitoring-sheet"]';
const EXPORTER = '127.0.0.1';
const MiB = 1024 * 1024;
const T0 = Date.now();

/** A UDP port nothing holds on 127.0.0.1 right now. */
async function freePort(): Promise<number> {
  const s = createSocket('udp4');
  await new Promise<void>((resolve) => s.bind(0, '127.0.0.1', resolve));
  const port = s.address().port;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}

/** 'free' when this script can bind the port, else the error code that refused it. */
function bindProbe(port: number): Promise<string> {
  return new Promise((resolve) => {
    const s = createSocket('udp4');
    s.once('error', (e) => {
      try { s.close(); } catch { /* never opened */ }
      resolve((e as NodeJS.ErrnoException).code ?? msg(e));
    });
    s.bind(port, '127.0.0.1', () => s.close(() => resolve('free')));
  });
}

/** A socket of this script's own holding the port, as another program would. */
function hold(port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const s = createSocket('udp4');
    s.once('error', reject);
    s.bind(port, '127.0.0.1', () => resolve(s));
  });
}

const sender = createSocket('udp4');
let sequence = 0;
interface Flow { src: string; dst: string; octets: number; packets: number }
function sendRaw(port: number, bytes: Uint8Array): Promise<void> {
  return new Promise((resolve, reject) => sender.send(bytes, port, '127.0.0.1', (e) => (e ? reject(e) : resolve())));
}

/** What this script has sent to one profile, so the expected totals are authored here and nowhere else. */
class Ledger {
  readonly flows: Flow[] = [];
  datagrams = 0;
  get records(): number { return this.flows.length; }
  get octets(): number { return this.flows.reduce((n, f) => n + f.octets, 0); }
  get packets(): number { return this.flows.reduce((n, f) => n + f.packets, 0); }
  async send(port: number, flows: Flow[]): Promise<void> {
    const bytes = v5Payload(
      { sequence: sequence, secs: Math.floor(Date.now() / 1000), nsecs: 0, uptime: 600_000 },
      flows.map((f) => ({ src: f.src, dst: f.dst, octets: f.octets, packets: f.packets })),
    );
    sequence += flows.length;
    await sendRaw(port, bytes);
    this.flows.push(...flows);
    this.datagrams++;
  }
  /** The rows the two tables should show, as the sheet formats them, sorted by address. */
  endpoints(): string[][] {
    const m = new Map<string, [number, number]>();
    for (const f of this.flows) {
      const s = m.get(f.src) ?? [0, 0]; s[0] += f.octets; m.set(f.src, s);
      const d = m.get(f.dst) ?? [0, 0]; d[1] += f.octets; m.set(f.dst, d);
    }
    return [...m].sort(([a], [b]) => (a < b ? -1 : 1)).map(([a, [s, r]]) => [a, formatBytes(s), formatBytes(r)]);
  }
  conversations(measure: 'octets' | 'packets'): string[][] {
    const m = new Map<string, [string, string, number, number]>();
    for (const f of this.flows) {
      const k = `${f.src}>${f.dst}`;
      const c = m.get(k) ?? [f.src, f.dst, 0, 0];
      c[2] += f.octets; c[3] += f.packets; m.set(k, c);
    }
    return [...m.values()].sort((a, b) => (a[0] + a[1] < b[0] + b[1] ? -1 : 1))
      .map(([s, d, o, p]) => [s, d, measure === 'octets' ? formatBytes(o) : new Intl.NumberFormat(undefined).format(p)]);
  }
}

const A: Flow = { src: '10.0.0.1', dst: '10.0.0.2', octets: 1000, packets: 10 };
const B: Flow = { src: '10.0.0.3', dst: '10.0.0.4', octets: 2500, packets: 5 };
const C: Flow = { src: '10.0.0.5', dst: '10.0.0.6', octets: 700, packets: 7 };

const profiles: string[] = [];
function tempProfile(tag: string): string {
  const dir = mkdtempSync(path.join(tmpdir(), `inwire-mondrive-${tag}-`));
  profiles.push(dir);
  return dir;
}
/** The saved source, written before launch so the form arrives filled in. */
function seed(profile: string, port: number, limitBytes = 256 * MiB): void {
  mkdirSync(path.join(profile, 'monitoring'), { recursive: true });
  writeFileSync(path.join(profile, 'monitoring', 'settings.json'), JSON.stringify({
    version: 1, source: { exporterIPv4: EXPORTER, bindIPv4: '127.0.0.1', port, storageLimitBytes: limitBytes },
  }));
}

const agent: StubAgent = await startStubAgent(PIPE, 5);
interface Run { app: ElectronApplication; p: Page }
const live = new Set<ElectronApplication>();

async function launch(profile: string): Promise<Run> {
  const app = await launchApp({
    args: ['.'],
    env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE } as Record<string, string>,
  });
  live.add(app);
  const p = await app.firstWindow();
  p.setDefaultTimeout(30_000);
  await p.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  return { app, p };
}

/** Quits the app the way a user would after saving: nothing unsaved, so no confirm. */
async function shutdown(r: Run): Promise<void> {
  await r.p.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (v: boolean) => void } })
    .inwire?.setUnsavedCapture?.(false)).catch(() => {});
  await Promise.race([r.app.close().catch(() => {}), sleep(40_000)]);
  reap(r.app);
  live.delete(r.app);
}

/** Kills what is left of an app that did not close; Playwright throws on a connection that is already gone. */
function reap(app: ElectronApplication): void {
  try {
    const proc = app.process();
    if (proc.exitCode === null) proc.kill();
  } catch { /* already gone */ }
}

async function closeAll(): Promise<void> {
  for (const app of [...live]) {
    // Frames in the buffer make closing raise the "Quit Inwire?" confirm; nothing here answers it.
    for (const w of app.windows()) {
      await Promise.race([
        w.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?: (v: boolean) => void } })
          .inwire?.setUnsavedCapture?.(false)).catch(() => {}),
        sleep(2000),
      ]);
    }
    await Promise.race([app.close().catch(() => {}), sleep(20_000)]);
    reap(app);
    live.delete(app);
  }
}

// A drive killed from outside must not leave a window behind: reap whatever is still alive on the way out.
const reapAll = () => { for (const app of live) reap(app); };
process.on('exit', reapAll);
for (const sig of ['SIGINT', 'SIGTERM', 'SIGBREAK'] as const) process.on(sig, () => { reapAll(); process.exit(1); });

async function until(cond: () => Promise<boolean>, ms: number): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond().catch(() => false)) return true;
    await sleep(200);
  }
  return false;
}

const ONLY = (process.env.DRIVE_ONLY ?? '').split(',').filter(Boolean);
async function scenario(name: string, fn: () => Promise<void>): Promise<void> {
  if (ONLY.length > 0 && !ONLY.some((n) => name.startsWith(`${n}.`) || name.startsWith(`${n} `))) return;
  const t = Date.now();
  console.log(`\n--- ${name} ---`);
  try {
    await fn();
  } catch (e) {
    failures++;
    console.log(`FAIL  ${name}: the drive threw: ${msg(e)}`);
  } finally {
    await closeAll();
  }
  note(`(${((Date.now() - t) / 1000).toFixed(1)} s)`);
}

// --- reading the sheet ----------------------------------------------------------------------------------------

const digits = (s: string | undefined): number | null => (s === undefined ? null : Number(s.replace(/\D/g, '')));
const sheetOpen = (p: Page) => p.locator(SHEET).count().then((n) => n > 0);
const sheetText = (p: Page) => p.locator(SHEET).innerText().catch(() => '');
const buttonVisible = (p: Page, name: string) => p.getByRole('button', { name, exact: true }).first().isVisible().catch(() => false);

async function read(p: Page): Promise<{ text: string; records: number | null; accepted: number | null }> {
  const text = await sheetText(p);
  return {
    text,
    records: digits(text.match(/(\d[\d.,  ]*)\s+received traffic records/)?.[1]),
    accepted: digits(text.match(/Accepted\s*(\d[\d.,  ]*)/)?.[1]),
  };
}

async function tables(p: Page): Promise<{ endpoints: string[][]; conversations: string[][] }> {
  const all = await p.evaluate((sel) => {
    const out: Record<string, string[][]> = {};
    for (const t of document.querySelectorAll(`${sel} table`)) {
      const title = t.parentElement?.querySelector('h3')?.textContent ?? '';
      out[title] = [...t.querySelectorAll('tbody tr')]
        .map((tr) => [...tr.querySelectorAll('td')].map((td) => (td.textContent ?? '').trim()));
    }
    return out;
  }, SHEET);
  const byAddress = (rows: string[][] | undefined) => [...(rows ?? [])].sort((a, b) => (a.join('>') < b.join('>') ? -1 : 1));
  return { endpoints: byAddress(all['Top endpoints']), conversations: byAddress(all['Top conversations']) };
}

async function openSheet(p: Page): Promise<void> {
  if (await sheetOpen(p)) return;
  const open = p.getByRole('button', { name: 'Open monitoring' });
  if (!(await open.isVisible().catch(() => false))) {
    await p.getByRole('button', { name: 'Statistics', exact: true }).click();
    if (!(await until(() => open.isVisible(), 2500))) await p.getByRole('button', { name: 'Network', exact: true }).click();
  }
  await open.click();
  if (!(await until(() => sheetOpen(p), 10_000))) throw new Error('the monitoring sheet did not open');
}

async function closeSheet(p: Page): Promise<void> {
  await p.keyboard.press('Escape');
  await until(() => sheetOpen(p).then((o) => !o), 5000);
}

/** Presses Start on the saved source and waits for the listener. */
async function startListening(p: Page): Promise<boolean> {
  await p.getByRole('button', { name: 'Start', exact: true }).click();
  return until(async () => /\bListening\b(?!,)/.test(await sheetText(p)) && (await buttonVisible(p, 'Stop')), 20_000);
}

async function stopListening(p: Page): Promise<boolean> {
  await p.getByRole('button', { name: 'Stop', exact: true }).click();
  return until(async () => (await sheetText(p)).includes('Stopped.') && (await buttonVisible(p, 'Start')), 15_000);
}

/** Waits for the history to show exactly the ledger's records (a refresh is 5 s). */
const waitRecords = (p: Page, n: number, ms = 25_000) => until(async () => (await read(p)).records === n, ms);

async function monitoringPid(app: ElectronApplication): Promise<number | null> {
  const metrics = await app.evaluate(({ app: a }) => a.getAppMetrics().map((m) => ({
    pid: m.pid, type: m.type, name: (m as { name?: string }).name ?? '', service: (m as { serviceName?: string }).serviceName ?? '',
  })));
  return metrics.find((m) => m.service === 'inwire-monitoring' || m.name === 'inwire-monitoring')?.pid ?? null;
}

const workerUrls = (p: Page, part: string) => p.workers().map((w) => w.url()).filter((u) => u.includes(part));
const countsOf = (p: Page) => p.evaluate(() => {
  const t = document.querySelector('[data-packet-counts]')?.textContent ?? '';
  const m = t.match(/([\d,]+)\s*\/\s*([\d,]+)/) ?? t.match(/([\d,]+)/);
  return m ? [Number(m[1].replace(/,/g, '')), Number((m[2] ?? m[1]).replace(/,/g, ''))] : [0, 0];
});

// --- the offline oracle -----------------------------------------------------------------------------------------

interface Oracle {
  datagrams: number; malformed: number; unsupported: number;
  records: number; octets: number; packets: number;
  boundaries: string[];
  sidecar: string;
  /** null where the rollup answer could not be compared (and why in `why`). */
  rollupEqualsRaw: boolean | null; rollupMinutes: number; why: string;
}
const inflate = (b: Uint8Array, maxOutput: number) => new Uint8Array(inflateRawSync(b, { maxOutputLength: maxOutput }));
const json = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? x.toString() : x));

/**
 * Reads the monitoring directory of a CLOSED app with the repo's own codecs, on a copy:
 * opening a journal closes a session left open, and that must not touch the profile.
 */
async function oracle(profile: string): Promise<Oracle> {
  const copy = mkdtempSync(path.join(tmpdir(), 'inwire-mondrive-oracle-'));
  profiles.push(copy);
  cpSync(path.join(profile, 'monitoring'), copy, { recursive: true });
  const segments = new NodeSegmentDirectory(copy);
  const sf = NodeBlockFile.open(path.join(copy, 'rollups.iwmr'));
  try {
    const { journal } = MonitoringJournal.open(segments, { limitBytes: 1 << 30 });
    const snap = journal.snapshot();
    const entries: Evidence[] = [];
    for (let after = 0; ;) {
      const page = journal.readPage(snap, after, 256, 1 << 20);
      entries.push(...page.entries);
      after = page.nextAfterId;
      if (page.done) break;
    }
    const out: Oracle = {
      datagrams: 0, malformed: 0, unsupported: 0, records: 0, octets: 0, packets: 0, boundaries: [],
      sidecar: '', rollupEqualsRaw: null, rollupMinutes: 0, why: '',
    };
    let firstMs = Infinity;
    for (const e of entries) {
      if (e.kind === 'boundary') { out.boundaries.push(`${e.action}:${e.reason}`); continue; }
      out.datagrams++;
      firstMs = Math.min(firstMs, e.receivedMs);
      const d = decodeV5(e, EXPORTER);
      if (d.kind === 'valid') {
        for (const f of d.flows) { out.records++; out.octets += Number(f.reportedOctets); out.packets += Number(f.reportedPackets); }
      } else if (d.kind === 'malformed') out.malformed++;
      else out.unsupported++;
    }
    const opened = RollupStore.open(
      sf, { generation: snap.generation, throughEntryId: snap.throughEntryId },
      { nowMs: () => Date.now() },
    );
    out.sidecar = opened.status;
    const rt = new LocalRuntime(journal, opened.store,
      opened.reason === undefined ? { status: opened.status } : { status: opened.status, reason: opened.reason });
    if (out.records === 0) { out.why = 'the journal holds no flow records'; return out; }
    const nowMs = Date.now();
    const spec: QuerySpec = {
      // Buckets one minute wide and minute-aligned: the planner folds a rollup minute only when the whole
      // minute falls inside one bucket (queries.ts foldRollups), so anything narrower is answered raw.
      sourceKey: sourceKey(EXPORTER, 0, 0), fromMs: Math.floor(firstMs / 60_000) * 60_000, toMs: Math.floor(firstMs / 60_000) * 60_000 + 3 * 60_000, bucketCount: 3,
    };
    const ask = async (forceRaw: boolean): Promise<HistoryResult | null> => {
      const r = await runHistoryQuery(rt, rt, spec, new AbortController().signal, { inflate, nowMs, forceRaw });
      return r.ok ? r.value : null;
    };
    const viaRollups = await ask(false);
    const raw = await ask(true);
    if (viaRollups === null || raw === null) { out.why = 'a history query was refused'; return out; }
    out.rollupMinutes = viaRollups.answeredFrom.rollupMinutes;
    if (opened.status !== 'ok' || out.rollupMinutes === 0) {
      out.why = `the sidecar answered ${out.rollupMinutes} minutes (status ${opened.status}), so the two answers would be one`;
      return out;
    }
    const project = (r: HistoryResult) => json({
      buckets: r.buckets, endpoints: r.endpoints, conversations: r.conversations,
      matchingRecords: r.matchingRecords, malformed: r.malformed, unsupported: r.unsupported,
    });
    out.rollupEqualsRaw = project(viaRollups) === project(raw);
    return out;
  } finally {
    segments.close();
    sf.close();
  }
}

const same = (a: unknown, b: unknown) => json(a) === json(b);

// --- 1 and 12: the golden path, and the pivot ----------------------------------------------------------------

const profileA = tempProfile('a');
const portA = await freePort();
const ledgerA = new Ledger();
let goldenSentAt = 0;

await scenario('1. golden path', async () => {
  const r = await launch(profileA);
  const { p } = r;
  await openSheet(p);
  await p.getByRole('textbox', { name: 'Exporter', exact: true }).fill(EXPORTER);
  await p.getByRole('textbox', { name: 'Listen on', exact: true }).fill('127.0.0.1');
  await p.getByRole('textbox', { name: 'Port', exact: true }).fill(String(portA));
  checkTrue('1: Start listens on the loopback port', await startListening(p));
  checkTrue('1: while it listens, the port is held (another program cannot bind it)', (await bindProbe(portA)) !== 'free');

  await ledgerA.send(portA, [A, B]);
  goldenSentAt = Date.now();
  checkTrue('1: the sheet reads Receiving', await until(async () => (await sheetText(p)).includes('Receiving'), 15_000));
  checkTrue('1: the history shows exactly 2 received traffic records', await waitRecords(p, ledgerA.records),
    JSON.stringify((await read(p)).records));
  const t = await tables(p);
  checkTrue('1: the top endpoints carry the exporter\'s bytes exactly', same(t.endpoints, ledgerA.endpoints()),
    `${json(t.endpoints)} vs ${json(ledgerA.endpoints())}`);
  checkTrue('1: the top conversations carry each flow\'s bytes exactly', same(t.conversations, ledgerA.conversations('octets')),
    `${json(t.conversations)} vs ${json(ledgerA.conversations('octets'))}`);
  checkTrue('1: the source\'s bytes in all are visible (3,500 B across the two flows)',
    t.conversations.length === 2 && ledgerA.octets === 3500 && t.endpoints.reduce((n, row) => n + (row[1] === formatBytes(0) ? 0 : 1), 0) === 2);
  checkTrue('1: Accepted counts the one datagram', (await read(p)).accepted === 1, String((await read(p)).accepted));
  await p.locator(`${SHEET} button`, { hasText: /^Packets$/ }).click();
  checkTrue('1: the Packets measure shows exactly 15 packets across the two flows',
    await until(async () => same((await tables(p)).conversations, ledgerA.conversations('packets')), 15_000),
    json((await tables(p)).conversations));
  await p.locator(`${SHEET} button`, { hasText: /^Bytes$/ }).click();

  checkTrue('1: Stop stops the listener', await stopListening(p));
  checkTrue('1: ...and the port is released: this script can bind it', (await bindProbe(portA)) === 'free');

  // 12. The pivot, on the history that is still on screen.
  await p.getByRole('button', { name: '10.0.0.1', exact: true }).first().click();
  checkTrue('12: selecting a host offers the pivot',
    await until(() => p.getByRole('button', { name: 'Filter capture by this host' }).isVisible(), 15_000));
  await p.getByRole('button', { name: 'Filter capture by this host' }).click();
  checkTrue('12: the pivot closes the sheet', await until(() => sheetOpen(p).then((o) => !o), 5000));
  const filter = await p.locator('input[placeholder="e.g. tcp.port == 443"]').inputValue().catch(() => '');
  checkTrue('12: ...the capture\'s filter reads ip.addr == 10.0.0.1', filter === 'ip.addr == 10.0.0.1', JSON.stringify(filter));
  checkTrue('12: ...on Packets', await until(
    () => p.locator('button[aria-label="Packets"]').getAttribute('aria-pressed').then((v) => v === 'true'), 5000));
});

// --- 2: reopen --------------------------------------------------------------------------------------------------

await scenario('2. reopen with the same profile', async () => {
  // Let the golden path's minute close, so the rollup has something to hold.
  const until1 = (Math.floor(goldenSentAt / 60_000) + 1) * 60_000 + 4000;
  if (goldenSentAt > 0 && until1 > Date.now()) { note(`waiting ${Math.ceil((until1 - Date.now()) / 1000)} s for the minute to close`); await sleep(until1 - Date.now()); }

  const before = await oracle(profileA);
  checkTrue('2: the journal on disk holds the 1 datagram, 2 flows, 3,500 B and 15 packets sent',
    before.datagrams === 1 && before.records === 2 && before.octets === 3500 && before.packets === 15, json(before));
  checkTrue('2: ...and the session was stopped by the user', before.boundaries.some((b) => b.startsWith('stop:')), json(before.boundaries));

  const r = await launch(profileA);
  const { p } = r;
  await openSheet(p);
  checkTrue('2: history is restored: 2 records', await waitRecords(p, ledgerA.records, 60_000), String((await read(p)).records));
  await sleep(6000);
  checkTrue('2: ...and not doubled after another refresh', (await read(p)).records === ledgerA.records, String((await read(p)).records));
  const t = await tables(p);
  checkTrue('2: ...the tables equal the ones before the reopen', same(t.endpoints, ledgerA.endpoints())
    && same(t.conversations, ledgerA.conversations('octets')), json(t));
  const text = await sheetText(p);
  checkTrue('2: nothing is listening: Start is offered and the status does not say Listening',
    (await buttonVisible(p, 'Start')) && !/\bListening\b(?!,)/.test(text) && !(await buttonVisible(p, 'Stop')),
    `start=${await buttonVisible(p, 'Start')} stop=${await buttonVisible(p, 'Stop')} listeningWord=${/\bListening\b(?!,)/.test(text)}`);
  checkTrue('2: ...and the port is free', (await bindProbe(portA)) === 'free');
  note(`the sheet read: ${text.match(/read from [^\n]+/)?.[0] ?? '(no "read from" line)'}`);
  await shutdown(r);

  const after = await oracle(profileA);
  checkTrue('2: the second open appended nothing a datagram could be mistaken for',
    after.datagrams === before.datagrams && after.records === before.records, json(after));
  if (after.rollupEqualsRaw === null) notRan('2: rollup answer equals raw answer', after.why);
  else checkTrue(`2: the rollup answer equals the raw answer for the same range (${after.rollupMinutes} summarised minute(s))`,
    after.rollupEqualsRaw);
});

// --- 3: the monitoring Worker terminated ----------------------------------------------------------------------------

await scenario('3. monitoring Worker terminated', async () => {
  const profile = tempProfile('w');
  const port = await freePort();
  const led = new Ledger();
  seed(profile, port);
  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  checkTrue('3: Start listens', await startListening(p));
  await led.send(port, [A]);
  checkTrue('3: one record is shown before the fault', await waitRecords(p, led.records));

  const pipeline0 = workerUrls(p, 'pipeline.worker');
  const maplibre0 = workerUrls(p, 'maplibre-gl-worker');
  const pid0 = await monitoringPid(r.app);
  checkTrue('3: exactly one monitoring Worker is alive', workerUrls(p, 'monitoring.worker').length === 1,
    JSON.stringify(p.workers().map((w) => w.url())));

  const worker = p.workers().find((w) => w.url().includes('monitoring.worker'));
  // An uncaught throw inside the Worker raises `error` on its owner, which is the client's cue to end it.
  await worker?.evaluate(() => { setTimeout(() => { throw new Error('monitoring-drive: terminate'); }, 0); }).catch(() => {});
  checkTrue('3: the sheet says monitoring is not available', await until(async () => {
    const t = await sheetText(p);
    return t.includes('Monitoring is not available') && /Worker failed/.test(t);
  }, 15_000), (await sheetText(p)).slice(0, 300));
  checkTrue('3: the Worker is really gone', await until(async () => workerUrls(p, 'monitoring.worker').length === 0, 10_000));

  await led.send(port, [B, C]); // during the outage
  await sleep(500);
  checkTrue('3: the listener is untouched by the Worker\'s death (the port is still held)', (await bindProbe(port)) !== 'free');

  await p.getByRole('button', { name: 'Try again' }).click();
  checkTrue('3: the UI reconnects to a new Worker', await until(async () => workerUrls(p, 'monitoring.worker').length === 1, 20_000));
  checkTrue('3: the datagram sent during the outage is counted: no gap in totals', await waitRecords(p, led.records, 40_000),
    `${(await read(p)).records} vs ${led.records}`);
  const t = await tables(p);
  checkTrue('3: ...with the exact bytes', same(t.endpoints, led.endpoints()), json(t.endpoints));
  checkTrue('3: ...and the listener still listening, Stop offered', await buttonVisible(p, 'Stop'));
  checkTrue('3: the same utility process kept the socket (no restart)', pid0 !== null && (await monitoringPid(r.app)) === pid0,
    `${pid0} -> ${await monitoringPid(r.app)}`);
  checkTrue('3: the capture pipeline Worker is untouched',
    pipeline0.length > 0 && same(pipeline0, workerUrls(p, 'pipeline.worker')), json([pipeline0, workerUrls(p, 'pipeline.worker')]));
  if (maplibre0.length === 0) notRan('3: map Worker untouched', 'the map Worker never started in this run (no map on screen without geo-IP consent), so there is nothing to compare');
  else checkTrue('3: the map Worker is untouched', same(maplibre0, workerUrls(p, 'maplibre-gl-worker')));

  // The other way a Worker dies: nothing is thrown, and no error event reaches the page.
  const second = p.workers().find((w) => w.url().includes('monitoring.worker'));
  await second?.evaluate(() => { self.close(); }).catch(() => {});
  await led.send(port, [A]);
  // The client's heartbeat calls a Worker gone after LIMITS.requestMs (15 s) without a message, so
  // the bound is that plus one 5 s ping and some slack for the sheet to draw it.
  checkTrue('3: a Worker that closes itself without any error event is noticed by the sheet',
    await until(async () => (await sheetText(p)).includes('Monitoring is not available'), 25_000),
    'the client\'s heartbeat (src/services/monitoring/client.ts armSilence) did not call the silent Worker gone within requestMs plus a ping');
  await p.reload();
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 2000 }).catch(() => {});
  await openSheet(p);
  checkTrue('3: ...and a reload still finds that datagram journaled', await waitRecords(p, led.records, 40_000),
    `${(await read(p)).records} vs ${led.records}`);
});

// --- 4: the utility process killed ----------------------------------------------------------------------------------

await scenario('4. utility process exit', async () => {
  const profile = tempProfile('u');
  const port = await freePort();
  const led = new Ledger();
  seed(profile, port);
  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  await startListening(p);
  await led.send(port, [A, B]);
  checkTrue('4: two records are shown before the kill', await waitRecords(p, led.records));
  const pid = await monitoringPid(r.app);
  checkTrue('4: the utility process is found by its service name', pid !== null);
  if (pid === null) return;
  process.kill(pid);

  checkTrue('4: the UI reports the exit', await until(async () => /monitoring stopped unexpectedly/.test(await sheetText(p)), 20_000),
    (await sheetText(p)).slice(0, 300));
  const t = await sheetText(p);
  checkTrue('4: ...and says the listener was running and Start must be pressed again',
    /The listener was running: press Start again/.test(t), t.slice(0, 400));
  checkTrue('4: the killed process released the port', await until(async () => (await bindProbe(port)) === 'free', 10_000));

  // hostCore.ts: nothing restarts by itself; the next connect forks a fresh utility and never binds.
  await p.getByRole('button', { name: 'Try again' }).click();
  checkTrue('4: Try again reconnects to a new utility process', await until(async () => {
    const n = await monitoringPid(r.app);
    return n !== null && n !== pid;
  }, 30_000));
  checkTrue('4: ...whose history still holds every record journaled before the kill', await waitRecords(p, led.records, 40_000),
    `${(await read(p)).records} vs ${led.records}`);
  checkTrue('4: ...and which is not listening by itself (the port stays free, Start is offered)',
    (await bindProbe(port)) === 'free' && (await buttonVisible(p, 'Start')));
  checkTrue('4: Start listens again', await startListening(p));
  await led.send(port, [C]);
  checkTrue('4: ...and new datagrams add to the old totals', await waitRecords(p, led.records, 40_000),
    `${(await read(p)).records} vs ${led.records}`);
  await stopListening(p);
  await shutdown(r);
  const o = await oracle(profile);
  checkTrue('4: the journal on disk holds all 2 datagrams and 3 flows', o.datagrams === led.datagrams && o.records === led.records
    && o.octets === led.octets && o.packets === led.packets, json(o));
});

// --- 5 and 8: reload, and the subscription's afterlife -------------------------------------------------------------

await scenario('5 and 8. page reload, and no duplicate feed', async () => {
  const profile = tempProfile('r');
  const port = await freePort();
  const led = new Ledger();
  seed(profile, port);
  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  await startListening(p);
  await led.send(port, [A]);
  checkTrue('5: one record before the reload', await waitRecords(p, led.records));
  const pid = await monitoringPid(r.app);

  const reloading = p.reload({ waitUntil: 'domcontentloaded' });
  await led.send(port, [B]); // while the page is going
  await reloading;
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  await openSheet(p);
  checkTrue('5: the UI reconnects after the reload: the listener is still on', await until(() => buttonVisible(p, 'Stop'), 30_000));
  checkTrue('5: ...and the datagram sent during the reload is counted: no gap', await waitRecords(p, led.records, 40_000),
    `${(await read(p)).records} vs ${led.records}`);
  checkTrue('5: ...by the same utility process', pid !== null && (await monitoringPid(r.app)) === pid);
  checkTrue('5: ...and the port was held throughout', (await bindProbe(port)) !== 'free');

  // 8. Close and reopen the sheet, and reload, repeatedly; every cycle sends one more datagram.
  for (let i = 0; i < 3; i++) {
    await closeSheet(p);
    await led.send(port, [C]);
    await openSheet(p);
    await waitRecords(p, led.records, 30_000);
  }
  await p.reload();
  await p.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  await led.send(port, [A]);
  await openSheet(p);
  checkTrue('8: after three close/reopen cycles and a second reload, the totals are exact: nothing is counted twice',
    await waitRecords(p, led.records, 40_000), `${(await read(p)).records} vs ${led.records}`);
  await sleep(6000);
  const t = await tables(p);
  checkTrue('8: ...they stay exact after another refresh', (await read(p)).records === led.records
    && same(t.endpoints, led.endpoints()), `${(await read(p)).records} vs ${led.records}`);
  const sourceText = (await read(p)).text;
  checkTrue('8: ...and the Source row still shows that something was received before the reload, without waiting for a new datagram',
    !/Nothing received from the exporter yet/.test(sourceText), `the sheet reads "Nothing received from the exporter yet" after a reload (the Worker's health restarts on connect; the utility's count does not)`);
  await led.send(port, [B]);
  // Accepted is the Worker's own counter, so it restarts with a new Worker; after one datagram it must be live again.
  checkTrue('8: ...and one more datagram brings the Source row back to life (Accepted counts again)', await until(async () => ((await read(p)).accepted ?? 0) >= 1, 20_000),
    `Accepted ${(await read(p)).accepted} (of ${led.datagrams} sent in all; the counter is per Worker)`);
  checkTrue('8: ...with the records still exact', await waitRecords(p, led.records, 30_000), `${(await read(p)).records} vs ${led.records}`);
  checkTrue('8: there is one live feed: exactly one monitoring Worker', workerUrls(p, 'monitoring.worker').length === 1,
    json(workerUrls(p, 'monitoring.worker')));
  checkTrue('8: ...and one utility process', (await monitoringPid(r.app)) === pid);
  await stopListening(p);
  await shutdown(r);
  const o = await oracle(profile);
  checkTrue('8: the journal holds exactly what was sent', o.datagrams === led.datagrams && o.records === led.records, json(o));
});

// --- 6: the port is taken -----------------------------------------------------------------------------------------

await scenario('6. occupied port', async () => {
  const profile = tempProfile('o');
  const port = await freePort();
  const led = new Ledger();
  seed(profile, port);
  const holder = await hold(port);
  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  await p.getByRole('button', { name: 'Start', exact: true }).click();
  checkTrue('6: Start shows the bind error', await until(async () => /already in use/.test(await sheetText(p)), 20_000),
    (await sheetText(p)).slice(0, 300));
  const t = await sheetText(p);
  checkTrue('6: ...in the header as well: Could not listen', /Could not listen/.test(t));
  checkTrue('6: ...and nothing is journaled: the history is empty',
    /No history yet|No received traffic records yet/.test(t) && !/received traffic records in/.test(t), t.slice(0, 300));
  checkTrue('6: ...and Start is offered again', await buttonVisible(p, 'Start'));

  await new Promise<void>((resolve) => holder.close(() => resolve()));
  checkTrue('6: with the port released, Start works', await startListening(p));
  await led.send(port, [A]);
  checkTrue('6: ...and a datagram is counted', await waitRecords(p, led.records));
  await stopListening(p);
  await shutdown(r);
  const o = await oracle(profile);
  checkTrue('6: the journal holds the one datagram and nothing from the failed Start', o.datagrams === 1 && o.records === 1, json(o));
  note(`boundaries in the journal: ${o.boundaries.join(', ')}`);
});

// --- 7: the quit confirm -----------------------------------------------------------------------------------------

await scenario('7. unsaved capture, then the window closed', async () => {
  const profile = tempProfile('q');
  const port = await freePort();
  const led = new Ledger();
  seed(profile, port);
  const r = await launch(profile);
  const { app, p } = r;
  await openSheet(p);
  await startListening(p);
  await led.send(port, [A]);
  await led.send(port, [B]);
  await waitRecords(p, led.records);
  await closeSheet(p);

  await p.getByRole('button', { name: 'Interfaces' }).click();
  await p.getByText('Ethernet', { exact: true }).first().click();
  await p.getByLabel('Start capture').click();
  checkTrue('7: a stub capture holds unsaved frames', await until(async () => (await countsOf(p))[0] > 10, 20_000));

  const requestClose = () => app.evaluate(({ BrowserWindow }) => { BrowserWindow.getAllWindows()[0]?.close(); });
  await requestClose();
  const keep = p.getByRole('button', { name: 'Keep capturing' });
  checkTrue('7: closing the window raises the Quit Inwire? confirm', await until(() => keep.isVisible(), 8000));
  await keep.click();
  checkTrue('7: Keep capturing keeps the window open', await until(async () => (await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length)) === 1, 5000));
  await openSheet(p);
  checkTrue('7: ...monitoring is still listening', await buttonVisible(p, 'Stop'));
  await led.send(port, [C]);
  checkTrue('7: ...and still counting', await waitRecords(p, led.records, 30_000), `${(await read(p)).records} vs ${led.records}`);
  await closeSheet(p);

  const closed = new Promise<boolean>((resolve) => { app.once('close', () => resolve(true)); setTimeout(() => resolve(false), 45_000); });
  await requestClose();
  const quit = p.getByRole('button', { name: 'Quit', exact: true });
  checkTrue('7: closing again raises the confirm again', await until(() => quit.isVisible(), 8000));
  await led.send(port, [A]); // sent just before the quit is accepted
  await quit.click();
  checkTrue('7: Quit quits the app', await closed);
  live.delete(app);

  const o = await oracle(profile);
  checkTrue('7: every datagram sent before the close is in the journal', o.datagrams === led.datagrams && o.records === led.records
    && o.octets === led.octets, `${json(o)} vs ${led.datagrams}/${led.records}`);
  const lastStop = [...o.boundaries].reverse().find((b) => b.startsWith('stop:')) ?? '';
  checkTrue('7: ...and the session was closed by the quit drain (stop reason quit)', /quit/i.test(lastStop), json(o.boundaries));

  const again = await launch(profile);
  await openSheet(again.p);
  checkTrue('7: reopened, history holds every record', await waitRecords(again.p, led.records, 60_000),
    `${(await read(again.p)).records} vs ${led.records}`);
  checkTrue('7: ...and the status says it stopped when Inwire last quit',
    (await sheetText(again.p)).includes('Stopped when Inwire last quit.'), (await sheetText(again.p)).slice(0, 300));
  checkTrue('7: ...with nothing listening', (await bindProbe(port)) === 'free' && (await buttonVisible(again.p, 'Start')));
});

// --- 9: the sidecar deleted -----------------------------------------------------------------------------------------

await scenario('9. sidecar deletion', async () => {
  const first = await launch(profileA);
  await openSheet(first.p);
  const okBefore = await waitRecords(first.p, ledgerA.records, 60_000);
  const rowsBefore = await tables(first.p);
  const recordsBefore = (await read(first.p)).records;
  await shutdown(first);
  const sidecar = path.join(profileA, 'monitoring', 'rollups.iwmr');
  checkTrue('9: there is a sidecar to delete', existsSync(sidecar));
  const size = existsSync(sidecar) ? statSync(sidecar).size : 0;
  rmSync(sidecar, { force: true });
  checkTrue(`9: the sidecar (${size} bytes) is deleted with the app closed`, !existsSync(sidecar));

  const second = await launch(profileA);
  await openSheet(second.p);
  checkTrue('9: history is rebuilt: the same 2 records', okBefore && (await waitRecords(second.p, ledgerA.records, 90_000)),
    `${recordsBefore} -> ${(await read(second.p)).records}`);
  const rowsAfter = await tables(second.p);
  checkTrue('9: ...the same top endpoints', same(rowsAfter.endpoints, rowsBefore.endpoints) && same(rowsAfter.endpoints, ledgerA.endpoints()),
    json([rowsBefore.endpoints, rowsAfter.endpoints]));
  checkTrue('9: ...and the same top conversations', same(rowsAfter.conversations, rowsBefore.conversations), json([rowsBefore.conversations, rowsAfter.conversations]));
  await shutdown(second);
  checkTrue('9: the app wrote a sidecar again', existsSync(sidecar));
  const o = await oracle(profileA);
  checkTrue('9: the journal itself was not touched: 1 datagram, 2 flows', o.datagrams === 1 && o.records === 2, json(o));
});

// --- 10: the storage limit -----------------------------------------------------------------------------------------

await scenario('10. storage limit', async () => {
  const profile = tempProfile('s');
  const port = await freePort();
  seed(profile, port, 16 * MiB);
  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  await startListening(p);
  // Random bytes under a version the decoder does not read: journaled whole, incompressible.
  const junk = () => { const b = randomBytes(60_000); b[0] = 0; b[1] = 9; return b; };
  let sent = 0;
  let stopped = false;
  for (; sent < 700 && !stopped; sent++) {
    await sendRaw(port, junk());
    if (sent % 10 === 0) { await sleep(25); stopped = /reached its storage limit/.test(await sheetText(p)); }
  }
  note(`${sent} datagrams of 60,000 bytes sent against a 16 MiB limit`);
  checkTrue('10: the sheet says the history reached its storage limit', stopped || await until(
    async () => /reached its storage limit/.test(await sheetText(p)), 20_000), (await sheetText(p)).slice(0, 300));
  const t = await sheetText(p);
  checkTrue('10: ...the Storage row reads Full', /Full/.test(t), t.slice(0, 600));
  checkTrue('10: ...the listener has stopped: Start is offered, not Stop', (await buttonVisible(p, 'Start')) && !(await buttonVisible(p, 'Stop')));
  checkTrue('10: ...the header line itself carries the stop, not a calm Receiving', /storage limit/.test(t.split(/\r?\n/).map((l) => l.trim()).filter(Boolean)[1] ?? ''),
    t.replace(/\s+/g, ' ').slice(0, 300));
  checkTrue('10: ...and the socket is released', await until(async () => (await bindProbe(port)) === 'free', 10_000));
  const acceptedAtStop = (await read(p)).accepted;
  for (let i = 0; i < 5; i++) { await sendRaw(port, junk()); await sleep(20); }
  await sleep(3000);
  checkTrue('10: datagrams after the stop are not counted', (await read(p)).accepted === acceptedAtStop,
    `${acceptedAtStop} -> ${(await read(p)).accepted}`);
  await shutdown(r);
  const o = await oracle(profile);
  checkTrue('10: the journal on disk holds only what was recorded before the stop', o.datagrams > 100 && o.datagrams <= sent,
    `${o.datagrams} of ${sent}`);
  notRan('10: storage-failed', 'a mid-run write failure needs a seam (a failing volume) that the built app does not have: an open journal handle cannot be broken from outside on Windows without a full disk');
});

// --- 11: the capture is independent --------------------------------------------------------------------------------

await scenario('11. capture independence', async () => {
  const profile = tempProfile('c');
  const port = await freePort();
  const led = new Ledger();
  seed(profile, port);
  const files = mkdtempSync(path.join(tmpdir(), 'inwire-mondrive-pcap-'));
  profiles.push(files);
  const frames = Array.from({ length: 25 }, (_, i) => dnsQuery(0x100 + i));
  const pcap = new Uint8Array(24 + frames.reduce((n, f) => n + 16 + f.length, 0));
  const view = new DataView(pcap.buffer);
  view.setUint32(0, 0xa1b2c3d4, true); view.setUint16(4, 2, true); view.setUint16(6, 4, true);
  view.setUint32(16, 262144, true); view.setUint32(20, 1, true);
  let at = 24;
  frames.forEach((f, i) => {
    view.setUint32(at, 1_700_000_000 + i, true); view.setUint32(at + 8, f.length, true); view.setUint32(at + 12, f.length, true);
    pcap.set(f, at + 16); at += 16 + f.length;
  });
  const pcapPath = path.join(files, 'small.pcap');
  writeFileSync(pcapPath, pcap);

  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  await startListening(p);
  await led.send(port, [A, B]);
  await waitRecords(p, led.records);
  const base = { read: await read(p), tables: await tables(p) };
  const unchanged = async (when: string) => {
    await openSheet(p);
    const ok = await waitRecords(p, led.records, 20_000);
    const now = { read: await read(p), tables: await tables(p) };
    checkTrue(`11: ${when}, monitoring totals are unchanged`, ok && now.read.accepted === base.read.accepted
      && same(now.tables, base.tables) && (await buttonVisible(p, 'Stop')), json([base.read.records, now.read.records, now.read.accepted]));
    await closeSheet(p);
  };
  await closeSheet(p);

  await p.getByRole('button', { name: 'Interfaces' }).click();
  await p.getByText('Ethernet', { exact: true }).first().click();
  await p.getByLabel('Start capture').click();
  checkTrue('11: a stub capture runs', await until(async () => (await countsOf(p))[0] > 10, 20_000));
  await unchanged('while a capture runs');
  await p.getByLabel('Stop capture').click();
  await sleep(500);

  await p.getByRole('button', { name: 'Settings', exact: true }).click();
  await p.getByRole('button', { name: 'Capture Health' }).first().click();
  await p.getByRole('button', { name: 'Clear View' }).click();
  checkTrue('11: Clear View empties the list', await until(async () => (await countsOf(p))[0] === 0, 15_000), json(await countsOf(p)));
  await p.keyboard.press('Escape');
  await sleep(500);
  await unchanged('after the capture is cleared');

  await p.getByLabel('Export or import a capture').click();
  await sleep(600);
  await p.getByRole('button', { name: /^import$/i }).click({ timeout: 2000 }).catch(() => {});
  await sleep(300);
  await p.locator('input[type="file"]').first().setInputFiles(pcapPath);
  checkTrue('11: the synthetic pcap is imported (25 frames)', await until(async () => (await countsOf(p))[1] >= 25, 60_000), json(await countsOf(p)));
  await p.keyboard.press('Escape');
  await sleep(500);
  await unchanged('after the import');
  await stopListening(p).catch(() => false);
  await shutdown(r);
});

// --- the end ---------------------------------------------------------------------------------------------------------

sender.close();
await closeAll();
await agent.close();
for (const dir of process.env.DRIVE_KEEP ? [] : profiles) {
  try { rmSync(dir, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }); } catch { note(`could not remove ${dir}`); }
}
if (process.env.DRIVE_KEEP) note(`kept: ${profiles.join(' ')}`);
const secs = ((Date.now() - T0) / 1000).toFixed(0);
console.log(`\n${failures === 0 ? 'All monitoring fault checks passed' : `${failures} monitoring fault check(s) failed`}`
  + `${notRun.length > 0 ? `; ${notRun.length} NOT RUN (${notRun.join('; ')})` : ''} - ${secs} s.`);
process.exit(failures === 0 ? 0 : 1);
