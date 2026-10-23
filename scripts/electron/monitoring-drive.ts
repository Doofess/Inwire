/**
 * NetFlow v5, v9 and IPFIX monitoring under fault, through the real built app,
 * against datagrams this script sends itself to loopback ports.
 *
 *   npx tsx scripts/electron/monitoring-drive.ts [--lifetime]
 *
 * `monitoring-ui.ts` proves the sheet works when nothing goes wrong. This
 * proves what happens when something does, in sixteen scenarios:
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
 *   13. a v9 exporter restarts mid-run: data sets that wait for a template are
 *       kept and counted, never decoded; the next template recovers
 *   14. the app restarted within the template lifetime: data-only v9 decodes
 *   15. the app restarted past the template lifetime (31 minutes of wall clock,
 *       so behind --lifetime): data-only v9 waits for a template
 *   16. retention expires the oldest segments during v9 collection: data-only
 *       datagrams still decode and the whole run still adds up (aggregate-only)
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
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { inflateRawSync } from 'node:zlib';
import type { ElectronApplication, Page } from 'playwright';
import { startStubAgent, dnsQuery, type StubAgent } from './stubAgent';
import { launchApp } from './launchApp';
import { V9_SAMPLE_RECORD_BYTES, v5Payload, v9DataOnly, v9Sample } from '../monitoring/fixtures';
import { formatBytes } from '../../src/lib/formatBytes';
import { NodeBlockFile } from '../../src/services/capture/nodeBlockFile';
import { MonitoringJournal } from '../../src/services/monitoring/journal';
import { NodeSegmentDirectory } from '../../electron/monitoring/volume';
import { LocalArchiveSource, LocalRuntime } from '../../src/services/monitoring/localRuntime';
import { ArchiveStore } from '../../src/services/monitoring/archive';
import { DecodeState } from '../../src/services/monitoring/decodeState';
import { FILE_HEADER_BYTES } from '../../src/services/monitoring/journalCodec';
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
    // The Reported line of the sheet's facts: "<bytes> and <packets> packets in <n> records, <range>".
    records: digits(text.match(/packets in (\d[\d.,\s\u00a0\u202f]*?)\s+records,/)?.[1]),
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
  note(`the sheet read: ${text.match(/Read from [^\n]+/)?.[0] ?? '(no "Read from" line)'}`);
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
    /No history yet|No received traffic records yet/.test(t) && !/packets in [\d.,\s\u00a0\u202f]+ records,/.test(t), t.slice(0, 300));
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

// --- 13 to 16: NetFlow v9 under fault ---------------------------------------------------------------------------------
//
// The expected totals are the ledger of what this script sent, split into what a collector can decode (a template
// was in force) and what it cannot (a data set that arrived before its template). The product promises to keep the
// second kind in the journal, count it, and never decode it later; the ledger is authored here and nowhere else.

const V9_SOURCE_ID = 7;
const V9_KEY = `v9:${EXPORTER}/${V9_SOURCE_ID}`;
const V9_CARD = `NetFlow v9, source ID ${V9_SOURCE_ID}`;
const UPTIME0 = 3_600_000;

/** What this script has sent to one profile as v9 from source ID 7, by whether a collector could decode it. */
class V9Ledger {
  records = 0; octets = 0; packets = 0;
  datagrams = 0;
  awaitingSets = 0; awaitingBytes = 0;
  lastWaited: number | null = null;
  private sequence = 0;
  /**
   * `template` sends template 256 with the data (what an exporter does when it refreshes); without it the datagram
   * is a data set alone. `decodable` is the script's own claim about what the collector holds at that moment.
   */
  async send(port: number, o: { uptime: number; flows: Flow[]; template: boolean; decodable: boolean }): Promise<void> {
    const h = { uptime: o.uptime, secs: Math.floor(Date.now() / 1000), sequence: this.sequence++, sourceId: V9_SOURCE_ID };
    const bytes = o.template ? v9Sample(h, o.flows, null) : v9DataOnly(h, o.flows);
    await sendRaw(port, bytes);
    this.datagrams++;
    if (o.decodable || o.template) {
      this.records += o.flows.length;
      for (const f of o.flows) { this.octets += f.octets; this.packets += f.packets; }
    } else {
      this.awaitingSets++;
      this.awaitingBytes += 4 + o.flows.length * V9_SAMPLE_RECORD_BYTES;
      this.lastWaited = 256;
    }
  }
}

const norm = (s: string) => s.replace(/\s+/g, ' ');
const v9Card = (p: Page) => p.locator(`${SHEET} section[aria-labelledby="monitoring-exporter"] section[aria-label="${V9_CARD}"]`);
const cardText = (p: Page) => v9Card(p).innerText().then(norm).catch(() => '');
const cardHas = (p: Page, text: string) => async () => (await cardText(p)).includes(text);
const awaitingLine = (sets: number, bytes: number, id: number) =>
  `${new Intl.NumberFormat(undefined).format(sets)} data ${sets === 1 ? 'set' : 'sets'} (${formatBytes(bytes)}) arrived before ${sets === 1 ? 'its' : 'their'} template: kept, records unknown; last waited for template ${id}`;
/** The Source block's "Data sets waiting for a template: N" counter; null when it is not shown (zero is not shown). */
async function waitingCounter(p: Page): Promise<number | null> {
  const m = norm(await sheetText(p)).match(/Data sets waiting for a template: ([\d.,  ]+)/);
  return m ? digits(m[1]) : null;
}

/** Waits for the wall-clock minute after `sentAt` to close, so the rollup sidecar has something to hold. */
async function minuteCloses(sentAt: number): Promise<void> {
  const until1 = (Math.floor(sentAt / 60_000) + 1) * 60_000 + 4000;
  if (until1 > Date.now()) { note(`waiting ${Math.ceil((until1 - Date.now()) / 1000)} s for the minute to close`); await sleep(until1 - Date.now()); }
}

interface Sum {
  matchingRecords: number; octets: bigint; packets: bigint; awaitingTemplate: number; awaitingBytes: number;
  coverage: string[]; rollupMinutes: number; rawMinutes: number;
}
const sumOf = (r: HistoryResult): Sum => ({
  matchingRecords: r.matchingRecords,
  octets: r.buckets.reduce((n, b) => n + (b.reportedOctets ?? 0n), 0n),
  packets: r.buckets.reduce((n, b) => n + (b.reportedPackets ?? 0n), 0n),
  awaitingTemplate: r.awaitingTemplate, awaitingBytes: r.awaitingBytes,
  coverage: [...new Set(r.buckets.map((b) => b.coverage))].sort(),
  rollupMinutes: r.answeredFrom.rollupMinutes, rawMinutes: r.answeredFrom.rawMinutes,
});

interface V9Oracle {
  datagrams: number; boundaries: string[]; firstEntryId: number; sidecar: string;
  /** The retained journal replayed through the repo's decoder, from empty state or from the archive's last cut; null where neither is possible. */
  replay: { records: number; octets: number; packets: number; awaitingSets: number; awaitingBytes: number; restarts: number } | null;
  rollup: Sum | null; raw: Sum | null;
  /** The all-raw answer for the range from the first retained entry on: no expired time in it, so every bucket has counters. */
  rawRetained: Sum | null;
  /** Whether the rollup answer and the raw answer are the same answer; null where one could not be asked. */
  equal: boolean | null; why: string;
}

/**
 * Reads the monitoring directory of a CLOSED app with the repo's codecs, on a copy, and asks the v9 source's
 * history over the whole run twice: from the rollups and from the journal. With an archive it serves the expired part.
 */
async function oracleV9(profile: string, startMs: number): Promise<V9Oracle> {
  const copy = mkdtempSync(path.join(tmpdir(), 'inwire-mondrive-oracle-'));
  profiles.push(copy);
  cpSync(path.join(profile, 'monitoring'), copy, { recursive: true });
  const segments = new NodeSegmentDirectory(copy);
  const sf = NodeBlockFile.open(path.join(copy, 'rollups.iwmr'));
  let af: NodeBlockFile | null = null;
  try {
    let archive: ArchiveStore | null = null;
    let lastCut = 0;
    const archivePath = path.join(copy, 'archive.iwma');
    if (existsSync(archivePath) && statSync(archivePath).size >= FILE_HEADER_BYTES) {
      af = NodeBlockFile.open(archivePath);
      archive = ArchiveStore.open(af, { generation: new Uint8Array(16), createdMs: 0 }).store;
      lastCut = archive.lastCut()?.throughEntryId ?? 0;
    }
    const { journal } = MonitoringJournal.open(segments, { limitBytes: 1 << 30, lastCutThroughEntryId: lastCut });
    const snap = journal.snapshot();
    const entries: Evidence[] = [];
    for (let after = Math.max(0, snap.firstEntryId - 1); ;) {
      const page = journal.readPage(snap, after, 256, 1 << 20);
      entries.push(...page.entries);
      after = page.nextAfterId;
      if (page.done) break;
    }
    const out: V9Oracle = {
      datagrams: entries.filter((e) => e.kind === 'datagram').length,
      boundaries: entries.flatMap((e) => (e.kind === 'boundary' ? [`${e.action}:${e.reason}`] : [])),
      firstEntryId: snap.firstEntryId, sidecar: '', replay: null, rollup: null, raw: null, rawRetained: null, equal: null, why: '',
    };
    // From empty state while the journal's head is there; else from the template state the archive's last cut kept
    // (the state through the entry the expiry took out), which is what a replay of the retained journal starts from.
    const cut = archive === null ? null : archive.lastCut();
    const ds = snap.firstEntryId <= 1 ? DecodeState.empty() : cut !== null && cut.throughEntryId === snap.firstEntryId - 1 ? DecodeState.fromCheckpoint(cut.checkpoint) : null;
    if (ds !== null) {
      const r = { records: 0, octets: 0, packets: 0, awaitingSets: 0, awaitingBytes: 0, restarts: 0 };
      for (const e of entries) {
        const s = ds.step(e);
        if (s === null || s.kind !== 'datagram' || s.decoded.kind !== 'valid') continue;
        for (const f of s.decoded.flows) { r.records++; r.octets += Number(f.reportedOctets); r.packets += Number(f.reportedPackets); }
        for (const a of s.decoded.awaiting) { r.awaitingSets += a.sets; r.awaitingBytes += a.bytes; }
        if (s.decoded.restart) r.restarts++;
      }
      out.replay = r;
    }
    const opened = RollupStore.open(
      sf, { generation: snap.generation, throughEntryId: snap.throughEntryId }, { nowMs: () => Date.now() },
    );
    out.sidecar = opened.status;
    const rt = new LocalRuntime(
      journal, opened.store, opened.reason === undefined ? { status: opened.status } : { status: opened.status, reason: opened.reason },
      archive === null ? undefined : new LocalArchiveSource(archive),
    );
    const nowMs = Date.now();
    // One-minute, minute-aligned buckets: the planner folds a rollup minute only when the whole minute is inside one bucket.
    const fromMs = Math.floor(startMs / 60_000) * 60_000;
    const minutes = Math.floor(nowMs / 60_000) + 1 - Math.floor(startMs / 60_000);
    if (minutes > 120) { out.why = `the run is ${minutes} minutes long, more than the 120 buckets a query takes`; return out; }
    const spec: QuerySpec = { sourceKey: V9_KEY, fromMs, toMs: fromMs + minutes * 60_000, bucketCount: minutes };
    const ask = async (forceRaw: boolean): Promise<HistoryResult | null> => {
      const r = await runHistoryQuery(rt, rt, spec, new AbortController().signal, { inflate, nowMs, forceRaw, ...(rt.archive === undefined ? {} : { archive: rt.archive }) });
      if (!r.ok) out.why += `${forceRaw ? 'raw' : 'rollup'} query refused: ${r.code}: ${r.message}. `;
      return r.ok ? r.value : null;
    };
    const viaRollups = await ask(false);
    const viaRaw = await ask(true);
    if (viaRollups !== null) out.rollup = sumOf(viaRollups);
    const firstRetained = entries.find((e) => e.kind === 'datagram');
    if (snap.firstEntryId > 1 && firstRetained !== undefined) {
      const r = await runHistoryQuery(rt, rt, { sourceKey: V9_KEY, fromMs: firstRetained.receivedMs, toMs: nowMs + 1, bucketCount: 1 },
        new AbortController().signal, { inflate, nowMs, forceRaw: true, ...(rt.archive === undefined ? {} : { archive: rt.archive }) });
      if (r.ok) out.rawRetained = sumOf(r.value); else out.why += `retained raw query refused: ${r.code}: ${r.message}. `;
    }
    if (viaRaw !== null) out.raw = sumOf(viaRaw);
    if (viaRollups !== null && viaRaw !== null) {
      const project = (r: HistoryResult) => json({
        buckets: r.buckets, endpoints: r.endpoints, conversations: r.conversations, matchingRecords: r.matchingRecords,
        malformed: r.malformed, unsupported: r.unsupported, awaitingTemplate: r.awaitingTemplate, awaitingBytes: r.awaitingBytes,
      });
      out.equal = project(viaRollups) === project(viaRaw);
    }
    return out;
  } finally {
    segments.close();
    sf.close();
    af?.close();
  }
}

/** The ledger's decodable totals against an answer of the history query; the two paths are held to the same numbers. */
function totalsMatch(s: Sum | null, led: V9Ledger): boolean {
  return s !== null && s.matchingRecords === led.records && s.octets === BigInt(led.octets) && s.packets === BigInt(led.packets)
    && s.awaitingTemplate === led.awaitingSets && s.awaitingBytes === led.awaitingBytes;
}

const sumText = (s: Sum | null) => (s === null ? 'null' : json(s));

function checkOracle(tag: string, o: V9Oracle, led: V9Ledger): void {
  checkTrue(`${tag}: the journal holds every datagram sent (${led.datagrams})`, o.datagrams === led.datagrams, `${o.datagrams} vs ${led.datagrams}`);
  if (o.replay === null) notRan(`${tag}: journal replay`, `the journal's head is gone (first entry id ${o.firstEntryId}), so a replay from empty state has no templates`);
  else {
    checkTrue(`${tag}: ...replayed from empty state, the journal decodes to exactly the ledger's records, bytes and packets`,
      o.replay.records === led.records && o.replay.octets === led.octets && o.replay.packets === led.packets, json([o.replay, led.records, led.octets, led.packets]));
    checkTrue(`${tag}: ...and holds ${led.awaitingSets} data set(s) (${led.awaitingBytes} B) that waited for a template`,
      o.replay.awaitingSets === led.awaitingSets && o.replay.awaitingBytes === led.awaitingBytes, json(o.replay));
  }
  checkTrue(`${tag}: the history from the rollups equals the ledger of decodable records only`, totalsMatch(o.rollup, led),
    `${sumText(o.rollup)} vs records ${led.records} octets ${led.octets} packets ${led.packets} awaiting ${led.awaitingSets}/${led.awaitingBytes}; ${o.why}`);
  checkTrue(`${tag}: ...and so does the history read from the journal`, totalsMatch(o.raw, led), `${sumText(o.raw)}; ${o.why}`);
  if (o.equal === null) notRan(`${tag}: rollup answer equals raw answer`, o.why || 'a query was not asked');
  else checkTrue(`${tag}: ...the rollup answer equals the raw answer (${o.rollup?.rollupMinutes ?? 0} summarised, ${o.raw?.rawMinutes ?? 0} raw minute(s))`, o.equal);
}

const flowsOf = (...f: Flow[]): Flow[] => f;

// --- 13: the exporter restarts -------------------------------------------------------------------------------------

await scenario('13. v9 exporter restart mid-run', async () => {
  const profile = tempProfile('x');
  const port = await freePort();
  const led = new V9Ledger();
  seed(profile, port);
  const startMs = Date.now();
  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  checkTrue('13: Start listens', await startListening(p));

  await led.send(port, { uptime: UPTIME0, flows: flowsOf(A, B), template: true, decodable: true });
  checkTrue('13: the first export (template 256 and 2 records) reads as 2 records', await waitRecords(p, led.records), String((await read(p)).records));
  checkTrue('13: the source gets a card', await until(async () => (await v9Card(p).count()) === 1, 20_000));
  checkTrue('13: ...which says every data set had its template', await until(cardHas(p, 'Every data set had its template'), 10_000), await cardText(p));

  // The restart: the header uptime steps back from 3,600,000 ms to 5,000 ms, and the data arrives without its template.
  const restartAt = Date.now();
  for (let i = 0; i < 3; i++) {
    await led.send(port, { uptime: 5_000 + i * 1_000, flows: flowsOf(C), template: false, decodable: false });
    await sleep(40);
  }
  const line = awaitingLine(led.awaitingSets, led.awaitingBytes, 256);
  checkTrue('13: the card shows the No template line: 3 data sets, their bytes, last waited for template 256',
    await until(cardHas(p, line), 20_000), `wanted "${line}"; the card reads "${await cardText(p)}"`);
  checkTrue('13: ...and Restarts: 1', await until(cardHas(p, '1 restart: its templates were dropped and learned again'), 10_000), await cardText(p));
  checkTrue('13: ...the Source block counts the 3 data sets waiting for a template', await until(async () => (await waitingCounter(p)) === 3, 10_000),
    String(await waitingCounter(p)));
  await sleep(6500);
  checkTrue('13: the sheet\'s record count did not grow by those records', (await read(p)).records === 2, String((await read(p)).records));

  // Recovery: the exporter re-sends its template with new records.
  await led.send(port, { uptime: 9_000, flows: flowsOf(B, C, A), template: true, decodable: true });
  checkTrue(`13: recovery: the count grows by exactly the 3 new records (to ${led.records})`, await waitRecords(p, led.records), String((await read(p)).records));
  checkTrue('13: ...the 3 data sets that waited stay counted, never decoded later', await cardHas(p, line)(), await cardText(p));
  checkTrue('13: ...and the restart count is still 1', (await cardText(p)).includes('1 restart:'), await cardText(p));
  note(`restart to recovery: ${((Date.now() - restartAt) / 1000).toFixed(1)} s`);

  await minuteCloses(Date.now());
  await stopListening(p);
  await shutdown(r);
  checkOracle('13', await oracleV9(profile, startMs), led);
});

// --- 14 and 15: the app restarts ----------------------------------------------------------------------------------

/** One v9 template and its data, Stop, close, relaunch the same profile, Start, then data without a template. */
async function appRestart(tag: string, past: boolean): Promise<void> {
  const profile = tempProfile(past ? 'p' : 'l');
  const port = await freePort();
  const led = new V9Ledger();
  seed(profile, port);
  const startMs = Date.now();
  const first = await launch(profile);
  await openSheet(first.p);
  checkTrue(`${tag}: Start listens`, await startListening(first.p));
  await led.send(port, { uptime: UPTIME0, flows: flowsOf(A, B), template: true, decodable: true });
  const templateAt = Date.now();
  checkTrue(`${tag}: template 256 and 2 records are counted`, await waitRecords(first.p, led.records), String((await read(first.p)).records));
  checkTrue(`${tag}: Stop stops the listener`, await stopListening(first.p));
  await shutdown(first);

  if (past) {
    const wake = templateAt + 31 * 60_000 + 5000;
    note(`closed; waiting ${Math.ceil((wake - Date.now()) / 1000)} s so the template is over 30 minutes old`);
    await sleep(Math.max(0, wake - Date.now()));
  }

  const second = await launch(profile);
  const { p } = second;
  await openSheet(p);
  checkTrue(`${tag}: reopened, the history holds the ${led.records} records`, await waitRecords(p, led.records, 60_000), String((await read(p)).records));
  checkTrue(`${tag}: ...and nothing listens until Start is pressed`, (await bindProbe(port)) === 'free' && (await buttonVisible(p, 'Start')));
  checkTrue(`${tag}: Start listens again`, await startListening(p));

  // Data only, the uptime and the sequence continuing forward from where they were.
  const n = past ? 60 : 3;
  const sendAt = Date.now();
  for (let i = 0; i < n; i++) {
    await led.send(port, { uptime: UPTIME0 + 60_000 + i * 1_000, flows: flowsOf(C, A), template: false, decodable: !past });
    await sleep(past ? 25 : 60);
  }
  if (!past) {
    checkTrue(`${tag}: data-only datagrams decode: the count grows to ${led.records}`, await waitRecords(p, led.records, 40_000), String((await read(p)).records));
    checkTrue(`${tag}: ...and the card says every data set had its template`, await until(cardHas(p, 'Every data set had its template'), 20_000), await cardText(p));
    checkTrue(`${tag}: ...with nothing awaiting a template`, (await waitingCounter(p)) === null, String(await waitingCounter(p)));
    checkTrue(`${tag}: ...and no restart`, !(await cardText(p)).includes(' restart'), await cardText(p));
  } else {
    const line = awaitingLine(led.awaitingSets, led.awaitingBytes, 256);
    checkTrue(`${tag}: the template is over 30 minutes and 48 messages old: all ${n} data sets wait for a template`,
      await until(cardHas(p, line), 30_000), `wanted "${line}"; the card reads "${await cardText(p)}"`);
    await sleep(6500);
    checkTrue(`${tag}: ...none decoded: the count stays ${led.records}`, (await read(p)).records === led.records, String((await read(p)).records));
    checkTrue(`${tag}: ...the Source block counts ${n}`, (await waitingCounter(p)) === n, String(await waitingCounter(p)));
    checkTrue(`${tag}: ...and it was no restart: the uptime only moved forward`, !(await cardText(p)).includes(' restart'), await cardText(p));
  }
  note(`data sent ${((Date.now() - sendAt) / 1000).toFixed(1)} s after Start`);
  await minuteCloses(Date.now());
  await stopListening(p);
  await shutdown(second);
  checkOracle(tag, await oracleV9(profile, startMs), led);
}

await scenario('14. app restart within the template lifetime', () => appRestart('14', false));

const LIFETIME = process.argv.includes('--lifetime');
if (LIFETIME) await scenario('15. app restart past the template lifetime', () => appRestart('15', true));
else if (ONLY.length === 0 || ONLY.includes('15')) notRan('15', 'needs 31 minutes of wall clock; pass --lifetime');

// --- 16: retention expires segments during v9 collection ---------------------------------------------------------------

/** The first entry id of the oldest segment on disk, or 0 with none. */
function oldestSegmentId(profile: string): number {
  try {
    const ids = readdirSync(path.join(profile, 'monitoring')).flatMap((n) => {
      const m = /^journal-(\d+)\.iwmj$/.exec(n);
      return m ? [Number(m[1])] : [];
    });
    return ids.length === 0 ? 0 : Math.min(...ids);
  } catch { return 0; }
}

await scenario('16. retention expiry during v9 collection', async () => {
  const profile = tempProfile('e');
  const port = await freePort();
  const led = new V9Ledger();
  // The 16 MiB minimum, retention set to expire the oldest segments at the limit instead of stopping.
  mkdirSync(path.join(profile, 'monitoring'), { recursive: true });
  writeFileSync(path.join(profile, 'monitoring', 'settings.json'), JSON.stringify({
    version: 2, source: { exporterIPv4: EXPORTER, bindIPv4: '127.0.0.1', port, storageLimitBytes: 16 * MiB },
    location: null, retention: { keepRawDays: null, atLimit: 'expire-oldest' },
  }));
  const startMs = Date.now();
  const r = await launch(profile);
  const { p } = r;
  await openSheet(p);
  checkTrue('16: Start listens', await startListening(p));

  // 2,000 records of 29 bytes: 58 KB, close to the datagram maximum, so the limit comes quickly.
  const flows: Flow[] = Array.from({ length: 2000 }, (_, i) => ({
    src: `10.0.0.${1 + (i % 8)}`, dst: `10.0.1.${1 + (i % 8)}`, octets: 1000 + (i % 5000), packets: 10 + (i % 90),
  }));
  const t0 = Date.now();
  let uptime = UPTIME0;
  await led.send(port, { uptime, flows, template: true, decodable: true });
  let sent = 1;
  const MAX = 1200;
  while (sent < MAX && oldestSegmentId(profile) <= 1) {
    for (let i = 0; i < 4; i++) { uptime += 100; await led.send(port, { uptime, flows, template: false, decodable: true }); sent++; }
    await sleep(80);
  }
  const expiredAfter = (Date.now() - t0) / 1000;
  const expired = oldestSegmentId(profile) > 1;
  note(`${sent} datagrams of ~58 KB (${(sent * 58_028 / MiB).toFixed(0)} MiB) sent against a 16 MiB limit; ${expired ? `the oldest segment started at entry ${oldestSegmentId(profile)} after ${expiredAfter.toFixed(1)} s` : 'no segment expired'}`);
  checkTrue('16: at least one segment expired: the oldest segment file no longer starts at entry 1', expired);
  if (expired && expiredAfter > 300) note(`NOTE: the minimum limit made this run take ${expiredAfter.toFixed(0)} s, over the ~5 minutes allowed for`);

  // Template 256 was in the datagram that has expired: the live state must still decode data-only datagrams.
  for (let i = 0; i < 40; i++) {
    uptime += 100;
    await led.send(port, { uptime, flows, template: false, decodable: true });
    if (i % 4 === 3) await sleep(80);
  }
  const lastSentAt = Date.now();
  checkTrue(`16: after the expiry, data-only datagrams still decode: the count reaches all ${led.records.toLocaleString()} records`,
    await waitRecords(p, led.records, 60_000), `${(await read(p)).records} vs ${led.records}`);
  checkTrue('16: ...with every data set having its template', await until(cardHas(p, 'Every data set had its template'), 20_000), await cardText(p));
  checkTrue('16: ...nothing awaiting a template in the Source block', (await waitingCounter(p)) === null, String(await waitingCounter(p)));
  const t = await sheetText(p);
  checkTrue('16: ...and still listening: expiring made room instead of stopping', (await buttonVisible(p, 'Stop')) && !/reached its storage limit/.test(t), t.slice(0, 200));
  checkTrue('16: Accepted counts every datagram: none shed', (await read(p)).accepted === led.datagrams, `${(await read(p)).accepted} vs ${led.datagrams}`);

  await minuteCloses(lastSentAt);
  const sc = () => { try { return statSync(path.join(profile, 'monitoring', 'rollups.iwmr')).size; } catch { return -1; } };
  await stopListening(p);
  await shutdown(r);
  note(`rollups.iwmr after shutdown: ${sc()} B (64 B is the header alone: nothing summarised)`);
  const o = await oracleV9(profile, startMs);
  checkTrue('16: the journal records the expiry (an expired boundary) and starts after entry 1', o.boundaries.some((b) => b.startsWith('expired')) && o.firstEntryId > 1,
    `${json(o.boundaries)} first ${o.firstEntryId}`);
  checkTrue(`16: the retained journal holds fewer datagrams than were sent (${o.datagrams} of ${led.datagrams})`, o.datagrams < led.datagrams);
  checkTrue('16: the history over the whole run equals the ledger, expired part included (rollups + archive)', totalsMatch(o.rollup, led),
    `${sumText(o.rollup)} vs records ${led.records} octets ${led.octets} packets ${led.packets}; ${o.why}`);
  checkTrue('16: ...the expired part is reported as aggregate-only coverage', (o.rollup?.coverage ?? []).includes('aggregate-only'), json(o.rollup?.coverage));
  checkTrue('16: ...and no part of the run is history-lost', !(o.rollup?.coverage ?? []).includes('history-lost'), json(o.rollup?.coverage));
  // The all-raw answer reads the journal alone (`rawOrLost`: expired time is lost to it, by design), so it is held to the
  // retained journal replayed independently from the archive's last cut, not to the whole-run ledger.
  if (o.replay === null) notRan('16: the all-raw answer equals the retained journal replayed from the archive cut', 'the archive cut does not end at the journal head');
  else {
    const rp = o.replay;
    checkTrue('16: the retained journal, replayed from the archive cut template state, decodes every datagram (nothing awaits a template)',
      rp.awaitingSets === 0 && rp.records > 0 && rp.records < led.records, json([rp, led.records]));
    checkTrue('16: ...the all-raw answer over the whole run counts those records, and calls the expired part history-lost (it reads no archive)',
      o.raw !== null && o.raw.matchingRecords === rp.records && o.raw.awaitingTemplate === 0 && o.raw.coverage.includes('history-lost'), `${sumText(o.raw)} vs ${json(rp)}; ${o.why}`);
    checkTrue('16: ...and from the first retained entry on, the all-raw answer equals that replay (records, bytes, packets)',
      o.rawRetained !== null && o.rawRetained.matchingRecords === rp.records && o.rawRetained.octets === BigInt(rp.octets) && o.rawRetained.packets === BigInt(rp.packets) && o.rawRetained.awaitingTemplate === 0,
      `${sumText(o.rawRetained)} vs ${json(rp)}; ${o.why}`);
  }
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
