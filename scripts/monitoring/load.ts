/**
 * A stepped load measurement of the BUILT app's NetFlow monitoring.
 *
 *   npx tsx scripts/monitoring/load.ts [--quick] [--seed <n>] [--protocol v5|v9|ipfix]
 *
 * `--protocol` (default v5, which is unchanged) picks what the sender exports. With v9 or ipfix every datagram
 * carries a data set of the same recurring or unique address pairs under a template, and a template set rides in
 * the first datagram of each step and every 20th after it; the rest are data-only. A v9 datagram's uptime runs on
 * the wall clock across steps (a step back is an exporter restart), and an IPFIX sender keeps one source port for
 * the whole run (a new port is a new template scope). The pause case's sequence jump moves the protocol's own
 * sequence field: flows for v5, export packets for v9, data records for IPFIX.
 *
 * A measurement, not a test: it has no pass mark beyond running to the end, it
 * claims no capacity beyond the points it ran, and it is in `check.ts`'s NOT_TESTS.
 *
 * What runs (about ten minutes in full, about two with --quick):
 *
 *   1. the sweep: 2, 7 and 50 datagrams a second (Task 1's planning profile), then
 *      doublings, until acceptance falls below what was offered or the ceiling;
 *   2. the cases at a rate the sweep sustained: 1-record datagrams, 30-record
 *      datagrams, every record a new address pair, and a source pause that ends
 *      with a jump in the exporter's sequence numbering;
 *   3. restart: close, relaunch, time to the restored history; then again with the
 *      rollup sidecar deleted, which is the sidecar's rebuild;
 *   4. storage exhaustion, in a fresh profile whose limit is the 16 MiB minimum.
 *
 * Throughout phases 1 to 3 the sheet is open and its range is cycled, a Focus is
 * opened, and the stub agent runs a synthetic capture: that is the concurrent load.
 *
 * The sender is a worker thread (this same file), so its pacing is not starved by
 * the harness reading the sheet. Datagrams come from 127.0.0.1, the configured
 * exporter; once a second a stray one comes from 127.0.0.2, which the collector
 * must refuse and count.
 *
 * Everything the app does not expose prints `not exposed` rather than a number
 * made up: the collector's inbox depth, its JS heap and its commit/fsync latency.
 * What stands in for them is named where it is printed (the shed count; the
 * collector process's working set and private bytes).
 *
 * Isolation: a temporary INWIRE_USER_DATA, a per-pid pipe, a free loopback port,
 * the window parked in the background through launchApp. It reads the app that is
 * in `dist/` and `dist-electron/`; it does not build.
 */
import { execFileSync } from 'node:child_process';
import { createSocket } from 'node:dgram';
import { existsSync, mkdtempSync, readdirSync, rmSync, statSync, statfsSync } from 'node:fs';
import { cpus, platform, release, tmpdir, totalmem, version as osVersion } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { be, dataSet, ipfixMessage, templateRecord, templateSet, v9Message, type WireField } from './fixtures';

// --- the sender (runs in the worker) -----------------------------------------------------------------

type Protocol = 'v5' | 'v9' | 'ipfix';

interface SendJob {
  port: number;
  protocol: Protocol;
  /** The sender's own source port for v9 and IPFIX, kept for the whole run; 0 lets the system choose (v5). */
  srcPort: number;
  /** The wall clock at which a v9 header's uptime read UPTIME_BASE, so the uptime never steps back between steps. */
  uptimeEpochMs: number;
  rate: number;
  records: number;
  secs: number;
  unique: boolean;
  /** The next sequence value in the protocol's own unit: flows (v5), export packets (v9) or data records (IPFIX). */
  sequence: number;
  /** The next address-pair ordinal when every record is new. */
  uniqueNext: number;
  /** A datagram a second from 127.0.0.2, to be refused. */
  stray: boolean;
}
interface SendDone {
  sent: number;
  flows: number;
  errors: number;
  strays: number;
  sequence: number;
  uniqueNext: number;
  actualSecs: number;
  lateMsMax: number;
}

const HEADER = 24;
const RECORD = 48;
const UPTIME_BASE = 3_600_000;

function datagram(job: { records: number }, sequence: number, uptime: number, wallMs: number, firstOrdinal: number, unique: boolean): Buffer {
  const out = Buffer.alloc(HEADER + job.records * RECORD);
  out.writeUInt16BE(5, 0);
  out.writeUInt16BE(job.records, 2);
  out.writeUInt32BE(uptime >>> 0, 4);
  out.writeUInt32BE(Math.floor(wallMs / 1000) >>> 0, 8);
  out.writeUInt32BE(((wallMs % 1000) * 1_000_000) >>> 0, 12);
  out.writeUInt32BE(sequence >>> 0, 16);
  for (let i = 0; i < job.records; i++) {
    const p = HEADER + i * RECORD;
    const n = firstOrdinal + i;
    if (unique) {
      // 24 bits of source, and a destination from the low 16: every pair differs.
      out[p] = 10; out[p + 1] = (n >>> 16) & 255; out[p + 2] = (n >>> 8) & 255; out[p + 3] = n & 255;
      out[p + 4] = 192; out[p + 5] = 168; out[p + 6] = (n >>> 8) & 255; out[p + 7] = (n + 1) & 255;
    } else {
      const k = n % 8;
      out[p] = 10; out[p + 1] = 0; out[p + 2] = 0; out[p + 3] = 1 + k;
      out[p + 4] = 10; out[p + 5] = 0; out[p + 6] = 1; out[p + 7] = 1 + k;
    }
    out.writeUInt32BE(10 + (n % 90), p + 16);
    out.writeUInt32BE(1000 + (n % 5000), p + 20);
    out.writeUInt32BE((uptime - 5000) >>> 0, p + 24);
    out.writeUInt32BE((uptime - 100) >>> 0, p + 28);
    out.writeUInt16BE(40_000 + (n % 20_000), p + 32);
    out.writeUInt16BE(443, p + 34);
    out[p + 37] = 0x18;
    out[p + 38] = 6;
  }
  return out;
}

/** A refresh of the template goes in the first datagram and every 20th after it. */
const TEMPLATE_EVERY = 20;
const V9_TEMPLATE_ID = 256;
const IPFIX_TEMPLATE_ID = 300;
const V9_FIELDS: WireField[] = [
  { type: 8, length: 4 }, { type: 12, length: 4 }, { type: 7, length: 2 }, { type: 11, length: 2 }, { type: 4, length: 1 },
  { type: 1, length: 4 }, { type: 2, length: 4 }, { type: 22, length: 4 }, { type: 21, length: 4 },
];
const IPFIX_FIELDS: WireField[] = [
  { type: 8, length: 4 }, { type: 12, length: 4 }, { type: 7, length: 2 }, { type: 11, length: 2 }, { type: 4, length: 1 },
  { type: 1, length: 8 }, { type: 2, length: 8 }, { type: 150, length: 4 }, { type: 151, length: 4 },
];

/** The same flows as the v5 builder's, as data records of the template above. */
function templatedRecord(protocol: 'v9' | 'ipfix', n: number, unique: boolean, uptime: number, secs: number): number[] {
  const k = n % 8;
  const src = unique ? [10, (n >>> 16) & 255, (n >>> 8) & 255, n & 255] : [10, 0, 0, 1 + k];
  const dst = unique ? [192, 168, (n >>> 8) & 255, (n + 1) & 255] : [10, 0, 1, 1 + k];
  const octets = 1000 + (n % 5000);
  const packets = 10 + (n % 90);
  const head = [...src, ...dst, ...be.u16(40_000 + (n % 20_000)), ...be.u16(443), ...be.u8(6)];
  if (protocol === 'v9') return [...head, ...be.u32(octets), ...be.u32(packets), ...be.u32((uptime - 5000) >>> 0), ...be.u32((uptime - 100) >>> 0)];
  return [...head, ...be.uint(octets, 8), ...be.uint(packets, 8), ...be.u32((secs - 5) >>> 0), ...be.u32(secs >>> 0)];
}

function templated(
  job: { records: number; protocol: 'v9' | 'ipfix' }, sequence: number, uptime: number, wallMs: number, firstOrdinal: number,
  unique: boolean, withTemplate: boolean,
): Uint8Array {
  const secs = Math.floor(wallMs / 1000);
  const v9 = job.protocol === 'v9';
  const records = Array.from({ length: job.records }, (_, i) => templatedRecord(job.protocol, firstOrdinal + i, unique, uptime, secs));
  const sets: number[][] = [];
  if (withTemplate) sets.push(templateSet(v9 ? 9 : 10, [templateRecord(v9 ? 9 : 10, v9 ? V9_TEMPLATE_ID : IPFIX_TEMPLATE_ID, v9 ? V9_FIELDS : IPFIX_FIELDS)]));
  sets.push(dataSet(v9 ? V9_TEMPLATE_ID : IPFIX_TEMPLATE_ID, records));
  return v9
    ? v9Message({ uptime: uptime >>> 0, secs, sequence: sequence >>> 0, sourceId: 7, count: job.records + (withTemplate ? 1 : 0) }, sets)
    : ipfixMessage({ secs, sequence: sequence >>> 0, domain: 300 }, sets);
}

async function sender(job: SendJob): Promise<SendDone> {
  const sock = createSocket('udp4');
  await new Promise<void>((resolve) => sock.bind(job.srcPort, '127.0.0.1', resolve));
  let strayer: ReturnType<typeof createSocket> | null = null;
  if (job.stray) {
    const s = createSocket('udp4');
    strayer = await new Promise<ReturnType<typeof createSocket> | null>((resolve) => {
      s.once('error', () => resolve(null));
      s.bind(0, '127.0.0.2', () => resolve(s));
    });
  }
  let pending = 0;
  let errors = 0;
  let sent = 0;
  let strays = 0;
  let sequence = job.sequence;
  let uniqueNext = job.uniqueNext;
  let lateMsMax = 0;
  const pause = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
  const started = performance.now();
  const wall0 = Date.now();
  let nextStray = 1000;
  while (true) {
    const elapsed = performance.now() - started;
    if (elapsed >= job.secs * 1000) break;
    const due = Math.min(Math.floor((job.rate * elapsed) / 1000), Math.ceil(job.rate * job.secs));
    if (due > sent) lateMsMax = Math.max(lateMsMax, elapsed - (sent * 1000) / job.rate);
    while (sent < due) {
      const el = performance.now() - started;
      const buf = job.protocol === 'v5'
        ? datagram(job, sequence, UPTIME_BASE + Math.floor(el), wall0 + Math.floor(el), uniqueNext, job.unique)
        : templated({ records: job.records, protocol: job.protocol }, sequence, UPTIME_BASE + (Date.now() - job.uptimeEpochMs), wall0 + Math.floor(el),
          uniqueNext, job.unique, sent % TEMPLATE_EVERY === 0);
      sequence = (sequence + (job.protocol === 'v9' ? 1 : job.records)) >>> 0;
      uniqueNext += job.records;
      sent++;
      pending++;
      sock.send(buf, job.port, '127.0.0.1', (err) => { if (err) errors++; pending--; });
    }
    if (strayer && elapsed >= nextStray) {
      nextStray += 1000;
      strays++;
      strayer.send(datagram({ records: 1 }, 0, UPTIME_BASE + Math.floor(elapsed), wall0 + Math.floor(elapsed), 0, false), job.port, '127.0.0.1', (err) => { if (err) errors++; });
    }
    await pause(2);
  }
  const drainBy = performance.now() + 3000;
  while (pending > 0 && performance.now() < drainBy) await pause(5);
  const actualSecs = (performance.now() - started) / 1000;
  sock.close();
  strayer?.close();
  return { sent, flows: sent * job.records, errors, strays, sequence, uniqueNext, actualSecs, lateMsMax };
}

if (!isMainThread) {
  const done = await sender(workerData as SendJob);
  parentPort!.postMessage(done);
  process.exit(0);
}

// --- the harness (main thread only) ------------------------------------------------------------------

const argv = process.argv.slice(2);
const QUICK = argv.includes('--quick');
const protocolArg = argv.indexOf('--protocol');
const PROTOCOL: Protocol = protocolArg >= 0 ? (argv[protocolArg + 1] as Protocol) : 'v5';
if (PROTOCOL !== 'v5' && PROTOCOL !== 'v9' && PROTOCOL !== 'ipfix') {
  console.log(`NOT RUN  load: --protocol takes v5, v9 or ipfix (got ${JSON.stringify(argv[protocolArg + 1])})`);
  process.exit(2);
}
const PROTOCOL_NAME = { v5: 'NetFlow v5', v9: 'NetFlow v9', ipfix: 'IPFIX' }[PROTOCOL];
/** Records per datagram in the storage-exhaustion phase: a datagram near the size v5's 30 records make (~1.5 KB), so the limit comes in comparable time. */
const EXHAUST_RECORDS = { v5: 30, v9: 50, ipfix: 40 }[PROTOCOL];
const UPTIME_EPOCH_MS = Date.now();
const STEP_SECS = QUICK ? 4 : 12;
const CEILING = QUICK ? 200 : 3200;
const PAUSE_SECS = QUICK ? 6 : 65;
const EXHAUST_CAP_SECS = QUICK ? 40 : 90;
const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));
const fmt = (n: number, digits = 0): string => n.toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits });
const mb = (bytes: number): string => (bytes < 1024 * 1024 ? `${(bytes / 1024).toFixed(1)} KB` : `${(bytes / (1024 * 1024)).toFixed(1)} MB`);

function skip(why: string): never {
  console.log(`NOT RUN  load: ${why}`);
  process.exit(0);
}
if (platform() !== 'win32') skip('the desktop app is Windows-only - nothing to launch here');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'monitoring', 'monitoring.cjs'))) {
  skip('no build with monitoring to launch - run `npm run build` first');
}
try {
  await import('playwright');
} catch {
  skip('playwright is not installed');
}

const { startStubAgent } = await import('../electron/stubAgent');
const { launchApp } = await import('../electron/launchApp');
const { ROLLUP_FILE, monitoringRoot } = await import('../../electron/monitoring/volume');
const { isSegmentFileName } = await import('../../src/services/monitoring/segments');
type StubAgent = Awaited<ReturnType<typeof startStubAgent>>;
type App = Awaited<ReturnType<typeof launchApp>>;
type Page = Awaited<ReturnType<App['firstWindow']>>;

const SHEET = '[data-testid="monitoring-sheet"]';
const SELF = fileURLToPath(import.meta.url);
const failures: string[] = [];
const fail = (what: string): void => { failures.push(what); console.log(`FAILURE  ${what}`); };
const out = (line = ''): void => console.log(line);

async function freePort(): Promise<number> {
  const s = createSocket('udp4');
  await new Promise<void>((resolve) => s.bind(0, '127.0.0.1', resolve));
  const port = s.address().port;
  await new Promise<void>((resolve) => s.close(() => resolve()));
  return port;
}

/** One source port for every sender of the run when the protocol's template scope depends on it (IPFIX); v5 and v9 let the system choose. */
const SENDER_PORT = PROTOCOL === 'ipfix' ? await freePort() : 0;

function runSender(job: Omit<SendJob, 'protocol' | 'srcPort' | 'uptimeEpochMs'>): Promise<SendDone> {
  return new Promise((resolve, reject) => {
    const w = new Worker(SELF, { workerData: { ...job, protocol: PROTOCOL, srcPort: SENDER_PORT, uptimeEpochMs: UPTIME_EPOCH_MS } satisfies SendJob });
    w.once('message', (m: SendDone) => resolve(m));
    w.once('error', reject);
    w.once('exit', (code) => { if (code !== 0) reject(new Error(`sender exited ${code}`)); });
  });
}

// --- one app under test --------------------------------------------------------------------------------

interface Session {
  app: App;
  page: Page;
  agent: StubAgent;
  profile: string;
  port: number;
  pipe: string;
}

let sessionCount = 0;
async function launch(profile: string, agent: StubAgent, pipe: string): Promise<{ app: App; page: Page; launchMs: number }> {
  const t0 = performance.now();
  const app = await launchApp({ args: ['.'], env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: pipe } });
  const page = await app.firstWindow();
  page.setDefaultTimeout(30_000);
  await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
  await page.getByRole('button', { name: 'Skip' }).click({ timeout: 3000 }).catch(() => {});
  void agent;
  return { app, page, launchMs: performance.now() - t0 };
}

async function openSheet(p: Page): Promise<void> {
  await p.getByRole('button', { name: 'Statistics', exact: true }).click();
  await p.getByRole('button', { name: 'Network', exact: true }).click();
  await p.getByRole('button', { name: 'Open monitoring' }).click();
  await p.locator(SHEET).waitFor();
}

async function newSession(profile?: string): Promise<Session & { launchMs: number }> {
  const pipe = String.raw`\\.\pipe\inwire-load-` + process.pid + '-' + sessionCount++;
  const agent = await startStubAgent(pipe, 20);
  const dir = profile ?? mkdtempSync(path.join(tmpdir(), 'inwire-load-profile-'));
  const { app, page, launchMs } = await launch(dir, agent, pipe);
  const port = await freePort();
  return { app, page, agent, profile: dir, port, pipe, launchMs };
}

async function closeApp(s: { app: App; page: Page }): Promise<void> {
  // A running capture holds frames, and closing with frames asks "Quit Inwire?": clear it first.
  await s.page.evaluate(`window.inwire && window.inwire.setUnsavedCapture && window.inwire.setUnsavedCapture(false)`).catch(() => {});
  await s.app.close().catch(() => {});
}

const sheetText = (p: Page): Promise<string> => p.locator(SHEET).innerText().catch(() => '');
const digitsOf = (s: string | undefined): number => (s === undefined ? 0 : Number(s.replace(/[^\d]/g, '')) || 0);
const NUM = '([\\d.,\\s\\u00a0\\u202f]+)';

interface Counters {
  listener: string;
  freshness: 'never' | 'receiving' | 'stale' | 'unknown';
  accepted: number;
  malformed: number;
  unsupported: number;
  engineLimit: number;
  shed: number;
  refused: number;
  records: number | null;
  engine: { jumps: number; gaps: number; duplicates: number; reordered: number; resets: number; unresolved: number } | null;
  /** The v9 or IPFIX card's Numbering line (no v5 engine table exists for those); null when there is none. */
  numbering: string | null;
  written: number | null;
  limit: number | null;
  tablesNote: string | null;
}

async function readCounters(p: Page): Promise<Counters> {
  const t = await sheetText(p);
  const grab = (re: RegExp): number => digitsOf(new RegExp(re.source + NUM).exec(t)?.[1]);
  const listener = /Listener\s+([^\n]+)/.exec(t)?.[1]?.trim() ?? '(no listener line)';
  const freshness = /No recent export/.test(t) ? 'stale' : /Nothing received from the exporter yet/.test(t) ? 'never' : /Receiving|Last export/.test(t) ? 'receiving' : 'unknown';
  // The History facts line: "<bytes> and <packets> packets in <n> records, <range>".
  const rec = new RegExp('packets in ' + NUM + 'records,').exec(t);
  const numbering = /Numbering\s+([^\n]+)/.exec(t)?.[1]?.trim() ?? null;
  const engine = await p.evaluate(`(() => {
    const t = [...document.querySelectorAll('table')].find((x) => /Engines the exporter reported/.test(x.querySelector('caption')?.textContent ?? ''));
    const row = t?.querySelector('tbody tr');
    if (!row) return null;
    const n = [...row.querySelectorAll('td')].map((c) => Number((c.textContent || '').replace(/[^\\d]/g, '')) || 0);
    return { jumps: n[1], gaps: n[2], duplicates: n[3], reordered: n[4], resets: n[5], unresolved: n[6] };
  })()`) as Counters['engine'];
  const meter = await p.evaluate(`(() => {
    const m = document.querySelector('[role="meter"][aria-label="History storage used"]');
    return m ? { now: Number(m.getAttribute('aria-valuenow')), max: Number(m.getAttribute('aria-valuemax')) } : null;
  })()`) as { now: number; max: number } | null;
  const tablesNote = /(That range is too large to read|The history could not be read|[^\n]*Choose a shorter range to see this table[^\n]*)/.exec(t)?.[1]?.trim() ?? null;
  return {
    listener, freshness,
    accepted: grab(/Accepted\s+/),
    malformed: grab(/Malformed:\s*/), unsupported: grab(/Unsupported version:\s*/), engineLimit: grab(/Past the engine limit:\s*/),
    shed: grab(/Shed before writing:\s*/),
    refused: digitsOf(new RegExp('127\\.0\\.0\\.2\\s+' + NUM + 'datagram').exec(t)?.[1]),
    records: rec ? digitsOf(rec[1]) : null,
    engine, numbering, written: meter?.now ?? null, limit: meter?.max ?? null, tablesNote,
  };
}

/** Waits until Accepted holds still for two reads, so the Worker's tail is counted. */
async function settle(p: Page, capMs = 25_000): Promise<{ counters: Counters; settleMs: number }> {
  const t0 = performance.now();
  let last = await readCounters(p);
  let still = 0;
  while (performance.now() - t0 < capMs) {
    await sleep(1500);
    const now = await readCounters(p);
    still = now.accepted === last.accepted && now.shed === last.shed && now.malformed === last.malformed && now.refused === last.refused ? still + 1 : 0;
    last = now;
    if (still >= 2) break;
  }
  return { counters: last, settleMs: performance.now() - t0 };
}

// --- in-page instruments: plain strings, so no transpiler helper lands in the page ---------------------------

const RESPONSIVENESS = `(() => {
  if (window.__resp) return true;
  const s = window.__resp = { lt: [], gaps: [], last: performance.now(), unsupported: false };
  try { new PerformanceObserver((l) => { for (const e of l.getEntries()) s.lt.push(e.duration); }).observe({ type: 'longtask' }); } catch (e) { s.unsupported = true; }
  const tick = (t) => { s.gaps.push(t - s.last); s.last = t; requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
  return true;
})()`;
const RESPONSIVENESS_RESET = `(() => { window.__resp.lt = []; window.__resp.gaps = []; return true; })()`;
const RESPONSIVENESS_READ = `(() => {
  const s = window.__resp; const g = s.gaps.slice(1);
  const sorted = [...g].sort((a, b) => a - b);
  return { longtasks: s.lt.length, longtaskMax: Math.max(0, ...s.lt), longtaskTotal: s.lt.reduce((a, b) => a + b, 0),
    unsupported: s.unsupported, frames: g.length, gapMax: Math.max(0, ...g), gapP99: sorted.length ? sorted[Math.floor(sorted.length * 0.99)] : 0,
    over100: g.filter((x) => x > 100).length };
})()`;

interface Responsiveness { longtasks: number; longtaskMax: number; longtaskTotal: number; unsupported: boolean; frames: number; gapMax: number; gapP99: number; over100: number }
interface Timed { ok: boolean; ms: number; why?: string; skipped?: boolean }

const rangeLatency = (p: Page, label: string): Promise<Timed> => p.evaluate(`(async () => {
  const label = ${JSON.stringify(label)};
  const root = document.querySelector('[data-testid="monitoring-sheet"]');
  if (!root) return { ok: false, ms: 0, why: 'no sheet' };
  const line = () => { const m = /[^\\n]*packets in [^\\n]* records,[^\\n]*/.exec(root.innerText); return m ? m[0] : null; };
  const group = root.querySelector('[role="group"][aria-label="Range"]');
  const btn = group && [...group.querySelectorAll('button')].find((b) => b.textContent.trim() === label);
  if (!btn) return { ok: false, ms: 0, why: 'no range button' };
  if (btn.getAttribute('aria-pressed') === 'true') return { ok: true, ms: 0, skipped: true };
  const before = line();
  const t0 = performance.now();
  btn.click();
  while (performance.now() - t0 < 30000) {
    await new Promise((r) => requestAnimationFrame(r));
    const l = line();
    if (l && l !== before) return { ok: true, ms: performance.now() - t0 };
    const al = root.querySelector('[role="alert"]');
    if (al) return { ok: false, ms: performance.now() - t0, why: al.innerText.slice(0, 100) };
  }
  return { ok: false, ms: 30000, why: 'timeout' };
})()`) as Promise<Timed>;

const focusLatency = (p: Page): Promise<Timed> => p.evaluate(`(async () => {
  const root = document.querySelector('[data-testid="monitoring-sheet"]');
  if (!root) return { ok: false, ms: 0, why: 'no sheet' };
  const h3 = [...root.querySelectorAll('h3')].find((h) => h.textContent.trim() === 'Top conversations');
  const btn = h3 && h3.parentElement.querySelector('tbody tr button');
  if (!btn) return { ok: false, ms: 0, why: 'no conversation row to open' };
  const t0 = performance.now();
  btn.click();
  let result = { ok: false, ms: 30000, why: 'timeout' };
  while (performance.now() - t0 < 30000) {
    await new Promise((r) => requestAnimationFrame(r));
    const sel = root.querySelector('section[aria-label="Selection"]');
    if (sel && sel.querySelector('[role="alert"]')) { result = { ok: false, ms: performance.now() - t0, why: sel.querySelector('[role="alert"]').innerText.slice(0, 100) }; break; }
    if (sel && !/Reading the supporting records/.test(sel.innerText)) { result = { ok: true, ms: performance.now() - t0 }; break; }
  }
  const clear = root.querySelector('button[aria-label="Clear the selection"]');
  if (clear) clear.click();
  return result;
})()`) as Promise<Timed>;

// --- processes and files --------------------------------------------------------------------------------

interface Proc { pid: number; type: string; name: string; ws: number; priv: number; cpu: number }
const metricsOf = (app: App): Promise<Proc[]> => app.evaluate(`(({ app }) => app.getAppMetrics().map((m) => ({ pid: m.pid, type: m.type, name: m.name || m.serviceName || '', ws: m.memory.workingSetSize * 1024, priv: (m.memory.privateBytes || 0) * 1024, cpu: m.cpu.percentCPUUsage })))(process.mainModule.require('electron'))`) as Promise<Proc[]>;

function collectorPid(port: number): number | null {
  try {
    const text = execFileSync('netstat', ['-ano', '-p', 'UDP'], { encoding: 'utf8' });
    for (const line of text.split(/\r?\n/)) {
      const parts = line.trim().split(/\s+/);
      if (parts[0] === 'UDP' && parts[1] === `127.0.0.1:${port}`) return Number(parts[parts.length - 1]);
    }
  } catch { /* reported as unknown */ }
  return null;
}

const sizeOf = (file: string): number => { try { return statSync(file).size; } catch { return 0; } };
/** Every segment the journal holds, summed: the journal is a run of files now, not one. */
const journalOf = (profile: string): number => {
  const root = monitoringRoot(profile);
  try { return readdirSync(root).filter(isSegmentFileName).reduce((n, f) => n + sizeOf(path.join(root, f)), 0); } catch { return 0; }
};
const sidecarOf = (profile: string): number => sizeOf(path.join(monitoringRoot(profile), ROLLUP_FILE));

async function startSource(s: Session, limit?: { value: string; unit: 'MiB' | 'GiB' }): Promise<boolean> {
  const p = s.page;
  await p.getByRole('textbox', { name: 'Exporter', exact: true }).fill('127.0.0.1');
  await p.getByRole('textbox', { name: 'Listen on', exact: true }).fill('127.0.0.1');
  await p.getByRole('textbox', { name: 'Port', exact: true }).fill(String(s.port));
  if (limit) {
    await p.getByRole('textbox', { name: 'Keep up to', exact: true }).fill(limit.value);
    await p.getByLabel('Storage unit').selectOption(limit.unit);
  }
  await p.getByRole('button', { name: 'Start', exact: true }).click();
  const end = Date.now() + 20_000;
  while (Date.now() < end) {
    if (/Listening/.test(await sheetText(p))) return true;
    await sleep(250);
  }
  return false;
}

async function startStubCapture(p: Page): Promise<boolean> {
  try {
    await p.getByRole('button', { name: 'Interfaces' }).click({ timeout: 10_000 });
    await p.getByText('Ethernet', { exact: true }).first().click({ timeout: 10_000 });
    await p.getByLabel('Start capture').click({ timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}
const captureFrames = (p: Page): Promise<number> =>
  p.evaluate(`Number((document.querySelector('[data-packet-counts]')?.textContent?.match(/([\\d,]+)/)?.[1] ?? '0').replace(/,/g, ''))`) as Promise<number>;

// --- one step ---------------------------------------------------------------------------------------------

interface StepDef { name: string; rate: number; records: number; secs: number; unique?: boolean }
interface StepResult {
  def: StepDef;
  offered: number;
  offeredRecords: number;
  actualSecs: number;
  accepted: number;
  rejected: number;
  strays: number;
  shed: number;
  malformed: number;
  acceptance: number;
}

const state = { sequence: 0, uniqueNext: 0, expectedRecords: 0 };

function medianOf(xs: number[]): number {
  if (xs.length === 0) return NaN;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}
const ms = (n: number): string => (Number.isFinite(n) ? `${fmt(n, n < 10 ? 1 : 0)} ms` : 'n/a');

async function runStep(s: Session, def: StepDef, collector: number | null): Promise<StepResult> {
  const p = s.page;
  out(`\n--- ${def.name}: ${fmt(def.rate)} datagrams/s x ${def.records} record${def.records === 1 ? '' : 's'}${def.unique ? ', every record a new address pair' : ''}, ${def.secs} s ---`);
  const before = await readCounters(p);
  const j0 = journalOf(s.profile);
  const r0 = sidecarOf(s.profile);
  await p.evaluate(RESPONSIVENESS_RESET);

  // Concurrent load: the metrics sampler and the range/Focus cycler.
  let running = true;
  const samples: Proc[][] = [];
  const sampler = (async () => {
    while (running) {
      try {
        const m = await metricsOf(s.app);
        if (Array.isArray(m)) samples.push(m);
      } catch { /* the app may be closing */ }
      await sleep(1000);
    }
  })();
  const underLoad: { kind: string; label: string; timed: Timed }[] = [];
  const cycler = (async () => {
    const labels = ['15 min', '6 h', '24 h', '7 d', '1 h'];
    let i = 0;
    while (running) {
      const label = labels[i++ % labels.length];
      underLoad.push({ kind: 'range', label, timed: await rangeLatency(p, label).catch((e) => ({ ok: false, ms: 0, why: String(e).slice(0, 80) })) });
      if (!running) break;
      await sleep(600);
      if (i % 2 === 0 && running) underLoad.push({ kind: 'focus', label: 'conversation', timed: await focusLatency(p).catch((e) => ({ ok: false, ms: 0, why: String(e).slice(0, 80) })) });
      await sleep(900);
    }
  })();

  const done = await runSender({
    port: s.port, rate: def.rate, records: def.records, secs: def.secs, unique: def.unique === true,
    sequence: state.sequence, uniqueNext: state.uniqueNext, stray: true,
  });
  state.sequence = done.sequence;
  state.uniqueNext = done.uniqueNext;
  const idleP = running;
  running = false;
  void idleP;
  await Promise.all([sampler, cycler]);
  const loadUi = await p.evaluate(RESPONSIVENESS_READ) as Responsiveness;

  const { counters: after, settleMs } = await settle(p);
  const j1 = journalOf(s.profile);
  const r1 = sidecarOf(s.profile);

  const accepted = after.accepted - before.accepted;
  const shed = after.shed - before.shed;
  const malformed = (after.malformed + after.unsupported + after.engineLimit) - (before.malformed + before.unsupported + before.engineLimit);
  const rejected = after.refused - before.refused;
  const accountedFor = accepted + shed + malformed;
  const acceptance = done.sent === 0 ? 1 : accepted / done.sent;
  state.expectedRecords += accepted * def.records;

  // Idle history-query latency after the load, one per range, then a Focus (raw).
  const idle: { label: string; timed: Timed }[] = [];
  for (const label of ['15 min', '6 h', '24 h', '7 d', '1 h']) {
    idle.push({ label, timed: await rangeLatency(p, label).catch((e) => ({ ok: false, ms: 0, why: String(e).slice(0, 80) })) });
    await sleep(300);
  }
  const focus = await focusLatency(p).catch((e) => ({ ok: false, ms: 0, why: String(e).slice(0, 80) } as Timed));

  // Records the sheet lists against the records the accepted datagrams carried.
  let recordsNow: number | null = null;
  const wait0 = Date.now();
  while (Date.now() - wait0 < 12_000) {
    recordsNow = (await readCounters(p)).records;
    if (recordsNow === state.expectedRecords) break;
    await sleep(1000);
  }

  // Process figures.
  const flat = samples.flat();
  const byPid = new Map<number, Proc[]>();
  for (const m of flat) byPid.set(m.pid, [...(byPid.get(m.pid) ?? []), m]);
  const col = collector === null ? [] : byPid.get(collector) ?? [];
  const peak = (xs: Proc[], k: 'ws' | 'priv' | 'cpu'): number => Math.max(0, ...xs.map((x) => x[k]));
  const mean = (xs: number[]): number => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : NaN);

  const ui = loadUi;
  const rangeLoad = underLoad.filter((u) => u.kind === 'range' && u.timed.ok && !u.timed.skipped).map((u) => u.timed.ms);
  const focusLoad = underLoad.filter((u) => u.kind === 'focus' && u.timed.ok).map((u) => u.timed.ms);
  const notReadyWhy = ['no range button', 'no conversation row to open'];
  const loadFailed = underLoad.filter((u) => !u.timed.ok && !notReadyWhy.includes(u.timed.why ?? ''));
  const notReady = underLoad.filter((u) => !u.timed.ok && notReadyWhy.includes(u.timed.why ?? '')).length;

  out(`  offered            ${fmt(done.sent)} datagrams in ${done.actualSecs.toFixed(1)} s = ${fmt(done.sent / done.actualSecs, 1)}/s (${fmt(done.flows)} records, ${fmt(done.flows / done.actualSecs)}/s)`);
  out(`  accepted           ${fmt(accepted)} datagrams = ${fmt(accepted / done.actualSecs, 1)}/s, ${(acceptance * 100).toFixed(2)}% of offered`);
  out(`  rejected           ${fmt(rejected)} of ${fmt(done.strays)} stray datagrams from 127.0.0.2 (the configured exporter is 127.0.0.1)`);
  out(`  local drop         shed before writing ${fmt(shed)}; malformed/unsupported/engine-limit ${fmt(malformed)}`);
  out(`  unaccounted        ${fmt(done.sent - accountedFor)} datagrams offered but not counted by the app (UDP loss on the way is never reported to Inwire); sender send errors ${fmt(done.errors)}`);
  if (PROTOCOL === 'v5') out(`  sequence           jumps ${fmt(after.engine?.jumps ?? 0)}  gaps ${fmt(after.engine?.gaps ?? 0)}  duplicates ${fmt(after.engine?.duplicates ?? 0)}  reordered ${fmt(after.engine?.reordered ?? 0)}  resets ${fmt(after.engine?.resets ?? 0)}  unresolved ${fmt(after.engine?.unresolved ?? 0)}  (engine 0/0, cumulative)`);
  else out(`  sequence           the ${PROTOCOL_NAME} card reads: ${after.numbering ?? '(no Numbering line)'}`);
  out(`  queue depth        not exposed (the inbox depth is internal; the shed count above is what shows it overflowing)`);
  out(`  JS heap            not exposed; collector process working-set max ${col.length ? mb(peak(col, 'ws')) : 'unknown'}, private-bytes max ${col.length ? mb(peak(col, 'priv')) : 'unknown'}, cpu mean ${col.length ? fmt(mean(col.map((c) => c.cpu)), 1) : 'n/a'}% max ${col.length ? fmt(peak(col, 'cpu'), 1) : 'n/a'}%`);
  const others = [...byPid.entries()].filter(([pid]) => pid !== collector).map(([, xs]) => `${xs[0].type}${xs[0].name ? ` ${xs[0].name}` : ''} pid ${xs[0].pid} ws ${mb(peak(xs, 'ws'))}`).sort();
  out(`  other processes    ${others.join('; ')}`);
  out(`  commit/fsync       not exposed (no latency figure leaves the collector; the settle time below is the nearest observable)`);
  out(`  settle             ${fmt(settleMs / 1000, 1)} s from the last datagram sent to Accepted holding still`);
  out(`  journal            ${fmt(j1 - j0)} bytes grown (${done.sent ? fmt((j1 - j0) / Math.max(1, accepted), 0) : 0} B per accepted datagram); file now ${mb(j1)}`);
  out(`  sidecar            ${fmt(r1 - r0)} bytes grown; file now ${mb(r1)}; the sheet's storage meter reads ${after.written === null ? 'not shown' : `${mb(after.written)} of ${mb(after.limit ?? 0)}`}`);
  out(`  query under load   ranges n=${rangeLoad.length} median ${ms(medianOf(rangeLoad))} max ${ms(rangeLoad.length ? Math.max(...rangeLoad) : NaN)}; Focus n=${focusLoad.length} median ${ms(medianOf(focusLoad))} max ${ms(focusLoad.length ? Math.max(...focusLoad) : NaN)}; not attempted (nothing on the sheet yet) ${notReady}; failed ${loadFailed.length}${loadFailed.length ? ` (${[...new Set(loadFailed.map((u) => u.timed.why ?? '?'))].join(' | ')})` : ''}`);
  out(`  query when idle    ${idle.map((i) => `${i.label} ${i.timed.skipped ? 'already shown' : i.timed.ok ? ms(i.timed.ms) : `FAILED (${i.timed.why})`}`).join('; ')}`);
  out(`  query, raw (Focus) ${focus.ok ? ms(focus.ms) : `FAILED (${focus.why})`}  (a Focus reads the supporting records from the journal; a range is answered from the rollup)`);
  out(`  history records    sheet lists ${recordsNow === null ? 'nothing' : fmt(recordsNow)} records in 1 h; the accepted datagrams carried ${fmt(state.expectedRecords)} (cumulative)${recordsNow === state.expectedRecords ? ' - equal' : ' - DIFFER'}${after.tablesNote ? `; sheet note: ${after.tablesNote}` : ''}`);
  out(`  UI (during load)   ${ui.unsupported ? 'longtask not supported; ' : `longtasks ${ui.longtasks} (max ${ms(ui.longtaskMax)}, total ${ms(ui.longtaskTotal)}); `}animation-frame gaps: ${fmt(ui.frames)} frames, p99 ${ms(ui.gapP99)}, max ${ms(ui.gapMax)}, over 100 ms ${ui.over100}`);
  out(`  sender pacing      slowest catch-up ${ms(done.lateMsMax)}`);

  if (recordsNow !== state.expectedRecords) fail(`${def.name}: the sheet lists ${recordsNow === null ? 'no' : fmt(recordsNow)} records but the accepted datagrams carried ${fmt(state.expectedRecords)}`);
  if (done.errors > 0) fail(`${def.name}: ${done.errors} send errors in the sender`);
  if (ui.longtaskMax > 1000 || ui.gapMax > 1000) fail(`${def.name}: the renderer stalled for ${ms(Math.max(ui.longtaskMax, ui.gapMax))}`);
  if (loadFailed.length > 0) fail(`${def.name}: ${loadFailed.length} history queries failed under load (${[...new Set(loadFailed.map((u) => u.timed.why ?? '?'))].join(' | ')})`);
  if (idle.some((i) => !i.timed.ok)) fail(`${def.name}: an idle history query failed (${idle.filter((i) => !i.timed.ok).map((i) => `${i.label}: ${i.timed.why}`).join(' | ')})`);
  if (!focus.ok) {
    if (focus.why === 'no conversation row to open' && after.tablesNote && /not shown|too large/i.test(after.tablesNote)) out(`  NOTE  no Focus was possible: the sheet declines to list tables for a range this wide (${after.tablesNote}) - the documented bound, not a fault`);
    else fail(`${def.name}: Focus failed (${focus.why})`);
  }

  return { def, offered: done.sent, offeredRecords: done.flows, actualSecs: done.actualSecs, accepted, rejected, strays: done.strays, shed, malformed, acceptance };
}

// --- environment -----------------------------------------------------------------------------------------------

function environment(): string {
  const c = cpus();
  let disk = 'disk unknown';
  try {
    const f = statfsSync(tmpdir());
    disk = `${mb(f.blocks * f.bsize).replace(' MB', '')} MB volume, ${mb(f.bavail * f.bsize)} free`;
  } catch { /* leave unknown */ }
  let media = '';
  try {
    media = execFileSync('powershell', ['-NoProfile', '-Command', '(Get-PhysicalDisk | Select-Object -First 1 | ForEach-Object { $_.FriendlyName + " " + $_.MediaType }) -join ""'], { encoding: 'utf8' }).trim();
  } catch { /* leave unknown */ }
  return `CPU ${c[0]?.model.trim() ?? 'unknown'}, ${c.length} logical cores; RAM ${mb(totalmem())}; temp volume ${disk}${media ? `; first physical disk ${media}` : ''}; OS Windows ${release()} (${osVersion()}); Node ${process.version}`;
}

// --- the run -----------------------------------------------------------------------------------------------------

const t0 = Date.now();
out(`load.ts ${QUICK ? '--quick' : '(full)'} --protocol ${PROTOCOL}  started ${new Date(t0).toISOString()}`);
out(`protocol: ${PROTOCOL_NAME}${PROTOCOL === 'v5' ? '' : `; a template set in the first datagram of each step and every ${TEMPLATE_EVERY}th, the rest data-only; sequence counts ${PROTOCOL === 'v9' ? 'export packets' : 'data records'}${PROTOCOL === 'ipfix' ? `; one sender source port, ${SENDER_PORT}` : ''}`}`);
out(environment());
out('NOTE  the parallel Task 8A worker also launches the built app on this machine; every figure below was taken with whatever it was running');

let session: (Session & { launchMs: number }) | null = null;
let phase2: (Session & { launchMs: number }) | null = null;
const results: StepResult[] = [];
let electronVersion = 'unknown';

try {
  session = await newSession();
  electronVersion = await session.app.evaluate(() => process.versions.electron).catch(() => 'unknown');
  out(`Electron ${electronVersion}; profile ${session.profile}; port ${session.port}`);
  const p = session.page;
  await p.evaluate(RESPONSIVENESS);
  await openSheet(p);
  const listening = await startSource(session);
  if (!listening) fail('the collector did not report Listening within 20 s');
  const collector = collectorPid(session.port);
  out(`collector process: ${collector === null ? 'not identified' : `pid ${collector} (owner of 127.0.0.1:${session.port} per netstat)`}`);
  const capture = await startStubCapture(p);
  await sleep(1500);
  const frames0 = await captureFrames(p);
  out(`synthetic capture through the stub agent: ${capture ? `started, ${fmt(frames0)} frames so far` : 'COULD NOT BE STARTED'}`);
  if (!capture) fail('the stub capture could not be started, so the concurrent capture load did not run');

  // 1. the sweep.
  out('\n===== 1. SWEEP: 10-record datagrams of 8 recurring address pairs =====');
  let sustained = 0;
  for (const rate of [2, 7, 50, 100, 200, 400, 800, 1600, 3200]) {
    if (rate > CEILING) break;
    const r = await runStep(session, { name: `sweep ${rate}/s`, rate, records: 10, secs: STEP_SECS }, collector);
    results.push(r);
    if (r.acceptance >= 0.98 && r.shed === 0) sustained = rate;
    else {
      out(`\n  acceptance fell below what was offered at ${rate}/s (${(r.acceptance * 100).toFixed(2)}%, ${fmt(r.shed)} shed): the sweep stops here`);
      break;
    }
  }
  if (sustained === 0) sustained = 2;
  const reachedCeiling = sustained === Math.max(...[2, 7, 50, 100, 200, 400, 800, 1600, 3200].filter((r) => r <= CEILING)) && results[results.length - 1].acceptance >= 0.98 && results[results.length - 1].shed === 0;
  out(`\n  highest sweep rate with acceptance >= 98% and nothing shed: ${fmt(sustained)} datagrams/s (this machine, this load, ${STEP_SECS} s per point)${reachedCeiling ? ` - this is the harness ceiling (${fmt(CEILING)}/s), not a limit the app reached` : ''}`);
  const caseRate = Math.min(sustained, 400);

  // 2. the cases.
  out(`\n===== 2. CASES at ${fmt(caseRate)} datagrams/s =====`);
  results.push(await runStep(session, { name: 'case: tiny datagrams', rate: caseRate, records: 1, secs: STEP_SECS }, collector));
  results.push(await runStep(session, { name: 'case: maximum datagrams', rate: caseRate, records: 30, secs: STEP_SECS }, collector));
  results.push(await runStep(session, { name: 'case: high cardinality', rate: caseRate, records: 30, secs: STEP_SECS, unique: true }, collector));

  // The pause case: traffic, silence, then traffic whose numbering has jumped.
  out(`\n--- case: source pause (${PAUSE_SECS} s of silence) and resume with a sequence jump ---`);
  const pre = await settle(p, 8000);
  const a = await runSender({ port: session.port, rate: 50, records: 10, secs: 3, unique: false, sequence: state.sequence, uniqueNext: state.uniqueNext, stray: false });
  state.sequence = a.sequence; state.uniqueNext = a.uniqueNext;
  const quiet0 = Date.now();
  let staleAfter: number | null = null;
  while (Date.now() - quiet0 < PAUSE_SECS * 1000) {
    await sleep(2000);
    if (staleAfter === null && (await readCounters(p)).freshness === 'stale') staleAfter = (Date.now() - quiet0) / 1000;
  }
  const mid = await settle(p, 8000);
  const skipped = 1000;
  state.sequence = (state.sequence + skipped) >>> 0;
  const b = await runSender({ port: session.port, rate: 50, records: 10, secs: 3, unique: false, sequence: state.sequence, uniqueNext: state.uniqueNext, stray: false });
  state.sequence = b.sequence; state.uniqueNext = b.uniqueNext;
  const post = await settle(p, 15_000);
  const acceptedPause = post.counters.accepted - pre.counters.accepted;
  state.expectedRecords += acceptedPause * 10;
  const gapsDelta = (post.counters.engine?.gaps ?? 0) - (pre.counters.engine?.gaps ?? 0);
  const jumpsDelta = (post.counters.engine?.jumps ?? 0) - (pre.counters.engine?.jumps ?? 0);
  const unitOfSequence = { v5: 'flows', v9: 'export packets', ipfix: 'data records' }[PROTOCOL];
  out(`  sent ${fmt(a.sent)} datagrams, silence ${PAUSE_SECS} s, then ${fmt(skipped)} ${unitOfSequence}' worth of numbering skipped (${PROTOCOL_NAME}'s own sequence field), then ${fmt(b.sent)} datagrams`);
  out(`  accepted ${fmt(acceptedPause)} of ${fmt(a.sent + b.sent)} offered; freshness after the burst: ${mid.counters.freshness}; ${staleAfter === null ? `the sheet never turned "No recent export" within ${PAUSE_SECS} s (it needs more than 60 s of silence)` : `the sheet turned "No recent export" after ${fmt(staleAfter, 0)} s of silence`}; after the resume: ${post.counters.freshness}`);
  if (PROTOCOL !== 'v5') out(`  sequence handling: the ${PROTOCOL_NAME} card read "${pre.counters.numbering ?? '(none)'}" before and reads "${post.counters.numbering ?? '(none)'}" after the skip`);
  else out(`  sequence handling: jumps +${fmt(jumpsDelta)} (flows the numbering skipped), gaps +${fmt(gapsDelta)}, duplicates +${fmt((post.counters.engine?.duplicates ?? 0) - (pre.counters.engine?.duplicates ?? 0))}, resets +${fmt((post.counters.engine?.resets ?? 0) - (pre.counters.engine?.resets ?? 0))}, reordered +${fmt((post.counters.engine?.reordered ?? 0) - (pre.counters.engine?.reordered ?? 0))}`);
  if (acceptedPause !== a.sent + b.sent) fail(`pause: ${fmt(a.sent + b.sent - acceptedPause)} datagrams around the pause were not accepted`);
  if (PROTOCOL === 'v5' && jumpsDelta !== skipped) out(`  NOTE  the app counted ${fmt(jumpsDelta)} jumped flows for a skip of ${fmt(skipped)}`);
  await p.getByRole('group', { name: 'Range' }).getByRole('button', { name: '1 h', exact: true }).click().catch(() => {});

  const framesNow = await captureFrames(p);
  out(`\nthe stub capture ran throughout: ${fmt(frames0)} frames at the start of the sweep, ${fmt(framesNow)} frames now`);
  if (capture && framesNow <= frames0) fail('the stub capture did not advance during the monitoring load');

  // 3. restart and rebuild.
  out('\n===== 3. RESTART =====');
  // The records line trails the Accepted counter (it is a history query), so wait for it to catch up before it is the number the restart is held to.
  let recordsBefore = (await readCounters(p)).records;
  for (const end = Date.now() + 20_000; Date.now() < end && recordsBefore !== state.expectedRecords; ) {
    await sleep(1000);
    recordsBefore = (await readCounters(p)).records;
  }
  out(`  before the close the sheet lists ${recordsBefore === null ? 'no' : fmt(recordsBefore)} records; the accepted datagrams carried ${fmt(state.expectedRecords)}${recordsBefore === state.expectedRecords ? ' - equal' : ' - DIFFER'}`);
  if (recordsBefore !== state.expectedRecords) fail(`before the restart the sheet lists ${recordsBefore === null ? 'no' : fmt(recordsBefore)} records but the accepted datagrams carried ${fmt(state.expectedRecords)}`);
  const profile = session.profile;
  await closeApp(session);
  await session.agent.close();
  session = null;
  const restart = async (label: string): Promise<{ records: number | null }> => {
    const pipe = String.raw`\\.\pipe\inwire-load-` + process.pid + '-' + sessionCount++;
    const agent = await startStubAgent(pipe, 5);
    const t = performance.now();
    const l = await launch(profile, agent, pipe);
    const tWindow = performance.now() - t;
    await openSheet(l.page);
    const tSheet = performance.now() - t;
    let records: number | null = null;
    let tHistory = NaN;
    const end = performance.now() + 120_000;
    while (performance.now() < end) {
      records = (await readCounters(l.page)).records;
      if (records !== null && records > 0) { tHistory = performance.now() - t; break; }
      await sleep(100);
    }
    const counters = await readCounters(l.page);
    out(`  ${label}: window ready ${fmt(tWindow)} ms, sheet open ${fmt(tSheet)} ms, history restored ${Number.isFinite(tHistory) ? `${fmt(tHistory)} ms after the launch call` : 'NEVER within 120 s'}; the sheet lists ${records === null ? 'no' : fmt(records)} records in 1 h (before the close: ${recordsBefore === null ? 'none' : fmt(recordsBefore)}); listener: ${counters.listener} (it must not start by itself)`);
    if (!Number.isFinite(tHistory)) fail(`${label}: the history was not restored within 120 s`);
    if (records !== recordsBefore) fail(`${label}: ${records === null ? 'no' : fmt(records)} records after the restart against ${recordsBefore === null ? 'none' : fmt(recordsBefore)} before`);
    if (/Listening/.test(counters.listener)) fail(`${label}: the collector started without being asked`);
    await closeApp(l);
    await agent.close();
    return { records };
  };
  out(`  files before: journal ${mb(journalOf(profile))}, sidecar ${mb(sidecarOf(profile))}`);
  await restart('clean restart');
  rmSync(path.join(monitoringRoot(profile), ROLLUP_FILE), { force: true });
  out('  sidecar deleted, relaunching');
  await restart('restart with the sidecar deleted (rebuild)');
  out(`  files after the rebuild: journal ${mb(journalOf(profile))}, sidecar ${mb(sidecarOf(profile))}`);
  rmSync(profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 });

  // 4. storage exhaustion.
  out('\n===== 4. STORAGE EXHAUSTION: limit 16 MiB, 30-record datagrams, every record a new address pair =====');
  phase2 = await newSession();
  const q = phase2.page;
  await openSheet(q);
  const startedSmall = await startSource(phase2, { value: '16', unit: 'MiB' });
  if (!startedSmall) fail('the small-limit collector did not report Listening');
  const collector2 = collectorPid(phase2.port);
  const start2 = Date.now();
  const flood = { sequence: 0, uniqueNext: 1_000_000 };
  let offered2 = 0;
  let stoppedAfter: number | null = null;
  let c2 = await readCounters(q);
  while ((Date.now() - start2) / 1000 < EXHAUST_CAP_SECS && stoppedAfter === null) {
    const d = await runSender({ port: phase2.port, rate: 400, records: EXHAUST_RECORDS, secs: 4, unique: true, sequence: flood.sequence, uniqueNext: flood.uniqueNext, stray: false });
    flood.sequence = d.sequence; flood.uniqueNext = d.uniqueNext; offered2 += d.sent;
    c2 = await readCounters(q);
    if (/storage limit|reached/i.test(c2.listener) || !/Listening/.test(c2.listener)) stoppedAfter = (Date.now() - start2) / 1000;
  }
  const after2 = (await settle(q, 15_000)).counters;
  out(`  ${stoppedAfter === null ? `the limit was NOT reached within ${EXHAUST_CAP_SECS} s` : `the collector stopped ${fmt(stoppedAfter, 1)} s in`}; offered ${fmt(offered2)} datagrams; accepted ${fmt(after2.accepted)}; shed ${fmt(after2.shed)}`);
  out(`  listener line: "${after2.listener}"`);
  out(`  storage meter: ${after2.written === null ? 'not shown' : `${mb(after2.written)} of ${mb(after2.limit ?? 0)}`}; journal file ${mb(journalOf(phase2.profile))}, sidecar ${mb(sidecarOf(phase2.profile))}; the limit is ${mb(16 * 1024 * 1024)}`);
  const text2 = await sheetText(q);
  out(`  guidance on screen: ${/Raise the storage limit/.test(text2) ? 'yes ("Raise the storage limit under Source, then press Start. The history already kept stays.")' : 'not shown'}`);
  // Datagrams after the stop go to a closed port.
  const late = await runSender({ port: phase2.port, rate: 100, records: EXHAUST_RECORDS, secs: 2, unique: true, sequence: flood.sequence, uniqueNext: flood.uniqueNext, stray: false });
  const afterLate = (await settle(q, 8000)).counters;
  out(`  after the stop, ${fmt(late.sent)} more datagrams were offered: accepted rose by ${fmt(afterLate.accepted - after2.accepted)}; journal file ${mb(journalOf(phase2.profile))}`);
  const readable = await rangeLatency(q, '6 h');
  const readCounts = await readCounters(q);
  out(`  the stored history stays readable: ${readable.ok || readable.skipped ? `yes, the sheet lists ${readCounts.records === null ? 'no' : fmt(readCounts.records)} records` : `NO (${readable.why})`}${readCounts.tablesNote ? `; sheet note: ${readCounts.tablesNote}` : ''}`);
  if (stoppedAfter === null) fail('storage exhaustion: the 16 MiB limit was not reached in the time allowed');
  if (journalOf(phase2.profile) > 16 * 1024 * 1024) fail(`storage exhaustion: the journal file (${mb(journalOf(phase2.profile))}) is larger than its 16 MiB limit`);
  if (afterLate.accepted !== after2.accepted) fail('storage exhaustion: datagrams were accepted after the collector stopped');
  void collector2;
} catch (e) {
  fail(`the run itself threw: ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
} finally {
  for (const s of [session, phase2]) {
    if (!s) continue;
    await closeApp(s);
    await s.agent.close().catch(() => {});
    try { rmSync(s.profile, { recursive: true, force: true, maxRetries: 20, retryDelay: 100 }); } catch { /* temp */ }
  }
}

// --- the summary ---------------------------------------------------------------------------------------------------

out('\n===== SUMMARY =====');
out('step                              offered/s   accepted/s   acceptance   shed    rejected(strays)');
for (const r of results) {
  out(`${r.def.name.padEnd(33)} ${fmt(r.offered / r.actualSecs, 1).padStart(9)}   ${fmt(r.accepted / r.actualSecs, 1).padStart(10)}   ${`${(r.acceptance * 100).toFixed(2)}%`.padStart(10)}   ${fmt(r.shed).padStart(5)}   ${fmt(r.rejected)}/${fmt(r.strays)}`);
}
out('\nFAILURES');
if (failures.length === 0) out('  none recorded');
for (const f of failures) out(`  ${f}`);
out(`\nelapsed ${((Date.now() - t0) / 1000).toFixed(0)} s; Electron ${electronVersion}`);
out(`ENVIRONMENT  ${environment()}`);
out('This is a measurement of this machine and this workload only: no pass mark, no capacity claim beyond the points listed.');
