/**
 * What a high-rate live capture costs the window: frames per second, long
 * tasks, where the main thread's time goes, how far the list falls behind.
 *
 *   npx tsx scripts/perf/ui-burst-drive.ts --pcap some.pcapng [--rates 10000,20000,40000] [--seconds 25] [--threads auto|1] [--no-file]
 *       [--app <dir>] [--out report.txt] [--profile <prefix>] [--follow-only]
 *
 * `--profile` also writes each phase's raw CPU profiles, the main thread's as
 * `<prefix>-<n>-main.cpuprofile` and the Worker's as `-worker`, for DevTools'
 * Performance panel or a second look. `--follow-only` skips the scrolling and
 * filter phases, which is what a before/after of the frame path wants.
 *
 * `--app` launches another app directory: `package.json`, `dist-electron/`, a
 * `node_modules` link, and a `dist/` built with
 * `vite build --minify false --sourcemap --outDir <dir>/dist`. The shipped
 * `dist/` is minified, so its profile names functions `nt` and `$2`; with an
 * unminified build and its source maps each row names its `src/` file. Main
 * finds the renderer at `dist-electron/../dist` either way.
 *
 * A MEASUREMENT and a DRIVER, so it is in `check.ts`'s NOT_TESTS: it launches
 * the built app (`dist/`, not rebuilt) against a pipe agent of its own that
 * replays REAL frames out of `--pcap` at a set rate - the stub agent sends one
 * DNS query shape, and a dissector's cost depends on what it is handed. Each
 * pass over the file shifts every TCP sequence and acknowledgement number (and
 * fixes the checksum) so a replay reads as more of the same transfer rather
 * than as a storm of retransmissions.
 *
 * Per phase it reports the renderer's animation frames per second, its long
 * tasks (PerformanceObserver), a CPU profile of the main thread by self time,
 * the main thread's and the pipeline Worker's JS heap, and the lag between
 * what the agent sent and what the title row's count shows. Then two more
 * phases at the middle rate: scrolling the list, and a display filter applied.
 *
 * The Worker's profile needs Chromium's own DevTools port, which Playwright
 * does not expose for workers; `--remote-debugging-port` is passed and used
 * when it answers, and the Worker's heap and profile are skipped when not.
 */
import { createServer, type Socket } from 'node:net';
import { appendFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { SourceMapConsumer } from 'source-map-js';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { BATCH_HEADER_BYTES, BATCH_RECORD_BYTES, BATCH_VERSION } from '../../src/services/agentBinary';
import { FRAME_BINARY, FRAME_JSON, FrameReader, encodeFrame, encodeJsonFrame, frameText } from '../../src/services/agentFraming';
import { REQUIRED_AGENT_VERSION } from '../../src/services/agentProtocol';

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}
const PCAP = arg('pcap', '');
const RATES = arg('rates', '10000,20000,40000').split(',').map(Number);
const SECONDS = Number(arg('seconds', '25'));
const OUT = arg('out', '');
const APP = arg('app', '');
/** Dissection threads: `auto`, the default, or `1`. */
const THREADS = arg('threads', 'auto');
const PROFILE_PREFIX = arg('profile', '');
const FOLLOW_ONLY = process.argv.includes('--follow-only');
/** Whether the agent writes the capture's pcapng, as the real one does - what the view catches up from. */
const FILE = !process.argv.includes('--no-file');
const DEVTOOLS_PORT = 9339;
if (!PCAP) { console.log('usage: --pcap file.pcapng'); process.exit(2); }

// --- frames ------------------------------------------------------------------

/** Enhanced and simple packet blocks out of a pcapng, Ethernet assumed. */
function readPcapng(file: string, limit = 400_000): Uint8Array[] {
  const b = readFileSync(file);
  const v = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const out: Uint8Array[] = [];
  let at = 0;
  while (at + 12 <= b.length && out.length < limit) {
    const type = v.getUint32(at, true);
    const len = v.getUint32(at + 4, true);
    if (len < 12 || at + len > b.length) break;
    if (type === 6) {
      const cap = v.getUint32(at + 20, true);
      out.push(new Uint8Array(b.subarray(at + 28, at + 28 + cap)));
    }
    at += len;
  }
  return out;
}

function sum16(bytes: Uint8Array, from: number, to: number, acc = 0): number {
  for (let i = from; i + 1 < to; i += 2) acc += (bytes[i] << 8) | bytes[i + 1];
  if ((to - from) & 1) acc += bytes[to - 1] << 8;
  return acc;
}
const fold = (s: number) => { while (s > 0xffff) s = (s & 0xffff) + (s >>> 16); return (~s) & 0xffff; };

/**
 * A copy of the frame with its TCP seq/ack moved by `delta` and the checksum
 * recomputed, or the frame itself when it is not TCP over IPv4/IPv6 on
 * Ethernet (with at most one VLAN tag).
 */
function shiftTcp(frame: Uint8Array, delta: number): Uint8Array {
  if (delta === 0) return frame;
  let l3 = 14;
  let et = (frame[12] << 8) | frame[13];
  if (et === 0x8100 && frame.length > 18) { et = (frame[16] << 8) | frame[17]; l3 = 18; }
  let l4: number; let pseudo: number; let tcpLen: number;
  if (et === 0x0800 && frame.length >= l3 + 20 && frame[l3 + 9] === 6) {
    const ihl = (frame[l3] & 0x0f) * 4;
    const total = (frame[l3 + 2] << 8) | frame[l3 + 3];
    l4 = l3 + ihl; tcpLen = Math.min(total - ihl, frame.length - l4);
    pseudo = sum16(frame, l3 + 12, l3 + 20) + 6 + tcpLen;
  } else if (et === 0x86dd && frame.length >= l3 + 40 && frame[l3 + 6] === 6) {
    l4 = l3 + 40; tcpLen = Math.min((frame[l3 + 4] << 8) | frame[l3 + 5], frame.length - l4);
    pseudo = sum16(frame, l3 + 8, l3 + 40) + 6 + tcpLen;
  } else return frame;
  if (tcpLen < 20 || l4 + tcpLen > frame.length) return frame;
  const out = frame.slice();
  const v = new DataView(out.buffer);
  v.setUint32(l4 + 4, (v.getUint32(l4 + 4) + delta) >>> 0);
  if (out[l4 + 13] & 0x10) v.setUint32(l4 + 8, (v.getUint32(l4 + 8) + delta) >>> 0);
  v.setUint16(l4 + 16, 0);
  v.setUint16(l4 + 16, fold(sum16(out, l4, l4 + tcpLen, pseudo)));
  return out;
}

// --- the agent ---------------------------------------------------------------

function encodeBatch(frames: { seq: number; tsNs: bigint; bytes: Uint8Array }[]): Uint8Array {
  const body = frames.reduce((n, f) => n + BATCH_RECORD_BYTES + f.bytes.length, 0);
  const out = new Uint8Array(BATCH_HEADER_BYTES + body);
  const view = new DataView(out.buffer);
  out.set([0x49, 0x57, 0x50, 0x31], 0);
  view.setUint8(4, BATCH_VERSION);
  view.setUint16(6, frames.length, true);
  let offset = BATCH_HEADER_BYTES;
  for (const f of frames) {
    view.setUint32(offset, f.seq, true);
    view.setUint16(offset + 4, 0, true);
    view.setUint32(offset + 6, f.bytes.length, true);
    view.setUint32(offset + 10, f.bytes.length, true);
    view.setBigUint64(offset + 14, f.tsNs, true);
    out.set(f.bytes, offset + BATCH_RECORD_BYTES);
    offset += BATCH_RECORD_BYTES + f.bytes.length;
  }
  return out;
}

const PIPE = `\\\\.\\pipe\\inwire-uiburst-${process.pid}`;
const INTERFACES = [{ id: 0, name: '\\Device\\NPF_{STUB-0}', label: 'Ethernet (stub)' }];

interface Agent { received: string[]; sent(): number; setRate(fps: number): void; close(): Promise<void> }

/**
 * The capture's own pcapng, as the real agent writes it (ADR 0052): into
 * `<root>/<captureId>/pcapng/capture.pcapng`, every frame before it goes on
 * the pipe, flushed once a second - which is what the live view catches up
 * from after the stream skipped (ADR 0053 phase 4). `--no-file` leaves it
 * out, to measure the app as it was without one.
 */
class CaptureFileWriter {
  private pending: Uint8Array[] = [];
  private timer: ReturnType<typeof setInterval>;
  constructor(private readonly file: string) {
    mkdirSync(path.dirname(file), { recursive: true });
    writeFileSync(file, pcapngHeader(INTERFACES[0].name));
    this.timer = setInterval(() => this.flush(), 1000);
  }
  add(seqFrame: { tsNs: bigint; bytes: Uint8Array }): void {
    this.pending.push(pcapngPacket(seqFrame.tsNs, seqFrame.bytes));
  }
  flush(): void {
    if (this.pending.length === 0) return;
    const parts = this.pending;
    this.pending = [];
    appendFileSync(this.file, Buffer.concat(parts));
  }
  close(): void {
    clearInterval(this.timer);
    this.flush();
  }
}

function pcapngHeader(name: string): Uint8Array {
  const text = new TextEncoder().encode(name);
  const pad = (4 - (text.length % 4)) % 4;
  const idbLength = 16 + 4 + text.length + pad + 8 + 4 + 4;
  const out = new Uint8Array(28 + idbLength);
  const v = new DataView(out.buffer);
  v.setUint32(0, 0x0a0d0d0a, true); v.setUint32(4, 28, true); v.setUint32(8, 0x1a2b3c4d, true);
  v.setUint16(12, 1, true); v.setBigInt64(16, -1n, true); v.setUint32(24, 28, true);
  v.setUint32(28, 1, true); v.setUint32(32, idbLength, true); v.setUint16(36, 1, true);
  let o = 44;
  v.setUint16(o, 2, true); v.setUint16(o + 2, text.length, true); out.set(text, o + 4); o += 4 + text.length + pad;
  v.setUint16(o, 9, true); v.setUint16(o + 2, 1, true); v.setUint8(o + 4, 9); o += 8;
  o += 4; // opt_endofopt
  v.setUint32(o, idbLength, true);
  return out;
}

function pcapngPacket(tsNs: bigint, bytes: Uint8Array): Uint8Array {
  const pad = (4 - (bytes.length % 4)) % 4;
  const length = 32 + bytes.length + pad;
  const out = new Uint8Array(length);
  const v = new DataView(out.buffer);
  v.setUint32(0, 6, true); v.setUint32(4, length, true);
  v.setUint32(12, Number(tsNs >> 32n), true); v.setUint32(16, Number(tsNs & 0xffffffffn), true);
  v.setUint32(20, bytes.length, true); v.setUint32(24, bytes.length, true);
  out.set(bytes, 28);
  v.setUint32(length - 4, length, true);
  return out;
}

async function startAgent(frames: Uint8Array[]): Promise<Agent> {
  const received: string[] = [];
  let seq = 0; let rate = 0; let cursor = 0; let pass = 0;
  let pump: ReturnType<typeof setInterval> | null = null;
  let captureRoot: string | null = null;
  let writer: CaptureFileWriter | null = null;
  const clients = new Set<Socket>();
  const stop = () => { if (pump) clearInterval(pump); pump = null; writer?.close(); writer = null; };
  const server = createServer((socket) => {
    clients.add(socket);
    const reader = new FrameReader();
    const send = (p: Uint8Array) => { if (!socket.destroyed) socket.write(p); };
    const tell = (m: unknown) => send(encodeJsonFrame(m));
    tell({ type: 'hello', version: REQUIRED_AGENT_VERSION, state: 'idle', interfaces: INTERFACES, clientId: 'burst-1', owner: null, npcapAccess: 'D:P(A;;FA;;;SY)(A;;FA;;;BA)' });
    socket.on('data', (chunk: Buffer) => {
      for (const frame of reader.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength))) {
        if (frame.kind !== FRAME_JSON) continue;
        const text = frameText(frame);
        received.push(text);
        const message = JSON.parse(text) as { type?: string; dir?: string; captureId?: string };
        if (message.type === 'set_capture_root' && typeof message.dir === 'string') captureRoot = message.dir;
        if (message.type === 'start_capture') {
          stop();
          // The file, and where it begins, before the first frame - the real
          // agent's order (`runtime.rs`).
          if (FILE && captureRoot !== null && typeof message.captureId === 'string') {
            const name = 'capture.pcapng';
            writer = new CaptureFileWriter(path.join(captureRoot, message.captureId, 'pcapng', name));
            tell({ type: 'capture_file', index: 1, name, state: 'open', firstSeq: null, lastSeq: null, frames: 0, bytes: 0 });
            tell({ type: 'capture_boundary', index: 1, firstSeq: seq + 1 });
          }
          // 10 ms ticks, so a 40,000 frame-a-second rate is 400 frames a
          // message - the real agent's pump is batched about that finely.
          let owed = 0;
          let last = performance.now();
          pump = setInterval(() => {
            const now = performance.now();
            // Capped at 50 ms of frames: this process also summarises the
            // profiles, and a timer that stalled behind that work would
            // otherwise send the whole stall at once - one run reported
            // 246,000 frames a second sent at a 40,000 setting. The real
            // agent drops rather than catching up, too.
            owed = Math.min(owed + rate * (now - last) / 1000, rate * 0.05);
            last = now;
            let n = Math.floor(owed);
            owed -= n;
            const base = BigInt(Date.now()) * 1_000_000n;
            while (n > 0) {
              const take = Math.min(n, 2000);
              const batch = [];
              for (let i = 0; i < take; i++) {
                seq++;
                const bytes = shiftTcp(frames[cursor], pass * 0x1000_0000);
                const frame = { seq, tsNs: base + BigInt(i * 1000), bytes };
                writer?.add(frame);
                batch.push(frame);
                if (++cursor === frames.length) { cursor = 0; pass++; }
              }
              send(encodeFrame(FRAME_BINARY, encodeBatch(batch)));
              n -= take;
            }
          }, 10);
        }
        if (message.type === 'stop_capture') stop();
        if (['start_capture', 'stop_capture', 'set_interfaces'].includes(message.type ?? '')) {
          tell({ type: 'state', state: pump ? 'sniffing' : 'idle', interfaces: INTERFACES, owner: pump ? 'burst-1' : null });
        }
      }
    });
    socket.on('close', () => { clients.delete(socket); stop(); });
    socket.on('error', () => {});
  });
  await new Promise<void>((resolve, reject) => { server.once('error', reject); server.listen(PIPE, () => resolve()); });
  return {
    received, sent: () => seq, setRate: (fps) => { rate = fps; },
    close: () => new Promise<void>((resolve) => { stop(); for (const s of clients) s.destroy(); server.close(() => resolve()); }),
  };
}

// --- a raw CDP client, for the Worker -------------------------------------------

class RawCdp {
  private id = 0;
  private waiting = new Map<number, (v: { result?: unknown; error?: unknown }) => void>();
  private constructor(private readonly ws: WebSocket) {
    ws.addEventListener('message', (e) => {
      const m = JSON.parse(String(e.data)) as { id?: number; result?: unknown; error?: unknown };
      if (m.id !== undefined) { this.waiting.get(m.id)?.(m); this.waiting.delete(m.id); }
    });
  }
  static async open(url: string): Promise<RawCdp> {
    const ws = new WebSocket(url);
    await new Promise((resolve, reject) => { ws.addEventListener('open', resolve); ws.addEventListener('error', reject); });
    return new RawCdp(ws);
  }
  send<T = any>(method: string, params: object = {}, sessionId?: string): Promise<T> {
    const id = ++this.id;
    this.ws.send(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }));
    return new Promise((resolve, reject) => this.waiting.set(id, (m) => m.error ? reject(new Error(JSON.stringify(m.error))) : resolve(m.result as T)));
  }
  close(): void { this.ws.close(); }
}

// --- profiles ------------------------------------------------------------------

interface CpuProfile {
  nodes: { id: number; callFrame: { functionName: string; url: string; lineNumber: number } }[];
  samples: number[]; timeDeltas: number[];
}

/** Source maps for the launched app's assets, when it was built with them. */
const maps = new Map<string, SourceMapConsumer | null>();
function original(url: string, line: number, column: number): string | null {
  const asset = /\/(assets\/[^/?]+\.js)/.exec(url)?.[1];
  if (!asset || !APP) return null;
  if (!maps.has(asset)) {
    const file = path.join(APP, 'dist', asset + '.map');
    maps.set(asset, existsSync(file) ? new SourceMapConsumer(JSON.parse(readFileSync(file, 'utf8'))) : null);
  }
  const map = maps.get(asset);
  if (!map) return null;
  const at = map.originalPositionFor({ line: line + 1, column });
  return at.source ? `${at.source.replace(/^.*?\/(src|node_modules)\//, '$1/')}:${at.line}` : null;
}

/** Self time summed by source file, which is where a subsystem's cost shows. */
function topFiles(profile: CpuProfile, n = 10): { pct: number; ms: number; fn: string }[] {
  const byId = new Map(profile.nodes.map((x) => [x.id, x]));
  const self = new Map<string, number>();
  profile.samples.forEach((id, i) => {
    const cf = byId.get(id)!.callFrame as { functionName: string; url: string; lineNumber: number; columnNumber?: number };
    const where = original(cf.url, cf.lineNumber, cf.columnNumber ?? 0);
    const key = where ? where.replace(/:\d+$/, '') : (cf.url ? cf.url.replace(/^.*\//, '') : cf.functionName || '(native)');
    self.set(key, (self.get(key) ?? 0) + (profile.timeDeltas[i] ?? 0));
  });
  const total = [...self.values()].reduce((a, b) => a + b, 0) || 1;
  return [...self].sort((a, b) => b[1] - a[1]).slice(0, n)
    .map(([fn, us]) => ({ pct: 100 * us / total, ms: us / 1000, fn }));
}

function topSelf(profile: CpuProfile, n = 15): { pct: number; ms: number; fn: string }[] {
  const byId = new Map(profile.nodes.map((x) => [x.id, x]));
  const self = new Map<string, number>();
  profile.samples.forEach((id, i) => {
    const cf = byId.get(id)!.callFrame as { functionName: string; url: string; lineNumber: number; columnNumber?: number };
    const url = cf.url.replace(/^.*\/(assets|src|node_modules)\//, '$1/').replace(/\?.*$/, '');
    const where = original(cf.url, cf.lineNumber, cf.columnNumber ?? 0)
      ?? `${url}${url ? ':' + (cf.lineNumber + 1) : ''}`;
    const key = `${cf.functionName || '(anonymous)'}  ${where}`;
    self.set(key, (self.get(key) ?? 0) + (profile.timeDeltas[i] ?? 0));
  });
  const total = [...self.values()].reduce((a, b) => a + b, 0) || 1;
  return [...self].sort((a, b) => b[1] - a[1]).slice(0, n)
    .map(([fn, us]) => ({ pct: 100 * us / total, ms: us / 1000, fn }));
}

// --- the run -------------------------------------------------------------------

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const report: string[] = [];
const say = (line = '') => { console.log(line); report.push(line); };

const frames = readPcapng(PCAP);
say(`frames loaded from ${path.basename(PCAP)}: ${frames.length.toLocaleString()}`);
const agent = await startAgent(frames);
const { _electron: electron } = await import('playwright');
const profile = mkdtempSync(path.join(tmpdir(), 'inwire-uiburst-'));
const app = await electron.launch({
  args: ['.', `--remote-debugging-port=${DEVTOOLS_PORT}`],
  ...(APP ? { cwd: APP } : {}),
  env: { ...process.env, INWIRE_USER_DATA: profile, INWIRE_AGENT_PIPE: PIPE },
});
const page = await app.firstWindow();
page.setDefaultTimeout(30_000);
// The pipeline's failures reach only the console (`useAgentConnection.ts`).
const pipelineWarnings: string[] = [];
page.on('console', (message) => {
  if (/packet pipeline/.test(message.text())) pipelineWarnings.push(message.text());
});
// tsx compiles with keepNames, which wraps functions in a `__name` helper the
// page does not have; a string evaluate goes through CDP and defines it.
await page.evaluate('window.__name = (f) => f');
await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
// Dissection threads (ADR 0053 phase 3): the profile is fresh, so the setting
// is its default, `auto`, unless this asks for one core - written where the
// app keeps it, and read by a reload before any capture.
if (THREADS === '1') {
  await page.evaluate(() => localStorage.setItem('inwire.performance',
    JSON.stringify({ dashboardRefreshMs: 500, packetBufferBytes: 'auto', dissectionThreads: 1 })));
  await page.reload();
  await page.evaluate('window.__name = (f) => f');
  await page.waitForFunction(() => (document.getElementById('root')?.childElementCount ?? 0) > 0);
}
say(`dissection threads: ${THREADS}`);
const cdp = await page.context().newCDPSession(page);
await cdp.send('Performance.enable');
await cdp.send('Profiler.enable');
await cdp.send('Profiler.setSamplingInterval', { interval: 500 });

// The Worker, through Chromium's own port if it answered.
let raw: RawCdp | null = null;
let workerSession: string | undefined;
try {
  const version = await (await fetch(`http://127.0.0.1:${DEVTOOLS_PORT}/json/version`)).json() as { webSocketDebuggerUrl: string };
  raw = await RawCdp.open(version.webSocketDebuggerUrl);
} catch { say('(no DevTools port: the Worker is measured by lag only)'); }

async function attachWorker(): Promise<void> {
  if (raw === null || workerSession !== undefined) return;
  const { targetInfos } = await raw.send<{ targetInfos: { targetId: string; type: string; url: string; title?: string }[] }>('Target.getTargets');
  // The pipeline Worker by its name: its shards are the same script (`shardRole.ts`).
  const w = targetInfos.find((t) => t.type === 'worker' && t.title === 'inwire-pipeline')
    ?? targetInfos.find((t) => t.type === 'worker' && /pipeline/.test(t.url) && !/inwire-shard/.test(t.title ?? ''))
    ?? targetInfos.find((t) => t.type === 'worker');
  if (!w) return;
  ({ sessionId: workerSession } = await raw.send<{ sessionId: string }>('Target.attachToTarget', { targetId: w.targetId, flatten: true }));
  await raw.send('Profiler.enable', {}, workerSession);
  await raw.send('Profiler.setSamplingInterval', { interval: 500 }, workerSession);
  say(`attached to the Worker: ${w.url.replace(/^.*\//, '')}`);
}

// Instruments in the page: animation frames and long tasks.
await page.evaluate(() => {
  const w = window as unknown as { __burst: { frames: number; long: number[]; reset(): void } };
  w.__burst = { frames: 0, long: [], reset() { this.frames = 0; this.long = []; } };
  const tick = () => { w.__burst.frames++; requestAnimationFrame(tick); };
  requestAnimationFrame(tick);
  new PerformanceObserver((list) => { for (const e of list.getEntries()) w.__burst.long.push(e.duration); })
    .observe({ type: 'longtask', buffered: false });
});

const shown = async (): Promise<number> => Number((await page.evaluate(
  () => document.querySelector('[data-packet-counts]')?.textContent?.match(/\/\s*([\d,]+)/)?.[1]
    ?? document.querySelector('[data-packet-counts]')?.textContent?.match(/([\d,]+)/)?.[1] ?? '0')).replace(/,/g, ''));
const heap = async () => {
  const m = (await cdp.send('Performance.getMetrics')).metrics as { name: string; value: number }[];
  const page = (m.find((x) => x.name === 'JSHeapUsedSize')?.value ?? 0) / 1048576;
  let worker = NaN;
  if (raw && workerSession) {
    try { worker = (await raw.send<{ usedSize: number }>('Runtime.getHeapUsage', {}, workerSession)).usedSize / 1048576; } catch { /* gone */ }
  }
  return { page, worker };
};

// Start a capture the way smoke.ts does.
await page.getByRole('button', { name: 'Interfaces' }).click();
await page.getByText('Ethernet', { exact: true }).first().click();
await page.keyboard.press('Escape');
agent.setRate(500);
await page.getByLabel('Start capture').click();
for (let i = 0; i < 100 && (await shown()) < 100; i++) await sleep(200);
await sleep(1500);
await attachWorker();
if (raw && !workerSession) {
  await raw.send('Target.setDiscoverTargets', { discover: true });
  await attachWorker();
}
// Parse the source maps now, not between phases: an 11 MB map takes seconds,
// and this process is also the agent.
if (APP && existsSync(path.join(APP, 'dist', 'assets'))) {
  for (const f of readdirSync(path.join(APP, 'dist', 'assets'))) {
    if (/^(index|pipeline\.worker)-.*\.js$/.test(f)) original(`/assets/${f}`, 0, 0);
  }
}

interface Phase { label: string; rate: number; during?: () => Promise<void>; before?: () => Promise<void> }
// The highest rate runs LAST. A rate the pipeline cannot keep up with leaves a
// backlog behind it, and every phase after it would measure that backlog
// draining rather than its own rate - the first version of this script ran its
// scrolling and filter phases 500,000 frames behind live.
const ascending = [...RATES].sort((a, b) => a - b);
const top = ascending.length > 1 ? ascending.pop()! : null;
const phases: Phase[] = ascending.map((rate) => ({ label: `${rate.toLocaleString()} f/s, list following`, rate }));
// Scrolling and filtering run at a rate the pipeline keeps up with, so they
// measure the window rather than a backlog building.
const mid = ascending[Math.floor((ascending.length - 1) / 2)];
const filterInput = () => page.getByPlaceholder('e.g. tcp.port == 443');
if (!FOLLOW_ONLY) phases.push({
  label: `${mid.toLocaleString()} f/s, scrolling the list`, rate: mid,
  during: async () => {
    const box = await page.evaluate(() => {
      const s = [...document.querySelectorAll('div')].find((d) => d.scrollHeight > d.clientHeight + 200 && d.querySelector('[role="row"]'));
      const r = s?.getBoundingClientRect();
      return r ? { x: r.x + r.width / 2, y: r.y + r.height / 2 } : null;
    });
    if (!box) return;
    await page.mouse.move(box.x, box.y);
    const until = Date.now() + SECONDS * 1000;
    let dir = -1;
    while (Date.now() < until) {
      for (let i = 0; i < 10; i++) { await page.mouse.wheel(0, dir * 300); await sleep(50); }
      dir = -dir;
    }
  },
});
if (!FOLLOW_ONLY) phases.push({
  label: `${mid.toLocaleString()} f/s, display filter tcp.len > 1000`, rate: mid,
  before: async () => {
    const input = filterInput();
    await input.click();
    await input.fill('tcp.len > 1000');
    await input.press('Enter');
    await page.keyboard.press('End').catch(() => {});
  },
});
if (top !== null) {
  phases.push({
    label: `${top.toLocaleString()} f/s, list following`, rate: top,
    before: async () => {
      const input = filterInput();
      await input.click();
      await input.fill('');
      await input.press('Enter');
    },
  });
}

/**
 * What the status bar says, and the frames it says the live view skipped
 * (ADR 0053). A skipped frame is never shown, so "behind" is what was sent,
 * less what is shown, less what was skipped - or a phase that shed would wait
 * for ever for a count that cannot catch up.
 */
async function statusText(): Promise<string> {
  return page.locator('footer[aria-label="Status"]').innerText({ timeout: 5000 }).catch(() => '');
}
async function skipped(): Promise<number> {
  const match = /([\d,]+) skipped/.exec(await statusText());
  return match ? Number(match[1].replace(/,/g, '')) : 0;
}
async function behindLive(): Promise<number> {
  return agent.sent() - await shown() - await skipped();
}

for (const [phaseIndex, phase] of phases.entries()) {
  // Level with live before it starts: the agent stops sending until the count
  // has caught up, so a phase measures its own rate and not the last one's
  // backlog. Bounded, and said when it ran out.
  agent.setRate(0);
  let behind = await behindLive();
  for (let i = 0; i < 90 && behind > 2000; i++) { await sleep(1000); behind = await behindLive(); }
  if (behind > 2000) say(`  (starting ${behind.toLocaleString()} frames behind live: the backlog had not drained in 90 s)`);
  await phase.before?.();
  agent.setRate(phase.rate);
  await sleep(2000);
  await page.evaluate(() => (window as unknown as { __burst: { reset(): void } }).__burst.reset());
  const heapStart = await heap();
  const sentStart = agent.sent();
  const shownStart = await shown();
  await cdp.send('Profiler.start');
  if (raw && workerSession) await raw.send('Profiler.start', {}, workerSession).catch(() => {});
  const t0 = Date.now();
  const lagSamples: number[] = [];
  const workerHeapSamples: number[] = [];
  const statusSamples: string[] = [];
  const skippedStart = await skipped();
  const sampler = (async () => {
    while (Date.now() - t0 < SECONDS * 1000) {
      await sleep(2000);
      lagSamples.push(await behindLive());
      workerHeapSamples.push((await heap()).worker);
      const text = (await statusText()).replace(/\s+/g, ' ').trim();
      const live = /(catching up|behind live [^·]*|[\d,]+ to go|[\d,]+ skipped)/g;
      statusSamples.push((text.match(live) ?? []).join(' · ') || 'live');
    }
  })();
  if (phase.during) await phase.during(); else await sleep(SECONDS * 1000);
  await sampler;
  const elapsed = (Date.now() - t0) / 1000;
  const { profile: mainProfile } = await cdp.send('Profiler.stop') as unknown as { profile: CpuProfile };
  let workerProfile: CpuProfile | null = null;
  if (raw && workerSession) {
    try { workerProfile = (await raw.send<{ profile: CpuProfile }>('Profiler.stop', {}, workerSession)).profile; } catch { /* none */ }
  }
  if (PROFILE_PREFIX) {
    writeFileSync(`${PROFILE_PREFIX}-${phaseIndex + 1}-main.cpuprofile`, JSON.stringify(mainProfile));
    if (workerProfile) writeFileSync(`${PROFILE_PREFIX}-${phaseIndex + 1}-worker.cpuprofile`, JSON.stringify(workerProfile));
  }
  const b = await page.evaluate(() => {
    const x = (window as unknown as { __burst: { frames: number; long: number[] } }).__burst;
    return { frames: x.frames, long: [...x.long] };
  });
  const heapEnd = await heap();
  const sent = agent.sent() - sentStart;
  const displayed = (await shown()) - shownStart;
  const long = b.long.sort((x, y) => y - x);
  const longMs = long.reduce((a, c) => a + c, 0);

  say('');
  say(`=== ${phase.label} (${elapsed.toFixed(0)} s) ===`);
  say(`  sent ${Math.round(sent / elapsed).toLocaleString()} f/s; count advanced ${Math.round(displayed / elapsed).toLocaleString()} f/s`);
  say(`  lag behind live (sent - shown - skipped), every 2 s: ${lagSamples.map((n) => n.toLocaleString()).join(', ')}`);
  say(`  skipped by the live view this phase: ${((await skipped()) - skippedStart).toLocaleString()} frames`);
  say(`  Worker heap every 2 s: ${workerHeapSamples.map((n) => n.toFixed(0)).join(', ')} MB`);
  say(`  status bar every 2 s: ${statusSamples.join(' | ')}`);
  say(`  animation frames: ${(b.frames / elapsed).toFixed(1)} fps`);
  say(`  long tasks: ${(long.length / elapsed).toFixed(1)}/s, ${(longMs / elapsed / 10).toFixed(0)}% of wall time; `
    + `p50 ${long[Math.floor(long.length / 2)]?.toFixed(0) ?? '-'} ms, max ${long[0]?.toFixed(0) ?? '-'} ms`);
  say(`  heap: main thread ${heapStart.page.toFixed(0)} -> ${heapEnd.page.toFixed(0)} MB; `
    + `Worker ${heapStart.worker.toFixed(0)} -> ${heapEnd.worker.toFixed(0)} MB`);
  const row = (r: { pct: number; ms: number; fn: string }) =>
    say(`    ${r.pct.toFixed(1).padStart(5)}%  ${r.ms.toFixed(0).padStart(6)} ms  ${r.fn}`);
  say('  main thread, top self time:');
  topSelf(mainProfile, 25).forEach(row);
  say('  main thread, by file:');
  topFiles(mainProfile).forEach(row);
  if (workerProfile) {
    say('  Worker, top self time:');
    topSelf(workerProfile).forEach(row);
    say('  Worker, by file:');
    topFiles(workerProfile).forEach(row);
  }
}

// After the burst: the agent stops sending, and the view either catches up
// with every frame it was sent - read back from the capture file where the
// stream skipped (ADR 0053 phase 4) - or says how many it skipped. How long
// that takes is the time to rejoin.
agent.setRate(0);
{
  const t0 = Date.now();
  let left = await behindLive();
  let text = await statusText();
  while (Date.now() - t0 < 180_000 && (left > 0 || /catching up/.test(text))) {
    await sleep(500);
    left = await behindLive();
    text = await statusText();
  }
  const settled = left <= 0 && !/catching up/.test(text);
  say('');
  say(`=== after the burst ===`);
  say(`  capture file written by the agent: ${FILE ? 'yes' : 'no (--no-file)'}`);
  say(`  sent ${agent.sent().toLocaleString()}; shown ${(await shown()).toLocaleString()}; skipped ${(await skipped()).toLocaleString()}`);
  say(settled
    ? `  level with live ${((Date.now() - t0) / 1000).toFixed(1)} s after the agent stopped sending`
    : `  NOT level with live 180 s after the agent stopped: ${left.toLocaleString()} frames behind; status "${text.replace(/\s+/g, ' ').trim()}"`);
  say(`  pipeline warnings: ${pipelineWarnings.length}`);
  for (const line of [...new Set(pipelineWarnings)].slice(0, 5)) say(`    ${line.slice(0, 300)}`);
}
await page.getByLabel(/Stop capture|Pause capture/).first().click().catch(() => {});
await sleep(1000);
await page.evaluate(() => (window as unknown as { inwire?: { setUnsavedCapture?(v: boolean): void } }).inwire?.setUnsavedCapture?.(false)).catch(() => {});
raw?.close();
await app.close().catch(() => {});
await agent.close();
try { rmSync(profile, { recursive: true, force: true }); } catch { /* the store may still hold a file a moment */ }
if (OUT) writeFileSync(OUT, report.join('\n') + '\n');
process.exit(0);
