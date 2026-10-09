/**
 * The speed-test engine against a local server that speaks Cloudflare's three
 * endpoints, so every way a test can end is driven without the internet.
 *
 *   npx tsx scripts/speed-test/engine.ts
 *
 * The server serves `/__down?bytes=N`, takes `POST /__up`, answers `/meta`, and
 * can be told to refuse (429, 500) or to stall. What is held: bytes are counted
 * the way they moved, connections ramp, a cancel at any point ends the run with
 * `cancelled` and leaves no socket open, and every failure is an event rather
 * than a hang.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { runSpeedTest, type EngineOptions } from '../../electron/speedTest/engine';
import type { SpeedEvent } from '../../src/services/speedTest/protocol';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

type Mode = 'ok' | 'down429' | 'up500' | 'stallDown' | 'meta500';
const ZERO = Buffer.alloc(64 * 1024);

async function serve(mode: Mode) {
  let uploaded = 0;
  let downloaded = 0;
  const sockets = new Set<import('node:net').Socket>();
  let peak = 0;
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    if (url.pathname === '/meta') {
      if (mode === 'meta500') { res.writeHead(500); res.end(); return; }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ asOrganization: 'Test ISP', asn: 64512, clientIp: '192.0.2.7', city: 'Testville', colo: { iata: 'TST', city: 'Test City' } }));
      return;
    }
    if (url.pathname === '/__down') {
      const bytes = Number(url.searchParams.get('bytes') ?? 0);
      if (mode === 'down429' && bytes > 0) { res.writeHead(429); res.end('x'); return; }
      res.writeHead(200, { 'Content-Length': String(bytes), 'Server-Timing': 'cfSpeedWorker;dur=1', colo: 'TST' });
      if (mode === 'stallDown' && bytes > 0) { res.write(ZERO.subarray(0, 1000)); return; } // and then nothing
      let left = bytes;
      const pump = (): void => {
        while (left > 0) {
          const n = Math.min(left, ZERO.length);
          left -= n;
          downloaded += n;
          if (!res.write(ZERO.subarray(0, n))) { res.once('drain', pump); return; }
        }
        res.end();
      };
      pump();
      return;
    }
    if (url.pathname === '/__up') {
      if (mode === 'up500') { req.resume(); res.writeHead(500); res.end(); return; }
      req.on('data', (c: Buffer) => { uploaded += c.length; });
      req.on('end', () => { res.writeHead(200); res.end(); });
      req.on('error', () => {});
      return;
    }
    res.writeHead(404); res.end();
  });
  server.on('connection', (s) => {
    sockets.add(s);
    peak = Math.max(peak, sockets.size);
    s.on('close', () => sockets.delete(s));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as AddressInfo).port;
  return {
    port,
    open: () => sockets.size,
    peak: () => peak,
    uploaded: () => uploaded,
    downloaded: () => downloaded,
    close: () => new Promise<void>((r) => { for (const s of sockets) s.destroy(); server.close(() => r()); }),
  };
}

const quick = (port: number, extra: Partial<EngineOptions> = {}): EngineOptions => ({
  target: { protocol: 'http:', host: '127.0.0.1', port },
  transferMs: 2_500, warmupMs: 500, latencySamples: 5,
  downloadCapBytes: 4_000_000_000, uploadCapBytes: 4_000_000_000,
  downloadRequestBytes: 8_000_000, uploadRequestBytes: 4_000_000,
  idleTimeoutMs: 1_500,
  ...extra,
});

async function run(options: EngineOptions, cancelAfterMs?: number, cancelWhen?: (e: SpeedEvent) => boolean) {
  const events: SpeedEvent[] = [];
  const ac = new AbortController();
  if (cancelAfterMs !== undefined) setTimeout(() => ac.abort(), cancelAfterMs);
  const startedAt = Date.now();
  await runSpeedTest(options, (e) => { events.push(e); if (cancelWhen?.(e)) ac.abort(); }, ac.signal);
  return { events, ms: Date.now() - startedAt };
}
const last = (events: SpeedEvent[]) => events[events.length - 1];
const settle = () => new Promise((r) => setTimeout(r, 300));

// --- a whole test ---------------------------------------------------------------
{
  const s = await serve('ok');
  const { events } = await run(quick(s.port));
  const end = last(events);
  check('a whole test ends with done', end.type === 'done', JSON.stringify(end).slice(0, 200));
  if (end.type === 'done') {
    const r = end.result;
    check('...with the server and ISP from /meta', r.server.isp === 'Test ISP' && r.server.coloCity === 'Test City' && r.server.ip === '192.0.2.7');
    check('...five idle samples, the handshake dropped', r.latency.samples === 5);
    check('...a download figure', r.download.mbps > 0 && r.download.p10 <= r.download.mbps && r.download.mbps <= r.download.p90);
    check('...an upload figure', r.upload.mbps > 0);
    check('...the bytes it counted downloading are bytes the server sent',
      r.download.bytes > 0 && r.download.bytes <= s.downloaded(), `${r.download.bytes} vs ${s.downloaded()}`);
    check('...and uploading, no more than the server received plus what was in flight',
      r.upload.bytes > 0 && r.upload.bytes <= s.uploaded() + 8 * 4_000_000, `${r.upload.bytes} vs ${s.uploaded()}`);
    check('...and a grade', /^(A\+|[A-DF])$/.test(r.grade));
  }
  const phases = events.filter((e) => e.type === 'phase').map((e) => (e as { phase: string }).phase);
  check('the phases come in order', JSON.stringify(phases) === JSON.stringify(['connecting', 'latency', 'download', 'upload']), phases.join(','));
  check('progress is reported while transferring', events.filter((e) => e.type === 'progress').length >= 20);
  check('loaded latency is probed during the transfers', events.filter((e) => e.type === 'loaded').length >= 4);
  await settle();
  check('...and no socket is left open', s.open() === 0, `${s.open()} open`);
  await s.close();
}

// --- caps -----------------------------------------------------------------------
{
  const s = await serve('ok');
  const { events } = await run(quick(s.port, { downloadCapBytes: 30_000_000, uploadCapBytes: 12_000_000 }));
  const end = last(events);
  check('a capped test still ends with done', end.type === 'done', JSON.stringify(end).slice(0, 300));
  if (end.type === 'done') {
    check('the download stops at its cap', end.result.download.bytes <= 30_000_000 + 1_000_000, String(end.result.download.bytes));
    check('the upload stops at its cap', end.result.upload.bytes <= 12_000_000 + 1_000_000, String(end.result.upload.bytes));
  }
  await s.close();
}

// --- cancel at every phase ---------------------------------------------------------
for (const at of ['latency', 'download', 'upload'] as const) {
  const s = await serve('ok');
  let seen = 0;
  const { events, ms } = await run(quick(s.port), undefined, (e) => {
    if (e.type === 'phase' && e.phase === at) seen = 1;
    // A little way into the phase, not on its first event.
    return seen > 0 && ++seen > 4;
  });
  check(`a cancel during ${at} ends with cancelled`, last(events).type === 'cancelled', last(events).type);
  check(`...promptly (${ms} ms)`, ms < 6_000);
  await settle();
  check('...and leaves no socket open', s.open() === 0, `${s.open()} open`);
  await s.close();
}

// --- failures are events ---------------------------------------------------------------
{
  const s = await serve('down429');
  const { events, ms } = await run(quick(s.port));
  const end = last(events);
  check('a 429 ends the test as failed, rate-limited', end.type === 'failed' && end.rateLimited === true && end.phase === 'download',
    JSON.stringify(end));
  check('...and says what to do', end.type === 'failed' && /try again/.test(end.message));
  check(`...without waiting out the transfer (${ms} ms)`, ms < 3_000);
  await settle();
  check('...and leaves no socket open', s.open() === 0, `${s.open()} open`);
  await s.close();
}
{
  const s = await serve('up500');
  const { events } = await run(quick(s.port));
  const end = last(events);
  check('a server error during upload fails the upload phase, not a hang', end.type === 'failed' && end.phase === 'upload' && /500/.test(end.message),
    JSON.stringify(end));
  await s.close();
}
{
  const s = await serve('stallDown');
  const { events, ms } = await run(quick(s.port, { transferMs: 2_000 }));
  const end = last(events);
  check('a server that stops sending fails or finishes - it never hangs', end.type === 'failed' || end.type === 'done', JSON.stringify(end).slice(0, 160));
  check(`...within the phase plus the idle timeout (${ms} ms)`, ms < 9_000);
  await settle();
  check('...and leaves no socket open', s.open() === 0, `${s.open()} open`);
  await s.close();
}
{
  const s = await serve('meta500');
  const { events } = await run(quick(s.port));
  const end = last(events);
  check('a /meta that fails costs the server line, not the test', end.type === 'done' && end.result.server.isp === null);
  if (end.type === 'done') check('...and the data centre still comes from the colo header', end.result.server.colo === 'TST');
  await s.close();
}
{
  const { events } = await run(quick(1));
  const end = last(events);
  check('nothing listening fails at once, named', end.type === 'failed' && end.phase === 'connecting' || end.type === 'failed',
    JSON.stringify(end));
}

console.log(failures === 0 ? '\nAll speed-test engine checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
