/**
 * A local stand-in for Cloudflare's speed endpoints, at a speed and latency of
 * our choosing - for the Electron drives that exercise the speed-test sheet
 * through `INWIRE_SPEEDTEST_TARGET` (loopback only; see `loopbackTarget`).
 *
 * A helper, not a test: it has no `process.exit`, so `scripts/check.ts` does
 * not run it on its own.
 *
 * Throughput is a token bucket shared by every connection, so the engine's
 * ramp sees what a real bottleneck does: more connections, the same total.
 * Latency is a delay on the empty requests, rising while a transfer runs, so
 * the bufferbloat grade has something to grade.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';

export type StubMode = 'ok' | 'down429' | 'up500' | 'stall' | 'reset';

export interface StubOptions {
  downMbps?: number;
  upMbps?: number;
  /** Idle round trip, and what a busy link adds to it. */
  idleMs?: number;
  loadedExtraMs?: number;
  mode?: StubMode;
}

export interface SpeedStub {
  url: string;
  set(options: StubOptions): void;
  close(): Promise<void>;
}

// 256 KB a piece: paced by setTimeout, and at 64 KB the timer's granularity on
// Windows capped the stub near 130 Mb/s whatever it was asked for.
const CHUNK = Buffer.alloc(256 * 1024, 0x5a);

export async function startSpeedStub(initial: StubOptions = {}): Promise<SpeedStub> {
  let o: Required<StubOptions> = { downMbps: 400, upMbps: 60, idleMs: 8, loadedExtraMs: 25, mode: 'ok', ...initial };
  let activeTransfers = 0;
  /**
   * When bytes last moved. "Busy" is judged from this rather than from
   * `activeTransfers`, which a cut connection can leave counted: a busy link
   * is one that moved data in the last few hundred milliseconds.
   */
  let lastMovedAt = -Infinity;
  const sockets = new Set<import('node:net').Socket>();

  /** Waits until `bytes` may pass at `mbps`, shared across everyone asking. */
  const buckets = { down: 0, up: 0 };
  const take = (dir: 'down' | 'up', bytes: number): Promise<void> => {
    lastMovedAt = performance.now();
    const mbps = dir === 'down' ? o.downMbps : o.upMbps;
    const bytesPerMs = (mbps * 1e6) / 8 / 1000;
    const now = performance.now();
    const at = Math.max(now, buckets[dir]) + bytes / bytesPerMs;
    buckets[dir] = at;
    // A little wobble, as a real link has.
    const wait = at - now + (Math.random() - 0.5) * 2;
    return new Promise((r) => setTimeout(r, Math.max(0, wait)));
  };
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', 'http://stub');
    // Unreachable, as a dropped connection looks from the client.
    if (o.mode === 'reset') { req.socket.destroy(); return; }
    if (url.pathname === '/meta') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        clientIp: '203.0.113.42', asn: 64500, asOrganization: 'Example Networks Ltd.', city: 'Haifa',
        colo: { iata: 'TLV', city: 'Tel Aviv' },
      }));
      return;
    }
    if (url.pathname === '/__down') {
      const bytes = Number(url.searchParams.get('bytes') ?? 0);
      if (bytes === 0) {
        const busy = performance.now() - lastMovedAt < 300;
        await sleep(o.idleMs + (busy ? o.loadedExtraMs : 0) + Math.random() * 1.5);
        res.writeHead(200, { 'Content-Length': '0', colo: 'TLV' });
        res.end();
        return;
      }
      if (o.mode === 'down429') { res.writeHead(429); res.end('x'); return; }
      res.writeHead(200, { 'Content-Length': String(bytes), colo: 'TLV' });
      if (o.mode === 'stall') { res.write(CHUNK.subarray(0, 1000)); return; }
      activeTransfers++;
      let left = bytes;
      let closed = false;
      // A transfer the client cut is over too, or the next test's idle ping
      // would be measured as if the link were still busy.
      res.on('close', () => { closed = true; });
      try {
        while (left > 0 && !closed) {
          const n = Math.min(left, CHUNK.length);
          await take('down', n);
          left -= n;
          // Drain or close, whichever comes: a write waiting on a response
          // the client cut would otherwise wait for ever.
          if (!res.write(CHUNK.subarray(0, n))) {
            await new Promise<void>((r) => {
              const done = (): void => { res.off('drain', done); res.off('close', done); r(); };
              res.on('drain', done);
              res.on('close', done);
            });
          }
        }
        res.end();
      } finally { activeTransfers--; }
      return;
    }
    if (url.pathname === '/__up') {
      if (o.mode === 'up500') { req.resume(); res.writeHead(500); res.end(); return; }
      activeTransfers++;
      req.on('data', (chunk: Buffer) => {
        req.pause();
        void take('up', chunk.length).then(() => req.resume());
      });
      req.on('end', () => { activeTransfers--; res.writeHead(200); res.end(); });
      req.on('close', () => { if (!res.writableEnded) activeTransfers = Math.max(0, activeTransfers - 1); });
      req.on('error', () => {});
      return;
    }
    res.writeHead(404); res.end();
  });
  server.on('connection', (s) => { sockets.add(s); s.on('close', () => sockets.delete(s)); });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    set(next) { o = { ...o, ...next }; },
    close: () => new Promise<void>((r) => { for (const s of sockets) s.destroy(); server.close(() => r()); }),
  };
}
