/**
 * The speed test's network half (ADR 0054): Node's own HTTP/1.1 client against
 * Cloudflare's speed endpoints, emitting `SpeedEvent`s as it goes.
 *
 * **Node's `https`, not `net.fetch`.** Chromium's stack may negotiate HTTP/3 to
 * Cloudflare, which would put the test on QUIC where the capture's TCP analysis
 * cannot see it; Node speaks HTTP/1.1 over TCP and nothing else.
 *
 * **Imports no Electron**, so `scripts/speed-test/engine.ts` drives it under
 * plain `tsx` against a local `node:http` server - the target is a parameter,
 * and production pins it to `CLOUDFLARE` (`electron/speedTest/entry.ts`), the
 * host `MAIN_OUTBOUND_HOSTS.speedTest` records.
 *
 * What the bytes MEAN is `src/services/speedTest/method.ts`; this file only
 * moves them and reads the clock.
 */
import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import {
  bloatGrade, DOWNLOAD_CAP_BYTES, DOWNLOAD_REQUEST_BYTES, jitter, LATENCY_SAMPLES, LOADED_PROBE_MS,
  median, netLatency, RAMP_EVERY_MS, RAMP_STEP, shouldRamp, SliceCounter, SLICE_MS, START_CONNECTIONS,
  transferFigure, TRANSFER_MS, UPLOAD_CAP_BYTES, UPLOAD_REQUEST_BYTES, WARMUP_MS, type TransferFigure,
} from '../../src/services/speedTest/method';
import type { SpeedEvent, SpeedPhase, SpeedServer } from '../../src/services/speedTest/protocol';

/** Where the test goes. Production is `CLOUDFLARE` and nothing else. */
export interface SpeedTarget {
  protocol: 'https:' | 'http:';
  host: string;
  port?: number;
  /**
   * Sent with the metadata request. Cloudflare's `/meta` answers `{}` unless
   * the request says it comes from their own page, which is the only page that
   * uses it; the ISP and the data centre's city are in that answer.
   */
  metaHeaders?: Record<string, string>;
}

export const CLOUDFLARE: SpeedTarget = {
  protocol: 'https:',
  host: 'speed.cloudflare.com',
  metaHeaders: { Origin: 'https://speed.cloudflare.com', Referer: 'https://speed.cloudflare.com/' },
};

/** The method's knobs, all defaulted to `method.ts`; tests shorten them. */
export interface EngineOptions {
  target: SpeedTarget;
  transferMs?: number;
  warmupMs?: number;
  latencySamples?: number;
  downloadCapBytes?: number;
  uploadCapBytes?: number;
  downloadRequestBytes?: number;
  uploadRequestBytes?: number;
  /** A request that sends nothing back for this long has failed rather than stalled. */
  idleTimeoutMs?: number;
}

/** A refusal worth naming: Cloudflare limits how much one address may test. */
export class RateLimited extends Error {
  constructor() { super('Cloudflare is limiting tests from this address - try again in a few minutes.'); }
}
class Aborted extends Error {}

const now = (): number => performance.now();

/**
 * Runs one whole test. Resolves when it has ended - done, failed or cancelled -
 * having emitted exactly one of `done`, `failed` or `cancelled` last. Never
 * rejects: every way out is an event, because a test that ended silently is a
 * dial that spins for ever.
 */
export async function runSpeedTest(
  options: EngineOptions,
  emit: (event: SpeedEvent) => void,
  signal: AbortSignal,
): Promise<void> {
  const run = new Run(options, emit, signal);
  let phase: SpeedPhase = 'connecting';
  try {
    emit({ type: 'phase', phase });
    const server = await run.meta();
    emit({ type: 'server', server });

    phase = 'latency';
    emit({ type: 'phase', phase });
    const idle = await run.idleLatency();

    phase = 'download';
    emit({ type: 'phase', phase });
    const down = await run.transfer('download');

    phase = 'upload';
    emit({ type: 'phase', phase });
    const up = await run.transfer('upload');

    const idleMs = median(idle)!;
    const loaded = Math.max(down.loadedLatencyMs ?? idleMs, up.loadedLatencyMs ?? idleMs);
    emit({
      type: 'done',
      result: {
        at: Date.now(),
        server: { ...server, colo: server.colo ?? run.colo },
        latency: { idleMs, jitterMs: jitter(idle) ?? 0, samples: idle.length },
        download: down,
        upload: up,
        grade: bloatGrade(idleMs, loaded),
        bytesMoved: down.bytes + up.bytes,
      },
    });
  } catch (error) {
    if (error instanceof Aborted || signal.aborted) emit({ type: 'cancelled' });
    else emit({
      type: 'failed',
      phase,
      message: error instanceof Error ? error.message : String(error),
      ...(error instanceof RateLimited ? { rateLimited: true } : {}),
    });
  } finally {
    run.close();
  }
}

interface Response { status: number; headers: http.IncomingHttpHeaders; firstByteMs: number }

class Run {
  private readonly client: typeof http | typeof https;
  private readonly agents = new Set<http.Agent>();
  private readonly requests = new Set<http.ClientRequest>();
  /** The data centre, from any response's `colo` header, if `/meta` said nothing. */
  colo: string | null = null;
  private readonly transferMs: number;
  private readonly warmupMs: number;
  private readonly idleTimeoutMs: number;

  constructor(
    private readonly options: EngineOptions,
    private readonly emit: (event: SpeedEvent) => void,
    private readonly signal: AbortSignal,
  ) {
    this.client = options.target.protocol === 'https:' ? https : http;
    this.transferMs = options.transferMs ?? TRANSFER_MS;
    this.warmupMs = options.warmupMs ?? WARMUP_MS;
    this.idleTimeoutMs = options.idleTimeoutMs ?? 15_000;
    signal.addEventListener('abort', () => this.close(), { once: true });
  }

  private agent(maxSockets: number): http.Agent {
    const agent = new this.client.Agent({ keepAlive: true, maxSockets });
    this.agents.add(agent);
    return agent;
  }

  /** Every socket this run opened, closed. Safe to call twice. */
  close(): void {
    for (const req of this.requests) req.destroy();
    this.requests.clear();
    for (const agent of this.agents) agent.destroy();
    this.agents.clear();
  }

  private checkAborted(): void {
    if (this.signal.aborted) throw new Aborted();
  }

  /**
   * One request. `onData` sees the body as it arrives; `body` is written for a
   * POST by `writeBody`, which owns the pacing. Rejects on a non-2xx answer
   * (429 as `RateLimited`), a socket error or `idleTimeoutMs` of silence.
   */
  private request(
    agent: http.Agent,
    method: 'GET' | 'POST',
    path: string,
    opts: {
      headers?: Record<string, string>;
      onData?: (bytes: number) => void;
      writeBody?: (req: http.ClientRequest) => void;
      stopped?: () => boolean;
    } = {},
  ): Promise<Response & { body: Buffer | null }> {
    this.checkAborted();
    const { target } = this.options;
    return new Promise((resolve, reject) => {
      const startedAt = now();
      let firstByteMs = 0;
      const chunks: Buffer[] | null = opts.onData ? null : [];
      const req = this.client.request({
        protocol: target.protocol, host: target.host, port: target.port, method, path, agent,
        headers: { 'User-Agent': 'Inwire speed test', ...opts.headers },
      }, (res) => {
        firstByteMs = now() - startedAt;
        const colo = res.headers.colo;
        if (typeof colo === 'string' && this.colo === null) this.colo = colo;
        const status = res.statusCode ?? 0;
        if (status < 200 || status >= 300) {
          res.resume();
          this.requests.delete(req);
          reject(status === 429 ? new RateLimited() : new Error(`the test server answered ${status} to ${path.split('?')[0]}`));
          return;
        }
        res.on('data', (chunk: Buffer) => {
          if (chunks) chunks.push(chunk);
          else opts.onData!(chunk.length);
        });
        res.on('end', () => {
          this.requests.delete(req);
          resolve({ status, headers: res.headers, firstByteMs, body: chunks ? Buffer.concat(chunks) : null });
        });
        res.on('error', (error) => { this.requests.delete(req); reject(error); });
        res.on('aborted', () => { this.requests.delete(req); reject(new Error('the test server closed the connection')); });
      });
      this.requests.add(req);
      req.setTimeout(this.idleTimeoutMs, () => req.destroy(new Error('the test server stopped answering')));
      req.on('error', (error) => {
        this.requests.delete(req);
        // A transfer stopped on purpose destroys its in-flight requests; that is
        // the end of a phase, not a failure.
        if (opts.stopped?.() || this.signal.aborted) resolve({ status: 0, headers: {}, firstByteMs, body: null });
        else reject(error);
      });
      if (opts.writeBody) opts.writeBody(req);
      else req.end();
    });
  }

  /** Who and where: the ISP and the data centre, from `/meta`. Never fatal. */
  async meta(): Promise<SpeedServer> {
    const empty: SpeedServer = { colo: null, coloCity: null, isp: null, asn: null, ip: null, city: null };
    try {
      const res = await this.request(this.agent(1), 'GET', '/meta', { headers: this.options.target.metaHeaders });
      const v = JSON.parse(res.body?.toString('utf8') || '{}') as Record<string, unknown>;
      const colo = (typeof v.colo === 'object' && v.colo !== null ? v.colo : {}) as Record<string, unknown>;
      const str = (x: unknown): string | null => (typeof x === 'string' && x.length > 0 && x.length < 200 ? x : null);
      return {
        colo: str(colo.iata),
        coloCity: str(colo.city),
        isp: str(v.asOrganization),
        asn: typeof v.asn === 'number' ? v.asn : null,
        ip: str(v.clientIp),
        city: str(v.city),
      };
    } catch (error) {
      if (error instanceof RateLimited || error instanceof Aborted || this.signal.aborted) throw error;
      return empty;
    }
  }

  /** Idle latency: empty requests on one warm connection, the first dropped. */
  async idleLatency(): Promise<number[]> {
    const agent = this.agent(1);
    const samples: number[] = [];
    const count = this.options.latencySamples ?? LATENCY_SAMPLES;
    for (let i = 0; i <= count; i++) {
      const res = await this.request(agent, 'GET', '/__down?bytes=0');
      if (i === 0) continue; // the TCP and TLS handshakes, not a round trip
      const ms = netLatency(res.firstByteMs, header(res.headers['server-timing']));
      samples.push(ms);
      this.emit({ type: 'latency', ms });
    }
    return samples;
  }

  /**
   * One direction: connections looping requests for `transferMs` or until the
   * cap, bytes counted into slices, ramping while the total still rises, and
   * a loaded-latency probe on a connection of its own throughout.
   */
  async transfer(direction: 'download' | 'upload'): Promise<TransferFigure & { loadedLatencyMs: number | null; connections: number }> {
    const counter = new SliceCounter(SLICE_MS);
    const cap = direction === 'download'
      ? this.options.downloadCapBytes ?? DOWNLOAD_CAP_BYTES
      : this.options.uploadCapBytes ?? UPLOAD_CAP_BYTES;
    const requestBytes = direction === 'download'
      ? this.options.downloadRequestBytes ?? DOWNLOAD_REQUEST_BYTES
      : this.options.uploadRequestBytes ?? UPLOAD_REQUEST_BYTES;
    const agent = this.agent(64);
    const probeAgent = this.agent(1);
    const startedAt = now();
    const elapsed = (): number => now() - startedAt;
    let moved = 0;
    let committed = 0;
    let stopped = false;
    let failure: unknown = null;
    let connections = 0;
    const loaded: number[] = [];
    const count = (bytes: number): void => {
      if (stopped) return;
      counter.add(elapsed(), bytes);
      moved += bytes;
      if (moved >= cap) stopped = true;
    };
    // One random megabyte, sent over and over: incompressible, and TLS makes
    // the repetition invisible on the wire.
    const payload = direction === 'upload' ? randomBytes(1 << 20) : null;

    const worker = async (): Promise<void> => {
      while (!stopped && !this.signal.aborted && elapsed() < this.transferMs) {
        const size = Math.min(requestBytes, cap - committed);
        if (size <= 0) break;
        committed += size;
        if (direction === 'download') {
          await this.request(agent, 'GET', `/__down?bytes=${size}`, { onData: count, stopped: () => stopped });
        } else {
          await this.request(agent, 'POST', '/__up', {
            headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': String(size) },
            stopped: () => stopped,
            writeBody: (req) => writeRandom(req, payload!, size, count, () => stopped),
          });
        }
      }
    };

    const workers: Promise<void>[] = [];
    const spawn = (n: number): void => {
      for (let i = 0; i < n; i++) {
        connections++;
        workers.push(worker().catch((error) => {
          if (!stopped) { failure ??= error; stopped = true; }
        }));
      }
    };
    spawn(START_CONNECTIONS);

    // The dial: the last second's speed, every slice.
    const progress = setInterval(() => {
      const t = elapsed();
      this.emit({
        type: 'progress', phase: direction, connections,
        mbps: counter.mbpsOver(Math.max(0, t - 1000), t), elapsedMs: Math.round(t),
      });
    }, SLICE_MS);
    // More connections while the total still rises.
    const ramp = setInterval(() => {
      const t = elapsed();
      if (stopped || t < 2 * RAMP_EVERY_MS) return;
      if (shouldRamp(connections, counter.mbpsOver(t - 1000, t), counter.mbpsOver(t - 2000, t - 1000))) {
        spawn(RAMP_STEP);
      }
    }, RAMP_EVERY_MS);
    // Loaded latency: an empty request every ~150 ms on its own connection.
    const probe = (async () => {
      while (!stopped && !this.signal.aborted && elapsed() < this.transferMs) {
        const began = now();
        try {
          const res = await this.request(probeAgent, 'GET', '/__down?bytes=0', { stopped: () => stopped });
          if (res.status === 200) {
            const ms = netLatency(res.firstByteMs, header(res.headers['server-timing']));
            loaded.push(ms);
            this.emit({ type: 'loaded', phase: direction, ms });
          }
        } catch {
          // A probe that fails under load is a lost sample, not a failed test.
        }
        const wait = LOADED_PROBE_MS - (now() - began);
        if (wait > 0) await sleep(wait);
      }
    })();

    const deadline = setTimeout(() => { stopped = true; endTransfer(); }, this.transferMs);
    const endTransfer = (): void => {
      // Cut the requests still in flight: a 25 MB request must not outlive the
      // phase it belongs to and pollute the next one.
      for (const req of [...this.requests]) req.destroy();
    };
    await new Promise<void>((resolve) => {
      const check = setInterval(() => {
        if (stopped || this.signal.aborted || elapsed() >= this.transferMs) {
          clearInterval(check);
          stopped = true;
          endTransfer();
          resolve();
        }
      }, 20);
    });
    clearTimeout(deadline);
    clearInterval(progress);
    clearInterval(ramp);
    await Promise.allSettled([...workers, probe]);
    agent.destroy();
    probeAgent.destroy();
    this.checkAborted();
    if (failure !== null) throw failure;

    const figure = transferFigure(counter, this.warmupMs, elapsed());
    if (figure === null) throw new Error(`the ${direction} moved no data`);
    this.emit({ type: 'figure', phase: direction, figure });
    return { ...figure, loadedLatencyMs: median(loaded), connections };
  }
}

/** Writes `size` bytes of `payload`, repeated, honouring backpressure and counting what the socket took. */
function writeRandom(
  req: http.ClientRequest, payload: Buffer, size: number, count: (bytes: number) => void, stopped: () => boolean,
): void {
  const CHUNK = 64 * 1024;
  let sent = 0;
  const pump = (): void => {
    while (sent < size) {
      if (stopped() || req.destroyed) return;
      const n = Math.min(CHUNK, size - sent);
      const offset = sent % (payload.length - CHUNK);
      const chunk = payload.subarray(offset, offset + n);
      sent += n;
      const ok = req.write(chunk, () => count(n));
      if (!ok) { req.once('drain', pump); return; }
    }
    req.end();
  };
  pump();
}

function header(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value.join(', ') : value;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
