/**
 * The reader half of `key-log-table.ts`: a `worker_threads` thread that adopts
 * the writer's buffer and looks connections up while the main thread is still
 * appending to it. Not a test by itself (no exit call: it ends by closing its
 * port), and it also exports the deterministic corpus both halves derive from.
 *
 * Connection `i` has a random and five secrets, all from a PRNG seeded by `i`,
 * so the reader can say what any connection must hold without being told.
 */
import { isMainThread, parentPort } from 'node:worker_threads';
import { KeyLogStore, type KeyLogShared } from '../../src/services/tls/keyLog';

export const THREAD_LABELS = [
  'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
  'SERVER_HANDSHAKE_TRAFFIC_SECRET',
  'CLIENT_TRAFFIC_SECRET_0',
  'SERVER_TRAFFIC_SECRET_0',
  'EXPORTER_SECRET',
] as const;

export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randomBytes(next: () => number, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i++) out[i] = Math.floor(next() * 256);
  return out;
}

const BYTE_HEX = Array.from({ length: 256 }, (_, x) => x.toString(16).padStart(2, '0'));
export function hexOf(b: Uint8Array): string {
  let out = '';
  for (let i = 0; i < b.length; i++) out += BYTE_HEX[b[i]];
  return out;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/** Connection `i`'s client random and its five secrets (32 bytes, 48 for odd `i`). */
export function connection(i: number): { random: Uint8Array; secrets: Uint8Array[] } {
  const next = mulberry32(Math.imul(i + 1, 0x9e3779b1) ^ 0x5bd1e995);
  const random = randomBytes(next, 32);
  const size = i % 2 === 0 ? 32 : 48;
  return { random, secrets: THREAD_LABELS.map(() => randomBytes(next, size)) };
}

/** The five key log lines of connection `i`. */
export function connectionText(i: number): string {
  const { random, secrets } = connection(i);
  const r = hexOf(random);
  return THREAD_LABELS.map((label, k) => `${label} ${r} ${hexOf(secrets[k])}\n`).join('');
}

export interface ReaderReport {
  /** Announced connections that were missing or not whole and correct. */
  wrong: number;
  /** Unannounced lookups that returned data that was not a correct prefix of the connection. */
  torn: number;
  /** Unannounced lookups that found a connection mid-write: a correct prefix, shorter than five. */
  partial: number;
  /** Lookups of connections the writer never wrote that found something. */
  phantom: number;
  adopted: number;
  checked: number;
}

export type ToReader =
  | { type: 'snapshot'; snapshot: KeyLogShared }
  | { type: 'step'; from: number; to: number }
  | { type: 'done' };

if (!isMainThread && parentPort) {
  const port = parentPort;
  const store = new KeyLogStore();
  const report: ReaderReport = { wrong: 0, torn: 0, partial: 0, phantom: 0, adopted: 0, checked: 0 };

  /** 'whole' (five correct), 'partial' (a correct prefix), 'none' (absent) or 'bad'. */
  const classify = (i: number): 'whole' | 'partial' | 'none' | 'bad' => {
    const { random, secrets } = connection(i);
    const found = store.secretsFor(random);
    if (found === undefined) return 'none';
    let k = 0;
    for (; k < THREAD_LABELS.length; k++) {
      const got = found.get(THREAD_LABELS[k]);
      if (got === undefined) break;
      if (!sameBytes(got, secrets[k])) return 'bad';
    }
    if (found.size !== k || k === 0) return 'bad';
    return k === THREAD_LABELS.length ? 'whole' : 'partial';
  };

  port.on('message', (message: ToReader) => {
    if (message.type === 'snapshot') {
      store.adopt(message.snapshot);
      report.adopted++;
    } else if (message.type === 'step') {
      for (let i = message.from; i < message.to; i++) {
        report.checked++;
        if (classify(i) !== 'whole') report.wrong++;
      }
      // The writer is already appending the next step: look at what it may be mid-way through.
      for (let pass = 0; pass < 3; pass++) {
        for (let i = message.to; i < message.to + 2000; i++) {
          const c = classify(i);
          if (c === 'bad') report.torn++;
          else if (c === 'partial') report.partial++;
        }
      }
      // And at connections that were never written.
      for (let i = 50_000_000; i < 50_000_100; i++) if (classify(i) !== 'none') report.phantom++;
    } else {
      port.postMessage(report);
      port.close();
    }
  });
}
