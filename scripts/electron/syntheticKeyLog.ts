/**
 * A key log the size of a browser's after weeks of `SSLKEYLOGFILE`, made of
 * random hex: it opens nothing, and it is written to a temp file at run time,
 * never committed.
 *
 * The shape is the owner's real file's (ADR 0073), which is what the store's
 * cost depends on: one connection in 26 is TLS 1.2, one `CLIENT_RANDOM` line
 * with a 48-byte secret; the rest are TLS 1.3, five lines with 32-byte secrets,
 * and half of those also offer 0-RTT, a sixth line.
 */
import { randomBytes } from 'node:crypto';
import { createWriteStream } from 'node:fs';

const TLS13 = [
  'CLIENT_HANDSHAKE_TRAFFIC_SECRET', 'SERVER_HANDSHAKE_TRAFFIC_SECRET',
  'CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0', 'EXPORTER_SECRET',
];

/** Writes `connections` connections' lines to `file`; answers how many lines and bytes. */
export async function writeSyntheticKeyLog(file: string, connections: number): Promise<{ lines: number; bytes: number }> {
  const out = createWriteStream(file, { encoding: 'latin1' });
  let lines = 0;
  let bytes = 0;
  let chunk = '';
  const flush = async () => {
    bytes += chunk.length;
    if (!out.write(chunk)) await new Promise<void>((resolve) => out.once('drain', () => resolve()));
    chunk = '';
  };
  for (let c = 0; c < connections; c++) {
    const random = randomBytes(32).toString('hex');
    if (c % 26 === 0) {
      chunk += `CLIENT_RANDOM ${random} ${randomBytes(48).toString('hex')}\n`;
      lines++;
    } else {
      if (c % 2 === 0) { chunk += `CLIENT_EARLY_TRAFFIC_SECRET ${random} ${randomBytes(32).toString('hex')}\n`; lines++; }
      for (const label of TLS13) chunk += `${label} ${random} ${randomBytes(32).toString('hex')}\n`;
      lines += TLS13.length;
    }
    if (chunk.length >= 1 << 20) await flush();
  }
  await flush();
  await new Promise<void>((resolve, reject) => out.end((error?: Error | null) => (error ? reject(error) : resolve())));
  return { lines, bytes };
}
