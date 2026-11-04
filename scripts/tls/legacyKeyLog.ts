/**
 * The key log store as it was before `KeyLogTable` (ADR 0073), kept verbatim as
 * the oracle `key-log-table.ts` compares the compact store against: a Map of
 * Maps, one string per line. Not used by the app, and it is not a test (it has
 * no exit call of its own, so `check.ts` does not run it).
 */
import { toHex } from '../../src/services/addressFormat';

const KNOWN_LABELS = new Set([
  'CLIENT_RANDOM',
  'CLIENT_EARLY_TRAFFIC_SECRET',
  'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
  'SERVER_HANDSHAKE_TRAFFIC_SECRET',
  'CLIENT_TRAFFIC_SECRET_0',
  'SERVER_TRAFFIC_SECRET_0',
  'EXPORTER_SECRET',
  'EARLY_EXPORTER_SECRET',
]);

export interface LegacyKeyLogStats { connections: number; secrets: number; ignored: number }

function fromHex(text: string): Uint8Array | null {
  if (text.length === 0 || text.length % 2 !== 0) return null;
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(text.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) return null;
    out[i] = byte;
  }
  return out;
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export class LegacyKeyLogStore {
  private byRandom = new Map<string, Map<string, Uint8Array>>();
  private ignoredLines = 0;
  private acceptedLines = 0;
  private lines: string[] = [];
  public generation = 0;

  public add(text: string): LegacyKeyLogStats {
    let changed = false;
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.length === 0 || line.startsWith('#')) continue;

      const parts = line.split(/\s+/);
      if (parts.length !== 3 || !KNOWN_LABELS.has(parts[0])) { this.ignoredLines++; continue; }

      const [label, randomHex, secretHex] = parts;
      if (randomHex.length !== 64) { this.ignoredLines++; continue; }
      const secret = fromHex(secretHex);
      if (secret === null) { this.ignoredLines++; continue; }

      const key = randomHex.toLowerCase();
      let entry = this.byRandom.get(key);
      if (entry === undefined) { entry = new Map(); this.byRandom.set(key, entry); }
      const held = entry.get(label);
      if (held !== undefined && sameBytes(held, secret)) continue;
      entry.set(label, secret);
      this.acceptedLines++;
      this.lines.push(`${label} ${key} ${secretHex.toLowerCase()}`);
      changed = true;
    }

    if (changed) this.generation++;
    return this.stats();
  }

  public stats(): LegacyKeyLogStats {
    return { connections: this.byRandom.size, secrets: this.acceptedLines, ignored: this.ignoredLines };
  }

  public secretsFor(clientRandom: Uint8Array): Map<string, Uint8Array> | undefined {
    return this.byRandom.get(toHex(clientRandom));
  }

  public get isEmpty(): boolean {
    return this.byRandom.size === 0;
  }

  public serialise(): string {
    return this.lines.length === 0 ? '' : `${this.lines.join('\n')}\n`;
  }
}
