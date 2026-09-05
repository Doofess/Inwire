/**
 * The NSS key log, which is how a browser hands over the secrets for its own
 * TLS and QUIC connections.
 *
 * Set `SSLKEYLOGFILE=<path>` before starting Chrome or Firefox and every
 * connection it makes appends its secrets to that file, one per line:
 *
 *   <LABEL> <client_random, 32 bytes hex> <secret, hex>
 *
 * The client random is the join key. It is the one value that is both unique
 * per connection and visible to a passive observer - it sits in the clear in
 * every ClientHello, TLS and QUIC alike - which is exactly why the format
 * chose it. Nothing here needs the private key of anything: these are the
 * session secrets themselves, already derived.
 *
 * Labels this understands:
 *
 *   CLIENT_RANDOM                     TLS 1.2's 48-byte master secret
 *   CLIENT_HANDSHAKE_TRAFFIC_SECRET   TLS 1.3, encrypted handshake, client
 *   SERVER_HANDSHAKE_TRAFFIC_SECRET   TLS 1.3, encrypted handshake, server
 *   CLIENT_TRAFFIC_SECRET_0           TLS 1.3, application data, client
 *   SERVER_TRAFFIC_SECRET_0           TLS 1.3, application data, server
 *   CLIENT_EARLY_TRAFFIC_SECRET       TLS 1.3, 0-RTT data
 *
 * EXPORTER_SECRET and EARLY_EXPORTER_SECRET are parsed and kept, though
 * nothing decrypts with them; they are what a key log is for when the question
 * is about an exporter-derived channel binding rather than the traffic.
 *
 * A key log is as sensitive as the traffic it opens, so it is held in memory
 * only: never written to session storage, never included in an export unless
 * the user asks for the Decryption Secrets Block explicitly.
 */

/** The labels a line may carry. Anything else is counted and ignored. */
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

export interface KeyLogStats {
  /** Connections (distinct client randoms) the log covers. */
  connections: number;
  /** Secret lines accepted. */
  secrets: number;
  /** Lines that were neither blank, a comment, nor a label we know. */
  ignored: number;
}

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

export function toHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

/**
 * Secrets indexed by client random.
 *
 * One instance per JavaScript context: the dissection pipeline runs in a
 * Worker and imports run on the main thread, so a key log the user loads is
 * pushed to both rather than shared.
 */
export class KeyLogStore {
  private byRandom = new Map<string, Map<string, Uint8Array>>();
  private ignoredLines = 0;
  private acceptedLines = 0;
  /** Every line accepted, in order, so an export can write back what was read. */
  private lines: string[] = [];
  /**
   * Bumped by every `add`. A dissector that concluded "no secret for this
   * connection" records the generation it concluded it at, so loading a log
   * during a live capture reopens the connections that were opaque instead of
   * leaving them opaque until the app is restarted.
   */
  public generation = 0;

  /**
   * Adds a key log's text. Callable repeatedly - a capture may pick up secrets
   * from a pcapng's own Decryption Secrets Blocks *and* a file the user
   * supplies, and a later line for the same label wins because a key log is
   * append-only and a repeated label means the connection was resumed.
   */
  public add(text: string): KeyLogStats {
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.length === 0 || line.startsWith('#')) continue;

      const parts = line.split(/\s+/);
      if (parts.length !== 3 || !KNOWN_LABELS.has(parts[0])) { this.ignoredLines++; continue; }

      const [label, randomHex, secretHex] = parts;
      // 32 bytes, always: the client random is a fixed-width field in the
      // ClientHello, and a line whose join key is the wrong width could not
      // match any connection anyway.
      if (randomHex.length !== 64) { this.ignoredLines++; continue; }
      const secret = fromHex(secretHex);
      if (secret === null) { this.ignoredLines++; continue; }

      const key = randomHex.toLowerCase();
      let entry = this.byRandom.get(key);
      if (entry === undefined) { entry = new Map(); this.byRandom.set(key, entry); }
      entry.set(label, secret);
      this.acceptedLines++;
      this.lines.push(`${label} ${key} ${secretHex.toLowerCase()}`);
    }

    this.generation++;
    return this.stats();
  }

  public stats(): KeyLogStats {
    return { connections: this.byRandom.size, secrets: this.acceptedLines, ignored: this.ignoredLines };
  }

  /** The secrets for one connection, or undefined when the log does not cover it. */
  public secretsFor(clientRandom: Uint8Array): Map<string, Uint8Array> | undefined {
    return this.byRandom.get(toHex(clientRandom));
  }

  public get isEmpty(): boolean {
    return this.byRandom.size === 0;
  }

  /** The log as text, for writing a pcapng Decryption Secrets Block. */
  public serialise(): string {
    return this.lines.length === 0 ? '' : `${this.lines.join('\n')}\n`;
  }

  public clear(): void {
    this.generation++;
    this.byRandom.clear();
    this.lines = [];
    this.ignoredLines = 0;
    this.acceptedLines = 0;
  }
}

/** The store this context dissects against. */
export const keyLog = new KeyLogStore();
