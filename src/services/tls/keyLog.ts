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
import { clearDerivedKeys } from '../crypto/aes';
import { toHex } from '../addressFormat';
import { KeyLogTable } from './keyLogTable';
import { MAX_KEYLOG_SECRETS } from './keyLogLimits';

export interface KeyLogStats {
  /** Connections (distinct client randoms) the log covers. */
  connections: number;
  /** Secret lines accepted. */
  secrets: number;
  /** Lines that were neither blank, a comment, nor a label we know. */
  ignored: number;
  /** Valid lines left out because the store already held `MAX_KEYLOG_SECRETS`. */
  dropped: number;
}

/** One state of the store, in a form that can be posted to a Worker. */
export interface KeyLogShared {
  buffer: SharedArrayBuffer | ArrayBuffer;
  /** True: shared memory, so later adds are visible without a new snapshot. False: a frozen copy. */
  live: boolean;
  /** The first snapshot after a clear; a reader flushes its derived AES keys on adopting it. */
  cleared: boolean;
}

export interface KeyLogStoreOptions {
  /** Test seam: force shared memory on or off. Default: on where the context allows it. */
  shared?: boolean;
  /** Test seam: the bound on stored secrets. Default `MAX_KEYLOG_SECRETS`. */
  maxSecrets?: number;
}

/** The longest a copy-mode writer waits before posting what it has learned. */
export const COPY_SNAPSHOT_MS = 250;

// Re-exported rather than moved out of reach: `toHex` reads as part of this
// module's surface at every call site that pairs it with a key log lookup.
export { toHex };

function canShareMemory(): boolean {
  return typeof SharedArrayBuffer === 'function'
    && (globalThis as { crossOriginIsolated?: boolean }).crossOriginIsolated !== false;
}

/**
 * Secrets indexed by client random.
 *
 * One writer per renderer, the page: the follower, the panel's Load and a
 * pcapng's Decryption Secrets Block all call `add` there. The pipeline Worker
 * and its shards `adopt` the page's buffer and read it in place, so the log is
 * held once (ADR 0073). A store that has adopted a buffer is a reader: `add`
 * and `clear` throw.
 *
 * The buffer is replaced when it fills and when the log is cleared. A
 * replacement is announced through `onSnapshot`; adds to a shared buffer are
 * not, because the readers already see them. Where memory cannot be shared
 * (`npm run dev` sends no COOP/COEP) the same protocol carries copies, at most
 * one per `COPY_SNAPSHOT_MS` after something changed.
 */
export class KeyLogStore {
  private table: KeyLogTable | null = null;
  private reader = false;
  private readonly live: boolean;
  private readonly maxSecrets: number;
  private readonly listeners = new Set<(snapshot: KeyLogShared) => void>();
  /** True from a clear until the buffer is next replaced (or, in copy mode, copied). */
  private clearedFlag = false;
  private copyTimer: ReturnType<typeof setTimeout> | undefined;

  public constructor(options: KeyLogStoreOptions = {}) {
    this.live = (options.shared ?? true) && canShareMemory();
    this.maxSecrets = options.maxSecrets ?? MAX_KEYLOG_SECRETS;
  }

  /**
   * Bumped by every `add` that learned something. A dissector that concluded
   * "no secret for this connection" records the generation it concluded it
   * at, so loading a log during a live capture reopens the connections that
   * were opaque instead of leaving them opaque until the app is restarted.
   *
   * **Only when something changed**, which did not matter while a key log
   * arrived once per session and matters a great deal now that it is
   * followed: `keyLogFollow` feeds every append Chrome makes, and a bump is
   * an instruction to every live TLS and QUIC conversation to re-derive its
   * keys on its next packet. A chunk that taught nothing must not cost that.
   *
   * It lives in the buffer, so a reader sees the writer's bumps, and it never
   * goes backwards across a replacement.
   */
  public get generation(): number {
    return this.table === null ? 0 : this.table.generation;
  }

  private create(generation: number): KeyLogTable {
    return KeyLogTable.create({ shared: this.live, maxSecrets: this.maxSecrets, generation });
  }

  /**
   * Adds a key log's text. Callable repeatedly - a capture may pick up secrets
   * from a pcapng's own Decryption Secrets Blocks *and* a file the user
   * supplies, and a later line for the same label wins because a key log is
   * append-only and a repeated label means the connection was resumed.
   *
   * A line already held is not a new secret: loading the same file twice
   * changes nothing, which matters because a followed file is re-sent whole
   * whenever a renderer attaches.
   */
  public add(text: string): KeyLogStats {
    if (this.reader) throw new Error('key log is read-only in this context');
    const table = this.table ?? (this.table = this.create(0));
    const before = table.buffer;
    const { changed } = table.addText(text);
    if (table.buffer !== before) this.clearedFlag = false;
    if (this.live) {
      if (table.buffer !== before) this.emit(this.snapshot(table));
    } else if (changed) {
      this.scheduleCopy();
    }
    return table.stats();
  }

  public stats(): KeyLogStats {
    return this.table === null ? { connections: 0, secrets: 0, ignored: 0, dropped: 0 } : this.table.stats();
  }

  /** The secrets for one connection, or undefined when the log does not cover it. Fresh copies. */
  public secretsFor(clientRandom: Uint8Array): Map<string, Uint8Array> | undefined {
    return this.table?.lookup(clientRandom);
  }

  public get isEmpty(): boolean {
    return this.table === null || this.table.isEmpty;
  }

  /** The log as ASCII text, one `LABEL random secret` line each, for a pcapng Decryption Secrets Block. */
  public serialise(): Uint8Array {
    return this.table === null ? new Uint8Array(0) : this.table.serialise();
  }

  /**
   * Forgets every secret.
   *
   * `clearDerivedKeys` too, and that is the point rather than tidiness. The
   * AES cache in `crypto/aes.ts` is keyed by the key bytes themselves and
   * holds up to 64 expanded schedules; nothing else ever flushed it, so
   * Settings -> Decryption reported "Cleared." while both the keys and their
   * schedules stayed in memory for the life of the page. ADR 0008's position
   * is that key material is transient, and a clear that leaves it behind is
   * the one place that was not true.
   *
   * The old buffer is retired, not zeroed: a reader still on it goes on
   * answering until it adopts the cleared snapshot, which is why that snapshot
   * is posted at once.
   */
  public clear(): void {
    if (this.reader) throw new Error('key log is read-only in this context');
    this.cancelCopy();
    this.table = this.create(this.generation + 1);
    this.clearedFlag = true;
    clearDerivedKeys();
    this.emit(this.snapshot(this.table));
  }

  /** The current buffer, allocated on first use. */
  public share(): KeyLogShared {
    if (this.table === null) this.table = this.create(0);
    return this.snapshot(this.table);
  }

  /**
   * Becomes a reader of a writer's buffer. A no-op when that buffer is this
   * store's own current one. Adopting a cleared snapshot flushes the derived
   * AES keys, as the writer's `clear` did.
   */
  public adopt(snapshot: KeyLogShared): void {
    if (this.table !== null && this.table.buffer === snapshot.buffer) return;
    const table = KeyLogTable.open(snapshot.buffer);
    this.cancelCopy();
    this.table = table;
    this.reader = true;
    if (snapshot.cleared) clearDerivedKeys();
  }

  /**
   * Hears of the writer's buffer being replaced (growth, clear) and, in copy
   * mode, of every change worth a copy. Returns the unsubscribe.
   */
  public onSnapshot(listener: (snapshot: KeyLogShared) => void): () => void {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  private snapshot(table: KeyLogTable): KeyLogShared {
    return this.live
      ? { buffer: table.buffer, live: true, cleared: this.clearedFlag }
      : { buffer: table.copy(), live: false, cleared: this.clearedFlag };
  }

  private emit(snapshot: KeyLogShared): void {
    if (!this.live) this.clearedFlag = false;
    for (const listener of [...this.listeners]) listener(snapshot);
  }

  private scheduleCopy(): void {
    if (this.copyTimer !== undefined || this.listeners.size === 0) return;
    this.copyTimer = setTimeout(() => {
      this.copyTimer = undefined;
      if (this.table !== null) this.emit(this.snapshot(this.table));
    }, COPY_SNAPSHOT_MS);
  }

  private cancelCopy(): void {
    if (this.copyTimer !== undefined) clearTimeout(this.copyTimer);
    this.copyTimer = undefined;
  }
}

/** The store this context dissects against. */
export const keyLog = new KeyLogStore();
