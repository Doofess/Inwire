/**
 * The decisions behind following a TLS key log, with no Electron and no `fs`.
 *
 * Split out of `keyLogFollower.ts` for the reason `pipeTransport.ts` sits
 * beside `agentPipe.ts`: every assertion script here runs under plain `tsx`,
 * and the parts of a file follower that are worth testing - where to read
 * from, what to do when the file shrinks, where a line ends - are arithmetic,
 * not I/O. `scripts/electron/keylog-follow.ts` holds them.
 *
 * ## Why the key log is followed rather than read once
 *
 * The app used to take a key log through `<input type="file">` and
 * `file.text()`: one snapshot, at the moment of the click. A key log is not a
 * document, it is a journal - Chrome appends a connection's secrets the moment
 * it derives them, for as long as it runs. The one on the machine this was
 * found on was 17,084 lines and had been written a minute before it was
 * measured.
 *
 * So a snapshot taken before a capture holds no secret for any connection the
 * capture sees. Every QUIC packet read `Protected Payload (KP0)` and every TLS
 * record stayed opaque, with a key log loaded and `SSLKEYLOGFILE` set - which
 * looks exactly like decryption being broken. The fixtures never showed it,
 * because a key log handed to an import is complete before the import starts.
 */

/** What to read next, given the file's size now and how far we have read. */
export type ReadPlan =
  | { kind: 'none' }
  | {
    kind: 'read';
    from: number;
    to: number;
    /**
     * The file is SHORTER than what we have already read: it was truncated or
     * replaced. Start again from the top, and throw away any half-line held,
     * because it belonged to a file that no longer exists.
     *
     * Secrets already handed on are not taken back. A key log is append-only
     * by contract, so a shrink is somebody deleting it - and the secrets it
     * held are still the right secrets for the connections they name.
     */
    restart: boolean;
  };

export function planRead(size: number, offset: number): ReadPlan {
  if (size < offset) return { kind: 'read', from: 0, to: size, restart: true };
  if (size === offset) return { kind: 'none' };
  return { kind: 'read', from: offset, to: size, restart: false };
}

/**
 * Hands on only COMPLETE lines, holding back the rest.
 *
 * A read can end mid-line: Chrome writes a line, the watcher fires, and the
 * read catches the file part-way through the next one. `keyLog.add` would
 * reject a truncated line as malformed - and it would never see the rest,
 * because the next read starts after it. So the tail is kept until its newline
 * arrives. Same shape, same reason, as `scripts/electron/mainOutput.ts`.
 */
export class LineAssembler {
  private partial = '';

  /** Returns everything up to and including the last newline; keeps the rest. */
  push(text: string): string {
    const all = this.partial + text;
    const cut = all.lastIndexOf('\n');
    if (cut < 0) {
      this.partial = all;
      return '';
    }
    this.partial = all.slice(cut + 1);
    return all.slice(0, cut + 1);
  }

  reset(): void {
    this.partial = '';
  }

  /** For tests: what is being held back. */
  get held(): string {
    return this.partial;
  }
}

/**
 * The largest single read, and so the largest single message to the renderer.
 *
 * A key log only grows - `SSLKEYLOGFILE` is never rotated by the browser - so
 * the first read after a launch can be large: 2.8 MB on the machine this was
 * written on, and nothing bounds it. One read per megabyte keeps any one IPC
 * message ordinary and lets the renderer start using the early secrets while
 * the rest are still arriving.
 */
export const MAX_READ_BYTES = 1024 * 1024;

/** Splits `[from, to)` into reads of at most `MAX_READ_BYTES`. */
export function readSpans(from: number, to: number, max = MAX_READ_BYTES): [number, number][] {
  const spans: [number, number][] = [];
  for (let at = from; at < to; at += max) spans.push([at, Math.min(to, at + max)]);
  return spans;
}

/** What the renderer is told about the follower. Plain data: it crosses IPC. */
export interface KeyLogFollowStatus {
  /** The file being followed, or null when none has been chosen. */
  path: string | null;
  /**
   * - `off` - nothing chosen
   * - `following` - read and watched
   * - `missing` - chosen, and not there right now. Kept, and checked again:
   *   the file is created by the browser on its first connection, so a path
   *   remembered from yesterday can legitimately not exist yet today.
   * - `unreadable` - there, and could not be read; `error` says why
   */
  state: 'off' | 'following' | 'missing' | 'unreadable';
  /** Bytes read so far. */
  bytes: number;
  /**
   * `SSLKEYLOGFILE` from main's environment, offered as a one-click choice.
   *
   * Main's rather than anything the renderer could supply, and that is the
   * security half of this whole feature: the renderer can ask main to follow
   * a file only by naming one of two things main already knows - this, or a
   * path a person picked in main's own native dialog. It never hands main a
   * path, so a compromised renderer cannot turn this into "read any file".
   */
  suggested: string | null;
  error?: string;
}

/** The settings file's shape. Only the path is ever written - never a secret. */
export interface KeyLogSettings {
  path: string | null;
}

/** Reads the settings file's text; anything malformed means "nothing chosen". */
export function parseKeyLogSettings(text: string | null): KeyLogSettings {
  if (text === null) return { path: null };
  try {
    const value = JSON.parse(text) as unknown;
    if (typeof value === 'object' && value !== null) {
      const path = (value as { path?: unknown }).path;
      if (typeof path === 'string' && path.length > 0) return { path };
    }
  } catch {
    // Falls through: a corrupt file must not stop the app starting, and the
    // cost is one click to choose the log again.
  }
  return { path: null };
}
