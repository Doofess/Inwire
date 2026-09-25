/**
 * A save written in pieces: the rules, without Electron.
 *
 * `saveFile.ts` takes a whole file in one IPC message, which is fine until the
 * file is a capture larger than the renderer's heap. This is the other shape -
 * open, write, write, close - and everything in it that has a rule lives here
 * rather than in `saveStream.ts`, because that file imports `electron` and
 * nothing in it can be driven under plain `tsx`. Same split as
 * `saveTarget.ts` beside `saveFile.ts`.
 *
 * ## The bytes go to a partial file until the renderer says it is done
 *
 * An export can be cancelled, can fail half way, and can lose its window. If
 * it wrote straight to the chosen path, every one of those would leave a
 * truncated `.pcapng` with the name the person asked for - a file that looks
 * finished and opens as a shorter capture than the one they took. So the
 * chosen name only ever appears by `rename`, which is the last thing a commit
 * does, and an abort deletes the partial instead.
 *
 * The partial is `<target>.<random>.partial`, created exclusively (`wx`). Not
 * `<target>.partial`: a file of that name this app did not create - the
 * person's own, or another program's - would otherwise be truncated on open
 * and deleted on abort. A name nobody could have predicted is one only this
 * session can own.
 *
 * ## A failed commit keeps the bytes
 *
 * The rename is the last step of what may have been many minutes of export,
 * and it is the step most likely to fail for a reason that has nothing to do
 * with the export: the target is read-only, or open in Wireshark, which holds
 * it without delete sharing so it cannot be replaced. (Measured on Windows 11:
 * even a plain Node read handle on the target is enough for `rename` onto it
 * to answer `EPERM`.) Deleting the partial then would throw the whole export
 * away over a lock the person can release in a second. So the partial is kept
 * and the error names where it is.
 *
 * What can be checked up front is: `open` opens an existing target for update
 * (`r+`) and closes it again, which fails for a read-only file and for one
 * another program holds without write sharing - before any of the export has
 * been spent. It cannot see a reader that shares writes but not deletes; that
 * one is the kept partial's job.
 *
 * ## A token belongs to the webContents that opened it
 *
 * The token is not a secret this relies on - it is a random UUID, but the
 * renderer is the only party that ever sees it. What binding it to the sender
 * buys is that a second window, or a page after a reload, cannot write into or
 * commit a file another one chose in a dialog. The dialog is the
 * authorisation; the token must not outlive the thing that was authorised.
 *
 * ## Nothing is left behind at quit
 *
 * `abandonAllSync` deletes every open session's partial with synchronous
 * calls, for a `will-quit` handler: nothing awaited there is guaranteed to run
 * before the process is gone, which is how a partial would outlive the app
 * that made it.
 */
import { randomBytes, randomUUID } from 'node:crypto';
import { rmSync } from 'node:fs';
import { open, rename, rm, type FileHandle } from 'node:fs/promises';

/**
 * How many saves may be open at once, across every window.
 *
 * Each holds an open file handle in main. A renderer that opened saves in a
 * loop and never closed them would otherwise exhaust handles in the privileged
 * process; a person exports one thing at a time, so four is generous.
 */
export const MAX_OPEN_SAVES = 4;

/**
 * The largest single write accepted.
 *
 * The renderer coalesces to a few megabytes (`src/lib/saveSink.ts`). Anything
 * far past that is not a chunk but the old whole-file message by another name,
 * and main should not be the process that holds it.
 */
export const MAX_WRITE_BYTES = 64 * 1024 * 1024;

/**
 * The most bytes one session may have accepted and not yet written.
 *
 * Writes queue behind each other, and IPC delivers them as fast as the
 * renderer sends; a renderer that never awaited one would otherwise park the
 * whole export in main's heap behind a slow disk. Past this the session fails:
 * a refused chunk is a hole in the file, so nothing after it may commit.
 */
export const MAX_PENDING_BYTES = 256 * 1024 * 1024;

export const PARTIAL_SUFFIX = '.partial';

/** A fresh partial name beside `target`. Random, so no existing file is it. */
export function partialPathFor(target: string): string {
  return `${target}.${randomBytes(6).toString('hex')}${PARTIAL_SUFFIX}`;
}

export type OpenResult = { token: string } | { error: string };
export type WriteResult = { ok: true } | { error: string };
export type CloseResult =
  | { saved: true; path: string }
  | { saved: false; canceled: true }
  | { saved: false; canceled: false; error: string };

/**
 * The two file operations whose failure a test needs to choose, so it can make
 * one fail the way a disk does without needing the disk to.
 */
export interface SaveFs {
  open: typeof open;
  rename: typeof rename;
}

const realFs: SaveFs = { open, rename };

interface Session {
  sender: number;
  target: string;
  partial: string;
  handle: FileHandle;
  /** Every operation on one session runs in order behind this. */
  tail: Promise<unknown>;
  /** Bytes accepted by `write` and not yet on disk. */
  pending: number;
  /** Set by the first failed write; everything after answers with it. */
  failure: string | null;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function codeOf(error: unknown): string | undefined {
  const code = (error as { code?: unknown } | null)?.code;
  return typeof code === 'string' ? code : undefined;
}

/** Why a target cannot be replaced, in words a person can act on. */
function blockedMessage(target: string, error: unknown): string {
  const code = codeOf(error);
  const why = code === 'EPERM' || code === 'EACCES' || code === 'EBUSY'
    ? `it is read-only, or open in another program (${code})`
    : messageOf(error);
  return `"${target}" cannot be replaced: ${why}.`;
}

export class SaveSessions {
  private readonly sessions = new Map<string, Session>();
  /** Opens in flight, counted against the limit before anything is awaited. */
  private opening = 0;

  constructor(
    private readonly maxOpen = MAX_OPEN_SAVES,
    private readonly fs: SaveFs = realFs,
    private readonly maxPending = MAX_PENDING_BYTES,
  ) {}

  get openCount(): number {
    return this.sessions.size;
  }

  /** The partial a token is writing, or null. For a test to look at. */
  partialOf(token: string): string | null {
    return this.sessions.get(token)?.partial ?? null;
  }

  /** Creates a fresh partial beside `target` and hands back a token for it. */
  async open(sender: number, target: string): Promise<OpenResult> {
    // The slot is taken here, synchronously. Checked after an await, two opens
    // arriving together would both see room and both be let in.
    if (this.sessions.size + this.opening >= this.maxOpen) {
      return { error: `too many saves in progress (${this.maxOpen}); finish one first` };
    }
    this.opening++;
    try {
      return await this.create(sender, target);
    } finally {
      this.opening--;
    }
  }

  private async create(sender: number, target: string): Promise<OpenResult> {
    // An existing target must be replaceable, or the whole export is spent
    // before the rename says it was not. `r+` opens without truncating, and
    // the handle is closed again at once.
    try {
      const probe = await this.fs.open(target, 'r+');
      await probe.close();
    } catch (error) {
      if (codeOf(error) !== 'ENOENT') {
        return { error: `${blockedMessage(target, error)} Choose another name, or close whatever is using it.` };
      }
    }

    let handle: FileHandle | null = null;
    let partial = '';
    for (let attempt = 0; attempt < 4 && handle === null; attempt++) {
      partial = partialPathFor(target);
      try {
        // `wx`: a name that already exists is somebody else's file, never ours
        // to truncate. A collision on 48 random bits is a retry, not an error.
        handle = await this.fs.open(partial, 'wx');
      } catch (error) {
        if (codeOf(error) !== 'EEXIST') return { error: messageOf(error) };
      }
    }
    if (handle === null) return { error: `could not create a temporary file beside "${target}"` };

    const token = randomUUID();
    this.sessions.set(token, {
      sender, target, partial, handle, tail: Promise.resolve(), pending: 0, failure: null,
    });
    return { token };
  }

  async write(sender: number, token: unknown, bytes: unknown): Promise<WriteResult> {
    const session = this.owned(sender, token);
    if ('error' in session) return session;
    if (!(bytes instanceof Uint8Array)) return { error: 'a save chunk must be bytes' };
    if (bytes.byteLength > MAX_WRITE_BYTES) {
      return { error: `a save chunk may be at most ${MAX_WRITE_BYTES} bytes` };
    }
    if (session.failure) return { error: session.failure };
    if (session.pending + bytes.byteLength > this.maxPending) {
      // Refused, and the session with it: the chunk is not in the file, so no
      // commit after this may claim the file is whole.
      session.failure = `more than ${this.maxPending} bytes were waiting to be written; the disk is not keeping up`;
      return { error: session.failure };
    }
    session.pending += bytes.byteLength;
    return this.enqueue(session, async (): Promise<WriteResult> => {
      try {
        if (session.failure) return { error: session.failure };
        // `FileHandle.write` can return short like `writeSync` can - the loop
        // is `nodeBlockFile.ts`'s lesson, and a short write here would be a
        // silently shorter file.
        let offset = 0;
        while (offset < bytes.byteLength) {
          const { bytesWritten } = await session.handle.write(bytes, offset, bytes.byteLength - offset);
          if (bytesWritten <= 0) throw new Error('the disk accepted no bytes');
          offset += bytesWritten;
        }
        return { ok: true };
      } catch (error) {
        session.failure = messageOf(error);
        return { error: session.failure };
      } finally {
        session.pending -= bytes.byteLength;
      }
    });
  }

  /**
   * Commit renames the partial over the target; abort deletes it.
   *
   * The token is forgotten before anything is awaited, so a second close -
   * a double click, a retry after a timeout - finds nothing and touches no
   * file, rather than deleting what the first one just committed.
   */
  async close(sender: number, token: unknown, commit: boolean): Promise<CloseResult> {
    const session = this.owned(sender, token);
    if ('error' in session) return { saved: false, canceled: false, error: session.error };
    this.sessions.delete(token as string);
    return this.enqueue(session, () => this.finish(session, commit === true));
  }

  /**
   * Abandons every save a webContents opened. For a window that closed or a
   * renderer that crashed mid-export: nobody is left to commit, so the partial
   * is deleted rather than left beside the target forever.
   */
  async dropSender(sender: number): Promise<void> {
    const mine = [...this.sessions].filter(([, session]) => session.sender === sender);
    for (const [token] of mine) this.sessions.delete(token);
    await Promise.all(mine.map(([, session]) => this.enqueue(session, () => this.finish(session, false))));
  }

  /**
   * Deletes every open session's partial, synchronously, and forgets them all.
   *
   * For `will-quit`. The name is removed before the handle is closed, because
   * closing a `FileHandle` is asynchronous; Node opens files with delete
   * sharing, so the name goes now and the handle goes with the process.
   */
  abandonAllSync(): void {
    const all = [...this.sessions.values()];
    this.sessions.clear();
    for (const session of all) {
      session.failure ??= 'the app is quitting';
      try { rmSync(session.partial, { force: true }); } catch { /* nobody is left to tell */ }
      // Started, not awaited: if the process outlives this call it closes
      // cleanly, and if not, the OS closes it.
      void session.handle.close().catch(() => undefined);
    }
  }

  private async finish(session: Session, commit: boolean): Promise<CloseResult> {
    let error = commit ? session.failure : null;
    try {
      await session.handle.close();
    } catch (closeError) {
      error ??= messageOf(closeError);
    }
    if (commit && !error) {
      try {
        // Over an existing file on purpose: the dialog already asked whether
        // to replace it, and on Windows Node's rename is MoveFileEx with
        // REPLACE_EXISTING.
        await this.fs.rename(session.partial, session.target);
        return { saved: true, path: session.target };
      } catch (renameError) {
        // The export is complete and on disk; only its name is wrong. Keeping
        // it is the difference between "close Wireshark and rename a file"
        // and "export for another ten minutes".
        return {
          saved: false,
          canceled: false,
          error: `${blockedMessage(session.target, renameError)} The export is complete and was kept as "${session.partial}".`,
        };
      }
    }
    await rm(session.partial, { force: true }).catch(() => undefined);
    return error
      ? { saved: false, canceled: false, error }
      : { saved: false, canceled: true };
  }

  private owned(sender: number, token: unknown): Session | { error: string } {
    const session = typeof token === 'string' ? this.sessions.get(token) : undefined;
    // One answer for "no such token" and "not yours": telling a caller that a
    // token exists but belongs to somebody else is information it has no use
    // for.
    if (!session || session.sender !== sender) return { error: 'no such save in progress' };
    return session;
  }

  private enqueue<T>(session: Session, step: () => Promise<T>): Promise<T> {
    const next = session.tail.then(step);
    session.tail = next.catch(() => undefined);
    return next;
  }
}
