/**
 * Follows a TLS key log on disk and streams what it gains to the renderer.
 *
 * `keyLogTail.ts` holds the decisions and the reason this exists at all - a
 * key log is a journal Chrome keeps appending to, and a snapshot taken before
 * a capture holds no secret for any connection the capture sees. This is the
 * part that touches `fs`, `dialog` and `WebContents`.
 *
 * ## Why main, and not the renderer
 *
 * The renderer is sandboxed and cannot open a file by path at all; that is the
 * point of the sandbox, and nothing here loosens it. Main reads, and hands the
 * renderer text - the same shape a file picker produced, so the store that
 * receives it (`services/tls/keyLog.ts`) is unchanged.
 *
 * **The renderer never supplies a path.** It can ask main to follow the file a
 * person picked in main's own dialog, or the one `SSLKEYLOGFILE` names in
 * main's environment, and nothing else. A renderer that could name a path
 * would be a renderer that could read any file on the machine, and this
 * renderer parses hostile bytes for a living.
 *
 * ## What is persisted, and ADR 0008
 *
 * The **path**, in `keylog.json` under userData. Never a secret: the secrets
 * are already on disk, in the browser's own file, which is the file being
 * followed. What changes against ADR 0008 is when key material enters memory -
 * at launch now, without a click in that session, because the person chose to
 * follow a file and that choice is remembered until they stop it. ADR 0045
 * records that, and `crashReporter` stays off for 0008's reason: a renderer
 * minidump would be a copy of every secret this has streamed.
 *
 * ## Watching
 *
 * A fast poll, `POLL_MS`, and `fs.watch` beside it. The latency matters and is
 * not a nicety: a secret has to reach the Worker before the packets it opens
 * are dissected, and the only slack is the Worker's 100 ms ordering window.
 *
 * **The poll is what sees a browser**, not the watcher: Chrome appends through
 * a handle it keeps open, and on Windows that raises no change notification at
 * all. `keyLogTail.ts` has the measurement. The watcher is kept for a writer
 * that opens and closes the file per line, which it sees in under a
 * millisecond, and the poll re-arms it when the file is replaced or created
 * late - both of which end an `fs.watch` without an error anyone sees.
 */
import { dialog, type BrowserWindow, type WebContents } from 'electron';
import {
  closeSync, existsSync, fstatSync, mkdirSync, openSync, readFileSync, readSync,
  watch, writeFileSync, type FSWatcher,
} from 'node:fs';
import path from 'node:path';
import { KEYLOG_STATUS_CHANNEL, KEYLOG_TEXT_CHANNEL } from './channels';
import { canSend } from './rendererLife';
import {
  LineAssembler, parseKeyLogSettings, planRead, POLL_MS, readSpans, REARM_TICKS,
  type KeyLogFollowStatus,
} from './keyLogTail';

export class KeyLogFollower {
  private file: string | null;
  private offset = 0;
  private readonly lines = new LineAssembler();
  private watcher: FSWatcher | null = null;
  private poll: ReturnType<typeof setInterval> | null = null;
  private target: WebContents | null = null;
  private state: KeyLogFollowStatus['state'] = 'off';
  private error: string | undefined;

  constructor(private readonly settingsPath: string) {
    let text: string | null = null;
    try {
      text = readFileSync(settingsPath, 'utf8');
    } catch {
      // No settings file is the first-launch case, not an error.
    }
    this.file = parseKeyLogSettings(text).path;
  }

  status(): KeyLogFollowStatus {
    return {
      path: this.file,
      state: this.file === null ? 'off' : this.state,
      bytes: this.offset,
      suggested: suggestedKeyLog(),
      ...(this.error !== undefined ? { error: this.error } : {}),
    };
  }

  /**
   * A renderer is ready to receive. Everything is sent from the top.
   *
   * From the top rather than from where the last renderer got to, because a
   * new renderer - a reload, or the first window of a launch - has an empty
   * key store. `keyLog.add` now ignores a line it already holds, so re-sending
   * costs a parse and nothing else.
   */
  attach(contents: WebContents): KeyLogFollowStatus {
    this.target = contents;
    const detach = (): void => {
      if (this.target === contents) {
        this.target = null;
        this.stopWatching();
      }
    };
    contents.once('destroyed', detach);
    // A crashed page keeps its webContents but receives nothing: every send
    // from the poll was a logged "Render frame was disposed". The page that
    // replaces it attaches again, from the top.
    contents.once('render-process-gone', detach);
    this.restart();
    return this.status();
  }

  /** Shows main's own open dialog and follows what the person picks. */
  async choose(parent: BrowserWindow | null): Promise<KeyLogFollowStatus> {
    const options: Electron.OpenDialogOptions = {
      title: 'Follow a TLS key log',
      properties: ['openFile'],
      filters: [
        { name: 'Key logs', extensions: ['txt', 'log', 'keys'] },
        { name: 'All files', extensions: ['*'] },
      ],
      // Opens where the browser is already writing, when it says where.
      ...(suggestedKeyLog() !== null ? { defaultPath: suggestedKeyLog()! } : {}),
    };
    const picked = parent
      ? await dialog.showOpenDialog(parent, options)
      : await dialog.showOpenDialog(options);
    if (picked.canceled || picked.filePaths.length === 0) return this.status();
    this.follow(picked.filePaths[0]);
    return this.status();
  }

  /** Follows the file `SSLKEYLOGFILE` names - main's value, never the page's. */
  followSuggested(): KeyLogFollowStatus {
    const suggested = suggestedKeyLog();
    if (suggested !== null) this.follow(suggested);
    return this.status();
  }

  /**
   * Stops following and forgets the path.
   *
   * Does not clear the secrets already handed over: stopping should not make
   * the capture on screen unreadable. Clearing them is the panel's separate
   * Clear, which is what says so.
   */
  forget(): KeyLogFollowStatus {
    this.stopWatching();
    this.file = null;
    this.offset = 0;
    this.lines.reset();
    this.state = 'off';
    this.error = undefined;
    this.save();
    this.pushStatus();
    return this.status();
  }

  stop(): void {
    this.stopWatching();
  }

  private follow(file: string): void {
    this.file = file;
    this.save();
    this.restart();
  }

  private restart(): void {
    this.stopWatching();
    this.offset = 0;
    this.lines.reset();
    this.error = undefined;
    if (this.file === null || this.target === null) {
      this.pushStatus();
      return;
    }
    this.readNew();
    this.watchFile();
    let tick = 0;
    this.poll = setInterval(() => {
      // The poll also re-arms the watcher, which a replaced or late-created
      // file leaves dead without saying so. About once a second rather than
      // every tick: on a missing file every attempt throws.
      if (this.watcher === null && ++tick % REARM_TICKS === 0) this.watchFile();
      this.readNew();
    }, POLL_MS);
  }

  private watchFile(): void {
    if (this.file === null) return;
    try {
      this.watcher = watch(this.file, () => this.readNew());
      this.watcher.on('error', () => {
        this.watcher?.close();
        this.watcher = null;
      });
    } catch {
      // Missing file: the poll will retry, and `readNew` reports the state.
      this.watcher = null;
    }
  }

  private stopWatching(): void {
    this.watcher?.close();
    this.watcher = null;
    if (this.poll !== null) clearInterval(this.poll);
    this.poll = null;
  }

  /** Reads whatever has been appended since last time and sends complete lines. */
  private readNew(): void {
    if (this.file === null) return;
    const before = this.state;
    const beforeOffset = this.offset;
    const beforeError = this.error;
    let fd: number | null = null;
    try {
      if (!existsSync(this.file)) {
        this.state = 'missing';
        if (before !== this.state) this.pushStatus();
        return;
      }
      fd = openSync(this.file, 'r');
      const size = fstatSync(fd).size;
      const plan = planRead(size, this.offset);
      if (plan.kind === 'read') {
        if (plan.restart) this.lines.reset();
        for (const [from, to] of readSpans(plan.from, plan.to)) {
          const buffer = Buffer.alloc(to - from);
          let got = 0;
          // Looped, for `nodeBlockFile.ts`'s reason: a short read is not an
          // error, and treating one as the end would lose the rest silently.
          while (got < buffer.length) {
            const n = readSync(fd, buffer, got, buffer.length - got, from + got);
            if (n === 0) break;
            got += n;
          }
          // A key log is ASCII by definition - labels and hex - so `latin1`
          // cannot split a character across two reads the way UTF-8 could.
          const complete = this.lines.push(buffer.subarray(0, got).toString('latin1'));
          if (complete.length > 0) this.send(complete);
          this.offset = from + got;
          if (got < buffer.length) break;
        }
      }
      this.state = 'following';
      this.error = undefined;
    } catch (error) {
      this.state = 'unreadable';
      this.error = error instanceof Error ? error.message : String(error);
    } finally {
      if (fd !== null) closeSync(fd);
    }
    // Every read that moved the offset is worth telling the panel about, and
    // so is every change of state - and nothing else is. This runs forty times
    // a second, and an unconditional push would be forty IPC messages and
    // forty panel renders a second to say nothing changed.
    if (this.offset !== beforeOffset || this.state !== before || this.error !== beforeError) {
      this.pushStatus();
    }
  }

  private send(text: string): void {
    const target = this.target;
    if (target === null || !canSend(target)) return;
    target.send(KEYLOG_TEXT_CHANNEL, text);
  }

  private pushStatus(): void {
    const target = this.target;
    if (target === null || !canSend(target)) return;
    target.send(KEYLOG_STATUS_CHANNEL, this.status());
  }

  private save(): void {
    try {
      mkdirSync(path.dirname(this.settingsPath), { recursive: true });
      // The path and nothing else. See the header.
      writeFileSync(this.settingsPath, JSON.stringify({ path: this.file }), 'utf8');
    } catch {
      // A settings file that cannot be written costs the person one click next
      // launch. It must not cost them the follow they just asked for.
    }
  }
}

/**
 * `SSLKEYLOGFILE` as main sees it, if it names something.
 *
 * Main's environment is the user's, inherited at launch - so a variable set at
 * User scope, as the one on this machine is, reaches here without anyone
 * restarting anything but the app.
 */
function suggestedKeyLog(): string | null {
  const value = process.env.SSLKEYLOGFILE;
  if (typeof value !== 'string' || value.trim().length === 0) return null;
  return value.trim();
}
