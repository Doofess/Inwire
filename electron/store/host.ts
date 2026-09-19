/**
 * The capture store process, and the channel the renderer talks over.
 *
 * Main owns the process because main owns OS resources, and it stays out of
 * the message path entirely: the renderer and the store get the two ends of a
 * `MessageChannelMain` and speak directly. Relaying every frame through main
 * would put a serialize-and-copy of the whole capture on the thread that also
 * has to stay responsive enough to show a quit dialog.
 */
import { app, MessageChannelMain, utilityProcess, type UtilityProcess, type WebContents } from 'electron';
import path from 'node:path';
import { STORE_EXIT_CHANNEL, STORE_INGEST_PORT_CHANNEL, STORE_PORT_CHANNEL } from '../channels';

export class CaptureStoreHost {
  private child: UtilityProcess | null = null;
  private spawned: Promise<void> | null = null;
  private exited = false;

  constructor(private readonly directory: string) {}

  /**
   * Forks the store and resolves once it is running.
   *
   * The wait matters: `child.postMessage(msg, [port])` before the `spawn`
   * event is not delivered, and the symptom is a store that never receives its
   * channel and a renderer whose every read hangs.
   */
  private ensure(): Promise<void> {
    if (this.spawned) return this.spawned;

    this.spawned = new Promise<void>((resolve, reject) => {
      const child = utilityProcess.fork(
        path.join(__dirname, 'store', 'store.cjs'),
        [this.directory],
        {
          // Named so it is not an anonymous "Utility" beside the renderer in
          // Task Manager, on a machine where somebody is already watching
          // processes for a living.
          serviceName: 'inwire-capture-store',
          // The default is `['ignore', 'inherit', 'inherit']`, and a packaged
          // Windows GUI app has no console to inherit - so every `fail()`
          // message the protocol calls "never silent" would go nowhere.
          stdio: 'pipe',
          // **This does not set a heap ceiling, and it looks exactly as
          // though it does.** The flag arrives - `process.execArgv` in the
          // store reads it back - and `heap_size_limit` is 4192 MB, V8's own
          // default, because V8 fixes the limit when it creates the isolate
          // and Electron creates the isolate before it looks at this.
          // Measured against the running app after the store was seen to die
          // at 4,060 MB with the flag in place.
          //
          // Kept anyway: it is harmless, it is what the intent would be if
          // Electron ever honoured it, and removing it would leave nothing
          // here pointing at `store/heapGuard.ts`, which enforces the ceiling
          // for real by sampling the heap and standing down deliberately.
          //
          // Either ending is handled: `child.on('exit')` tells the renderer
          // over its own channel, because a dead `MessagePort` just goes quiet
          // and every pending read would hang for the life of the window. The
          // difference the guard makes is that somebody can tell what
          // happened. Swapping a workstation to death is not handled and
          // cannot be.
          execArgv: ['--max-old-space-size=2048'],
        },
      );
      this.child = child;

      child.stdout?.on('data', (data: Buffer) => log('out', data));
      child.stderr?.on('data', (data: Buffer) => log('err', data));

      child.once('spawn', () => resolve());
      child.once('exit', (code) => {
        this.exited = true;
        this.child = null;
        const reason = `the capture store stopped (exit ${code})`;
        for (const listener of this.exitListeners) listener(reason);
        reject(new Error(reason));
      });
    });
    return this.spawned;
  }

  private readonly exitListeners: ((reason: string) => void)[] = [];

  /**
   * Tells a renderer when the store dies.
   *
   * A `MessagePort` has no error event and no reliable close event, so a dead
   * store is a channel that goes quiet - and `CaptureClient` holds a promise
   * per in-flight read. Without this the hex viewer spins for the life of the
   * window. It travels on its own IPC channel precisely because the port it is
   * reporting on is the thing that is gone.
   */
  watch(contents: WebContents): void {
    this.exitListeners.push((reason) => {
      if (!contents.isDestroyed()) contents.send(STORE_EXIT_CHANNEL, reason);
    });
  }

  /** Gives this renderer one end of a fresh channel to the store. */
  async connect(contents: WebContents): Promise<void> {
    await this.give(contents, 'client', STORE_PORT_CHANNEL);
  }

  /**
   * The second channel, for frames on their way to disk.
   *
   * One-way and separate from the client's, so a 256 kB batch never queues in
   * front of the read the hex viewer is waiting on. ADR 0038.
   */
  async connectIngest(contents: WebContents): Promise<void> {
    await this.give(contents, 'ingest', STORE_INGEST_PORT_CHANNEL);
  }

  /**
   * Hands one end to the store and the other to the renderer.
   *
   * **The role travels with the port, and that is not decoration.** `entry.ts`
   * used to take `event.ports[0]` from any parent message and assign it to its
   * single `port` - so a second channel silently replaced the first, and every
   * reply the app was waiting on went down a port nothing was reading.
   */
  private async give(
    contents: WebContents, role: 'client' | 'ingest', channel: string,
  ): Promise<void> {
    if (this.exited) throw new Error('the capture store is not running');
    await this.ensure();
    if (!this.child) throw new Error('the capture store is not running');

    const { port1, port2 } = new MessageChannelMain();
    this.child.postMessage({ role }, [port2]);
    contents.postMessage(channel, null, [port1]);
  }

  /** Ends the process. The store seals whatever is open on the way out. */
  stop(): void {
    this.child?.kill();
    this.child = null;
  }
}

function log(stream: 'out' | 'err', data: Buffer): void {
  const text = data.toString().trimEnd();
  if (text) console.log(`[capture-store:${stream}] ${text}`);
}

/** Where captures live: Local, never Roaming. See `main.ts`. */
export function captureDirectory(): string {
  return path.join(app.getPath('userData'), 'captures');
}
