/**
 * The byte stream to the capture agent: connect, deframe, reframe, retry.
 *
 * Split from `agentPipe.ts` for the reason every decision in `electron/` is
 * split out - so `scripts/electron/agent-link.ts` can drive it under plain
 * `tsx`, against a real pipe served by `node:net`, with no Electron in the
 * process. It takes its three outputs as callbacks for exactly the reason
 * `PipeConnection` in `local-agent/pipe_server.py` takes its write and close
 * as callables: the half with the decisions in it should be testable on a
 * machine that has none of the surrounding machinery.
 *
 * ## What a byte stream costs, and what it buys
 *
 * A WebSocket gave message boundaries and a text/binary distinction for free.
 * A pipe gives neither, so `agentFraming.ts` supplies both and this file is
 * where a read boundary stops being confused with a message boundary - one
 * read can carry half a header and another can carry nine whole batches, and
 * both happen under load.
 *
 * What it buys is that the kernel decides who may connect. The pairing token,
 * the origin allowlist and the `icacls` call on `config.json` all existed
 * because `ws://localhost:8999` was reachable by every process on the machine;
 * see the security descriptor in `local-agent/pipe_server.py`.
 */
import { connect, type Socket } from 'node:net';
import {
  FRAME_BINARY, FRAME_JSON, FrameReader, encodeFrame, frameText,
} from '../src/services/agentFraming';
import type { AgentLinkStatus } from '../src/services/agentLink';

/**
 * Where the agent listens. The counterpart of `PIPE_NAME` in
 * `local-agent/pipe_server.py`, and the one string that must match it.
 */
export const AGENT_PIPE_PATH = '\\\\.\\pipe\\inwire-agent';

/**
 * The settled cadence, once the fast attempts have not found it.
 *
 * Unchanged from the Worker's old `RECONNECT_MS`, and it is still what a
 * machine with no agent installed pays: a retry every three seconds for as
 * long as the window is open.
 */
const RECONNECT_MS = 3000;

/**
 * What the first four retries wait instead.
 *
 * The agent is demand-start now, so the ordinary case at launch is a pipe that
 * is not there **yet** - main has just asked the SCM for it and the service is
 * coming up. A flat three seconds meant the app spent most of a service start
 * deliberately not looking, and the person watched the status bar say the agent
 * was missing for the whole of it.
 *
 * Doubling from 150 ms covers a warm start inside the first attempt or two and
 * reaches the settled cadence in 2.25 s, which is under the time the SCM itself
 * takes on a cold one. It is bounded rather than unbounded-exponential because
 * the failure this must not create is a process that hammers a pipe for ever.
 */
const FAST_RETRY_MS = [150, 300, 600, 1200];

/**
 * A connection this short did not do any work.
 *
 * The agent sends `hello` the moment it accepts, so a connection that lived
 * under a second either found the service mid-exit or found it exiting. Two
 * seconds would also catch a slow machine's healthy start; one is chosen to
 * under-report rather than to accuse the agent of crashing when it is merely
 * busy.
 */
const SHORT_CONNECTION_MS = 1000;

/** How far back short connections are counted. Three retries at 3s, plus slack. */
const CRASH_WINDOW_MS = 30_000;

/** What the transport tells its owner. Nothing else leaves this file. */
export interface PipeEvents {
  status(status: AgentLinkStatus): void;
  /** One control message, deframed and decoded. */
  text(text: string): void;
  /** One packet batch, deframed. Owns its bytes exactly. */
  binary(bytes: Uint8Array): void;
}

const encoder = new TextEncoder();

export class PipeTransport {
  private socket: Socket | null = null;
  private reader = new FrameReader();
  /** Whether a connection is wanted. Survives a dropped pipe; a retry reads it. */
  private wanted = false;
  private retry: ReturnType<typeof setTimeout> | null = null;
  /** Set while a socket is opening, so a second `open` cannot race the first. */
  private opening = false;
  /** When the current socket connected, for the short-connection count. */
  private connectedAt = 0;
  /** Timestamps of recent connections that died almost immediately. */
  private shortLived: number[] = [];
  /**
   * Retries since the last connection that lasted, indexing `FAST_RETRY_MS`.
   *
   * Reset by a connection that **survived** rather than by one that opened: a
   * service dying a moment after accepting would otherwise keep the fast steps
   * armed for ever, which is a crash loop retried four times a second.
   */
  private attempt = 0;

  /**
   * @param greeting What main says first on every connection, before anyone
   *   is told it is up: `set_capture_root` (ADR 0052), so the agent knows
   *   where this app's captures live before any `start_capture` can name one.
   *   On every connection because the agent forgets a client's root when its
   *   pipe closes, and a reconnect is a new client.
   */
  constructor(
    private readonly events: PipeEvents,
    private readonly pipePath: string = AGENT_PIPE_PATH,
    private readonly reconnectMs: number = RECONNECT_MS,
    private readonly greeting: string | null = null,
  ) {}

  /** Connect, and keep reconnecting until `close`. */
  open(): void {
    this.wanted = true;
    // Somebody asked, so this is a fresh start however the last one ended.
    // `recycle()` is the caller that makes this matter: a driver has just been
    // installed and the reconnect must not inherit a backed-off cadence.
    this.attempt = 0;
    this.openSocket();
  }

  /** Disconnect and stop retrying. */
  close(): void {
    this.wanted = false;
    this.closeSocket();
    this.events.status('disconnected');
  }

  /**
   * Send one control message.
   *
   * Text, already serialised: nothing here knows the agent's vocabulary, so
   * everything that decides what to say stays with the code that knows what
   * the answers mean. Dropped when the link is down, exactly as a closed
   * socket dropped it.
   */
  send(text: string): void {
    const socket = this.socket;
    if (!socket || socket.destroyed || this.opening) return;
    socket.write(encodeFrame(FRAME_JSON, encoder.encode(text)));
  }

  /**
   * Connections that opened and died within a second, in the recent past.
   *
   * The one symptom of a crash loop that only this end can see: every value in
   * the service's registry key is exactly what it should be while it happens.
   */
  get shortConnections(): number {
    const since = Date.now() - CRASH_WINDOW_MS;
    this.shortLived = this.shortLived.filter((at) => at >= since);
    return this.shortLived.length;
  }

  // -- the socket -------------------------------------------------------------

  private openSocket(): void {
    if (!this.wanted || this.socket !== null || this.opening) return;
    this.opening = true;
    this.events.status('connecting');
    // A fresh reader per connection: whatever the last one was holding was
    // half of a message from a stream that no longer exists.
    this.reader = new FrameReader();

    const socket = connect({ path: this.pipePath });
    this.socket = socket;

    socket.on('connect', () => {
      this.opening = false;
      this.connectedAt = Date.now();
      if (this.greeting !== null) socket.write(encodeFrame(FRAME_JSON, encoder.encode(this.greeting)));
      this.events.status('connected');
    });

    socket.on('data', (chunk: Buffer) => this.consume(chunk));

    socket.on('error', () => {
      // Every reason the agent is not there arrives here and they are not
      // worth telling apart: not installed, not started, still coming up
      // behind Npcap. `close` follows and the retry covers the rest.
      this.events.status('error');
    });

    socket.once('close', () => {
      this.opening = false;
      // A connection that never connected is not a short connection - it is a
      // service that is not there, which the registry answers and this must
      // not also answer, differently.
      if (this.connectedAt !== 0 && Date.now() - this.connectedAt < SHORT_CONNECTION_MS) {
        this.shortLived.push(Date.now());
      } else if (this.connectedAt !== 0) {
        // A connection that lasted. The next drop is a fresh event rather than
        // the continuation of a failing start, so the fast steps are armed
        // again - which is what makes the agent's own idle stop and restart
        // cost a fraction of a second instead of three of them.
        this.attempt = 0;
      }
      this.connectedAt = 0;
      if (this.socket === socket) this.socket = null;
      this.events.status('disconnected');
      this.scheduleRetry();
    });
  }

  private consume(chunk: Buffer): void {
    // A plain view rather than the `Buffer` itself, and this is not
    // decoration. `Buffer.prototype.slice` is `subarray` - it returns a VIEW
    // where `TypedArray.prototype.slice` copies - so a `FrameReader` fed
    // `Buffer`s hands out payloads that are windows into Node's 8 kB read
    // pool: right bytes, wrong shape. The pool is not rewritten under them
    // (the cursor advances rather than wrapping), so nothing is corrupted -
    // what breaks is downstream. `asArrayBuffer` in `pipeline.worker.ts` takes
    // `payload.buffer` when the view owns it exactly, and a small control
    // message would also pin the whole pool behind it. Feeding the reader a
    // non-`Buffer` view costs nothing and makes `slice` mean copy again.
    const bytes = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    let frames;
    try {
      frames = this.reader.push(bytes);
    } catch (error) {
      // Unrecoverable by construction: the stream position is no longer known,
      // so there is nothing to resynchronise to. Drop the connection and let
      // the retry start a clean one - the same conclusion `pipe_server.py`
      // reaches from the other end of the same pipe.
      console.warn('[agent-pipe]', String(error));
      this.closeSocket();
      this.scheduleRetry();
      return;
    }
    for (const frame of frames) {
      if (frame.kind === FRAME_JSON) this.events.text(frameText(frame));
      else if (frame.kind === FRAME_BINARY) this.events.binary(frame.payload);
    }
  }

  private scheduleRetry(): void {
    if (!this.wanted || this.retry !== null) return;
    // `reconnectMs` is still the floor a caller can override - `agent-link.ts`
    // drives this with a short one - so the fast steps are capped by it rather
    // than replacing it. Without that a test asking for a 20 ms cadence would
    // silently get 150.
    const step = FAST_RETRY_MS[this.attempt];
    const wait = step === undefined ? this.reconnectMs : Math.min(step, this.reconnectMs);
    this.attempt += 1;
    this.retry = setTimeout(() => {
      this.retry = null;
      this.openSocket();
    }, wait);
  }

  private closeSocket(): void {
    if (this.retry !== null) {
      clearTimeout(this.retry);
      this.retry = null;
    }
    const socket = this.socket;
    this.socket = null;
    this.opening = false;
    if (socket) {
      // Listeners first, so the teardown does not read as the agent going away
      // and re-arm the retry that closing exists to stop. The Worker's old
      // `closeSocket` had the same line for the same reason.
      socket.removeAllListeners();
      socket.destroy();
    }
  }
}
