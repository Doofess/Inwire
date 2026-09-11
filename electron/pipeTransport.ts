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
 * Unchanged from the Worker's old `RECONNECT_MS`.
 *
 * The retry moved here with the handle, and the cadence did not move with it:
 * the header's "connecting…" is meant to behave exactly as it did.
 */
export const RECONNECT_MS = 3000;

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

  constructor(
    private readonly events: PipeEvents,
    private readonly pipePath: string = AGENT_PIPE_PATH,
    private readonly reconnectMs: number = RECONNECT_MS,
  ) {}

  /** Connect, and keep reconnecting until `close`. */
  open(): void {
    this.wanted = true;
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
    this.retry = setTimeout(() => {
      this.retry = null;
      this.openSocket();
    }, this.reconnectMs);
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
