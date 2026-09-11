/**
 * The connection to the capture agent: a named pipe, owned by main.
 *
 * ## Why this is not in the Worker any more
 *
 * It could not be. `net.connect` is Node, and the renderer has no Node - a
 * `sandbox: true` renderer least of all. So the OS handle lives here, and the
 * Worker gets the other end of a `MessageChannelMain`; see
 * `src/services/agentLink.ts` for what travels over it and why the renderer's
 * main thread never appears in the frame path.
 *
 * ## What the pipe replaced, and what that deleted
 *
 * `ws://localhost:8999` was reachable by every process on the machine, and
 * everything defensive in the old agent existed because of that: a pairing
 * token the user pasted in by hand, an origin allowlist, an `icacls` call on
 * `config.json`. A named pipe carries a security descriptor, so the kernel
 * answers the question those were asked to answer - see the SDDL in
 * `local-agent/pipe_server.py`, where the interactive-user ACE is the whole
 * point.
 *
 * State honestly what that does not stop: an administrator, and code injected
 * into this process. It is a materially higher bar than a bearer token any
 * process running as the user could read out of the app's own storage, and it
 * is enforced by the kernel rather than by us.
 *
 * ## Reconnection is main's job now
 *
 * The Worker used to hold the retry timer. It says `open` and `close` and this
 * file decides the rest, because the thing being retried is a handle only this
 * process can hold. The cadence is the Worker's old one, unchanged, so the
 * header's "connecting…" behaves exactly as it did.
 */
import { MessageChannelMain, type MessagePortMain, type WebContents } from 'electron';
import { connect, type Socket } from 'node:net';
import {
  FRAME_BINARY, FRAME_JSON, FrameReader, encodeFrame, frameText,
} from '../src/services/agentFraming';
import type { FromAgentLink, ToAgentLink } from '../src/services/agentLink';
import { AGENT_PORT_CHANNEL } from './channels';

/**
 * Where the agent listens. The counterpart of `PIPE_NAME` in
 * `local-agent/pipe_server.py`, and the one string that must match it.
 */
export const AGENT_PIPE_PATH = '\\\\.\\pipe\\inwire-agent';

/** Unchanged from the Worker's `RECONNECT_MS`, which the header's copy assumes. */
const RECONNECT_MS = 3000;

const encoder = new TextEncoder();

/**
 * One renderer's link to the agent.
 *
 * Per renderer rather than per app because the port is: a reload makes a new
 * renderer, and the old port is dead the moment its Worker is.
 */
export class AgentPipeLink {
  private socket: Socket | null = null;
  private port: MessagePortMain | null = null;
  private reader = new FrameReader();
  /** Whether the Worker has asked to be connected. Survives a dropped pipe. */
  private wanted = false;
  private retry: NodeJS.Timeout | null = null;
  /** Set while a socket is opening, so a second `open` does not race a first. */
  private opening = false;

  constructor(private readonly pipePath: string = AGENT_PIPE_PATH) {}

  /** Gives this renderer one end of a fresh channel and keeps the other. */
  attach(contents: WebContents): void {
    // A reload replaces the link rather than adding one. Without this a dev
    // session accumulates a pipe connection per refresh, and the agent's
    // `capture_busy` starts arbitrating between a window and its own ghosts.
    this.detach();

    const { port1, port2 } = new MessageChannelMain();
    this.port = port2;
    port2.on('message', (event) => this.receive(event.data as ToAgentLink));
    // Nothing is delivered until this is called, and the failure is silent:
    // the Worker connects, main never hears `open`, and the app sits on
    // "connecting" for ever.
    port2.start();
    contents.postMessage(AGENT_PORT_CHANNEL, null, [port1]);
  }

  /** Drops the connection and the channel. Called on reload and on quit. */
  detach(): void {
    this.wanted = false;
    this.closeSocket();
    this.port?.close();
    this.port = null;
  }

  // -- the Worker's side ------------------------------------------------------

  private receive(message: ToAgentLink): void {
    switch (message.type) {
      case 'open':
        this.wanted = true;
        this.openSocket();
        break;
      case 'close':
        this.wanted = false;
        this.closeSocket();
        this.tell({ type: 'status', status: 'disconnected' });
        break;
      case 'send':
        this.write(encodeFrame(FRAME_JSON, encoder.encode(message.text)));
        break;
    }
  }

  private tell(message: FromAgentLink): void {
    this.port?.postMessage(message);
  }

  // -- the pipe ---------------------------------------------------------------

  private openSocket(): void {
    if (!this.wanted || this.socket !== null || this.opening) return;
    this.opening = true;
    this.tell({ type: 'status', status: 'connecting' });
    this.reader = new FrameReader();

    const socket = connect({ path: this.pipePath });
    this.socket = socket;

    socket.on('connect', () => {
      this.opening = false;
      this.tell({ type: 'status', status: 'connected' });
    });

    socket.on('data', (chunk: Buffer) => this.consume(chunk));

    socket.on('error', () => {
      // Every reason the agent is not there arrives here and they are not
      // worth telling apart: not installed, not started, still booting behind
      // Npcap. The app's own "agent not connected" state says the useful half,
      // and the retry below covers the rest.
      this.tell({ type: 'status', status: 'error' });
    });

    socket.once('close', () => {
      this.opening = false;
      if (this.socket === socket) this.socket = null;
      this.tell({ type: 'status', status: 'disconnected' });
      this.scheduleRetry();
    });
  }

  private consume(chunk: Buffer): void {
    // A plain view rather than the `Buffer` itself, and this is not
    // decoration. `Buffer.prototype.slice` is `subarray` - it returns a VIEW
    // where `TypedArray.prototype.slice` copies - so a `FrameReader` fed
    // `Buffer`s would hand out payloads pointing into Node's shared read pool,
    // and a batch would be quietly rewritten by the next read.
    const bytes = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
    let frames;
    try {
      frames = this.reader.push(bytes);
    } catch (error) {
      // Unrecoverable by construction: the stream position is no longer known,
      // so there is nothing to resynchronise to. Drop it and let the retry
      // start a clean one - the same conclusion `pipe_server.py` reaches from
      // the other end.
      console.warn('[agent-pipe]', String(error));
      this.closeSocket();
      this.scheduleRetry();
      return;
    }
    for (const frame of frames) {
      if (frame.kind === FRAME_JSON) {
        this.tell({ type: 'text', text: frameText(frame) });
      } else if (frame.kind === FRAME_BINARY) {
        // `payload` came out of `TypedArray.prototype.slice`, so it owns its
        // bytes exactly and the clone across the port copies nothing extra.
        this.tell({ type: 'binary', bytes: frame.payload });
      }
    }
  }

  private write(frame: Uint8Array): void {
    const socket = this.socket;
    if (!socket || socket.destroyed || this.opening) return;
    socket.write(frame);
  }

  private scheduleRetry(): void {
    if (!this.wanted || this.retry !== null) return;
    this.retry = setTimeout(() => {
      this.retry = null;
      this.openSocket();
    }, RECONNECT_MS);
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
      // and re-arm the retry that closing exists to stop. The Worker's
      // `closeSocket` had the same line and the same reason.
      socket.removeAllListeners();
      socket.destroy();
    }
  }
}

/** Referenced so the unused-import check keeps the type honest. */
export type { FromAgentLink };
