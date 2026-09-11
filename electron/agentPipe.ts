/**
 * The connection to the capture agent: a named pipe, owned by main.
 *
 * ## Why this is not in the Worker any more
 *
 * It could not be. `net.connect` is Node, and the renderer has no Node - a
 * `sandbox: true` renderer least of all. So the OS handle lives here, and the
 * pipeline Worker gets the other end of a `MessageChannelMain`; see
 * `src/services/agentLink.ts` for what travels over it and why the renderer's
 * main thread never appears in the frame path.
 *
 * That inverts the old constraint exactly. While the transport was a
 * WebSocket, the socket *had* to be in the renderer - `is_origin_allowed`
 * refuses a connection with no `Origin`, and only a renderer sends one.
 *
 * ## What the pipe replaced, and what that deleted
 *
 * `ws://localhost:8999` was reachable by every process on the machine, and
 * everything defensive in the old agent existed because of that: a pairing
 * token the user pasted in by hand, an origin allowlist, an `icacls` call on
 * `config.json`. A named pipe carries a security descriptor, so the kernel
 * answers the question those were asked to answer - see the SDDL in
 * `local-agent/pipe_server.py`, where the interactive-user ACE is the point.
 *
 * State honestly what that does not stop: an administrator, and code injected
 * into this process. It is a materially higher bar than a bearer token any
 * process running as the user could read out of the app's own storage, and it
 * is enforced by the kernel rather than by us.
 *
 * ## What is left here
 *
 * The channel, and nothing else. Everything about the byte stream - framing,
 * reconnection, the read-boundary rule - is in `pipeTransport.ts`, which
 * imports no Electron so that `scripts/electron/agent-link.ts` can drive it
 * against a real pipe under plain `tsx`.
 */
import { MessageChannelMain, type MessagePortMain, type WebContents } from 'electron';
import type { FromAgentLink, ToAgentLink } from '../src/services/agentLink';
import { AGENT_PIPE_PATH, PipeTransport } from './pipeTransport';
import { AGENT_PORT_CHANNEL } from './channels';

export { AGENT_PIPE_PATH };

/**
 * One renderer's link to the agent.
 *
 * Per renderer rather than per app because the port is: a reload makes a new
 * renderer, and the old port is dead the moment its Worker is.
 */
export class AgentPipeLink {
  private port: MessagePortMain | null = null;
  private readonly pipe: PipeTransport;

  constructor(pipePath: string = AGENT_PIPE_PATH) {
    this.pipe = new PipeTransport({
      status: (status) => this.tell({ type: 'status', status }),
      text: (text) => this.tell({ type: 'text', text }),
      // A copy across the port, not a transfer: `MessagePortMain`'s transfer
      // list accepts only ports. One memcpy per ~256 kB batch at ~30 batches a
      // second is what the renderer's main thread staying out of the frame
      // path costs, and it is not the number worth optimising.
      binary: (bytes) => this.tell({ type: 'binary', bytes }),
    }, pipePath);
  }

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
    // the Worker asks to connect, main never hears it, and the app sits on
    // "connecting" for ever.
    port2.start();
    contents.postMessage(AGENT_PORT_CHANNEL, null, [port1]);
  }

  /** Drops the connection and the channel. Called on reload and on quit. */
  detach(): void {
    this.pipe.close();
    this.port?.close();
    this.port = null;
  }

  private receive(message: ToAgentLink): void {
    switch (message.type) {
      case 'open': this.pipe.open(); break;
      case 'close': this.pipe.close(); break;
      case 'send': this.pipe.send(message.text); break;
    }
  }

  private tell(message: FromAgentLink): void {
    this.port?.postMessage(message);
  }
}
