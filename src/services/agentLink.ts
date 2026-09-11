/**
 * What the main process and the pipeline Worker say to each other about the
 * agent.
 *
 * ## Why there is a channel here at all
 *
 * While the transport was a WebSocket, the socket had to live in the Worker -
 * and not by preference. `is_origin_allowed` rejects a connection with no
 * `Origin`, and only a renderer context sends one, so the socket could not
 * have moved to the main process even if it had belonged there.
 *
 * A named pipe inverts that exactly. It has no `Origin`, and **no renderer and
 * no Web Worker can open one at all** - `net.connect` is Node, and the
 * renderer has no Node. So the connection moves to main, which is where an OS
 * handle belonged in the first place.
 *
 * What must not move with it is the frame path. ADR 0007 bought the property
 * that the renderer's main thread never sees a captured frame, and relaying
 * batches through it would hand that back at wire rate. So main pumps the pipe
 * into one end of a `MessageChannelMain` and the Worker holds the other: the
 * renderer's main thread carries the port across and then plays no part.
 *
 * ## The shape is the WebSocket's, deliberately
 *
 * `text` and `binary` are what `ws.onmessage` already distinguished, and
 * `status` is what `onopen`/`onerror`/`onclose` already said. The Worker's
 * handling of an agent message is therefore unchanged - which is the point,
 * because that code is the ordering window and the dissector's front door.
 *
 * The framing itself (`agentFraming.ts`) is main's business and is decoded
 * before anything reaches this channel. A pipe is a byte stream; a message
 * boundary is not a read boundary. Nobody above this line needs to know that.
 */

/** Exactly `PipelineStatus`, because it is forwarded as one. */
export type AgentLinkStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/** What the SCM's registry key said. Mirrors `electron/agentService.ts`. */
export interface AgentServiceFacts {
  installed: boolean;
  startType: 'auto' | 'manual' | 'disabled' | 'unknown';
}

/** Main -> Worker. */
export type FromAgentLink =
  /** Where the connection stands. Main is the authority; the Worker forwards. */
  | { type: 'status'; status: AgentLinkStatus }
  /** One control message, already deframed and decoded. */
  | { type: 'text'; text: string }
  /**
   * One packet batch, already deframed.
   *
   * A copy, not a transfer: `MessagePortMain`'s transfer list accepts only
   * ports, so there is no zero-copy hop out of the main process. Measured
   * against what it buys - the renderer's main thread never touching a frame -
   * one memcpy per ~256 kB batch at ~30 batches a second is not the cost worth
   * optimising.
   */
  | { type: 'binary'; bytes: Uint8Array }
  /**
   * Why the link is down, as far as anything outside the pipe can tell.
   *
   * Sent only while it IS down, and only from main, because both halves are
   * things a renderer cannot reach: the service's registry key, and how long
   * each of the last few connections lasted. See `services/agentHealth.ts` for
   * what is made of them - this message carries facts and no conclusion.
   */
  | { type: 'service'; facts: AgentServiceFacts; shortConnections: number };

/** Worker -> main. */
export type ToAgentLink =
  /** Connect, and keep reconnecting until told otherwise. */
  | { type: 'open' }
  /** Disconnect, and stop retrying. */
  | { type: 'close' }
  /**
   * A command for the agent, already serialised by `encodeAgentCommand`.
   *
   * Text rather than a command object, so the main process needs no knowledge
   * of the agent's vocabulary: it wraps the string in a frame and writes it.
   * Everything that decides what to say still lives with the code that knows
   * what the answers mean.
   */
  | { type: 'send'; text: string }
  /**
   * Ask Windows to start the agent's service.
   *
   * Elevation is unavoidable and is the point: the app runs unelevated so that
   * the dissector never parses hostile bytes as an administrator, which means
   * it cannot start a LocalSystem service either. Main raises the UAC prompt
   * rather than the app holding a privilege it wanted once.
   */
  | { type: 'startService' };
