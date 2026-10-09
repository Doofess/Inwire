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
  | {
      type: 'binary';
      bytes: Uint8Array;
      /**
       * Main's id for this batch, which the Worker hands back in `drained`
       * once every frame in it is dissected (`electron/pipeCredit.ts`).
       * Absent from a sender that keeps no credit, which a test may be.
       */
      batch?: number;
    }
  /**
   * How far behind live the Worker is, as main counts it, once a second
   * while connected (ADR 0053). Main's to say, because main is the one end
   * that knows both when a batch arrived and whether it has been answered.
   */
  | { type: 'backlog'; backlog: LiveBacklog }
  /**
   * Main shed a batch rather than post it (`electron/pipeCredit.ts`): these
   * frames are in the capture's pcapng and will not be in the view. Sent in
   * the batch's place, so it arrives exactly where the gap is.
   */
  | { type: 'shed'; firstSeq: number; frames: number }
  /**
   * Why the link is down, as far as anything outside the pipe can tell.
   *
   * Sent only while it IS down, and only from main, because both halves are
   * things a renderer cannot reach: the service's registry key, and how long
   * each of the last few connections lasted. See `services/agentHealth.ts` for
   * what is made of them - this message carries facts and no conclusion.
   */
  | { type: 'service'; facts: AgentServiceFacts; shortConnections: number }
  /**
   * A piece of the capture's own pcapng, answering `readCaptured` (ADR 0053
   * phase 4): the bytes from the offset asked, fewer at the file's end and
   * none when nothing new has been written; `gone` when a ring deleted the
   * file. Opaque here - the Worker parses them.
   */
  | { type: 'capturedBytes'; requestId: number; bytes: Uint8Array | null; gone: boolean; error?: string };

/** What main reports about the live stream (`electron/pipeCredit.ts`). */
export interface LiveBacklog {
  /** Frames posted to the Worker and not yet dissected. */
  frames: number;
  /** The same, in batch bytes. */
  bytes: number;
  /** Milliseconds since main read the oldest of them off the pipe; 0 when none. */
  oldestMs: number;
  /** Frames main has shed since the link connected. */
  shedFrames: number;
  /** Whether main is shedding right now. */
  shedding: boolean;
}

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
   * Batches whose every frame has been dissected, or dropped unread: main's
   * credit for them is returned (`electron/pipeCredit.ts`). Sent once per
   * flush with whatever completed in it.
   */
  | { type: 'drained'; batches: number[] }
  /**
   * Read part of the capture's own pcapng, to catch the live view up after
   * the stream skipped (ADR 0053 phase 4). A capture id and the name the
   * agent gave the file - **never a path**: main checks both and reads from
   * its own folder (`electron/capturedRead.ts`).
   */
  | { type: 'readCaptured'; requestId: number; captureId: string; name: string; offset: number; length: number }
  /**
   * Ask Windows to start the agent's service.
   *
   * Elevation is unavoidable and is the point: the app runs unelevated so that
   * the dissector never parses hostile bytes as an administrator, which means
   * it cannot start a LocalSystem service either. Main raises the UAC prompt
   * rather than the app holding a privilege it wanted once.
   */
  | { type: 'startService' };
