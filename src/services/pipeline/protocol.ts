/**
 * What the main thread and the pipeline Worker say to each other.
 *
 * The Worker owns the ordering window, the trackers and dissection
 * (docs/decisions/0003). It no longer owns the connection: the agent is a
 * named pipe, which only the main process can open, so what the Worker holds
 * is a port main pumps that pipe into (`services/agentLink.ts`). The port is
 * transferred through here rather than opened here, and the renderer's main
 * thread never sees a frame either way. The main thread owns the packet buffer,
 * every view over it, and the raw bytes - which ride along on each frame
 * because carrying them costs 1.1us per frame and leaving them behind would
 * cost export, Follow Stream, the hex view and session persistence a rewrite
 * each (docs/decisions/0007).
 *
 * Control messages - hello, state, error, log, interface_stats, capture_stats -
 * are forwarded up **verbatim**. There are a handful a second at most and every
 * one of them lands in React state, so re-describing them here would be a
 * second vocabulary to keep correct for no gain. The Worker is a pipe for
 * those and a pipeline for packets.
 */
import type { AgentCommand, AgentMessage } from '../agentProtocol';
import type { Packet } from '../../types/packet';
import type { NetworkFacts } from '../networkFacts';
import type { InfoPatch } from '../pcapParser';

/** Where a connection stands, in the terms the header already shows. */
export type PipelineStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

/** Which adapter a frame came from, so the Frame layer can name it. */
export interface PipelineInterface {
  /** The agent's own id for the adapter; the index into its list when absent. */
  id?: number;
  name: string;
  label: string;
}

// --- main thread -> worker ---------------------------------------------------

export type ToPipeline =
  /**
   * The channel to the agent, transferred in the message's transfer list.
   *
   * The Worker no longer opens anything. The agent is a named pipe, which only
   * the main process can open, so what arrives here is one end of a
   * `MessageChannelMain` that main pumps the pipe into - see
   * `services/agentLink.ts`. Sent before `connect`, and `connect` waits for it
   * if it has not arrived yet.
   */
  | { type: 'agentPort' }
  /** Ask main to connect, and to keep retrying on the usual cadence. */
  | { type: 'connect' }
  /** Ask it to disconnect and stop retrying. */
  | { type: 'disconnect' }
  /** Forward a command to the agent. Dropped if the socket is not open. */
  | { type: 'command'; command: AgentCommand }
  /**
   * Whether arriving frames should be dissected at all. The socket stays open
   * either way - the agent is detected before capture starts - so this is what
   * separates "connected" from "recording".
   */
  | { type: 'capturing'; capturing: boolean }
  /** The adapter list from hello/state, so a frame's `iface` can be named. */
  | { type: 'interfaces'; interfaces: PipelineInterface[] }
  /**
   * Forget everything: the buffer was cleared, so the trackers describe a
   * capture that no longer exists. Frame numbering restarts from `nextId`.
   *
   * `captureStartUs` and `lastPacketUs` seed the relative-time clock, which
   * lives in the Worker alongside the numbering. A restored session passes the
   * capture it is continuing; a cleared buffer passes nothing and the next
   * frame to arrive starts the clock.
   */
  | { type: 'reset'; nextId: number; captureStartUs?: number | null; lastPacketUs?: number | null }
  /**
   * A TLS key log, appended to the Worker's own store.
   *
   * The store cannot be shared: the Worker is a separate JavaScript context
   * with its own module instances, and an import runs on the main thread
   * against the main thread's copy. So the text is pushed to both, and pushed
   * again for every key log the user loads.
   *
   * Sent as text rather than as parsed secrets because the parser is one
   * function and the wire is then one string, and because the same text is
   * what a pcapng Decryption Secrets Block wants back out.
   */
  | { type: 'keylog'; text: string }
  /**
   * Who this machine is, for deciding which way each frame went.
   *
   * Sent as plain arrays rather than as a `HostIdentity` because a `Set` does
   * not survive structured clone into a Worker as the same thing on both
   * sides; the Worker rebuilds them. `macs` empty means "nobody knows", and
   * every frame after it carries no direction rather than a guessed one - so
   * clearing this is how the app says the answer has been lost.
   */
  | {
      type: 'host';
      macs: string[]; addresses: string[];
      inferred: boolean; confidence: number; basis?: string;
    }
  /** The protocol tree for one frame. Replies with `detail` or `needReplay`. */
  | { type: 'detail'; id: number }
  /**
   * The frames needed to rebuild a tree the Worker no longer holds, oldest
   * first, with the target last. See `dissectReplay`.
   */
  | {
      type: 'replay'; id: number; frames: ReplayFrame[]; truncated: boolean;
      streamId?: number; retroactive?: InfoPatch;
      /** See ReplayBundle.process - a fact the bytes do not contain. */
      process?: { pid: number; name: string; exe: string };
    };

/** One frame of a replay: everything dissection needs and nothing else. */
export interface ReplayFrame {
  id: number;
  tsUs: number;
  relativeTime: number;
  timeDelta: number;
  origLen: number;
  bytes: Uint8Array;
}

// --- worker -> main thread ---------------------------------------------------

export type FromPipeline =
  | { type: 'status'; status: PipelineStatus }
  /** A control message from the agent, exactly as it arrived. */
  | { type: 'agent'; message: AgentMessage }
  /**
   * A flush's worth of dissected frames, in capture order.
   *
   * `icmpReplies` and `infoPatches` are facts a frame in this batch learned
   * about an EARLIER one - a ping's reply, a reassembled PDU's segments - and
   * are applied by the caller over one pass of the buffer rather than by
   * mapping it per fact.
   */
  | {
      type: 'frames';
      packets: Packet[];
      icmpReplies: { requestFrameId: number; replyId: number }[];
      infoPatches: InfoPatch[];
      /** Frames released behind one that had already left the ordering window. */
      lateCount: number;
    }
  | { type: 'detail'; id: number; layers: Packet['layers'] }
  /**
   * What the capture has revealed about the network it was taken on.
   *
   * Posted only when something new was learned rather than per flush: these
   * are facts about a network, and a network does not acquire a new resolver
   * ten times a second. See `services/networkFacts.ts`.
   */
  | { type: 'networkFacts'; facts: NetworkFacts }
  /**
   * The tree for this frame is no longer cached, and rebuilding it needs the
   * frames before it on its stream - which the main thread has and the Worker
   * does not.
   */
  | { type: 'needReplay'; id: number }
  /** Something went wrong that the user should be told about, not swallowed. */
  | { type: 'failure'; message: string };
