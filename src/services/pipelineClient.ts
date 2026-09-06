/**
 * The main thread's handle on the pipeline Worker.
 *
 * Deliberately shaped like the WebSocket it replaces - `connect`, `send`, a
 * message callback, a status callback - so the app's agent handling reads the
 * same way it did when the socket was here. What changed is where the work
 * happens, not what the app is told about it.
 *
 * One instance per page. The Worker is started on first use rather than at
 * module load, so a build that never opens a capture never spawns it.
 */
import type { AgentMessage, AgentCommand } from './agentProtocol';
import type { Packet, ProtocolLayer } from '../types/packet';
import type { InfoPatch } from './pcapParser';
import type { HostIdentity } from './direction';
import type { NetworkFacts } from './networkFacts';
import type {
  FromPipeline, PipelineInterface, PipelineStatus, ReplayFrame, ToPipeline,
} from './pipeline/protocol';

export interface FrameBatch {
  packets: Packet[];
  icmpReplies: { requestFrameId: number; replyId: number }[];
  infoPatches: InfoPatch[];
  lateCount: number;
}

/** What a replay needs, produced by the caller only when one is actually needed. */
export interface ReplayBundle {
  frames: ReplayFrame[];
  /** The conversation's earlier frames are no longer in the buffer. */
  truncated: boolean;
  /** The stream index the capture gave this conversation, if it had one. */
  streamId?: number;
  /** A generated row a later frame wrote onto this one; see `dissectReplay`. */
  retroactive?: InfoPatch;
  /**
   * The process that owned this frame's socket, carried rather than re-derived.
   *
   * Same reason as `retroactive` above: a replay dissects bytes, and no amount
   * of dissecting says which program sent them. The frame learned it when it
   * was first captured; the rebuilt tree is handed it back, so the detail pane
   * and the Process column cannot end up disagreeing about one frame.
   */
  process?: { pid: number; name: string; exe: string };
}

export class PipelineClient {
  private worker: Worker | null = null;
  /** Detail requests waiting on the Worker, by frame number. */
  private pendingDetail = new Map<number, {
    resolve: (layers: ProtocolLayer[]) => void;
    replay: () => ReplayBundle | Promise<ReplayBundle>;
  }>();

  onStatus: (status: PipelineStatus) => void = () => {};
  onAgentMessage: (message: AgentMessage) => void = () => {};
  onFrames: (batch: FrameBatch) => void = () => {};
  onFailure: (message: string) => void = () => {};
  /**
   * What the capture revealed about the network, when it changes.
   *
   * Not per flush: these are facts about a network, and a network does not
   * acquire a new resolver ten times a second.
   */
  onNetworkFacts: (facts: NetworkFacts) => void = () => {};

  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    // A module worker, resolved through the bundler the same way maplibre's
    // own workers are - the arrangement vite.config.ts already handles.
    const worker = new Worker(new URL('../workers/pipeline.worker.ts', import.meta.url), {
      type: 'module',
      name: 'inwire-pipeline',
    });
    worker.onmessage = (event: MessageEvent<FromPipeline>) => this.receive(event.data);
    worker.onerror = (event) => this.onFailure(event.message || 'the packet pipeline failed');
    this.worker = worker;
    return worker;
  }

  private send(message: ToPipeline, transfer?: Transferable[]) {
    this.ensureWorker().postMessage(message, transfer ?? []);
  }

  private receive(message: FromPipeline) {
    switch (message.type) {
      case 'status':
        this.onStatus(message.status);
        break;
      case 'agent':
        this.onAgentMessage(message.message);
        break;
      case 'frames':
        this.onFrames(message);
        break;
      case 'failure':
        this.onFailure(message.message);
        break;
      case 'networkFacts':
        this.onNetworkFacts(message.facts);
        break;
      case 'detail': {
        const waiting = this.pendingDetail.get(message.id);
        this.pendingDetail.delete(message.id);
        waiting?.resolve(message.layers);
        break;
      }
      case 'needReplay': {
        // The Worker no longer holds this frame's tree. Rebuilding it needs
        // the frames before it on its conversation, which live in the buffer
        // up here - so they go down now, and only now: sending them with every
        // request would cost megabytes per click for the frames the Worker
        // could have answered from its cache.
        const waiting = this.pendingDetail.get(message.id);
        if (!waiting) break;
        // The bundle may have to be awaited: a frame whose bytes the buffer no
        // longer holds gets them back from the store, and so may the frames
        // before it on its conversation (services/packetBytes.ts). Wrapped
        // rather than awaited, because a message handler that blocks would
        // stall every other message behind it.
        void Promise.resolve(waiting.replay()).then(
          (bundle) => {
            this.send({
              type: 'replay', id: message.id,
              frames: bundle.frames, truncated: bundle.truncated,
              streamId: bundle.streamId, retroactive: bundle.retroactive,
              process: bundle.process,
            });
          },
          // A rejected replay used to wedge the frame permanently. Nothing
          // caught it, and the pending entry is only removed when a `detail`
          // reply arrives - so the promise `detail()` handed back never
          // settled, the pane spun for ever, and because a second request for
          // the same id JOINS the one in flight, that frame could not be
          // opened again for the life of the page.
          //
          // Answered with an empty tree rather than a rejection, which is the
          // rule the sibling path already follows: `packetBytes` gives a frame
          // the store cannot supply an empty array, because a frame whose
          // bytes are gone is a thing to render and not an error to handle.
          // Dropping the entry first is what makes the next attempt a fresh
          // request rather than a join onto a dead one.
          () => {
            this.pendingDetail.delete(message.id);
            waiting.resolve([]);
          },
        );
        break;
      }
    }
  }

  connect(url: string) {
    this.send({ type: 'connect', url });
  }

  disconnect() {
    this.send({ type: 'disconnect' });
  }

  command(command: AgentCommand) {
    this.send({ type: 'command', command });
  }

  setCapturing(capturing: boolean) {
    this.send({ type: 'capturing', capturing });
  }

  setInterfaces(interfaces: PipelineInterface[]) {
    this.send({ type: 'interfaces', interfaces });
  }

  /**
   * Hand the Worker a TLS key log. Only affects connections dissected from
   * here on: the frames already in the buffer were dissected without it, and
   * re-dissecting a live capture's history would renumber nothing but would
   * mean replaying every tracker.
   */
  addKeyLog(text: string) {
    this.send({ type: 'keylog', text });
  }

  /**
   * Who this machine is, so the Worker can say which way each frame went.
   *
   * Sets rather than arrays at this boundary, because that is what the rest of
   * the app holds; the wire carries arrays because a Set does not survive a
   * structured clone as itself.
   *
   * Applies to frames dissected from here on. The ones already in the buffer
   * are re-derived by the main thread, which is the side that holds them - the
   * Worker keeps no buffer to revisit.
   */
  setHost(host: HostIdentity) {
    this.send({
      type: 'host',
      macs: [...host.macs], addresses: [...host.addresses],
      inferred: host.inferred, confidence: host.confidence, basis: host.basis,
    });
  }

  /**
   * The buffer changed underneath the pipeline: forget the trackers, number the
   * next frame `nextId`, and set the relative-time clock.
   *
   * A cleared buffer passes no clock and the next frame starts it. A restored
   * session passes the capture it is continuing.
   */
  reset(nextId: number, captureStartUs?: number | null, lastPacketUs?: number | null) {
    this.send({ type: 'reset', nextId, captureStartUs, lastPacketUs });
  }

  /**
   * The protocol tree for one frame.
   *
   * `replay` is called only if the Worker has to rebuild the tree, so the
   * caller can gather a conversation's frames lazily rather than on every
   * selection.
   *
   * A second request for a frame already in flight joins the first rather than
   * queueing behind it - arrow-keying down the packet list issues one of these
   * per row, and most of them are superseded before they are answered.
   */
  detail(id: number, replay: () => ReplayBundle | Promise<ReplayBundle>): Promise<ProtocolLayer[]> {
    const inFlight = this.pendingDetail.get(id);
    if (inFlight) {
      return new Promise((resolve) => {
        const previous = inFlight.resolve;
        inFlight.resolve = (layers) => { previous(layers); resolve(layers); };
      });
    }
    return new Promise((resolve) => {
      this.pendingDetail.set(id, { resolve, replay });
      this.send({ type: 'detail', id });
    });
  }
}

/** The one pipeline this page uses. */
export const pipeline = new PipelineClient();
