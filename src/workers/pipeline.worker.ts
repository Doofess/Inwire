/**
 * The packet pipeline: socket -> ordering -> dissection -> trackers, off the
 * main thread (docs/decisions/0003, docs/decisions/0007).
 *
 * Everything that runs per captured frame lives here. The main thread's job is
 * now the buffer and the views over it; it never parses a message from the
 * agent, never decodes base64, never advances a tracker and never dissects.
 * What it receives is a batch of finished `Packet`s once per flush, with the
 * raw bytes attached and the protocol tree left behind.
 *
 * The connection is not here any more, and that is a change of owner rather
 * than of design. The agent is reached over a named pipe, which neither a
 * renderer nor a Web Worker can open - `net.connect` is Node. So the main
 * process holds the handle and pumps it into one end of a channel; this Worker
 * holds the other (`services/agentLink.ts`). What must not change with it is
 * that the renderer's MAIN THREAD never sees a frame: it carries the port
 * across once and then plays no part, so the property ADR 0007 bought is
 * intact. Control messages are forwarded up untouched - there are a handful a
 * second and every one of them lands in React state.
 */
/// <reference lib="webworker" />

import { OrderingWindow, type Orderable } from '../services/dissect/orderingWindow';
import { keyLog } from '../services/tls/keyLog';
import { decodePacketBatch, isPacketBatch, retain } from '../services/agentBinary';
import { encodeAgentCommand, parseAgentMessage } from '../services/agentProtocol';
import type { FromAgentLink, ToAgentLink } from '../services/agentLink';
import { decodeRawEthernetPacket, type InfoPatch } from '../services/pcapParser';
import { LINKTYPE } from '../services/dissect/types';
import { flowAnnotations } from '../services/flowAnnotations';
import { addProcessRow, annotatePacket } from '../services/dissect/processFields';
import { addLiveGapRow, markLiveGap } from '../services/dissect/liveGapFields';
import { HOLE_MIN_FRAMES, LiveFlow } from '../services/pipeline/liveFlow';
import { CaptureFiles, CatchUp, CatchUpRouter, type CatchUpEnd, type FileFrame } from '../services/pipeline/catchUp';
import { clientFingerprints, learnOrLabelFingerprint } from '../services/dissect/clientFingerprints';
import { buildFallbackPacket } from '../services/sessionRestore';
import { TcpStreamTracker } from '../services/tcpStreamTracker';
import { IcmpEchoTracker } from '../services/icmpEchoTracker';
import { QuicFlowTracker } from '../services/quicFlowTracker';
import { DnsTracker } from '../services/dnsTracker';
import { Sequencer } from '../services/dissect/sequencer';
import { L3Tracker } from '../services/l3Tracker';
import { NO_HOST, type HostIdentity } from '../services/direction';
import { NetworkFactsCollector } from '../services/networkFacts';
import { DuplicateFinder, duplicateSuffix } from '../services/duplicateFrames';
import { dissectReplay, interfacesByLabel } from '../services/pipeline/replay';
import { FrameRecorder, FrameRevisit, RecordMiss } from '../services/dissect/frameRecord';
import { DerivedStore } from '../services/pipeline/derivedStore';
import { withDissectEnv } from '../services/dissect/dissectEnv';
import { applyInfoPatch, treeLinksOf } from '../services/dissect/infoPatch';
import type { FromCapture } from '../services/capture/captureProtocol';
import type { RingPart } from '../services/capture/segments';
import { packFrames } from '../services/capture/frameSlab';
import { RingFiling } from '../services/pipeline/ringFiling';
import type { ProcessInfo } from '../services/flowAnnotations';
import type {
  FromPipeline, PipelineInterface, ToPipeline,
} from '../services/pipeline/protocol';
import type { Packet, ProtocolLayer } from '../types/packet';
import { Coordinator, WatchedTcpOrder, type Merged, type PackedRef } from '../services/pipeline/coordinator';
import { PackSender, PackedFlush } from '../services/pipeline/rowPack';
import { overlayOf, type RowOverlay } from '../services/pipeline/rowOverlay';
import { mergeRowSide } from '../services/pipeline/rowSteps';
import { shardEnv } from '../services/pipeline/shard';
import { FifoMap } from '../services/pipeline/fifoMap';
import type { FromShard, ToShard } from '../services/pipeline/shardProtocol';
import { LIVE_ENV } from '../services/dissect/dissectEnv';
import { settleTreeTls } from '../services/dissect/shardNumbering';
import { shardsFor, type DissectionThreads } from '../services/pipeline/threads';
import { isShardRole, runShard, SHARD_NAME } from './shardRole';

/** Matches the main thread's old flush cadence, which the packet list is tuned to. */
const FLUSH_MS = 100;
/** See services/dissect/orderingWindow.ts. */
const ORDERING_HOLD_MS = 100;
/**
 * How many frames' trees are kept for the detail pane.
 *
 * A tree is 10.6 kB, so this is about 42 MB - the price of answering a click on
 * a recent frame without dissecting anything again, which is what nearly every
 * click during a live capture is. Older frames are rebuilt by replaying their
 * conversation (services/pipeline/replay.ts).
 */
const DETAIL_CACHE_FRAMES = 4000;

interface LiveFrame extends Orderable {
  /** Nanoseconds past `tsUs`; see `agentBinary.ts`. */
  tsNsRem: number;
  bytes: Uint8Array;
  origLen: number;
  iface: number;
  /** The agent's ring file it is in, filed as it arrived (`ringFiling.ts`). */
  ring?: RingPart;
  /** Main's id for the batch it came in, handed back once it is dissected. */
  batch?: number;
  /** Frames the live stream skipped just before this one (`liveFlow.ts`). */
  holeBefore?: number;
}

const ctx = self as unknown as DedicatedWorkerGlobalScope;

function post(message: FromPipeline, transfer?: Transferable[]) {
  ctx.postMessage(message, transfer ?? []);
}

// --- capture state -----------------------------------------------------------

/** The channel to the agent, handed over by main. See `services/agentLink.ts`. */
let agentPort: MessagePort | null = null;
/** Whether the app wants a connection, held here because the port may be late. */
let wantConnection = false;

let capturing = false;

/**
 * The capture store, for frame bytes. Null until the port arrives, and
 * possibly for ever - see `ToPipeline`'s `storePort`.
 *
 * **This is what takes the write off the dissector's critical path.** Bytes are
 * posted for a whole released group BEFORE any of it is dissected, so a frame
 * whose own dissection throws still reaches disk - which it did not before:
 * `ingest`'s catch reported the failure and the frame was simply gone.
 */
let storePort: MessagePort | null = null;
/**
 * The ids whose bytes this Worker has posted on `storePort`, as one run:
 * frames are numbered consecutively, so a capture is one run, and anything
 * that breaks it - a reset, a new port, a group posted with no port - starts
 * another. A row inside the run goes to the store without its bytes
 * (`bytesSent`); one outside it carries them, and the store's own slot rule
 * decides, as it always has.
 */
let bytesSentFrom = -1;
let bytesSentThrough = -1;
/**
 * Frames posted to the store that it may not have had a capture open for.
 *
 * Should always be zero. The app sends `open` to the store before it sends
 * `start_capture` to the agent, and `capturing` below is set after both - so
 * bytes cannot precede the open by any ordinary path. Counted rather than
 * assumed, because the two travel on different ports and nothing orders two
 * ports against each other; a silent loss at the start of every capture is the
 * shape this codebase has shipped before.
 */
let bytesPostedWhileIdle = 0;
/**
 * Whether a capture has run since the last reset. Frames released after Stop
 * are that capture's tail, going to a capture that is open - not frames that
 * reached the store before one was, which is what the warning below is for.
 */
let capturedSinceReset = false;
let interfaces: PipelineInterface[] = [];

/**
 * Everything numbered across conversations - the stream indexes, the TCP
 * connection order, each frame's clocks - in one stage the trackers ask
 * (`dissect/sequencer.ts`, ADR 0053). Rebuilt with them.
 */
let sequencer = new Sequencer();
let tcpTracker = new TcpStreamTracker(sequencer);
let icmpTracker = new IcmpEchoTracker();
let quicTracker = new QuicFlowTracker();
let dnsTracker = new DnsTracker();
let l3Tracker = new L3Tracker(sequencer);

/**
 * Who this machine is, and what the capture says about the network.
 *
 * Both live beside the trackers because both are cross-frame state the
 * dissection reads, and both are reset with them. The identity comes from the
 * agent's `adapter_config` for a live capture - the only source that is a fact
 * rather than an inference - so it is empty until a client subscribes, and
 * every frame before that carries no direction rather than a guessed one.
 */
/**
 * The trackers, behind a recorder (ADR 0049). Every frame is dissected through
 * `recorder.sources`, which answers from the real trackers and writes down what
 * they said, so the frame's tree can be built again later from that frame and
 * its record - with no replay of its conversation.
 */
function makeRecorder(): FrameRecorder {
  return new FrameRecorder({
    tcp: tcpTracker, quic: quicTracker, dns: dnsTracker, icmp: icmpTracker, l3: l3Tracker,
  });
}
let recorder = makeRecorder();

let host: HostIdentity = NO_HOST;
const networkFacts = new NetworkFactsCollector();
/**
 * Frames captured twice, on two adapters at once.
 *
 * Only consulted when more than one interface is being captured. In the common
 * single-interface case there is by construction nothing to find, and hashing
 * every frame to discover that would be work on the hot path in exchange for
 * a guaranteed empty answer.
 */
const duplicates = new DuplicateFinder();

const ordering = new OrderingWindow<LiveFrame>(ORDERING_HOLD_MS);

/**
 * What this Worker owes main and is owed by the store, and the holes in the
 * agent's numbering - ADR 0053's bounds on the live path (`liveFlow.ts`).
 */
const flow = new LiveFlow();

/**
 * Frames released from the ordering window, in capture order, not yet
 * dissected; `releasedFrom` is the first one still waiting.
 *
 * **Why there is a queue between the window and the dissector at all.** A
 * flush used to dissect everything the window released in one go, which is
 * right while dissection keeps up - and when it does not, each flush is
 * longer than the last and the Worker answers nothing else for the length of
 * it: not the detail pane asking for the selected frame's tree, and not
 * main's report of how far behind live it is, which would then be as late as
 * the backlog it reports. So a flush dissects a slice (`SLICE_MS`) and comes
 * straight back for the next while frames are waiting, and messages are
 * handled between slices.
 */
let released: LiveFrame[] = [];
let releasedFrom = 0;
/** How long one flush may dissect before it yields, in milliseconds. */
const SLICE_MS = 50;
/** A running estimate of one frame's dissection, so a slice is sized without a clock read per frame. */
let usPerFrame = 25;
let flushSoon = false;

/** Ids are assigned here now: the frame is numbered where it is dissected. */
let nextId = 1;
/**
 * Which ring file each frame is in, from the agent's `capture_boundary`
 * messages. Never reset: an epoch is a run of the agent's capture, and one
 * that outlived a Clear is still the run it was.
 */
const ringFiling = new RingFiling();
/** Stand-in sequence number for an agent that sends none. */
let arrivalSeq = 0;

// --- catching up from the agent's file (ADR 0053 phase 4) ---------------------

/**
 * The capture's id, from its `start_capture`: what main is asked to read the
 * agent's pcapng under. Null for a capture that writes no file - then a hole
 * in the stream is marked, as it was before catch-up existed.
 */
let captureId: string | null = null;
/** What the agent has said about the capture's files: where each begins, its name, whether it is gone. */
const captureFiles = new CaptureFiles();
const catchUp = new CatchUp<LiveFrame>(captureFiles);
/** Every live frame meets the live path here, and every frame read back from the file (`catchUp.ts`). */
const router = new CatchUpRouter<LiveFrame>(
  flow, catchUp, fromFile,
  (frame, hole) => { ordering.push(hole > 0 ? { ...frame, holeBefore: hole } : frame); },
  (frame) => { flow.frameDone(frame.batch); },
  HOLE_MIN_FRAMES,
);
/** The read main is answering, if one is out. */
let catchUpRequest: number | null = null;
let nextCatchUpRequest = 1;
let catchUpRetry: ReturnType<typeof setTimeout> | null = null;
/**
 * Frames waiting to be dissected past which the file is not read further:
 * a read is about 3,600 frames, and this is a second or so of the Worker's
 * work - enough to keep it busy, not enough to be a heap of its own.
 */
const CATCH_UP_BACKLOG = 40_000;
/** The adapter of the newest live frame, for a file frame whose IDB names none this list has. */
let lastLiveIface = 0;

/** A frame read back from the file, as the live path carries one. */
function fromFile(frame: FileFrame): LiveFrame {
  return {
    tsUs: frame.tsUs,
    tsNsRem: frame.tsNsRem,
    seq: frame.seq,
    arrivedAt: performance.now(),
    bytes: frame.bytes,
    origLen: frame.origLen,
    iface: ifaceOfIdb(frame.idb),
    ring: ringFiling.partOf(frame.seq),
  };
}

/**
 * The agent's adapter id for an IDB of its file. The IDB names the device and
 * the interface list names it too; a name this list does not have - or a file
 * with no names - is read as the adapter the live stream last came from.
 */
function ifaceOfIdb(idb: number): number {
  const name = catchUp.idbName(idb);
  if (name !== null) {
    const index = interfaces.findIndex((entry) => entry.name === name);
    if (index >= 0) return interfaces[index].id ?? index;
  }
  return lastLiveIface;
}

/** Asks main for the next piece of the file, if catching up and the Worker has room for it. */
function pumpCatchUp(): void {
  if (!capturing || !catchUp.active || catchUpRequest !== null || catchUpRetry !== null) return;
  if (captureId === null || agentPort === null) return;
  if (released.length - releasedFrom + ordering.size > CATCH_UP_BACKLOG) return;
  const want = catchUp.wantRead();
  if (want === null) return;
  catchUpRequest = nextCatchUpRequest++;
  tellAgent({ type: 'readCaptured', requestId: catchUpRequest, captureId, ...want });
}

/** Main's answer to a read. */
function receiveCaptured(message: Extract<FromAgentLink, { type: 'capturedBytes' }>): void {
  if (message.requestId !== catchUpRequest) return;
  catchUpRequest = null;
  if (!capturing) return;
  const outcome = router.read(message);
  if (outcome.ended !== undefined) reportCatchUpEnd(outcome.ended);
  if (!flushSoon) {
    flushSoon = true;
    setTimeout(flush, 0);
  }
  if (outcome.retryMs !== undefined && outcome.retryMs > 0) {
    catchUpRetry = setTimeout(() => { catchUpRetry = null; pumpCatchUp(); }, outcome.retryMs);
  } else {
    pumpCatchUp();
  }
}

/**
 * Said when catch-up gives up for a reason a person should hear. A ring file
 * deleted before it was read needs no message: the hole it leaves is marked
 * on the frame after it, like any other.
 */
function reportCatchUpEnd(why: CatchUpEnd): void {
  if (why === 'noFile') return;
  const reason = why === 'unreadable' ? 'the capture file could not be read'
    : 'the capture file does not hold the frames where their numbers say, because its writer refused some';
  post({
    type: 'failure',
    message: `The live view could not catch up from the capture file: ${reason}. `
      + 'What it skipped is marked on the frame after each gap, and is in the file.',
  });
}

/** The capture stopped: catch-up ends here, and what it held goes on live. */
function stopCatchUp(): void {
  if (catchUpRetry !== null) clearTimeout(catchUpRetry);
  catchUpRetry = null;
  catchUpRequest = null;
  router.stop();
}

/**
 * What the flush needs of a row it forwards as the pack the shard made: its
 * id and its bytes. A shard row that was never decoded here is only this.
 */
type RowStub = Pick<Packet, 'id' | 'rawBytes'>;
let pendingPackets: (Packet | RowStub)[] = [];
/**
 * Beside `pendingPackets`, one per row: where a shard's row sits in the pack
 * it came in (null for a row this Worker built, which is always a whole
 * `Packet`), and what the merge wrote to it since. The flush forwards the pack
 * rather than the decoded row (`rowPack.ts`). With more than one interface the
 * coordinator decodes every row, so `pendingPackets` is whole when `duplicates`
 * reads it.
 */
let pendingRefs: (PackedRef | null)[] = [];
let pendingOverlays: (RowOverlay | null)[] = [];
/** What each receiver has been sent, and whether it is to forget the last capture's packs. */
const windowSender = new PackSender();
const storeSender = new PackSender();

function isWholePacket(row: Packet | RowStub): row is Packet {
  return 'layers' in row;
}

/** A row this Worker built, which is never a stub: the only rows with no pack to go on in. */
function wholeRow(row: Packet | RowStub): Packet {
  if (!isWholePacket(row)) throw new Error('a row with no pack to travel in was queued without its fields');
  return row;
}

function queueRow(packet: Packet | RowStub, ref: PackedRef | null = null, overlay: RowOverlay | null = null): void {
  pendingPackets.push(packet);
  pendingRefs.push(ref);
  pendingOverlays.push(overlay);
}

function clearPendingRows(): void {
  pendingPackets = [];
  pendingRefs = [];
  pendingOverlays = [];
}
let pendingIcmpReplies: { requestFrameId: number; replyId: number }[] = [];
let pendingInfoPatches: InfoPatch[] = [];
/** This flush's frame records, for the store. */
let pendingRecords: { id: number; record: Uint8Array }[] = [];
/**
 * Each frame's decrypted answers, which its record refuses to hold: memory
 * only, here, and gone with the key log or the capture (ADR 0049).
 */
const derivedStore = new DerivedStore();

/**
 * Recently dissected trees, so the detail pane can be answered without
 * re-dissecting anything. The newest `DETAIL_CACHE_FRAMES` are kept, in a
 * `FifoMap` rather than a Map evicted from its front - which walks every hole
 * its deletes left on each eviction (`pipeline/fifoMap.ts`).
 */
const treeCache = new FifoMap<ProtocolLayer[]>(DETAIL_CACHE_FRAMES);

function cacheTree(id: number, layers: ProtocolLayer[]) {
  treeCache.set(id, layers);
}

// --- dissection on several cores (ADR 0053 phase 3) -------------------------

/**
 * The setting, and the shards it was last applied as. Applied when a capture
 * is cleared - which is how a fresh one begins - so a capture is never split
 * between two arrangements.
 */
let threadsWanted: DissectionThreads = 1;
/**
 * The coordinator and its shard Workers, or null for the single Worker - in
 * which case everything below this block is exactly what it always was.
 */
let parallel: {
  coordinator: Coordinator;
  workers: Worker[];
} | null = null;
/** Every key log text loaded, for a shard started after it arrived. */
const keyLogTexts: string[] = [];
/** Detail requests a shard is answering, by request id. */
const shardDetails = new Map<number, (layers: ProtocolLayer[] | null) => void>();
let nextShardDetail = 1;
/**
 * The last socket table, and the time it was applied at, since the annotations
 * were last cleared: for shards started after it arrived, which would
 * otherwise annotate nothing the single Worker would have. Only the last table
 * is kept, so a flow an earlier table listed and the last no longer does is
 * lost to those shards.
 */
let lastFlows: Extract<ToShard, { type: 'flows' }> | null = null;
/** Frames in flight past which the flush stops handing the coordinator more. */
const PARALLEL_BACKLOG = 65_536;
/** Trees each shard keeps for the detail pane: lane 0 keeps its own `DETAIL_CACHE_FRAMES`. */
const SHARD_CACHE_FRAMES = 2_000;
/** When rows were last posted to the app, for `afterMerge`'s cadence. */
let lastPostedAt = 0;

/** Lane 0's trackers for a new capture, numbering through a watched TCP order. */
function laneZero(): { trackers: { tcp: TcpStreamTracker; icmp: IcmpEchoTracker; quic: QuicFlowTracker; dns: DnsTracker; l3: L3Tracker }; sequencer: Sequencer } {
  const fresh = new Sequencer(new WatchedTcpOrder());
  return {
    sequencer: fresh,
    trackers: {
      tcp: new TcpStreamTracker(fresh), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
      dns: new DnsTracker(), l3: new L3Tracker(fresh),
    },
  };
}

function hostMessage(): ToShard {
  return {
    type: 'host', macs: [...host.macs], addresses: [...host.addresses],
    inferred: host.inferred, confidence: host.confidence, basis: host.basis,
  };
}

function interfacesMessage(): ToShard {
  return {
    type: 'interfaces',
    interfaces: [...interfaceById.entries()].map(([id, record]) => {
      const tsPrecision = tsPrecisionById.get(id);
      return [id, tsPrecision === undefined ? record : { ...record, tsPrecision }];
    }),
  };
}

function stopParallel(): void {
  if (parallel === null) return;
  for (const worker of parallel.workers) worker.terminate();
  for (const answer of shardDetails.values()) answer(null);
  shardDetails.clear();
  parallel = null;
}

/** The shards the setting asks for, started - or none, and the single Worker. */
function startParallel(shards: number): void {
  stopParallel();
  // A new coordinator numbers its packs from zero again.
  windowSender.reset();
  storeSender.reset();
  if (shards < 1) return;
  const workers: Worker[] = [];
  const lane = laneZero();
  const coordinator = new Coordinator({
    shards,
    route: 'connection',
    maxInFlight: 3,
    trackers: lane.trackers,
    sequencer: lane.sequencer,
    env: shardEnv(LIVE_ENV, shards),
    ifaceOf: (iface) => (iface === undefined ? undefined : interfaceFor(iface)),
    send: (shard, message, transfer) => workers[shard]?.postMessage(message, transfer),
    emit: (merged) => emitMerged(merged),
  });
  coordinator.lane0.host = host;
  // With more than one interface `duplicates.scan` reads every row, so each
  // one is decoded here; otherwise the merge works from the side records.
  coordinator.decodeRows = interfaces.length > 1;
  for (let s = 0; s < shards; s++) {
    // The same script, in its shard role (`shardRole.ts`).
    const worker = new Worker(self.location.href, { type: 'module', name: `${SHARD_NAME}${s}` });
    worker.onmessage = (event: MessageEvent<FromShard>) => receiveFromShard(s, event.data);
    worker.onerror = (event) => {
      event.preventDefault();
      shardDown(s, event.message || 'it stopped');
    };
    worker.postMessage({ type: 'init', shards, cacheFrames: SHARD_CACHE_FRAMES } satisfies ToShard);
    workers.push(worker);
  }
  parallel = { coordinator, workers };
  coordinator.broadcast(hostMessage());
  coordinator.broadcast(interfacesMessage());
  for (const text of keyLogTexts) coordinator.broadcast({ type: 'keylog', text });
  if (lastFlows !== null) coordinator.broadcast(lastFlows);
}

function shardDown(shard: number, reason: string): void {
  post({ type: 'failure', message: `dissection shard ${shard + 1} stopped: ${reason}` });
  parallel?.coordinator.shardFailed(shard, reason);
  afterMerge();
}

function receiveFromShard(shard: number, message: FromShard): void {
  if (parallel === null) return;
  // Not a `switch`: `scripts/tls/key-log.ts` reads the app's command cases out
  // of this file's source by their labels, and a second case labelled with the
  // detail message above them would be the one it found.
  if (message.type === 'results') {
    parallel.coordinator.receive(shard, message);
    afterMerge();
  } else if (message.type === 'detail') {
    const answer = shardDetails.get(message.requestId);
    shardDetails.delete(message.requestId);
    answer?.(message.layers);
  } else {
    shardDown(shard, message.message);
  }
}

/** A recent frame's tree from the shard that dissected it, or null when it has gone. */
function treeFromShard(shard: number, id: number): Promise<ProtocolLayer[] | null> {
  const current = parallel;
  if (current === null) return Promise.resolve(null);
  const requestId = nextShardDetail++;
  return new Promise((resolve) => {
    shardDetails.set(requestId, resolve);
    // What the merge owes the shard - rows, links - first, so the tree is whole.
    current.coordinator.flushSide(shard);
    current.workers[shard].postMessage({ type: 'detail', requestId, id } satisfies ToShard);
  });
}

/**
 * One frame merged back into order - what `ingest` does after its dissection,
 * for a frame any lane dissected. The rows the process, a live gap and a
 * fingerprint add go to the Frame layer of whichever tree the frame has: here
 * for lane 0, on the shard for the others. A shard annotates and marks its
 * own rows, so only lane 0's are done here; the order-dependent steps -
 * fingerprints, network facts - run here for all of them, from the packet
 * when it was decoded and from the shard's side record when it was not.
 */
function emitMerged(merged: Merged): void {
  const frame = merged.meta as LiveFrame;
  flow.frameDone(frame.batch);
  if (merged.error !== undefined || (merged.packet === undefined && merged.packed === undefined)) {
    post({ type: 'failure', message: merged.error ?? 'failed to dissect a captured frame' });
    return;
  }
  const id = merged.id;
  if (merged.record !== undefined) pendingRecords.push({ id, record: merged.record });
  if (merged.derived) derivedStore.set(id, merged.derived);

  const packet = merged.packet;
  if (packet === undefined) {
    // A light row: it stays in the pack the shard made, and the overlay says
    // what the merge adds to it. The shard has put the clock in the pack by the
    // same rule as below.
    const { overlay, frameRows } = mergeRowSide(
      merged.side, { fingerprints: clientFingerprints, facts: networkFacts, host }, merged.overlay ?? null,
    );
    if (frameRows.length > 0) parallel?.coordinator.frameRows(merged.lane, id, frameRows);
    queueRow({ id, rawBytes: merged.bytes ?? NO_ROW_BYTES }, merged.packed ?? null, overlay);
  } else {
    const precision = tsPrecisionById.get(frame.iface) ?? 6;
    packet.tsPrecision = precision;
    if (precision > 6) packet.tsNanos = BigInt(frame.tsUs) * 1000n + BigInt(frame.tsNsRem);

    const tree = merged.lane === 0 ? packet.layers : null;
    const stub: ProtocolLayer = { name: 'Frame', summary: '', fields: [] };
    packet.layers = tree ?? [stub];
    // A shard did both of these to its row before packing it; a second
    // `annotatePacket` would add a second Process row.
    if (merged.lane === 0) {
      annotatePacket(packet, flowAnnotations);
      if (frame.holeBefore !== undefined) markLiveGap(packet, frame.holeBefore);
    }
    learnOrLabelFingerprint(packet.fields, clientFingerprints, packet.layers);
    networkFacts.observe(packet, host);
    if (tree !== null) cacheTree(id, tree);
    else parallel?.coordinator.frameRows(merged.lane, id, stub.fields);
    packet.layers = [];

    // After the last write to the row, so the overlay carries every one of them.
    // The mark it is compared with was taken when the coordinator unpacked the row.
    queueRow(packet, merged.packed ?? null, merged.packed?.mark === undefined ? null : overlayOf(packet, merged.packed.mark));
  }
  if (merged.icmpMatchedRequestFrameId !== undefined) {
    pendingIcmpReplies.push({ requestFrameId: merged.icmpMatchedRequestFrameId, replyId: id });
  }
  if (merged.infoPatches) {
    pendingInfoPatches.push(...merged.infoPatches);
    parallel?.coordinator.routePatches(merged.lane, merged.infoPatches, (patch) => {
      const cached = treeCache.get(patch.frameId);
      if (cached !== undefined) {
        applyInfoPatch({ layers: cached, info: '', fields: {} } as unknown as Packet, { ...patch, suffix: undefined });
      }
    });
  }
}

/**
 * Whether what this Worker feeds - the store, or the app's window - has not
 * taken enough of what it was sent, so frames wait in the ordering window
 * (ADR 0053, `liveFlow.ts`).
 */
function downstreamBehind(): boolean {
  return flow.storeBehind || flow.rendererBehind;
}

/** The window or the store just took something: a flush they were holding back can go. */
function resumeIfHeld(wasBehind: boolean): void {
  if (wasBehind && !downstreamBehind() && !flushSoon) {
    flushSoon = true;
    setTimeout(flush, 0);
  }
}

/** After the coordinator merged something: post it, and let the flush take more. */
function afterMerge(): void {
  // Not on every answer: a shard answers every few hundred frames, and the
  // app's main thread pays per message as well as per row. The flush timer
  // posts whatever this leaves.
  if (pendingPackets.length >= 4096 || performance.now() - lastPostedAt >= SLICE_MS) postFlushed();
  if (released.length > releasedFrom && !flushSoon && !downstreamBehind()
    && parallel !== null && parallel.coordinator.backlog < PARALLEL_BACKLOG / 2) {
    flushSoon = true;
    setTimeout(flush, 0);
  }
}

/** The clock frames are numbered by: the coordinator's when there is one. */
function frameClock(): Sequencer['clock'] {
  return parallel !== null ? parallel.coordinator.clock : sequencer.clock;
}

/** The last reset's arguments, for a setting applied before anything followed it. */
let resetAt: { startId: number; startUs: number | null; lastUs: number | null } = { startId: 1, startUs: null, lastUs: null };

/** The shards the setting asks for, started if they are not the ones running. True when it changed anything. */
function applyThreads(): boolean {
  const shards = shardsFor(threadsWanted, navigator.hardwareConcurrency ?? 1);
  if (shards === (parallel?.workers.length ?? 0)) return false;
  startParallel(shards);
  return true;
}

function resetPipeline(startId: number, startUs?: number | null, lastUs?: number | null) {
  resetAt = { startId, startUs: startUs ?? null, lastUs: lastUs ?? null };
  // The setting is applied here, between captures.
  if (!applyThreads() && parallel !== null) parallel.coordinator.reset(laneZero());
  // A clear while catching up: what the file still owed is from before the
  // clear, so it is not read, and the numbering starts again from the next
  // live frame rather than calling the cleared part a hole. The agent's
  // files go on, and where they were read is kept for the next hole.
  if (catchUp.active) {
    stopCatchUp();
    flow.startCapture();
    router.clear();
  }
  ordering.clear();
  // Cleared frames will never be dissected, so main is told it is owed
  // nothing for them; the next flush sends the ids.
  released = [];
  releasedFrom = 0;
  flow.abandonBatches();
  flow.forgetRenderer();
  sequencer = new Sequencer();
  tcpTracker = new TcpStreamTracker(sequencer);
  icmpTracker = new IcmpEchoTracker();
  quicTracker = new QuicFlowTracker();
  dnsTracker = new DnsTracker();
  l3Tracker = new L3Tracker(sequencer);
  recorder = makeRecorder();
  // The facts, but not the identity. Clearing the buffer discards what this
  // capture observed; it does not make the machine a different machine, and
  // re-deriving the adapter's own MAC would mean every frame after a clear
  // read as unknown until the agent next spoke.
  networkFacts.reset();
  duplicates.reset();
  treeCache.clear();
  revisitedTrees.clear();
  derivedStore.clear();
  clearPendingRows();
  pendingIcmpReplies = [];
  pendingInfoPatches = [];
  // Rows of the capture before this one may still be half read at either end.
  windowSender.reset();
  storeSender.reset();
  capturedSinceReset = false;
  pendingRecords = [];
  // A restored session hands back the capture it is continuing (`resumeLive`).
  frameClock().resumeLive(startUs ?? null, lastUs ?? null);
  arrivalSeq = 0;
  nextId = startId;
  bytesSentFrom = bytesSentThrough = -1;
}

// --- dissection --------------------------------------------------------------

/**
 * The adapter a frame came from, by the index the agent gave it.
 *
 * Undefined when nothing matches, rather than the first adapter. The list this
 * searches is the *capturable* one - App.tsx filters it before sending it here
 * - while the agent indexes into the unfiltered one, so a mismatch is
 * reachable rather than theoretical, and falling back to `interfaces[0]`
 * labelled the frame with a confident, wrong adapter name in the Frame layer
 * and the interface column. Same rule as the drop counters and process
 * attribution: an unknown is not a zero, and is never rendered as one.
 */
/**
 * Prebuilt, and rebuilt only when the list changes.
 *
 * This is read once per captured frame. As a `find` with a closure it was a
 * linear scan of the adapter list per frame, and it allocated a fresh
 * `{name, label}` per frame for the dissector to read once and drop - at tens
 * of thousands of frames a second, for a list that changes when the user picks
 * an adapter. The objects in this map are shared and live as long as the list.
 */
let interfaceById = new Map<number, { name: string; label: string }>();

/**
 * Each adapter's link type, by the same key.
 *
 * A second map rather than a third property on the one above, because that
 * object is handed to the dissector as its `captureInterface` and is compared
 * by identity - widening it would put a number nobody reads into every
 * frame's Frame layer. Only adapters the agent actually named a type for are
 * in here; a miss means Ethernet, which is `decodeRawEthernetPacket`'s own
 * default.
 */
let linkTypeById = new Map<number, number>();

/**
 * How many decimals of a second each adapter's stamps carry - 9 where the
 * agent's driver gave nanoseconds, 6 where it gave microseconds. A miss is 6,
 * which is what every live frame was until the agent could say.
 */
let tsPrecisionById = new Map<number, number>();

/**
 * The same records, keyed by the label a frame carries - see
 * `interfacesByLabel`, which holds the `eth0` trap this must not walk into.
 */
let interfaceByLabel = new Map<string, { name: string; label: string }>();

function rebuildInterfaceIndex(): void {
  interfaceById = new Map(
    // `entry.id ?? index` is the agent's own indexing rule, kept exactly: the
    // list this searches is the *capturable* one and the agent indexes into
    // the unfiltered one, so the fallback is load-bearing.
    interfaces.map((entry, index) => [
      entry.id ?? index, { name: entry.name, label: entry.label },
    ]),
  );
  linkTypeById = new Map(
    interfaces
      .map((entry, index) => [entry.id ?? index, entry.linkType] as const)
      .filter((pair): pair is readonly [number, number] => pair[1] !== undefined),
  );
  tsPrecisionById = new Map(
    interfaces
      .map((entry, index) => [entry.id ?? index, entry.tsPrecision] as const)
      .filter((pair): pair is readonly [number, number] => pair[1] !== undefined),
  );
  // Built from the same objects as `interfaceById`, so a replayed frame and a
  // live one are handed the identical record rather than two equal ones.
  interfaceByLabel = interfacesByLabel([...interfaceById.values()]);
}

/**
 * The adapter a replayed frame says it came off, if this list still has it.
 *
 * `undefined` for an imported file, for the `eth0` fallback, and for an
 * adapter that has gone away since the frame was captured - all three of which
 * are honestly "no adapter" rather than a guess, which is the rule the drop
 * counters and process attribution follow.
 */
function interfaceByFrameLabel(label: string): { name: string; label: string } | undefined {
  return interfaceByLabel.get(label);
}

function interfaceFor(iface: number): { name: string; label: string } | undefined {
  return interfaceById.get(iface);
}

/**
 * How to read this adapter's frames.
 *
 * **Ethernet when the agent did not say**, which is what this whole path
 * assumed before the agent could say anything - right for every adapter here
 * except Npcap's loopback, which is `LINKTYPE.NULL` and was being read as
 * Ethernet: fabricated MACs with vendors resolved from them, a direction
 * decided from those MACs, and no transport layer at all.
 */
function linkTypeFor(iface: number): number {
  return linkTypeById.get(iface) ?? LINKTYPE.ETHERNET;
}

function ingest(frame: LiveFrame, id: number): void {
  try {
    // Clamped at zero and kept to the nanosecond (`FrameClock.fromLive`).
    const { relativeTime, timeDelta } = sequencer.clock.fromLive(frame.tsUs, frame.tsNsRem);

    const precision = tsPrecisionById.get(frame.iface) ?? 6;
    recorder.begin();
    const src = recorder.sources;
    const decoded = withDissectEnv(src.env, () => decodeRawEthernetPacket(
      frame.bytes, id, frame.tsUs, relativeTime, timeDelta, frame.origLen,
      src.tcp, src.icmp, src.quic, src.dns, interfaceFor(frame.iface),
      linkTypeFor(frame.iface), src.l3, host,
      { nanosRemainder: precision > 6 ? frame.tsNsRem : undefined },
    ));
    // Only for a frame that dissected: one that threw has no record to trust,
    // and its tree is built the old way.
    pendingRecords.push({ id, record: recorder.end() });
    const derived = recorder.endDerived();
    if (derived !== null) derivedStore.set(id, derived);
    const packet = decoded.packet;
    packet.tsPrecision = precision;
    // The exact stamp, as an import carries one, only where there is more of
    // it than `tsUs` already says.
    if (precision > 6) packet.tsNanos = BigInt(frame.tsUs) * 1000n + BigInt(frame.tsNsRem);

    // The tree stays here; only its bytes and its summary go up. Carrying it
    // would be 91% of the cost of crossing the boundary and 89% of the buffer's
    // memory, for something one frame at a time is ever looked at
    // (docs/decisions/0007).
    // Which program opened the socket this frame belongs to, if the agent has
    // been asked and the answer is knowable. Applied here rather than inside
    // `decodeRawEthernetPacket` because that function is the wire, shared with
    // every imported file, and a process name is not something a file can
    // contain - it is a fact about the machine the capture was taken on.
    //
    // Before the tree is cached, because it adds a row to it.
    annotatePacket(packet, flowAnnotations);
    // The first frame after a hole in the live stream says so, and says the
    // frames are in the capture file (`liveGapFields.ts`). Before the tree is
    // cached, for the same reason as the process row.
    if (frame.holeBefore !== undefined) markLiveGap(packet, frame.holeBefore);

    // After attribution, because it is attribution that makes a hello a
    // labelled example. A frame the OS named teaches this store; one it could
    // not is what the teaching is for.
    learnOrLabelFingerprint(packet.fields, clientFingerprints, packet.layers);

    // What this frame reveals about the network it crossed: the resolver that
    // was really asked, the router that really advertised, the MAC that really
    // forwards. Read off a frame that was going to be dissected anyway, so it
    // costs comparisons rather than work, and posted only when it changes.
    networkFacts.observe(packet, host);

    cacheTree(id, packet.layers);
    packet.layers = [];

    queueRow(packet);
    if (decoded.icmpMatchedRequestFrameId !== undefined) {
      pendingIcmpReplies.push({ requestFrameId: decoded.icmpMatchedRequestFrameId, replyId: id });
    }
    if (decoded.infoPatches) {
      pendingInfoPatches.push(...decoded.infoPatches);
      // A tree still cached here was built before this frame knew anything, so
      // it gains the same rows the stored row does - or a frame opened soon
      // after its answer would lack the link it gains once it leaves the cache.
      for (const patch of decoded.infoPatches) {
        const cached = treeCache.get(patch.frameId);
        if (cached !== undefined && (patch.links !== undefined || patch.responseInFrame !== undefined)) {
          applyInfoPatch({ layers: cached, info: '', fields: {} } as unknown as Packet, { ...patch, suffix: undefined });
        }
      }
    }
  } catch (err) {
    post({ type: 'failure', message: `failed to dissect a captured frame: ${String(err)}` });
  }
}

// --- rebuilding a tree from its record (ADR 0049) ----------------------------

type RevisitKit = Extract<FromCapture, { type: 'revisitKit' }>;

/**
 * How long a revisit waits for the store before building the tree the old way.
 * The store answers in milliseconds; this is for a store that died, so the
 * detail pane falls back rather than waiting for ever.
 */
const KIT_TIMEOUT_MS = 5000;
/** Rebuilt trees kept, for a frame looked at twice. Arrival's cache is separate. */
const REVISITED_TREES = 64;

const kitWaiters = new Map<number, (kit: RevisitKit | null) => void>();
let nextKitRequest = 1;
const revisitedTrees = new Map<number, ProtocolLayer[]>();

function requestKit(id: number): Promise<RevisitKit | null> {
  if (storePort === null) return Promise.resolve(null);
  const requestId = nextKitRequest++;
  const port = storePort;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      kitWaiters.delete(requestId);
      resolve(null);
    }, KIT_TIMEOUT_MS);
    kitWaiters.set(requestId, (kit) => {
      clearTimeout(timer);
      resolve(kit);
    });
    port.postMessage({ type: 'revisitKit', requestId, id });
  });
}

/** The process a stored row was attributed to at arrival, as `annotatePacket` wrote it. */
function processOfRow(row: Packet): ProcessInfo | null {
  const name = row.fields?.['inwire.process.name'];
  const pid = row.fields?.['inwire.process.pid'];
  if (typeof name !== 'string' || typeof pid !== 'number') return null;
  const exe = row.fields?.['inwire.process.path'];
  return { name, pid, exe: typeof exe === 'string' ? exe : '' };
}

/**
 * One frame's tree, from the store's kit: its bytes, its row and its record,
 * plus the bytes of the frames its record names. Null when the frame has no
 * record or the record cannot give the tree back - the caller then replays.
 */
async function revisitFromStore(id: number): Promise<ProtocolLayer[] | null> {
  const kit = await requestKit(id);
  if (kit === null || kit.record === null || kit.row === null) return null;
  const bytes = new Map(kit.frames);
  const own = bytes.get(id);
  if (own === undefined) return null;
  const row = kit.row;
  try {
    const again = new FrameRevisit(kit.record, (frame) => bytes.get(frame), derivedStore.get(id));
    const rs = again.sources;
    const { packet } = withDissectEnv(rs.env, () => decodeRawEthernetPacket(
      own, id, row.tsUs, row.relativeTime, row.timeDelta, row.length,
      rs.tcp, rs.icmp, rs.quic, rs.dns, interfaceByFrameLabel(row.interfaceName),
      row.linkType ?? LINKTYPE.ETHERNET, rs.l3, host,
      // The stored row keeps the nanoseconds (`chunkCodec.ts`), so a revisit
      // draws the same arrival times arrival did.
      { nanosRemainder: row.tsNanos !== undefined ? Number(row.tsNanos % 1000n) : undefined },
    ));
    again.finish();
    // What LATER frames wrote into this one's tree, carried on the row.
    const links = treeLinksOf((abbrev) => row.fields?.[abbrev]);
    if (links !== undefined) applyInfoPatch(packet, { frameId: id, links });
    addProcessRow(packet.layers, processOfRow(row));
    addLiveGapRow(packet.layers, row.fields?.['inwire.live.skipped']);
    revisitedTrees.set(id, packet.layers);
    while (revisitedTrees.size > REVISITED_TREES) {
      const oldest = revisitedTrees.keys().next();
      if (oldest.done) break;
      revisitedTrees.delete(oldest.value);
    }
    return packet.layers;
  } catch (error) {
    if (!(error instanceof RecordMiss)) {
      post({ type: 'failure', message: `failed to rebuild frame ${id} from its record: ${String(error)}` });
    }
    return null;
  }
}

function flush(): void {
  flushSoon = false;
  // Frames leave the ordering window in capture order and are dissected right
  // here, so the trackers see them in the order the wire did. Stopping
  // releases whatever is still held rather than stranding it.
  const fresh = capturing ? ordering.drain(performance.now()) : ordering.flush();
  for (const frame of fresh) released.push(frame);

  // **The store's backlog is a reason to stop releasing** (ADR 0053): past
  // its budget, frames wait here - bounded, because main stops posting to a
  // Worker that has not answered for them - rather than in the store's inbound
  // queue, which nothing bounded and which a real burst grew to its 2 GB heap
  // guard. A stopped capture releases everything regardless: the stop path is
  // waiting for its last rows.
  let take = 0;
  if (!capturing) take = released.length - releasedFrom;
  else if (!downstreamBehind()) {
    take = Math.min(released.length - releasedFrom, Math.max(256, Math.floor((SLICE_MS * 1000) / usPerFrame)));
    // With shards, what is in flight on them is the queue to bound: past it
    // frames wait here, and each answer that brings it down asks for a flush.
    if (parallel !== null) take = Math.max(0, Math.min(take, PARALLEL_BACKLOG - parallel.coordinator.backlog));
  }
  const ready = released.slice(releasedFrom, releasedFrom + take);
  releasedFrom += take;
  if (releasedFrom === released.length) {
    released = [];
    releasedFrom = 0;
  } else if (releasedFrom > 65_536) {
    released = released.slice(releasedFrom);
    releasedFrom = 0;
  }
  // More waiting and the store not in the way: straight back for it, after
  // whatever messages queued behind this slice.
  // With shards full, it is their answers that come back for it (`afterMerge`).
  if (releasedFrom < released.length && !downstreamBehind() && !flushSoon && !(parallel !== null && take === 0)) {
    flushSoon = true;
    setTimeout(flush, 0);
  }

  // **Ids first, then bytes to disk, then dissection - in that order, for the
  // whole group.** ADR 0038.
  //
  // The id has to come first because it is what addresses the frame on disk,
  // and it is assigned here rather than inside `ingest` so that the bytes can
  // go before any dissection runs. Doing it per frame inside the loop would
  // put each frame's write behind the previous frame's dissection, which is
  // the coupling this removes.
  //
  // What it buys, concretely: a frame whose dissection throws still reaches
  // disk. Before this, `ingest`'s catch reported the failure and the frame was
  // gone - not counted anywhere, not on disk, not in the list.
  const assigned = ready.map((frame) => ({ frame, id: nextId++ }));
  if (storePort !== null && assigned.length > 0) {
    if (!capturing && !capturedSinceReset && bytesPostedWhileIdle === 0) {
      // Said once, and said at all. A counter nobody reads is the same silence
      // it was written to break; the store drops these, so if this ever fires
      // it is frames lost at the start of a capture and somebody has to know.
      post({
        type: 'failure',
        message: 'frames reached the store before a capture was open - '
          + 'some may not have been written',
      });
    }
    if (!capturing && !capturedSinceReset) bytesPostedWhileIdle += assigned.length;
    const first = assigned[0].id;
    if (first !== bytesSentThrough + 1 || bytesSentFrom < 0) bytesSentFrom = first;
    bytesSentThrough = assigned[assigned.length - 1].id;
    storePort.postMessage({
      type: 'appendBytes',
      slab: packFrames(assigned.map(({ frame, id }) => (frame.ring === undefined
        ? { id, tsUs: frame.tsUs, bytes: frame.bytes }
        : { id, tsUs: frame.tsUs, bytes: frame.bytes, ring: frame.ring }))),
      // Answered with `bytesTaken`; the unanswered count is the store's backlog.
      ack: flow.storeSent(assigned.length),
    });
  }

  const sliceStart = performance.now();
  if (parallel !== null) {
    // On several cores (ADR 0053 phase 3): numbered here in frame order, then
    // TCP to the shards and the rest dissected on this thread. Every frame
    // comes back through `emitMerged`, in order - this flush's lane-0 frames
    // before this returns, the shards' as they answer.
    const clock = parallel.coordinator.clock;
    parallel.coordinator.dispatch(assigned.map(({ frame, id }) => {
      const { relativeTime, timeDelta } = clock.fromLive(frame.tsUs, frame.tsNsRem);
      const precision = tsPrecisionById.get(frame.iface) ?? 6;
      return {
        id, bytes: frame.bytes, tsUs: frame.tsUs, relativeTime, timeDelta, origLen: frame.origLen,
        linktype: linkTypeFor(frame.iface), iface: frame.iface,
        facts: { nanosRemainder: precision > 6 ? frame.tsNsRem : undefined, holeBefore: frame.holeBefore },
        meta: frame,
      };
    }));
  } else {
    for (const { frame, id } of assigned) {
      ingest(frame, id);
      flow.frameDone(frame.batch);
    }
  }
  if (assigned.length >= 64) {
    const measured = ((performance.now() - sliceStart) * 1000) / assigned.length;
    usPerFrame = usPerFrame * 0.7 + measured * 0.3;
  }
  postFlushed();
  // Room for more of the file, if catching up.
  pumpCatchUp();
}

/**
 * Everything dissected since the last call, posted: main's credit, the
 * records to the store, the rows to the app. The end of every flush, and -
 * with shards - of every answer from one.
 */
function postFlushed(): void {
  // Main's credit for every batch whose last frame is now dissected.
  const drained = flow.takeCompleted();
  if (drained.length > 0) tellAgent({ type: 'drained', batches: drained });

  // The group's records, after its bytes and in the same flush - so no chunk
  // can seal between a frame's bytes and its record.
  //
  // **Copied, never transferred.** The other end of this port is a
  // `MessagePortMain` in the store's utility process, and a message whose
  // transfer list holds an ArrayBuffer does not arrive there - no error on
  // either side, just nothing. That is how every live capture wrote zero
  // records while every import, whose records go through the renderer's port
  // without a transfer list, wrote all of them. A record is tens to hundreds of
  // bytes; the copy costs nothing. `scripts/electron/live-revisit-drive.ts`.
  if (storePort !== null && pendingRecords.length > 0) {
    storePort.postMessage({ type: 'appendRecords', frames: pendingRecords });
  }
  pendingRecords = [];

  // Frames the same capture saw twice, on two adapters. Done over the batch
  // rather than per frame because a duplicate is a relationship BETWEEN
  // frames, and the two copies routinely land in one flush.
  if (interfaces.length > 1 && pendingPackets.length > 0) {
    // Whole, because the coordinator decodes every row with more than one
    // interface. A stub here means the interfaces changed under rows already
    // merged; they are left out of the scan, and said so.
    const whole = pendingPackets.filter(isWholePacket);
    if (whole.length !== pendingPackets.length) {
      post({ type: 'failure', message: 'duplicate frames were not looked for in some rows: the adapters changed while they were being dissected' });
    }
    for (const mark of duplicates.scan(whole)) {
      pendingInfoPatches.push({ frameId: mark.frameId, suffix: duplicateSuffix(mark) });
    }
  }

  // Before the early return below, and deliberately: a capture can learn
  // something about the network in a flush that produced no frames the app
  // wants - and more importantly, the facts must not be held hostage to
  // there being packets pending.
  if (networkFacts.takeChanged()) {
    post({ type: 'networkFacts', facts: networkFacts.snapshot() });
  }

  if (pendingPackets.length === 0 && pendingIcmpReplies.length === 0 && pendingInfoPatches.length === 0) {
    return;
  }
  const packets = pendingPackets;
  const refs = pendingRefs;
  const overlays = pendingOverlays;
  const icmpReplies = pendingIcmpReplies;
  const infoPatches = pendingInfoPatches;
  clearPendingRows();
  pendingIcmpReplies = [];
  pendingInfoPatches = [];

  // The frames' bytes reach the window as ONE slab per flush: `seal` copies
  // every row's bytes into a single exactly-sized buffer, and that buffer alone
  // is transferred. Nothing about a frame's own buffer matters any more - a
  // view into an agent batch, a restored or fallback packet - so no frame is
  // detached and the trackers' `.slice()` rule guards only the slab's reader.
  // An object row's own `rawBytes` is swapped for the empty view before the
  // post, below, because its bytes travel in the slab.

  // **The rows and their patches go to the store from here, not from the
  // window.** They used to cross to the renderer's main thread and be cloned
  // again from there on its own port - a fifth of that thread at 60,000 frames
  // a second, the largest single thing on it, measured. This Worker has the
  // same objects in hand: no `FieldBlock` yet (the window adds that), so the
  // graph cloned here is the one `plainForStore` copied there, bytes and all,
  // and the writer's one question - do I have a slot? - answers as before.
  // Behind this group's bytes on the same port, so a row never overtakes its
  // slot; before the window's post below, which empties the objects' bytes.
  //
  // **And the bytes stay behind.** The store wrote each of these frames' bytes
  // when this Worker posted them, a flush ago; cloning them again cost 30% of
  // a row's clone, and the store then held a second copy of every staged frame
  // for its whole patch horizon. A row whose id is in the run this Worker sent
  // goes as a row and nothing else (`bytesSent`); any other - an agent's
  // metadata-only frame - carries its bytes, as the window's always did.
  //
  // **A shard's rows go on as the pack the shard made** (`rowPack.ts`), to the
  // window and, separately, to the store; both get the same order, so the
  // store's digest, which drops an id at or below the last it folded, sees
  // rows as it always did. The window's copy of each pack is cloned, never
  // moved: a later flush, or a store port that arrives mid-capture, may need a
  // pack this flush already sent.
  const stored = storePort !== null;
  const windowRows = new PackedFlush();
  const storeRows = storePort !== null ? new PackedFlush() : null;
  // Every row, when none went as a pack; then `postRows` sends them whole. Also
  // the object rows of a packed flush: their bytes ride in each flush's slab.
  const storeObjects: Packet[] = [];
  const wholeRows: Packet[] = [];
  let storePacked = false;
  for (let i = 0; i < packets.length; i++) {
    const packet = packets[i];
    const ref = refs[i];
    if (ref === null) {
      const whole = wholeRow(packet);
      wholeRows.push(whole);
      windowRows.object(whole, whole.rawBytes);
      if (storeRows !== null) {
        storeRows.object(whole, inSentRun(whole) ? null : whole.rawBytes);
        storeObjects.push(whole);
      }
      continue;
    }
    windowRows.packed(ref.pack, ref.index, packet.rawBytes, overlays[i]);
    if (storeRows !== null) {
      storeRows.packed(ref.pack, ref.index, inSentRun(packet) ? null : packet.rawBytes, overlays[i]);
      storePacked = true;
    }
  }
  if (storePort !== null) {
    if (storeRows !== null && storePacked) {
      // Before `postPackedRows` swaps any bytes out: `inSentRun` reads their length.
      postPackedRows(storePort, storeRows, Uint8Array.from(packets, (p) => (inSentRun(p) ? 1 : 0)), storeObjects);
    } else if (wholeRows.length > 0) postRows(storePort, wholeRows);
    if (infoPatches.length > 0) storePort.postMessage({ type: 'patches', patches: infoPatches });
  }

  const rows = windowSender.seal(windowRows);
  // Their bytes are in the slab now, and nothing reads a row's own after this
  // line (the store's posts are done): left empty, not restored - every row,
  // packed ones too, as the per-frame transfer used to detach them, so no
  // row the Worker still holds keeps a batch of bytes alive.
  for (const packet of packets) packet.rawBytes = NO_ROW_BYTES;
  post({
    type: 'frames', rows, icmpReplies, infoPatches, lateCount: ordering.lateCount, stored,
  }, [rows.bytes.buffer as ArrayBuffer]);
  // Owed until the app says it committed them (`rowsTaken`).
  flow.rowsPosted(packets.length);
  lastPostedAt = performance.now();
}

/** An empty view, for a row whose bytes stay behind; never detached, never written. */
const NO_ROW_BYTES = new Uint8Array(0);

/** Whether this Worker already posted the row's bytes to the store, so the row travels without them. */
function inSentRun(packet: RowStub): boolean {
  return packet.id >= bytesSentFrom && packet.id <= bytesSentThrough && packet.rawBytes.byteLength > 0;
}

/**
 * A flush that holds packed rows, to the store as one message in merged order.
 * `sent` says, row by row, which rows' bytes went ahead (`inSentRun`) - the
 * store cannot tell from an empty `rawBytes`, which an agent's metadata-only
 * frame also has. A packed row in the run was sealed with no bytes. Every
 * object row (`objects`: all of the flush's) has
 * its `rawBytes` swapped out for the synchronous clone, as `postRows` does:
 * its bytes, where the store needs them, ride in the flush's slab.
 */
function postPackedRows(port: MessagePort, flush: PackedFlush, sent: Uint8Array, objects: readonly Packet[]): void {
  const bytes = objects.map((packet) => packet.rawBytes);
  for (const packet of objects) packet.rawBytes = NO_ROW_BYTES;
  try {
    port.postMessage({ type: 'appendPacked', rows: storeSender.seal(flush), sent });
  } finally {
    for (let i = 0; i < objects.length; i++) objects[i].rawBytes = bytes[i];
  }
}

/**
 * A flush's rows to the store: those whose bytes went out on this port as rows
 * alone, the rest with their bytes. The clone is synchronous, so each row's
 * `rawBytes` is swapped out for the length of the `postMessage` and put back -
 * the packets go on to the window with theirs, and no copy of 25 fields is made
 * per frame to leave one out.
 */
function postRows(port: MessagePort, packets: readonly Packet[]): void {
  const rows: Packet[] = [];
  const withBytes: Packet[] = [];
  for (const packet of packets) {
    if (inSentRun(packet)) rows.push(packet);
    else withBytes.push(packet);
  }
  if (rows.length > 0) {
    const bytes = rows.map((packet) => packet.rawBytes);
    for (const packet of rows) packet.rawBytes = NO_ROW_BYTES;
    try {
      port.postMessage({ type: 'append', packets: rows, bytesSent: true });
    } finally {
      for (let i = 0; i < rows.length; i++) rows[i].rawBytes = bytes[i];
    }
  }
  if (withBytes.length > 0) port.postMessage({ type: 'append', packets: withBytes });
}

/**
 * Drains whose answer waits for the store, by the ack of the empty append
 * that is their barrier.
 *
 * **Stop seals the capture with a `finish` on the app's port, and the last
 * rows now travel on this Worker's.** Nothing orders two ports into one
 * process against each other - which is why the rows used to be sent on the
 * app's port, "ahead of the finish". So the drain is answered only once the
 * store has answered an append posted behind everything this Worker sent it:
 * every byte, record, row and patch of the tail has been read by then, and
 * the finish the app sends next cannot overtake any of them. The records had
 * leaned on two ports arriving in order before this; now nothing does.
 */
const drainBarriers = new Map<number, number>();
/** How long a drain waits for a store that does not answer, before answering anyway. */
const DRAIN_BARRIER_MS = 5_000;

function answerDrain(requestId: number): void {
  if (storePort === null) {
    post({ type: 'drained', requestId });
    return;
  }
  const ack = flow.storeSent(0);
  drainBarriers.set(ack, requestId);
  storePort.postMessage({ type: 'appendBytes', slab: packFrames([]), ack });
  // A store that died answers nothing, and Stop must still end: the app's own
  // port is what reports that store's death.
  setTimeout(() => {
    if (drainBarriers.delete(ack)) post({ type: 'drained', requestId });
  }, DRAIN_BARRIER_MS);
}

// Started at the bottom of this file, in the pipeline role only.

// --- the agent link ----------------------------------------------------------
//
// Main owns the pipe and the retry timer; this end owns what the messages
// mean. The four cases below are exactly what `ws.onmessage` and the socket's
// own events used to deliver, which is why everything downstream of them is
// unchanged.

function tellAgent(message: ToAgentLink): void {
  agentPort?.postMessage(message);
}

function receiveFromAgent(message: FromAgentLink): void {
  switch (message.type) {
    case 'status':
      // Main is the authority on this now. It reports the same four states the
      // socket's `onopen`/`onerror`/`onclose` did, so everything that renders
      // the connection status is unchanged.
      post({ type: 'status', status: message.status });
      return;
    case 'service':
      post({
        type: 'agentService',
        facts: message.facts,
        shortConnections: message.shortConnections,
      });
      return;
    case 'binary':
      receiveBatch(message.bytes, message.batch);
      return;
    case 'shed':
      // Caught up from the capture file where there is one; counted and
      // marked on the next frame where there is not.
      if (capturing) {
        router.shed(message.firstSeq, message.frames);
        pumpCatchUp();
      }
      return;
    case 'capturedBytes':
      receiveCaptured(message);
      return;
    case 'backlog': {
      // Main counts what this Worker owes it; the skipped frames are counted
      // here, from the agent's numbering, because only the frames say where
      // the stream had holes. Forwarded once a second, as main sends it.
      //
      // While catching up, how far behind is the file's to say: the frames
      // between where it has read to and the newest live one, and the capture
      // time between them. Main's count is only what it has posted.
      const behind = catchUp.status();
      post({
        type: 'liveLag',
        behindFrames: catchUp.active ? behind.toGo : message.backlog.frames,
        behindMs: catchUp.active ? behind.behindMs : message.backlog.oldestMs,
        skippedFrames: flow.skippedFrames,
        shedding: message.backlog.shedding,
        storeBehind: flow.storeBehind,
        catchingUp: catchUp.active,
      });
      return;
    }
    case 'text':
      receiveControl(message.text);
      return;
  }
}

/**
 * The batch's bytes as an `ArrayBuffer`, copying only if it has to.
 *
 * A structured clone of an exactly-sized `Uint8Array` produces another one, so
 * the fast path is the one that always runs; the copy is there because
 * `decodePacketBatch` takes a buffer and a view into a larger one would decode
 * from the wrong offset in silence.
 */
function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? (bytes.buffer as ArrayBuffer)
    : (bytes.slice().buffer as ArrayBuffer);
}

function receiveBatch(bytes: Uint8Array, batch: number | undefined): void {
  // A batch that will never be dissected is answered for now, or main would
  // count it as owed for ever and stop posting.
  if (!capturing) { flow.batchDropped(batch); return; } // agent detected, capture not started
  const buffer = asArrayBuffer(bytes);
  let frames;
  try {
    frames = isPacketBatch(buffer) ? decodePacketBatch(buffer) : null;
  } catch (err) {
    flow.batchDropped(batch);
    post({ type: 'failure', message: String(err) });
    return;
  }
  if (!frames) { flow.batchDropped(batch); return; }
  flow.batchArrived(batch, frames.length);
  const arrivedAt = performance.now();
  for (const frame of frames) {
    // Not dissected here: frames wait in the ordering window and are dissected
    // by the flush, in capture order - unless the stream skipped and the view
    // is catching up from the file, which has these (`catchUp.ts`). `retain`
    // copies the bytes out of the batch, which one held frame would otherwise
    // keep alive in full.
    lastLiveIface = frame.iface;
    router.arrive({
      tsUs: frame.tsUs,
      tsNsRem: frame.tsNsRem,
      seq: frame.seq,
      arrivedAt,
      bytes: retain(frame),
      origLen: frame.origLen,
      iface: frame.iface,
      ring: ringFiling.partOf(frame.seq),
      batch,
    });
  }
  pumpCatchUp();
}

function receiveControl(text: string): void {
  const message = parseAgentMessage(text);
  if (!message) return;

  if (message.type === 'socket_table') {
    // Applied here because this is where dissection happens, so every frame
    // from now on is annotated as it is built. It is forwarded as well: the
    // main thread keeps its own copy of the store to re-annotate frames that
    // were already dissected before this table arrived - the same split
    // `keyLog` has, for the same reason. The shards get it too, ahead of any
    // frame dispatched after this point.
    const nowUs = Date.now() * 1000;
    flowAnnotations.apply(message, nowUs);
    lastFlows = { type: 'flows', table: message, nowUs };
    parallel?.coordinator.broadcast(lastFlows);
    post({ type: 'agent', message });
    return;
  }

  // The ring's two facts the store needs, taken here because here is where
  // frames are filed (ADR 0052). Both are passed on to the app as well.
  if (message.type === 'capture_boundary') {
    ringFiling.boundary(message.index, message.firstSeq);
    captureFiles.boundary(message.index, message.firstSeq);
  }
  if (message.type === 'capture_file') captureFiles.file(message.index, message.name, message.state, message.firstSeq);
  if (message.type === 'capture_file' && message.state === 'deleted' && message.lastSeq !== null) {
    storePort?.postMessage({ type: 'ringDeleted', epoch: ringFiling.epoch, lastSeq: message.lastSeq });
  }

  if (message.type !== 'packet') {
    post({ type: 'agent', message });
    return;
  }

  // A pre-3.2 agent, which still sends one JSON message per frame. Kept
  // working so an agent that has not been updated yet streams while it nags,
  // rather than showing an empty list next to an "Update" pill.
  if (!capturing) return;
  const raw = message as unknown as Record<string, unknown>;
  const tsUs = typeof raw.tsUs === 'number'
    ? raw.tsUs
    : typeof raw.timestamp === 'number' ? Math.round(raw.timestamp * 1000) : Date.now() * 1000;
  const bytes = typeof raw.raw === 'string' && raw.raw.length > 0 ? base64Bytes(raw.raw) : null;
  if (bytes) {
    ordering.push({
      tsUs,
      tsNsRem: 0,
      seq: typeof raw.seq === 'number' ? raw.seq : arrivalSeq++,
      arrivedAt: performance.now(),
      bytes,
      origLen: typeof raw.origLen === 'number' ? raw.origLen : bytes.length,
      iface: typeof raw.iface === 'number' ? raw.iface : 0,
    });
  } else {
    // Metadata only, from an agent that sent no bytes. Nothing is fabricated:
    // the frame is what the agent said it was and no more.
    queueRow(buildFallbackPacket({
      id: nextId++,
      tsUs,
      relativeTime: frameClock().liveStartUs === null ? 0 : (tsUs - frameClock().liveStartUs!) / 1_000_000,
      timeDelta: 0,
      length: Number(raw.length) || 0,
      source: String(raw.source ?? ''),
      destination: String(raw.destination ?? ''),
      sourcePort: raw.sourcePort as number | undefined,
      destPort: raw.destPort as number | undefined,
      protocol: raw.protocol as string | undefined,
      info: raw.info as string | undefined,
    }));
  }
}

function base64Bytes(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

// --- commands from the main thread -------------------------------------------

function handleCommand(event: MessageEvent<ToPipeline>): void {
  const command = event.data;
  switch (command.type) {
    case 'agentPort': {
      const [port] = event.ports;
      if (!port) break;
      agentPort = port;
      port.onmessage = (message: MessageEvent<FromAgentLink>) => receiveFromAgent(message.data);
      // A transferred port delivers nothing until it is started. Assigning
      // `onmessage` starts it implicitly, but saying so costs one line and the
      // failure it prevents is a Worker that connects and never hears back.
      port.start();
      // `connect` may have arrived first - it is sent in the same tick, and
      // the port is not - so the wish is honoured now rather than lost.
      if (wantConnection) tellAgent({ type: 'open' });
      break;
    }

    case 'storePort': {
      const [port] = event.ports;
      if (!port) break;
      storePort = port;
      bytesSentFrom = bytesSentThrough = -1;
      // A new store has been sent no pack, and its reader holds none.
      storeSender.reset();
      // Frames and records go out on it; the one thing that comes back is a
      // revisit kit this Worker asked for (ADR 0049). Everything else the store
      // says goes to the app's own port - `entry.ts` keeps them apart.
      // A new store owes nothing on the old one's ledger.
      flow.forgetStore();
      port.onmessage = (message: MessageEvent<FromCapture>) => {
        // The store has taken an append: its backlog shrinks, and a flush
        // the backlog was holding can go.
        if (message.data?.type === 'bytesTaken') {
          const drainRequest = drainBarriers.get(message.data.ack);
          if (drainRequest !== undefined) {
            drainBarriers.delete(message.data.ack);
            post({ type: 'drained', requestId: drainRequest });
          }
          const wasBehind = downstreamBehind();
          flow.storeTaken(message.data.ack);
          resumeIfHeld(wasBehind);
          return;
        }
        if (message.data?.type !== 'revisitKit') return;
        const waiter = kitWaiters.get(message.data.requestId);
        kitWaiters.delete(message.data.requestId);
        waiter?.(message.data);
      };
      port.start();
      break;
    }

    case 'connect':
      wantConnection = true;
      // Nothing to do if the port is still in flight; its arrival above
      // catches up. Said here rather than queued, because a queue for one
      // possible message is a queue nobody will remember to drain.
      if (agentPort) tellAgent({ type: 'open' });
      break;

    case 'disconnect':
      wantConnection = false;
      tellAgent({ type: 'close' });
      post({ type: 'status', status: 'disconnected' });
      break;

    case 'command':
      // The capture's id is what its pcapng is read back under, to catch up.
      if (command.command.type === 'start_capture') {
        captureId = command.command.captureId ?? null;
        router.enable(captureId !== null);
      }
      // Dropped if the link is not up, exactly as a closed socket dropped it.
      // Main knows whether the pipe is writable; this end does not need to.
      tellAgent({ type: 'send', text: encodeAgentCommand(command.command) });
      break;

    case 'startAgentService':
      // Not an agent command - the agent is by definition not there to receive
      // one. This asks MAIN to raise a UAC prompt.
      tellAgent({ type: 'startService' });
      break;

    case 'capturing':
      // A capture starting is a new run of the agent's numbering.
      if (command.capturing && !capturing) {
        flow.startCapture();
        router.reset();
      }
      if (!command.capturing && capturing) stopCatchUp();
      capturing = command.capturing;
      if (capturing) capturedSinceReset = true;
      break;

    case 'drain':
      // Everything held goes now, in the order a flush sends it - bytes and
      // records to the store, then the rows up - and only then the answer, so
      // the app has the last rows in hand when it seals the capture.
      //
      // A catch-up stops with the capture: what it had not read yet is
      // counted as skipped, marked, and in the file.
      stopCatchUp();
      capturing = false;
      flush();
      if (parallel === null) {
        answerDrain(command.requestId);
        break;
      }
      // With shards, the last frames are still on them: the answer waits
      // until every one has been merged and posted.
      {
        const requestId = command.requestId;
        parallel.coordinator.whenIdle(() => {
          postFlushed();
          answerDrain(requestId);
        });
      }
      break;

    case 'rowsTaken': {
      const wasBehind = downstreamBehind();
      flow.rowsTaken(command.count);
      resumeIfHeld(wasBehind);
      break;
    }

    case 'threads':
      // Applied at the next reset - the start of the next capture - so a
      // capture is never dissected half one way and half the other. Or now,
      // when nothing has been dissected since the last one: the setting
      // arrives once at launch, before any capture.
      threadsWanted = command.threads;
      if (!capturedSinceReset && nextId === resetAt.startId && released.length === releasedFrom
        && (parallel?.coordinator.backlog ?? 0) === 0) {
        applyThreads();
        frameClock().resumeLive(resetAt.startUs, resetAt.lastUs);
      }
      break;

    case 'interfaces':
      interfaces = command.interfaces;
      rebuildInterfaceIndex();
      if (parallel !== null) {
        parallel.coordinator.decodeRows = interfaces.length > 1;
        parallel.coordinator.broadcast(interfacesMessage());
      }
      break;

    case 'host':
      // Rebuilt into Sets here: a Set does not survive structured clone as
      // itself, so the wire carries arrays and the Worker is the one place
      // that turns them back. Frames already dissected keep whatever they
      // decided - the main thread re-derives those, because it is the side
      // that holds the buffer.
      host = {
        macs: new Set(command.macs), addresses: new Set(command.addresses),
        inferred: command.inferred, confidence: command.confidence, basis: command.basis,
      };
      if (parallel !== null) {
        parallel.coordinator.lane0.host = host;
        parallel.coordinator.broadcast(hostMessage());
      }
      break;
    case 'reset':
      resetPipeline(command.nextId, command.captureStartUs, command.lastPacketUs);
      // A cleared buffer is a new capture. Keeping the old socket table would
      // let a port reused since then be attributed to the process that held
      // it during a capture that is no longer on screen.
      flowAnnotations.clear();
      lastFlows = null;
      parallel?.coordinator.broadcast({ type: 'flowsClear' });
      // Fingerprints are learned from THIS capture's attributions. Carrying
      // them into the next one would keep applying a label whose evidence has
      // been discarded.
      clientFingerprints.clear();
      break;

    case 'keylog':
      keyLog.add(command.text);
      // Every shard holds the key log too, and one started later is given it whole.
      keyLogTexts.push(command.text);
      parallel?.coordinator.broadcast({ type: 'keylog', text: command.text });
      // A rebuilt tree read the key log as it was; with more keys, the same
      // frame may now decrypt. Arrival's cache stays, as ADR 0045 records.
      revisitedTrees.clear();
      break;

    case 'keylog-clear':
      // `clear` also flushes the derived AES schedules; see its comment.
      keyLog.clear();
      keyLogTexts.length = 0;
      // A shard's cached trees are a fourth place, cleared with its key log.
      parallel?.coordinator.broadcast({ type: 'keylogClear' });
      // And the cached trees, which are the other place a decrypted payload
      // lives: without this a recent frame would keep showing plaintext after
      // the panel said the secrets were gone. The decrypted answers kept for
      // revisits are the third.
      treeCache.clear();
      revisitedTrees.clear();
      derivedStore.clear();
      break;

    case 'derived':
      for (const [id, bytes] of command.frames) derivedStore.set(id, bytes);
      break;

    case 'derivedBudget':
      derivedStore.resize(command.bytes);
      break;

    case 'detail': {
      const layers = treeCache.get(command.id) ?? revisitedTrees.get(command.id);
      if (layers) {
        // Lane 0's tree, its `tls.stream` placeholders numbered by now.
        if (parallel !== null) settleTreeTls(layers, (p) => parallel!.coordinator.resolveLaneZero(p));
        post({ type: 'detail', id: command.id, layers });
        break;
      }
      // Not dissected recently: rebuilt from the frame's record, which the
      // store holds for every frame of the capture (ADR 0049). Only a frame
      // with no record - a capture older than records, a frame that failed to
      // dissect - falls back to replaying its conversation. A frame a shard
      // dissected recently is asked of the shard first, which still has it.
      const id = command.id;
      const shard = parallel?.coordinator.treeShard(id) ?? null;
      const fromShard = shard === null ? Promise.resolve(null) : treeFromShard(shard, id);
      void fromShard.then((cached) => cached ?? revisitFromStore(id)).then((rebuilt) => {
        if (rebuilt !== null) post({ type: 'detail', id, layers: rebuilt });
        else post({ type: 'needReplay', id });
      });
      break;
    }

    case 'replay': {
      const { layers } = dissectReplay(
        command.frames, command.truncated, command.streamId, command.retroactive, host,
        command.seeds,
        // The adapter, resolved here because here is where the list is. Without
        // it every rebuilt tree read `Interface description: Imported capture`
        // on a live capture - and a displayed tree is always a rebuilt one
        // (ADR 0007), so that was every tree a person ever saw.
        interfaceByFrameLabel,
      );
      // The process came down with the request rather than being looked up
      // here: this store is a moving picture of open sockets, and a frame
      // scrolled back to may belong to one that closed long ago.
      addProcessRow(layers, command.process ?? null);
      addLiveGapRow(layers, command.liveSkipped);
      // Not cached: a replayed frame is one the user scrolled back to, and
      // caching it would evict the recent frames that answer without any work
      // at all.
      post({ type: 'detail', id: command.id, layers });
      break;
    }
  }
}

// --- start ---------------------------------------------------------------------
//
// One script, two roles. The app starts it as the pipeline; the pipeline starts
// it again, by its own URL, for each TCP shard it dissects on (ADR 0053 phase 3,
// `shardRole.ts`) - and a shard must never run the pipeline's timer or answer
// the app.
if (isShardRole(ctx)) {
  runShard(ctx);
} else {
  setInterval(flush, FLUSH_MS);
  ctx.onmessage = handleCommand;
}
