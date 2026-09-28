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
import { clientFingerprints, learnOrLabelFingerprint } from '../services/dissect/clientFingerprints';
import { buildFallbackPacket } from '../services/sessionRestore';
import { TcpStreamTracker } from '../services/tcpStreamTracker';
import { IcmpEchoTracker } from '../services/icmpEchoTracker';
import { QuicFlowTracker } from '../services/quicFlowTracker';
import { DnsTracker } from '../services/dnsTracker';
import { L3Tracker } from '../services/l3Tracker';
import { NO_HOST, type HostIdentity } from '../services/direction';
import { NetworkFactsCollector } from '../services/networkFacts';
import { DuplicateFinder, duplicateSuffix } from '../services/duplicateFrames';
import { dissectReplay, interfacesByLabel } from '../services/pipeline/replay';
import { FrameRecorder, FrameRevisit, RecordMiss } from '../services/dissect/frameRecord';
import { DerivedStore } from '../services/pipeline/derivedStore';
import { withDissectEnv } from '../services/dissect/dissectEnv';
import { applyInfoPatch } from '../services/dissect/infoPatch';
import type { FromCapture } from '../services/capture/captureProtocol';
import type { RingPart } from '../services/capture/segments';
import { RingFiling } from '../services/pipeline/ringFiling';
import type { ProcessInfo } from '../services/flowAnnotations';
import type {
  FromPipeline, PipelineInterface, ToPipeline,
} from '../services/pipeline/protocol';
import type { Packet, ProtocolLayer } from '../types/packet';

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

let tcpTracker = new TcpStreamTracker();
let icmpTracker = new IcmpEchoTracker();
let quicTracker = new QuicFlowTracker();
let dnsTracker = new DnsTracker();
let l3Tracker = new L3Tracker();

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
let captureStartUs: number | null = null;
let lastPacketUs: number | null = null;
/**
 * The nanoseconds past each of those, so an adapter stamping in nanoseconds
 * gets a relative-time column in nanoseconds. A restored session hands back
 * microseconds only, and its remainders start at 0 - a sub-microsecond offset
 * on a column that capture was already showing to six places.
 */
let captureStartNsRem = 0;
let lastPacketNsRem = 0;

let pendingPackets: Packet[] = [];
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
 * Recently dissected trees, oldest first, so the detail pane can be answered
 * without re-dissecting anything. A plain Map relies on JS insertion order,
 * which is what makes the oldest key the first one `keys()` yields.
 */
const treeCache = new Map<number, ProtocolLayer[]>();

function cacheTree(id: number, layers: ProtocolLayer[]) {
  treeCache.set(id, layers);
  while (treeCache.size > DETAIL_CACHE_FRAMES) {
    const oldest = treeCache.keys().next();
    if (oldest.done) break;
    treeCache.delete(oldest.value);
  }
}

function resetPipeline(startId: number, startUs?: number | null, lastUs?: number | null) {
  ordering.clear();
  tcpTracker = new TcpStreamTracker();
  icmpTracker = new IcmpEchoTracker();
  quicTracker = new QuicFlowTracker();
  dnsTracker = new DnsTracker();
  l3Tracker = new L3Tracker();
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
  pendingPackets = [];
  pendingIcmpReplies = [];
  pendingInfoPatches = [];
  capturedSinceReset = false;
  pendingRecords = [];
  // A restored session hands back the capture it is continuing, so the frames
  // that arrive next carry on its relative-time column rather than restarting
  // it at zero underneath frames that are already numbered in the thousands.
  captureStartUs = startUs ?? null;
  lastPacketUs = lastUs ?? null;
  captureStartNsRem = 0;
  lastPacketNsRem = 0;
  arrivalSeq = 0;
  nextId = startId;
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
    if (captureStartUs === null) {
      captureStartUs = frame.tsUs;
      captureStartNsRem = frame.tsNsRem;
      lastPacketUs = null;
    }
    // In nanoseconds, then seconds: a difference of two stamps is small enough
    // that its nanosecond count is exact in a double where the stamps are not.
    const relativeTime = ((frame.tsUs - captureStartUs) * 1000 + frame.tsNsRem - captureStartNsRem) / 1e9;
    const timeDelta = lastPacketUs !== null
      ? Math.max(0, ((frame.tsUs - lastPacketUs) * 1000 + frame.tsNsRem - lastPacketNsRem) / 1e9)
      : 0;
    lastPacketUs = frame.tsUs;
    lastPacketNsRem = frame.tsNsRem;

    recorder.begin();
    const src = recorder.sources;
    const decoded = withDissectEnv(src.env, () => decodeRawEthernetPacket(
      frame.bytes, id, frame.tsUs, relativeTime, timeDelta, frame.origLen,
      src.tcp, src.icmp, src.quic, src.dns, interfaceFor(frame.iface),
      linkTypeFor(frame.iface), src.l3, host,
    ));
    // Only for a frame that dissected: one that threw has no record to trust,
    // and its tree is built the old way.
    pendingRecords.push({ id, record: recorder.end() });
    const derived = recorder.endDerived();
    if (derived !== null) derivedStore.set(id, derived);
    const packet = decoded.packet;
    const precision = tsPrecisionById.get(frame.iface) ?? 6;
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

    pendingPackets.push(packet);
    if (decoded.icmpMatchedRequestFrameId !== undefined) {
      pendingIcmpReplies.push({ requestFrameId: decoded.icmpMatchedRequestFrameId, replyId: id });
    }
    if (decoded.infoPatches) pendingInfoPatches.push(...decoded.infoPatches);
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
    ));
    again.finish();
    // The one thing a LATER frame writes into a tree, carried on the row.
    const responseIn = row.fields?.['dns.response_in'];
    if (typeof responseIn === 'number') applyInfoPatch(packet, { frameId: id, responseInFrame: responseIn });
    addProcessRow(packet.layers, processOfRow(row));
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
  // Frames leave the ordering window in capture order and are dissected right
  // here, so the trackers see them in the order the wire did. Stopping
  // releases whatever is still held rather than stranding it.
  const ready = capturing ? ordering.drain(performance.now()) : ordering.flush();

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
    storePort.postMessage({
      type: 'appendBytes',
      frames: assigned.map(({ frame, id }) => (frame.ring === undefined
        ? { id, tsUs: frame.tsUs, bytes: frame.bytes }
        : { id, tsUs: frame.tsUs, bytes: frame.bytes, ring: frame.ring })),
    });
  }

  for (const { frame, id } of assigned) ingest(frame, id);

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
    for (const mark of duplicates.scan(pendingPackets)) {
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
  const icmpReplies = pendingIcmpReplies;
  const infoPatches = pendingInfoPatches;
  pendingPackets = [];
  pendingIcmpReplies = [];
  pendingInfoPatches = [];

  // The frames' bytes are MOVED rather than copied. `retain()` gives every
  // frame an exactly-sized buffer of its own (agentBinary.ts), and the three
  // arrays above have already been swapped out, so nothing here reads a packet
  // again after this line - which is what makes detaching them safe.
  //
  // Measured at 2.16 us a frame, 1.27% of one (scripts/perf/throughput.ts).
  // Small: the boundary is only ~4% of a frame to begin with, and the bytes are
  // a fifth of that. Worth taking because it is free and correct, not because
  // it moves the ceiling - the ceiling is dissection (docs/decisions/0007).
  //
  // Deduplicated because a transfer list may not name one buffer twice, and
  // zero-length ones are skipped: a frame with no bytes shares the empty
  // buffer, which would be a duplicate every time two of them land together.
  const transfer: ArrayBuffer[] = [];
  const seen = new Set<ArrayBuffer>();
  for (const packet of packets) {
    const bytes = packet.rawBytes;
    if (!bytes || bytes.byteLength === 0) continue;
    const buffer = bytes.buffer as ArrayBuffer;
    // A view over a larger buffer would detach more than this frame - never
    // true for a retained live frame, but a restored or fallback packet is
    // built elsewhere and this is not the place to assume.
    if (bytes.byteOffset !== 0 || bytes.byteLength !== buffer.byteLength) continue;
    if (seen.has(buffer)) continue;
    seen.add(buffer);
    transfer.push(buffer);
  }

  post({ type: 'frames', packets, icmpReplies, infoPatches, lateCount: ordering.lateCount }, transfer);
}

setInterval(flush, FLUSH_MS);

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
      receiveBatch(message.bytes);
      return;
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

function receiveBatch(bytes: Uint8Array): void {
  if (!capturing) return; // agent detected, capture not started
  const buffer = asArrayBuffer(bytes);
  let frames;
  try {
    frames = isPacketBatch(buffer) ? decodePacketBatch(buffer) : null;
  } catch (err) {
    post({ type: 'failure', message: String(err) });
    return;
  }
  if (!frames) return;
  const arrivedAt = performance.now();
  for (const frame of frames) {
    // Not dissected here: frames wait in the ordering window and are dissected
    // by the flush, in capture order. `retain` copies the bytes out of the
    // batch, which one held frame would otherwise keep alive in full.
    ordering.push({
      tsUs: frame.tsUs,
      tsNsRem: frame.tsNsRem,
      seq: frame.seq,
      arrivedAt,
      bytes: retain(frame),
      origLen: frame.origLen,
      iface: frame.iface,
      ring: ringFiling.partOf(frame.seq),
    });
  }
}

function receiveControl(text: string): void {
  const message = parseAgentMessage(text);
  if (!message) return;

  if (message.type === 'socket_table') {
    // Applied here because this is where dissection happens, so every frame
    // from now on is annotated as it is built. It is forwarded as well: the
    // main thread keeps its own copy of the store to re-annotate frames that
    // were already dissected before this table arrived - the same split
    // `keyLog` has, for the same reason.
    flowAnnotations.apply(message, Date.now() * 1000);
    post({ type: 'agent', message });
    return;
  }

  // The ring's two facts the store needs, taken here because here is where
  // frames are filed (ADR 0052). Both are passed on to the app as well.
  if (message.type === 'capture_boundary') ringFiling.boundary(message.index, message.firstSeq);
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
    pendingPackets.push(buildFallbackPacket({
      id: nextId++,
      tsUs,
      relativeTime: captureStartUs === null ? 0 : (tsUs - captureStartUs) / 1_000_000,
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

ctx.onmessage = (event: MessageEvent<ToPipeline>) => {
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
      // Frames and records go out on it; the one thing that comes back is a
      // revisit kit this Worker asked for (ADR 0049). Everything else the store
      // says goes to the app's own port - `entry.ts` keeps them apart.
      port.onmessage = (message: MessageEvent<FromCapture>) => {
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
      capturing = command.capturing;
      if (capturing) capturedSinceReset = true;
      break;

    case 'drain':
      // Everything held goes now, in the order a flush sends it - bytes and
      // records to the store, then the rows up - and only then the answer, so
      // the app has the last rows in hand when it seals the capture.
      capturing = false;
      flush();
      post({ type: 'drained', requestId: command.requestId });
      break;

    case 'interfaces':
      interfaces = command.interfaces;
      rebuildInterfaceIndex();
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
      break;
    case 'reset':
      resetPipeline(command.nextId, command.captureStartUs, command.lastPacketUs);
      // A cleared buffer is a new capture. Keeping the old socket table would
      // let a port reused since then be attributed to the process that held
      // it during a capture that is no longer on screen.
      flowAnnotations.clear();
      // Fingerprints are learned from THIS capture's attributions. Carrying
      // them into the next one would keep applying a label whose evidence has
      // been discarded.
      clientFingerprints.clear();
      break;

    case 'keylog':
      keyLog.add(command.text);
      // A rebuilt tree read the key log as it was; with more keys, the same
      // frame may now decrypt. Arrival's cache stays, as ADR 0045 records.
      revisitedTrees.clear();
      break;

    case 'keylog-clear':
      // `clear` also flushes the derived AES schedules; see its comment.
      keyLog.clear();
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
        post({ type: 'detail', id: command.id, layers });
        break;
      }
      // Not dissected recently: rebuilt from the frame's record, which the
      // store holds for every frame of the capture (ADR 0049). Only a frame
      // with no record - a capture older than records, a frame that failed to
      // dissect - falls back to replaying its conversation.
      const id = command.id;
      void revisitFromStore(id).then((rebuilt) => {
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
      // Not cached: a replayed frame is one the user scrolled back to, and
      // caching it would evict the recent frames that answer without any work
      // at all.
      post({ type: 'detail', id: command.id, layers });
      break;
    }
  }
};
