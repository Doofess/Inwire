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
import { dissectReplay } from '../services/pipeline/replay';
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
  bytes: Uint8Array;
  origLen: number;
  iface: number;
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
/** Stand-in sequence number for an agent that sends none. */
let arrivalSeq = 0;
let captureStartUs: number | null = null;
let lastPacketUs: number | null = null;

let pendingPackets: Packet[] = [];
let pendingIcmpReplies: { requestFrameId: number; replyId: number }[] = [];
let pendingInfoPatches: InfoPatch[] = [];

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
  // The facts, but not the identity. Clearing the buffer discards what this
  // capture observed; it does not make the machine a different machine, and
  // re-deriving the adapter's own MAC would mean every frame after a clear
  // read as unknown until the agent next spoke.
  networkFacts.reset();
  duplicates.reset();
  treeCache.clear();
  pendingPackets = [];
  pendingIcmpReplies = [];
  pendingInfoPatches = [];
  // A restored session hands back the capture it is continuing, so the frames
  // that arrive next carry on its relative-time column rather than restarting
  // it at zero underneath frames that are already numbered in the thousands.
  captureStartUs = startUs ?? null;
  lastPacketUs = lastUs ?? null;
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

function rebuildInterfaceIndex(): void {
  interfaceById = new Map(
    // `entry.id ?? index` is the agent's own indexing rule, kept exactly: the
    // list this searches is the *capturable* one and the agent indexes into
    // the unfiltered one, so the fallback is load-bearing.
    interfaces.map((entry, index) => [
      entry.id ?? index, { name: entry.name, label: entry.label },
    ]),
  );
}

function interfaceFor(iface: number): { name: string; label: string } | undefined {
  return interfaceById.get(iface);
}

function ingest(frame: LiveFrame): void {
  try {
    if (captureStartUs === null) {
      captureStartUs = frame.tsUs;
      lastPacketUs = null;
    }
    const relativeTime = (frame.tsUs - captureStartUs) / 1_000_000;
    const timeDelta = lastPacketUs !== null
      ? Math.max(0, (frame.tsUs - lastPacketUs) / 1_000_000)
      : 0;
    lastPacketUs = frame.tsUs;

    const id = nextId++;
    const decoded = decodeRawEthernetPacket(
      frame.bytes, id, frame.tsUs, relativeTime, timeDelta, frame.origLen,
      tcpTracker, icmpTracker, quicTracker, dnsTracker, interfaceFor(frame.iface),
      undefined, l3Tracker, host,
    );
    const packet = decoded.packet;
    packet.tsPrecision = 6;

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

function flush(): void {
  // Frames leave the ordering window in capture order and are dissected right
  // here, so the trackers see them in the order the wire did. Stopping
  // releases whatever is still held rather than stranding it.
  const ready = capturing ? ordering.drain(performance.now()) : ordering.flush();
  for (const frame of ready) ingest(frame);

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
// mean. The three cases below are exactly what `ws.onmessage` and the socket's
// own events used to deliver, which is why everything downstream of them is
// unchanged.

function tellAgent(message: ToAgentLink): void {
  agentPort?.postMessage(message);
}

function receiveFromAgent(message: FromAgentLink): void {
  switch (message.type) {
    case 'status':
      // Main is the authority on this now. It reports the same four states the
      // socket's `onopen`/`onerror`/`onclose` did, so the header is unchanged.
      post({ type: 'status', status: message.status });
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
      seq: frame.seq,
      arrivedAt,
      bytes: retain(frame),
      origLen: frame.origLen,
      iface: frame.iface,
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

    case 'capturing':
      capturing = command.capturing;
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
      break;

    case 'detail': {
      const layers = treeCache.get(command.id);
      if (layers) post({ type: 'detail', id: command.id, layers });
      else post({ type: 'needReplay', id: command.id });
      break;
    }

    case 'replay': {
      const { layers } = dissectReplay(
        command.frames, command.truncated, command.streamId, command.retroactive, host,
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
