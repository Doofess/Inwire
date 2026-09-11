import { useCallback, useEffect, useRef, useState, type Dispatch, type RefObject, type SetStateAction } from 'react';

import type { Packet } from '../types/packet';
import type { InfoPatch } from '../services/dissect/types';
import type { FrameBatch } from '../services/pipelineClient';
import { FieldBlockWriter } from '../services/dissect/fieldSplit';
import { appendFrames, trimFramesBelow } from '../services/sessionStore';
import { captureStore } from '../services/capture/captureClient';
import {
  adoptAccounting, commitBatch, prepareBatch, freshAccounting, type BufferAccounting,
} from '../services/packetBuffer';

/** How often the ingest queue is drained into React state. */
const PACKET_FLUSH_MS = 100;
/** How many of the newest frames keep their raw bytes resident. */
const BYTES_RESIDENT_FRAMES = 25000;

/**
 * The packet buffer: the frames the app is holding, and everything that decides
 * which frames those are.
 *
 * Six places in `App.tsx` used to reach into the same eight refs - the ingest
 * drain, the session restore, `queueFrames`, Clear, Discard and Import - and
 * nothing else in the file touched any of them. That is one concern wearing a
 * disguise, and this is it: the three arrival queues, the running accounting,
 * the dense-field writer, the buffer itself, and the flush that ties them
 * together.
 *
 * What it deliberately does NOT own is the session restore. Restore refills the
 * buffer, so it looks like it belongs here, but it also reads the agent, the
 * host identity, the capture clock and the stored session - seven things that
 * are nothing to do with which frames are in memory. It stays in `App.tsx` and
 * borrows `accountingRef` and `fieldWriter`, which is the one seam left.
 *
 * The flush itself lives in `services/packetBuffer.ts` so it can be tested
 * without React - `scripts/session/ingest.ts` drives it and runs every commit
 * twice, because React does.
 */
export interface PacketBufferOptions {
  /**
   * The buffer's byte budget, as a plain value. The hook mirrors it into a ref
   * of its own because the flush is registered once and its closure would
   * otherwise pin whatever the budget was when the app started.
   */
  packetBufferBytes: number;
  isCapturingRef: RefObject<boolean>;
  /**
   * The buffer hit its budget and capture has to stop. The hook sets its own
   * `bufferAutoPaused`; this is for the parts it does not own - the capture
   * flag and telling the agent.
   */
  onAutoPause: () => void;
  /**
   * The first and last capture timestamps in a batch. The stored session
   * carries both so a restore can carry on from them, and they belong to the
   * capture clock rather than to the buffer.
   */
  onFramesQueued: (firstTsUs: number, lastTsUs: number) => void;
}

export interface PacketBuffer {
  packets: Packet[];
  setPackets: Dispatch<SetStateAction<Packet[]>>;
  /** Frames pushed out because the buffer was full. */
  droppedBuffer: number;
  bufferAutoPaused: boolean;
  setBufferAutoPaused: Dispatch<SetStateAction<boolean>>;
  /** Hands a Worker batch to the next flush. */
  queueFrames: (batch: FrameBatch) => void;
  /**
   * The buffer is now exactly these frames.
   *
   * Clear, Discard and Import all did the same three things by hand; this is
   * them. `persistedThroughId` is explicit because the three call sites
   * disagree about it and always have - Clear and Discard reset it to 0, and
   * Import passes `null` to leave it alone. That asymmetry is preserved here
   * rather than quietly settled, because settling it changes behaviour.
   */
  adoptBuffer: (packets: Packet[], persistedThroughId: number | null) => void;
  /** Summary bytes the buffer is holding, for the settings panel. */
  residentBytes: () => number;
  /** The current byte budget, for the restore path's own trimming. */
  budgetBytes: () => number;
  /** Borrowed by the session restore - see the note above. */
  accountingRef: RefObject<BufferAccounting>;
  fieldWriter: RefObject<FieldBlockWriter>;
}

export function usePacketBuffer({
  packetBufferBytes, isCapturingRef, onAutoPause, onFramesQueued,
}: PacketBufferOptions): PacketBuffer {
  const [packets, setPackets] = useState<Packet[]>([]);
  const packetBufferBytesRef = useRef(packetBufferBytes);
  useEffect(() => {
    packetBufferBytesRef.current = packetBufferBytes;
  }, [packetBufferBytes]);
  /**
   * Frames pushed out of the buffer because it filled.
   *
   * The third of the three places a frame can go missing between the wire and
   * the list - the driver's ring, the agent's send queue, and here - and the
   * only one that was never counted. Capture auto-pauses at 99% of the buffer,
   * so this moves during an import or a restore rather than during a capture,
   * and it is what makes "the list starts at frame 40,001" a statement rather
   * than a mystery.
   */
  const [droppedBuffer, setDroppedBuffer] = useState(0);
  /**
   * One column-block writer for the session.
   *
   * A writer per flush would mean a block per batch, and a slow capture's
   * batches are small enough that the per-block overhead would exceed what the
   * columns save. One writer lets a block fill across many flushes
   * (`services/dissect/fieldSplit.ts`).
   */
  const fieldWriter = useRef(new FieldBlockWriter());
  /**
   * What the buffer's summaries are estimated to cost, in bytes.
   *
   * Added to outside the state updater and subtracted inside the one guard that
   * already survives StrictMode's double invoke - see the trim below. A ref
   * rather than state because nothing renders from it: it decides when to trim
   * and when to auto-pause, both of which happen inside the flush.
   *
   * An estimate, with a tested error bound: `scripts/perf/buffer-budget.ts`
   * holds it to within 15% of the heap those frames actually occupy.
   */
  /**
   * The buffer's running accounting - resident bytes, frames dropped, the head
   * id that guards a repeated trim, and how far the store has been written.
   *
   * One object rather than four refs because those four are read and written
   * together by everything that touches the buffer, and because
   * `services/packetBuffer.ts` needs them as a unit it can be handed in a test.
   */
  const accountingRef = useRef(freshAccounting());
  // Set when capture stopped itself because the buffer filled, so the reason
  // is visible rather than the capture appearing to have stopped for no
  // reason. Cleared by anything that makes room or deliberately restarts.
  const [bufferAutoPaused, setBufferAutoPaused] = useState(false);
  // Packets arrive one WebSocket message at a time but are committed to state
  // in batches - see the ingest comment in the socket handler below.
  const pendingPacketsRef = useRef<Packet[]>([]);
  // ICMP replies patch an EARLIER packet's info text. Collected alongside the
  // new packets so the patch is applied once per flush over one array pass,
  // rather than mapping the whole buffer per reply.
  const pendingIcmpRepliesRef = useRef<{ requestFrameId: number; replyId: number }[]>([]);
  /** Info suffixes for earlier frames, learned by later ones (reassembly); applied on the next flush. */
  const pendingInfoPatchesRef = useRef<InfoPatch[]>([]);

  /**
   * Queues a Worker batch. Cheap on purpose: it appends and returns, and the
   * flush below commits the whole batch in one state update, which is what
   * keeps ingest cost independent of buffer size.
   */
  const queueFrames = useCallback(({ packets, icmpReplies, infoPatches }: FrameBatch) => {
      if (packets.length > 0) {
        // The relative-time origin and the last frame's stamp are written into
        // the stored session so a restore can carry on from them. They used to
        // be set per packet by the ingest that now lives in the Worker; the
        // batch carries the same two facts.
        onFramesQueued(packets[0].tsUs, packets[packets.length - 1].tsUs);
        // A loop, not `push(...packets)`. Spreading passes one argument per
        // frame, and an engine throws RangeError somewhere past ~65-125k of
        // them. Nothing here bounds the batch: the Worker sends what one flush
        // dissected, so a Worker that stalled for a few seconds at rate - the
        // exact condition this whole change exists to survive - arrives as one
        // batch large enough to throw, losing the batch and every frame queued
        // behind it. See the sibling pushes below.
        for (const packet of packets) pendingPacketsRef.current.push(packet);
      }
      for (const reply of icmpReplies) pendingIcmpRepliesRef.current.push(reply);
      for (const patch of infoPatches) pendingInfoPatchesRef.current.push(patch);
  }, []);

  // Drains the ingest queue into state on a fixed cadence. Runs for the life
  // of the app rather than only while capturing, so packets queued in the
  // instant before a stop still land instead of being stranded.
  useEffect(() => {
    const flush = () => {
      // Already dissected, in capture order, by the pipeline Worker - which
      // owns the ordering window and the trackers, so the wire's order is
      // preserved where it matters (docs/decisions/0003). All that happens
      // here is committing a batch to React state.
      const incoming = pendingPacketsRef.current;
      const replies = pendingIcmpRepliesRef.current;
      const patches = pendingInfoPatchesRef.current;
      if (incoming.length === 0 && replies.length === 0 && patches.length === 0) return;
      pendingPacketsRef.current = [];
      pendingIcmpRepliesRef.current = [];
      pendingInfoPatchesRef.current = [];

      // The half that must happen exactly once - the store write, the
      // dense-field split, the byte count - outside the updater because React
      // runs that twice under StrictMode. See services/packetBuffer.ts.
      prepareBatch(incoming, accountingRef.current, {
        persist: (frames) => {
          appendFrames(frames as Packet[]);
          // Shadow write to the capture store. Beside IndexedDB, not instead
          // of it: nothing reads OPFS yet, so a refresh still restores the way
          // it always has while the new path is watched on a real capture.
          //
          // Inside `persist` deliberately - that is the half of the flush that
          // runs exactly once even under StrictMode's double invoke, and
          // writing a frame twice is exactly what it exists to prevent.
          captureStore.append(frames as Packet[]);
        },
        absorb: (frames) => fieldWriter.current.absorb(frames),
      });

      // Patches go over immediately after the frames, and separately, because
      // one almost always targets a frame from an EARLIER flush - a TLS record
      // reassembled across a dozen segments, an ICMP reply seconds later. The
      // writer's staging ring is what holds those rows back long enough to
      // receive them; see services/capture/captureWriter.ts.
      if (patches.length > 0) captureStore.patch(patches);

      // Snapshotted here, outside the updater, because React may run that twice
      // and the trim plan must not be computed from a number the first run
      // moved - see `residentBytesAtEntry` in services/packetBuffer.ts.
      const residentBytesAtEntry = accountingRef.current.residentBytes;
      setPackets((prev) => commitBatch(
        prev, incoming, replies, patches, accountingRef.current,
        {
          budgetBytes: packetBufferBytesRef.current,
          capturing: isCapturingRef.current,
          residentFrames: BYTES_RESIDENT_FRAMES,
          residentBytesAtEntry,
        },
        {
          trimFramesBelow,
          // The capture store's range, not IndexedDB's. IndexedDB's floor
          // rises with its own 512 MB budget, faster than the RAM window's,
          // and `evictOldBytes` may only drop bytes it can read back - so
          // every frame that budget had evicted kept its bytes in memory for
          // the rest of the capture. See services/packetBytes.ts.
          storedIdRange: () => captureStore.storedRange,
          // Deferred: calling a setter from inside an updater is the impure
          // part, and the head-id guard is what keeps it to one call.
          reportDropped: (total) => queueMicrotask(() => setDroppedBuffer(total)),
          autoPause: () => {
            setBufferAutoPaused(true);
            onAutoPause();
          },
        },
      ));
    };
    const timer = window.setInterval(flush, PACKET_FLUSH_MS);
    return () => window.clearInterval(timer);
  }, []);

  const adoptBuffer = useCallback((next: Packet[], persistedThroughId: number | null) => {
    // A fresh writer, because the blocks the old one handed out belong to
    // frames that are no longer here.
    fieldWriter.current = new FieldBlockWriter();
    adoptAccounting(accountingRef.current, next, persistedThroughId);
    // `adoptAccounting` zeroes the running total; this is the copy Driver Info
    // renders, and it has to follow or the panel keeps the old number.
    setDroppedBuffer(0);
    setPackets(next);
  }, []);

  const residentBytes = useCallback(() => accountingRef.current.residentBytes, []);
  const budgetBytes = useCallback(() => packetBufferBytesRef.current, []);

  return {
    packets, setPackets, droppedBuffer, bufferAutoPaused, setBufferAutoPaused,
    queueFrames, adoptBuffer, residentBytes, budgetBytes, accountingRef, fieldWriter,
  };
}
