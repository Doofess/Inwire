/**
 * The protocol tree of the selected frame, fetched when it is selected.
 *
 * Frames in the buffer carry their bytes and their summary but not their tree:
 * a tree is 10.6 kB against the frame's own 1.2 kB, and the detail pane is the
 * only thing that ever reads one (docs/decisions/0007). So the tree is asked
 * for on selection and arrives a beat later, while the columns, the hex dump
 * and the byte highlighter - all of which come off the frame itself - render
 * immediately.
 *
 * The pipeline Worker answers from its cache of recently dissected frames,
 * which is nearly every click during a live capture. When it cannot, it asks
 * for the frame's conversation and rebuilds the tree by dissecting it again,
 * because a mid-conversation frame's tree is not a function of its own bytes
 * (see services/pipeline/replay.ts).
 */
import { useEffect, useRef, useState } from 'react';
import { pipeline, type ReplayBundle } from '../services/pipelineClient';
import { streamPackets, targetForPacket } from '../services/followStream';
import { hasBytes, packetBytes, packetsBytes } from '../services/packetBytes';
import type { Packet } from '../types/packet';

/**
 * The frames a replay of `packet`'s conversation needs: everything on its
 * stream up to and including it, oldest first.
 */
export async function replayBundleFor(
  packet: Packet,
  buffer: readonly Packet[],
): Promise<ReplayBundle> {
  const target = targetForPacket(packet);
  const stream = target
    ? streamPackets(buffer, target).filter((p) => p.id <= packet.id)
    // A frame on no stream at all - an ARP, a broadcast - has no conversation
    // to replay and needs none: nothing before it changed how it dissects.
    : [packet];
  // The bytes, from the packets themselves where they still have them and from
  // the store where they do not. A replay is wrong without them - it would
  // dissect a conversation of empty frames - so this is one of the few places
  // that genuinely needs every frame's bytes rather than the selected one's.
  const source = stream.length > 0 ? stream : [packet];
  const bytesById = await packetsBytes(source);
  const frames = source.map((p) => ({
    id: p.id,
    tsUs: p.tsUs,
    relativeTime: p.relativeTime,
    timeDelta: p.timeDelta,
    origLen: p.length,
    bytes: bytesById.get(p.id) ?? p.rawBytes,
  }));

  // A TCP conversation starts with a SYN. If the earliest frame we still hold
  // for this one is not it, the buffer has forgotten the beginning, and the
  // tree's sequence numbers and reassembly are relative to where the replay
  // could start rather than to where the conversation did. Said rather than
  // guessed at, because a reader cannot tell the difference by looking.
  const first = stream[0];
  const truncated = target?.kind === 'tcp'
    && first !== undefined
    && first.fields?.['tcp.flags.syn'] !== 1;

  // `[Response In: N]` on a DNS query is written by the frame that answers it,
  // which sits after the target and so is not replayed. The frame recorded the
  // fact when it first learned it; the rebuilt tree is handed it back.
  const responseIn = packet.fields?.['dns.response_in'];
  const retroactive = typeof responseIn === 'number'
    ? { frameId: packet.id, responseInFrame: responseIn }
    : undefined;

  // Read back off the frame rather than looked up again. The store that knew
  // this lives in the Worker and the answer is time-dependent, so asking it a
  // second time - minutes later, for a socket long closed - could legitimately
  // give a different answer than the column is already showing.
  const processName = packet.fields?.['inwire.process.name'];
  const processPid = packet.fields?.['inwire.process.pid'];
  const process = typeof processName === 'string' && typeof processPid === 'number'
    ? {
      name: processName,
      pid: processPid,
      exe: String(packet.fields?.['inwire.process.path'] ?? ''),
    }
    : undefined;

  return { frames, truncated, streamId: packet.streamId, retroactive, process };
}

/**
 * `packet` with its tree filled in, or with an empty one until it arrives.
 *
 * Returns the same object identity while a fetch is in flight, so the panes
 * below do not remount between the frame being selected and its tree landing.
 */
export function usePacketDetail(packet: Packet | null, buffer: readonly Packet[]): Packet | null {
  const [detail, setDetail] = useState<{ id: number; packet: Packet } | null>(null);

  // The buffer is read through a ref rather than closed over as a dependency:
  // a replay only happens on a cache miss, and re-running the fetch whenever a
  // packet arrives would cancel it on every flush of a live capture.
  const bufferRef = useRef(buffer);
  bufferRef.current = buffer;

  useEffect(() => {
    if (!packet) return;
    // Already carries a tree: a frame from a build that kept them, or one a
    // custom dissector produced. Nothing to fetch.
    // Both already present: a frame from a build that kept trees, or one still
  // carrying its bytes and its tree. Nothing to fetch.
  if (packet.layers.length > 0 && hasBytes(packet)) return;

    let live = true;
    // The tree and the bytes together, because a frame the buffer has stopped
    // holding bytes for needs both back before the hex dump, the byte-range
    // highlighter or the frame-length rows can render - and every one of those
    // reads them off the packet this hook returns, so filling them in here is
    // the whole of their migration.
    void Promise.all([
      pipeline.detail(packet.id, () => replayBundleFor(packet, bufferRef.current)),
      packetBytes(packet),
    ]).then(([layers, rawBytes]) => {
      if (live) setDetail({ id: packet.id, packet: { ...packet, layers, rawBytes } });
    });
    return () => { live = false; };
  }, [packet]);

  if (!packet) return null;
  if (packet.layers.length > 0 && hasBytes(packet)) return packet;
  if (detail && detail.id === packet.id) return detail.packet;
  return packet;
}
