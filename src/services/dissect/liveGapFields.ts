/**
 * Marking the frame after a hole in the live stream (ADR 0053).
 *
 * When the live view falls too far behind, frames are shed - by main, or by
 * the agent's own per-client queue - and the stream the Worker dissects has a
 * gap in the agent's sequence numbers. The frames in it are NOT lost: the
 * agent wrote every one into the capture's pcapng before it put it on the
 * pipe (ADR 0052). So the first frame after the gap says exactly that, as a
 * field, an expert finding and a row on its Frame layer.
 *
 * **`CaptureGap`, not `Loss`.** TCP analysis is left to run across the gap,
 * and it will say "previous segment not captured" and "ACKed unseen segment"
 * of the streams that crossed it - which is true of what this view
 * dissected, and which the TLS record cursor needs said, or it would read the
 * bytes after the hole as the middle of a record. Those verdicts are already
 * filed under `CaptureGap` ("this capture is incomplete", `types/packet.ts`),
 * never under the network's loss, so nothing here accuses the wire; this note
 * is what tells the reader why, and that the missing frames can be had from
 * the file. Catching the gap up from that file is ADR 0053's phase 4, after
 * which there is no gap to explain.
 *
 * A fact about how this machine received the capture, not about the bytes -
 * like the process row (`processFields.ts`), it is written after dissection,
 * carried on the stored row, and put back on a rebuilt tree from there.
 */
import type { Packet, ProtocolLayer } from '../../types/packet';

function liveGapMessage(skipped: number): string {
  return `${skipped.toLocaleString('en-US')} frame${skipped === 1 ? '' : 's'} before this one `
    + 'skipped by the live view - they are in the capture file';
}

/** Adds the note to the Frame layer of a tree, when `skipped` says there was a hole. */
export function addLiveGapRow(layers: ProtocolLayer[], skipped: unknown): void {
  if (typeof skipped !== 'number' || !(skipped > 0)) return;
  const frame = layers.find((layer) => layer.name === 'Frame');
  if (!frame) return;
  frame.fields.push({
    name: 'Skipped by the live view',
    value: skipped,
    generated: true,
    abbrev: 'inwire.live.skipped',
    expertInfo: { category: 'CaptureGap', message: liveGapMessage(skipped) },
  });
}

/** Marks the first frame after a hole of `skipped` frames: field, finding and row. */
export function markLiveGap(packet: Packet, skipped: number): void {
  if (!(skipped > 0)) return;
  (packet.fields ??= {})['inwire.live.skipped'] = skipped;
  (packet.expert ??= []).push({ category: 'CaptureGap', message: liveGapMessage(skipped) });
  addLiveGapRow(packet.layers, skipped);
}
