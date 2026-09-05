import { Packet, ProtocolField } from '../../types/packet';

/**
 * The parts of the packet detail window that are pure functions of a packet
 * and the buffer around it.
 *
 * Kept out of the component so they can be exercised without a browser (see
 * scripts/packet-detail/model.ts) - the frame lookup in particular has edge
 * cases that are tedious to reach through the UI: a buffer whose numbering no
 * longer starts at 1 because it has been trimmed, a number outside the buffer,
 * and a number that is not a number.
 */

/**
 * Finds the index of the frame numbered `id`, or -1.
 *
 * Binary search rather than `findIndex`, because the buffer holds up to 50,000
 * packets and the frame-number box is typed into repeatedly. Sorted order is
 * guaranteed: ids come from `PacketGenerator` monotonically and nothing
 * reorders the buffer.
 *
 * Note what this deliberately does NOT do: compute the index arithmetically as
 * `id - packets[0].id`. That is correct only while numbering is contiguous,
 * which stops being true the moment the buffer trims its oldest entries or a
 * restored session resumes numbering - the exact situations where a wrong
 * answer would be least obvious.
 */
export function findPacketIndexById(packets: Packet[], id: number): number {
  let low = 0;
  let high = packets.length - 1;
  while (low <= high) {
    const mid = (low + high) >> 1;
    const midId = packets[mid].id;
    if (midId === id) return mid;
    if (midId < id) low = mid + 1;
    else high = mid - 1;
  }
  return -1;
}

/** The outcome of typing something into the frame-number box. */
export type FrameLookup =
  | { kind: 'empty' }
  | { kind: 'invalid'; text: string }
  | { kind: 'found'; index: number; packet: Packet }
  | { kind: 'outOfRange'; id: number; first: number | null; last: number | null };

/**
 * Resolves what the user typed into a frame.
 *
 * The three failures are kept distinct rather than collapsed into one "no":
 * an empty box is not an error, `12x` is a typo, and 900,000 is a real number
 * for a frame this buffer does not hold - and only the last one can usefully
 * say what range *is* held.
 */
export function lookupFrame(packets: Packet[], text: string): FrameLookup {
  const trimmed = text.trim();
  if (!trimmed) return { kind: 'empty' };
  if (!/^\d+$/.test(trimmed)) return { kind: 'invalid', text: trimmed };

  const id = Number(trimmed);
  const index = findPacketIndexById(packets, id);
  if (index !== -1) return { kind: 'found', index, packet: packets[index] };

  return {
    kind: 'outOfRange',
    id,
    first: packets.length > 0 ? packets[0].id : null,
    last: packets.length > 0 ? packets[packets.length - 1].id : null,
  };
}

/**
 * Why a jump to frame `id` cannot happen, or null when it can.
 *
 * Every cross-reference in the app points at a frame by number - `[Response In:
 * N]`, `[Reassembled in N]`, `(request in N)`, a Statistics row's first frame,
 * a related-frame link. All of them were written when that frame was in the
 * buffer, and the buffer trims its oldest frames, so all of them can outlive
 * their target. Clicking one then did **nothing at all**: no movement, no
 * message, nothing to distinguish "gone" from "broken".
 *
 * The frame-number box already had this right - it is `lookupFrame`'s
 * `outOfRange`, which carries the range that IS held precisely so a refusal can
 * say what the buffer has instead. This is that answer in the shape the
 * navigation callbacks need, so the four places that jump between frames give
 * one explanation rather than four.
 */
export function frameJumpRefusal(packets: Packet[], id: number): string | null {
  const lookup = lookupFrame(packets, String(id));
  if (lookup.kind !== 'outOfRange') return null;
  if (lookup.first === null || lookup.last === null) {
    return `Frame ${id.toLocaleString()} is not here - the buffer is empty.`;
  }
  // Which end it fell off matters: one means the capture has not got there
  // yet, the other means it has been trimmed away, and only the second is
  // permanent.
  const trimmed = id < lookup.first;
  return `Frame ${id.toLocaleString()} is ${trimmed ? 'no longer' : 'not yet'} in the buffer, `
    + `which holds ${lookup.first.toLocaleString()}–${lookup.last.toLocaleString()}.`;
}

/** The frame-level facts shown in the summary strip. */
export interface FrameSummary {
  /** Epoch milliseconds, formatted in the viewer's own zone. */
  localTime: string;
  utcTime: string;
  /** Seconds since the capture began. */
  relativeTime: string;
  /** Seconds since the previous frame. */
  timeDelta: string;
  /** Bytes on the wire. */
  frameLength: number;
  /**
   * Bytes actually captured, and only set when it differs from the wire
   * length - a frame captured under a snaplen, or one the agent sent as
   * metadata only. Equal lengths are the normal case and saying so twice
   * would be noise.
   */
  captureLength: number | null;
  interfaceName: string;
  /** Lowercase dissected layers, outermost first. */
  protocolChain: string[];
  analysisFlags: string[];
  status: Packet['status'];
}

/**
 * Formats a time to the capture's own resolution.
 *
 * `tsPrecision` is the number of meaningful decimals the capture carries - 6
 * for a microsecond file, 9 for nanosecond - and is what the packet list's
 * Time column already honours. Printing more digits than the capture holds
 * would invent precision.
 */
function formatSeconds(seconds: number, precision: number): string {
  return seconds.toFixed(precision);
}

export function buildFrameSummary(packet: Packet): FrameSummary {
  const precision = packet.tsPrecision ?? 6;
  const date = new Date(packet.tsUs / 1000);
  // A Date holds milliseconds, so the fraction of a second is taken from the
  // stamp itself: nanoseconds when the capture file carried them, else the
  // microseconds every live frame has.
  const fractional = packet.tsNanos !== undefined
    ? Number(packet.tsNanos % 1_000_000_000n) / 1e9
    : (packet.tsUs % 1_000_000) / 1e6;
  const fractionalDigits = formatSeconds(fractional, precision).slice(2);

  const valid = Number.isFinite(packet.tsUs) && !Number.isNaN(date.getTime());
  const localTime = valid
    ? `${date.toLocaleString(undefined, { hour12: false })}.${fractionalDigits}`
    : 'unknown';
  const utcTime = valid
    ? `${date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '')}.${fractionalDigits} UTC`
    : 'unknown';

  const captured = packet.rawBytes?.length ?? 0;

  return {
    localTime,
    utcTime,
    relativeTime: formatSeconds(packet.relativeTime ?? 0, precision),
    timeDelta: formatSeconds(packet.timeDelta ?? 0, precision),
    frameLength: packet.length,
    captureLength: captured > 0 && captured !== packet.length ? captured : null,
    interfaceName: packet.interfaceName,
    protocolChain: packet.frameProtocols ?? [],
    analysisFlags: packet.analysisFlags ?? [],
    status: packet.status,
  };
}

/** A frame this one points at, and why. */
export interface RelatedFrame {
  frameNumber: number;
  /** The field that carried the reference, e.g. "[Response In]". */
  label: string;
}

/**
 * Collects the cross-frame references a dissector emitted for this packet.
 *
 * These already exist as `linkToFrame` on `ProtocolField` - it is how
 * `[Response In: 11]` and ICMP's `(reply in N)` are represented - so this
 * gathers rather than derives. Walks children too: the references sit at
 * whatever depth their dissector put them, often under a generated
 * `[Timestamps]`-style grouping node rather than at the top of a layer.
 */
export function collectRelatedFrames(packet: Packet): RelatedFrame[] {
  const found: RelatedFrame[] = [];
  const seen = new Set<number>();

  const visit = (fields: ProtocolField[] | undefined) => {
    if (!fields) return;
    for (const field of fields) {
      if (field.linkToFrame !== undefined && !seen.has(field.linkToFrame)) {
        seen.add(field.linkToFrame);
        found.push({ frameNumber: field.linkToFrame, label: field.name });
      }
      visit(field.children);
    }
  };

  for (const layer of packet.layers ?? []) visit(layer.fields);
  return found;
}
