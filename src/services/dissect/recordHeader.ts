/**
 * The front of a frame record: its version, and the other frames whose bytes a
 * revisit of it needs (ADR 0049).
 *
 * Its own module so the capture store can read it - to fetch those frames'
 * bytes along with the record - without importing the dissectors, which is
 * everything behind `frameRecord.ts`. The store never reads further than this.
 *
 * Layout: one version byte; a varint count; then the frame ids ascending, each
 * as a varint distance above the one before it. The call log follows.
 */

/**
 * The record format; a record with any other leading byte reads as no record.
 * 5: the L3 tracker answers WireGuard sessions, which moved every method id
 * after it - a version 4 record replays its conversation instead.
 * 6: the TCP tracker answers SSH conversations and the L3 tracker ESP
 * sequence numbers, which moved them again.
 */
export const FRAME_RECORD_VERSION = 6;

function varint(record: Uint8Array, at: { i: number }): number {
  let n = 0;
  let scale = 1;
  for (;;) {
    if (at.i >= record.length) throw new RangeError('frame record: header past the end');
    const b = record[at.i++];
    n += (b & 0x7f) * scale;
    if (b < 0x80) return n;
    scale *= 0x80;
  }
}

/** The header, and where the call log starts; null for a record this build does not read. */
export function readRecordHeader(record: Uint8Array): { refs: number[]; logStart: number } | null {
  if (record.length === 0 || record[0] !== FRAME_RECORD_VERSION) return null;
  const at = { i: 1 };
  const count = varint(record, at);
  const refs: number[] = [];
  let previous = 0;
  for (let i = 0; i < count; i++) {
    previous += varint(record, at);
    refs.push(previous);
  }
  return { refs, logStart: at.i };
}

/** The frames whose bytes a revisit of this record needs, ascending. */
export function recordRefs(record: Uint8Array): number[] {
  return readRecordHeader(record)?.refs ?? [];
}

/** A header for these frames, to go in front of a call log. */
export function writeRecordHeader(refs: readonly number[]): Uint8Array {
  const sorted = [...refs].sort((a, b) => a - b);
  const bytes: number[] = [FRAME_RECORD_VERSION];
  const push = (n: number) => {
    while (n >= 0x80) {
      bytes.push((n % 0x80) | 0x80);
      n = Math.floor(n / 0x80);
    }
    bytes.push(n);
  };
  push(sorted.length);
  let previous = 0;
  for (const frame of sorted) {
    push(frame - previous);
    previous = frame;
  }
  return Uint8Array.from(bytes);
}
