/**
 * A capture's segments: what they are called, and which of them may go
 * (ADR 0052).
 *
 * ## Why a capture has segments at all
 *
 * The agent can write a ring of pcapng files - N files of some size, keeping
 * the newest - and the capture on disk follows it: when the agent deletes a
 * file, the frames it held leave the list too, or a ring would bound the
 * agent's files and leave the app's own copy of the same frames to grow for
 * ever. The capture's four data files are append-only, and their front cannot
 * be given back, so a capture that follows a ring keeps its data in segments -
 * `seg-NNNNNN/`, each four files of its own - and a segment is deleted whole.
 * `captureIndex.ts` says how the index names them; this says which may go.
 *
 * ## The rule, and why each part of it is there
 *
 * **This is the one place a capture's frames are deleted without the user
 * pressing anything**, and it narrows ADR 0012 ("a capture is deleted only
 * when the user asks") to exactly this: the user asked for a ring, and the
 * agent has deleted the file that held these frames. So a segment goes only
 * when every one of these is true, and `scripts/capture/segment-guard.ts`
 * puts each back wrong to watch it fail:
 *
 * - **It is not segment 0.** Segment 0 is the files beside the index - an
 *   import, a capture from an agent that writes no ring, anything written
 *   before segments existed. None of it followed a ring.
 * - **It is not the segment being written**, and none of its frames are still
 *   staged: a segment is deleted once, whole, after its last chunk sealed.
 * - **Every frame in it was filed** under the capture the agent deleted from
 *   (`epoch`) - a segment holding a frame with no file, or one from an earlier
 *   run of the agent, whose ring is not this one, is kept.
 * - **Its newest frame is at or below the deleted file's last sequence
 *   number.** By sequence number rather than by file, and that is the part
 *   with a failure behind it: a frame is filed by the agent's `capture_boundary`
 *   messages, and a boundary the pipe shed would file a whole ring file under
 *   the one before it. By file, deleting that one would take frames the agent
 *   still holds; by sequence number, the segment just waits a file longer.
 * - **Oldest first, and no gaps.** The walk stops at the first segment it
 *   keeps, so what has gone is always a prefix - which is what lets one number,
 *   the floor, say what is left.
 *
 * It is pure so the guard can drive it. The writer supplies the facts and
 * does the deleting, floor first (`captureWriter.ts`).
 */

/** A segment's directory: `seg-` and six digits. Nothing else is ever removed. */
export const SEGMENT_PATTERN = /^seg-(\d{6})$/;

/** The most segments a capture can have. A million ring files is past any ring. */
export const MAX_SEGMENT = 999_999;

/** Segment `n`'s directory name. Segment 0 has none: it is the capture's own. */
export function segmentName(n: number): string {
  if (!Number.isInteger(n) || n < 1 || n > MAX_SEGMENT) {
    throw new RangeError(`segment ${n} is not one a capture can have`);
  }
  return `seg-${String(n).padStart(6, '0')}`;
}

/** The segment a directory name is, or null for anything that is not one. */
export function segmentNumberOf(name: string): number | null {
  const match = SEGMENT_PATTERN.exec(name);
  if (match === null) return null;
  const n = Number(match[1]);
  return n >= 1 ? n : null;
}

/**
 * Which ring file of which run of the agent a frame came from, and its
 * sequence number. The pipeline Worker files each frame this way from the
 * agent's `capture_boundary` messages; a frame from an agent that writes no
 * ring has none.
 */
export interface RingPart {
  /** Which run of the agent's capture: a new one each time its files start again at 1. */
  epoch: number;
  /** The ring file, 1-based as the agent numbers them. */
  file: number;
  seq: number;
}

/** What the writer knows of a segment it wrote in this run. */
export interface SegmentMeta {
  /** The run its frames were filed under. */
  epoch: number;
  /** The highest sequence number among them. */
  maxSeq: number;
  /**
   * It holds a frame filed under another run, or under none - and so is never
   * removed, because no one ring's deletions describe it.
   */
  mixed: boolean;
}

export interface EvictionFacts {
  chunkCount: number;
  /** The first chunk still held. */
  floorChunk: number;
  segmentOf(chunk: number): number;
  /** The segment being written. */
  current: number;
  /**
   * The oldest segment with a frame still staged, or null when nothing is.
   * Staging is in order, so every segment from here up is unsealed or later.
   */
  oldestStaged: number | null;
  /** What this run of the writer knows of each segment. One it has no entry for is kept. */
  meta: ReadonlyMap<number, SegmentMeta>;
  /** The newest file the agent has deleted: its run and its last sequence number. */
  deleted: { epoch: number; lastSeq: number };
}

export interface EvictionPlan {
  /** The new floor: the first chunk still held once `remove` has gone. */
  floorChunk: number;
  /** Segments to delete, oldest first. Empty when nothing may go. */
  remove: number[];
}

/** Which segments may go, and where the floor then is. See the module header. */
export function planSegmentEviction(facts: EvictionFacts): EvictionPlan {
  const remove: number[] = [];
  let chunk = facts.floorChunk;
  while (chunk < facts.chunkCount) {
    const segment = facts.segmentOf(chunk);
    if (segment === 0 || segment === facts.current) break;
    if (facts.oldestStaged !== null && segment >= facts.oldestStaged) break;
    const meta = facts.meta.get(segment);
    if (meta === undefined || meta.mixed) break;
    if (meta.epoch !== facts.deleted.epoch || meta.maxSeq > facts.deleted.lastSeq) break;
    // The whole segment, which is a run of chunks: segments are written in
    // order and never revisited.
    let end = chunk;
    while (end < facts.chunkCount && facts.segmentOf(end) === segment) end++;
    remove.push(segment);
    chunk = end;
  }
  return { floorChunk: chunk, remove };
}
