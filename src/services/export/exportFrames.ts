/**
 * Every frame an export covers, in pages, from wherever each one is.
 *
 * An export used to be `packets` - the RAM window - and nothing else, so a
 * capture that had outgrown the buffer exported its newest few hundred
 * thousand frames and said nothing about the rest. The rest is on disk, and
 * this reads it: ordinals `[0, below)` from the capture store, then the window
 * itself, which is the capture from ordinal `below` onward.
 *
 * ## Two halves, and the seam between them is exact
 *
 * The window's frames are on disk too - the store is handed every frame as it
 * arrives - so the disk half stops at `below` and not at the end of the
 * capture. The store answers whole chunks, and the chunk holding `below`
 * holds window frames past it; those are clipped, never emitted, or the
 * window's oldest frames would be written twice.
 *
 * `below` is asked of the store here, for the window this export was handed,
 * and never taken from the caller. The list's own copy (`useWindowOrdinal`)
 * is the answer to an async question about an earlier window: a trim between
 * that answer and this export leaves it too small, and the frames between the
 * two ordinals would be in neither half - with `done === total` saying the
 * file was whole, because the total came from the same stale number.
 *
 * The window half is read from memory rather than from disk even though disk
 * has it, because the window is what the user is looking at: its rows carry
 * Info patches and linkType that a stored row may not, and its newest frames
 * are still staged behind the patch horizon and not on disk yet at all.
 *
 * ## Filtered, it is the list's own answer
 *
 * Disk rows come from the scan's `MatchSet` and window rows from
 * `FilterEngine.filterPackets`, which is exactly how the packet list splits
 * the same question (`lib/captureRowSpace.ts`) - so the file holds the frames
 * the list shows, and the count on the export button is the list's count. The
 * export does not run a scan of its own: the store runs one at a time, and a
 * second would cancel the list's.
 *
 * Between matches it **jumps**: the next position read is the next match's,
 * `ordinalAt(rank(at))`, so a chunk holding no match is never decoded. A
 * filter like `dns` over a long TLS transfer touches a handful of chunks
 * rather than all of them.
 *
 * ## A chunk that cannot be read is stepped over, not the end
 *
 * The store answers an unreadable chunk one of two ways: as a block with no
 * rows (a read the file could not satisfy - `CaptureReader.readRows`), or, when
 * decoding it threw, with nothing at all for the whole request
 * (`CaptureHost.onRowsAt`). Either way the export steps past it rather than
 * ending, because every later chunk is still readable and counting them all
 * as lost would be a lie with a number on it. Two reads at most, each bounded
 * by `CHUNK_FRAMES` - the most frames a chunk can hold:
 *
 * 1. `[at, at + CHUNK_FRAMES + 1)`. The chunk holding `at` ends within that,
 *    so the store's walk - which moves from chunk to chunk by the index, not
 *    by what it decoded - reaches the chunk after it. Exact for the first
 *    shape: the gap counted is exactly the bad chunk's frames.
 * 2. From `at + CHUNK_FRAMES`, which cannot be in the chunk holding `at`. For
 *    the second shape, where no answer names where the bad chunk ends. The
 *    frames from `at` to the first chunk found there are counted unreadable;
 *    that is exact unless the bad chunk was short **and** followed by another
 *    short one - which only a capture resumed after a restore produces - and
 *    then that one short chunk is counted as lost with it.
 *
 * If neither moves, everything left below the window is counted and the disk
 * half ends: a store that went away answers nothing for ever, and a loop that
 * kept asking would be a hang with a progress bar.
 *
 * ## What a disk row is missing
 *
 * `chunkCodec.decodeChunk` hands back rows without `rawBytes`, `cols`,
 * `colorSlot` and `layers`. The first comes back per page through
 * `packetsBytes`; the rest no writer needs.
 *
 * `linkType` is stored with each row from chunk version 2 on, and a row read
 * from such a chunk keeps its own - absent meaning Ethernet, as on a window
 * frame. A row from an older chunk has none recorded, and gets one from the
 * interface table, **first**, because an anonymiser or writer that saw the
 * frame without it would read a loopback frame's address family as a MAC
 * address (`anonymise.ts`). The table is keyed by adapter label, which is why
 * it is only the fallback: an import labels every frame alike, so a
 * multi-interface file has one label and two link types, and a table can hold
 * only one of them.
 *
 * ## Every yielded frame is a copy
 *
 * Shallow, so it costs an object and not the bag - but the window's packets
 * are React state and the buffer's own objects, and an export that set
 * `rawBytes` on one would silently undo `evictOldBytes`, holding a million
 * frames' bytes for the rest of the session.
 */
import { FilterEngine } from '../filterEngine';
import { LINKTYPE } from '../dissect/types';
import { matchesBeforeWindow } from '../../lib/captureRowSpace';
import { CHUNK_FRAMES } from '../capture/chunkCodec';
import { packetsBytes, type ByteSource } from '../packetBytes';
import type { MatchSet } from '../capture/matchSet';
import type { RowBlock } from '../capture/captureClient';
import type { Packet } from '../../types/packet';

/**
 * What the export reads the disk through. `captureStore` is one; a test hands
 * in its own over a real `CaptureHost`.
 */
export interface CaptureRowReader extends ByteSource {
  readRowsAt(from: number, to: number): Promise<RowBlock[]>;
  /** Where a frame sits in the capture, or -1 - `CaptureClient.ordinalOf`. */
  ordinalOf(id: number): Promise<number>;
}

/** Which frames an export reads. */
export interface FrameScope {
  /**
   * The RAM window: the capture's newest frames, from wherever the store
   * places `window[0]` onward. Everything before that is read off disk.
   */
  window: readonly Packet[];
  /**
   * The display filter, or null for the whole capture.
   *
   * `matches` is the scan's bitmap over the disk. Null is allowed only when
   * there is no disk below the window; otherwise the caller has to wait for
   * the scan, because exporting the window's matches alone and calling it the
   * filter's answer is the failure this module exists to end.
   */
  filter: { expression: string; matches: MatchSet | null } | null;
}

/**
 * How long to wait for the store to place the window's first frame. See
 * `windowOrdinal`.
 */
export interface LocateRetry {
  attempts: number;
  delayMs: number;
}

/** Two seconds: long enough for a live capture's next chunk to seal. */
export const LOCATE_RETRY: LocateRetry = { attempts: 10, delayMs: 200 };

export interface ExportFramesOptions {
  /**
   * Read each frame's bytes. False for a writer that uses the rows alone -
   * the PDF, and CSV - so a whole-capture export of those does no byte IO.
   */
  hydrateBytes: boolean;
  /** Adapter label to `LINKTYPE_*`, from `linkTypeTable`. */
  linkTypes: ReadonlyMap<string, number>;
  signal?: AbortSignal;
  /**
   * Frames per window page, and the span one disk read asks for. Disk pages
   * are whatever the store answers - whole chunks, clipped - because that is
   * the unit it decodes anyway.
   */
  pageSize?: number;
  /** `LOCATE_RETRY` when absent. */
  locate?: LocateRetry;
}

export interface ExportPage {
  packets: Packet[];
  /** Frames accounted for so far - yielded plus unreadable - for progress. */
  done: number;
  /** `exportTotal(scope)`, repeated so a consumer needs no second source. */
  total: number;
  /** Capture ordinals below the window, as the store placed it at the start. */
  below: number;
  /**
   * Frames the scope covers that the store could not hand back, so far: a torn
   * tail, or a chunk missing from the index. Counted rather than thrown,
   * because a capture that lost its last chunk to a crash is still worth
   * exporting, and the caller says how many it lost.
   */
  unreadable: number;
  /**
   * Frames yielded without bytes when bytes were asked for, so far. Not
   * always a loss - the agent can send a frame with no payload - but a number
   * that jumps is one the caller should see.
   */
  bytesMissing: number;
}

export const EXPORT_PAGE_FRAMES = 4096;

/**
 * Adapter label to link type, for putting `linkType` back on disk rows.
 *
 * The same table a restore builds (`App.tsx`), from the same kind of source,
 * plus what the window's own frames say - which covers an import, whose
 * adapter names are the file's and in no interface list, and an adapter that
 * has since disappeared. Where both speak, the frames win: they are what was
 * actually dissected.
 *
 * Ethernet is left out, the way the dissector leaves it out of a frame:
 * absent means Ethernet, and a frame should not gain a property to say so.
 */
export function linkTypeTable(
  interfaces: readonly { label: string; linkType?: number }[],
  window: readonly Packet[],
): Map<string, number> {
  const table = new Map<string, number>();
  for (const i of interfaces) {
    if (i.linkType !== undefined && i.linkType !== LINKTYPE.ETHERNET) table.set(i.label, i.linkType);
  }
  for (const p of window) {
    if (p.linkType !== undefined && p.linkType !== LINKTYPE.ETHERNET) {
      table.set(p.interfaceName, p.linkType);
    }
  }
  return table;
}

function noScanYet(): Error {
  return new Error(
    'the display filter has not finished scanning the capture on disk; '
    + 'wait for the scan (or rescan) before exporting what it selects',
  );
}

/**
 * The window's matches, remembered per window array and expression.
 *
 * `exportTotal` and `exportFrames` both need it and a caller asks for both at
 * once; filtering a million-frame window twice is a second or so of main
 * thread for the same answer. Keyed weakly on the array's identity, which
 * React replaces on every commit: a stale entry cannot be returned for a
 * window that has changed, and no entry keeps an old window - up to gigabytes
 * of frames - alive once nothing else holds it.
 */
const windowFilterCache = new WeakMap<readonly Packet[], Map<string, Packet[]>>();

function windowMatches(window: readonly Packet[], expression: string): Packet[] {
  let byExpression = windowFilterCache.get(window);
  if (byExpression === undefined) {
    byExpression = new Map();
    windowFilterCache.set(window, byExpression);
  }
  let result = byExpression.get(expression);
  if (result === undefined) {
    result = FilterEngine.filterPackets(window as Packet[], expression);
    byExpression.set(expression, result);
  }
  return result;
}

const sleep = (ms: number) => new Promise<void>((resolve) => { setTimeout(resolve, ms); });

/**
 * Capture ordinals below the window: where the store places `window[0]`.
 *
 * -1 from the store has two readings, and they must not be confused:
 *
 * - **Nothing is sealed on disk at all** - a short capture whose every frame
 *   is still staged. The window is then the whole capture, and 0 is the truth.
 * - **Frames are on disk and the window's first is not placed yet** - staged
 *   behind the patch horizon, which passes as the next chunk seals. Reading
 *   that as 0 would skip the whole disk half and export the window alone, so
 *   the store is asked again for a bounded while and then the export is
 *   refused, saying why. Refused rather than guessed: the frames between the
 *   sealed ones and the window have no other way to be located, and a file
 *   silently short of them is the failure this module exists to end.
 *
 * An empty window has no frame to place and answers 0; the app has no state
 * with frames on disk and none in the buffer.
 */
export async function windowOrdinal(
  window: readonly Packet[],
  reader: CaptureRowReader,
  retry: LocateRetry = LOCATE_RETRY,
): Promise<number> {
  if (window.length === 0) return 0;
  const id = window[0].id;
  let ordinal = await reader.ordinalOf(id);
  if (ordinal >= 0) return ordinal;

  const sealed = await reader.readRowsAt(0, 1);
  if (sealed.length === 0) return 0;

  for (let attempt = 1; attempt < retry.attempts && ordinal < 0; attempt++) {
    await sleep(retry.delayMs);
    ordinal = await reader.ordinalOf(id);
  }
  if (ordinal >= 0) return ordinal;
  throw new Error(
    'the capture store has not yet placed the oldest frame held in memory, so '
    + 'the frames on disk before it cannot be counted; wait a moment and export again',
  );
}

/** Disk ordinals the scope reads, `[0, limit)`. See `matchesBeforeWindow`. */
function diskLimit(scope: FrameScope, below: number): number {
  const matches = scope.filter?.matches;
  // A scan covers the frames that existed when it started. One that stopped
  // short of `below` is refused before this is asked (`ScanBehindError`), so
  // the clip only ever trims matches past the window, which the window half
  // answers from memory.
  return matches ? Math.min(below, matches.frameCount) : below;
}

/**
 * The scan stopped short of the window: frames `[frameCount, below)` arrived
 * after it started, and it has no answer for them. Refused rather than
 * exported without them - the list says "+N unsearched" for the same frames,
 * and a file cannot say anything at all.
 */
export class ScanBehindError extends Error {
  constructor(readonly uncovered: number) {
    super(`${uncovered.toLocaleString('en-US')} frames on disk arrived after the display filter's scan, `
      + 'so it cannot say whether they match; rescan the capture and export again');
    this.name = 'ScanBehindError';
  }
}

/**
 * The capture store was re-opened on another capture while an export was
 * reading it. Every read after that answers about the wrong capture - other
 * frames, and ids the old one also used - so the export stops, loudly.
 */
export class CaptureChangedError extends Error {
  constructor() {
    super('the capture changed while it was being exported (a new capture or an import started); '
      + 'nothing was saved');
    this.name = 'CaptureChangedError';
  }
}

/**
 * `reader`, refusing every read once `identity()` stops answering what it
 * answered when this was called - `captureStore.generation`, in the app.
 *
 * Belt and braces: the app cancels a running export before it re-opens the
 * store (`exportJob.cancelExportForChange`). This is what makes a path that
 * forgot to fail instead of writing a file that is half one capture and half
 * another.
 */
export function guardedReader(reader: CaptureRowReader, identity: () => unknown): CaptureRowReader {
  const at = identity();
  const check = () => { if (identity() !== at) throw new CaptureChangedError(); };
  return {
    async readRowsAt(from, to) {
      check();
      const blocks = await reader.readRowsAt(from, to);
      check();
      return blocks;
    },
    async readBytes(ids) {
      check();
      const bytes = await reader.readBytes(ids);
      check();
      return bytes;
    },
    async ordinalOf(id) {
      check();
      const ordinal = await reader.ordinalOf(id);
      check();
      return ordinal;
    },
  };
}

function totalFor(scope: FrameScope, below: number): number {
  if (scope.filter === null) return below + scope.window.length;
  const { expression, matches } = scope.filter;
  if (matches === null && below > 0) throw noScanYet();
  if (matches !== null && matches.frameCount < below) throw new ScanBehindError(below - matches.frameCount);
  const fromDisk = matches === null ? 0 : matchesBeforeWindow(matches, below);
  return fromDisk + windowMatches(scope.window, expression).length;
}

/**
 * How many frames the scope holds - the progress bar's denominator, and the
 * number the export offers before it starts.
 *
 * Asks the store where the window sits, exactly as `exportFrames` does, so the
 * number offered and the number exported come from one kind of answer. A
 * trim between the two calls can still move it; the pages' own `total` is the
 * one that describes the file.
 */
export async function exportTotal(
  scope: FrameScope,
  reader: CaptureRowReader,
  retry?: LocateRetry,
): Promise<number> {
  return totalFor(scope, await windowOrdinal(scope.window, reader, retry));
}

/**
 * The scope's frames in capture order, a page at a time.
 *
 * Throws, rather than ending short, when the signal aborts: a writer that
 * finished cleanly on a cancelled export would commit a file that looks
 * complete.
 */
export async function* exportFrames(
  scope: FrameScope,
  reader: CaptureRowReader,
  options: ExportFramesOptions,
): AsyncGenerator<ExportPage> {
  const pageSize = Math.max(1, Math.floor(options.pageSize ?? EXPORT_PAGE_FRAMES));
  const below = await windowOrdinal(scope.window, reader, options.locate);
  const total = totalFor(scope, below);
  const matches = scope.filter?.matches ?? null;
  const limit = diskLimit(scope, below);
  let done = 0;
  let unreadable = 0;
  let bytesMissing = 0;
  /** What the last page yielded said it had accounted for; -1 before any. */
  let reported = -1;

  /** Frames the scope wants in `[from, to)` - a count of matches when filtered. */
  const wanted = (from: number, to: number): number => {
    if (to <= from) return 0;
    return matches === null ? to - from : matches.rank(to) - matches.rank(from);
  };

  const finish = async (packets: Packet[]): Promise<ExportPage> => {
    if (options.hydrateBytes && packets.length > 0) {
      const bytes = await packetsBytes(packets, reader);
      for (const p of packets) {
        if (p.rawBytes.byteLength > 0) continue;
        const found = bytes.get(p.id);
        if (found !== undefined && found.byteLength > 0) p.rawBytes = found;
        else bytesMissing++;
      }
    }
    done += packets.length;
    reported = done + unreadable;
    return { packets, done: reported, total, below, unreadable, bytesMissing };
  };

  /**
   * Takes what `blocks` hold from `from` on into `rows`, and answers how far
   * that got. A span the blocks skip over is counted unreadable.
   */
  const take = (blocks: readonly RowBlock[], from: number, rows: Packet[]): number => {
    let cursor = from;
    for (const block of blocks) {
      // A chunk the store skipped over, or one it could not decode followed
      // by one it could: the frames between are gone, and saying how many is
      // the honest answer.
      if (block.firstOrdinal > cursor) {
        const gapEnd = Math.min(block.firstOrdinal, limit);
        unreadable += wanted(cursor, gapEnd);
        cursor = gapEnd;
      }
      const start = Math.max(cursor, block.firstOrdinal);
      const end = Math.min(block.firstOrdinal + block.packets.length, limit);
      for (let ordinal = start; ordinal < end; ordinal++) {
        if (matches !== null && !matches.has(ordinal)) continue;
        const row = block.packets[ordinal - block.firstOrdinal];
        const copy: Packet = { ...row };
        // A chunk that recorded link types has already said: absent is
        // Ethernet there, as on a window frame. Only an older chunk's rows
        // need the table, and only for what the table can know.
        if (block.linkTypesStored !== true && copy.linkType === undefined) {
          const linkType = options.linkTypes.get(copy.interfaceName);
          if (linkType !== undefined) copy.linkType = linkType;
        }
        rows.push(copy);
      }
      if (end > cursor) cursor = end;
    }
    return cursor;
  };

  /**
   * Past the unreadable chunk holding `at`, in at most two reads. See the
   * module header, "A chunk that cannot be read is stepped over".
   */
  const stepOver = async (at: number, askedTo: number, rows: Packet[]): Promise<number> => {
    const past = Math.min(limit, at + CHUNK_FRAMES + 1);
    if (past > askedTo) {
      const cursor = take(await reader.readRowsAt(at, past), at, rows);
      if (cursor > at) return cursor;
    }
    const probe = Math.min(at + CHUNK_FRAMES, limit - 1);
    if (probe <= at) return at;
    const probeTo = matches === null ? Math.min(limit, probe + pageSize) : probe + 1;
    return take(await reader.readRowsAt(probe, probeTo), at, rows);
  };

  // ---- the disk half: ordinals [0, limit) --------------------------------
  let at = 0;
  while (at < limit) {
    options.signal?.throwIfAborted();

    let to: number;
    if (matches !== null) {
      // The next match at or after `at`. `rank(at)` counts the matches
      // strictly before it, so it is also the index of the first one that is
      // not - and asking for exactly that position reads exactly its chunk.
      const next = matches.ordinalAt(matches.rank(at));
      if (next < 0 || next >= limit) break;
      at = next;
      to = at + 1;
    } else {
      to = Math.min(limit, at + pageSize);
    }

    const rows: Packet[] = [];
    let cursor = take(await reader.readRowsAt(at, to), at, rows);
    if (cursor <= at) cursor = await stepOver(at, to, rows);

    // Still nowhere: a torn tail, or a store that went away. Everything from
    // here to the window is counted as lost rather than asked for again.
    if (cursor <= at) {
      unreadable += wanted(at, limit);
      break;
    }
    at = cursor;
    if (rows.length > 0) yield await finish(rows);
  }

  // ---- the window half ---------------------------------------------------
  const window = scope.filter === null
    ? scope.window
    : windowMatches(scope.window, scope.filter.expression);
  for (let i = 0; i < window.length; i += pageSize) {
    options.signal?.throwIfAborted();
    // A window frame already carries what it was dissected with, linkType
    // included - absent there means Ethernet, not "unknown" - so the table is
    // not consulted for it.
    const page = window.slice(i, i + pageSize).map((p) => ({ ...p }));
    yield await finish(page);
  }
  options.signal?.throwIfAborted();
  // The counters, once more, when the last page did not carry them: a torn
  // tail below the window with nothing after it counts its frames after the
  // last page went out, and a consumer that never heard would say the file
  // was whole and its progress would stop short of the total.
  if (reported !== done + unreadable) yield await finish([]);
}
