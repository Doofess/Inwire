/**
 * What one read of the agent's pcapng becomes in the catch-up reader (ADR 0053,
 * "Catch-up past the ceiling, 2026-11-04"), as a pure function of the tail's
 * state and the bytes read.
 *
 * The reader holds nothing between reads: a request carries the `TailState`
 * the read starts from and the reply carries the one the next read starts from,
 * so a reply that is dropped - a clear, a Stop - costs one read and never a
 * frame. The reply is built to be transferred: the frames' bytes are a few
 * slabs, each sized exactly to the frames in it, and their fixed fields are
 * typed columns, so a read of a million frames is a handful of buffers rather
 * than a million objects.
 */
import { PcapngTail, type TailFrame, type TailSection, type TailState } from './pcapngTail';

/** The most bytes in one slab; a single frame larger than this has a slab of its own. */
export const SLAB_BYTES = 256 * 1024;

export interface ReadParse {
  /** The file offset this read started at, and how many bytes it was given. */
  start: number;
  length: number;
  /** The block at the start of the read, once eight bytes of it are here. */
  head: { type: number; length: number } | null;
  /** Where the next read starts, and what it reads by. */
  end: TailState;
  count: number;
  /** Per frame: where its block starts in the file, and how long the block is. */
  blockAt: Float64Array;
  blockLen: Uint32Array;
  idb: Uint32Array;
  tsUs: Float64Array;
  tsNsRem: Uint16Array;
  origLen: Uint32Array;
  capLen: Uint32Array;
  /** Per frame: its slab, and where in the slab its bytes start. */
  slab: Uint32Array;
  slabAt: Uint32Array;
  /** Per frame: an index into `sections`, the description it was read by. */
  section: Uint32Array;
  sections: TailSection[];
  slabs: ArrayBuffer[];
  /** Set when the file was found corrupt; `end` is where the read stopped. */
  error: string | null;
}

/** Parse what main read from `state.offset`, into frames and the state to go on from. */
export function parseRead(state: TailState, bytes: Uint8Array): ReadParse {
  const tail = PcapngTail.restore(state);
  tail.push(bytes);
  const head = tail.blockHead();
  const frames: TailFrame[] = [];
  const blockAt: number[] = [];
  const blockLen: number[] = [];
  const sectionOf: number[] = [];
  const sections: TailSection[] = [];
  let lastSection = -1;
  let error: string | null = null;
  try {
    let frame;
    while ((frame = tail.next('view')) !== null) {
      if (tail.sectionNo !== lastSection) {
        lastSection = tail.sectionNo;
        sections.push(tail.section());
      }
      frames.push(frame);
      blockAt.push(tail.blockAt);
      blockLen.push(tail.position - tail.blockAt);
      sectionOf.push(sections.length - 1);
    }
  } catch (e) {
    error = e instanceof Error ? e.message : String(e);
  }

  const count = frames.length;
  const out: ReadParse = {
    start: state.offset,
    length: bytes.length,
    head,
    end: tail.save(),
    count,
    blockAt: Float64Array.from(blockAt),
    blockLen: Uint32Array.from(blockLen),
    idb: new Uint32Array(count),
    tsUs: new Float64Array(count),
    tsNsRem: new Uint16Array(count),
    origLen: new Uint32Array(count),
    capLen: new Uint32Array(count),
    slab: new Uint32Array(count),
    slabAt: new Uint32Array(count),
    section: Uint32Array.from(sectionOf),
    sections,
    slabs: [],
    error,
  };

  // Slabs are cut in a second pass, over the views: a frame never splits across
  // two, and one closes when the next frame would take it past SLAB_BYTES.
  let slabFirst = 0;
  let slabBytes = 0;
  const close = (end: number): void => {
    const buffer = new ArrayBuffer(slabBytes);
    const into = new Uint8Array(buffer);
    for (let i = slabFirst; i < end; i++) into.set(frames[i].bytes, out.slabAt[i]);
    out.slabs.push(buffer);
  };
  for (let i = 0; i < count; i++) {
    const f = frames[i];
    if (slabBytes > 0 && slabBytes + f.capLen > SLAB_BYTES) {
      close(i);
      slabFirst = i;
      slabBytes = 0;
    }
    out.idb[i] = f.idb;
    out.tsUs[i] = f.tsUs;
    out.tsNsRem[i] = f.tsNsRem;
    out.origLen[i] = f.origLen;
    out.capLen[i] = f.capLen;
    out.slab[i] = out.slabs.length;
    out.slabAt[i] = slabBytes;
    slabBytes += f.capLen;
  }
  if (count > 0) close(count);
  return out;
}

/** Every buffer a parse holds, each once: the ten columns, then the slabs. */
export function parseTransfer(parse: ReadParse): ArrayBuffer[] {
  return [
    parse.blockAt, parse.blockLen, parse.idb, parse.tsUs, parse.tsNsRem, parse.origLen, parse.capLen,
    parse.slab, parse.slabAt, parse.section,
  ].map((column) => column.buffer as ArrayBuffer).concat(parse.slabs);
}

export type ToReader = { type: 'parse'; requestId: number; state: TailState; bytes: Uint8Array };
export type FromReader = { type: 'parsed'; requestId: number; parse: ReadParse } | { type: 'failure'; message: string };

/** The reader's whole job: a request in, a reply and what to transfer with it out. Never throws. */
export function answerParse(message: ToReader): { reply: FromReader; transfer: ArrayBuffer[] } {
  try {
    const parse = parseRead(message.state, message.bytes);
    return { reply: { type: 'parsed', requestId: message.requestId, parse }, transfer: parseTransfer(parse) };
  } catch (e) {
    return { reply: { type: 'failure', message: e instanceof Error ? e.message : String(e) }, transfer: [] };
  }
}
