/**
 * The shape every export writer has, and the two ways to drive one.
 *
 * A writer is handed the capture a page at a time and hands back the bytes
 * that page became. It never holds the capture: what it keeps between pages
 * is what the format needs at the end - pcapng's interface table, the
 * workbook's own model - and nothing else. `write` returns chunks rather than
 * writing to a sink itself so the writer stays synchronous and testable, and
 * so one writer serves both a streamed save (`pipeToSink`) and the old
 * one-shot entry points (`chunksToBlob`).
 *
 * Chunks are `Uint8Array`, always: the `ByteSink` contract, and the one form
 * every format produces without a detour - text writers encode a page at a
 * time, binary ones build it directly.
 *
 * ## Colour rules travel with the page
 *
 * `rules`, when given, is the colour rule each frame of `page` matched, index
 * for index. A caller that anonymises matches the real frames first
 * (`export/ruleMatcher.ts`) - the anonymised copies have no field bag and
 * match nothing - and a writer handed no answers matches the page itself.
 */
import type { ColorRule, Packet } from '../../../types/packet';
import type { ByteSink } from '../../../lib/saveSink';
import type { SaveOutcome } from '../../../lib/saveFile';

export interface ExportWriter {
  write(page: readonly Packet[], rules?: readonly (ColorRule | null)[]): Uint8Array[];
  /** What is left: a trailer, a header nothing was written before, or the whole buffered file. */
  finish(): Uint8Array[] | Promise<Uint8Array[]>;
}

/** Joins chunks into a Blob, for the one-shot entry points. */
export function chunksToBlob(chunks: readonly Uint8Array[], type: string): Blob {
  return new Blob(chunks as unknown as BlobPart[], { type });
}

/** Joins chunks into one array, for a caller that wants the bytes. */
export function concatChunks(chunks: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const c of chunks) length += c.byteLength;
  const out = new Uint8Array(length);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.byteLength;
  }
  return out;
}

export interface PipedPage {
  packets: readonly Packet[];
  rules?: readonly (ColorRule | null)[];
}

/**
 * Pages through a writer into a sink, and closes it.
 *
 * Every page's chunks are awaited before the next page is asked for, which is
 * the backpressure: a whole-capture export reads no faster than the disk
 * takes it. Any failure - the pages, the writer, the sink - aborts the sink,
 * so nothing is left with the chosen name.
 */
export async function pipeToSink(
  writer: ExportWriter,
  pages: AsyncIterable<PipedPage> | Iterable<PipedPage>,
  sink: ByteSink,
): Promise<SaveOutcome> {
  try {
    for await (const page of pages) {
      for (const chunk of writer.write(page.packets, page.rules)) await sink.write(chunk);
    }
    for (const chunk of await writer.finish()) await sink.write(chunk);
  } catch (error) {
    await sink.abort();
    throw error;
  }
  return sink.close();
}

const encoder = new TextEncoder();

/** UTF-8, for the text writers. */
export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}
