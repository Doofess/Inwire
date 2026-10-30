import { Packet } from '../types/packet';
import { BYTES_RESIDENT_FRAMES, estimateSummaryBytes } from './bufferBudget';
import { DnsTracker } from './dnsTracker';
import { ImportFailure, rowsToFrames } from './exportSchema';
import { PcapService, type FrameRecordEntry } from './pcapParser';
import type { CaptureFileFacts } from './captureFileFacts';
import { applyIcmpReplies, restoreBatch } from './sessionRestore';
import { extensionOf, readTabularFile, TABULAR_EXTENSIONS } from './tabularReaders';
import { IcmpEchoTracker } from './icmpEchoTracker';
import { QuicFlowTracker } from './quicFlowTracker';
import { TcpStreamTracker } from './tcpStreamTracker';

/**
 * The single front door for every file the Import panel accepts.
 *
 * Before this existed, `PcapService.parsePcapFile` was the whole importer, and
 * its last resort was to `JSON.parse` the file and, if the result happened to
 * be an array, hand it back **as `Packet[]` with no checking at all**. Any JSON
 * array at all became "packets": objects with no `rawBytes`, which fault the
 * hex pane the moment one is selected. Every format now goes through the same
 * evaluator, and a file that is not packet data is refused by name.
 */

export interface ImportSuccess {
  ok: true;
  packets: Packet[];
  /** Things the user should know about what was lost. Never fatal. */
  notes: string[];
  /**
   * What a capture file said about how it was taken - its interfaces'
   * filters, snaplens and counters (`captureFileFacts.ts`). Absent for
   * anything that is not a capture file.
   */
  facts?: CaptureFileFacts;
}

export type ImportOutcome = ImportSuccess | { ok: false; failure: ImportFailure };

export const CAPTURE_EXTENSIONS = ['.pcap', '.pcapng', '.cap'];

/** Everything the file picker should offer, in one place. */
export const IMPORT_ACCEPT = [...CAPTURE_EXTENSIONS, '.json', ...TABULAR_EXTENSIONS, '.zip'].join(',');

/**
 * Decodes frames the same way session restore and pcap import do.
 *
 * The trackers are created fresh per import and shared across the whole file:
 * TCP stream ids, retransmission flags and ICMP request/reply pairings are all
 * order-dependent state, so a single pass in row order is what makes an
 * imported capture come out with the same stream numbering it had.
 */
function framesToPackets(
  frames: Parameters<typeof restoreBatch>[0],
  fallbackOrigin: { sourceLabel: string; frameNote: string },
): Packet[] {
  const { packets, icmpReplies } = restoreBatch(
    frames,
    {
      tcpTracker: new TcpStreamTracker(),
      icmpTracker: new IcmpEchoTracker(),
      quicTracker: new QuicFlowTracker(),
      dnsTracker: new DnsTracker(),
    },
    undefined,
    fallbackOrigin,
  );
  return applyIcmpReplies(packets, icmpReplies);
}

/**
 * A table of strings to packets, with everything that was lost written down.
 *
 * The notes are the honest part of this feature. A spreadsheet cannot carry
 * wire bytes unless someone ticked the box, and a user who imports one and
 * finds an empty hex pane deserves to have been told why at import time rather
 * than to discover it by clicking.
 */
export function importRows(
  rows: string[][],
  sourceLabel: string,
): ImportOutcome {
  const parsed = rowsToFrames(rows, sourceLabel);
  // Explicit === false, not !parsed.ok: this project compiles non-strict, and
  // without strictNullChecks TypeScript will not narrow a union on the
  // truthiness of a boolean-literal discriminant. It does narrow on ===.
  if (parsed.ok === false) return parsed;

  const notes: string[] = [];
  if (!parsed.hadRawBytes) {
    notes.push(
      'No raw packet bytes in this file, so these frames have no hex dump and no protocol '
      + 'tree. Re-export with "Include raw packet bytes" to keep them.',
    );
  }
  if (parsed.rejected > 0) {
    notes.push(`${parsed.rejected} row(s) were skipped: no usable source, destination, protocol or length.`);
  }
  if (parsed.badRawBytes > 0) {
    notes.push(`${parsed.badRawBytes} row(s) had a RawBytes cell that was not valid base64; imported without bytes.`);
  }
  if (parsed.synthesizedEpoch) {
    notes.push('The file carried no absolute timestamps, so the capture is anchored at the time of import.');
  }
  if (parsed.droppedExpert > 0) {
    notes.push(
      `${parsed.droppedExpert} row(s) named an expert finding. A row carries only the summary, `
      + 'not the category or the tree row it was raised on, so the findings were not rebuilt.',
    );
  }

  return {
    ok: true,
    packets: framesToPackets(parsed.frames, {
      sourceLabel,
      frameNote: `imported from ${sourceLabel} without raw packet bytes`,
    }),
    notes,
  };
}

/**
 * JSON, routed through the same evaluator as every other table.
 *
 * The array of objects is flattened to a header row plus value rows, which
 * means one validator covers CSV, Excel and JSON rather than a third bespoke
 * check that can disagree with the other two.
 */
async function importJson(file: File): Promise<ImportOutcome> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await file.text());
  } catch (err) {
    return {
      ok: false,
      failure: {
        kind: 'unreadable',
        message: `This file is not valid JSON. (${err instanceof Error ? err.message : String(err)})`,
      },
    };
  }

  const records = Array.isArray(parsed)
    ? parsed
    : Array.isArray((parsed as { packets?: unknown }).packets)
      ? (parsed as { packets: unknown[] }).packets
      : null;

  if (!records) {
    return {
      ok: false,
      failure: {
        kind: 'no-table',
        message: 'This JSON is not a list of packets. Inwire expects an array, or an object with a "packets" array.',
      },
    };
  }
  if (records.length === 0) {
    return { ok: false, failure: { kind: 'no-rows', message: 'This JSON list is empty.', rejected: 0 } };
  }

  const keys: string[] = [];
  for (const record of records) {
    if (record && typeof record === 'object' && !Array.isArray(record)) {
      for (const key of Object.keys(record)) if (!keys.includes(key)) keys.push(key);
    }
  }
  if (keys.length === 0) {
    return {
      ok: false,
      failure: {
        kind: 'no-table',
        message: 'This JSON is an array, but not of objects - there are no fields to read as columns.',
      },
    };
  }

  const rows: string[][] = [keys];
  for (const record of records) {
    const object = (record ?? {}) as Record<string, unknown>;
    rows.push(
      keys.map(key => {
        const value = object[key];
        if (value === null || value === undefined) return '';
        // `layers` and friends are objects; they are rebuilt from bytes, so
        // they are not worth stringifying into a cell nobody reads.
        return typeof value === 'object' ? '' : String(value);
      }),
    );
  }

  return importRows(rows, file.name);
}

/**
 * Unwraps a zip and imports the one supported file inside it.
 *
 * Present because the export panel can now produce a zip, and an export format
 * that cannot be re-imported is a one-way door. Deliberately refuses an archive
 * holding several captures rather than picking one: which of them the user
 * meant is not something to guess at, and the buffer holds one capture.
 */
async function importZip(file: File, maxFrames: number): Promise<ImportOutcome> {
  let entries: Record<string, Uint8Array>;
  try {
    const { unzipSync } = await import('fflate');
    entries = unzipSync(new Uint8Array(await file.arrayBuffer()));
  } catch (err) {
    return {
      ok: false,
      failure: {
        kind: 'unreadable',
        message: `This zip could not be opened. (${err instanceof Error ? err.message : String(err)})`,
      },
    };
  }

  const supported = [...CAPTURE_EXTENSIONS, '.json', ...TABULAR_EXTENSIONS];
  const candidates = Object.keys(entries).filter(
    name => !name.endsWith('/') && supported.includes(extensionOf(name)),
  );

  if (candidates.length === 0) {
    return {
      ok: false,
      failure: {
        kind: 'no-table',
        message:
          'This zip holds nothing Inwire can import. Expected one of: '
          + `${supported.join(', ')}.`,
      },
    };
  }
  if (candidates.length > 1) {
    return {
      ok: false,
      failure: {
        kind: 'no-table',
        message:
          `This zip holds ${candidates.length} importable files (${candidates.slice(0, 4).join(', ')}`
          + `${candidates.length > 4 ? ', ...' : ''}). Unzip it and import the one you want.`,
      },
    };
  }

  const name = candidates[0];
  const inner = entries[name];
  const outcome = await importAnyFile(new File([inner as unknown as BlobPart], name), { maxFrames });
  if (outcome.ok === true) outcome.notes.unshift(`Read ${name} from ${file.name}.`);
  return outcome;
}

async function importCapture(
  file: File, maxFrames: number, residentBytes: number, onBatch?: ImportBatchSink,
  onProgress?: ImportProgress,
): Promise<ImportOutcome> {
  try {
    const notes: string[] = [];
    const { packets, totalFrames, stored, facts } = onBatch === undefined
      ? await readWholeCapture(file, maxFrames)
      : await readStreamedCapture(file, maxFrames, residentBytes, onBatch, onProgress);

    if (stored === null && totalFrames > packets.length) {
      // Only when there is nowhere to put the rest. With a sink the frames are
      // on disk and reachable, so the honest note is about where they are, not
      // about what was thrown away.
      notes.push(
        `The file holds ${totalFrames.toLocaleString()} frames; the first `
        + `${packets.length.toLocaleString()} were loaded, which is the buffer size set `
        + 'under Settings > Interface. Raise it and import again to see the rest.',
      );
    } else if (stored !== null && stored > packets.length) {
      notes.push(
        `All ${stored.toLocaleString()} frames were imported. The newest `
        + `${packets.length.toLocaleString()} are in memory; the rest are on disk and the `
        + 'list scrolls into them.',
      );
    }
    if (packets.length === 0) {
      return {
        ok: false,
        failure: {
          kind: 'no-rows',
          message: 'No frames could be decoded from this capture file.',
          rejected: 0,
        },
      };
    }
    return { ok: true, packets, notes, facts };
  } catch (err) {
    return {
      ok: false,
      failure: {
        kind: 'unreadable',
        message: err instanceof Error ? err.message : 'This capture file could not be parsed.',
      },
    };
  }
}

/** What an import produced, and how many frames reached the store. */
interface CaptureRead {
  /** The frames to put in the RAM buffer - the newest, when streaming. */
  packets: Packet[];
  totalFrames: number;
  /** Frames handed to the sink, or null when there was none. */
  stored: number | null;
  facts: CaptureFileFacts;
}

/** The old route: everything in one array, capped at the buffer's size. */
async function readWholeCapture(file: File, maxFrames: number): Promise<CaptureRead> {
  const { packets, totalFrames, facts } = await PcapService.parseCaptureFile(file, maxFrames);
  return { packets, totalFrames, stored: null, facts };
}

/**
 * The streaming route: every frame to the sink, the newest kept for the buffer.
 *
 * The tail rather than the head, which is the opposite of what the cap used to
 * keep and is the right way round now. Truncating had to keep the beginning -
 * it was all there would ever be. With the rest on disk the buffer is a
 * **window**, and the window a reader wants first is the end of the capture,
 * the same one a live capture leaves them at.
 */
async function readStreamedCapture(
  file: File, maxFrames: number, residentBytes: number, onBatch: ImportBatchSink,
  onProgress?: ImportProgress,
): Promise<CaptureRead> {
  const tail: Packet[] = [];
  // Each tail row's estimate, parallel to `tail`, so dropping a row subtracts
  // what it added without estimating it again.
  const sizes: number[] = [];
  let tailBytes = 0;
  // How many of the tail's oldest rows have let their bytes go. The budget does
  // not count raw bytes; they stay for the newest BYTES_RESIDENT_FRAMES only, as
  // in the live buffer, and older frames read theirs from the store. Kept on
  // every row, a tail of full-size frames held a 2.7 GB file's bytes (#20).
  let released = 0;
  // Recorded, because every frame of a streamed import goes to the store, and
  // a frame's record there is what rebuilds its tree later (ADR 0049).
  const outcome = await PcapService.streamCaptureFile(file, (batch, records) => {
    onBatch(batch, records ?? []);
    for (const packet of batch) {
      const size = estimateSummaryBytes(packet);
      tail.push(packet);
      sizes.push(size);
      tailBytes += size;
    }
    // Trimmed as it goes, not at the end: holding the whole capture to slice
    // the last slab off it is the memory this route exists to avoid. Both
    // bounds hold, one frame always stays, and the head goes in one splice.
    let drop = 0;
    while (
      tail.length - drop > 1
      && (tailBytes > residentBytes || tail.length - drop > maxFrames)
    ) {
      tailBytes -= sizes[drop];
      drop++;
    }
    if (drop > 0) {
      tail.splice(0, drop);
      sizes.splice(0, drop);
      released = Math.max(0, released - drop);
    }
    // After `onBatch`, which has handed each frame to the store: its append
    // copies the packet object there and then, so this reaches only the tail's.
    for (; released < tail.length - BYTES_RESIDENT_FRAMES; released++) {
      tail[released].rawBytes = RELEASED_BYTES;
    }
  }, { record: true, onProgress });
  return { packets: tail, totalFrames: outcome.totalFrames, stored: outcome.built, facts: outcome.facts };
}

/**
 * Where a streamed import's frames go: each batch, with each of its frames'
 * records (ADR 0049) - which the store must be handed before the rows.
 */
export type ImportBatchSink = (packets: Packet[], records: FrameRecordEntry[]) => void;

/** How much of the file has been read, of its size; called as each window loads. */
type ImportProgress = (readBytes: number, totalBytes: number) => void;

/**
 * What a tail row holds once its bytes have gone: empty, which is all
 * `hasBytes` in `packetBytes.ts` asks. Not imported from there, so this module
 * does not pull the store client in.
 */
const RELEASED_BYTES = new Uint8Array(0);

export interface ImportOptions {
  /**
   * How many frames a capture file may contribute - the packet buffer's size,
   * so an import never produces more packets than the app is set to hold. A
   * capture beyond the cap loads its first `maxFrames` frames and says so.
   */
  maxFrames?: number;
  /**
   * Where every frame goes, in the order it was dissected.
   *
   * Supplied by the app, which writes each batch to the capture store. With
   * one, a capture file is imported **whole** and `maxFrames` becomes what the
   * RAM buffer keeps rather than what the file may contribute. Without one -
   * every script, and every format that is not a capture file - nothing
   * changes.
   */
  onBatch?: ImportBatchSink;
  /**
   * With `onBatch`: what the RAM tail may hold, in `estimateSummaryBytes` terms
   * - the measure `adoptAccounting` and `planBufferTrim` use, so the buffer
   * does not start over budget. It binds beside `maxFrames`; the tighter of the
   * two wins and one frame always stays. Ignored without `onBatch`.
   */
  residentBytes?: number;
  /**
   * With `onBatch`: bytes of the file read so far, of its size, called between
   * the windows the capture is read in. Ignored without `onBatch`.
   */
  onProgress?: ImportProgress;
}

export async function importAnyFile(file: File, options: ImportOptions = {}): Promise<ImportOutcome> {
  const maxFrames = options.maxFrames ?? Number.POSITIVE_INFINITY;
  const extension = extensionOf(file.name);

  if (extension === '.zip') return importZip(file, maxFrames);
  if (CAPTURE_EXTENSIONS.includes(extension)) {
    return importCapture(
      file, maxFrames, options.residentBytes ?? Number.POSITIVE_INFINITY, options.onBatch,
      options.onProgress,
    );
  }
  if (extension === '.json') return importJson(file);

  if (TABULAR_EXTENSIONS.includes(extension)) {
    const table = await readTabularFile(file);
    if (table.ok === false) return table;
    return importRows(table.rows, file.name);
  }

  return {
    ok: false,
    failure: {
      kind: 'unreadable',
      message:
        `Inwire cannot import ${extension || 'files without an extension'}. `
        + `Supported: ${IMPORT_ACCEPT.replace(/,/g, ', ')}.`,
    },
  };
}
