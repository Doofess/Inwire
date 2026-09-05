import { Packet } from '../types/packet';
import { DnsTracker } from './dnsTracker';
import { ImportFailure, rowsToFrames } from './exportSchema';
import { PDF_PACKET_LIMIT } from './pdfReportFormat';
import { PcapService } from './pcapParser';
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
  /**
   * What kind of file the rows came out of.
   *
   * Only 'pdf' behaves differently, and it has to: a report is a document, not
   * a data format, and carries the newest 100 frames with Info cut short. That
   * caveat belongs here with the other notes rather than being bolted on by the
   * caller - a note the dispatcher adds is a note no test of this function can
   * see.
   */
  sourceKind: 'table' | 'pdf' = 'table',
): ImportOutcome {
  const parsed = rowsToFrames(rows, sourceLabel);
  // Explicit === false, not !parsed.ok: this project compiles non-strict, and
  // without strictNullChecks TypeScript will not narrow a union on the
  // truthiness of a boolean-literal discriminant. It does narrow on ===.
  if (parsed.ok === false) return parsed;

  const notes: string[] = [];
  if (sourceKind === 'pdf') {
    notes.push(
      `A PDF report holds only the most recent ${PDF_PACKET_LIMIT} packets, with shortened Info text.`,
    );
  }
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
  if (parsed.droppedAnomalies > 0) {
    notes.push(
      `${parsed.droppedAnomalies} row(s) named an anomaly. A row carries only its title, not its `
      + 'severity or description, so the alerts were not rebuilt.',
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
 * means one validator covers CSV, Excel, PDF and JSON rather than a fourth
 * bespoke check that can disagree with the other three.
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

async function importCapture(file: File, maxFrames: number): Promise<ImportOutcome> {
  try {
    const notes: string[] = [];
    const { packets, totalFrames } = await PcapService.parseCaptureFile(file, maxFrames);
    if (totalFrames > packets.length) {
      notes.push(
        `The file holds ${totalFrames.toLocaleString()} frames; the first `
        + `${packets.length.toLocaleString()} were loaded, which is the buffer size set `
        + 'under Settings > Interface. Raise it and import again to see the rest.',
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
    return { ok: true, packets, notes };
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

export interface ImportOptions {
  /**
   * How many frames a capture file may contribute - the packet buffer's size,
   * so an import never produces more packets than the app is set to hold. A
   * capture beyond the cap loads its first `maxFrames` frames and says so.
   */
  maxFrames?: number;
}

export async function importAnyFile(file: File, options: ImportOptions = {}): Promise<ImportOutcome> {
  const maxFrames = options.maxFrames ?? Number.POSITIVE_INFINITY;
  const extension = extensionOf(file.name);

  if (extension === '.zip') return importZip(file, maxFrames);
  if (CAPTURE_EXTENSIONS.includes(extension)) return importCapture(file, maxFrames);
  if (extension === '.json') return importJson(file);

  if (TABULAR_EXTENSIONS.includes(extension)) {
    const table = await readTabularFile(file);
    if (table.ok === false) return table;
    return importRows(table.rows, file.name, extension === '.pdf' ? 'pdf' : 'table');
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
