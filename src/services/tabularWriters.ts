import type { Packet } from '../types/packet';
import { surveyFields, FieldSurvey } from './export/fieldColumns';
import { CsvWriter, CSV_MIME } from './export/writers/csv';
import { chunksToBlob, concatChunks } from './export/writers/writer';
import type { CaptureMeta } from './export/captureMeta';

/**
 * The tabular formats' one-shot entry points: a whole array in, a whole file
 * out.
 *
 * The writers themselves live in `export/writers/`, and take a capture a page
 * at a time so a whole-capture export never holds it. These hand them one
 * page - the array - for a caller that already has one, and survey the array
 * for its field columns first, so a one-shot export carries every dissected
 * field exactly as a streamed one does.
 *
 * `exceljs` and `fflate` are both reached through `await import(...)`.
 * Together they are about a megabyte, and the overwhelming majority of
 * sessions never open the export panel at all - so they are paid for on the
 * click that needs them rather than on every page load.
 */

// --- CSV ---------------------------------------------------------------------

// `ignoreBOM` keeps the BOM the writer put there, so the text is the file.
const UTF8_KEEP_BOM = new TextDecoder('utf-8', { ignoreBOM: true });

export function buildCsvText(packets: readonly Packet[], includeRawBytes: boolean, meta?: CaptureMeta): string {
  const writer = new CsvWriter({ includeRawBytes, fields: surveyFields(packets), meta });
  const bytes = concatChunks([...writer.write(packets), ...writer.finish()]);
  return UTF8_KEEP_BOM.decode(bytes);
}

export function buildCsv(packets: readonly Packet[], includeRawBytes: boolean, meta?: CaptureMeta): Blob {
  const writer = new CsvWriter({ includeRawBytes, fields: surveyFields(packets), meta });
  return chunksToBlob([...writer.write(packets), ...writer.finish()], CSV_MIME);
}

// --- Excel -------------------------------------------------------------------

export interface XlsxOptions {
  includeRawBytes: boolean;
  /** Shown on the Capture sheet so a filtered export says what it was filtered by. */
  filter?: string;
  meta?: CaptureMeta;
}

/**
 * The workbook, for an array. See `export/writers/xlsx.ts` for the sheets,
 * the colours and the budget - which this is held to like any other export,
 * and which refuses with a message naming CSV when the array is past it.
 */
export async function buildXlsx(packets: readonly Packet[], options: XlsxOptions): Promise<Blob> {
  const { createXlsxWriter, XLSX_MIME } = await import('./export/writers/xlsx');
  const survey = new FieldSurvey();
  survey.addPage(packets);
  const writer = await createXlsxWriter({
    includeRawBytes: options.includeRawBytes,
    fields: survey.columns(),
    meta: options.meta,
    filter: options.filter,
    expectedFrames: packets.length,
    expectedFieldCells: survey.cells,
  });
  writer.write(packets);
  return chunksToBlob(await writer.finish(), XLSX_MIME);
}

// --- Zip ---------------------------------------------------------------------

/**
 * Wraps one already-generated file in a zip container.
 *
 * `zipSync` rather than fflate's worker-backed `zip`: the data is already fully
 * in memory by the time this is called, and this repo has a documented history
 * of losing an afternoon to a library's web worker meeting Vite's pre-bundler
 * (see the maplibre note in `vite.config.ts`). A streamed export zips as it
 * goes instead (`lib/saveSink.ts`'s `zipSink`).
 */
export async function zipSingleFile(blob: Blob, filename: string): Promise<Blob> {
  const { zipSync } = await import('fflate');
  const bytes = new Uint8Array(await blob.arrayBuffer());
  const zipped = zipSync({ [filename]: bytes }, { level: 6 });
  return new Blob([zipped as unknown as ArrayBuffer], { type: 'application/zip' });
}
