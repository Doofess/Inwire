/**
 * The streamed writers handed one array, for a caller that has one.
 *
 * These were static methods on `PcapService`, and that was a weight problem
 * rather than a style one: `pcapParser.ts` is in the entry chunk because the
 * importer and the pipeline need it, so every writer it named for these came
 * into every launch with it - for exports that now go through `runExport`,
 * fetched when a format is pressed. Nothing in the app calls these; the
 * assertion scripts and the TLS replay tool do.
 *
 * CSV's one-shot is `tabularWriters.buildCsvText`, and pcapng's is
 * `pcapngWriter.generatePcapNg`, for the same reason and in the same shape.
 */
import type { Packet } from '../../types/packet';
import type { CaptureMeta } from './captureMeta';
import { PcapWriter, PCAP_MIME } from './writers/pcap';
import { JsonWriter } from './writers/json';
import { chunksToBlob, concatChunks } from './writers/writer';

/**
 * A classic libpcap 2.4 file.
 *
 * In capture order: the buffer can hold frames from several adapters that
 * arrived out of order (the ordering window only covers thread skew), and a
 * file is forever, so it is sorted here. Stable, so equal stamps keep
 * frame-number order. The header's link type is the first frame's - see
 * `writers/pcap.ts` for why it is read and not assumed.
 */
export function generatePcapBinary(packets: readonly Packet[]): Blob {
  const ordered = [...packets].sort((a, b) => a.tsUs - b.tsUs);
  const writer = new PcapWriter();
  return chunksToBlob([...writer.write(ordered), ...writer.finish()], PCAP_MIME);
}

const UTF8 = new TextDecoder();

/**
 * The JSON export (`writers/json.ts`, version 2) as one string.
 *
 * The field names are the ones `exportSchema` recognises, and `epoch` is
 * present, so a JSON export re-imports through the same evaluator as a CSV.
 */
export function exportToJson(packets: readonly Packet[], includeRawBytes = false, meta?: CaptureMeta): string {
  const writer = new JsonWriter({ includeRawBytes, meta });
  const bytes = concatChunks([...writer.write(packets), ...writer.finish()]);
  return UTF8.decode(bytes);
}
