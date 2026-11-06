/**
 * The page's read of one `frames` message's pack, with the failure handled
 * (`PipelineClient.receive`).
 */
import type { Packet } from '../types/packet';
import type { PackedRows, PackReader } from './pipeline/rowPack';

export type PackReadOutcome = { ok: true; packets: Packet[] } | { ok: false; message: string };

export function readPackedBatch(
  reader: Pick<PackReader, 'read' | 'reset'>,
  rows: PackedRows,
  /** Tells the Worker `count` rows are taken (`PipelineClient.rowsTaken`). */
  acknowledge: (count: number) => void,
): PackReadOutcome {
  try {
    return { ok: true, packets: reader.read(rows) };
  } catch (error) {
    // The Worker counts these rows as owed until the page says it has taken them
    // (`flow.rowsPosted`), and a batch that cannot be shown is never committed, so
    // nothing else would say it: acknowledge them here or the flow's debt never
    // clears. The reader may have been left holding packs for rows that were never
    // read; forget them, so the next batch is not judged by this one's leftovers.
    acknowledge(rows.order.length / 2);
    reader.reset();
    return { ok: false, message: error instanceof Error ? error.message : String(error) };
  }
}
