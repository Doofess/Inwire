/**
 * The pcapng writer's one-shot entry point.
 *
 * The writer itself is `export/writers/pcapng.ts`, which takes a capture a
 * page at a time so a whole-capture export never holds it. This is the same
 * writer handed one array, for a caller that has one: the frames are sorted by
 * capture time first, as the classic writer sorts them - the buffer can hold
 * frames from several adapters that arrived out of order, and a file is
 * forever. Stable, so frames sharing a timestamp keep their frame-number order.
 */
import type { Packet } from '../types/packet';
import { PcapngWriter, PCAPNG_MIME, type PcapngOptions } from './export/writers/pcapng';
import { chunksToBlob } from './export/writers/writer';

export {
  DSB_SECRETS_TYPE_TLS_KEY_LOG,
  type PcapngInterface,
  type PcapngOptions,
} from './export/writers/pcapng';

export function generatePcapNg(packets: readonly Packet[], options: PcapngOptions = {}): Blob {
  const writer = new PcapngWriter(options);
  const ordered = [...packets].sort((a, b) => a.tsUs - b.tsUs);
  return chunksToBlob([...writer.write(ordered), ...writer.finish()], PCAPNG_MIME);
}
