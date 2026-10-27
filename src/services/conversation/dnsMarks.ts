/**
 * The ladder's DNS marks (ADR 0055, stage 3): `no answer` on a query nothing
 * answered, the rcode's name on an error answer. Paired by `dns.id` in frame
 * order, with the rules of the digest's tally (`foldDns`), except that a
 * repeated query marks only its last copy. A query still inside
 * `DNS_WAIT_SECONDS` of the capture's end is waiting and gets nothing, unless
 * the capture is `finished` (a file, or one that stopped or paused): no answer
 * can arrive any more, so every open query is marked.
 */
import type { Packet } from '../../types/packet';
import { fieldValue } from '../dissect/fieldAccess';
import { DNS_RCODE_NAMES } from '../dissectors/dnsRecords';
import { DNS_WAIT_SECONDS } from './flowSummary';

const num = (row: Packet, abbrev: string): number | undefined => {
  const v = fieldValue(row, abbrev);
  return typeof v === 'number' ? v : undefined;
};

export function dnsMarks(frames: readonly Packet[], captureEnd: number, finished = false): Map<number, string> {
  const marks = new Map<number, string>();
  const open = new Map<number, Packet>();
  for (const row of frames) {
    const id = num(row, 'dns.id');
    const response = num(row, 'dns.flags.response');
    if (id === undefined || response === undefined) continue;
    if (response === 0) { open.set(id, row); continue; }
    open.delete(id);
    const rcode = num(row, 'dns.flags.rcode') ?? 0;
    if (rcode !== 0) marks.set(row.id, DNS_RCODE_NAMES[rcode] ?? 'error');
  }
  for (const q of open.values()) {
    if (finished || captureEnd - q.relativeTime >= DNS_WAIT_SECONDS) marks.set(q.id, 'no answer');
  }
  return new Map([...marks].sort((a, b) => a[0] - b[0]));
}
