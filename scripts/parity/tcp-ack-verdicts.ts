/**
 * TCP's ACK verdicts in the tree, frame for frame, against the reference.
 *
 *   npx tsx scripts/parity/tcp-ack-verdicts.ts
 *
 * Four rows a network engineer reads an ACK by, which this build computed and
 * did not draw, or did not compute:
 * - **`[Duplicate ACK #]` and `[Duplicate to the ACK in frame]`** - the count
 *   that makes three of them a fast retransmit, and the frame they repeat. They
 *   were filter values only.
 * - **`tcp.analysis.partial_ack`** - the ACK covers part of a segment, which is
 *   what a receiver coalescing segments (GRO) does. Computed, never drawn.
 * - **`tcp.analysis.ambiguous_ack`** - the segment it acknowledges was sent more
 *   than once, so Karn's rule says its RTT means nothing. Not computed at all.
 *
 * `tree-coverage.ts` sees an abbrev present somewhere in a capture; this holds
 * WHICH frames carry each, and the duplicate's number and frame, to tshark's
 * own answer on every TCP fixture. Skips cleanly without tshark or fixtures.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { PcapService } from '../../src/services/pcapParser';
import { findWiresharkTool } from '../export/realCaptures';
import type { Packet, ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const tshark = findWiresharkTool('tshark');
if (tshark === null) {
  console.log('SKIP  tshark not found');
  process.exit(0);
}
const FIXTURES = [
  'inwire_capture_1788478187989.pcap',
  'bulk_capture_1788426090876.pcap',
  'keylog_capture_1790455330535.pcapng',
].map((f) => path.join(root, 'test', 'fixtures', f)).filter((f) => existsSync(f));
if (FIXTURES.length === 0) {
  console.log('SKIP  no fixture captures (test/fixtures/README.md)');
  process.exit(0);
}

/** One frame's verdicts as a comparable string: `P`, `A`, `dup#2@233`. */
const verdicts = (partial: boolean, ambiguous: boolean, dupNum?: unknown, dupFrame?: unknown) =>
  [partial ? 'P' : '', ambiguous ? 'A' : '', dupNum !== undefined ? `dup#${dupNum}@${dupFrame}` : '']
    .filter(Boolean).join(' ');

function rowsOf(packet: Packet): Map<string, unknown> {
  const out = new Map<string, unknown>();
  const walk = (fields: readonly ProtocolField[]) => {
    for (const f of fields) {
      if (f.abbrev !== undefined && !out.has(f.abbrev)) out.set(f.abbrev, f.value);
      if (f.children) walk(f.children);
    }
  };
  for (const layer of packet.layers ?? []) walk(layer.fields);
  return out;
}

const env = { ...process.env, WIRESHARK_CONFIG_DIR: path.join(root, 'scripts', 'wireshark-profile') };
for (const file of FIXTURES) {
  const name = path.basename(file);
  const out = spawnSync(tshark, ['-n', '-r', file, '-T', 'fields', '-E', 'occurrence=f',
    '-e', 'frame.number', '-e', 'tcp.analysis.partial_ack', '-e', 'tcp.analysis.ambiguous_ack',
    '-e', 'tcp.analysis.duplicate_ack_num', '-e', 'tcp.analysis.duplicate_ack_frame'],
  { encoding: 'utf8', env, maxBuffer: 1 << 30 }).stdout;
  const theirs = new Map<number, string>();
  for (const line of out.trim().split(/\r?\n/)) {
    const [n, partial, ambiguous, dupNum, dupFrame] = line.split('\t');
    // A present FT_NONE field prints as `1`, an absent one as nothing.
    theirs.set(Number(n), verdicts(partial === '1', ambiguous === '1', dupNum || undefined, dupFrame || undefined));
  }

  const { packets } = await PcapService.parseCaptureFile(
    new File([readFileSync(file)], name), Number.POSITIVE_INFINITY, true);
  const counts = { P: [0, 0], A: [0, 0], dup: [0, 0] };
  const differ: string[] = [];
  for (const packet of packets) {
    const rows = rowsOf(packet);
    const ours = verdicts(rows.has('tcp.analysis.partial_ack'), rows.has('tcp.analysis.ambiguous_ack'),
      rows.get('tcp.analysis.duplicate_ack_num'), rows.get('tcp.analysis.duplicate_ack_frame'));
    const ref = theirs.get(packet.id) ?? '';
    for (const key of ['P', 'A', 'dup'] as const) {
      if (ours.split(' ').some((t) => t.startsWith(key))) counts[key][0]++;
      if (ref.split(' ').some((t) => t.startsWith(key))) counts[key][1]++;
    }
    if (ours !== ref) differ.push(`frame ${packet.id}: this build "${ours}", the reference "${ref}"`);
  }
  check(`${name}: every frame's ACK verdicts match the reference `
    + `(partial ${counts.P[1]}, ambiguous ${counts.A[1]}, duplicate ${counts.dup[1]})`,
  differ.length === 0, `${differ.length} differ:\n        ${differ.slice(0, 5).join('\n        ')}`);
  check(`${name}: the fixture exercises them (${counts.P[1] + counts.A[1] + counts.dup[1]} verdicts)`,
    counts.P[1] + counts.A[1] + counts.dup[1] > 0);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All TCP ACK verdict checks passed.');
process.exit(0);
