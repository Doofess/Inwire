/**
 * TCP's per-frame analysis rows, every frame against the reference.
 *
 *   npx tsx scripts/parity/tcp-analysis-rows.ts
 *
 * `tree-coverage.ts` asks whether a field appears anywhere in a capture, and
 * these all did - which hid that each was drawn on the wrong frames:
 * - **[Next Sequence Number]** was left off every bare ACK, 40% of `inwire`.
 * - **[iRTT]** appeared only on the handshake's ACK; the reference prints the
 *   connection's first RTT in every SEQ/ACK analysis it draws.
 * - **[Bytes in flight] and [Bytes sent since last PSH flag]** followed an
 *   older method: in flight was `nextSeq - lastAck` on any data segment, and
 *   the push count was reported only on a PSH. packet-tcp.c spans the
 *   unacknowledged segments less the peer's SACKs, only while an ACK has made
 *   the direction measurable, and reports the running push count beside it.
 * - **[SEQ/ACK analysis]** was dropped when empty, where the reference draws
 *   it whenever it holds analysis for the frame.
 * - **[Window size scaling factor]** was drawn on SYNs, which offer the scale
 *   rather than apply it.
 *
 * Each row's value is compared with tshark's, frame for frame, on every TCP
 * fixture. Skips cleanly without tshark or the fixtures.
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

/**
 * The rows, and how a value is compared. iRTT is held to a microsecond: the
 * analysis clock here is microseconds, so on a nanosecond capture the RTT
 * the reference prints to 100 ns is rounded - a known limit of this build,
 * not of the rule being tested.
 */
const ROWS: { abbrev: string; same?: (ours: string, ref: string) => boolean }[] = [
  { abbrev: 'tcp.nxtseq' },
  { abbrev: 'tcp.analysis', same: (o, r) => (o === '') === (r === '') },
  { abbrev: 'tcp.analysis.initial_rtt', same: (o, r) => (o === '') === (r === '') && (o === '' || Math.abs(Number(o) - Number(r)) < 1e-6) },
  { abbrev: 'tcp.analysis.bytes_in_flight' },
  { abbrev: 'tcp.analysis.push_bytes_sent' },
  { abbrev: 'tcp.window_size_scalefactor' },
  { abbrev: 'tcp.window_size' },
];

/** The first row of each abbrev, as a string; a present row with no value reads as "present". */
function rowsOf(packet: Packet): Map<string, string> {
  const out = new Map<string, string>();
  const walk = (fields: readonly ProtocolField[]) => {
    for (const f of fields) {
      if (f.abbrev !== undefined && !out.has(f.abbrev)) {
        out.set(f.abbrev, f.value === '' ? 'present' : String(f.value).replace(/ seconds$/, ''));
      }
      if (f.children) walk(f.children);
    }
  };
  for (const layer of packet.layers ?? []) walk(layer.fields);
  return out;
}

const env = { ...process.env, WIRESHARK_CONFIG_DIR: path.join(root, 'scripts', 'wireshark-profile') };
for (const file of FIXTURES) {
  const name = path.basename(file);
  // `tcp.analysis` is FT_NONE: present prints as nothing, so its presence is
  // asked by display filter instead.
  const fields = ROWS.filter((r) => r.abbrev !== 'tcp.analysis');
  const out = spawnSync(tshark, ['-n', '-r', file, '-T', 'fields', '-E', 'occurrence=f',
    '-e', 'frame.number', ...fields.flatMap((r) => ['-e', r.abbrev])],
  { encoding: 'utf8', env, maxBuffer: 1 << 30 }).stdout.trim().split(/\r?\n/);
  const analysed = new Set(spawnSync(tshark, ['-n', '-r', file, '-Y', 'tcp.analysis', '-T', 'fields', '-e', 'frame.number'],
    { encoding: 'utf8', env, maxBuffer: 1 << 30 }).stdout.trim().split(/\r?\n/).filter(Boolean).map(Number));

  const { packets } = await PcapService.parseCaptureFile(
    new File([readFileSync(file)], name), Number.POSITIVE_INFINITY, true);
  const differ = new Map<string, string[]>();
  packets.forEach((packet, i) => {
    const cols = (out[i] ?? '').split('\t').slice(1);
    const mine = rowsOf(packet);
    for (const row of ROWS) {
      const ref = row.abbrev === 'tcp.analysis'
        ? (analysed.has(packet.id) ? 'present' : '')
        : cols[fields.indexOf(row)] ?? '';
      const ours = mine.get(row.abbrev) ?? '';
      const same = row.same ? row.same(ours, ref) : ours === ref;
      if (!same) (differ.get(row.abbrev) ?? differ.set(row.abbrev, []).get(row.abbrev)!)
        .push(`frame ${packet.id}: this build "${ours}", the reference "${ref}"`);
    }
  });
  for (const row of ROWS) {
    const d = differ.get(row.abbrev) ?? [];
    check(`${name}: ${row.abbrev} matches the reference on every frame`, d.length === 0,
      `${d.length} differ, e.g.\n        ${d.slice(0, 4).join('\n        ')}`);
  }
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All TCP analysis row checks passed.');
process.exit(0);
