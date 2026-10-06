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
 * - **Wireshark 4.6's contiguous-streams counts** - how many runs of sequence
 *   space each side has been seen to send, one when nothing is missing - did
 *   not exist here.
 * - **[iRTT] and the ACK RTT** were rounded to the microsecond on a capture
 *   that measured nanoseconds.
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
 * The rows, and how a value is compared. The two RTTs are held to the
 * nanosecond, which is what the key-log capture measures: the analysis keeps
 * a frame's nanoseconds (`TcpSegment.nsRemainder`) where it used to round
 * them to the microsecond.
 */
const sameSeconds = (o: string, r: string) => (o === '') === (r === '') && (o === '' || Math.abs(Number(o) - Number(r)) < 5e-10);
const ROWS: { abbrev: string; same?: (ours: string, ref: string) => boolean }[] = [
  { abbrev: 'tcp.nxtseq' },
  { abbrev: 'tcp.analysis', same: (o, r) => (o === '') === (r === '') },
  { abbrev: 'tcp.analysis.initial_rtt', same: sameSeconds },
  { abbrev: 'tcp.analysis.ack_rtt', same: sameSeconds },
  { abbrev: 'tcp.analysis.bytes_in_flight' },
  { abbrev: 'tcp.analysis.push_bytes_sent' },
  { abbrev: 'tcp.window_size_scalefactor' },
  { abbrev: 'tcp.window_size' },
  { abbrev: 'tcp.stream.client.contiguity_count' },
  { abbrev: 'tcp.stream.server.contiguity_count' },
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

/**
 * Reassembly blocks known to list fewer segments than the reference, each
 * with why. Named one by one so a new difference fails rather than hides.
 */
const KNOWN_BLOCKS: Record<string, string> = {
  'inwire_capture_1788478187989.pcap#2410':
    'the record was filled in by retransmitted segments (2393-2403); TLS reads an out-of-order '
    + 'segment against a copy of its cursor, so they are not credited - the length and data agree',
};

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

  // **Reassembly, held where it is drawn.** `tcp.segment_data` - this segment's
  // share of each PDU its desegmentation handles - and the `[N Reassembled TCP
  // Segments]` block. The reference reassembles HTTP for itself and resyncs a
  // stream picked up mid-record differently, so it draws some this build does
  // not; every one this build DOES draw must be the reference's, byte counts
  // and segment lists exactly. Coverage is printed, not held.
  const reassembly = spawnSync(tshark, ['-n', '-r', file, '-T', 'fields', '-E', 'occurrence=a', '-E', 'aggregator=|',
    '-e', 'tcp.segment_data', '-e', 'tcp.segment', '-e', 'tcp.reassembled.length'],
  { encoding: 'utf8', env, maxBuffer: 1 << 30 }).stdout.split(/\r?\n/);
  let shown = 0;
  let referenceShows = 0;
  const wrong: string[] = [];
  packets.forEach((packet, i) => {
    const [data = '', segments = '', length = ''] = (reassembly[i] ?? '').replace(/\r$/, '').split('\t');
    const refData = data ? data.split('|').map((hex) => hex.length / 2) : [];
    const ours = { data: [] as number[], segments: [] as unknown[], lengths: [] as unknown[] };
    const walk = (fields: readonly ProtocolField[]) => {
      for (const f of fields) {
        if (f.abbrev === 'tcp.segment_data') ours.data.push(Number(/\((\d+) bytes?\)/.exec(f.name)?.[1]));
        if (f.abbrev === 'tcp.segment') ours.segments.push(f.value);
        if (f.abbrev === 'tcp.reassembled.length') ours.lengths.push(f.value);
        if (f.children) walk(f.children);
      }
    };
    const tcp = packet.layers?.find((l) => l.name === 'Transmission Control Protocol');
    if (tcp) walk(tcp.fields);
    if (refData.length > 0 || segments) referenceShows++;
    if (ours.data.length === 0 && ours.segments.length === 0) return;
    shown++;
    if (ours.data.length > 0 && ours.data.join('|') !== refData.join('|')) {
      wrong.push(`frame ${packet.id}: segment data ${ours.data.join('|')}, the reference ${refData.join('|')}`);
    }
    const block = `${ours.segments.join(',')} / ${ours.lengths.join('|')}`;
    const refBlock = `${segments.replace(/\|/g, ',')} / ${length}`;
    if (ours.segments.length > 0 && block !== refBlock && KNOWN_BLOCKS[`${name}#${packet.id}`] === undefined) {
      wrong.push(`frame ${packet.id}: reassembled ${block}, the reference ${refBlock}`);
    }
  });
  check(`${name}: every segment-data row and reassembly block drawn is the reference's `
    + `(${shown} frames, of the ${referenceShows} the reference marks)`, wrong.length === 0,
  `${wrong.length} differ, e.g.\n        ${wrong.slice(0, 4).join('\n        ')}`);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All TCP analysis row checks passed.');
process.exit(0);
