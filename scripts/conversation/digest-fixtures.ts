/**
 * The stream digest, held to the real fixtures by two oracles neither of which
 * this module wrote (ADR 0055).
 *
 *   npx tsx scripts/conversation/digest-fixtures.ts
 *
 * 1. `ConversationTable` at the TCP level over the same rows. The digest keys
 *    by `tcp.stream` and the table by five-tuple, so a reused port pair can be
 *    two streams here and one conversation there: summaries are grouped by
 *    five-tuple and summed before the comparison.
 * 2. tshark's `tcp.completeness`, a bitmask of what the reference saw in a
 *    stream (1 SYN, 2 SYN-ACK, 4 ACK, 8 DATA, 16 FIN, 32 RST). It counts flags
 *    and not states, so only implications are checked, never equality.
 *
 * Skips cleanly without the untracked fixtures; the tshark oracle skips alone
 * without tshark. Each fixture also prints a census, outcome -> streams.
 */
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { PcapService } from '../../src/services/pcapParser';
import { ConversationTable } from '../../src/services/statistics';
import { StreamDigest, type StreamSummary } from '../../src/services/conversation/streamDigest';
import { findWiresharkTool } from '../export/realCaptures';

const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/bulk_capture_1788426090876.pcap',
];

let failures = 0;
function check(name: string, ok: boolean, detail?: string): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${detail}`);
}

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

const missing = FIXTURES.filter((f) => !existsSync(path.join(root, f)));
if (missing.length > 0) {
  console.log(`SKIP  fixture missing: ${missing[0]} (see test/fixtures/README.md)`);
  process.exit(0);
}

const tshark = findWiresharkTool('tshark');
const env = { ...process.env, WIRESHARK_CONFIG_DIR: path.join(root, 'scripts', 'wireshark-profile') };

const CLOSE_OUTCOMES = new Set(['closed cleanly', 'closing', 'half-closed by client', 'half-closed by server']);
const RESET_OUTCOMES = new Set(['refused', 'reset by client', 'reset by server']);

/** A five-tuple with the lower `address:port` first, so both directions agree. */
function tupleKey(a: { address: string; port: number }, b: { address: string; port: number }): { key: string; swapped: boolean } {
  const x = `${a.address}|${a.port}`;
  const y = `${b.address}|${b.port}`;
  return x <= y ? { key: `${x}|${y}`, swapped: false } : { key: `${y}|${x}`, swapped: true };
}

interface Sum { lowToHigh: [number, number]; highToLow: [number, number]; start: number; end: number }

for (const rel of FIXTURES) {
  const file = path.join(root, rel);
  const name = path.basename(file).split('_')[0];
  const { packets } = await PcapService.parseCaptureFile(
    new File([new Uint8Array(readFileSync(file))], path.basename(file)), 1_000_000);

  const digest = new StreamDigest();
  for (const p of packets) digest.feed(p);
  const summaries: StreamSummary[] = digest.changedSince(0);

  // ---- Census.
  const census = new Map<string, number>();
  for (const s of summaries) census.set(s.outcome, (census.get(s.outcome) ?? 0) + 1);
  const joined = summaries.filter((s) => s.joinedMidStream).length;
  const line = [...census].sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', ');
  console.log(`      ${name}: ${summaries.length} streams (${joined} joined mid-stream): ${line}`);
  check(`${name}: the digest found streams`, summaries.length > 0);

  // ---- Oracle 1: ConversationTable.
  const table = new ConversationTable('tcp');
  for (const p of packets) table.add(p);
  const ours = new Map<string, Sum>();
  for (const s of summaries) {
    const { key, swapped } = tupleKey(s.client, s.server);
    // client -> server is toServer; map onto low -> high by the ordering.
    const lowToHigh = swapped ? s.toClient : s.toServer;
    const highToLow = swapped ? s.toServer : s.toClient;
    const sum = ours.get(key) ?? { lowToHigh: [0, 0], highToLow: [0, 0], start: Infinity, end: -Infinity };
    sum.lowToHigh[0] += lowToHigh.packets; sum.lowToHigh[1] += lowToHigh.bytes;
    sum.highToLow[0] += highToLow.packets; sum.highToLow[1] += highToLow.bytes;
    sum.start = Math.min(sum.start, s.start);
    sum.end = Math.max(sum.end, s.end);
    ours.set(key, sum);
  }
  const theirs = new Map<string, Sum>();
  for (const c of table.result()) {
    const a = { address: c.addressA, port: c.portA! };
    const b = { address: c.addressB, port: c.portB! };
    const { key, swapped } = tupleKey(a, b);
    const sum: Sum = {
      lowToHigh: swapped ? [c.packetsBtoA, c.bytesBtoA] : [c.packetsAtoB, c.bytesAtoB],
      highToLow: swapped ? [c.packetsAtoB, c.bytesAtoB] : [c.packetsBtoA, c.bytesBtoA],
      start: c.startRel, end: c.startRel + c.duration,
    };
    theirs.set(key, sum);
  }
  const diffs: string[] = [];
  for (const [key, t] of theirs) {
    const o = ours.get(key);
    if (o === undefined) { diffs.push(`${key}: no digest streams`); continue; }
    if (o.lowToHigh.join() !== t.lowToHigh.join() || o.highToLow.join() !== t.highToLow.join()) {
      diffs.push(`${key}: digest ${o.lowToHigh}/${o.highToLow}, table ${t.lowToHigh}/${t.highToLow}`);
    } else if (Math.abs(o.start - t.start) > 1e-9 || Math.abs(o.end - t.end) > 1e-9) {
      diffs.push(`${key}: digest ${o.start}..${o.end}, table ${t.start}..${t.end}`);
    }
  }
  for (const key of ours.keys()) if (!theirs.has(key)) diffs.push(`${key}: not in the table`);
  check(`${name}: packets, bytes and times per direction equal ConversationTable (${theirs.size} conversations)`,
    diffs.length === 0, `${diffs.length} differ, e.g.\n        ${diffs.slice(0, 4).join('\n        ')}`);

  // ---- Oracle 2: tshark's completeness.
  if (tshark === null) {
    console.log('SKIP  tshark not found: completeness cross-check');
    continue;
  }
  const out = spawnSync(tshark, ['-n', '-r', file, '-Y', 'tcp', '-T', 'fields',
    '-e', 'frame.number', '-e', 'tcp.completeness', '-e', 'tcp.flags.fin', '-e', 'tcp.flags.reset'],
  { encoding: 'utf8', env, maxBuffer: 1 << 30 }).stdout.trim().split(/\r?\n/);
  // A stream's mask is every bit the reference reported on any of its frames.
  // Not the last frame's value: tshark prints the completeness a frame sees
  // BEFORE that frame's own flags are folded in, so a stream that ends on its
  // RST reports the mask without bit 32 on that frame (inwire frame 3128 reads
  // 15 while the frame itself reads tcp.flags.reset=True; in stream 2 the
  // RST on frame 1280 reads 28 and the next frame 60). The frame's own
  // FIN and RST flags are therefore added, read from tshark's own flag fields.
  const frameMask = new Map<number, number>();
  for (const l of out) {
    const [frame, value, fin, rst] = l.split('\t');
    if (frame === undefined || value === undefined || value === '') continue;
    // A frame can carry the field more than once (tunnels); the last is the stream's own.
    const v = Number(value.split(',').pop());
    if (Number.isNaN(v)) continue;
    const own = (fin?.split(',').pop() === 'True' ? 16 : 0) | (rst?.split(',').pop() === 'True' ? 32 : 0);
    frameMask.set(Number(frame), v | own);
  }
  const completeness = new Map<number, number>();
  for (const p of packets) {
    const m = frameMask.get(p.id);
    if (m === undefined || p.streamId === undefined) continue;
    completeness.set(p.streamId, (completeness.get(p.streamId) ?? 0) | m);
  }

  const bad: string[] = [];
  let compared = 0;
  for (const s of summaries) {
    const mask = completeness.get(s.streamId);
    if (mask === undefined) continue;
    compared++;
    const why = (msg: string) => bad.push(`stream ${s.streamId} (frames ${s.firstId}-${s.lastId}, "${s.outcome}", mask ${mask}): ${msg}`);
    if (RESET_OUTCOMES.has(s.outcome) && (mask & 32) === 0) why('reset without the reference seeing an RST');
    if (CLOSE_OUTCOMES.has(s.outcome) && (mask & 16) === 0) why('closing without the reference seeing a FIN');
    if (s.joinedMidStream && (mask & 1) !== 0) why('joined mid-stream but the reference saw the SYN');
    if (s.outcome === 'no reply' && mask !== 1) why('no reply but the mask is not exactly SYN');
  }
  check(`${name}: outcomes agree with tshark's tcp.completeness (${compared} streams)`, bad.length === 0,
    `${bad.length} disagree, e.g.\n        ${bad.slice(0, 5).join('\n        ')}`);
}

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
