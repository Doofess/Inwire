/**
 * The gate for rebuilding a frame's tree from its own record (ADR 0049).
 *
 *   npx tsx scripts/pipeline/revisit.ts
 *
 * Every frame of every real fixture is dissected twice. First as it arrives,
 * in order, with the real trackers behind a `FrameRecorder` - which is exactly
 * what the app does, plus a record of what the trackers said. Then each frame
 * alone, from its bytes and its record, with a `FrameRevisit` in the trackers'
 * place. The two trees must render identically, for every frame.
 *
 * There are exactly two acceptable outcomes per frame, and the whole point of
 * the gate is that there is no third:
 *
 * - **equal** - the revisit gave back the tree arrival built;
 * - **miss** - the revisit could not, and said so with `RecordMiss`. The app
 *   then builds that tree another way.
 *
 * A revisit that finishes with a DIFFERENT tree is a confident wrong answer
 * about a frame somebody is looking at, and is the one thing that fails this
 * script. Misses are counted by reason and printed; which reasons are allowed
 * narrows phase by phase until none are.
 *
 * Also printed, not asserted: what the records cost - bytes per frame raw and
 * deflated in the store's own 4,096-frame chunks at its own level.
 *
 * Real captures only (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { deflateSync } from 'fflate';
import { PcapService, decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { applyInfoPatch } from '../../src/services/dissect/infoPatch';
import { withDissectEnv } from '../../src/services/dissect/dissectEnv';
import {
  FrameRecorder, FrameRevisit, RecordMiss, recordComposition, recordRefs,
} from '../../src/services/dissect/frameRecord';
import type { InfoPatch } from '../../src/services/dissect/types';
import type { Packet, ProtocolLayer } from '../../src/types/packet';

const FIXTURES: { name: string; path: string; optional?: boolean }[] = [
  { name: 'inwire', path: 'test/fixtures/inwire_capture_1788478187989.pcap' },
  { name: 'bulk', path: 'test/fixtures/bulk_capture_1788426090876.pcap' },
  { name: 'icmpErrors', path: 'test/fixtures/icmp_errors_capture_1790359378632.pcapng', optional: true },
];

/** The store's chunk size and deflate level (chunkCodec.ts, captureWriter.ts). */
const CHUNK_FRAMES = 4096;
const STORE_LEVEL = 6;

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)?.slice(0, 400)}`);
    console.log(`        actual   ${JSON.stringify(actual)?.slice(0, 400)}`);
  }
}

/** A tree, as a string, so a diff points at the row that moved. */
function render(layers: ProtocolLayer[]): string {
  const lines: string[] = [];
  const visit = (fields: ProtocolLayer['fields'], depth: number) => {
    for (const f of fields) {
      lines.push(`${'  '.repeat(depth)}${f.name}: ${String(f.value)}`);
      if (f.children) visit(f.children, depth + 1);
    }
  };
  for (const layer of layers) {
    lines.push(`${layer.name} | ${layer.summary}`);
    visit(layer.fields, 1);
  }
  return lines.join('\n');
}

/** The first line two renders differ on, with a little context. */
function firstDifference(want: string, got: string): string {
  const a = want.split('\n');
  const b = got.split('\n');
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] !== b[i]) return `line ${i + 1}: arrival "${a[i] ?? '(none)'}" / revisit "${b[i] ?? '(none)'}"`;
  }
  return '(identical)';
}

function percentile(sorted: number[], p: number): number {
  return sorted.length === 0 ? 0 : sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))];
}

interface Arrived {
  packet: Packet;
  record: Uint8Array;
  input: { bytes: Uint8Array; tsUs: number; relativeTime: number; timeDelta: number; origLen: number; linktype: number };
}

async function runFixture(name: string, path: string) {
  const file = new File([new Uint8Array(readFileSync(path))], `${name}.pcap`);
  const { frames } = await PcapService.extractFrames(file, Number.POSITIVE_INFINITY);
  const host = PcapService.inferHostFromFrames(frames);

  // --- arrival: the importer's own loop, with a recorder in front ------------
  const recorder = new FrameRecorder({
    tcp: new TcpStreamTracker(), quic: new QuicFlowTracker(), dns: new DnsTracker(),
    icmp: new IcmpEchoTracker(), l3: new L3Tracker(),
  });
  const src = recorder.sources;
  const arrived: Arrived[] = [];
  const patchesFor = new Map<number, InfoPatch[]>();
  let baseNanos: bigint | null = null;
  let prevNanos: bigint | null = null;
  const t0 = performance.now();
  for (const frame of frames) {
    if (baseNanos === null) baseNanos = frame.tsNanos;
    const relativeTime = Number(frame.tsNanos - baseNanos) / 1e9;
    const timeDelta = prevNanos === null ? 0 : Number(frame.tsNanos - prevNanos) / 1e9;
    prevNanos = frame.tsNanos;
    const tsUs = Number(frame.tsNanos / 1000n);
    const id = arrived.length + 1;

    recorder.begin();
    const { packet, icmpMatchedRequestFrameId, infoPatches } = withDissectEnv(src.env, () =>
      decodeRawEthernetPacket(frame.rawBytes, id, tsUs, relativeTime, timeDelta, frame.origLen,
        src.tcp, src.icmp, src.quic, src.dns, undefined, frame.linktype, src.l3, host));
    arrived.push({
      packet, record: recorder.end(),
      input: { bytes: frame.rawBytes, tsUs, relativeTime, timeDelta, origLen: frame.origLen, linktype: frame.linktype },
    });
    if (icmpMatchedRequestFrameId !== undefined) {
      arrived[icmpMatchedRequestFrameId - 1].packet.info += ` (reply in ${packet.id})`;
    }
    for (const patch of infoPatches ?? []) {
      applyInfoPatch(arrived[patch.frameId - 1].packet, patch);
      const list = patchesFor.get(patch.frameId) ?? [];
      list.push(patch);
      patchesFor.set(patch.frameId, list);
    }
  }
  const arrivalMs = performance.now() - t0;

  // --- revisit: every frame alone ---------------------------------------------
  let equal = 0;
  let wrong = 0;
  const misses = new Map<string, number>();
  const wrongExamples: string[] = [];
  const t1 = performance.now();
  for (const { packet, record, input } of arrived) {
    try {
      // Other frames' bytes, as the store hands them over: by id, and only for
      // the frames the record names.
      const named = new Set(recordRefs(record));
      const revisit = new FrameRevisit(record, (frame) =>
        (named.has(frame) ? arrived[frame - 1]?.input.bytes : undefined));
      const rs = revisit.sources;
      const { packet: again } = withDissectEnv(rs.env, () =>
        decodeRawEthernetPacket(input.bytes, packet.id, input.tsUs, input.relativeTime, input.timeDelta,
          input.origLen, rs.tcp, rs.icmp, rs.quic, rs.dns, undefined, input.linktype, rs.l3, host));
      revisit.finish();
      for (const patch of patchesFor.get(packet.id) ?? []) applyInfoPatch(again, patch);
      const want = render(packet.layers);
      const got = render(again.layers);
      if (want === got) {
        equal += 1;
      } else {
        wrong += 1;
        if (wrongExamples.length < 5) wrongExamples.push(`frame ${packet.id}: ${firstDifference(want, got)}`);
      }
    } catch (error) {
      if (!(error instanceof RecordMiss)) throw error;
      misses.set(error.reason, (misses.get(error.reason) ?? 0) + 1);
    }
  }
  const revisitMs = performance.now() - t1;

  // --- what the records cost ----------------------------------------------------
  const sizes = arrived.map((a) => a.record.length).sort((a, b) => a - b);
  const raw = sizes.reduce((s, n) => s + n, 0);
  let deflated = 0;
  for (let i = 0; i < arrived.length; i += CHUNK_FRAMES) {
    const chunk = arrived.slice(i, i + CHUNK_FRAMES);
    const joined = new Uint8Array(chunk.reduce((s, a) => s + a.record.length, 0));
    let at = 0;
    for (const a of chunk) { joined.set(a.record, at); at += a.record.length; }
    deflated += deflateSync(joined, { level: STORE_LEVEL }).length;
  }
  const missed = [...misses.values()].reduce((s, n) => s + n, 0);
  const byQuestion = new Map<string, number>();
  for (const a of arrived) {
    for (const [question, bytes] of recordComposition(a.record)) {
      byQuestion.set(question, (byQuestion.get(question) ?? 0) + bytes);
    }
  }

  console.log(`\n--- ${name}: ${arrived.length.toLocaleString()} frames ---`);
  console.log(`      equal ${equal.toLocaleString()}, missed ${missed.toLocaleString()}, wrong ${wrong}`);
  for (const [reason, count] of [...misses].sort((a, b) => b[1] - a[1])) {
    console.log(`        miss ${count.toString().padStart(6)}  ${reason}`);
  }
  console.log(`      record: mean ${(raw / arrived.length).toFixed(1)} B, p99 ${percentile(sizes, 0.99)} B, `
    + `max ${sizes[sizes.length - 1]} B raw; ${(deflated / arrived.length).toFixed(1)} B/frame deflated`);
  const heaviest = [...byQuestion].sort((a, b) => b[1] - a[1]).slice(0, 6);
  console.log(`      raw bytes by question: ${heaviest
    .map(([q, b]) => `${q} ${((100 * b) / raw).toFixed(0)}%`).join(', ')}`);
  console.log(`      arrival ${arrivalMs.toFixed(0)} ms, revisit of every frame ${revisitMs.toFixed(0)} ms `
    + `(${((revisitMs * 1000) / arrived.length).toFixed(1)} us a frame)`);
  for (const example of wrongExamples) console.log(`        WRONG ${example}`);

  check(`${name}: no frame is revisited into a different tree`, wrong, 0);
  check(`${name}: every frame either matches or says why it cannot`, equal + missed + wrong, arrived.length);
}

async function main() {
  let ran = 0;
  for (const { name, path, optional } of FIXTURES) {
    if (!existsSync(path)) {
      console.log(`SKIP  ${name}: ${path} is not present${optional ? ' (optional)' : ''} - see test/fixtures/README.md`);
      continue;
    }
    await runFixture(name, path);
    ran += 1;
  }
  if (ran === 0) console.log('\nAll revisit checks passed (skipped).');
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All revisit checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
