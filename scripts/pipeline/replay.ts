/**
 * Assertion tests for rebuilding a protocol tree from a conversation.
 *
 *   npx tsx scripts/pipeline/replay.ts
 *
 * Phase 11 stopped carrying a tree per frame: it is 10.6 kB against the
 * frame's own 1.2 kB, 91% of the cost of crossing the worker boundary and 89%
 * of the buffer's memory, for something one frame at a time is ever looked at
 * (docs/decisions/0007). The tree of the frame being looked at is rebuilt
 * instead, by dissecting its conversation again.
 *
 * The property that has to hold is exact equality: **a rebuilt tree is the
 * tree the eager pass produced.** That is not obvious and it is not free. A
 * frame's tree is not a function of its own bytes - the TLS record cursor, the
 * QUIC keys, the DNS and ICMP pairings and the TCP relative sequence numbers
 * are all state the frames before it built up - so a rebuild that gets the
 * conversation wrong produces a tree that is confidently, silently different
 * from what the same build showed a moment earlier.
 *
 * So this runs against the real fixture, parses it twice - once keeping every
 * tree, once rebuilding them one at a time - and diffs. Frames are chosen for
 * where they sit in a conversation, not at random: the interesting ones are
 * deep in a TCP stream, inside a TLS session, on a QUIC flow, and on no stream
 * at all.
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { dissectReplay } from '../../src/services/pipeline/replay';
import { inferHostIdentity } from '../../src/services/hostIdentity';
import { streamPackets, targetForPacket } from '../../src/services/followStream';
import type { ReplayFrame } from '../../src/services/pipeline/protocol';
import type { Packet, ProtocolLayer } from '../../src/types/packet';

const FIXTURE = 'test/fixtures/inwire_capture_1788478187989.pcap';

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
function checkTrue(name: string, condition: boolean) {
  check(name, condition, true);
}

/** The frames a rebuild of `packet`'s tree needs, oldest first. */
function bundleFor(packet: Packet, buffer: Packet[]): ReplayFrame[] {
  const target = targetForPacket(packet);
  const stream = target
    ? streamPackets(buffer, target).filter((p) => p.id <= packet.id)
    : [packet];
  return (stream.length > 0 ? stream : [packet]).map((p) => ({
    id: p.id,
    tsUs: p.tsUs,
    relativeTime: p.relativeTime,
    timeDelta: p.timeDelta,
    origLen: p.length,
    bytes: p.rawBytes,
  }));
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

async function main() {
  if (!existsSync(FIXTURE)) {
    console.log(`SKIP  ${FIXTURE} is not present (see test/fixtures/README.md)`);
    console.log('\nAll replay checks passed (skipped).');
    return;
  }

  const file = new File([new Uint8Array(readFileSync(FIXTURE))], 'fixture.pcap');
  const truth = await PcapService.parsePcapFileWithTrees(file);
  const buffer = truth.map((p) => ({ ...p, layers: [] as ProtocolLayer[] }));

  checkTrue('the fixture parsed', truth.length > 1000);
  checkTrue('the buffer this app keeps carries no trees',
    buffer.every((p) => p.layers.length === 0));
  checkTrue('...but every frame keeps its bytes',
    buffer.every((p) => p.rawBytes.length > 0 || p.length === 0));

  // --- the frames worth rebuilding ------------------------------------------
  // Chosen by what state they depend on, and each one reported so a failure
  // says which kind of conversation broke rather than which array index.
  const byProtocol = (want: string, minDepth: number): Packet | undefined => {
    const seen = new Map<number, number>();
    for (const p of truth) {
      if (!p.frameProtocols?.includes(want)) continue;
      const target = targetForPacket(p);
      const key = target ? `${target.addressA}:${target.portA}` : '';
      const depth = (seen.get(p.streamId ?? -1) ?? 0) + 1;
      seen.set(p.streamId ?? -1, depth);
      if (depth >= minDepth && key !== '') return p;
    }
    return undefined;
  };

  // Who took the capture. The importer works this out before it dissects
  // (`PcapService.inferHostFromFrames`) and the Worker holds the same value for
  // a live capture, so a replay that did not have it would be comparing a tree
  // built with the host against one built without - and the only rows that
  // differ are the checksum verdicts on frames this machine sent, which is a
  // difference easy to read as noise. `inferHostIdentity` caps itself at
  // `SCORING_FRAMES`, so passing the whole buffer scores the same prefix the
  // importer scored.
  const host = inferHostIdentity(truth) ?? undefined;

  const cases: { label: string; packet: Packet | undefined }[] = [
    { label: 'a TCP segment deep in its stream', packet: byProtocol('tcp', 20) },
    { label: 'a TLS record', packet: byProtocol('tls', 3) },
    { label: 'a QUIC frame', packet: byProtocol('quic', 5) },
    { label: 'a DNS message', packet: byProtocol('dns', 1) },
    { label: 'a frame on no stream at all', packet: truth.find((p) => targetForPacket(p) === null) },
  ];

  for (const { label, packet } of cases) {
    if (!packet) {
      console.log(`SKIP  ${label} - the fixture has none`);
      continue;
    }
    const frames = bundleFor(packet, buffer);
    // What a later frame told this one about itself, handed back rather than
    // re-derived - see `dissectReplay`'s `retroactive`.
    const responseIn = packet.fields?.['dns.response_in'];
    const retroactive = typeof responseIn === 'number'
      ? { frameId: packet.id, responseInFrame: responseIn }
      : undefined;
    const { layers } = dissectReplay(frames, false, packet.streamId, retroactive, host);
    check(`${label} (frame ${packet.id}, ${frames.length} replayed) rebuilds identically`,
      render(layers), render(packet.layers));
  }

  // --- the stream index -------------------------------------------------------
  // A tracker that has only ever seen one conversation calls it stream 0, and
  // the tree prints that number. Without the seed a replayed frame reports an
  // index belonging to some other conversation entirely - the kind of wrong
  // that reads as a fact.
  const tcpFrame = truth.find((p) => (p.streamId ?? 0) > 3 && p.frameProtocols?.includes('tcp'));
  if (tcpFrame) {
    const frames = bundleFor(tcpFrame, buffer);
    const unseeded = render(dissectReplay(frames, false, undefined, undefined, host).layers);
    const seeded = render(dissectReplay(frames, false, tcpFrame.streamId, undefined, host).layers);
    checkTrue('an unseeded replay gets the stream index wrong', unseeded !== seeded);
    check('...and a seeded one gets it right', seeded, render(tcpFrame.layers));
  }

  // --- a truncated replay says so ---------------------------------------------
  // The buffer forgets its oldest frames, so a conversation's beginning can be
  // gone. A tree rebuilt from the middle is not wrong about the bytes, but its
  // sequence numbers and reassembly are relative to where the replay could
  // start rather than to where the conversation did, and a reader cannot tell
  // by looking.
  const deep = byProtocol('tcp', 40);
  if (deep) {
    const frames = bundleFor(deep, buffer);
    const partial = dissectReplay(frames.slice(-5), true, deep.streamId, undefined, host);
    checkTrue('a replay that could not start at the beginning reports it', partial.truncated);
    checkTrue('...and says so in the tree rather than only to its caller',
      render(partial.layers).includes('[Reassembly context]'));
    checkTrue('a complete replay says nothing of the sort',
      !render(dissectReplay(frames, false, deep.streamId, undefined, host).layers).includes('[Reassembly context]'));
  }

  // --- degenerate inputs --------------------------------------------------------
  check('a replay of nothing is an empty tree, not a crash',
    dissectReplay([], false).layers.length, 0);
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All replay checks passed.');
  process.exit(0);
});
