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
import {
  dissectReplay, interfacesByLabel, seedsFor, NOT_AN_ADAPTER,
} from '../../src/services/pipeline/replay';
import { inferHostIdentity } from '../../src/services/hostIdentity';
import { streamPackets, targetForPacket } from '../../src/services/followStream';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import { treeLinksOf } from '../../src/services/dissect/infoPatch';
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
    const links = treeLinksOf((abbrev) => fieldValue(packet, abbrev));
    const retroactive = links ? { frameId: packet.id, links } : undefined;
    const { layers } = dissectReplay(frames, false, packet.streamId, retroactive, host, seedsFor(packet));
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
    const seeded = render(dissectReplay(
      frames, false, tcpFrame.streamId, undefined, host, seedsFor(tcpFrame),
    ).layers);
    checkTrue('an unseeded replay gets the stream index wrong', unseeded !== seeded);
    check('...and a seeded one gets it right', seeded, render(tcpFrame.layers));
  }

  // The same trap one layer down, and it needs its own case: `quic.connection
  // .number` is seeded through `QuicFlowTracker` rather than `L3Tracker`, so a
  // seed that stopped being passed would leave every check above passing while
  // a replayed QUIC tree named the wrong connection. Picked past connection 3
  // for the reason the TCP case is: connection 0 is what an unseeded tracker
  // says anyway, so a frame on it proves nothing.
  const quicFrame = truth.find((p) => {
    const n = fieldValue(p, 'quic.connection.number');
    return typeof n === 'number' && n > 3 && (p.frameProtocols ?? []).includes('quic');
  });
  if (quicFrame) {
    const frames = bundleFor(quicFrame, buffer);
    const seeds = seedsFor(quicFrame);
    const seeded = render(dissectReplay(frames, false, quicFrame.streamId, undefined, host, seeds).layers);
    const unseeded = render(dissectReplay(
      frames, false, quicFrame.streamId, undefined, host, { ...seeds, quic: undefined },
    ).layers);
    const want = `Connection Number: ${fieldValue(quicFrame, 'quic.connection.number')}`;
    checkTrue(`a seeded replay names connection ${fieldValue(quicFrame, 'quic.connection.number')}`
      + ` (frame ${quicFrame.id})`, seeded.includes(want));
    checkTrue('...and an unseeded one does not', !unseeded.includes(want));
    check('...and the seeded tree is the eager one', seeded, render(quicFrame.layers));
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

  // --- the adapter the frame came off ---------------------------------------
  //
  // **This suite could not see the Frame layer's interface rows, and they were
  // wrong the whole time.** `dissectReplay` passed a hard-coded `undefined` as
  // its capture interface, so every rebuilt tree read `Interface name:
  // unknown` / `Interface description: Imported capture`. On a live capture
  // that is simply false - and since a displayed tree is always a rebuilt one
  // (ADR 0007), it was every tree anybody ever saw.
  //
  // The equality check above ran green through all of it, and the reason is
  // the one `CLAUDE.md` states about the fixtures: **a measurement that cannot
  // see a feature cannot defend it.** This script imports a file, where
  // `undefined` is the correct answer, so both sides said `Imported capture`
  // and matched. Supplying an adapter is what makes the rows observable, and
  // the `not Imported capture` assertion is what stops this passing by both
  // sides agreeing on nothing again.
  {
    const ADAPTER = { name: '\\Device\\NPF_{0BADF00D}', label: 'Wi-Fi 6E' };
    const resolve = (label: string) => interfacesByLabel([ADAPTER]).get(label);
    const sample = truth.find((p) => p.rawBytes.length > 0);
    if (!sample) {
      console.log('SKIP  no frame with bytes - the fixture is unusable');
    } else {
      const bare: ReplayFrame[] = [{
        id: sample.id, tsUs: sample.tsUs, relativeTime: sample.relativeTime,
        timeDelta: sample.timeDelta, origLen: sample.length, bytes: sample.rawBytes,
      }];
      const onAdapter: ReplayFrame[] = [{ ...bare[0], interfaceName: ADAPTER.label }];

      const imported = render(dissectReplay(bare, false).layers);
      const live = render(dissectReplay(onAdapter, false, undefined, undefined,
        undefined, undefined, resolve).layers);

      // The import case, which is what this always did and is right for a file.
      checkTrue('a frame off no adapter still reads as an imported capture',
        imported.includes('Interface description: Imported capture'));

      // The bug, named as the thing it must not say.
      checkTrue('a frame off an adapter does NOT read as an imported capture',
        !live.includes('Imported capture'));
      checkTrue('...it names the adapter', live.includes(`Interface description: ${ADAPTER.label}`));
      checkTrue('...and its device name', live.includes(`Interface name: ${ADAPTER.name}`));
      checkTrue('...including in the row that summarises the two',
        live.includes(`Interface id: 0 (${ADAPTER.name})`));

      // Nothing else moved. Without this the rows could be right and some
      // other part of the tree quietly different, which is the failure this
      // whole file exists for.
      const strip = (tree: string) => tree.split('\n')
        .filter((line) => !line.includes('Interface ')).join('\n');
      check('and no other row in the tree changed', strip(live), strip(imported));

      // The trap `sessionRestore.ts` records, now held where a script can
      // reach it: `eth0` is `pcapParser.ts`'s fallback for a frame with no
      // interface, and trusting it invents an adapter for every imported file.
      check('the eth0 fallback is not treated as an adapter',
        interfacesByLabel([{ name: 'x', label: NOT_AN_ADAPTER }]).size, 0);
      check('...while a real adapter beside it survives',
        [...interfacesByLabel([{ name: 'x', label: NOT_AN_ADAPTER }, ADAPTER]).keys()],
        [ADAPTER.label]);
      // Two adapters sharing a label is not resolved by preferring the later
      // one; an unknown is not a guess.
      check('a duplicate label keeps the first record',
        interfacesByLabel([ADAPTER, { name: 'other', label: ADAPTER.label }])
          .get(ADAPTER.label)?.name,
        ADAPTER.name);
    }
  }
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
