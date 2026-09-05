/**
 * Assertion tests for rebuilding a session from stored frames.
 *
 *   npx tsx scripts/session/restore.ts
 *
 * The contract is that a restored packet is indistinguishable from the one
 * originally captured. So the central check here decodes the same frames twice
 * - once as "live capture", once as "restored from disk" - and diffs the
 * results field by field. Anything the round trip loses shows up there.
 *
 * The rest cover what a naive restore gets wrong: packet numbers restarting at
 * 1, stateful trackers being fed out of order, metadata-only frames being
 * dropped, and ICMP reply pairings that point at a packet in an earlier chunk.
 */
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { DnsTracker } from '../../src/services/dnsTracker';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { PacketGenerator } from '../../src/services/packetGenerator';
import { toStoredFrame, type StoredFrame } from '../../src/services/sessionStore';
import { applyIcmpReplies, buildFallbackPacket, restoreBatch } from '../../src/services/sessionRestore';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

const freshTrackers = () => ({
  tcpTracker: new TcpStreamTracker(),
  icmpTracker: new IcmpEchoTracker(),
  quicTracker: new QuicFlowTracker(),
  dnsTracker: new DnsTracker(),
});

// --- Frame builders ---------------------------------------------------------

const MAC_A = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_B = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

function ipv4(payload: number[], proto: number, src: number[], dst: number[]): number[] {
  const totalLen = 20 + payload.length;
  const header = [
    0x45, 0x00, (totalLen >> 8) & 0xff, totalLen & 0xff,
    0x00, 0x01, 0x40, 0x00,
    0x40, proto, 0x00, 0x00,
    ...src, ...dst,
  ];
  return [...MAC_B, ...MAC_A, 0x08, 0x00, ...header, ...payload];
}

/** A TCP segment, so the stateful stream tracker has something to track. */
function tcpFrame(sport: number, dport: number, seq: number, flags: number): Uint8Array {
  const tcp = [
    (sport >> 8) & 0xff, sport & 0xff,
    (dport >> 8) & 0xff, dport & 0xff,
    (seq >>> 24) & 0xff, (seq >>> 16) & 0xff, (seq >>> 8) & 0xff, seq & 0xff,
    0x00, 0x00, 0x00, 0x00,
    0x50, flags, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00,
  ];
  return new Uint8Array(ipv4(tcp, 6, [10, 0, 0, 1], [10, 0, 0, 2]));
}

/** An ICMP echo request or reply, for the request/reply pairing check. */
function icmpFrame(type: number, id: number, seq: number): Uint8Array {
  const icmp = [
    type, 0x00, 0x00, 0x00,
    (id >> 8) & 0xff, id & 0xff,
    (seq >> 8) & 0xff, seq & 0xff,
    0xde, 0xad, 0xbe, 0xef,
  ];
  const src = type === 8 ? [10, 0, 0, 1] : [10, 0, 0, 2];
  const dst = type === 8 ? [10, 0, 0, 2] : [10, 0, 0, 1];
  return new Uint8Array(ipv4(icmp, 1, src, dst));
}

/** The capture under test: interleaved TCP streams plus an ICMP exchange. */
function buildCapture(): Uint8Array[] {
  const frames: Uint8Array[] = [];
  for (let i = 0; i < 6; i++) {
    frames.push(tcpFrame(50000 + (i % 2), 443, 1000 + i * 100, i === 0 ? 0x02 : 0x10));
    frames.push(tcpFrame(443, 50000 + (i % 2), 5000 + i * 100, 0x10));
  }
  frames.push(icmpFrame(8, 0x1234, 1));
  frames.push(icmpFrame(0, 0x1234, 1));
  return frames;
}

/** Decodes frames the way live capture does: one pass, one set of trackers. */
function decodeLive(raws: Uint8Array[]): { packets: Packet[]; replies: { requestFrameId: number; replyId: number }[] } {
  const trackers = freshTrackers();
  const packets: Packet[] = [];
  const replies: { requestFrameId: number; replyId: number }[] = [];
  raws.forEach((raw, i) => {
    const d = decodeRawEthernetPacket(
      raw, i + 1, 1_700_000_000_000 + i * 10, i * 0.01, 0.01, raw.length,
      trackers.tcpTracker, trackers.icmpTracker, trackers.quicTracker, trackers.dnsTracker, undefined,
    );
    packets.push(d.packet);
    if (d.icmpMatchedRequestFrameId !== undefined) {
      replies.push({ requestFrameId: d.icmpMatchedRequestFrameId, replyId: i + 1 });
    }
  });
  return { packets, replies };
}

const raws = buildCapture();
const live = decodeLive(raws);
const stored: StoredFrame[] = live.packets.map(toStoredFrame);

// --- A stored frame keeps what is needed and drops what is derived ---------
{
  const f = stored[0];
  check('a stored frame keeps the raw bytes', f.raw instanceof Uint8Array && f.raw.length === raws[0].length, true);
  check('...and the packet number', f.id, live.packets[0].id);
  check('...and the timing', [f.tsUs, f.relativeTime, f.timeDelta], [live.packets[0].tsUs, live.packets[0].relativeTime, live.packets[0].timeDelta]);
  check('...and drops the derived layers', 'layers' in f, false);
  check('...and drops the derived info column', 'info' in f, false);
  const bytes = JSON.stringify(Array.from(f.raw!));
  check('the stored bytes are the captured bytes', bytes, JSON.stringify(Array.from(raws[0])));
}

// --- The round trip is lossless -------------------------------------------
{
  // Restored in one batch, then compared against the live decode field by
  // field. This is the check the whole feature rests on.
  const restored = restoreBatch(stored, freshTrackers(), undefined, undefined, true);
  check('every packet comes back', restored.packets.length, live.packets.length);

  const compare = (key: keyof Packet) =>
    check(`round trip preserves ${String(key)}`,
      restored.packets.map(p => p[key]),
      live.packets.map(p => p[key]));

  for (const key of ['id', 'timestamp', 'relativeTime', 'timeDelta', 'source', 'destination',
                     'sourcePort', 'destPort', 'protocol', 'protocolLabel', 'length', 'info',
                     'status', 'streamId'] as (keyof Packet)[]) {
    compare(key);
  }
  // Trees are rebuilt on demand now (docs/decisions/0007), so this asks for
  // them explicitly. What is being asserted is unchanged and is the point of
  // storing the bytes at all: a frame off disk dissects to the same tree the
  // live one did.
  check('round trip preserves the dissected layers',
    JSON.stringify(restored.packets.map(p => p.layers)),
    JSON.stringify(live.packets.map(p => p.layers)));
  check('round trip preserves the raw bytes',
    restored.packets.map(p => Array.from(p.rawBytes).join()),
    live.packets.map(p => Array.from(p.rawBytes).join()));
  check('round trip preserves ICMP reply pairings', restored.icmpReplies, live.replies);
  check('...and there really was a pairing to preserve', live.replies.length > 0, true);
}

// --- Chunking must not change the answer ----------------------------------
{
  // The restore decodes in chunks so it can yield to the browser between them.
  // The trackers are stateful, so this proves chunk boundaries are invisible.
  for (const size of [1, 2, 5, 7]) {
    const trackers = freshTrackers();
    const packets: Packet[] = [];
    const replies: { requestFrameId: number; replyId: number }[] = [];
    for (let i = 0; i < stored.length; i += size) {
      const out = restoreBatch(stored.slice(i, i + size), trackers, undefined, undefined, true);
      packets.push(...out.packets);
      replies.push(...out.icmpReplies);
    }
    check(`chunk size ${size} gives the same stream ids`,
      packets.map(p => p.streamId), live.packets.map(p => p.streamId));
    check(`chunk size ${size} gives the same info column`,
      packets.map(p => p.info), live.packets.map(p => p.info));
    check(`chunk size ${size} finds the same ICMP pairings`, replies, live.replies);
  }
}

// --- ICMP replies patch packets already committed in an earlier chunk -----
{
  const committed = live.packets.slice(0, 12).map(p => ({ ...p }));
  const target = committed[0];
  const patched = applyIcmpReplies(committed, [{ requestFrameId: target.id, replyId: 99 }]);
  check('a reply patches the request it names', patched[0].info, `${target.info} (reply in 99)`);
  check('...and leaves the others alone', patched[1].info, committed[1].info);
  check('no replies returns the same array, so React can skip the update',
    applyIcmpReplies(committed, []) === committed, true);
  check('a reply naming an absent packet changes nothing',
    applyIcmpReplies(committed, [{ requestFrameId: 999999, replyId: 5 }]) === committed, true);
}

// --- Metadata-only frames survive -----------------------------------------
{
  // The agent can send a packet with no bytes. It must come back exactly as
  // unhelpful as it was, not dropped and not given invented payload.
  const bare = buildFallbackPacket({
    id: 7, tsUs: 1_700_000_000_000_000, relativeTime: 1.5, timeDelta: 0.02,
    length: 120, source: '192.0.2.1', destination: '192.0.2.9',
    sourcePort: 1234, destPort: 80, protocol: 'UDP', info: 'Something happened',
  });
  const frame = toStoredFrame(bare);
  check('a byteless packet stores no raw bytes', frame.raw, undefined);
  check('...and stores its display fields instead', frame.fallback?.info, 'Something happened');

  const back = restoreBatch([frame], freshTrackers(), undefined, undefined, true).packets[0];
  check('it comes back with the same id', back.id, 7);
  check('...the same addresses', [back.source, back.destination], ['192.0.2.1', '192.0.2.9']);
  check('...the same ports', [back.sourcePort, back.destPort], [1234, 80]);
  check('...the same protocol and info', [back.protocol, back.info], ['UDP', 'Something happened']);
  check('...and still no fabricated payload', back.rawBytes.length, 0);
}

// --- A mixed buffer restores in order -------------------------------------
{
  const bare = toStoredFrame(buildFallbackPacket({
    id: 500, tsUs: 1_700_000_000_500_000, relativeTime: 9, timeDelta: 0.1, length: 64,
  }));
  const mixed = [stored[0], bare, stored[1]];
  const back = restoreBatch(mixed, freshTrackers(), undefined, undefined, true).packets;
  check('a byteless frame between real ones keeps position and order',
    back.map(p => p.id), [stored[0].id, 500, stored[1].id]);
  check('...and the real frames either side still dissect',
    [back[0].layers.length > 1, back[2].layers.length > 1], [true, true]);
}

// --- The capture adapter survives the round trip --------------------------
{
  // A stored frame remembers the adapter's label; the Frame layer also shows
  // its id, which only the session's interface table can map back to. Getting
  // this wrong is not a crash - it silently reports every restored frame as an
  // imported capture, which is exactly how it was found.
  const LABEL = 'Ethernet 2 (Intel(R) Ethernet Controller (3) I225-V #2)';
  const ID = '\Device\NPF_{28524299-03EF-4F59-A8D2-419D761418B7}';

  const captured = decodeRawEthernetPacket(
    raws[0], 1, 1_700_000_000_000, 0, 0, raws[0].length,
    new TcpStreamTracker(), new IcmpEchoTracker(), new QuicFlowTracker(), new DnsTracker(),
    { name: ID, label: LABEL },
  ).packet;

  const frameFields = (p: Packet) =>
    Object.fromEntries((p.layers[0]?.fields ?? []).flatMap(f => {
      const walk = (x: typeof f): [string, string][] => [
        [x.name, String(x.value)],
        ...(x.children ?? []).flatMap(walk),
      ];
      return walk(f);
    }));

  const live = frameFields(captured);
  check('a live frame names its adapter id', live['Interface name'], ID);
  check('...and its description', live['Interface description'], LABEL);
  check('...and the packet carries the label', captured.interfaceName, LABEL);

  const stored = toStoredFrame(captured);
  check('the stored frame keeps the label', stored.interfaceName, LABEL);

  const withTable = restoreBatch([stored], freshTrackers(), new Map([[LABEL, ID]]), undefined, true).packets[0];
  const restoredFields = frameFields(withTable);
  check('restored with the table, the adapter id comes back', restoredFields['Interface name'], ID);
  check('...and so does the description', restoredFields['Interface description'], LABEL);
  check('...and the packet label', withTable.interfaceName, LABEL);

  // Without the table there is no way to identify the adapter, and claiming
  // one anyway is what broke the round-trip check above: Packet.interfaceName
  // falls back to the literal "eth0" for a frame that had no interface, which
  // reads exactly like a real label. So: identify it or say nothing.
  const noTable = frameFields(restoreBatch([stored], freshTrackers(), undefined, undefined, true).packets[0]);
  check('with no table it does not invent an adapter', noTable['Interface description'], 'Imported capture');
  const wrongTable = frameFields(restoreBatch([stored], freshTrackers(), new Map([['Some other adapter', 'x']]), undefined, true).packets[0]);
  check('a table that does not list this adapter is not forced to fit', wrongTable['Interface description'], 'Imported capture');

  // A frame that genuinely has no adapter keeps the imported-capture wording.
  const anonymous = { ...stored, interfaceName: undefined };
  const anon = frameFields(restoreBatch([anonymous], freshTrackers(), undefined, undefined, true).packets[0]);
  check('a frame with no adapter still reads as an imported capture', anon['Interface description'], 'Imported capture');
}

// --- Packet numbering continues after a restore ---------------------------
{
  const gen = new PacketGenerator();
  check('a fresh generator starts at 1', gen.getNextId(), 1);

  const resumed = new PacketGenerator();
  resumed.resumeAfter(4321);
  check('after a restore the next number follows the last restored one', resumed.getNextId(), 4322);
  check('...and keeps counting', resumed.getNextId(), 4323);

  // A stale or lower value must never wind the counter backwards onto numbers
  // already in the buffer.
  resumed.resumeAfter(10);
  check('resuming from an older id does not go backwards', resumed.getNextId(), 4324);

  const empty = new PacketGenerator();
  empty.resumeAfter(0);
  check('resuming an empty session still starts at 1', empty.getNextId(), 1);
}

console.log(failures === 0 ? '\nAll checks passed.' : `\n${failures} check(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
