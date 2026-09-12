/**
 * An import handed over in batches is the same import.
 *
 *   npx tsx scripts/capture/import-stream.ts
 *
 * ## What changed and what must not have
 *
 * A capture file used to be dissected into one array and returned. That array
 * is the thing the import cap existed to bound, so a file bigger than the RAM
 * buffer was **truncated** - the importer built `maxFrames` frames and put a
 * note on screen saying so. `streamCaptureFile` hands frames over as it builds
 * them, so the caller can write them to the capture store and keep only the
 * tail.
 *
 * The property that matters is that nothing about a frame depends on which
 * route it took. Not "the counts match" - the same count of subtly different
 * rows is exactly the failure mode - so every frame is compared field for
 * field against the array the old path produces, on the same file.
 *
 * ## The patch window is the risky part
 *
 * Dissection amends frames it has already emitted, by indexing straight into
 * the array being built. Streaming means that array is a sliding window, so
 * the index has to be relative to what has left it, and a patch that reaches
 * back further than the window has to be **counted rather than applied to
 * whichever frame happens to sit at that offset**. An unchecked index would
 * write `[TCP PDU reassembled in N]` onto an unrelated frame, silently, and
 * only on captures big enough for anyone to care.
 *
 * So the window is driven to its edges here: a whole capture inside it, and
 * the same capture with the window forced small enough that patches fall off
 * the back.
 */
import { pcapOf } from '../parity/synthetic';
import { PcapService } from '../../src/services/pcapParser';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/** Ethernet/IPv4/UDP/DNS query, built by hand so the result is predictable. */
function dnsQuery(txid: number): Uint8Array {
  const name = [7, ...[...'example'].map((c) => c.charCodeAt(0)),
    3, ...[...'com'].map((c) => c.charCodeAt(0)), 0];
  const dns = [
    (txid >> 8) & 0xff, txid & 0xff, 0x01, 0x00,
    0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ...name, 0x00, 0x01, 0x00, 0x01,
  ];
  const udpLen = 8 + dns.length;
  const srcPort = 0xc000 + (txid & 0x0fff);
  const udp = [
    (srcPort >> 8) & 0xff, srcPort & 0xff, 0x00, 0x35,
    (udpLen >> 8) & 0xff, udpLen & 0xff, 0x00, 0x00, ...dns,
  ];
  const total = 20 + udp.length;
  const ip = [
    0x45, 0x00, (total >> 8) & 0xff, total & 0xff,
    0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00,
    192, 168, 1, 42, 1, 1, 1, 1,
  ];
  const eth = [0xaa, 0xbb, 0xcc, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0, 0, 2, 0x08, 0x00];
  return new Uint8Array([...eth, ...ip, ...udp]);
}

/**
 * An ICMP echo request or reply.
 *
 * Here because it is the patch with the longest reach - `(reply in N)` is
 * written onto a frame that can be thousands of frames back - so it is what
 * drives the window's edge.
 */
function icmpEcho(id: number, seq: number, reply: boolean): Uint8Array {
  const body = [reply ? 0 : 8, 0, 0, 0, (id >> 8) & 0xff, id & 0xff,
    (seq >> 8) & 0xff, seq & 0xff, ...new Array(32).fill(0x61)];
  // The checksum is left zero: nothing here asserts on the verdict, and a
  // wrong one would be the same on both sides of the comparison anyway.
  const total = 20 + body.length;
  const ip = [
    0x45, 0x00, (total >> 8) & 0xff, total & 0xff,
    0x00, 0x00, 0x40, 0x00, 0x40, 0x01, 0x00, 0x00,
    ...(reply ? [1, 1, 1, 1, 192, 168, 1, 42] : [192, 168, 1, 42, 1, 1, 1, 1]),
  ];
  const eth = [0xaa, 0xbb, 0xcc, 0, 0, 1, 0xaa, 0xbb, 0xcc, 0, 0, 2, 0x08, 0x00];
  return new Uint8Array([...eth, ...ip, ...body]);
}

const fileOf = (bytes: Uint8Array, name = 'synthetic.pcap') =>
  new File([bytes as unknown as BlobPart], name);

/** Everything about a frame that the two routes must agree on. */
function shapeOf(packet: Packet) {
  return {
    id: packet.id,
    source: packet.source,
    destination: packet.destination,
    protocol: packet.protocol,
    info: packet.info,
    length: packet.length,
    status: packet.status,
    relativeTime: packet.relativeTime,
    timeDelta: packet.timeDelta,
    tsUs: packet.tsUs,
    frameProtocols: packet.frameProtocols,
    bytes: packet.rawBytes?.length ?? -1,
  };
}

/**
 * Streams a file and returns every frame, in order.
 *
 * The window is forced well below the file's size on purpose. At the real
 * 100,000 a test capture never fills it, so nothing is ever handed over until
 * the final flush - which means `shipped` stays 0 and every index into the
 * window is accidentally correct. The first version of this compared 48,000
 * frames against a 100,000-frame window and passed with the offset arithmetic
 * removed entirely.
 */
async function streamed(
  file: File, patchWindow = 5_000,
): Promise<{ packets: Packet[]; missedPatches: number }> {
  const packets: Packet[] = [];
  const outcome = await PcapService.streamCaptureFile(
    file, (batch) => packets.push(...batch), { patchWindow, batchFrames: 512 },
  );
  check('the stream built every frame in the file', outcome.built, outcome.totalFrames);
  return { packets, missedPatches: outcome.missedPatches };
}

console.log('--- the same frames, whichever route they took ---\n');

{
  // A mix that produces patches: DNS queries, and ICMP echoes whose replies
  // are ~1,200 frames behind their requests.
  const frames: Uint8Array[] = [];
  const PAIRS = 40;
  const GAP = 1_200;
  for (let i = 0; i < PAIRS * GAP; i++) {
    if (i % GAP === 0) frames.push(icmpEcho(0x4141, i / GAP, false));
    else if (i % GAP === GAP - 1) frames.push(icmpEcho(0x4141, (i - GAP + 1) / GAP, true));
    else frames.push(dnsQuery(i & 0xffff));
  }
  const file = fileOf(pcapOf(frames));
  console.log(`      ${frames.length.toLocaleString()} frames, `
    + `${PAIRS} ICMP pairs ${GAP - 1} frames apart\n`);

  const whole = await PcapService.parseCaptureFile(file);
  const { packets, missedPatches } = await streamed(fileOf(pcapOf(frames)));

  check('the same number of frames', packets.length, whole.packets.length);
  // Field for field. A count that matches over rows that differ is the exact
  // failure this is guarding against.
  const mismatched = packets
    .map((p, i) => [i, JSON.stringify(shapeOf(p)), JSON.stringify(shapeOf(whole.packets[i]))])
    .filter(([, a, b]) => a !== b);
  check('every frame identical, field for field',
    mismatched.slice(0, 2).map(([i]) => `frame ${Number(i) + 1}`), []);
  check('no patch fell outside the window', missedPatches, 0);

  // And the patches actually landed, so "identical" is not two empty answers.
  const replies = packets.filter((p) => p.info.includes('reply in')).length;
  checkTrue(`the ICMP cross-references are there (${replies} of ${PAIRS})`, replies === PAIRS);
}

console.log('\n--- when a patch reaches back further than the window ---\n');

{
  // The same shape, but the reply is further behind the request than the
  // window can hold. The frame is out of reach by then, and what must NOT
  // happen is a cross-reference landing on whatever frame sits at that offset.
  const frames: Uint8Array[] = [];
  const GAP = 6_000;
  for (let i = 0; i < GAP * 3; i++) {
    if (i % GAP === 0) frames.push(icmpEcho(0x4242, i / GAP, false));
    else if (i % GAP === GAP - 1) frames.push(icmpEcho(0x4242, (i - GAP + 1) / GAP, true));
    else frames.push(dnsQuery(i & 0xffff));
  }
  const file = fileOf(pcapOf(frames));

  // The window is forced down to 500, which is what the real 100,000 does to
  // a capture too big to hold in one.
  const packets: Packet[] = [];
  const outcome = await PcapService.streamCaptureFile(
    file, (batch) => packets.push(...batch), { patchWindow: 500, batchFrames: 250 },
  );

  check('every frame still arrives', outcome.built, frames.length);
  checkTrue(`patches that reached past it are counted (${outcome.missedPatches})`,
    outcome.missedPatches > 0);
  checkTrue('...and none of them is missing its bytes',
    packets.every((p) => (p.rawBytes?.length ?? 0) > 0));

  // Whatever the window does to the cross-reference, it must never be wrong:
  // a frame that says "reply in N" must be an echo request, not a DNS query
  // that happened to be at the right offset.
  const wrong = packets.filter(
    (p) => p.info.includes('reply in') && !p.info.toLowerCase().includes('echo'));
  check('no frame was given a cross-reference that is not its own',
    wrong.slice(0, 3).map((p) => `frame ${p.id}: ${p.info}`), []);
}

console.log('\n--- batches ---\n');

{
  const frames = Array.from({ length: 5_000 }, (_, i) => dnsQuery(i & 0xffff));
  const file = fileOf(pcapOf(frames));

  const sizes: number[] = [];
  const ids: number[] = [];
  const shipped: Packet[] = [];
  await PcapService.streamCaptureFile(file, (batch) => {
    sizes.push(batch.length);
    for (const p of batch) { ids.push(p.id); shipped.push(p); }
  });

  checkTrue(`arrived in ${sizes.length} batches, not one`, sizes.length > 1);
  check('and in order, with no frame twice or missing',
    [ids.length, ids[0], ids[ids.length - 1], new Set(ids).size],
    [5_000, 1, 5_000, 5_000]);
  checkTrue('every frame is in exactly one batch',
    sizes.reduce((a, b) => a + b, 0) === 5_000);
  // The dense-field split runs on the way out, so a shipped frame is
  // finished - it carries a column block and a row in it, which is what the
  // buffer expects of anything it adopts.
  const split = shipped.filter((p) => p.cols !== undefined && typeof p.row === 'number');
  check('...and every one left with its dense fields split out',
    split.length, shipped.length);
}

console.log(failures === 0
  ? '\nAll import stream checks passed.'
  : `\n${failures} import stream check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
