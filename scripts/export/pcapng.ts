/**
 * Assertion tests for the pcapng writer.
 *
 *   npx tsx scripts/export/pcapng.ts
 *
 * A writer is easy to test badly: feed its output to your own reader and
 * declare victory. That proves the two agree, which is exactly what a matched
 * pair of bugs also looks like. So this asserts the **bytes** - block types,
 * the trailing length that lets a reader walk the file backwards, the option
 * codes and the padding - against the format rather than against this repo's
 * own reader, and then round-trips through the reader as a second, weaker
 * check on top.
 *
 * The trailing block length is the field most often got wrong. It counts
 * itself, the leading length and the type, and every block is padded to a
 * multiple of four; a writer that forgets either produces a file that opens
 * correctly and cannot be read backwards, which nothing notices until someone
 * seeks in it.
 */
import { generatePcapNg } from '../../src/services/pcapngWriter';
import { PcapService } from '../../src/services/pcapParser';
import { decodeRawEthernetPacket } from '../../src/services/pcapParser';
import { LINKTYPE } from '../../src/services/dissect/types';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  // BigInt is unavoidable here - a nanosecond tick count is past the exact
  // range of a double, which is the whole reason the writer assembles it in
  // bigint - and JSON.stringify refuses to serialise one.
  const show = (v: unknown) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x));
  const pass = show(actual) === show(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${show(expected)}`);
    console.log(`        actual   ${show(actual)}`);
  }
}
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

// --- a capture to write ----------------------------------------------------------

const MAC_DST = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
const MAC_SRC = [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb];

function frame(sport: number, payload = 4): Uint8Array {
  const tcp = [
    (sport >> 8) & 0xff, sport & 0xff, 0x01, 0xbb,
    0x00, 0x00, 0x03, 0xe8,
    0x00, 0x00, 0x00, 0x00,
    0x50, 0x10, 0x20, 0x00,
    0x00, 0x00, 0x00, 0x00,
    ...new Array(payload).fill(0xaa),
  ];
  const total = 20 + tcp.length;
  return new Uint8Array([
    ...MAC_DST, ...MAC_SRC, 0x08, 0x00,
    0x45, 0x00, (total >> 8) & 0xff, total & 0xff,
    0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00,
    10, 0, 0, 1, 93, 184, 216, 34,
    ...tcp,
  ]);
}

function packet(id: number, tsUs: number, iface?: string, payload = 4): Packet {
  const bytes = frame(51000 + id, payload);
  const p = decodeRawEthernetPacket(
    bytes, id, tsUs, 0, 0, bytes.length,
    undefined, undefined, undefined, undefined, undefined, LINKTYPE.ETHERNET,
  ).packet;
  if (iface) p.interfaceName = iface;
  return p;
}

// --- the block structure ------------------------------------------------------------

interface Block { type: number; length: number; body: Uint8Array; at: number }

/** Walks the file the way a reader does, and fails loudly if it cannot. */
function walk(bytes: Uint8Array): Block[] {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const out: Block[] = [];
  let at = 0;
  while (at + 12 <= bytes.length) {
    const type = view.getUint32(at, true);
    const length = view.getUint32(at + 4, true);
    if (length < 12 || at + length > bytes.length) throw new Error(`block at ${at} claims ${length} bytes`);
    const trailing = view.getUint32(at + length - 4, true);
    if (trailing !== length) throw new Error(`block at ${at}: trailing length ${trailing} != ${length}`);
    if (length % 4 !== 0) throw new Error(`block at ${at} is not padded to four bytes`);
    out.push({ type, length, body: bytes.subarray(at + 8, at + length - 4), at });
    at += length;
  }
  if (at !== bytes.length) throw new Error(`${bytes.length - at} bytes after the last block`);
  return out;
}

/** The options at the end of a block body, as code -> raw value. */
function options(body: Uint8Array, from: number): Map<number, Uint8Array[]> {
  const view = new DataView(body.buffer, body.byteOffset, body.byteLength);
  const out = new Map<number, Uint8Array[]>();
  let at = from;
  while (at + 4 <= body.length) {
    const code = view.getUint16(at, true);
    const length = view.getUint16(at + 2, true);
    if (code === 0) break;
    if (at + 4 + length > body.length) throw new Error('option runs past the block');
    out.set(code, [...(out.get(code) ?? []), body.subarray(at + 4, at + 4 + length)]);
    at += 4 + length + ((4 - (length % 4)) % 4);
  }
  return out;
}

const text = (b: Uint8Array) => new TextDecoder().decode(b);

async function main() {
  const packets = [
    packet(1, 1_700_000_000_000_000, 'eth0'),
    packet(2, 1_700_000_000_250_000, 'wlan0'),
    // Deliberately out of order: the buffer can hold frames from several
    // adapters that arrived out of order, and a file is forever.
    packet(3, 1_700_000_000_100_000, 'eth0'),
    // An odd payload length, so the writer's padding is exercised rather than
    // being accidentally correct.
    packet(4, 1_700_000_000_400_000, 'wlan0', 5),
  ];

  const blob = generatePcapNg(packets, {
    interfaces: [
      { name: 'eth0', description: 'Ethernet', tsPrecision: 6, received: 4242, dropped: 17 },
      { name: 'wlan0', description: 'Wi-Fi', tsPrecision: 9 },
    ],
    names: [
      { address: '93.184.216.34', names: ['example.com'] },
      { address: '2001:db8::1', names: ['router.local'] },
      { address: 'not-an-address', names: ['ignored'] },
    ],
    comment: 'a test capture',
    secrets: 'CLIENT_RANDOM 001122 aabbccdd\n',
  });
  const bytes = new Uint8Array(await blob.arrayBuffer());

  // --- every block is well formed --------------------------------------------
  let blocks: Block[] = [];
  try {
    blocks = walk(bytes);
    checkTrue('the file walks cleanly from start to end', true);
  } catch (err) {
    check('the file walks cleanly from start to end', String(err), 'no error');
  }

  const types = blocks.map((b) => b.type);
  check('it opens with a Section Header Block', types[0], 0x0a0d0d0a);
  check('...followed by one Interface Description Block per adapter',
    types.slice(1, 3), [0x00000001, 0x00000001]);
  check('...then a packet block per frame',
    types.filter((t) => t === 0x00000006).length, 4);
  check('...a Name Resolution Block', types.filter((t) => t === 0x00000004).length, 1);
  // Before the frames, not after: a reader walks the file once, so secrets
  // written after the packets they open would arrive too late to open them.
  check('...a Decryption Secrets Block, ahead of the first packet',
    types.indexOf(0x0000000a) < types.indexOf(0x00000006), true);
  // One per interface that has counters, and only eth0 was given any.
  check('...and an Interface Statistics Block for the adapter that has counters',
    types.filter((t) => t === 0x00000005).length, 1);

  // --- the section header ------------------------------------------------------
  {
    const shb = blocks[0];
    const view = new DataView(shb.body.buffer, shb.body.byteOffset, shb.body.byteLength);
    check('the byte-order magic says little-endian', view.getUint32(0, true), 0x1a2b3c4d);
    check('...and the version is 1.0', [view.getUint16(4, true), view.getUint16(6, true)], [1, 0]);
    // -1 is the legal "not known" form, and the honest one: backfilling it
    // would mean holding the whole file to rewrite eight bytes.
    check('the section length is the "unknown" form', view.getBigUint64(8, true), 0xffffffffffffffffn);
    const opts = options(shb.body, 16);
    check('the comment survives', text(opts.get(1)![0]), 'a test capture');
    check('...and the file says what wrote it', text(opts.get(4)![0]), 'Inwire');
  }

  // --- the interface descriptions -----------------------------------------------
  {
    const idb = blocks[1];
    const view = new DataView(idb.body.buffer, idb.body.byteOffset, idb.body.byteLength);
    check('the link type is Ethernet', view.getUint16(0, true), LINKTYPE.ETHERNET);
    const opts = options(idb.body, 8);
    check('the adapter is named', text(opts.get(2)![0]), 'eth0');
    check('...and described', text(opts.get(3)![0]), 'Ethernet');
    check('...with its timestamp resolution', opts.get(9)![0][0], 6);

    const second = blocks[2];
    check('a nanosecond adapter records nanosecond resolution',
      options(second.body, 8).get(9)![0][0], 9);
  }

  // --- the frames -----------------------------------------------------------------
  {
    const epbs = blocks.filter((b) => b.type === 0x00000006);
    const read = epbs.map((b) => {
      const view = new DataView(b.body.buffer, b.body.byteOffset, b.body.byteLength);
      const ticks = (BigInt(view.getUint32(4, true)) << 32n) | BigInt(view.getUint32(8, true));
      return {
        iface: view.getUint32(0, true),
        ticks,
        capLen: view.getUint32(12, true),
        origLen: view.getUint32(16, true),
      };
    });

    check('frames are written in capture order, whatever order they arrived in',
      read.map((r) => Number(r.iface)), [0, 0, 1, 1]);
    // eth0 is microseconds, wlan0 nanoseconds, and the tick count is in each
    // interface's own units - which is the thing classic pcap cannot express.
    check('a microsecond adapter counts microseconds', read[0].ticks, 1_700_000_000_000_000n);
    check('...and a nanosecond adapter counts nanoseconds', read[2].ticks, 1_700_000_000_250_000_000n);
    checkTrue('the wire length is never below the captured length',
      read.every((r) => r.origLen >= r.capLen));
  }

  // --- what the capture missed ------------------------------------------------------
  {
    const isb = blocks.find((b) => b.type === 0x00000005)!;
    const view = new DataView(isb.body.buffer, isb.body.byteOffset, isb.body.byteLength);
    check('the statistics block names its interface', view.getUint32(0, true), 0);
    const opts = options(isb.body, 12);
    const u64 = (b: Uint8Array) => new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(0, true);
    check('...how many frames the adapter saw', u64(opts.get(4)![0]), 4242n);
    // A file that does not say it is incomplete reads as complete.
    check('...and how many it dropped', u64(opts.get(5)![0]), 17n);
    checkTrue('...with a start and an end time', opts.has(2) && opts.has(3));
  }

  // --- the names this capture taught us ----------------------------------------------
  {
    const nrb = blocks.find((b) => b.type === 0x00000004)!;
    const view = new DataView(nrb.body.buffer, nrb.body.byteOffset, nrb.body.byteLength);
    const records: { type: number; address: number[]; names: string[] }[] = [];
    let at = 0;
    while (at + 4 <= nrb.body.length) {
      const type = view.getUint16(at, true);
      const length = view.getUint16(at + 2, true);
      if (type === 0) break;
      const size = type === 1 ? 4 : 16;
      const value = nrb.body.subarray(at + 4, at + 4 + length);
      records.push({
        type,
        address: Array.from(value.subarray(0, size)),
        names: text(value.subarray(size)).split('\0').filter((n) => n.length > 0),
      });
      at += 4 + length + ((4 - (length % 4)) % 4);
    }
    check('both addresses are recorded', records.map((r) => r.type), [1, 2]);
    check('the IPv4 record holds the address as four bytes', records[0].address, [93, 184, 216, 34]);
    check('...and its name', records[0].names, ['example.com']);
    check('the IPv6 record holds sixteen', records[1].address.length, 16);
    check('...and its name', records[1].names, ['router.local']);
    // Something that is not an address is dropped rather than written as
    // whatever the parser made of it.
    check('a value that is not an address is not written', records.length, 2);
  }

  // --- the secrets ---------------------------------------------------------------------
  {
    const dsb = blocks.find((b) => b.type === 0x0000000a)!;
    const view = new DataView(dsb.body.buffer, dsb.body.byteOffset, dsb.body.byteLength);
    check('the secrets type is the NSS key log one', view.getUint32(0, true), 0x544c534b);
    const length = view.getUint32(4, true);
    check('...the length counts the text and not its padding', length, 30);
    check('...and the text is the key log itself',
      text(dsb.body.subarray(8, 8 + length)), 'CLIENT_RANDOM 001122 aabbccdd\n');
  }

  // --- and it reads back ---------------------------------------------------------------
  {
    const back = await PcapService.parseCaptureFile(new File([bytes], 'out.pcapng'), 100);
    check('every frame comes back', back.packets.length, 4);
    const ordered = [...packets].sort((a, b) => a.tsUs - b.tsUs);
    check('...with their timestamps intact', back.packets.map((p) => p.tsUs), ordered.map((p) => p.tsUs));
    checkTrue('...and their bytes',
      back.packets.every((p, i) => p.rawBytes.length === ordered[i].rawBytes.length
        && p.rawBytes.every((b, j) => b === ordered[i].rawBytes[j])));
    check('...and the nanosecond adapter keeps its precision',
      back.packets.map((p) => p.tsPrecision), [6, 6, 9, 9]);
  }

  // --- process attribution survives the file --------------------------------------
  //
  // The one fact in a capture file that no reader could derive from the frames,
  // so it reaches anybody only if it is actually written - and written where a
  // reader that has never heard of this app will show it.
  {
    const attributed = packet(9, 1_700_000_000_000_000, 'eth0');
    attributed.fields = {
      ...attributed.fields,
      'inwire.process.name': 'curl.exe',
      'inwire.process.pid': 4242,
      'inwire.process.path': 'C:/Windows/System32/curl.exe',
    };
    const plain = packet(10, 1_700_000_000_000_001, 'eth0');

    const bytes = new Uint8Array(await generatePcapNg([attributed, plain], {
      interfaces: [{ name: 'eth0', description: 'Ethernet', tsPrecision: 6 }],
    }).arrayBuffer());
    const epbs = walk(bytes).filter((b) => b.type === 0x00000006);
    check('both frames are written', epbs.length, 2);

    // Options begin after the fixed EPB header and the packet data, padded to
    // a four-byte boundary like every variable-length field in the format.
    const optionsOf = (b: { body: Uint8Array }) => {
      const view = new DataView(b.body.buffer, b.body.byteOffset, b.body.byteLength);
      const capLen = view.getUint32(12, true);
      return options(b.body, 20 + Math.ceil(capLen / 4) * 4);
    };

    const comment = optionsOf(epbs[0]).get(1)?.[0];
    checkTrue('the attributed frame carries a comment', comment !== undefined);
    check('...naming the process, its pid and its path',
      new TextDecoder().decode(comment ?? new Uint8Array()),
      'Process: curl.exe (pid 4242) - C:/Windows/System32/curl.exe');

    // Absent, not empty. An empty comment would read as "known to be nothing".
    check('an unattributed frame carries no comment at all',
      optionsOf(epbs[1]).get(1), undefined);
  }

  // --- degenerate inputs -----------------------------------------------------------------
  {
    const empty = new Uint8Array(await generatePcapNg([]).arrayBuffer());
    const walked = walk(empty);
    check('an empty capture is still a valid file', walked.map((b) => b.type), [0x0a0d0d0a, 0x00000001]);
    check('...with one interface to describe nothing', walked.length, 2);
  }
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All pcapng writer checks passed.');
  process.exit(0);
}).catch((err) => {
  console.log(`FAIL  the writer threw: ${err}`);
  process.exit(1);
});
