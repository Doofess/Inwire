/**
 * The QUIC header, which this build read for a year and published nowhere.
 *
 *   npx tsx scripts/quic/dissect.ts
 *
 * **This is the gap ADR 0039's tree coverage named.** `dissectors/quic.ts`
 * parses every field below, decrypts what it can, labels the Protocol column
 * and writes the Info string - and until `buildQuicLayer` existed it published
 * *not one* `quic.*` abbrev on either surface.
 * `test/fixtures/acceptance.json` recorded that under `unimplemented`, against
 * 40 reference fields on `inwire` and 37 on `bulk`, rather than floored at 0:
 * a zero floor protects nothing and reads as measured-and-accepted.
 *
 * ## Why a built capture rather than the fixtures
 *
 * The same reason as `scripts/icmp/dissect.ts`, `scripts/http/dissect.ts` and
 * `scripts/tls/certificate.ts`: **a measurement that cannot see a feature
 * cannot defend it.** The fixtures are full of QUIC - 3,088 rows on `inwire` -
 * but every one of those datagrams is a real connection, so which header fields
 * are present varies frame to frame and nothing in them pins the *shape*: that
 * a Version Negotiation packet has no packet type, that Retry has no Length,
 * that a coalesced datagram draws two subtrees under **one** layer. Frames
 * built byte by byte from RFC 9000 §17 pin exactly that.
 *
 * ## What is deliberately not asserted here
 *
 * **Anything past the packet number.** A QUIC packet is protected header and
 * all, so the frame types, CRYPTO offsets and STREAM ids only appear once a
 * packet decrypts - which for a passive observer means an Initial whose keys
 * derive from a DCID it actually saw, and otherwise means a key log. Producing
 * one here would mean implementing QUIC's AEAD and header protection *forwards*
 * in a test whose job is to check the parser, so the decrypted half stays with
 * the fixtures, where 3,088 real Initials exercise it. The packets below are
 * undecryptable on purpose and the tree must degrade to the clear header rather
 * than to nothing - which is itself the assertion that a connection whose first
 * Initial was missed still reads.
 */
import { useRepositoryWiresharkProfile } from '../wiresharkProfile';
import { readFileSync, writeFileSync, mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { Bytes, pcapOf, udpFrameTo } from '../parity/synthetic';
import { PcapService } from '../../src/services/pcapParser';
import { fieldValue } from '../../src/services/dissect/fieldAccess';
import type { Packet, ProtocolField } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- building the packets ----------------------------------------------------

/** One flow, so the long headers below teach the tracker what the short one uses. */
const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.9';
const CLIENT_PORT = 51234;

const DCID = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
const SCID = [0xaa, 0xbb, 0xcc, 0xdd];
const DCID_HEX = '0102030405060708';
const SCID_HEX = 'aabbccdd';

/** QUIC v1. `0x6b3343cf` would be v2, which renumbers the packet types. */
const VERSION_1 = 0x00000001;

/**
 * A long header, with a payload that will not decrypt.
 *
 * The first byte is `1 1 TT RRPP`: header form, fixed bit, two type bits, two
 * reserved and two packet-number-length bits. The reserved and length bits sit
 * under header protection on a real packet, which is exactly why the values
 * chosen here are irrelevant - nothing reads them without the keys, and the
 * assertions below are all on fields in the clear.
 */
function longHeader(typeBits: number, opts: { token?: boolean; payload: number } = { payload: 20 }): Uint8Array {
  const body = new Bytes().u8(0).u8(...Array.from({ length: opts.payload }, (_, i) => (i * 7) & 0xff));
  const protectedPayload = body.build();
  const header = new Bytes()
    .u8(0xc0 | (typeBits << 4))
    .u32(VERSION_1)
    .u8(DCID.length).u8(...DCID)
    .u8(SCID.length).u8(...SCID);
  // Only Initial carries a token, and its length is a varint even when zero.
  if (opts.token === true) header.u8(0x00);
  // A one-byte varint covers a length below 64, which every packet here is.
  header.u8(protectedPayload.length);
  return Uint8Array.from([...header.build(), ...protectedPayload]);
}

/**
 * Version Negotiation: version zero, and therefore no packet type at all.
 *
 * The type bits in the first byte are meaningless here - RFC 9000 §17.2.1 says
 * a server sets them arbitrarily - which is the whole reason the dissector
 * must branch on the version before it reads them, and the reason this packet
 * is in the capture.
 */
function versionNegotiation(): Uint8Array {
  return Uint8Array.from(new Bytes()
    .u8(0xc0)
    .u32(0)
    .u8(DCID.length).u8(...DCID)
    .u8(SCID.length).u8(...SCID)
    .u32(VERSION_1)
    .build());
}

/**
 * A short header, which is only identifiable at all against a flow already seen.
 *
 * It carries no version, no length, and a connection id with nothing in front
 * of it saying how long that id is - so the frame ordering in this capture is
 * load-bearing: the long headers above are what teach the tracker the eight
 * bytes to match here.
 */
function shortHeader(): Uint8Array {
  return Uint8Array.from(new Bytes()
    .u8(0x40)
    .u8(...DCID)
    .u8(...Array.from({ length: 16 }, (_, i) => (i * 11) & 0xff))
    .build());
}

const INITIAL = longHeader(0, { token: true, payload: 20 });
const HANDSHAKE = longHeader(2, { payload: 10 });

const FRAMES: { name: string; bytes: Uint8Array }[] = [
  {
    name: 'initial',
    bytes: udpFrameTo(CLIENT, SERVER, CLIENT_PORT, 443, INITIAL),
  },
  {
    // Two packets back to back in one datagram, which is what a real handshake
    // looks like the moment it has anything to coalesce.
    name: 'coalesced',
    bytes: udpFrameTo(SERVER, CLIENT, 443, CLIENT_PORT,
      Uint8Array.from([...INITIAL, ...HANDSHAKE])),
  },
  {
    name: 'version negotiation',
    bytes: udpFrameTo(SERVER, CLIENT, 443, CLIENT_PORT, versionNegotiation()),
  },
  {
    name: 'short header',
    bytes: udpFrameTo(CLIENT, SERVER, CLIENT_PORT, 443, shortHeader()),
  },
];

// --- dissecting them ---------------------------------------------------------

const directory = mkdtempSync(join(tmpdir(), 'inwire-quic-'));
const capture = join(directory, 'quic.pcap');
writeFileSync(capture, pcapOf(FRAMES.map((f) => f.bytes)));

const { packets } = await PcapService.parseCaptureFile(
  new File([readFileSync(capture)], 'quic.pcap'), Number.POSITIVE_INFINITY, true);

check('every synthetic frame dissected', packets.length, FRAMES.length);

/** Every row in a frame's tree, depth first, with its abbrev. */
function rows(packet: Packet): ProtocolField[] {
  const out: ProtocolField[] = [];
  const visit = (fields: ProtocolField[]) => {
    for (const field of fields) {
      out.push(field);
      if (field.children) visit(field.children);
    }
  };
  for (const layer of packet.layers ?? []) visit(layer.fields);
  return out;
}

const valueOf = (packet: Packet, abbrev: string): unknown =>
  rows(packet).find((row) => row.abbrev === abbrev)?.value;
const allValuesOf = (packet: Packet, abbrev: string): unknown[] =>
  rows(packet).filter((row) => row.abbrev === abbrev).map((row) => row.value);
const layerNames = (packet: Packet): string[] => (packet.layers ?? []).map((l) => l.name);

const at = (name: string): Packet => packets[FRAMES.findIndex((f) => f.name === name)];

// --- the layer exists at all -------------------------------------------------

console.log('\n--- the layer ---');
{
  const initial = at('initial');
  check('QUIC grows a layer of its own',
    layerNames(initial),
    ['Frame', 'Ethernet II', 'Internet Protocol Version 4', 'User Datagram Protocol', 'QUIC IETF']);

  // **The doubling trap.** `frameProtocols` is derived from the layer NAMES,
  // and `udpTransport.ts` also pushes `quic` through `protocolTokens`. The
  // splice in `pcapParser.ts` filters a token a layer already supplies, so the
  // bareword must appear exactly once - twice reads as a protocol nested inside
  // itself, and `quic` in a filter or a colour rule would still match, which is
  // what would make it silent.
  check('the bareword appears exactly once',
    (initial.frameProtocols ?? []).filter((t) => t === 'quic').length, 1);
  check('...and after udp, not before it',
    initial.frameProtocols, ['frame', 'eth', 'ip', 'udp', 'quic']);
}

// --- the clear header --------------------------------------------------------

console.log('\n--- the header, which is in the clear ---');
{
  const initial = at('initial');
  check('header form', valueOf(initial, 'quic.header_form'), 'Long Header (1)');
  check('packet type', valueOf(initial, 'quic.long.packet_type'), 'Initial (0)');
  check('version', valueOf(initial, 'quic.version'), '0x00000001');
  check('destination connection id length', valueOf(initial, 'quic.dcil'), 8);
  check('destination connection id', valueOf(initial, 'quic.dcid'), DCID_HEX);
  check('source connection id length', valueOf(initial, 'quic.scil'), 4);
  check('source connection id', valueOf(initial, 'quic.scid'), SCID_HEX);
  check('token length', valueOf(initial, 'quic.token_length'), 0);
  // The header's own Length field covers the packet number and the protected
  // payload - 21 bytes here, not the 42 the packet occupies.
  check('length', valueOf(initial, 'quic.length'), 21);

  check('the filterable half reaches the bag', [
    fieldValue(initial, 'quic.version'),
    fieldValue(initial, 'quic.long.packet_type'),
    fieldValue(initial, 'quic.dcid'),
    fieldValue(initial, 'quic.scid'),
  ], [1, 0, DCID_HEX, SCID_HEX]);

  // `treeOnly` means the row is drawn and the bag does not answer. Asserted
  // rather than assumed, because the two halves are registered a line apart in
  // `fieldRegistry.ts` and a stray bag write is invisible on screen.
  check('the accounting half is tree-only', [
    fieldValue(initial, 'quic.dcil'),
    fieldValue(initial, 'quic.token_length'),
    fieldValue(initial, 'quic.length'),
  ], [undefined, undefined, undefined]);
}

// --- what a packet that will not decrypt still says --------------------------

console.log('\n--- an undecryptable packet degrades to its header ---');
{
  const initial = at('initial');
  check('no packet number is invented', valueOf(initial, 'quic.packet_number'), undefined);
  check('...and no frame types either', allValuesOf(initial, 'quic.frame_type'), []);
  // The Info column is what `scripts/parity/parity-check.ts` holds to the
  // reference frame for frame, so it must be unchanged by any of this.
  check('the Info column is the header and nothing more',
    initial.info, `Initial, DCID=${DCID_HEX}`);
  check('the Protocol column still reads QUIC', initial.protocol, 'QUIC');
}

// --- one datagram, several packets, one layer --------------------------------

console.log('\n--- coalesced packets ---');
{
  const coalesced = at('coalesced');
  check('two packets still make one layer',
    layerNames(coalesced).filter((n) => n === 'QUIC IETF').length, 1);
  check('...with a subtree each',
    allValuesOf(coalesced, 'quic.long.packet_type'), ['Initial (0)', 'Handshake (2)']);
  check('...and the bareword is still singular',
    (coalesced.frameProtocols ?? []).filter((t) => t === 'quic').length, 1);
  // The reference summarizes a coalesced datagram with the LAST packet, which
  // is what `dissectQuicDatagram` returns and what the Info floors are built
  // on. The tree draws all of them; the column names one.
  check('the Info column is the last packet', coalesced.info, `Handshake, DCID=${DCID_HEX}`);
}

// --- the two headers that are not the usual shape ----------------------------

console.log('\n--- version negotiation and the short header ---');
{
  const vn = at('version negotiation');
  check('version zero is Version Negotiation', vn.info, 'Version Negotiation');
  check('...and it has a version row', valueOf(vn, 'quic.version'), '0x00000000');
  // The type bits in a Version Negotiation packet's first byte are arbitrary,
  // so a row drawn from them would be a number the sender chose at random.
  check('...and no packet type at all', valueOf(vn, 'quic.long.packet_type'), undefined);

  const short = at('short header');
  check('a short header is a short header', valueOf(short, 'quic.header_form'), 'Short Header (0)');
  check('...carries no version', valueOf(short, 'quic.version'), undefined);
  // Only readable because the long headers above taught the tracker the id.
  check('...and its connection id came from the flow, not the wire',
    valueOf(short, 'quic.dcid'), DCID_HEX);
}

// --- the reference agrees ----------------------------------------------------

const TSHARK_CANDIDATES = [
  process.env.TSHARK, 'tshark',
  'C:/Program Files/Wireshark/tshark.exe',
  'C:/Program Files (x86)/Wireshark/tshark.exe',
  '/usr/bin/tshark', '/usr/local/bin/tshark', '/opt/homebrew/bin/tshark',
].filter((p): p is string => typeof p === 'string' && p.length > 0);

function findTshark(): string | null {
  useRepositoryWiresharkProfile();
  for (const candidate of TSHARK_CANDIDATES) {
    if (existsSync(candidate)) return candidate;
    try {
      execFileSync(candidate, ['-v'], { stdio: 'ignore' });
      return candidate;
    } catch { /* not here */ }
  }
  return null;
}

const tshark = findTshark();
if (tshark === null) {
  console.log('\nSKIP  tshark not found - the assertions above ran; the cross-check did not.');
} else {
  console.log(`\n--- the reference agrees (${tshark}) ---`);
  // `-e` repeats a field once per occurrence, comma-separated, which is how the
  // reference expresses what this build expresses as repeated tree rows - so a
  // coalesced datagram's two packet types come back as one cell.
  const columns = ['quic.version', 'quic.dcid', 'quic.scid', 'quic.long.packet_type',
    'quic.dcil', 'quic.token_length', 'quic.length', 'frame.protocols'];
  const out = execFileSync(tshark, ['-r', capture, '-T', 'fields',
    ...columns.flatMap((c) => ['-e', c]), '-E', 'separator=|'], { encoding: 'utf8' });
  const reference = out.trimEnd().split('\n').map((line) => {
    const cells = line.replace(/\r$/, '').split('|');
    return Object.fromEntries(columns.map((c, i) => [c, cells[i] ?? ''])) as Record<string, string>;
  });
  const row = (name: string) => reference[FRAMES.findIndex((f) => f.name === name)];

  // The abbrevs above are the reason this block matters more than it looks:
  // every one of them is a name `scripts/dissect/wireshark-abbrevs.ts` holds
  // against `tshark -G fields`, and a cell that comes back empty for every
  // frame means the name is wrong rather than the value.
  check('the reference reads the same version', row('initial')['quic.version'], '0x00000001');
  // Colons stripped rather than matched: the reference prints a bytes field as
  // `01:02:...` or as a bare run depending on its version, and which one it
  // picks says nothing about whether it read the same eight bytes.
  const bare = (cell: string) => cell.replace(/:/g, '');
  check('the reference reads the same connection ids',
    [bare(row('initial')['quic.dcid']), bare(row('initial')['quic.scid'])],
    [DCID_HEX, SCID_HEX]);
  check('the reference reads the same lengths',
    [row('initial')['quic.dcil'], row('initial')['quic.token_length'], row('initial')['quic.length']],
    ['8', '0', '21']);
  check('the reference sees two packets in the coalesced datagram',
    row('coalesced')['quic.long.packet_type'], '0,2');
  check('the reference nests QUIC under UDP',
    row('initial')['frame.protocols'], 'eth:ethertype:ip:udp:quic');
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All QUIC dissection checks passed.');
