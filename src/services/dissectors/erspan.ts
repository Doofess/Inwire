/**
 * ERSPAN: a switch's port mirror, sent across a routed network inside GRE.
 *
 * A SPAN port copies a switch port's traffic to another port on the same
 * switch. ERSPAN copies it to an IP address instead - Cisco's, and Arista's,
 * Juniper's, Linux's (`ip link add type erspan`) and the cloud providers'
 * traffic mirroring - so a capture on the receiving machine holds other hosts'
 * frames, each wrapped in IP, GRE and an ERSPAN header. Reading it THROUGH is
 * what lets one machine watch a whole network without a hub, a tap or a
 * mirror port of its own.
 *
 * Three formats, told apart as the reference tells them apart:
 *
 *   type I    GRE protocol 0x88BE with no sequence number. No ERSPAN header
 *             at all - the mirrored frame starts straight after GRE.
 *   type II   GRE protocol 0x88BE with a sequence number, and an 8-byte
 *             header whose version nibble is 1.
 *   type III  a 12-byte header whose version nibble is 2 (usually GRE
 *             protocol 0x22EB, but the reference reads the nibble, not the
 *             protocol), and when its O bit is set an 8-byte platform
 *             subheader whose layout the 6-bit platform id picks.
 *
 * Every field name and value is the reference's, held row for row by
 * `scripts/erspan/dissect.ts`. Two of its choices are matched rather than
 * corrected, because a capture read two ways is worse than either:
 *
 *   - **Type III opens the mirrored frame only when its Frame Type is
 *     Ethernet.** Type 2 is IP, and the reference leaves it as data rather
 *     than reading it as IP; so does this.
 *   - **Platform 2's Reserved row**, which every undefined platform id gets
 *     too, is the low 26 bits of the subheader's SECOND word: the reference
 *     reads all eight bytes as one number and masks the low end. It is
 *     reserved either way.
 *
 * The header is read a field at a time against what arrived, so a cut header
 * shows every field it kept and then `[Malformed Packet: ERSPAN]`, which is
 * where the reference stops too.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import { GRE_ERSPAN } from './gre';

const LAYER_NAME = 'Encapsulated Remote Switch Packet ANalysis';

const VERSIONS: Record<number, string> = { 1: 'Type II', 2: 'Type III' };
const ENCAP = [
  'Originally without VLAN tag', 'Originally ISL encapsulated',
  'Originally 802.1Q encapsulated', 'VLAN tag preserved in frame',
];
const BSO = ['Good or unknown integrity', 'Short frame', 'Oversized frame', 'CRC or alignment error'];
const FRAME_TYPES: Record<number, string> = { 0: 'Ethernet', 2: 'IP' };
const GRANULARITY = ['100 microseconds', '100 nanoseconds', 'IEEE 1588', 'Custom granularity'];

export interface ErspanResult {
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
  /**
   * What follows the header: a mirrored Ethernet frame at `payloadStart`;
   * bytes the reference leaves as data; nothing it reads at all (a version it
   * does not know); or a header cut short.
   */
  carries: 'ethernet' | 'data' | 'none' | 'malformed';
  payloadStart: number;
}

/** A header that ended before this field did. */
class Short extends Error {}

/**
 * Reads the ERSPAN header that starts at `start`, behind a GRE header of
 * `protocolType` that did or did not carry a sequence number.
 */
export function readErspan(
  bytes: Uint8Array, start: number, end: number, protocolType: number, greHasSequence: boolean,
): ErspanResult {
  const rows: ProtocolField[] = [];
  const fields: Record<string, string | number> = {};
  const layer = (kind: string, headerEnd: number): ProtocolLayer => ({
    name: LAYER_NAME,
    summary: `${LAYER_NAME} ${kind}`,
    ...(headerEnd > start ? { rawBytesRange: [start, headerEnd - 1] as [number, number] } : {}),
    fields: rows,
  });

  if (protocolType === GRE_ERSPAN && !greHasSequence) {
    return { layer: layer('Type I', start), fields, carries: 'ethernet', payloadStart: start };
  }

  const need = (at: number, length: number) => {
    if (at + length > end) throw new Short();
  };
  const u16 = (at: number) => (bytes[at] << 8) | bytes[at + 1];
  const u32 = (at: number) => ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0;
  /** One row of a 16- or 32-bit word: `bits` wide, `offset` bits from its top. */
  const bitsRow = (
    at: number, width: 16 | 32, offset: number, bits: number, name: string, abbrev: string,
    show: (n: number) => string | number = (n) => n,
  ): number => {
    need(at, width / 8);
    const word = width === 16 ? u16(at) : u32(at);
    const value = Math.floor(word / 2 ** (width - offset - bits)) % 2 ** bits;
    rows.push({
      name, value: show(value), abbrev, rawBytesRange: [at, at + width / 8 - 1],
      bitfield: { bitOffset: offset, bitLength: bits, totalBits: width },
    });
    return value;
  };
  const named = (names: Record<number, string> | readonly string[]) =>
    (n: number) => `${(names as Record<number, string>)[n] ?? 'Unknown'} (${n})`;

  let version = -1;
  let headerEnd = start;
  let carries: ErspanResult['carries'] = 'ethernet';
  try {
    need(start, 2);
    version = (bytes[start] >> 4) & 0xf;
    const versionRow = (): ProtocolField => ({
      name: 'Version', value: named(VERSIONS)(version), abbrev: 'erspan.version',
      rawBytesRange: [start, start + 1], bitfield: { bitOffset: 0, bitLength: 4, totalBits: 16 },
    });
    rows.push(versionRow());
    fields['erspan.version'] = version;
    if (version !== 1 && version !== 2) {
      // The reference draws the row a second time, with its complaint under
      // it, and reads nothing further.
      rows.push({
        ...versionRow(),
        children: [{
          name: 'Unknown version, please report or test to use fake ERSPAN preference', value: '',
          abbrev: 'erspan.version.unknown', generated: true,
          expertInfo: { category: 'Broken', message: 'Unknown version, please report or test to use fake ERSPAN preference' },
        }],
      });
      return { layer: layer('Unknown', start + 2), fields, carries: 'none', payloadStart: start + 2 };
    }
    fields['erspan.vlan'] = bitsRow(start, 16, 4, 12, 'Vlan', 'erspan.vlan');
    bitsRow(start + 2, 16, 0, 3, 'COS', 'erspan.cos');
    if (version === 1) bitsRow(start + 2, 16, 3, 2, 'Encap', 'erspan.encap', named(ENCAP));
    else bitsRow(start + 2, 16, 3, 2, 'Bad/Short/Oversized', 'erspan.bso', named(BSO));
    bitsRow(start + 2, 16, 5, 1, 'Truncated', 'erspan.truncated', (n) => (n ? 'Truncated (1)' : 'Not truncated (0)'));
    fields['erspan.spanid'] = bitsRow(start + 2, 16, 6, 10, 'SpanID', 'erspan.spanid');

    if (version === 1) {
      bitsRow(start + 4, 32, 0, 12, 'Reserved', 'erspan.reserved');
      bitsRow(start + 4, 32, 12, 20, 'Index', 'erspan.index');
      headerEnd = start + 8;
    } else {
      need(start + 4, 4);
      rows.push({ name: 'Timestamp', value: u32(start + 4), abbrev: 'erspan.timestamp', rawBytesRange: [start + 4, start + 7] });
      need(start + 8, 2);
      rows.push({ name: 'Security Group Tag', value: u16(start + 8), abbrev: 'erspan.sgt', rawBytesRange: [start + 8, start + 9] });
      const flagsAt = start + 10;
      bitsRow(flagsAt, 16, 0, 1, 'Has Ethernet PDU', 'erspan.p');
      const frameType = bitsRow(flagsAt, 16, 1, 5, 'Frame Type', 'erspan.ft', named(FRAME_TYPES));
      bitsRow(flagsAt, 16, 6, 6, 'Hardware ID', 'erspan.hw');
      bitsRow(flagsAt, 16, 12, 1, 'Direction', 'erspan.direction', (n) => (n ? 'Egress' : 'Ingress'));
      bitsRow(flagsAt, 16, 13, 2, 'Timestamp granularity', 'erspan.gra', named(GRANULARITY));
      const subheader = bitsRow(flagsAt, 16, 15, 1, 'Optional Sub headers', 'erspan.o');
      headerEnd = start + 12;
      if (subheader === 1) {
        platformRows(start + 12);
        headerEnd = start + 20;
      }
      if (frameType !== 0) carries = 'data';
    }
  } catch (error) {
    if (!(error instanceof Short)) throw error;
    rows.push({
      name: '[Malformed Packet: ERSPAN]', value: '', generated: true,
      expertInfo: { category: 'Broken', message: 'Malformed Packet (Exception occurred)' },
    });
    const kind = version === 1 || version === 2 ? VERSIONS[version] : 'Unknown';
    return { layer: layer(kind, end), fields, carries: 'malformed', payloadStart: end };
  }
  return { layer: layer(VERSIONS[version], headerEnd), fields, carries, payloadStart: headerEnd };

  /** The platform-specific subheader, whose layout the platform id picks. */
  function platformRows(at: number): void {
    const platform = bitsRow(at, 32, 0, 6, 'Platform ID', 'erspan.platid');
    need(at + 4, 4);
    const second = u32(at + 4);
    const upper = (name: string, abbrev: string) =>
      rows.push({ name, value: second, abbrev, rawBytesRange: [at + 4, at + 7] });
    switch (platform) {
      case 1:
        bitsRow(at, 32, 6, 14, 'Reserved', 'erspan.pid1.rsvd1');
        bitsRow(at, 32, 20, 12, 'VSM Domain ID', 'erspan.pid1.vsmid');
        upper('Port ID/Index', 'erspan.pid1.port_index');
        break;
      case 3:
        bitsRow(at, 32, 6, 12, 'Reserved', 'erspan.pid3.rsvd1');
        bitsRow(at, 32, 18, 14, 'Port ID/Index', 'erspan.pid3.port_index');
        upper('Upper 32-bit Timestamp', 'erspan.pid3.timestamp');
        break;
      case 4:
        bitsRow(at, 32, 6, 12, 'Reserved', 'erspan.pid4.rsvd1');
        bitsRow(at, 32, 18, 14, 'Reserved', 'erspan.pid4.rsvd2');
        upper('Reserved', 'erspan.pid4.rsvd3');
        break;
      case 5:
      case 6:
        bitsRow(at, 32, 6, 10, 'Switch ID', 'erspan.pid5.switchid');
        bitsRow(at, 32, 16, 16, 'Port ID/Index', 'erspan.pid5.port_index');
        upper('Timestamp (seconds)', 'erspan.pid5.timestamp');
        break;
      case 0:
      case 7:
        bitsRow(at, 32, 6, 6, 'Reserved', 'erspan.pid7.rsvd1');
        bitsRow(at, 32, 12, 20, 'Source Index', 'erspan.pid7.source_index');
        upper('Upper 32-bit Timestamp', 'erspan.pid7.timestamp');
        break;
      default:
        // Platform 2, and every id the draft does not define.
        rows.push({
          name: 'Reserved', value: second % 2 ** 26, abbrev: 'erspan.pid.rsvd', rawBytesRange: [at, at + 7],
          bitfield: { bitOffset: 38, bitLength: 26, totalBits: 64 },
        });
    }
  }
}
