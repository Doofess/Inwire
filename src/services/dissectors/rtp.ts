/**
 * RTP (RFC 3550): the audio and video of a call - Teams, Meet, WhatsApp, a
 * SIP phone - and RFC 4733's telephone events riding in it.
 *
 *   PT=ITU-T G.711 PCMU, SSRC=0x11223344, Seq=1, Time=160
 *   PT=DynamicRTP-Type-111, SSRC=0x5E2A01C4, Seq=4812, Time=96000, Mark
 *   Payload type=RTP Event, DTMF Five 5 (end)
 *
 * RTP has no port and no magic number, so whether a datagram IS one is not
 * this module's question: `rtpStreams.ts` answers it per flow, and this reads
 * a datagram that flow has been settled for. What this module does decide is
 * whether a datagram is shaped like RTP at all - `looksLikeRtp`, the
 * reference's own structural checks, plus RFC 5761's rule that keeps RTCP out.
 *
 * Rows, names and Info are the reference's, checked against `tshark -T pdml`
 * by `scripts/rtp/dissect.ts`, including RFC 8285's one- and two-byte header
 * extensions - the audio-level and transport-sequence numbers every WebRTC
 * packet carries. Payload types 100 and 101 read as telephone events because
 * that is the reference's default for them; a capture's own session
 * description is not consulted for that yet.
 *
 * Not read, where the reference hands the payload on: the codecs with a
 * dissector of their own (G.723.1, JPEG, H.261, MPEG-1 video, MPEG-2
 * transport and H.263 among the static types), RFC 2198 redundancy on payload
 * type 99, and ED137's radio header extension. Their payload and extension
 * words are drawn as bytes, under an RTP Protocol column where the reference
 * names the codec.
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';
import type { RtpStreamFacts } from '../rtpStreams';
import { RTP_EVENTS } from './rtpEventNames';

/** The static payload types the reference names (RFC 3551). */
const STATIC_TYPES: Readonly<Record<number, string>> = {
  0: 'ITU-T G.711 PCMU',
  1: 'USA Federal Standard FS-1016',
  2: 'ITU-T G.721',
  3: 'GSM 06.10',
  4: 'ITU-T G.723',
  5: 'DVI4 8000 samples/s',
  6: 'DVI4 16000 samples/s',
  7: 'Experimental linear predictive encoding from Xerox PARC',
  8: 'ITU-T G.711 PCMA',
  9: 'ITU-T G.722',
  10: '16-bit uncompressed audio, stereo',
  11: '16-bit uncompressed audio, monaural',
  12: 'Qualcomm Code Excited Linear Predictive coding',
  13: 'Comfort noise',
  14: 'MPEG-I/II Audio',
  15: 'ITU-T G.728',
  16: 'DVI4 11025 samples/s',
  17: 'DVI4 22050 samples/s',
  18: 'ITU-T G.729',
  19: 'Comfort noise (old)',
  25: 'Sun CellB video encoding',
  26: 'JPEG-compressed video',
  28: "'nv' program",
  31: 'ITU-T H.261',
  32: 'MPEG-I/II Video',
  33: 'MPEG-II transport streams',
  34: 'ITU-T H.263',
};

/** The payload types the reference reads as RFC 4733 events by default: 101, and Cisco's NSE on 100. */
const EVENT_TYPES = new Set([100, 101]);

const ONE_BYTE_PROFILE = 0xbede;

export function payloadTypeName(pt: number): string {
  if (pt >= 96) return `DynamicRTP-Type-${pt}`;
  return STATIC_TYPES[pt] ?? 'Unassigned';
}

function profileName(profile: number): string {
  if (profile === ONE_BYTE_PROFILE) return 'RFC 5285 One-Byte Header Extensions';
  if ((profile & 0xfff0) === 0x1000) return 'RFC 5285 Two-Byte Header Extensions';
  if (profile === 103) return 'ED137';
  if (profile === 359) return 'ED137A';
  return 'Unknown';
}

const u16 = (b: Uint8Array, at: number) => (b[at] << 8) | b[at + 1];
const u32 = (b: Uint8Array, at: number) => ((b[at] << 24) | (b[at + 1] << 16) | (b[at + 2] << 8) | b[at + 3]) >>> 0;
const hex = (b: Uint8Array, from: number, to: number) => {
  let s = '';
  for (let i = from; i < to; i++) s += (b[i] < 16 ? '0' : '') + b[i].toString(16);
  return s;
};

/** The fixed header's numbers, which is what a flow is judged by. */
export interface RtpHeader {
  payloadType: number;
  seq: number;
  timestamp: number;
  ssrc: number;
}

/** Where a datagram's parts lie, once its lengths have been checked. */
interface Layout {
  csrcCount: number;
  /** The extension header's offset, or -1. */
  extension: number;
  extensionEnd: number;
  payload: number;
  /** Where the payload stops: the padding's start, or the datagram's end. */
  payloadEnd: number;
  padding: number;
}

/**
 * Whether these bytes are shaped like RTP, and where their parts are.
 *
 * The reference's structural checks, which its heuristic and its decode of a
 * known flow both make: version 2, a 12-byte header, contributing sources and
 * an extension that fit, and a padding count that is neither zero nor more
 * than the payload. Payload types 72-76 are refused, as the reference refuses
 * them - an RTCP Sender Report's first two bytes read as one - and so is
 * anything RFC 5761 reserves for RTCP when the two share a port: the marker
 * set over 64-95, which is every RTCP packet type.
 *
 * `cut` is a datagram a snaplen shortened: its padding count is not there to
 * read, so the payload runs to what was kept.
 */
function layoutOf(b: Uint8Array, start: number, end: number, cut = false): Layout | null {
  if (end - start < 12) return null;
  const first = b[start];
  if (first >> 6 !== 2) return null;
  const second = b[start + 1];
  const pt = second & 0x7f;
  if (pt >= 72 && pt <= 76) return null;
  if (second >= 192 && second <= 223) return null;
  const csrcCount = first & 0x0f;
  let at = start + 12 + 4 * csrcCount;
  if (at > end) return null;
  let extension = -1;
  let extensionEnd = at;
  if ((first & 0x10) !== 0) {
    if (at + 4 > end) return null;
    extension = at;
    extensionEnd = at + 4 + 4 * u16(b, at + 2);
    if (extensionEnd > end) return null;
    at = extensionEnd;
  }
  let padding = 0;
  if ((first & 0x20) !== 0 && !cut) {
    padding = b[end - 1];
    if (padding === 0 || at + padding > end) return null;
  }
  return { csrcCount, extension, extensionEnd, payload: at, payloadEnd: end - padding, padding };
}

export function looksLikeRtp(b: Uint8Array, start: number, end: number, cut = false): boolean {
  return layoutOf(b, start, end, cut) !== null;
}

export function rtpHeader(b: Uint8Array, start: number): RtpHeader {
  return { payloadType: b[start + 1] & 0x7f, seq: u16(b, start + 2), timestamp: u32(b, start + 4), ssrc: u32(b, start + 8) };
}

export interface RtpResult {
  protocolLabel: string;
  info: string;
  layers: ProtocolLayer[];
  tokens: string[];
  fields: Record<string, string | number>;
}

/** RFC 8285's elements, one- or two-byte, as packet-rtp.c walks them. */
function extensionElements(b: Uint8Array, from: number, to: number, twoByte: boolean, appBits: number): ProtocolField[] {
  const rows: ProtocolField[] = [];
  let at = from;
  while (at < to) {
    const padStart = at;
    while (at < to && b[at] === 0) at++;
    // Trailing zeros are the extension's own padding to a word, and the
    // reference draws nothing for them.
    if (at >= to) break;
    if (at > padStart) {
      rows.push({ name: 'Padding data', value: hex(b, padStart, at), abbrev: 'rtp.padding.data', rawBytesRange: [padStart, at - 1] });
    }
    const id = twoByte ? b[at] : b[at] >> 4;
    // A one-byte header's 15 is reserved for a future format: the reference
    // stops reading there.
    if (!twoByte && id === 15) break;
    const headerLength = twoByte ? 2 : 1;
    if (twoByte && at + 1 >= to) break;
    const length = twoByte ? b[at + 1] : (b[at] & 0x0f) + 1;
    const dataEnd = at + headerLength + length;
    // An element longer than what is left ends the walk, unremarked.
    if (dataEnd > to) break;
    const children: ProtocolField[] = [];
    if (twoByte) children.push({ name: 'Application Bits', value: appBits, abbrev: 'rtp.ext.rfc5285.appbits', rawBytesRange: [at, at] });
    children.push(
      { name: 'Identifier', value: id, abbrev: 'rtp.ext.rfc5285.id', rawBytesRange: [at, at] },
      { name: 'Length', value: length, abbrev: 'rtp.ext.rfc5285.len', rawBytesRange: twoByte ? [at + 1, at + 1] : [at, at] },
    );
    if (length > 0) {
      children.push({
        name: 'Extension Data', value: hex(b, at + headerLength, dataEnd), abbrev: 'rtp.ext.rfc5285.data',
        rawBytesRange: [at + headerLength, dataEnd - 1],
      });
    }
    rows.push({
      name: `RFC 5285 Header Extension (${twoByte ? 'Two' : 'One'}-Byte Header)`, value: '',
      rawBytesRange: [at, dataEnd - 1], children,
    });
    at = dataEnd;
  }
  return rows;
}

/** RFC 4733's event, the first in the payload - the reference reads no further. */
function eventLayer(b: Uint8Array, at: number): { layer: ProtocolLayer; info: string; fields: Record<string, number> } {
  const id = b[at];
  const flags = b[at + 1];
  const end = (flags & 0x80) !== 0;
  const name = RTP_EVENTS[id] ?? 'Unknown';
  const fields = {
    'rtpevent.event_id': id,
    'rtpevent.end_of_event': end ? 1 : 0,
    'rtpevent.volume': flags & 0x3f,
    'rtpevent.duration': u16(b, at + 2),
  };
  return {
    info: `Payload type=RTP Event, ${RTP_EVENTS[id] ?? `Unknown (${id})`}${end ? ' (end)' : ''}`,
    fields,
    layer: {
      name: 'RFC 2833 RTP Event',
      summary: 'RFC 2833 RTP Event',
      rawBytesRange: [at, at + 3],
      fields: [
        { name: 'Event ID', value: `${name} (${id})`, abbrev: 'rtpevent.event_id', rawBytesRange: [at, at] },
        { name: 'End of Event', value: end, abbrev: 'rtpevent.end_of_event', rawBytesRange: [at + 1, at + 1], bitfield: { bitOffset: 0, bitLength: 1, totalBits: 8 } },
        { name: 'Reserved', value: (flags & 0x40) !== 0, abbrev: 'rtpevent.reserved', rawBytesRange: [at + 1, at + 1], bitfield: { bitOffset: 1, bitLength: 1, totalBits: 8 } },
        { name: 'Volume', value: flags & 0x3f, abbrev: 'rtpevent.volume', rawBytesRange: [at + 1, at + 1], bitfield: { bitOffset: 2, bitLength: 6, totalBits: 8 } },
        { name: 'Event Duration', value: u16(b, at + 2), abbrev: 'rtpevent.duration', rawBytesRange: [at + 2, at + 3] },
      ],
    },
  };
}

/**
 * Reads one RTP datagram of a settled flow. Null only when it is not shaped
 * like RTP, which a caller has normally asked `looksLikeRtp` already.
 */
export function dissectRtp(b: Uint8Array, start: number, end: number, stream: RtpStreamFacts, cut = false): RtpResult | null {
  const layout = layoutOf(b, start, end, cut);
  if (layout === null) return null;
  const first = b[start];
  const second = b[start + 1];
  const { payloadType: pt, seq, timestamp, ssrc } = rtpHeader(b, start);
  const marker = (second & 0x80) !== 0;
  const padded = (first & 0x20) !== 0;
  const extended = (first & 0x10) !== 0;
  const ptName = payloadTypeName(pt);
  const flag = (offset: number): ProtocolField['bitfield'] => ({ bitOffset: offset, bitLength: 1, totalBits: 8 });

  const rows: ProtocolField[] = [
    {
      name: `Stream setup by ${stream.setupMethod} (frame ${stream.setupFrame})`, value: '', abbrev: 'rtp.setup', generated: true,
      children: [
        { name: 'Setup frame', value: stream.setupFrame, abbrev: 'rtp.setup-frame', generated: true, linkToFrame: stream.setupFrame },
        { name: 'Setup Method', value: stream.setupMethod, abbrev: 'rtp.setup-method', generated: true },
      ],
    },
    { name: 'Version', value: 'RFC 1889 Version (2)', abbrev: 'rtp.version', rawBytesRange: [start, start], bitfield: { bitOffset: 0, bitLength: 2, totalBits: 8 } },
    { name: 'Padding', value: padded, abbrev: 'rtp.padding', rawBytesRange: [start, start], bitfield: flag(2) },
    { name: 'Extension', value: extended, abbrev: 'rtp.ext', rawBytesRange: [start, start], bitfield: flag(3) },
    { name: 'Contributing source identifiers count', value: layout.csrcCount, abbrev: 'rtp.cc', rawBytesRange: [start, start], bitfield: { bitOffset: 4, bitLength: 4, totalBits: 8 } },
    { name: 'Marker', value: marker, abbrev: 'rtp.marker', rawBytesRange: [start + 1, start + 1], bitfield: flag(0) },
    { name: 'Payload type', value: `${ptName} (${pt})`, abbrev: 'rtp.p_type', rawBytesRange: [start + 1, start + 1] },
    { name: 'Sequence number', value: seq, abbrev: 'rtp.seq', rawBytesRange: [start + 2, start + 3] },
    { name: 'Extended sequence number', value: stream.extSeq, abbrev: 'rtp.extseq', generated: true },
    { name: 'Timestamp', value: timestamp, abbrev: 'rtp.timestamp', rawBytesRange: [start + 4, start + 7] },
    { name: 'Extended timestamp', value: stream.extTs, abbrev: 'rtp.timestamp_ext', generated: true },
    {
      name: 'Synchronization Source identifier', value: `0x${ssrc.toString(16).padStart(8, '0')} (${ssrc})`,
      abbrev: 'rtp.ssrc', rawBytesRange: [start + 8, start + 11],
    },
  ];

  if (layout.csrcCount > 0) {
    const items: ProtocolField[] = [];
    for (let i = 0; i < layout.csrcCount; i++) {
      const at = start + 12 + 4 * i;
      items.push({ name: `CSRC item ${i}`, value: `0x${u32(b, at).toString(16).toUpperCase()}`, abbrev: 'rtp.csrc.item', rawBytesRange: [at, at + 3] });
    }
    rows.push({
      name: `Contributing Source identifiers (${layout.csrcCount} items)`, value: '', abbrev: 'rtp.csrc.items',
      rawBytesRange: [start + 12, start + 12 + 4 * layout.csrcCount - 1], children: items,
    });
  }

  if (layout.extension >= 0) {
    const at = layout.extension;
    const profile = u16(b, at);
    const words = u16(b, at + 2);
    rows.push(
      { name: 'Defined by profile', value: `${profileName(profile)} (0x${profile.toString(16).padStart(4, '0')})`, abbrev: 'rtp.ext.profile', rawBytesRange: [at, at + 1] },
      { name: 'Extension length', value: words, abbrev: 'rtp.ext.len', rawBytesRange: [at + 2, at + 3] },
    );
    if (words > 0) {
      const from = at + 4;
      const to = layout.extensionEnd;
      let children: ProtocolField[];
      if (profile === ONE_BYTE_PROFILE) children = extensionElements(b, from, to, false, 0);
      else if ((profile & 0xfff0) === 0x1000) children = extensionElements(b, from, to, true, profile & 0x0f);
      else {
        children = [];
        for (let w = from; w < to; w += 4) {
          const v = u32(b, w);
          children.push({ name: 'Header extension', value: `0x${v.toString(16).padStart(8, '0')} (${v})`, abbrev: 'rtp.hdr_ext', rawBytesRange: [w, w + 3] });
        }
      }
      rows.push({ name: 'Header extensions', value: '', abbrev: 'rtp.hdr_exts', rawBytesRange: [from, to - 1], children });
    }
  }

  const fields: Record<string, string | number> = {
    'rtp.version': 2,
    'rtp.padding': padded ? 1 : 0,
    'rtp.ext': extended ? 1 : 0,
    'rtp.cc': layout.csrcCount,
    'rtp.marker': marker ? 1 : 0,
    'rtp.p_type': pt,
    'rtp.seq': seq,
    'rtp.extseq': stream.extSeq,
    'rtp.timestamp': timestamp,
    'rtp.ssrc': ssrc,
  };
  const layers: ProtocolLayer[] = [];
  const tokens = ['rtp'];
  let protocolLabel = 'RTP';
  let info = `PT=${ptName}, SSRC=0x${ssrc.toString(16).toUpperCase()}, Seq=${seq}, Time=${timestamp}${marker ? ', Mark' : ''}`;

  const payloadLength = layout.payloadEnd - layout.payload;
  let event: ReturnType<typeof eventLayer> | null = null;
  if (EVENT_TYPES.has(pt) && payloadLength >= 4) event = eventLayer(b, layout.payload);
  else if (payloadLength > 0) {
    rows.push({ name: 'Payload', value: hex(b, layout.payload, layout.payloadEnd), abbrev: 'rtp.payload', rawBytesRange: [layout.payload, layout.payloadEnd - 1] });
  }
  if (layout.padding > 0) {
    if (layout.padding > 1) {
      rows.push({ name: 'Padding data', value: hex(b, layout.payloadEnd, end - 1), abbrev: 'rtp.padding.data', rawBytesRange: [layout.payloadEnd, end - 2] });
    }
    rows.push({ name: 'Padding count', value: layout.padding, abbrev: 'rtp.padding.count', rawBytesRange: [end - 1, end - 1] });
  }

  layers.push({ name: 'Real-Time Transport Protocol', summary: 'Real-Time Transport Protocol', rawBytesRange: [start, end - 1], fields: rows });
  if (event !== null) {
    layers.push(event.layer);
    tokens.push('rtpevent');
    protocolLabel = 'RTP EVENT';
    info = event.info;
    Object.assign(fields, event.fields);
  }
  return { protocolLabel, info, layers, tokens, fields };
}
