/**
 * The media a SIP message's session description announces (RFC 4566), which
 * is how a signalled call's RTP is found: the reference reads the `c=` and
 * `m=` lines, and from then on a datagram to or from that address and port is
 * RTP, named with the `a=rtpmap` encodings the description gave - `PT=opus`
 * rather than `PT=DynamicRTP-Type-96`.
 *
 * Only what finding the media needs is read here. The description itself is
 * not drawn as a layer yet - the reference's column for such a message reads
 * `SIP/SDP` and this build's `SIP`.
 */
import { formatIpv6Address, parseIpv6 } from '../addressFormat';

/** One `m=` line's RTP endpoint. */
export interface SdpMedia {
  address: string;
  port: number;
  /** `a=rtpmap` encoding names, by dynamic payload type. */
  encodings: Record<number, string>;
}

/** What one SIP message's description says, and which exchange it belongs to. */
export interface SdpDescription {
  callId: string;
  /** A request's description is an offer or the answer to one in a response, and the reverse. */
  request: boolean;
  media: SdpMedia[];
}

const MAX_MESSAGE = 65535;
const text = new TextDecoder();

/** Header names and their RFC 3261 compact forms. */
const CALL_ID = new Set(['call-id', 'i']);
const CONTENT_TYPE = new Set(['content-type', 'c']);

export function sdpOfSip(bytes: Uint8Array, start: number, end: number): SdpDescription | null {
  const message = text.decode(bytes.subarray(start, Math.min(end, start + MAX_MESSAGE)));
  const split = message.indexOf('\r\n\r\n');
  const bodyStart = split >= 0 ? split + 4 : message.indexOf('\n\n') + 2;
  if (bodyStart < 2) return null;
  const lines = message.slice(0, bodyStart).split(/\r?\n/);
  const request = !lines[0].startsWith('SIP/');
  let callId: string | undefined;
  let sdp = false;
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (CALL_ID.has(name)) callId = value;
    else if (CONTENT_TYPE.has(name)) sdp = value.split(';')[0].trim().toLowerCase() === 'application/sdp';
  }
  if (!sdp || callId === undefined) return null;

  const media: SdpMedia[] = [];
  let sessionAddress: string | undefined;
  let current: { port: number; encodings: Record<number, string>; rtp: boolean; address?: string } | null = null;
  const close = () => {
    const address = current?.address ?? sessionAddress;
    if (current !== null && current.rtp && current.port > 0 && address !== undefined) {
      media.push({ address, port: current.port, encodings: current.encodings });
    }
  };
  for (const raw of message.slice(bodyStart).split(/\r?\n/)) {
    const line = raw.trim();
    if (line.length < 2 || line[1] !== '=') continue;
    const value = line.slice(2);
    if (line[0] === 'm') {
      close();
      const [, port, proto] = value.split(/\s+/);
      current = { address: undefined, port: Number.parseInt(port ?? '', 10) || 0, encodings: {}, rtp: /^(UDP\/TLS\/)?RTP\//i.test(proto ?? '') };
    } else if (line[0] === 'c') {
      const [, type, address] = value.split(/\s+/);
      if ((type === 'IP4' || type === 'IP6') && address !== undefined) {
        // A multicast address carries a TTL and a count after a slash.
        // An IPv6 address is written as the datagram's own will be, so the
        // two compare as text.
        let bare = address.split('/')[0].toLowerCase();
        if (type === 'IP6') {
          const bytes = parseIpv6(bare);
          if (bytes === null) continue;
          bare = formatIpv6Address(bytes, 0);
        }
        if (current === null) sessionAddress = bare;
        else current.address = bare;
      }
    } else if (line[0] === 'a' && current !== null && value.startsWith('rtpmap:')) {
      // Only a dynamic type takes its description's name: the reference
      // still calls 0 `ITU-T G.711 PCMU` when an rtpmap says `PCMU`.
      const match = /^rtpmap:(\d+)\s+([^/\s]+)/.exec(value);
      if (match !== null && Number(match[1]) >= 96) current.encodings[Number(match[1])] = match[2];
    }
  }
  close();
  return media.length > 0 ? { callId, request, media } : null;
}
