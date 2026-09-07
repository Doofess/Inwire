/**
 * The pieces both transport decoders need.
 *
 * `checksumVerdict` is the offload policy - a checksum this machine has not
 * filled in yet is `Unverified`, never `Bad` - and TCP and UDP both ask it. The
 * three ASCII helpers under it turn a payload into something the Info column
 * can show, and both decoders reach for those too.
 *
 * They lived in `pcapParser.ts` because that is where the only two callers
 * lived. Splitting the transport branches into their own modules makes that
 * accidental: a helper two modules share is a module, not a private function
 * one of them happens to host.
 */
import { ETHERNET_MAX_FRAME } from '../direction';

/**
 * One decoder, not one per call - `new TextDecoder()` is not free, and
 * `scripts/perf/hot-path-allocations.ts` fails the build on one constructed
 * inside a function under `src/services/`.
 */
const utf8Decoder = new TextDecoder('utf-8', { fatal: false });

export const ETHERNET_IPV4_HEADER_BYTES = 14 + 20;

/** One's-complement sum over the pseudo-header and a byte range, RFC 1071. */
export function transportChecksum(pseudoHeader: Uint8Array, rawBytes: Uint8Array, start: number, end: number): number {
  let sum = 0;
  for (let i = 0; i + 1 < pseudoHeader.length; i += 2) sum += (pseudoHeader[i] << 8) | pseudoHeader[i + 1];
  for (let i = start; i + 1 < end; i += 2) sum += (rawBytes[i] << 8) | rawBytes[i + 1];
  if ((end - start) % 2 === 1) sum += rawBytes[end - 1] << 8;
  while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
  return (~sum) & 0xffff;
}

/**
 * Verdict on a transport checksum, with the offload policy Wireshark ships
 * (its TCP/UDP validation is off by default for exactly this reason): a
 * segment captured on the sending host before the NIC filled the checksum
 * in - one larger than the wire MTU (segmentation offload) or with a zero
 * checksum - is "Unverified", never "Bad". A frame the capture truncated is
 * Unverified too, since the bytes to check are not all there.
 */
export function checksumVerdict(
  pseudoHeader: Uint8Array | undefined, rawBytes: Uint8Array, start: number, declaredEnd: number, stored: number, udp: boolean,
  /**
   * True when this machine SENT the frame, which settles the question.
   *
   * The existing guards catch offload only where it leaves an obvious trace -
   * a zero checksum, a frame past the MTU. Windows' partial checksum offload
   * leaves neither: the NIC writes the pseudo-header sum and finishes the job
   * afterwards, so the field is non-zero, wrong, and indistinguishable from
   * corruption by looking at the bytes.
   *
   * Measured over both fixtures, that is **1,998 and 3,459 frames, and 100% of
   * them outbound** - every "Bad" checksum in either capture. Wireshark cannot
   * make this call because it does not know which frames the host sent; it
   * settles for shipping TCP/UDP validation off by default. Knowing the
   * direction, the honest verdict is Unverified.
   */
  sentByUs: boolean,
): { status: 'Good' | 'Bad' | 'Unverified'; computed?: number } {
  if (pseudoHeader === undefined || stored === 0 || declaredEnd > rawBytes.length || declaredEnd - start > ETHERNET_MAX_FRAME - ETHERNET_IPV4_HEADER_BYTES) {
    return { status: 'Unverified' };
  }
  if (sentByUs) return { status: 'Unverified' };
  const computed = transportChecksum(pseudoHeader, rawBytes, start, declaredEnd);
  // A UDP checksum computing to 0 is sent as 0xffff.
  const good = computed === 0 || (udp && computed === 0 && stored === 0xffff);
  return { status: good ? 'Good' : 'Bad', computed };
}

// Surfacing a readable hostname/URL in the Info column is far more useful at
// a glance than "Len=76" alone - but a generic "does this look like a domain"
// regex scanned over an entire payload is a bad idea: high-entropy encrypted
// traffic (TLS, QUIC on port 443) renders as ASCII noise once non-printable
// bytes become '.', and over a large enough payload that noise very often
// happens to look like a short hostname (e.g. "3b.Hl.sBR"). No amount of
// regex tightening fixes that, because that traffic genuinely contains no
// real hostname - any match there is a false positive by construction.
//
// So instead of one heuristic scan, this uses two precise extractors and
// only runs them where cleartext can plausibly exist:
//  - DNS query names are decoded from the actual wire format (length-prefixed
//    labels), not guessed at - the length byte must numerically match the
//    label that follows, which noise essentially never satisfies.
//  - Everywhere else, only literal, highly-specific prefixes ("http://",
//    "Host: ") are matched - safe because matching an exact multi-byte
//    literal by chance in random bytes is astronomically unlikely.
// Neither runs on known-encrypted traffic (TLS/QUIC on port 443), since that
// can never contain genuine plaintext.
export const URL_PATTERN = /https?:\/\/[^\s"'<>\\]+/;

export const HTTP_HOST_HEADER_PATTERN = /(?:^|\r\n)Host:\s*([^\r\n]+)/i;

// formatAsciiDump() turns CR/LF into '.' along with every other non-printable
// byte, which destroys the "\r\n" line boundary the Host-header match relies
// on - this variant keeps real CR/LF characters so line-based matching works,
// while still mapping every other non-printable byte to '.' as before.
export function toLineAwareText(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => {
      if (b === 13) return '\r';
      if (b === 10) return '\n';
      return b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
    })
    .join('');
}

export function extractLiteralUrlOrHost(rawBytes: Uint8Array, payloadStart: number): string | null {
  const text = toLineAwareText(rawBytes.slice(payloadStart));
  const urlMatch = text.match(URL_PATTERN);
  if (urlMatch) return urlMatch[0].replace(/[.,;:)]+$/, '');
  const hostMatch = text.match(HTTP_HOST_HEADER_PATTERN);
  return hostMatch ? hostMatch[1].trim() : null;
}

/**
 * Reads the first CRLF-terminated ASCII line of a text protocol payload
 * (SSDP's "M-SEARCH * HTTP/1.1", HTTP's request line). Returns null unless the
 * line is entirely printable and plausibly a request line, so binary payloads
 * on the same port don't produce mojibake in the Info column.
 */
export function readAsciiRequestLine(rawBytes: Uint8Array, payloadStart: number): string | null {
  const limit = Math.min(rawBytes.length, payloadStart + 256);
  let end = payloadStart;
  while (end < limit && rawBytes[end] !== 0x0d && rawBytes[end] !== 0x0a) {
    const byte = rawBytes[end];
    if (byte < 0x20 || byte > 0x7e) return null;
    end++;
  }
  if (end === payloadStart || end >= limit) return null;
  return utf8Decoder.decode(rawBytes.subarray(payloadStart, end));
}
