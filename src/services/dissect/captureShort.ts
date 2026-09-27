/**
 * Frames a snaplen cut short, and the one sentence that says so.
 *
 * A snaplen keeps the first N bytes of every frame and counts the rest in the
 * wire length (`Packet.length`), so a cut frame is one whose captured bytes
 * end before its wire length does. That alone is not what Wireshark marks:
 * Ethernet pads a short frame to 60 bytes, and a snaplen that cuts only the
 * padding has cut nothing anybody reads. What it marks is a frame whose
 * *content* ran past what was kept - so this asks where the frame's own
 * headers say the content ends (`declaredPayloadEnd`, which the Ethernet
 * trailer rows already ask).
 *
 * **Measured against the reference, and a superset of it on purpose.**
 * Wireshark appends `[Packet size limited during capture]` when a dissector
 * reads past the captured end, so a payload nothing reads - QUIC's protected
 * payload, the body of a TLS record in the middle of a stream - is cut and not
 * marked there. Here every frame whose content was cut is marked, because
 * "the capture did not keep all of this" is the fact a reader needs, and it
 * should not depend on whether a dissector happened to look.
 * `scripts/parity/snaplen.ts` counts both directions against tshark.
 */
import { declaredPayloadEnd } from '../dissectors/linkLayer';

const ETHERTYPE_IPV6 = 0x86dd;
const IPV6_HEADER_BYTES = 40;

/** Wireshark's words, appended to the Info column as it appends them. */
export const SIZE_LIMITED = '[Packet size limited during capture]';

/**
 * How many bytes of this frame's content the capture did not keep, or 0.
 *
 * `wireLength` of 0 means the source never said, which is not a cut. A
 * declared end at or before the headers themselves - an IPv4 total length or
 * IPv6 payload length of 0, which is segmentation offload leaving the field
 * for the NIC - says nothing, and neither does a type with no length at all;
 * both count to the wire length.
 */
export function bytesNotCaptured(
  rawBytes: Uint8Array, l3Offset: number, etherType: number, wireLength: number,
): number {
  if (wireLength <= rawBytes.length) return 0;
  const declared = declaredPayloadEnd(rawBytes, l3Offset, etherType);
  const saysNothing = declared <= l3Offset
    || (etherType === ETHERTYPE_IPV6 && declared === l3Offset + IPV6_HEADER_BYTES);
  const end = saysNothing ? wireLength : Math.min(wireLength, declared);
  return Math.max(0, end - rawBytes.length);
}
