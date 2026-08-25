/**
 * HKDF (RFC 5869) over SHA-256, plus the TLS 1.3 HKDF-Expand-Label wrapper
 * (RFC 8446 §7.1) that QUIC key derivation is written in terms of.
 */
import { hmacSha256, SHA256_DIGEST_LENGTH } from './sha256';

export function hkdfExtract(salt: Uint8Array, keyMaterial: Uint8Array): Uint8Array {
  // Extract is just HMAC with the salt as the key - it condenses possibly
  // non-uniform input keying material into a fixed-length pseudorandom key.
  return hmacSha256(salt, keyMaterial);
}

export function hkdfExpand(pseudoRandomKey: Uint8Array, info: Uint8Array, length: number): Uint8Array {
  const output = new Uint8Array(length);
  let previousBlock = new Uint8Array(0);
  let generated = 0;

  for (let counter = 1; generated < length; counter++) {
    const input = new Uint8Array(previousBlock.length + info.length + 1);
    input.set(previousBlock);
    input.set(info, previousBlock.length);
    input[input.length - 1] = counter;

    previousBlock = hmacSha256(pseudoRandomKey, input);
    const take = Math.min(SHA256_DIGEST_LENGTH, length - generated);
    output.set(previousBlock.subarray(0, take), generated);
    generated += take;
  }

  return output;
}

/**
 * TLS 1.3's structured Expand: the info parameter is a serialized HkdfLabel
 *
 *   uint16 length
 *   opaque label<7..255>    prefixed with "tls13 "
 *   opaque context<0..255>
 *
 * QUIC reuses this verbatim, which is why its labels ("client in", "quic key")
 * are always written without the prefix that actually goes on the wire.
 */
export function hkdfExpandLabel(
  secret: Uint8Array,
  label: string,
  context: Uint8Array,
  length: number
): Uint8Array {
  const fullLabel = `tls13 ${label}`;
  const labelBytes = new TextEncoder().encode(fullLabel);

  const info = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
  info[0] = (length >> 8) & 0xff;
  info[1] = length & 0xff;
  info[2] = labelBytes.length;
  info.set(labelBytes, 3);
  info[3 + labelBytes.length] = context.length;
  info.set(context, 4 + labelBytes.length);

  return hkdfExpand(secret, info, length);
}
