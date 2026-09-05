/**
 * HKDF (RFC 5869), plus the TLS 1.3 HKDF-Expand-Label wrapper (RFC 8446 §7.1)
 * that QUIC key derivation is written in terms of.
 *
 * Parameterised by hash because TLS 1.3 chooses one per cipher suite: the
 * SHA-256 suites derive with HKDF-SHA-256 and `TLS_AES_256_GCM_SHA384` with
 * HKDF-SHA-384. QUIC's Initial keys are always SHA-256, which is why the
 * unsuffixed functions default to it and the QUIC code never had to say so.
 */
import { hmacSha256, SHA256_DIGEST_LENGTH } from './sha256';
import { hmacSha384, SHA384_DIGEST_LENGTH } from './sha512';

/** One encoder, not one per call - see scripts/perf/hot-path-allocations.ts. */
const utf8Encoder = new TextEncoder();

/** A hash, as HKDF needs to see it: its output length and its HMAC. */
export interface HashSpec {
  name: string;
  digestLength: number;
  hmac: (key: Uint8Array, message: Uint8Array) => Uint8Array;
}

export const SHA256: HashSpec = { name: 'SHA-256', digestLength: SHA256_DIGEST_LENGTH, hmac: hmacSha256 };
export const SHA384: HashSpec = { name: 'SHA-384', digestLength: SHA384_DIGEST_LENGTH, hmac: hmacSha384 };

export function hkdfExtract(salt: Uint8Array, keyMaterial: Uint8Array, hash: HashSpec = SHA256): Uint8Array {
  // Extract is just HMAC with the salt as the key - it condenses possibly
  // non-uniform input keying material into a fixed-length pseudorandom key.
  return hash.hmac(salt, keyMaterial);
}

export function hkdfExpand(
  pseudoRandomKey: Uint8Array,
  info: Uint8Array,
  length: number,
  hash: HashSpec = SHA256
): Uint8Array {
  const output = new Uint8Array(length);
  let previousBlock = new Uint8Array(0);
  let generated = 0;

  for (let counter = 1; generated < length; counter++) {
    const input = new Uint8Array(previousBlock.length + info.length + 1);
    input.set(previousBlock);
    input.set(info, previousBlock.length);
    input[input.length - 1] = counter;

    previousBlock = hash.hmac(pseudoRandomKey, input);
    const take = Math.min(hash.digestLength, length - generated);
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
  length: number,
  hash: HashSpec = SHA256
): Uint8Array {
  const fullLabel = `tls13 ${label}`;
  const labelBytes = utf8Encoder.encode(fullLabel);

  const info = new Uint8Array(2 + 1 + labelBytes.length + 1 + context.length);
  info[0] = (length >> 8) & 0xff;
  info[1] = length & 0xff;
  info[2] = labelBytes.length;
  info.set(labelBytes, 3);
  info[3 + labelBytes.length] = context.length;
  info.set(context, 4 + labelBytes.length);

  return hkdfExpand(secret, info, length, hash);
}

/**
 * TLS 1.2's PRF (RFC 5246 §5), which is not HKDF at all.
 *
 * P_hash is an HMAC chain seeded on the label and seed, run until enough
 * output has been produced. TLS 1.2 uses the cipher suite's hash - SHA-256 for
 * everything except the SHA-384 suites - and TLS 1.0/1.1's split MD5/SHA-1
 * construction is deliberately not implemented: nothing negotiates those any
 * more, and a wrong answer would be worse than none.
 */
export function tls12Prf(
  secret: Uint8Array,
  label: string,
  seed: Uint8Array,
  length: number,
  hash: HashSpec = SHA256
): Uint8Array {
  const labelBytes = utf8Encoder.encode(label);
  const labelAndSeed = new Uint8Array(labelBytes.length + seed.length);
  labelAndSeed.set(labelBytes);
  labelAndSeed.set(seed, labelBytes.length);

  const output = new Uint8Array(length);
  // A(0) is the seed itself; A(i) = HMAC(secret, A(i-1)).
  let a = labelAndSeed;
  let generated = 0;

  while (generated < length) {
    a = hash.hmac(secret, a);
    const input = new Uint8Array(a.length + labelAndSeed.length);
    input.set(a);
    input.set(labelAndSeed, a.length);

    const block = hash.hmac(secret, input);
    const take = Math.min(block.length, length - generated);
    output.set(block.subarray(0, take), generated);
    generated += take;
  }

  return output;
}
