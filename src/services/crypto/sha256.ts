/**
 * Synchronous SHA-256 and HMAC-SHA256.
 *
 * The browser already ships both in WebCrypto - but only behind a Promise,
 * and the packet dissection pipeline this feeds is synchronous from
 * decodeRawEthernetPacket down. Making dissection async to reach WebCrypto
 * would ripple through every caller including the live-capture path, so the
 * two primitives QUIC key derivation needs are implemented directly instead.
 *
 * Used only to derive QUIC Initial keys, which are public knowledge by
 * construction (RFC 9001 derives them from the connection ID, which is sent
 * in the clear). Nothing here guards a secret, so the usual warning about
 * hand-rolled crypto in a security boundary does not apply - but equally,
 * do not reach for these for anything that does.
 */

const ROUND_CONSTANTS = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const BLOCK_SIZE = 64;
export const SHA256_DIGEST_LENGTH = 32;

function rotr(value: number, bits: number): number {
  return ((value >>> bits) | (value << (32 - bits))) >>> 0;
}

export function sha256(message: Uint8Array): Uint8Array {
  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);

  // Pad to a multiple of 64 bytes: a 0x80 byte, then zeros, then the message
  // length in bits as a 64-bit big-endian integer.
  // 9 = the mandatory 0x80 byte plus the 8-byte length field, so this is the
  // smallest multiple of the block size that fits the message and both.
  const bitLength = message.length * 8;
  const paddedLength = Math.ceil((message.length + 9) / BLOCK_SIZE) * BLOCK_SIZE;
  const padded = new Uint8Array(paddedLength);
  padded.set(message);
  padded[message.length] = 0x80;

  const w = new Uint32Array(64);
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32), false);
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);

  for (let offset = 0; offset < paddedLength; offset += BLOCK_SIZE) {
    for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }

    let [a, b, c, d, e, f, g, hh] = h;

    for (let i = 0; i < 64; i++) {
      const s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (hh + s1 + ch + ROUND_CONSTANTS[i] + w[i]) >>> 0;
      const s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (s0 + maj) >>> 0;

      hh = g; g = f; f = e;
      e = (d + temp1) >>> 0;
      d = c; c = b; b = a;
      a = (temp1 + temp2) >>> 0;
    }

    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  const digest = new Uint8Array(SHA256_DIGEST_LENGTH);
  const digestView = new DataView(digest.buffer);
  for (let i = 0; i < 8; i++) digestView.setUint32(i * 4, h[i], false);
  return digest;
}

/** HMAC-SHA256 (RFC 2104). */
export function hmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  // Keys longer than the block size are hashed down first; shorter ones are
  // zero-padded up to it.
  const blockKey = new Uint8Array(BLOCK_SIZE);
  blockKey.set(key.length > BLOCK_SIZE ? sha256(key) : key);

  const innerPad = new Uint8Array(BLOCK_SIZE);
  const outerPad = new Uint8Array(BLOCK_SIZE);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    innerPad[i] = blockKey[i] ^ 0x36;
    outerPad[i] = blockKey[i] ^ 0x5c;
  }

  const inner = new Uint8Array(BLOCK_SIZE + message.length);
  inner.set(innerPad);
  inner.set(message, BLOCK_SIZE);
  const innerHash = sha256(inner);

  const outer = new Uint8Array(BLOCK_SIZE + SHA256_DIGEST_LENGTH);
  outer.set(outerPad);
  outer.set(innerHash, BLOCK_SIZE);
  return sha256(outer);
}
