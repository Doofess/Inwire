/**
 * Synchronous SHA-512 and SHA-384, and HMAC over either.
 *
 * Needed because TLS 1.3 picks its hash from the cipher suite:
 * `TLS_AES_128_GCM_SHA256` derives keys with HKDF-SHA-256, which sha256.ts
 * already gives us, but `TLS_AES_256_GCM_SHA384` - the suite most servers
 * choose when a client offers it - derives them with HKDF-SHA-384. Deriving
 * with the wrong hash produces keys that are wrong in a completely silent way:
 * the AEAD tag simply fails and the record looks like it was never decryptable
 * at all. TLS 1.2's PRF has the same split.
 *
 * SHA-384 is SHA-512 with different initial state, truncated to 48 bytes; the
 * two share every line below.
 *
 * JavaScript has no 64-bit integer arithmetic short of BigInt, which would be
 * an order of magnitude slower here, so each 64-bit word is a pair of 32-bit
 * halves. The one thing that needs care is the carry out of the low half:
 * a sum of up to five unsigned 32-bit values stays exact in a double, so it is
 * added as a double and the carry read off the top rather than reconstructed
 * from comparisons.
 *
 * See the note in sha256.ts on why hand-rolling is acceptable here.
 */

/** The first 64 bits of the fractional parts of the cube roots of the first 80 primes. */
const K = new Uint32Array([
  0x428a2f98, 0xd728ae22, 0x71374491, 0x23ef65cd, 0xb5c0fbcf, 0xec4d3b2f, 0xe9b5dba5, 0x8189dbbc,
  0x3956c25b, 0xf348b538, 0x59f111f1, 0xb605d019, 0x923f82a4, 0xaf194f9b, 0xab1c5ed5, 0xda6d8118,
  0xd807aa98, 0xa3030242, 0x12835b01, 0x45706fbe, 0x243185be, 0x4ee4b28c, 0x550c7dc3, 0xd5ffb4e2,
  0x72be5d74, 0xf27b896f, 0x80deb1fe, 0x3b1696b1, 0x9bdc06a7, 0x25c71235, 0xc19bf174, 0xcf692694,
  0xe49b69c1, 0x9ef14ad2, 0xefbe4786, 0x384f25e3, 0x0fc19dc6, 0x8b8cd5b5, 0x240ca1cc, 0x77ac9c65,
  0x2de92c6f, 0x592b0275, 0x4a7484aa, 0x6ea6e483, 0x5cb0a9dc, 0xbd41fbd4, 0x76f988da, 0x831153b5,
  0x983e5152, 0xee66dfab, 0xa831c66d, 0x2db43210, 0xb00327c8, 0x98fb213f, 0xbf597fc7, 0xbeef0ee4,
  0xc6e00bf3, 0x3da88fc2, 0xd5a79147, 0x930aa725, 0x06ca6351, 0xe003826f, 0x14292967, 0x0a0e6e70,
  0x27b70a85, 0x46d22ffc, 0x2e1b2138, 0x5c26c926, 0x4d2c6dfc, 0x5ac42aed, 0x53380d13, 0x9d95b3df,
  0x650a7354, 0x8baf63de, 0x766a0abb, 0x3c77b2a8, 0x81c2c92e, 0x47edaee6, 0x92722c85, 0x1482353b,
  0xa2bfe8a1, 0x4cf10364, 0xa81a664b, 0xbc423001, 0xc24b8b70, 0xd0f89791, 0xc76c51a3, 0x0654be30,
  0xd192e819, 0xd6ef5218, 0xd6990624, 0x5565a910, 0xf40e3585, 0x5771202a, 0x106aa070, 0x32bbd1b8,
  0x19a4c116, 0xb8d2d0c8, 0x1e376c08, 0x5141ab53, 0x2748774c, 0xdf8eeb99, 0x34b0bcb5, 0xe19b48a8,
  0x391c0cb3, 0xc5c95a63, 0x4ed8aa4a, 0xe3418acb, 0x5b9cca4f, 0x7763e373, 0x682e6ff3, 0xd6b2b8a3,
  0x748f82ee, 0x5defb2fc, 0x78a5636f, 0x43172f60, 0x84c87814, 0xa1f0ab72, 0x8cc70208, 0x1a6439ec,
  0x90befffa, 0x23631e28, 0xa4506ceb, 0xde82bde9, 0xbef9a3f7, 0xb2c67915, 0xc67178f2, 0xe372532b,
  0xca273ece, 0xea26619c, 0xd186b8c7, 0x21c0c207, 0xeada7dd6, 0xcde0eb1e, 0xf57d4f7f, 0xee6ed178,
  0x06f067aa, 0x72176fba, 0x0a637dc5, 0xa2c898a6, 0x113f9804, 0xbef90dae, 0x1b710b35, 0x131c471b,
  0x28db77f5, 0x23047d84, 0x32caab7b, 0x40c72493, 0x3c9ebe0a, 0x15c9bebc, 0x431d67c4, 0x9c100d4c,
  0x4cc5d4be, 0xcb3e42b6, 0x597f299c, 0xfc657e2a, 0x5fcb6fab, 0x3ad6faec, 0x6c44198c, 0x4a475817,
]);

const H512 = new Uint32Array([
  0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b, 0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
  0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f, 0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
]);

const H384 = new Uint32Array([
  0xcbbb9d5d, 0xc1059ed8, 0x629a292a, 0x367cd507, 0x9159015a, 0x3070dd17, 0x152fecd8, 0xf70e5939,
  0x67332667, 0xffc00b31, 0x8eb44a87, 0x68581511, 0xdb0c2e0d, 0x64f98fa7, 0x47b5481d, 0xbefa4fa4,
]);

const BLOCK_SIZE = 128;
const SHA512_DIGEST_LENGTH = 64;
export const SHA384_DIGEST_LENGTH = 48;

const w = new Uint32Array(160);

/**
 * The compression function, shared by both digest lengths.
 *
 * `initial` supplies the eight starting words; `digestLength` truncates the
 * result, which is the whole of the difference between SHA-384 and SHA-512
 * once the initial state has been chosen.
 */
function digest(message: Uint8Array, initial: Uint32Array, digestLength: number): Uint8Array {
  const h = new Uint32Array(initial);

  // Pad: a 0x80 byte, zeros, then the length in bits as a 128-bit big-endian
  // integer. 17 = that byte plus the 16-byte length field. The high 64 bits of
  // the length are always zero here - a message long enough to need them could
  // not be held in memory.
  const paddedLength = Math.ceil((message.length + 17) / BLOCK_SIZE) * BLOCK_SIZE;
  const padded = new Uint8Array(paddedLength);
  padded.set(message);
  padded[message.length] = 0x80;

  const view = new DataView(padded.buffer);
  const bitLength = message.length * 8;
  view.setUint32(paddedLength - 4, bitLength >>> 0, false);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32), false);

  for (let offset = 0; offset < paddedLength; offset += BLOCK_SIZE) {
    for (let i = 0; i < 32; i++) w[i] = view.getUint32(offset + i * 4, false);

    for (let i = 16; i < 80; i++) {
      const i2 = i * 2;
      const m15h = w[i2 - 30], m15l = w[i2 - 29];
      const m2h = w[i2 - 4], m2l = w[i2 - 3];

      // s0 = ROTR^1 ^ ROTR^8 ^ SHR^7
      const s0h = (((m15h >>> 1) | (m15l << 31)) ^ ((m15h >>> 8) | (m15l << 24)) ^ (m15h >>> 7)) >>> 0;
      const s0l = (((m15l >>> 1) | (m15h << 31)) ^ ((m15l >>> 8) | (m15h << 24)) ^ ((m15l >>> 7) | (m15h << 25))) >>> 0;
      // s1 = ROTR^19 ^ ROTR^61 ^ SHR^6. ROTR^61 on a 64-bit word is a rotate
      // left by 3, which in halves means the *other* half leads.
      const s1h = (((m2h >>> 19) | (m2l << 13)) ^ ((m2l >>> 29) | (m2h << 3)) ^ (m2h >>> 6)) >>> 0;
      const s1l = (((m2l >>> 19) | (m2h << 13)) ^ ((m2h >>> 29) | (m2l << 3)) ^ ((m2l >>> 6) | (m2h << 26))) >>> 0;

      const lo = (w[i2 - 31] >>> 0) + (s0l >>> 0) + (w[i2 - 13] >>> 0) + (s1l >>> 0);
      const hi = w[i2 - 32] + s0h + w[i2 - 14] + s1h + Math.floor(lo / 0x100000000);
      w[i2] = hi >>> 0;
      w[i2 + 1] = lo >>> 0;
    }

    let ah = h[0], al = h[1], bh = h[2], bl = h[3], ch = h[4], cl = h[5], dh = h[6], dl = h[7];
    let eh = h[8], el = h[9], fh = h[10], fl = h[11], gh = h[12], gl = h[13], hh = h[14], hl = h[15];

    for (let i = 0; i < 80; i++) {
      const i2 = i * 2;

      // Sigma1(e) = ROTR^14 ^ ROTR^18 ^ ROTR^41. The last is a rotate left by
      // 23, so again the halves cross over.
      const S1h = (((eh >>> 14) | (el << 18)) ^ ((eh >>> 18) | (el << 14)) ^ ((el >>> 9) | (eh << 23))) >>> 0;
      const S1l = (((el >>> 14) | (eh << 18)) ^ ((el >>> 18) | (eh << 14)) ^ ((eh >>> 9) | (el << 23))) >>> 0;
      const chh = ((eh & fh) ^ (~eh & gh)) >>> 0;
      const chl = ((el & fl) ^ (~el & gl)) >>> 0;

      const t1l = (hl >>> 0) + (S1l >>> 0) + (chl >>> 0) + (K[i2 + 1] >>> 0) + (w[i2 + 1] >>> 0);
      const t1h = (hh + S1h + chh + K[i2] + w[i2] + Math.floor(t1l / 0x100000000)) >>> 0;
      const t1lo = t1l >>> 0;

      // Sigma0(a) = ROTR^28 ^ ROTR^34 ^ ROTR^39, the last two being rotates
      // left by 30 and 25.
      const S0h = (((ah >>> 28) | (al << 4)) ^ ((al >>> 2) | (ah << 30)) ^ ((al >>> 7) | (ah << 25))) >>> 0;
      const S0l = (((al >>> 28) | (ah << 4)) ^ ((ah >>> 2) | (al << 30)) ^ ((ah >>> 7) | (al << 25))) >>> 0;
      const majh = ((ah & bh) ^ (ah & ch) ^ (bh & ch)) >>> 0;
      const majl = ((al & bl) ^ (al & cl) ^ (bl & cl)) >>> 0;

      const t2l = (S0l >>> 0) + (majl >>> 0);
      const t2h = (S0h + majh + Math.floor(t2l / 0x100000000)) >>> 0;
      const t2lo = t2l >>> 0;

      hh = gh; hl = gl; gh = fh; gl = fl; fh = eh; fl = el;

      const el2 = (dl >>> 0) + (t1lo >>> 0);
      eh = (dh + t1h + Math.floor(el2 / 0x100000000)) >>> 0;
      el = el2 >>> 0;

      dh = ch; dl = cl; ch = bh; cl = bl; bh = ah; bl = al;

      const al2 = (t1lo >>> 0) + (t2lo >>> 0);
      ah = (t1h + t2h + Math.floor(al2 / 0x100000000)) >>> 0;
      al = al2 >>> 0;
    }

    const add = (index: number, vh: number, vl: number): void => {
      const lo = (h[index + 1] >>> 0) + (vl >>> 0);
      h[index] = (h[index] + vh + Math.floor(lo / 0x100000000)) >>> 0;
      h[index + 1] = lo >>> 0;
    };
    add(0, ah, al); add(2, bh, bl); add(4, ch, cl); add(6, dh, dl);
    add(8, eh, el); add(10, fh, fl); add(12, gh, gl); add(14, hh, hl);
  }

  const out = new Uint8Array(digestLength);
  const outView = new DataView(out.buffer);
  for (let i = 0; i * 4 < digestLength; i++) outView.setUint32(i * 4, h[i], false);
  return out;
}

export function sha512(message: Uint8Array): Uint8Array {
  return digest(message, H512, SHA512_DIGEST_LENGTH);
}

export function sha384(message: Uint8Array): Uint8Array {
  return digest(message, H384, SHA384_DIGEST_LENGTH);
}

/**
 * HMAC (RFC 2104) over either digest.
 *
 * The block size is 128 bytes for both, not 64 - it is the *compression
 * function's* block, not the digest length, and using 64 here yields an HMAC
 * that is self-consistent and disagrees with every other implementation.
 */
function hmac(
  hash: (m: Uint8Array) => Uint8Array,
  digestLength: number,
  key: Uint8Array,
  message: Uint8Array
): Uint8Array {
  const blockKey = new Uint8Array(BLOCK_SIZE);
  blockKey.set(key.length > BLOCK_SIZE ? hash(key) : key);

  const inner = new Uint8Array(BLOCK_SIZE + message.length);
  const outer = new Uint8Array(BLOCK_SIZE + digestLength);
  for (let i = 0; i < BLOCK_SIZE; i++) {
    inner[i] = blockKey[i] ^ 0x36;
    outer[i] = blockKey[i] ^ 0x5c;
  }
  inner.set(message, BLOCK_SIZE);
  outer.set(hash(inner), BLOCK_SIZE);
  return hash(outer);
}

export function hmacSha384(key: Uint8Array, message: Uint8Array): Uint8Array {
  return hmac(sha384, SHA384_DIGEST_LENGTH, key, message);
}
