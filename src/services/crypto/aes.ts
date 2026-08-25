/**
 * Synchronous AES-128 (encryption only) and AES-128-GCM decryption.
 *
 * Two things QUIC needs that WebCrypto cannot give a synchronous dissector:
 * a raw single-block AES encryption - which WebCrypto deliberately does not
 * expose, since ECB is unsafe as a general mode but is exactly what QUIC's
 * header protection is defined in terms of - and GCM decryption without a
 * Promise. Only the encryption direction is implemented, because GCM builds
 * both encryption and decryption out of the forward cipher in counter mode.
 *
 * See the note in sha256.ts on why hand-rolling is acceptable here: these
 * keys are derived from a connection ID sent in the clear, so nothing in this
 * file protects a secret.
 */

const SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const ROUND_CONSTANTS = new Uint8Array([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]);

export const AES_BLOCK_SIZE = 16;
const AES128_ROUNDS = 10;

/** Multiply by x in GF(2^8) with the AES reduction polynomial. */
function xtime(byte: number): number {
  return ((byte << 1) ^ (byte & 0x80 ? 0x1b : 0)) & 0xff;
}

/** Expands a 16-byte key into the 11 round keys AES-128 uses. */
export function expandKey128(key: Uint8Array): Uint8Array {
  if (key.length !== 16) throw new Error(`AES-128 needs a 16-byte key, got ${key.length}`);

  const roundKeys = new Uint8Array(16 * (AES128_ROUNDS + 1));
  roundKeys.set(key);

  for (let word = 4; word < 4 * (AES128_ROUNDS + 1); word++) {
    let t0 = roundKeys[(word - 1) * 4];
    let t1 = roundKeys[(word - 1) * 4 + 1];
    let t2 = roundKeys[(word - 1) * 4 + 2];
    let t3 = roundKeys[(word - 1) * 4 + 3];

    if (word % 4 === 0) {
      // RotWord, SubWord, then XOR the round constant into the first byte.
      const rotated = t0;
      t0 = SBOX[t1] ^ ROUND_CONSTANTS[word / 4 - 1];
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[rotated];
    }

    roundKeys[word * 4] = roundKeys[(word - 4) * 4] ^ t0;
    roundKeys[word * 4 + 1] = roundKeys[(word - 4) * 4 + 1] ^ t1;
    roundKeys[word * 4 + 2] = roundKeys[(word - 4) * 4 + 2] ^ t2;
    roundKeys[word * 4 + 3] = roundKeys[(word - 4) * 4 + 3] ^ t3;
  }

  return roundKeys;
}

/**
 * Encrypts one 16-byte block in place-free fashion, returning a new block.
 * This is the raw block cipher - QUIC's header protection calls for exactly
 * this, applied to a sample of the ciphertext.
 */
export function encryptBlock128(roundKeys: Uint8Array, block: Uint8Array): Uint8Array {
  const state = new Uint8Array(block.subarray(0, AES_BLOCK_SIZE));

  for (let i = 0; i < 16; i++) state[i] ^= roundKeys[i];

  for (let round = 1; round <= AES128_ROUNDS; round++) {
    for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];

    // ShiftRows: row r rotates left by r. State is column-major, so row r is
    // bytes r, r+4, r+8, r+12.
    let tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;

    // MixColumns is skipped in the final round.
    if (round !== AES128_ROUNDS) {
      for (let column = 0; column < 4; column++) {
        const i = column * 4;
        const a0 = state[i], a1 = state[i + 1], a2 = state[i + 2], a3 = state[i + 3];
        const all = a0 ^ a1 ^ a2 ^ a3;
        state[i] = a0 ^ all ^ xtime(a0 ^ a1);
        state[i + 1] = a1 ^ all ^ xtime(a1 ^ a2);
        state[i + 2] = a2 ^ all ^ xtime(a2 ^ a3);
        state[i + 3] = a3 ^ all ^ xtime(a3 ^ a0);
      }
    }

    for (let i = 0; i < 16; i++) state[i] ^= roundKeys[round * 16 + i];
  }

  return state;
}

/**
 * One step of GHASH: multiplies X by H in GF(2^128) using the bit-reflected
 * polynomial GCM is defined over. The shift-and-xor form is used rather than
 * a precomputed table because this runs a few times per QUIC handshake, not
 * per byte of a bulk stream.
 */
function galoisMultiply(x: Uint8Array, h: Uint8Array): Uint8Array {
  const z = new Uint8Array(16);
  const v = new Uint8Array(h);

  for (let bit = 0; bit < 128; bit++) {
    if ((x[bit >> 3] >> (7 - (bit & 7))) & 1) {
      for (let i = 0; i < 16; i++) z[i] ^= v[i];
    }

    // v >>= 1 across the whole 128-bit value, reducing by 0xe1 << 120 when a
    // one falls off the bottom.
    const lsbSet = v[15] & 1;
    for (let i = 15; i > 0; i--) v[i] = ((v[i] >>> 1) | ((v[i - 1] & 1) << 7)) & 0xff;
    v[0] >>>= 1;
    if (lsbSet) v[0] ^= 0xe1;
  }

  return z;
}

/** GHASH over a sequence of already-padded 16-byte blocks. */
function ghash(h: Uint8Array, data: Uint8Array): Uint8Array {
  let y = new Uint8Array(16);
  for (let offset = 0; offset < data.length; offset += 16) {
    const block = new Uint8Array(16);
    block.set(data.subarray(offset, Math.min(offset + 16, data.length)));
    for (let i = 0; i < 16; i++) block[i] ^= y[i];
    y = galoisMultiply(block, h);
  }
  return y;
}

/** Increments the low 32 bits of a counter block, per GCM's inc32. */
function incrementCounter(counter: Uint8Array): void {
  for (let i = 15; i >= 12; i--) {
    counter[i] = (counter[i] + 1) & 0xff;
    if (counter[i] !== 0) break;
  }
}

function ctrXor(roundKeys: Uint8Array, initialCounter: Uint8Array, data: Uint8Array): Uint8Array {
  const output = new Uint8Array(data.length);
  const counter = new Uint8Array(initialCounter);

  for (let offset = 0; offset < data.length; offset += AES_BLOCK_SIZE) {
    incrementCounter(counter);
    const keystream = encryptBlock128(roundKeys, counter);
    const blockLength = Math.min(AES_BLOCK_SIZE, data.length - offset);
    for (let i = 0; i < blockLength; i++) output[offset + i] = data[offset + i] ^ keystream[i];
  }

  return output;
}

/**
 * AES-128-GCM decryption with authentication.
 *
 * `nonce` must be 12 bytes, which is what QUIC always uses. Returns null when
 * the authentication tag does not verify - which is the point: it means the
 * keys were wrong or the bytes are not what we assumed, and the "plaintext"
 * would be noise. Callers rely on that to avoid rendering garbage.
 */
export function aes128GcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Uint8Array | null {
  if (nonce.length !== 12) return null;

  const roundKeys = expandKey128(key);
  const h = encryptBlock128(roundKeys, new Uint8Array(16));

  // With a 96-bit nonce, J0 is simply the nonce followed by the integer 1.
  const j0 = new Uint8Array(16);
  j0.set(nonce);
  j0[15] = 1;

  // GHASH input is AAD and ciphertext, each zero-padded to a block boundary,
  // followed by their bit lengths as two 64-bit big-endian integers.
  const aadPadded = Math.ceil(aad.length / 16) * 16;
  const ciphertextPadded = Math.ceil(ciphertext.length / 16) * 16;
  const hashInput = new Uint8Array(aadPadded + ciphertextPadded + 16);
  hashInput.set(aad);
  hashInput.set(ciphertext, aadPadded);
  const lengthView = new DataView(hashInput.buffer, aadPadded + ciphertextPadded, 16);
  lengthView.setUint32(4, aad.length * 8, false);
  lengthView.setUint32(12, ciphertext.length * 8, false);

  const s = ghash(h, hashInput);
  const tagMask = encryptBlock128(roundKeys, j0);

  let mismatch = 0;
  for (let i = 0; i < 16; i++) mismatch |= (s[i] ^ tagMask[i]) ^ tag[i];
  if (mismatch !== 0) return null;

  return ctrXor(roundKeys, j0, ciphertext);
}
