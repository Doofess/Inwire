/**
 * Synchronous AES (encryption direction only) and AES-GCM decryption, for
 * 128-, 192- and 256-bit keys.
 *
 * Two things QUIC needs that WebCrypto cannot give a synchronous dissector:
 * a raw single-block AES encryption - which WebCrypto deliberately does not
 * expose, since ECB is unsafe as a general mode but is exactly what QUIC's
 * header protection is defined in terms of - and GCM decryption without a
 * Promise. Only the encryption direction is implemented, because GCM builds
 * both encryption and decryption out of the forward cipher in counter mode.
 *
 * The 256-bit path exists for TLS: `TLS_AES_256_GCM_SHA384` is the second
 * most common TLS 1.3 suite, and every AES-256 suite in TLS 1.2 needs it too.
 * The key schedule is the only thing that differs between the three sizes -
 * the round function is identical - so the round count is carried in the
 * length of the expanded key rather than in a parameter every caller would
 * have to thread and could get wrong.
 *
 * See the note in sha256.ts on why hand-rolling is acceptable here: these
 * keys come either from a connection ID sent in the clear or from a key log
 * the user chose to supply, so nothing in this file protects a secret of its
 * own.
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

/** Multiply by x in GF(2^8) with the AES reduction polynomial. */
function xtime(byte: number): number {
  return ((byte << 1) ^ (byte & 0x80 ? 0x1b : 0)) & 0xff;
}

/**
 * Expands a 16-, 24- or 32-byte key into the round keys of its variant.
 *
 * The returned array's length says which variant it is (16 x (rounds + 1)),
 * which is how `encryptBlock` knows how many rounds to run without being told
 * a second time - a round count that could disagree with the key it came from
 * is a bug waiting to happen.
 */
export function expandKey(key: Uint8Array): Uint8Array {
  if (key.length !== 16 && key.length !== 24 && key.length !== 32) {
    throw new Error(`AES needs a 16-, 24- or 32-byte key, got ${key.length}`);
  }

  const nk = key.length / 4;
  // AES's own table: 10 rounds for a 128-bit key, 12 for 192, 14 for 256.
  const rounds = nk + 6;
  const totalWords = 4 * (rounds + 1);

  const roundKeys = new Uint8Array(16 * (rounds + 1));
  roundKeys.set(key);

  for (let word = nk; word < totalWords; word++) {
    let t0 = roundKeys[(word - 1) * 4];
    let t1 = roundKeys[(word - 1) * 4 + 1];
    let t2 = roundKeys[(word - 1) * 4 + 2];
    let t3 = roundKeys[(word - 1) * 4 + 3];

    if (word % nk === 0) {
      // RotWord, SubWord, then XOR the round constant into the first byte.
      const rotated = t0;
      t0 = SBOX[t1] ^ ROUND_CONSTANTS[word / nk - 1];
      t1 = SBOX[t2];
      t2 = SBOX[t3];
      t3 = SBOX[rotated];
    } else if (nk > 6 && word % nk === 4) {
      // AES-256 only: an extra SubWord a third of the way through each
      // expansion step. Leaving it out yields a schedule that still agrees
      // with the real one for the first two round keys and then quietly
      // diverges - the most common way a from-scratch AES-256 goes wrong,
      // and why the assertion script checks the 256-bit vector too.
      t0 = SBOX[t0]; t1 = SBOX[t1]; t2 = SBOX[t2]; t3 = SBOX[t3];
    }

    roundKeys[word * 4] = roundKeys[(word - nk) * 4] ^ t0;
    roundKeys[word * 4 + 1] = roundKeys[(word - nk) * 4 + 1] ^ t1;
    roundKeys[word * 4 + 2] = roundKeys[(word - nk) * 4 + 2] ^ t2;
    roundKeys[word * 4 + 3] = roundKeys[(word - nk) * 4 + 3] ^ t3;
  }

  return roundKeys;
}

/** Expands a 16-byte key. Kept under its own name because QUIC only ever has one. */
export function expandKey128(key: Uint8Array): Uint8Array {
  if (key.length !== 16) throw new Error(`AES-128 needs a 16-byte key, got ${key.length}`);
  return expandKey(key);
}

/**
 * Encrypts one 16-byte block in place-free fashion, returning a new block.
 * This is the raw block cipher - QUIC's header protection calls for exactly
 * this, applied to a sample of the ciphertext.
 */
export function encryptBlock(roundKeys: Uint8Array, block: Uint8Array): Uint8Array {
  const lastRound = roundKeys.length / 16 - 1;
  const state = new Uint8Array(block.subarray(0, AES_BLOCK_SIZE));

  for (let i = 0; i < 16; i++) state[i] ^= roundKeys[i];

  for (let round = 1; round <= lastRound; round++) {
    for (let i = 0; i < 16; i++) state[i] = SBOX[state[i]];

    // ShiftRows: row r rotates left by r. State is column-major, so row r is
    // bytes r, r+4, r+8, r+12.
    let tmp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = tmp;

    // MixColumns is skipped in the final round.
    if (round !== lastRound) {
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

/** `encryptBlock` under its original name, for the QUIC code that predates the other sizes. */
export const encryptBlock128 = encryptBlock;

/**
 * GHASH over a sequence of 16-byte blocks (the tail is zero-padded).
 *
 * The multiply is shift-and-xor over the bit-reflected polynomial GCM is
 * defined on, held in four 32-bit words rather than sixteen bytes. When this
 * only ran a handful of times per QUIC handshake the byte form was clearer and
 * fast enough; decrypting TLS application data runs it over every byte of
 * every record, where it was the whole cost of GCM - 11 MB/s against the block
 * cipher's 60. Four words instead of sixteen bytes is the same algorithm and
 * roughly five times the speed, which is why there is no precomputed table
 * here: the tables cost memory per key and this is no longer the bottleneck.
 */
function ghash(h: Uint8Array, data: Uint8Array): Uint8Array {
  const view = new DataView(h.buffer, h.byteOffset, 16);
  const h0 = view.getUint32(0, false), h1 = view.getUint32(4, false);
  const h2 = view.getUint32(8, false), h3 = view.getUint32(12, false);

  let y0 = 0, y1 = 0, y2 = 0, y3 = 0;
  const block = new Uint8Array(16);
  const blockView = new DataView(block.buffer);

  for (let offset = 0; offset < data.length; offset += 16) {
    block.fill(0);
    block.set(data.subarray(offset, Math.min(offset + 16, data.length)));

    // x = y XOR block, the running value this iteration multiplies by H.
    const x0 = (y0 ^ blockView.getUint32(0, false)) >>> 0;
    const x1 = (y1 ^ blockView.getUint32(4, false)) >>> 0;
    const x2 = (y2 ^ blockView.getUint32(8, false)) >>> 0;
    const x3 = (y3 ^ blockView.getUint32(12, false)) >>> 0;

    let z0 = 0, z1 = 0, z2 = 0, z3 = 0;
    let v0 = h0, v1 = h1, v2 = h2, v3 = h3;

    for (let word = 0; word < 4; word++) {
      const x = word === 0 ? x0 : word === 1 ? x1 : word === 2 ? x2 : x3;
      for (let bit = 31; bit >= 0; bit--) {
        if ((x >>> bit) & 1) { z0 ^= v0; z1 ^= v1; z2 ^= v2; z3 ^= v3; }

        // v >>= 1 across the whole 128-bit value, reducing by the polynomial's
        // 0xe1 << 120 whenever a one falls off the bottom.
        const carry = v3 & 1;
        v3 = ((v3 >>> 1) | (v2 << 31)) >>> 0;
        v2 = ((v2 >>> 1) | (v1 << 31)) >>> 0;
        v1 = ((v1 >>> 1) | (v0 << 31)) >>> 0;
        v0 = v0 >>> 1;
        if (carry) v0 = (v0 ^ 0xe1000000) >>> 0;
      }
    }

    y0 = z0 >>> 0; y1 = z1 >>> 0; y2 = z2 >>> 0; y3 = z3 >>> 0;
  }

  const out = new Uint8Array(16);
  const outView = new DataView(out.buffer);
  outView.setUint32(0, y0, false);
  outView.setUint32(4, y1, false);
  outView.setUint32(8, y2, false);
  outView.setUint32(12, y3, false);
  return out;
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
    const keystream = encryptBlock(roundKeys, counter);
    const blockLength = Math.min(AES_BLOCK_SIZE, data.length - offset);
    for (let i = 0; i < blockLength; i++) output[offset + i] = data[offset + i] ^ keystream[i];
  }

  return output;
}

/**
 * AES-GCM decryption with authentication, for any of the three key sizes.
 *
 * `nonce` must be 12 bytes, which is what QUIC and TLS both always use.
 * Returns null when the authentication tag does not verify - which is the
 * point: it means the keys were wrong or the bytes are not what we assumed,
 * and the "plaintext" would be noise. Callers rely on that to avoid rendering
 * garbage, and an honest failure is the only reason it is safe to *try* a key
 * log entry against a stream at all.
 */
/**
 * Derived key state, by key.
 *
 * `expandKey` and the GHASH subkey H are pure functions of the key, and one key
 * serves every packet on a connection and every record on a TLS session - so
 * `aesGcmDecrypt` was re-expanding the schedule and re-deriving H (a whole AES
 * block encryption) every time it opened anything.
 *
 * **This is a small win, and it is not the fix for QUIC's cost.** Measured on
 * the `inwire` fixture: 898 derivations for 12,858 frames, 85% of them served
 * from here - perhaps 1% of dissection, which is below the noise on a
 * throughput run. It was written expecting more, because QUIC frames are 2.7%
 * of frames carrying 47% of dissection time; they are not slow for this reason.
 * They are slow because the block cipher itself is JavaScript, ~81 block
 * encryptions for a 1292-byte packet, which is the standing cost of ADR 0003's
 * decision to keep dissection synchronous rather than adopt async WebCrypto.
 *
 * Kept because it is correct, bounded and removes real work - and because a
 * TLS-heavy capture reuses one key across far more records than this fixture
 * does. Not kept as an answer to the tail.
 *
 * Bounded and evicting oldest-first: QUIC derives Initial keys from the
 * connection id, so a capture of many short connections produces many
 * single-use keys rather than the small stable set the cache is shaped for.
 *
 * **The returned arrays are shared and must not be mutated.** Nothing here
 * does: `encryptBlock` copies its block into a fresh state array and only ever
 * reads the round keys, and `ghash` reads H through a DataView.
 *
 * This is memory, not disk. ADR 0008's rule - key material never persists - is
 * untouched; a schedule derived from a key already in memory is not a new
 * exposure, and it is dropped with the module.
 */
interface DerivedKey { roundKeys: Uint8Array; h: Uint8Array }

const derivedKeys = new Map<string, DerivedKey>();
const DERIVED_KEY_CACHE_MAX = 64;

function keyId(key: Uint8Array): string {
  let id = '';
  for (let i = 0; i < key.length; i++) id += String.fromCharCode(key[i]);
  return id;
}

function derive(key: Uint8Array): DerivedKey {
  const id = keyId(key);
  const hit = derivedKeys.get(id);
  if (hit !== undefined) return hit;

  const roundKeys = expandKey(key);
  const state: DerivedKey = { roundKeys, h: encryptBlock(roundKeys, new Uint8Array(16)) };
  // Insertion order is what makes the first key the oldest.
  while (derivedKeys.size >= DERIVED_KEY_CACHE_MAX) {
    const oldest = derivedKeys.keys().next();
    if (oldest.done) break;
    derivedKeys.delete(oldest.value);
  }
  derivedKeys.set(id, state);
  return state;
}

/**
 * `expandKey`, memoised. For a caller that runs the same key over and over -
 * QUIC header protection is applied to every packet on a connection - and that
 * will not mutate what it gets back.
 */
export function expandKeyCached(key: Uint8Array): Uint8Array {
  return derive(key).roundKeys;
}

/** Forgets every derived schedule. For a capture ending, and for tests. */
export function clearDerivedKeys(): void {
  derivedKeys.clear();
}

export function aesGcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Uint8Array | null {
  if (nonce.length !== 12) return null;
  if (tag.length !== 16) return null;

  const { roundKeys, h } = derive(key);

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
  const tagMask = encryptBlock(roundKeys, j0);

  let mismatch = 0;
  for (let i = 0; i < 16; i++) mismatch |= (s[i] ^ tagMask[i]) ^ tag[i];
  if (mismatch !== 0) return null;

  return ctrXor(roundKeys, j0, ciphertext);
}

/** `aesGcmDecrypt` under its original name; QUIC Initials are always AES-128. */
export const aes128GcmDecrypt = aesGcmDecrypt;
