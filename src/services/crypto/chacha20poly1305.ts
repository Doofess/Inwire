/**
 * ChaCha20-Poly1305 AEAD (RFC 8439), decryption direction.
 *
 * The third cipher suite TLS 1.3 defines and the one a phone or a low-power
 * server usually picks, because it is faster than AES anywhere without AES
 * hardware. QUIC names it too. Without it a key log would decrypt some
 * connections and silently fail on others, which is the worst of both.
 *
 * ChaCha20 is a stream cipher, so decryption is the same keystream XOR as
 * encryption - what has to be written out here is only the keystream and the
 * one-time authenticator.
 *
 * On Poly1305 and JavaScript: the accumulator is 130 bits, and the usual
 * portable layout of five 26-bit limbs needs products up to 2^54, which a
 * double cannot hold exactly - the resulting MAC is wrong on perhaps one
 * message in a thousand, which is far worse than being wrong on all of them.
 * Ten limbs of 13 bits keep every intermediate under 2^32 and divide 130
 * exactly, so the reduction lands on a limb boundary instead of straddling
 * one.
 *
 * See the note in sha256.ts on why hand-rolling is acceptable here.
 */

const POLY1305_TAG_LENGTH = 16;
const LIMB_BITS = 13;
const LIMB_MASK = 0x1fff;
const LIMBS = 10;

// --- ChaCha20 ---------------------------------------------------------------

/** "expand 32-byte k", the constant first four words of the state. */
const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function rotl32(value: number, bits: number): number {
  return ((value << bits) | (value >>> (32 - bits))) >>> 0;
}

/**
 * One 64-byte ChaCha20 block: twenty rounds over a 4x4 word state, added back
 * to the state it started from (the addition is what makes it one-way).
 */
function chachaBlock(key: Uint32Array, counter: number, nonce: Uint32Array, out: Uint8Array): void {
  const x = new Uint32Array(16);
  x[0] = SIGMA[0]; x[1] = SIGMA[1]; x[2] = SIGMA[2]; x[3] = SIGMA[3];
  for (let i = 0; i < 8; i++) x[4 + i] = key[i];
  x[12] = counter >>> 0;
  x[13] = nonce[0]; x[14] = nonce[1]; x[15] = nonce[2];

  const s = new Uint32Array(x);

  for (let round = 0; round < 10; round++) {
    // Column round, then diagonal round - the pairing is the whole design.
    quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13);
    quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15);
    quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12);
    quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14);
  }

  const view = new DataView(out.buffer, out.byteOffset, out.byteLength);
  for (let i = 0; i < 16; i++) view.setUint32(i * 4, (x[i] + s[i]) >>> 0, true);
}

function quarter(x: Uint32Array, a: number, b: number, c: number, d: number): void {
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
}

/**
 * ChaCha20 keystream XOR (RFC 8439 §2.4). Encryption and decryption are the
 * same operation; `counter` is the block counter the first block uses - 1 for
 * the payload, since block 0 produced the Poly1305 key.
 */
export function chacha20(key: Uint8Array, nonce: Uint8Array, counter: number, data: Uint8Array): Uint8Array {
  if (key.length !== 32 || nonce.length !== 12) {
    throw new Error(`ChaCha20 needs a 32-byte key and a 12-byte nonce, got ${key.length} and ${nonce.length}`);
  }

  const keyWords = new Uint32Array(8);
  const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) keyWords[i] = keyView.getUint32(i * 4, true);

  const nonceWords = new Uint32Array(3);
  const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let i = 0; i < 3; i++) nonceWords[i] = nonceView.getUint32(i * 4, true);

  const output = new Uint8Array(data.length);
  const block = new Uint8Array(64);

  for (let offset = 0; offset < data.length; offset += 64) {
    chachaBlock(keyWords, counter + offset / 64, nonceWords, block);
    const take = Math.min(64, data.length - offset);
    for (let i = 0; i < take; i++) output[offset + i] = data[offset + i] ^ block[i];
  }

  return output;
}

// --- Poly1305 ---------------------------------------------------------------

/** Splits a little-endian byte string into 13-bit limbs. */
function toLimbs(bytes: Uint8Array, extraBit: boolean, limbs: Int32Array): void {
  limbs.fill(0);
  let accumulator = 0;
  let bits = 0;
  let limb = 0;

  for (let i = 0; i < bytes.length && limb < LIMBS; i++) {
    accumulator |= bytes[i] << bits;
    bits += 8;
    while (bits >= LIMB_BITS && limb < LIMBS) {
      limbs[limb++] = accumulator & LIMB_MASK;
      accumulator >>>= LIMB_BITS;
      bits -= LIMB_BITS;
    }
  }
  if (limb < LIMBS) limbs[limb] = accumulator & LIMB_MASK;

  // The message block's implicit high bit: 2^(8 * length), which for a full
  // 16-byte block is bit 128 - limb 9, bit 11.
  if (extraBit) {
    const bit = bytes.length * 8;
    limbs[Math.floor(bit / LIMB_BITS)] |= 1 << (bit % LIMB_BITS);
  }
}

/**
 * Poly1305 (RFC 8439 §2.5): a one-time authenticator, not a hash. Evaluating
 * the message as a polynomial at the secret point r, modulo 2^130 - 5, then
 * adding the secret s.
 */
export function poly1305(key: Uint8Array, message: Uint8Array): Uint8Array {
  // r is clamped: certain bits are cleared so that the intermediate values
  // stay small enough for the reference implementation's arithmetic. Every
  // implementation must clamp identically or the MACs disagree.
  const clamped = new Uint8Array(key.subarray(0, 16));
  clamped[3] &= 15; clamped[7] &= 15; clamped[11] &= 15; clamped[15] &= 15;
  clamped[4] &= 252; clamped[8] &= 252; clamped[12] &= 252;

  const r = new Int32Array(LIMBS);
  toLimbs(clamped, false, r);

  const h = new Int32Array(LIMBS);
  const block = new Int32Array(LIMBS);
  const product = new Float64Array(LIMBS);

  for (let offset = 0; offset < message.length; offset += 16) {
    const chunk = message.subarray(offset, Math.min(offset + 16, message.length));
    toLimbs(chunk, true, block);
    for (let i = 0; i < LIMBS; i++) h[i] += block[i];

    // h = h * r mod 2^130 - 5. The wrap-around term is where the modulus
    // enters: a limb overflowing past 2^130 is worth 5 times its value back
    // at the bottom, and 130 being exactly ten limbs is what keeps that a
    // whole-limb shift rather than a bit-level one.
    for (let i = 0; i < LIMBS; i++) {
      let sum = 0;
      for (let j = 0; j <= i; j++) sum += h[j] * r[i - j];
      for (let j = i + 1; j < LIMBS; j++) sum += 5 * h[j] * r[i + LIMBS - j];
      product[i] = sum;
    }

    let carry = 0;
    for (let i = 0; i < LIMBS; i++) {
      const value = product[i] + carry;
      h[i] = value % 0x2000;
      carry = Math.floor(value / 0x2000);
    }
    // The carry out of the top limb is worth 5 each, folded back in.
    carry *= 5;
    for (let i = 0; i < LIMBS && carry !== 0; i++) {
      const value = h[i] + carry;
      h[i] = value & LIMB_MASK;
      carry = value >>> LIMB_BITS;
    }
  }

  // Final reduction: h + 5 overflows 2^130 exactly when h >= 2^130 - 5.
  const candidate = new Int32Array(LIMBS);
  let carry = 5;
  for (let i = 0; i < LIMBS; i++) {
    const value = h[i] + carry;
    candidate[i] = value & LIMB_MASK;
    carry = value >>> LIMB_BITS;
  }
  if (carry === 1) h.set(candidate);

  // Serialise the low 128 bits and add s, which is the second half of the key.
  const tag = new Uint8Array(POLY1305_TAG_LENGTH);
  let accumulator = 0;
  let bits = 0;
  let byte = 0;
  for (let i = 0; i < LIMBS && byte < POLY1305_TAG_LENGTH; i++) {
    accumulator |= h[i] << bits;
    bits += LIMB_BITS;
    while (bits >= 8 && byte < POLY1305_TAG_LENGTH) {
      tag[byte++] = accumulator & 0xff;
      accumulator >>>= 8;
      bits -= 8;
    }
  }

  let addCarry = 0;
  for (let i = 0; i < POLY1305_TAG_LENGTH; i++) {
    const value = tag[i] + key[16 + i] + addCarry;
    tag[i] = value & 0xff;
    addCarry = value >>> 8;
  }

  return tag;
}

// --- the AEAD ----------------------------------------------------------------

/** RFC 8439 §2.8: each of AAD and ciphertext padded to 16 bytes, then both lengths. */
function poly1305Input(aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const aadPadded = Math.ceil(aad.length / 16) * 16;
  const ciphertextPadded = Math.ceil(ciphertext.length / 16) * 16;
  const input = new Uint8Array(aadPadded + ciphertextPadded + 16);
  input.set(aad);
  input.set(ciphertext, aadPadded);

  const view = new DataView(input.buffer, aadPadded + ciphertextPadded, 16);
  // 64-bit little-endian lengths. Neither can approach 2^32 here - a TLS
  // record is at most 16 KB and a QUIC packet at most a datagram.
  view.setUint32(0, aad.length >>> 0, true);
  view.setUint32(8, ciphertext.length >>> 0, true);
  return input;
}

/**
 * ChaCha20-Poly1305 decryption with authentication.
 *
 * Returns null when the tag does not verify, exactly as `aesGcmDecrypt` does
 * and for the same reason: a wrong key must be reported, never rendered.
 */
export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array
): Uint8Array | null {
  if (key.length !== 32 || nonce.length !== 12 || tag.length !== POLY1305_TAG_LENGTH) return null;

  // The one-time Poly1305 key is the first 32 bytes of block 0 of the very
  // same keystream, which is why the payload starts at block 1.
  const otk = chacha20(key, nonce, 0, new Uint8Array(32));
  const expected = poly1305(otk, poly1305Input(aad, ciphertext));

  let mismatch = 0;
  for (let i = 0; i < POLY1305_TAG_LENGTH; i++) mismatch |= expected[i] ^ tag[i];
  if (mismatch !== 0) return null;

  return chacha20(key, nonce, 1, ciphertext);
}
