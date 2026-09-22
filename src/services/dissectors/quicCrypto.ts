/**
 * QUIC Initial packet decryption (RFC 9001).
 *
 * Initial packets are the one part of a QUIC connection anyone can read: their
 * keys derive from the Destination Connection ID, which the client sends in
 * the clear precisely so that a server which has never seen the connection can
 * decrypt it. Everything after the handshake - 0-RTT, Handshake, and 1-RTT
 * packets - needs the TLS session secrets, which a passive observer does not
 * have, so those stay opaque here exactly as they do in the reference analyzer.
 *
 * This is what turns "Initial, DCID=9635b6f53a7cb323" into
 * "Initial, DCID=9635b6f53a7cb323, PKN: 1, CRYPTO, CRYPTO, PING".
 */
import {
  encryptBlock, expandKeyCached, aesGcmDecrypt, AES_BLOCK_SIZE, AEAD_TAG_LENGTH,
} from '../crypto/aes';
import { chacha20, chacha20Poly1305Decrypt } from '../crypto/chacha20poly1305';
import { hkdfExtract, hkdfExpandLabel } from '../crypto/hkdf';
import type { CipherSuiteSpec } from '../tls/cipherSuites';

/** RFC 9001 §5.2. Changed by QUIC v2 so v1 and v2 keys never collide. */
export const QUIC_V1_INITIAL_SALT = new Uint8Array([
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
  0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
]);

/** RFC 9369 §3.3.1. */
const QUIC_V2_INITIAL_SALT = new Uint8Array([
  0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
  0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
]);

const QUIC_VERSION_1 = 0x00000001;
export const QUIC_VERSION_2 = 0x6b3343cf;

/** The sample used for header protection is always 16 bytes, taken 4 past the packet number. */
const HEADER_PROTECTION_SAMPLE_OFFSET = 4;

export interface DirectionKeys {
  key: Uint8Array;
  iv: Uint8Array;
  headerProtection: Uint8Array;
  /**
   * Which AEAD opens the payload and which primitive builds the header
   * protection mask. Initial packets are always AES-128-GCM; a connection that
   * negotiated ChaCha20-Poly1305 uses it for everything after them, including
   * the header mask, which is a *different* construction rather than the same
   * one with another cipher.
   */
  aead: 'aes-gcm' | 'chacha20-poly1305';
}

export interface InitialKeys {
  client: DirectionKeys;
  server: DirectionKeys;
}

function deriveDirection(initialSecret: Uint8Array, label: string, isV2: boolean): DirectionKeys {
  const secret = hkdfExpandLabel(initialSecret, label, new Uint8Array(0), 32);
  // QUIC v2 renamed the key labels so that a v1 and a v2 connection with the
  // same connection ID cannot end up with identical keys.
  const prefix = isV2 ? 'quicv2 ' : 'quic ';
  return {
    key: hkdfExpandLabel(secret, `${prefix}key`, new Uint8Array(0), 16),
    iv: hkdfExpandLabel(secret, `${prefix}iv`, new Uint8Array(0), 12),
    headerProtection: hkdfExpandLabel(secret, `${prefix}hp`, new Uint8Array(0), 16),
    aead: 'aes-gcm',
  };
}

/**
 * Derives one direction's packet protection keys from a key log traffic
 * secret (RFC 9001 section 5.1).
 *
 * The same secret TLS would expand into a record key expands here into a QUIC
 * packet key - with QUIC's own labels, and one extra output TLS has no need
 * for: the header protection key, because QUIC encrypts its packet number and
 * some of its first byte where TLS leaves its record header in the clear. The
 * hash is the cipher suite's, so a SHA-384 suite must expand with SHA-384 or
 * the keys are wrong in a way only the AEAD tag reveals.
 */
export function deriveTrafficKeys(
  secret: Uint8Array,
  suite: CipherSuiteSpec,
  isV2 = false
): DirectionKeys {
  const prefix = isV2 ? 'quicv2 ' : 'quic ';
  return {
    key: hkdfExpandLabel(secret, `${prefix}key`, new Uint8Array(0), suite.keyLength, suite.hash),
    iv: hkdfExpandLabel(secret, `${prefix}iv`, new Uint8Array(0), 12, suite.hash),
    headerProtection: hkdfExpandLabel(secret, `${prefix}hp`, new Uint8Array(0), suite.keyLength, suite.hash),
    aead: suite.aead,
  };
}

/**
 * The five-byte header protection mask (RFC 9001 section 5.4).
 *
 * Two constructions, one per AEAD family. AES applies the raw block cipher to
 * the sample - which is the reason a single-block AES primitive exists in this
 * codebase at all. ChaCha20 instead reads the sample as a counter and a nonce
 * and encrypts five zero bytes with them, so the "mask" is the head of a
 * keystream block. Using one where the other belongs yields a plausible-
 * looking packet number and a payload that fails to authenticate.
 */
function headerProtectionMask(keys: DirectionKeys, sample: Uint8Array): Uint8Array {
  if (keys.aead === 'aes-gcm') {
    // Cached: header protection is applied to every packet on the connection,
    // and the key does not change - so this was expanding the same schedule
    // once per packet.
    return encryptBlock(expandKeyCached(keys.headerProtection), sample);
  }
  const counter = sample[0] | (sample[1] << 8) | (sample[2] << 16) | (sample[3] << 24);
  return chacha20(keys.headerProtection, sample.subarray(4, 16), counter >>> 0, new Uint8Array(5));
}

/**
 * Derives both directions' Initial keys from the client's Destination
 * Connection ID - the one from the *first* Initial packet of the connection,
 * which is what seeds the whole thing.
 */
export function deriveInitialKeys(
  destinationConnectionId: Uint8Array,
  salt: Uint8Array,
  isV2: boolean
): InitialKeys {
  const initialSecret = hkdfExtract(salt, destinationConnectionId);
  return {
    client: deriveDirection(initialSecret, 'client in', isV2),
    server: deriveDirection(initialSecret, 'server in', isV2),
  };
}

export function saltForVersion(version: number): Uint8Array | null {
  if (version === QUIC_VERSION_1) return QUIC_V1_INITIAL_SALT;
  if (version === QUIC_VERSION_2) return QUIC_V2_INITIAL_SALT;
  return null;
}

/**
 * Reconstructs a full packet number from the truncated one on the wire
 * (RFC 9000 §A.3). Only the low bits are transmitted, so the value is
 * resolved to whichever candidate sits closest to the one expected next.
 */
function decodePacketNumber(largestReceived: number, truncated: number, bitLength: number): number {
  const window = 2 ** bitLength;
  const expected = largestReceived + 1;
  const candidate = (expected & ~(window - 1)) | truncated;

  if (candidate <= expected - window / 2 && candidate < 2 ** 62 - window) return candidate + window;
  if (candidate > expected + window / 2 && candidate >= window) return candidate - window;
  return candidate;
}

export interface DecryptedPacket {
  packetNumber: number;
  payload: Uint8Array;
  /**
   * The first byte with header protection removed.
   *
   * Carried out because it is the only place the protected bits are readable
   * and they were being computed and dropped: the long header's two reserved
   * bits and the packet-number length live in its low nibble, and RFC 9001
   * masks exactly those. A packet this build could not decrypt genuinely has
   * no answer for them - which is why they are optional on the record rather
   * than drawn as zero.
   */
  firstByte: number;
  /** Bytes the packet number occupies, 1 to 4, from the unprotected bits. */
  packetNumberLength: number;
}

/**
 * Removes header protection and decrypts one packet's payload, long header or
 * short.
 *
 * `isLongHeader` decides how much of the first byte is protected: four bits on
 * a long header, five on a short one, the extra bit being the key phase. That
 * one-bit difference is the whole of what separates a Handshake packet from a
 * 1-RTT packet here; everything else - the sample position, the nonce, the AAD
 * - is identical, which is why they share this function.
 */
export function decryptQuicPacket(
  bytes: Uint8Array,
  packetStart: number,
  pnOffset: number,
  packetEnd: number,
  keys: DirectionKeys,
  largestPacketNumber: number,
  isLongHeader: boolean
): DecryptedPacket | null {
  const sampleStart = pnOffset + HEADER_PROTECTION_SAMPLE_OFFSET;
  if (sampleStart + AES_BLOCK_SIZE > packetEnd) return null;

  const mask = headerProtectionMask(keys, bytes.subarray(sampleStart, sampleStart + AES_BLOCK_SIZE));

  const firstByte = bytes[packetStart] ^ (mask[0] & (isLongHeader ? 0x0f : 0x1f));
  const pnLength = (firstByte & 0x03) + 1;
  if (pnOffset + pnLength > packetEnd) return null;

  let truncatedPacketNumber = 0;
  const packetNumberBytes = new Uint8Array(pnLength);
  for (let i = 0; i < pnLength; i++) {
    packetNumberBytes[i] = bytes[pnOffset + i] ^ mask[1 + i];
    truncatedPacketNumber = (truncatedPacketNumber << 8) | packetNumberBytes[i];
  }
  const packetNumber = decodePacketNumber(largestPacketNumber, truncatedPacketNumber >>> 0, pnLength * 8);

  const ciphertextStart = pnOffset + pnLength;
  const ciphertextEnd = packetEnd - AEAD_TAG_LENGTH;
  if (ciphertextEnd <= ciphertextStart) return null;

  // The nonce is the static IV XORed with the packet number, right-aligned.
  const nonce = new Uint8Array(keys.iv);
  for (let i = 0; i < 8; i++) {
    // Split the shift: packet numbers can exceed 32 bits, where JS's bitwise
    // operators would silently wrap.
    const shifted = Math.floor(packetNumber / 2 ** (8 * i)) & 0xff;
    nonce[nonce.length - 1 - i] ^= shifted;
  }

  // The AAD is the packet header exactly as it appears once unprotected -
  // first byte and packet number in the clear, everything else untouched.
  const aad = new Uint8Array(bytes.subarray(packetStart, ciphertextStart));
  aad[0] = firstByte;
  aad.set(packetNumberBytes, pnOffset - packetStart);

  const ciphertext = bytes.subarray(ciphertextStart, ciphertextEnd);
  const tag = bytes.subarray(ciphertextEnd, packetEnd);
  const payload = keys.aead === 'aes-gcm'
    ? aesGcmDecrypt(keys.key, nonce, aad, ciphertext, tag)
    : chacha20Poly1305Decrypt(keys.key, nonce, aad, ciphertext, tag);
  if (!payload) return null;

  return { packetNumber, payload, firstByte, packetNumberLength: pnLength };
}
