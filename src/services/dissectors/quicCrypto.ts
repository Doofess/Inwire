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
import { encryptBlock128, expandKey128, aes128GcmDecrypt, AES_BLOCK_SIZE } from '../crypto/aes';
import { hkdfExtract, hkdfExpandLabel } from '../crypto/hkdf';

/** RFC 9001 §5.2. Changed by QUIC v2 so v1 and v2 keys never collide. */
export const QUIC_V1_INITIAL_SALT = new Uint8Array([
  0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
  0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
]);

/** RFC 9369 §3.3.1. */
export const QUIC_V2_INITIAL_SALT = new Uint8Array([
  0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
  0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
]);

export const QUIC_VERSION_1 = 0x00000001;
export const QUIC_VERSION_2 = 0x6b3343cf;

const AEAD_TAG_LENGTH = 16;
/** The sample used for header protection is always 16 bytes, taken 4 past the packet number. */
const HEADER_PROTECTION_SAMPLE_OFFSET = 4;

export interface DirectionKeys {
  key: Uint8Array;
  iv: Uint8Array;
  headerProtection: Uint8Array;
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
  };
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
}

/**
 * Removes header protection and decrypts one Initial packet's payload.
 *
 * `packetStart` points at the packet's first byte, `pnOffset` at its packet
 * number field (i.e. just past the Length varint), and `packetEnd` at the byte
 * after its final one. Returns null whenever anything fails to line up -
 * including a failed authentication tag, which is the honest answer when the
 * keys are wrong, and keeps a wrong guess from rendering as plausible frames.
 */
export function decryptInitialPacket(
  bytes: Uint8Array,
  packetStart: number,
  pnOffset: number,
  packetEnd: number,
  keys: DirectionKeys,
  largestPacketNumber: number
): DecryptedPacket | null {
  const sampleStart = pnOffset + HEADER_PROTECTION_SAMPLE_OFFSET;
  if (sampleStart + AES_BLOCK_SIZE > packetEnd) return null;

  // The protection mask is the raw block cipher applied to a sample of the
  // ciphertext - this is why a single-block AES primitive is needed at all.
  const mask = encryptBlock128(
    expandKey128(keys.headerProtection),
    bytes.subarray(sampleStart, sampleStart + AES_BLOCK_SIZE)
  );

  // Long headers expose only the low 4 bits of the first byte to protection.
  const firstByte = bytes[packetStart] ^ (mask[0] & 0x0f);
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

  const payload = aes128GcmDecrypt(
    keys.key,
    nonce,
    aad,
    bytes.subarray(ciphertextStart, ciphertextEnd),
    bytes.subarray(ciphertextEnd, packetEnd)
  );
  if (!payload) return null;

  return { packetNumber, payload };
}
