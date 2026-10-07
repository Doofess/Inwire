/**
 * Names for the numbers in a TLS handshake, as the IANA registries spell
 * them (which is also how Wireshark spells them, so the tree reads the same
 * in both). Only the values that actually appear in modern traffic plus the
 * legacy ones a 2010-era server still offers; anything else renders as
 * `Unknown (0x....)`, which is honest and filterable.
 */

import { CIPHER_SUITES, EXTENSIONS, GROUPS, SIGNATURE_ALGORITHMS } from './tlsNames';

export const TLS_VERSION_NAMES: Record<number, string> = {
  0x0300: 'SSLv3',
  0x0301: 'TLSv1',
  0x0302: 'TLSv1.1',
  0x0303: 'TLSv1.2',
  0x0304: 'TLSv1.3',
  // DTLS counts down from 0xffff, skipping 1.1 (RFC 6347 §4.1).
  0xfeff: 'DTLSv1.0',
  0xfefd: 'DTLSv1.2',
  0xfefc: 'DTLSv1.3',
};

export const CONTENT_TYPE_NAMES: Record<number, string> = {
  20: 'Change Cipher Spec',
  21: 'Alert',
  22: 'Handshake',
  23: 'Application Data',
  24: 'Heartbeat',
  // 25 and 26 are inside `CT_MAX` - they may resynchronise a stream - but only
  // 25 has a name. The reference analyzer's tree reads "Connection ID (25)" and
  // "Unknown (26)", and NEITHER contributes an element to the Info column; see
  // `INFO_NAMED_CONTENT_TYPE_MAX` in tls.ts.
  25: 'Connection ID',
};

export const HANDSHAKE_TYPE_NAMES: Record<number, string> = {
  0: 'Hello Request',
  1: 'Client Hello',
  2: 'Server Hello',
  3: 'Hello Verify Request',
  4: 'New Session Ticket',
  5: 'End of Early Data',
  8: 'Encrypted Extensions',
  11: 'Certificate',
  12: 'Server Key Exchange',
  13: 'Certificate Request',
  14: 'Server Hello Done',
  15: 'Certificate Verify',
  16: 'Client Key Exchange',
  20: 'Finished',
  22: 'Certificate Status',
  24: 'Key Update',
  67: 'Compressed Certificate',
  254: 'Message Hash',
};

/** RFC 6961. The reference writes "OCSP Multi" for 2, not "OCSP v2". */
export const CERTIFICATE_STATUS_TYPE_NAMES: Record<number, string> = {
  1: 'OCSP',
  2: 'OCSP Multi',
};

export const ALERT_LEVEL_NAMES: Record<number, string> = { 1: 'Warning', 2: 'Fatal' };

export const ALERT_DESCRIPTION_NAMES: Record<number, string> = {
  0: 'Close Notify', 10: 'Unexpected Message', 20: 'Bad Record MAC', 21: 'Decryption Failed',
  22: 'Record Overflow', 30: 'Decompression Failure', 40: 'Handshake Failure', 41: 'No Certificate',
  42: 'Bad Certificate', 43: 'Unsupported Certificate', 44: 'Certificate Revoked',
  45: 'Certificate Expired', 46: 'Certificate Unknown', 47: 'Illegal Parameter', 48: 'Unknown CA',
  49: 'Access Denied', 50: 'Decode Error', 51: 'Decrypt Error', 60: 'Export Restriction',
  70: 'Protocol Version', 71: 'Insufficient Security', 80: 'Internal Error',
  86: 'Inappropriate Fallback', 90: 'User Canceled', 100: 'No Renegotiation',
  109: 'Missing Extension', 110: 'Unsupported Extension', 111: 'Certificate Unobtainable',
  112: 'Unrecognized Name', 113: 'Bad Certificate Status Response', 114: 'Bad Certificate Hash Value',
  115: 'Unknown PSK Identity', 116: 'Certificate Required', 120: 'No Application Protocol',
};




export const EC_POINT_FORMAT_NAMES: Record<number, string> = {
  0: 'uncompressed', 1: 'ansiX962_compressed_prime', 2: 'ansiX962_compressed_char2',
};

export const PSK_KEY_EXCHANGE_MODE_NAMES: Record<number, string> = { 0: 'PSK-only', 1: 'PSK with (EC)DHE' };


/**
 * RFC 8701 GREASE values: `0x?a?a` with both bytes equal. Clients sprinkle
 * these through every list so servers stay tolerant of unknown values; they
 * mean nothing and every fingerprint strips them.
 */
export function isGrease(value: number): boolean {
  return (value & 0x0f0f) === 0x0a0a && ((value >> 8) & 0xff) === (value & 0xff);
}

const hex4 = (n: number) => `0x${n.toString(16).padStart(4, '0')}`;

export const nameVersion = (v: number) => TLS_VERSION_NAMES[v] ?? `Unknown (${hex4(v)})`;
/** A suite as the reference writes one: its name and its code, `TLS_AES_128_GCM_SHA256 (0x1301)`. */
export const nameCipher = (v: number) =>
  isGrease(v) ? `Reserved (GREASE) (${hex4(v)})` : `${CIPHER_SUITES[v] ?? 'Unknown'} (${hex4(v)})`;
export const nameExtension = (v: number) =>
  isGrease(v) ? `Reserved (GREASE) (${v})` : `${EXTENSIONS[v] ?? 'Unknown type'} (${v})`;
/** A group and its code in hex, as the reference writes it: `x25519 (0x001d)`. */
export const nameGroup = (v: number) =>
  isGrease(v) ? `Reserved (GREASE) (${hex4(v)})` : `${GROUPS[v] ?? 'Unknown'} (${hex4(v)})`;
/** The bare name, for a key share's own summary line: `Group: x25519, Key Exchange length: 32`. */
export const groupName = (v: number) => (isGrease(v) ? 'Reserved (GREASE)' : GROUPS[v] ?? 'Unknown');
/** RFC 5246 §7.4.1.4.1's two halves of a TLS 1.2 signature algorithm, by the reference's names. */
const SIGNATURE_HASHES: Record<number, string> = { 0: 'None', 1: 'MD5', 2: 'SHA1', 3: 'SHA224', 4: 'SHA256', 5: 'SHA384', 6: 'SHA512' };
const SIGNATURE_KINDS: Record<number, string> = { 0: 'Anonymous', 1: 'RSA', 2: 'DSA', 3: 'ECDSA' };
export const nameSignatureHash = (v: number) => `${SIGNATURE_HASHES[v] ?? 'Unknown'} (${v})`;
export const nameSignatureKind = (v: number) => `${SIGNATURE_KINDS[v] ?? 'Unknown'} (${v})`;
export const nameSignatureAlgorithm = (v: number) =>
  // A TLS 1.2 pair the TLS 1.3 table has no name for is its two halves, as
  // the reference writes it: `SHA224 ECDSA (0x0303)`.
  `${SIGNATURE_ALGORITHMS[v] ?? `${SIGNATURE_HASHES[(v >> 8) & 0xff] ?? 'Unknown'} ${SIGNATURE_KINDS[v & 0xff] ?? 'Unknown'}`} (${hex4(v)})`;
export const nameAlert = (level: number, description: number) =>
  `Level: ${ALERT_LEVEL_NAMES[level] ?? level}, Description: ${ALERT_DESCRIPTION_NAMES[description] ?? description}`;
