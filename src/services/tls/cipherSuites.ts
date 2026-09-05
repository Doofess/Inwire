/**
 * The cipher suites this build can decrypt, and what each one needs.
 *
 * A suite number decides four things at once - the AEAD, the key length, how
 * the nonce is built, and which hash the key schedule runs on - and getting
 * any of them wrong produces keys that fail the AEAD tag with no indication of
 * which of the four was to blame. Naming them in one table is what keeps that
 * from being spread across the code that uses them.
 *
 * What is deliberately absent: the CBC suites. They are MAC-then-encrypt with
 * an explicit IV and a padding check, not an AEAD, and they were removed from
 * TLS 1.3 for reasons that also make them a poor thing to reimplement. A
 * connection using one is reported as "not decryptable" with the reason,
 * rather than silently ignored - the user supplied a key log and deserves to
 * know why it did not help. The CCM suites are absent for a simpler reason:
 * nothing on the open web negotiates them.
 */
import { SHA256, SHA384, type HashSpec } from '../crypto/hkdf';

export type AeadAlgorithm = 'aes-gcm' | 'chacha20-poly1305';

export interface CipherSuiteSpec {
  name: string;
  aead: AeadAlgorithm;
  /** Bytes of key material the AEAD takes. */
  keyLength: number;
  /**
   * Bytes of IV derived from the key schedule. TLS 1.3 and the TLS 1.2
   * ChaCha20 suites derive a full 12-byte IV and XOR the sequence number into
   * it; the TLS 1.2 GCM suites derive only a 4-byte salt and send the other
   * eight bytes of the nonce in front of every record.
   */
  ivLength: number;
  /** Bytes of nonce sent in the clear ahead of the ciphertext. Zero for everything but TLS 1.2 GCM. */
  explicitNonceLength: number;
  /** The hash the key schedule (HKDF for 1.3, the PRF for 1.2) runs on. */
  hash: HashSpec;
  /** True for the TLS 1.3 suites, whose numbers live in their own registry. */
  tls13: boolean;
}

const TLS13: Record<number, CipherSuiteSpec> = {
  0x1301: { name: 'TLS_AES_128_GCM_SHA256', aead: 'aes-gcm', keyLength: 16, ivLength: 12, explicitNonceLength: 0, hash: SHA256, tls13: true },
  0x1302: { name: 'TLS_AES_256_GCM_SHA384', aead: 'aes-gcm', keyLength: 32, ivLength: 12, explicitNonceLength: 0, hash: SHA384, tls13: true },
  0x1303: { name: 'TLS_CHACHA20_POLY1305_SHA256', aead: 'chacha20-poly1305', keyLength: 32, ivLength: 12, explicitNonceLength: 0, hash: SHA256, tls13: true },
};

const TLS12: Record<number, CipherSuiteSpec> = {
  0x009c: { name: 'TLS_RSA_WITH_AES_128_GCM_SHA256', aead: 'aes-gcm', keyLength: 16, ivLength: 4, explicitNonceLength: 8, hash: SHA256, tls13: false },
  0x009d: { name: 'TLS_RSA_WITH_AES_256_GCM_SHA384', aead: 'aes-gcm', keyLength: 32, ivLength: 4, explicitNonceLength: 8, hash: SHA384, tls13: false },
  0x009e: { name: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', aead: 'aes-gcm', keyLength: 16, ivLength: 4, explicitNonceLength: 8, hash: SHA256, tls13: false },
  0x009f: { name: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', aead: 'aes-gcm', keyLength: 32, ivLength: 4, explicitNonceLength: 8, hash: SHA384, tls13: false },
  0xc02b: { name: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', aead: 'aes-gcm', keyLength: 16, ivLength: 4, explicitNonceLength: 8, hash: SHA256, tls13: false },
  0xc02c: { name: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', aead: 'aes-gcm', keyLength: 32, ivLength: 4, explicitNonceLength: 8, hash: SHA384, tls13: false },
  0xc02f: { name: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', aead: 'aes-gcm', keyLength: 16, ivLength: 4, explicitNonceLength: 8, hash: SHA256, tls13: false },
  0xc030: { name: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', aead: 'aes-gcm', keyLength: 32, ivLength: 4, explicitNonceLength: 8, hash: SHA384, tls13: false },
  0xcca8: { name: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', aead: 'chacha20-poly1305', keyLength: 32, ivLength: 12, explicitNonceLength: 0, hash: SHA256, tls13: false },
  0xcca9: { name: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256', aead: 'chacha20-poly1305', keyLength: 32, ivLength: 12, explicitNonceLength: 0, hash: SHA256, tls13: false },
  0xccaa: { name: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256', aead: 'chacha20-poly1305', keyLength: 32, ivLength: 12, explicitNonceLength: 0, hash: SHA256, tls13: false },
};

export function cipherSuiteSpec(suite: number): CipherSuiteSpec | null {
  return TLS13[suite] ?? TLS12[suite] ?? null;
}

/**
 * Why a suite we recognise by name cannot be decrypted, for the tree note.
 * Returns null when the suite *is* supported, which is the only case where
 * silence is the right answer.
 */
export function undecryptableReason(suite: number, suiteName: string): string | null {
  if (cipherSuiteSpec(suite) !== null) return null;
  if (/_CBC_/.test(suiteName)) return 'CBC cipher suites are not decrypted (MAC-then-encrypt, not an AEAD)';
  if (/_CCM/.test(suiteName)) return 'CCM cipher suites are not decrypted';
  if (/RC4|NULL|EXPORT|DES/.test(suiteName)) return `${suiteName} is not decrypted`;
  return `cipher suite 0x${suite.toString(16).padStart(4, '0')} is not decrypted`;
}
