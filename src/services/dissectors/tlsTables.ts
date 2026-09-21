/**
 * Names for the numbers in a TLS handshake, as the IANA registries spell
 * them (which is also how Wireshark spells them, so the tree reads the same
 * in both). Only the values that actually appear in modern traffic plus the
 * legacy ones a 2010-era server still offers; anything else renders as
 * `Unknown (0x....)`, which is honest and filterable.
 */

export const TLS_VERSION_NAMES: Record<number, string> = {
  0x0300: 'SSLv3',
  0x0301: 'TLSv1',
  0x0302: 'TLSv1.1',
  0x0303: 'TLSv1.2',
  0x0304: 'TLSv1.3',
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

const EXTENSION_NAMES: Record<number, string> = {
  0: 'server_name', 1: 'max_fragment_length', 2: 'client_certificate_url', 3: 'trusted_ca_keys',
  4: 'truncated_hmac', 5: 'status_request', 6: 'user_mapping', 7: 'client_authz', 8: 'server_authz',
  9: 'cert_type', 10: 'supported_groups', 11: 'ec_point_formats', 12: 'srp', 13: 'signature_algorithms',
  14: 'use_srtp', 15: 'heartbeat', 16: 'application_layer_protocol_negotiation',
  17: 'status_request_v2', 18: 'signed_certificate_timestamp', 19: 'client_certificate_type',
  20: 'server_certificate_type', 21: 'padding', 22: 'encrypt_then_mac', 23: 'extended_master_secret',
  24: 'token_binding', 25: 'cached_info', 26: 'tls_lts', 27: 'compress_certificate',
  28: 'record_size_limit', 29: 'pwd_protect', 30: 'pwd_clear', 31: 'password_salt', 32: 'ticket_pinning',
  33: 'tls_cert_with_extern_psk', 34: 'delegated_credentials', 35: 'session_ticket',
  36: 'TLMSP', 37: 'TLMSP_proxying', 38: 'TLMSP_delegate', 39: 'supported_ekt_ciphers',
  41: 'pre_shared_key', 42: 'early_data', 43: 'supported_versions', 44: 'cookie',
  45: 'psk_key_exchange_modes', 47: 'certificate_authorities', 48: 'oid_filters', 49: 'post_handshake_auth',
  50: 'signature_algorithms_cert', 51: 'key_share', 52: 'transparency_info', 53: 'connection_id',
  54: 'connection_id', 55: 'external_id_hash', 56: 'external_session_id', 57: 'quic_transport_parameters',
  58: 'ticket_request', 59: 'dnssec_chain', 60: 'sequence_number_encryption_algorithms',
  61: 'rrc', 62: 'tls_flags', 0xfd00: 'ech_outer_extensions', 0xfe0d: 'encrypted_client_hello',
  0xff01: 'renegotiation_info', 0x4469: 'application_settings_old', 0x44cd: 'application_settings',
  0xffce: 'encrypted_server_name',
};

const GROUP_NAMES: Record<number, string> = {
  1: 'sect163k1', 2: 'sect163r1', 3: 'sect163r2', 4: 'sect193r1', 5: 'sect193r2', 6: 'sect233k1',
  7: 'sect233r1', 8: 'sect239k1', 9: 'sect283k1', 10: 'sect283r1', 11: 'sect409k1', 12: 'sect409r1',
  13: 'sect571k1', 14: 'sect571r1', 15: 'secp160k1', 16: 'secp160r1', 17: 'secp160r2', 18: 'secp192k1',
  19: 'secp192r1', 20: 'secp224k1', 21: 'secp224r1', 22: 'secp256k1', 23: 'secp256r1', 24: 'secp384r1',
  25: 'secp521r1', 26: 'brainpoolP256r1', 27: 'brainpoolP384r1', 28: 'brainpoolP512r1',
  29: 'x25519', 30: 'x448', 31: 'brainpoolP256r1tls13', 32: 'brainpoolP384r1tls13',
  33: 'brainpoolP512r1tls13', 34: 'GC256A', 35: 'GC256B', 36: 'GC256C', 37: 'GC256D', 38: 'GC512A',
  39: 'GC512B', 40: 'GC512C', 41: 'curveSM2', 256: 'ffdhe2048', 257: 'ffdhe3072', 258: 'ffdhe4096',
  259: 'ffdhe6144', 260: 'ffdhe8192', 512: 'MLKEM512', 513: 'MLKEM768', 514: 'MLKEM1024',
  0x11eb: 'SecP256r1MLKEM768', 0x11ec: 'X25519MLKEM768', 0x11ed: 'SecP384r1MLKEM1024',
  0x6399: 'X25519Kyber768Draft00', 0x639a: 'SecP256r1Kyber768Draft00',
  0xff01: 'arbitrary_explicit_prime_curves', 0xff02: 'arbitrary_explicit_char2_curves',
};

const SIGNATURE_ALGORITHM_NAMES: Record<number, string> = {
  0x0201: 'rsa_pkcs1_sha1', 0x0203: 'ecdsa_sha1', 0x0401: 'rsa_pkcs1_sha256', 0x0403: 'ecdsa_secp256r1_sha256',
  0x0501: 'rsa_pkcs1_sha384', 0x0503: 'ecdsa_secp384r1_sha384', 0x0601: 'rsa_pkcs1_sha512',
  0x0603: 'ecdsa_secp521r1_sha512', 0x0804: 'rsa_pss_rsae_sha256', 0x0805: 'rsa_pss_rsae_sha384',
  0x0806: 'rsa_pss_rsae_sha512', 0x0807: 'ed25519', 0x0808: 'ed448', 0x0809: 'rsa_pss_pss_sha256',
  0x080a: 'rsa_pss_pss_sha384', 0x080b: 'rsa_pss_pss_sha512', 0x081a: 'ecdsa_brainpoolP256r1tls13_sha256',
  0x081b: 'ecdsa_brainpoolP384r1tls13_sha384', 0x081c: 'ecdsa_brainpoolP512r1tls13_sha512',
  0x0904: 'mldsa44', 0x0905: 'mldsa65', 0x0906: 'mldsa87',
};

export const EC_POINT_FORMAT_NAMES: Record<number, string> = {
  0: 'uncompressed', 1: 'ansiX962_compressed_prime', 2: 'ansiX962_compressed_char2',
};

export const PSK_KEY_EXCHANGE_MODE_NAMES: Record<number, string> = { 0: 'PSK-only', 1: 'PSK with (EC)DHE' };

const CIPHER_SUITE_NAMES: Record<number, string> = {
  0x0000: 'TLS_NULL_WITH_NULL_NULL',
  0x0004: 'TLS_RSA_WITH_RC4_128_MD5', 0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA', 0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
  0x003d: 'TLS_RSA_WITH_AES_256_CBC_SHA256', 0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
  0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
  0x006b: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384', 0x009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
  0x009f: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
  0x1301: 'TLS_AES_128_GCM_SHA256', 0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256', 0x1304: 'TLS_AES_128_CCM_SHA256', 0x1305: 'TLS_AES_128_CCM_8_SHA256',
  0x5600: 'TLS_FALLBACK_SCSV',
  0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 0xc00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xc023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 0xc024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
  0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 0xc028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xc0ac: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM', 0xc0ad: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM',
  0xc0ae: 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8', 0xc0af: 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256', 0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0xccaa: 'TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
};

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
export const nameCipher = (v: number) =>
  isGrease(v) ? `Reserved (GREASE) (${hex4(v)})` : (CIPHER_SUITE_NAMES[v] ?? `Unknown (${hex4(v)})`);
export const nameExtension = (v: number) =>
  isGrease(v) ? `Reserved (GREASE) (${v})` : `${EXTENSION_NAMES[v] ?? 'Unknown type'} (${v})`;
export const nameGroup = (v: number) =>
  isGrease(v) ? `Reserved (GREASE) (${v})` : `${GROUP_NAMES[v] ?? 'Unknown'} (${v})`;
export const nameSignatureAlgorithm = (v: number) =>
  `${SIGNATURE_ALGORITHM_NAMES[v] ?? 'Unknown'} (${hex4(v)})`;
export const nameAlert = (level: number, description: number) =>
  `Level: ${ALERT_LEVEL_NAMES[level] ?? level}, Description: ${ALERT_DESCRIPTION_NAMES[description] ?? description}`;
