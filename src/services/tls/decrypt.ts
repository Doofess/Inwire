/**
 * Turning key log secrets into TLS record plaintext.
 *
 * Two key schedules live here because TLS 1.2 and 1.3 share nothing but the
 * name. In 1.2 the log gives the 48-byte master secret and the PRF expands it
 * into a key block both directions are cut from, once, for the life of the
 * connection. In 1.3 the log gives one traffic secret per direction *per
 * epoch* - handshake and application - and HKDF-Expand-Label derives a key and
 * an IV from each; a direction's records restart their sequence numbering at
 * zero every time it moves to the next epoch.
 *
 * Nothing here guesses. Every decryption is checked by the AEAD tag, and a
 * failure is returned as a failure: a TLS record that will not authenticate
 * under the key we derived is a record we have no business rendering.
 */
import { aesGcmDecrypt, AEAD_TAG_LENGTH } from '../crypto/aes';
import { chacha20Poly1305Decrypt } from '../crypto/chacha20poly1305';
import { hkdfExpandLabel, tls12Prf } from '../crypto/hkdf';
import type { CipherSuiteSpec } from './cipherSuites';

/** One direction's keys for one epoch. */
export interface DirectionEpoch {
  /** "handshake" or "application" in TLS 1.3; "application" alone in TLS 1.2. */
  name: string;
  key: Uint8Array;
  iv: Uint8Array;
}

export interface TlsDecryptionKeys {
  suite: CipherSuiteSpec;
  /** In the order a direction moves through them. */
  client: DirectionEpoch[];
  server: DirectionEpoch[];
  /** Which key log labels this was built from, for the tree note. */
  from: string[];
}

function expand(secret: Uint8Array, suite: CipherSuiteSpec, name: string): DirectionEpoch {
  return {
    name,
    key: hkdfExpandLabel(secret, 'key', new Uint8Array(0), suite.keyLength, suite.hash),
    iv: hkdfExpandLabel(secret, 'iv', new Uint8Array(0), 12, suite.hash),
  };
}

/**
 * Derives both directions' keys from whatever the key log holds for this
 * connection. Returns null when the log has nothing usable for it, which is
 * the ordinary case for a capture whose log covers only some connections.
 */
export function deriveFromKeyLog(
  suite: CipherSuiteSpec,
  clientRandom: Uint8Array,
  serverRandom: Uint8Array,
  secrets: Map<string, Uint8Array>
): TlsDecryptionKeys | null {
  const from: string[] = [];

  if (suite.tls13) {
    const client: DirectionEpoch[] = [];
    const server: DirectionEpoch[] = [];

    // Order matters: a direction walks this list forwards and never back.
    const clientHandshake = secrets.get('CLIENT_HANDSHAKE_TRAFFIC_SECRET');
    const serverHandshake = secrets.get('SERVER_HANDSHAKE_TRAFFIC_SECRET');
    if (clientHandshake && serverHandshake) {
      client.push(expand(clientHandshake, suite, 'handshake'));
      server.push(expand(serverHandshake, suite, 'handshake'));
      from.push('CLIENT_HANDSHAKE_TRAFFIC_SECRET', 'SERVER_HANDSHAKE_TRAFFIC_SECRET');
    }

    const clientApp = secrets.get('CLIENT_TRAFFIC_SECRET_0');
    const serverApp = secrets.get('SERVER_TRAFFIC_SECRET_0');
    if (clientApp && serverApp) {
      client.push(expand(clientApp, suite, 'application'));
      server.push(expand(serverApp, suite, 'application'));
      from.push('CLIENT_TRAFFIC_SECRET_0', 'SERVER_TRAFFIC_SECRET_0');
    }

    if (client.length === 0) return null;
    return { suite, client, server, from };
  }

  const master = secrets.get('CLIENT_RANDOM');
  if (master === undefined) return null;

  // TLS 1.2 §6.3: one key block, cut in a fixed order. The seed is the server
  // random first - the opposite order from the one the master secret itself
  // was derived with, which is a real and easily-missed asymmetry.
  const seed = new Uint8Array(serverRandom.length + clientRandom.length);
  seed.set(serverRandom);
  seed.set(clientRandom, serverRandom.length);

  const needed = 2 * suite.keyLength + 2 * suite.ivLength;
  const block = tls12Prf(master, 'key expansion', seed, needed, suite.hash);

  let p = 0;
  const clientKey = block.subarray(p, p + suite.keyLength); p += suite.keyLength;
  const serverKey = block.subarray(p, p + suite.keyLength); p += suite.keyLength;
  const clientIv = block.subarray(p, p + suite.ivLength); p += suite.ivLength;
  const serverIv = block.subarray(p, p + suite.ivLength);

  return {
    suite,
    client: [{ name: 'application', key: clientKey, iv: clientIv }],
    server: [{ name: 'application', key: serverKey, iv: serverIv }],
    from: ['CLIENT_RANDOM'],
  };
}

/** The static IV with the record sequence number XORed into its right-hand end. */
function nonceFromSequence(iv: Uint8Array, sequence: number): Uint8Array {
  const nonce = new Uint8Array(iv);
  for (let i = 0; i < 8; i++) {
    // Split the shift rather than using a 64-bit operator: a long-lived
    // connection's sequence number passes 2^32, where JavaScript's bitwise
    // operators wrap without saying so.
    const byte = Math.floor(sequence / 2 ** (8 * i)) & 0xff;
    nonce[nonce.length - 1 - i] ^= byte;
  }
  return nonce;
}

function openAead(
  suite: CipherSuiteSpec,
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  body: Uint8Array
): Uint8Array | null {
  if (body.length < AEAD_TAG_LENGTH) return null;
  const ciphertext = body.subarray(0, body.length - AEAD_TAG_LENGTH);
  const tag = body.subarray(body.length - AEAD_TAG_LENGTH);
  return suite.aead === 'aes-gcm'
    ? aesGcmDecrypt(key, nonce, aad, ciphertext, tag)
    : chacha20Poly1305Decrypt(key, nonce, aad, ciphertext, tag);
}

export interface DecryptedRecord {
  plaintext: Uint8Array;
  /**
   * The real content type. In TLS 1.3 the record header always says 23
   * (application data) and the true type is the last non-zero byte of the
   * plaintext, which is how the handshake hides behind application records.
   */
  contentType: number;
}

/**
 * Decrypts one record body. `recordVersion` and `recordLength` are the header
 * fields as they appeared on the wire, because both key schedules authenticate
 * the header rather than just the payload.
 */
export function decryptRecord(
  keys: TlsDecryptionKeys,
  epoch: DirectionEpoch,
  sequence: number,
  headerContentType: number,
  recordVersion: number,
  body: Uint8Array
): DecryptedRecord | null {
  const suite = keys.suite;

  if (suite.tls13) {
    // AAD is the record header exactly as sent.
    const aad = new Uint8Array([
      headerContentType, recordVersion >> 8, recordVersion & 0xff, body.length >> 8, body.length & 0xff,
    ]);
    const plaintext = openAead(suite, epoch.key, nonceFromSequence(epoch.iv, sequence), aad, body);
    if (plaintext === null) return null;

    // Strip the zero padding, then take the type byte that ends the record.
    let end = plaintext.length;
    while (end > 0 && plaintext[end - 1] === 0) end--;
    if (end === 0) return null;
    return { plaintext: plaintext.subarray(0, end - 1), contentType: plaintext[end - 1] };
  }

  const explicit = suite.explicitNonceLength;
  if (body.length < explicit + AEAD_TAG_LENGTH) return null;

  // TLS 1.2 GCM sends eight bytes of nonce in front of the ciphertext and
  // derives only the four-byte salt; the ChaCha20 suites derive all twelve and
  // XOR the sequence number in, exactly as 1.3 does.
  const nonce = explicit > 0
    ? Uint8Array.from([...epoch.iv, ...body.subarray(0, explicit)])
    : nonceFromSequence(epoch.iv, sequence);

  const payload = body.subarray(explicit);
  const plaintextLength = payload.length - AEAD_TAG_LENGTH;

  // AAD is the sequence number and the header, with the length of the
  // *plaintext* - not of the record as sent.
  const aad = new Uint8Array(13);
  for (let i = 0; i < 8; i++) aad[7 - i] = Math.floor(sequence / 2 ** (8 * i)) & 0xff;
  aad[8] = headerContentType;
  aad[9] = recordVersion >> 8;
  aad[10] = recordVersion & 0xff;
  aad[11] = plaintextLength >> 8;
  aad[12] = plaintextLength & 0xff;

  const plaintext = openAead(suite, epoch.key, nonce, aad, payload);
  if (plaintext === null) return null;
  return { plaintext, contentType: headerContentType };
}
