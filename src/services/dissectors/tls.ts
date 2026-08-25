/**
 * TLS record-layer dissection, enough to produce Wireshark's Protocol label
 * ("TLSv1.2") and Info summary ("Application Data", "Client Hello (SNI=...)")
 * without decrypting anything.
 *
 * This exists because guessing "port 443 means TLS" is wrong often enough to
 * matter: a bare ACK, a keep-alive, or a retransmission on a TLS connection
 * carries no TLS record at all, and Wireshark labels those frames TCP. Only
 * a frame that actually contains a well-formed record header gets a TLS label.
 */

const CONTENT_TYPE_CHANGE_CIPHER_SPEC = 20;
const CONTENT_TYPE_ALERT = 21;
const CONTENT_TYPE_HANDSHAKE = 22;
const CONTENT_TYPE_APPLICATION_DATA = 23;

/**
 * Record-layer version -> display name. TLS 1.3 deliberately pins the record
 * layer at 0x0303 ("TLSv1.2") for middlebox compatibility and negotiates the
 * real version in a ClientHello extension, so a 1.3 connection still shows
 * TLSv1.2 here until the handshake is parsed - which is exactly what Wireshark
 * shows too.
 */
const VERSION_NAMES: Record<number, string> = {
  0x0300: 'SSLv3',
  0x0301: 'TLSv1',
  0x0302: 'TLSv1.1',
  0x0303: 'TLSv1.2',
  0x0304: 'TLSv1.3',
};

const HANDSHAKE_TYPE_NAMES: Record<number, string> = {
  0: 'Hello Request',
  1: 'Client Hello',
  2: 'Server Hello',
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
};

export interface TlsDissectorResult {
  /** "TLSv1.2" - what the Protocol column shows. */
  protocolLabel: string;
  /** "Application Data", or several records joined with ", ". */
  info: string;
}

/**
 * Reads the Server Name Indication out of a ClientHello, so the Info column
 * can name the host being connected to. Walks the variable-length fields the
 * extension block sits behind; returns null the moment anything doesn't fit,
 * since a truncated or encrypted hello is common and not an error.
 */
function extractSni(bytes: Uint8Array, handshakeStart: number, handshakeEnd: number): string | null {
  // ClientHello: version(2) random(32) then variable-length session id,
  // cipher suites, and compression methods before the extension block.
  let p = handshakeStart + 4 + 2 + 32;
  if (p >= handshakeEnd) return null;

  const sessionIdLen = bytes[p];
  p += 1 + sessionIdLen;
  if (p + 2 > handshakeEnd) return null;

  const cipherSuitesLen = (bytes[p] << 8) | bytes[p + 1];
  p += 2 + cipherSuitesLen;
  if (p >= handshakeEnd) return null;

  const compressionLen = bytes[p];
  p += 1 + compressionLen;
  if (p + 2 > handshakeEnd) return null;

  const extensionsLen = (bytes[p] << 8) | bytes[p + 1];
  p += 2;
  const extensionsEnd = Math.min(handshakeEnd, p + extensionsLen);

  while (p + 4 <= extensionsEnd) {
    const extType = (bytes[p] << 8) | bytes[p + 1];
    const extLen = (bytes[p + 2] << 8) | bytes[p + 3];
    const extBody = p + 4;
    if (extType === 0x0000 && extBody + 5 <= extensionsEnd) {
      // server_name: list length(2), name type(1), name length(2), name.
      const nameLen = (bytes[extBody + 3] << 8) | bytes[extBody + 4];
      const nameStart = extBody + 5;
      if (nameStart + nameLen <= extensionsEnd) {
        return new TextDecoder().decode(bytes.subarray(nameStart, nameStart + nameLen));
      }
      return null;
    }
    p = extBody + extLen;
  }
  return null;
}

/**
 * Dissects the TLS records in a TCP payload. Returns null when the payload
 * isn't TLS, which the caller should treat as "this is a plain TCP frame".
 */
export function dissectTls(bytes: Uint8Array, payloadStart: number, payloadEnd: number): TlsDissectorResult | null {
  if (payloadEnd - payloadStart < 5) return null;

  const descriptions: string[] = [];
  let protocolLabel: string | null = null;
  let offset = payloadStart;

  while (offset + 5 <= payloadEnd) {
    const contentType = bytes[offset];
    const version = (bytes[offset + 1] << 8) | bytes[offset + 2];
    const recordLength = (bytes[offset + 3] << 8) | bytes[offset + 4];

    const versionName = VERSION_NAMES[version];
    // Both checks matter: random encrypted bytes will occasionally look like a
    // plausible content type, but almost never alongside a real version and a
    // record length inside TLS's 2^14 + overhead ceiling.
    const isRecord =
      versionName !== undefined &&
      contentType >= CONTENT_TYPE_CHANGE_CIPHER_SPEC &&
      contentType <= CONTENT_TYPE_APPLICATION_DATA &&
      recordLength > 0 &&
      recordLength <= 0x4800;
    if (!isRecord) break;

    // Wireshark labels the frame with the *first* record's version.
    if (protocolLabel === null) protocolLabel = versionName;

    const recordBody = offset + 5;
    const recordEnd = Math.min(payloadEnd, recordBody + recordLength);

    if (contentType === CONTENT_TYPE_APPLICATION_DATA) {
      descriptions.push('Application Data');
    } else if (contentType === CONTENT_TYPE_CHANGE_CIPHER_SPEC) {
      descriptions.push('Change Cipher Spec');
    } else if (contentType === CONTENT_TYPE_ALERT) {
      // A 2-byte alert is plaintext; anything longer is the encrypted form.
      descriptions.push(recordLength === 2 ? 'Alert' : 'Encrypted Alert');
    } else if (contentType === CONTENT_TYPE_HANDSHAKE) {
      const handshakeType = recordBody < recordEnd ? bytes[recordBody] : -1;
      const name = HANDSHAKE_TYPE_NAMES[handshakeType];
      if (name === undefined) {
        // Post-ChangeCipherSpec handshake records are encrypted, so the first
        // byte is ciphertext rather than a handshake type.
        descriptions.push('Encrypted Handshake Message');
      } else if (handshakeType === 1) {
        const sni = extractSni(bytes, recordBody, recordEnd);
        descriptions.push(sni ? `Client Hello (SNI=${sni})` : 'Client Hello');
      } else {
        descriptions.push(name);
      }
    }

    offset = recordBody + recordLength;
  }

  if (protocolLabel === null || descriptions.length === 0) return null;

  return { protocolLabel, info: descriptions.join(', ') };
}
