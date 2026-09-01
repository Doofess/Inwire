/**
 * Remembers which UDP flows have been observed carrying a QUIC long header,
 * and which connection IDs those headers named.
 *
 * This exists because a QUIC *short* header is nearly unidentifiable on its
 * own: it has no version field, and the destination connection ID that follows
 * the first byte has no length prefix - only the two endpoints know how long
 * it is. So a short-header packet can only be recognized as QUIC in the
 * context of a handshake seen earlier on the same flow, which is exactly what
 * The reference analyzer does. Without this, any UDP datagram on port 443 whose first byte
 * happens to have the right two bits set gets mislabeled QUIC - including the
 * datagrams that precede the handshake, which the reference analyzer reports as plain UDP.
 *
 * One instance represents one capture session; call reset() when the packet
 * buffer is cleared or a new file is imported.
 */
import { deriveInitialKeys, saltForVersion, decryptInitialPacket, QUIC_VERSION_2, InitialKeys } from './dissectors/quicCrypto';
import type { InitialDecryptor } from './dissectors/quic';

interface InitialSession {
  keys: InitialKeys;
  /** "ip:port" of whichever endpoint sent the connection's first Initial. */
  clientEndpoint: string;
}

export class QuicFlowTracker {
  /** Connection IDs (hex) seen in long headers, keyed by normalized flow. */
  private flowConnectionIds = new Map<string, Set<string>>();
  /** Initial keys and client identity, keyed by normalized flow. */
  private initialSessions = new Map<string, InitialSession>();
  /** Highest packet number decrypted per sending direction. */
  private largestPacketNumber = new Map<string, number>();

  /** Order-independent key, so both directions of a flow share their state. */
  private flowKey(srcIp: string, srcPort: number, dstIp: string, dstPort: number): string {
    const a = `${srcIp}:${srcPort}`;
    const b = `${dstIp}:${dstPort}`;
    return a <= b ? `${a}|${b}` : `${b}|${a}`;
  }

  /**
   * Records that this flow carried a long header, along with any non-empty
   * connection IDs it advertised. Registering the flow at all is what makes
   * subsequent short-header packets recognizable.
   */
  public noteLongHeader(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    connectionIds: string[]
  ): void {
    const key = this.flowKey(srcIp, srcPort, dstIp, dstPort);
    let ids = this.flowConnectionIds.get(key);
    if (!ids) {
      ids = new Set<string>();
      this.flowConnectionIds.set(key, ids);
    }
    for (const id of connectionIds) {
      if (id.length > 0) ids.add(id);
    }
  }

  public isKnownFlow(srcIp: string, srcPort: number, dstIp: string, dstPort: number): boolean {
    return this.flowConnectionIds.has(this.flowKey(srcIp, srcPort, dstIp, dstPort));
  }

  /**
   * Returns the connection ID a short header carries, if the bytes right after
   * its first byte match one this flow has already advertised. A zero-length
   * connection ID - which one peer commonly chooses - matches nothing and
   * correctly yields undefined, so the Info column simply omits it.
   */
  public matchConnectionId(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    bytes: Uint8Array, offset: number
  ): string | undefined {
    const ids = this.flowConnectionIds.get(this.flowKey(srcIp, srcPort, dstIp, dstPort));
    if (!ids) return undefined;

    for (const id of ids) {
      const byteLength = id.length / 2;
      if (offset + byteLength > bytes.length) continue;
      let matches = true;
      for (let i = 0; i < byteLength; i++) {
        if (bytes[offset + i] !== parseInt(id.slice(i * 2, i * 2 + 2), 16)) {
          matches = false;
          break;
        }
      }
      if (matches) return id;
    }
    return undefined;
  }

  /**
   * Builds a decryptor bound to one direction of one flow.
   *
   * All the per-connection state Initial decryption needs lives here rather
   * than in the dissector: which endpoint is the client (the one that sent the
   * first Initial), the original Destination Connection ID the keys derive
   * from, and the largest packet number seen per direction, which is what
   * resolves a truncated packet number back to its full value.
   */
  public createInitialDecryptor(
    srcIp: string, srcPort: number, dstIp: string, dstPort: number,
    bytes: Uint8Array
  ): InitialDecryptor {
    const flowKey = this.flowKey(srcIp, srcPort, dstIp, dstPort);
    const senderKey = `${flowKey}>${srcIp}:${srcPort}`;

    return (packetStart, packetNumberOffset, packetEnd, version, destinationConnectionId) => {
      const salt = saltForVersion(version);
      if (!salt) return null;

      let session = this.initialSessions.get(flowKey);
      if (!session) {
        // The first Initial on a flow is the client's, and its Destination
        // Connection ID is the one RFC 9001 derives both directions' keys
        // from - including for every later Initial, whose DCID will have
        // changed to the server's chosen value.
        if (destinationConnectionId.length === 0) return null;
        session = {
          keys: deriveInitialKeys(destinationConnectionId, salt, version === QUIC_VERSION_2),
          clientEndpoint: `${srcIp}:${srcPort}`,
        };
        this.initialSessions.set(flowKey, session);
      }

      const isFromClient = session.clientEndpoint === `${srcIp}:${srcPort}`;
      const keys = isFromClient ? session.keys.client : session.keys.server;
      const largest = this.largestPacketNumber.get(senderKey) ?? -1;

      const decrypted = decryptInitialPacket(bytes, packetStart, packetNumberOffset, packetEnd, keys, largest);
      if (!decrypted) return null;

      if (decrypted.packetNumber > largest) {
        this.largestPacketNumber.set(senderKey, decrypted.packetNumber);
      }
      return decrypted;
    };
  }

  public reset(): void {
    this.flowConnectionIds.clear();
    this.initialSessions.clear();
    this.largestPacketNumber.clear();
  }
}
