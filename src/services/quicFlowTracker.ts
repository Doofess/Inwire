/**
 * Remembers which UDP flows have been observed carrying a QUIC long header,
 * and which connection IDs those headers named.
 *
 * This exists because a QUIC *short* header is nearly unidentifiable on its
 * own: it has no version field, and the destination connection ID that follows
 * the first byte has no length prefix - only the two endpoints know how long
 * it is. So a short-header packet can only be recognized as QUIC in the
 * context of a handshake seen earlier on the same flow, which is exactly what
 * Wireshark does. Without this, any UDP datagram on port 443 whose first byte
 * happens to have the right two bits set gets mislabeled QUIC - including the
 * datagrams that precede the handshake, which Wireshark reports as plain UDP.
 *
 * One instance represents one capture session; call reset() when the packet
 * buffer is cleared or a new file is imported.
 */
export class QuicFlowTracker {
  /** Connection IDs (hex) seen in long headers, keyed by normalized flow. */
  private flowConnectionIds = new Map<string, Set<string>>();

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

  public reset(): void {
    this.flowConnectionIds.clear();
  }
}
