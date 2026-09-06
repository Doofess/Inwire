/**
 * Packet numbers, and nothing else.
 *
 * It used to hold a `CustomDissectorEngine` too - taken in the constructor,
 * replaced by `setDissectorEngine` - and **never read it**. Nothing in this
 * class consulted the engine, so the field was a reference kept alive for no
 * reader. See `App.handleUpdateDissectors` for the gap that leaves.
 */
export class PacketGenerator {
  private packetIdCounter = 1;

  public reset(): void {
    this.packetIdCounter = 1;
  }

  public getNextId(): number {
    return this.packetIdCounter++;
  }

  /**
   * Continues numbering after a restored session.
   *
   * Packet numbers are the buffer's identity - React keys off them, the
   * details tree cross-references frames by them, and the ICMP "reply in N"
   * text points at them - so a restored capture must carry on from where it
   * left off rather than restarting at 1 and colliding with everything
   * already in the list.
   */
  public resumeAfter(lastId: number): void {
    this.packetIdCounter = Math.max(this.packetIdCounter, Math.floor(lastId) + 1);
  }
}
