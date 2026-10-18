/**
 * An admission budget over a count and a byte total (ADR 0058's limits table).
 *
 * The utility's inbox is 1,024 datagrams or 8 MiB, whichever comes first, and
 * the live credit to the Worker is a batch of at most 64 datagrams or 256 KiB.
 * Both are the same question - may one more item join what is already held? -
 * so both use this. A refusal is the caller's to count: this class only says
 * no, it never drops anything itself.
 *
 * **An item larger than the byte limit may go alone.** ADR 0058 says a
 * maximum-size datagram may be sent by itself, and a batch limit smaller than
 * one datagram must not make that datagram unsendable for ever - it would
 * block the queue behind it. So an empty budget admits any one item, and
 * nothing joins it until it is released.
 */
export class ByteBudget {
  private heldItems = 0;
  private heldBytes = 0;

  constructor(private readonly maxItems: number, private readonly maxBytes: number) {}

  /** How many items are held. */
  get items(): number { return this.heldItems; }

  /** How many bytes are held. */
  get bytes(): number { return this.heldBytes; }

  /** True and counted if `bytes` may join; false and unchanged if not. */
  admit(bytes: number): boolean {
    if (!Number.isSafeInteger(bytes) || bytes < 0) return false;
    if (this.heldItems === 0) {
      if (this.maxItems < 1) return false;
    } else if (this.heldItems + 1 > this.maxItems || this.heldBytes + bytes > this.maxBytes) {
      return false;
    }
    this.heldItems++;
    this.heldBytes += bytes;
    return true;
  }

  /**
   * Gives back one admitted item. Releasing what was never admitted would
   * leave the budget wider than its limit, and that is a bug in the caller to
   * find, not a case to absorb.
   */
  release(bytes: number): void {
    if (this.heldItems < 1 || !Number.isSafeInteger(bytes) || bytes < 0 || bytes > this.heldBytes) {
      throw new RangeError(`release of ${bytes} bytes, but the budget holds ${this.heldItems} items and ${this.heldBytes} bytes`);
    }
    this.heldItems--;
    this.heldBytes -= bytes;
  }
}
