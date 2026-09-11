/**
 * Which frames a filter matched, as a bitmap with rank/select.
 *
 * ## Why the result cannot be an array of frames
 *
 * `FilterEngine.filterPackets` returns `Packet[]`, which is right while the
 * whole capture is in RAM and structurally impossible once it is not: a filter
 * over 47M frames can match 47M frames. Even a list of ordinals is 4 bytes each
 * - 188 MB for a filter as ordinary as `tcp`, allocated on the main thread
 * every time someone types.
 *
 * A bitmap is **one bit per frame whatever the filter matches**: 5.9 MB for
 * 47M frames, and 590 kB at the 5 GB target. It is also the shape the live path
 * already wants, because a newly sealed chunk's bits can be appended as the
 * capture runs rather than the whole capture being re-filtered.
 *
 * ## Rank/select, and why prefix sums are not an optimisation
 *
 * The packet list is virtualised: it asks for "filtered rows 12,000 to 12,050",
 * which means "the 12,000th set bit". Answering that by walking the bitmap is
 * O(frames) **per scroll event** - at 47M frames, a full walk every time the
 * wheel moves.
 *
 * So a running count per chunk is kept alongside. `ordinalAt(k)` binary-searches
 * those counts to find the chunk holding the k-th match, then pops through at
 * most one chunk's 4,096 bits. 11,500 counts is 46 kB and turns a scroll from
 * O(frames) into O(log chunks).
 *
 * The counts are only valid once every chunk is present, which is what `seal()`
 * marks. A `MatchSet` still being filled answers `count()` but refuses
 * `ordinalAt`, because a half-built prefix sum gives a confidently wrong row
 * rather than an error.
 */

/** Frames per chunk of the bitmap. Matches `chunkCodec.CHUNK_FRAMES`. */
const BITS_PER_CHUNK = 4096;
const WORDS_PER_CHUNK = BITS_PER_CHUNK / 32;

/** Population count of a 32-bit word - the SWAR trick, no lookup table. */
function popcount(v: number): number {
  v = v - ((v >>> 1) & 0x55555555);
  v = (v & 0x33333333) + ((v >>> 2) & 0x33333333);
  v = (v + (v >>> 4)) & 0x0f0f0f0f;
  return (v * 0x01010101) >>> 24;
}

export class MatchSet {
  private readonly words: Uint32Array;
  /**
   * Matches in chunks `[0, i)`, so `counts[i]` is where chunk `i` starts in
   * filtered-row space and `counts[chunkCount]` is the total.
   */
  private readonly counts: Uint32Array;
  private sealed = false;

  readonly frameCount: number;
  readonly chunkCount: number;

  constructor(frameCount: number) {
    if (frameCount < 0) throw new RangeError(`frameCount ${frameCount} is negative`);
    this.frameCount = frameCount;
    this.chunkCount = Math.ceil(frameCount / BITS_PER_CHUNK);
    this.words = new Uint32Array(this.chunkCount * WORDS_PER_CHUNK);
    this.counts = new Uint32Array(this.chunkCount + 1);
  }

  /** Marks the frame at `ordinal` as matching. */
  set(ordinal: number): void {
    if (ordinal < 0 || ordinal >= this.frameCount) {
      throw new RangeError(`ordinal ${ordinal} outside 0..${this.frameCount - 1}`);
    }
    if (this.sealed) throw new Error('MatchSet: set() after seal()');
    this.words[ordinal >>> 5] |= 1 << (ordinal & 31);
  }

  has(ordinal: number): boolean {
    if (ordinal < 0 || ordinal >= this.frameCount) return false;
    return (this.words[ordinal >>> 5] & (1 << (ordinal & 31))) !== 0;
  }

  /**
   * Takes one chunk's bits wholesale, which is how the scan fills this.
   *
   * The scan decodes a chunk's prefix block, evaluates the matcher over it and
   * hands back 4,096 bits; copying them in is one `set` per word rather than
   * one per matching frame.
   */
  setChunk(chunk: number, bits: Uint32Array): void {
    if (this.sealed) throw new Error('MatchSet: setChunk() after seal()');
    if (chunk < 0 || chunk >= this.chunkCount) throw new RangeError(`chunk ${chunk} out of range`);
    if (bits.length !== WORDS_PER_CHUNK) {
      throw new RangeError(`chunk bits must be ${WORDS_PER_CHUNK} words, got ${bits.length}`);
    }
    this.words.set(bits, chunk * WORDS_PER_CHUNK);
    // The last chunk is usually short, and a matcher handed a full word of
    // padding could set bits past the end of the capture. Clearing them here
    // rather than trusting the caller keeps `count()` honest.
    if (chunk === this.chunkCount - 1) this.clearTail();
  }

  private clearTail(): void {
    const used = this.frameCount - (this.chunkCount - 1) * BITS_PER_CHUNK;
    if (used >= BITS_PER_CHUNK) return;
    const base = (this.chunkCount - 1) * WORDS_PER_CHUNK;
    const wholeWords = used >>> 5;
    const spare = used & 31;
    if (spare !== 0) this.words[base + wholeWords] &= (1 << spare) - 1;
    this.words.fill(0, base + wholeWords + (spare === 0 ? 0 : 1), base + WORDS_PER_CHUNK);
  }

  /**
   * Computes the running counts. Nothing may be set afterwards.
   *
   * Separate from filling on purpose: a prefix sum that is rebuilt on every
   * `set` is O(chunks) per matching frame, and one that is merely stale is a
   * scroll landing on the wrong row with no error anywhere.
   */
  seal(): this {
    if (this.chunkCount > 0) this.clearTail();
    let running = 0;
    for (let c = 0; c < this.chunkCount; c++) {
      this.counts[c] = running;
      const base = c * WORDS_PER_CHUNK;
      for (let w = 0; w < WORDS_PER_CHUNK; w++) running += popcount(this.words[base + w]);
    }
    this.counts[this.chunkCount] = running;
    this.sealed = true;
    return this;
  }

  get isSealed(): boolean { return this.sealed; }

  /** How many frames matched. This is the virtualised list's row count. */
  count(): number {
    if (this.sealed) return this.counts[this.chunkCount];
    let total = 0;
    for (let i = 0; i < this.words.length; i++) total += popcount(this.words[i]);
    return total;
  }

  /**
   * The capture ordinal of the `k`-th match, or -1.
   *
   * This is what the packet list calls: the row it wants to draw is a position
   * in the filtered view, and this turns it into a position in the capture.
   */
  ordinalAt(k: number): number {
    if (!this.sealed) throw new Error('MatchSet: ordinalAt() before seal()');
    if (k < 0 || k >= this.counts[this.chunkCount]) return -1;

    // Which chunk holds it: the last one whose running count is <= k.
    let lo = 0, hi = this.chunkCount - 1, chunk = 0;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (this.counts[mid] <= k) { chunk = mid; lo = mid + 1; } else hi = mid - 1;
    }

    let remaining = k - this.counts[chunk];
    const base = chunk * WORDS_PER_CHUNK;
    for (let w = 0; w < WORDS_PER_CHUNK; w++) {
      const word = this.words[base + w];
      if (word === 0) continue;
      const bits = popcount(word);
      if (remaining >= bits) { remaining -= bits; continue; }
      for (let b = 0; b < 32; b++) {
        if ((word & (1 << b)) === 0) continue;
        if (remaining === 0) return chunk * BITS_PER_CHUNK + w * 32 + b;
        remaining -= 1;
      }
    }
    return -1;
  }

  /**
   * How many matches precede `ordinal` - the inverse, for keeping the selected
   * frame in view when a filter is applied.
   */
  rank(ordinal: number): number {
    if (!this.sealed) throw new Error('MatchSet: rank() before seal()');
    if (ordinal <= 0) return 0;
    const stop = Math.min(ordinal, this.frameCount);
    const chunk = Math.min(this.chunkCount - 1, Math.floor(stop / BITS_PER_CHUNK));
    let total = this.counts[chunk];
    const base = chunk * WORDS_PER_CHUNK;
    const within = stop - chunk * BITS_PER_CHUNK;
    const wholeWords = within >>> 5;
    for (let w = 0; w < wholeWords; w++) total += popcount(this.words[base + w]);
    const spare = within & 31;
    if (spare !== 0) total += popcount(this.words[base + wholeWords] & ((1 << spare) - 1));
    return total;
  }

  /** The raw bits, for persisting a filter result beside the capture. */
  toBytes(): Uint8Array {
    return new Uint8Array(this.words.buffer.slice(0), 0, this.words.byteLength);
  }

  static fromBytes(frameCount: number, bytes: Uint8Array): MatchSet {
    const set = new MatchSet(frameCount);
    if (bytes.byteLength !== set.words.byteLength) {
      throw new RangeError(
        `MatchSet.fromBytes: ${bytes.byteLength} bytes for ${frameCount} frames, expected ${set.words.byteLength}`,
      );
    }
    new Uint8Array(set.words.buffer).set(bytes);
    return set.seal();
  }
}

export const MATCH_SET_BITS_PER_CHUNK = BITS_PER_CHUNK;
