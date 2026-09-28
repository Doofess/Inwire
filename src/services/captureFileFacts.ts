/**
 * What a capture file says about how it was captured (ADR 0052).
 *
 * A pcapng file carries more than its frames: each Interface Description
 * Block names the adapter and says the capture filter and snaplen it was
 * taken with, and each Interface Statistics Block counts what the driver
 * received and dropped. dumpcap writes all of them, and so does the agent. An
 * import used to read an IDB's link type and timestamp resolution and walk
 * past everything else, so a file that said "captured with `tcp port 443`,
 * 1,204 dropped" imported as a capture that said nothing - and exported again
 * as one that never had.
 *
 * This is the vocabulary; `pcapParser.ts` collects it on the walk it already
 * makes over every block, and the import's source carries it into the
 * metadata and back out into an exported pcapng's IDB and ISB.
 */

/** One interface as its IDB and its last ISB describe it. */
export interface FileInterfaceFacts {
  linkType: number;
  /** `if_name`, or null when the file does not say. */
  name: string | null;
  /** `if_description`. */
  description: string | null;
  /** `if_filter`'s libpcap expression, or null for none. */
  filter: string | null;
  /** The IDB's snaplen, or null for whole frames - 0, or the most any capture keeps. */
  snaplen: number | null;
  /** `isb_ifrecv` from the interface's last ISB; null when no ISB said. */
  received: number | null;
  /** `isb_ifdrop`, the same way. */
  dropped: number | null;
}

export interface CaptureFileFacts {
  /** `shb_userappl`: what wrote the file. Null for classic pcap, or when absent. */
  application: string | null;
  interfaces: FileInterfaceFacts[];
}

/**
 * A snaplen that keeps every frame whole: 0 ("no limit" in pcapng) or at least
 * dumpcap's and the agent's maximum, 262,144 (ADR 0052).
 */
export function snaplenOrWhole(snaplen: number): number | null {
  return snaplen === 0 || snaplen >= 262_144 ? null : snaplen;
}

/**
 * What a file says of the capture as a whole: the filter and snaplen when
 * every interface agrees, and the counts summed when every interface gave
 * them. `undefined` is "the interfaces disagree, or the file does not say" -
 * never a value it did not state.
 */
export function wholeCaptureFacts(facts: CaptureFileFacts): {
  filter: string | null | undefined;
  snaplen: number | null | undefined;
  received: number | null;
  dropped: number | null;
} {
  const all = facts.interfaces;
  const agreed = <T>(pick: (f: FileInterfaceFacts) => T): T | undefined =>
    all.length > 0 && all.every((f) => pick(f) === pick(all[0])) ? pick(all[0]) : undefined;
  const summed = (pick: (f: FileInterfaceFacts) => number | null): number | null =>
    all.length > 0 && all.every((f) => pick(f) !== null) ? all.reduce((sum, f) => sum + (pick(f) ?? 0), 0) : null;
  return {
    filter: agreed((f) => f.filter),
    snaplen: agreed((f) => f.snaplen),
    received: summed((f) => f.received),
    dropped: summed((f) => f.dropped),
  };
}
