/**
 * Facts about a flow that did not come off the wire.
 *
 * Everything else in this app is dissected from bytes - `nameResolution.ts` is
 * explicit that nothing is looked up - and that is the right default. This is
 * the exception, and the reason it is allowed: Inwire runs ON the machine it is
 * capturing. The operating system knows which process opened which socket, and
 * no observer anywhere else on the network can. That is not a fact the frame
 * failed to carry; it is a fact the frame never had.
 *
 * The shape here is deliberately general. Process attribution is the first
 * source, and a companion browser extension reporting request URLs would be the
 * second; both are the same thing - something that knows about a *flow*, keyed
 * by its endpoints, arriving *after* the frames it describes. Building two
 * bespoke paths for that would be the mistake.
 *
 * **Keyed by the LOCAL endpoint alone.** Not a choice: Windows reports no
 * remote address for UDP sockets, so a five-tuple key would attribute no QUIC
 * and no DNS - which is most of what a browser does. See
 * `local-agent/sockets.py`.
 *
 * Nothing here changes what a frame IS. `Packet.source` stays the address on
 * every path, the same rule passive name resolution follows, so filters,
 * exports and the tshark parity harness are untouched by any of it.
 */

/** The transports a socket table can name. */
export type FlowProto = 'tcp' | 'udp';

/** What the OS said about one process. */
export interface ProcessInfo {
  pid: number;
  name: string;
  /** Full path, or '' when the OS named the process but denied its path. */
  exe: string;
}

/**
 * One socket's life, as observed.
 *
 * `fromUs` is `-Infinity` for a socket that was already open when the app
 * subscribed: it existed, and how long it had existed is not knowable. That is
 * what lets the frames of a long-lived connection captured before subscription
 * still be attributed, rather than only those after it.
 *
 * `toUs` is `Infinity` while the socket is still open.
 */
interface SocketLife {
  process: ProcessInfo | null;
  fromUs: number;
  toUs: number;
}

/**
 * How far a boundary is widened, in microseconds.
 *
 * The table is read once a second, so a socket seen for the first time at T
 * may have opened at any point in the second before, and one first seen gone
 * at T was alive at some point in the second before that. Both edges are
 * uncertain by exactly one polling interval, and pretending otherwise would
 * drop the attribution for the frames at the very start and end of a
 * connection - which for a short connection is all of them.
 *
 * Widening both edges is also what can make two lives for a reused port
 * overlap, and `lookup` answers an overlap with nothing at all.
 */
const POLL_UNCERTAINTY_US = 1_000_000;

/** The addresses a socket binds to when it means "any of mine". */
const WILDCARD_ADDRESSES = ['0.0.0.0', '::'];

/**
 * How long a **closed** socket's life is kept after it closed.
 *
 * Every life ever observed used to be kept for the length of the capture, one
 * array per local endpoint, appended to on every reuse of the port - so an hour
 * of browsing, which is thousands of short-lived ports, grew this without any
 * bound (`scripts/perf/tracker-cost.ts`).
 *
 * A closed life can be dropped once no frame that could still be dissected
 * falls inside it. Dissection runs forwards, so that is a question about the
 * past: a life that closed two minutes ago cannot match a frame arriving now.
 * The window has to clear three things, and does so by two orders of magnitude
 * - the poll uncertainty either edge is widened by (1 s), the ordering window's
 * hold (100 ms), and `App.tsx`'s retro-annotation window for a delta (3 s).
 *
 * An **open** life is never swept however old it is: "still open" is not a
 * timestamp, and a connection can outlive any window - which is exactly the
 * long-lived socket whose attribution is most worth keeping.
 */
const CLOSED_LIFE_RETENTION_US = 120_000_000;

/**
 * How many lives one local endpoint keeps, newest last.
 *
 * A backstop for the sweep above rather than the main bound: a port cycled hard
 * enough to exceed this inside the retention window has produced more history
 * than any lookup can use, since two lives covering one instant already answer
 * with nothing.
 */
const MAX_LIVES_PER_ENDPOINT = 8;

function keyOf(proto: FlowProto, address: string, port: number): string {
  return `${proto}|${address}|${port}`;
}

/** True for an address that means "every local address", not one of them. */
export function isWildcardAddress(address: string): boolean {
  return WILDCARD_ADDRESSES.includes(address);
}

/**
 * The socket table as the app holds it, and what it can say about a frame.
 *
 * Held by the Worker, which is where dissection happens, and consulted while a
 * frame's summary is built.
 */
export class FlowAnnotationStore {
  /** Every observed life of every local endpoint, oldest first. */
  private lives = new Map<string, SocketLife[]>();

  /**
   * Concrete local addresses, learned from the table itself.
   *
   * This is what decides which END of a frame is the local one, and it has to
   * be decided rather than guessed at: a frame to a server on port 443 must
   * not match a local listener bound to `0.0.0.0:443` just because the numbers
   * agree. Learned from the table rather than configured because every key in
   * it is, by construction, a local address - so there is nothing to configure
   * and nothing to keep in step.
   */
  private localAddresses = new Set<string>();

  /**
   * Bumped on every change, so a consumer can tell "nothing new" from "nothing
   * known" without diffing. Mirrors `keyLog.generation`.
   */
  generation = 0;

  /** Forgets everything. Used when a capture is cleared or the link drops. */
  clear(): void {
    this.lives.clear();
    this.localAddresses.clear();
    this.generation += 1;
  }

  /**
   * Applies one `socket_table` message.
   *
   * `nowUs` is the app's clock in epoch microseconds. Comparing it against a
   * frame's `tsUs` - which comes from libpcap on the agent's side - is sound
   * only because the two are the same machine. Nothing here is applied to an
   * imported capture, which has no socket table and no shared clock.
   */
  apply(
    message: {
      full: boolean;
      procs: Record<string, { name: string; exe: string }>;
      add: [string, string, number, number][];
      gone: [string, string, number][];
    },
    nowUs: number,
  ): void {
    // A snapshot describes a table this store never saw being built, so
    // merging into what it holds would leave sockets that closed while it was
    // unsubscribed open for ever.
    if (message.full) {
      this.lives.clear();
      this.localAddresses.clear();
    }

    for (const [proto, address, port, pid] of message.add) {
      if (proto !== 'tcp' && proto !== 'udp') continue;
      const described = message.procs[String(pid)];
      const key = keyOf(proto, address, port);
      const history = this.lives.get(key) ?? [];

      // An addition for a key already open means the port was handed to a
      // different process without this store seeing the close - so the old
      // life ends where the new one starts, rather than both staying open and
      // every later frame being ambiguous.
      const open = history.find((life) => life.toUs === Infinity);
      if (open) open.toUs = nowUs;

      history.push({
        process: described && pid ? { pid, name: described.name, exe: described.exe } : null,
        // A socket in the opening snapshot has been open for an unknown time.
        fromUs: message.full ? -Infinity : nowUs,
        toUs: Infinity,
      });
      // Newest last, so the oldest are the ones dropped. Splicing from the
      // front rather than truncating keeps the still-open life, which is
      // always the last one pushed.
      if (history.length > MAX_LIVES_PER_ENDPOINT) {
        history.splice(0, history.length - MAX_LIVES_PER_ENDPOINT);
      }
      this.lives.set(key, history);
      if (!isWildcardAddress(address)) this.localAddresses.add(address);
    }

    for (const [proto, address, port] of message.gone) {
      if (proto !== 'tcp' && proto !== 'udp') continue;
      const history = this.lives.get(keyOf(proto, address, port));
      if (!history) continue;
      for (const life of history) if (life.toUs === Infinity) life.toUs = nowUs;
    }

    this.sweepClosed(nowUs);
    this.generation += 1;
  }

  /**
   * Forgets lives that closed long enough ago that no frame can still land in
   * them, and endpoints left with no lives at all.
   *
   * Driven from `apply` rather than from a timer: the store only changes when
   * a table arrives, so that is the only moment there is anything new to
   * forget, and a timer would be a second thing to tear down when a capture
   * ends.
   */
  private sweepClosed(nowUs: number): void {
    const horizon = nowUs - CLOSED_LIFE_RETENTION_US;
    for (const [key, history] of this.lives) {
      // An open life has `toUs === Infinity`, which fails this test for every
      // horizon - so "still open" survives however long it has been open.
      if (!history.some((life) => life.toUs < horizon)) continue;
      const kept = history.filter((life) => life.toUs >= horizon);
      if (kept.length === 0) this.lives.delete(key);
      else this.lives.set(key, kept);
    }
  }

  /** True once anything is known, so a caller can skip the work entirely. */
  get isEmpty(): boolean {
    return this.lives.size === 0;
  }

  /** Whether this address belongs to the machine the capture was taken on. */
  isLocalAddress(address: string): boolean {
    return this.localAddresses.has(address);
  }

  /**
   * The process behind a local endpoint at a moment, or null.
   *
   * Null covers three different situations on purpose - the endpoint was never
   * seen, it was seen but the OS would not name its owner, and two lives of a
   * reused port both cover this instant. All three mean the same thing to a
   * caller, and all three must render as nothing rather than as a guess. An
   * unknown is not a zero, and a plausible wrong process name is worse than a
   * blank column.
   */
  lookup(proto: FlowProto, address: string, port: number, tsUs: number): ProcessInfo | null {
    // Exact bind first, then the wildcard the OS itself would fall back to. A
    // socket bound to `0.0.0.0:62664` serves traffic on every address, and on
    // this machine 34 of 59 UDP sockets were bound that way - including
    // Chrome's QUIC sockets, which is most of the traffic worth attributing.
    const candidates = [keyOf(proto, address, port)];
    for (const wildcard of WILDCARD_ADDRESSES) candidates.push(keyOf(proto, wildcard, port));

    for (const key of candidates) {
      const history = this.lives.get(key);
      if (!history) continue;
      const matches = history.filter(
        (life) => tsUs >= life.fromUs - POLL_UNCERTAINTY_US
          && tsUs <= life.toUs + POLL_UNCERTAINTY_US,
      );
      // Exactly one, or nothing. Two lives covering one instant is a port
      // reused inside the uncertainty window, and there is no way to tell
      // which of them sent the frame.
      if (matches.length === 1) return matches[0].process;
      if (matches.length > 1) return null;
    }
    return null;
  }

  /**
   * The process behind a frame, given both of its endpoints.
   *
   * Which end is local is decided by the address, never by the port: matching
   * on port alone would attribute a frame sent TO a server on 443 to whatever
   * local process happens to listen on 443.
   */
  forEndpoints(
    proto: FlowProto,
    sourceAddress: string,
    sourcePort: number,
    destAddress: string,
    destPort: number,
    tsUs: number,
  ): ProcessInfo | null {
    if (this.isLocalAddress(sourceAddress)) {
      return this.lookup(proto, sourceAddress, sourcePort, tsUs);
    }
    if (this.isLocalAddress(destAddress)) {
      return this.lookup(proto, destAddress, destPort, tsUs);
    }
    // Neither end is this machine - traffic from a mirror port or a hub, which
    // no socket table can describe.
    return null;
  }
}

/**
 * The one store the dissection path reads.
 *
 * A module singleton for the same reason `keyLog` is one: the Worker dissects
 * live capture with its own module instance and the main thread dissects
 * imports, and each wants the store its own side has been given.
 */
export const flowAnnotations = new FlowAnnotationStore();
