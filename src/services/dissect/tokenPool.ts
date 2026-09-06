import type { ExpertInfo } from '../../types/packet';

/**
 * One array per distinct list, shared by every frame carrying it.
 *
 * `Packet.frameProtocols`, `Packet.analysisFlags` and `Packet.expert` are all
 * short lists built fresh for every frame, and all three have very few distinct
 * values. Measured over both fixtures' 27,640 frames: **21 distinct protocol
 * chains, 13 distinct flag sets, and 209 distinct expert sets** - so the buffer
 * held tens of thousands of arrays where a couple of hundred would do, at
 * 115 B, 25 B and 102 B a frame (`scripts/perf/record-cost.ts`).
 *
 * This is the same trick as the address pool in `services/addressFormat.ts`,
 * and it is here rather than there because these are lists rather than strings
 * and the key has to be built from their contents.
 *
 * **It is deliberately not the bitmask the plan asked for.** A bitmask is
 * smaller still, and it cannot be used: the protocol hierarchy reads
 * `frameProtocols` **in nesting order**, since a token's position is what makes
 * it a child of the layer before it (`services/statistics.ts`, and the note in
 * CLAUDE.md about `quic` coming to sit under the TLS it carries). A set of bits
 * has no order. Pooling keeps each array exactly as it was - same contents,
 * same order, same type - so nothing downstream changes at all, which is also
 * why it needs no decode step on the read side.
 *
 * **The pooled arrays are frozen.** They are shared by thousands of frames, so
 * a consumer that sorted or pushed to one would change what every other frame
 * reports. Nothing does today - every reader calls `includes`, `join` or `map` -
 * and freezing is what keeps that true: the mistake becomes a throw rather than
 * a capture that quietly disagrees with itself.
 */

/**
 * Bounded, for the same reason the address pool is: a capture with custom
 * dissectors can legitimately produce many distinct chains, and an unbounded
 * pool would be the leak it exists to prevent. Past the cap it stops admitting
 * new lists rather than evicting - the entries already in it are the ones being
 * asked for repeatedly - and the caller simply gets its own array back.
 */
const MAX_POOLED = 4096;

/**
 * Separates list entries within a key, and the parts of one finding within an
 * entry.
 *
 * U+0001 and U+0002: characters no protocol token and no dissector's message
 * can contain, so `['a', 'b']` and `['a:b']` cannot produce the same key -
 * which `join(':')` would allow, and `frameProtocols` really is joined with `:`
 * elsewhere.
 *
 * Spelled with `fromCharCode` rather than as an escape because an escape for an
 * unprintable character is worth exactly one typo, and the wrong separator here
 * is a silent collision between two different lists rather than an error.
 */
const SEPARATOR = String.fromCharCode(1);
const SUBSEP = String.fromCharCode(2);

const tokenLists = new Map<string, readonly string[]>();
const expertLists = new Map<string, readonly ExpertInfo[]>();

/**
 * The shared array equal to `tokens`, admitting it to the pool on first sight.
 *
 * Returns the caller's own array unchanged once the pool is full, so a
 * pathological capture degrades to today's behaviour rather than to a wrong
 * answer.
 */
export function poolTokens(tokens: string[]): string[] {
  const key = tokens.join(SEPARATOR);
  const existing = tokenLists.get(key);
  if (existing !== undefined) return existing as string[];
  if (tokenLists.size >= MAX_POOLED) return tokens;
  const frozen = Object.freeze(tokens);
  tokenLists.set(key, frozen);
  return frozen as string[];
}

/**
 * The shared list of expert findings equal to `entries`.
 *
 * The same idea one level deeper: an `ExpertInfo` is `{message, category?}`,
 * and a finding is a fixed sentence a dissector emits - so a capture
 * raising "TCP Retransmission" seven hundred times built seven hundred
 * identical objects inside seven hundred identical arrays.
 *
 * Sharing the array shares the entries inside it, which is the point, and is
 * safe for the same reason as above: every reader only reads. The array is
 * frozen; the entries are not, because freezing each one would cost per finding
 * rather than per distinct set, and the array is the shared thing.
 */
export function poolExpert(entries: ExpertInfo[]): ExpertInfo[] {
  // Built by hand rather than with `JSON.stringify`: this runs for every frame
  // that carries a finding, and stringifying on the way to a map key is the
  // kind of cost that does not show up until it is a third of a profile.
  let key = '';
  for (const entry of entries) {
    key += SEPARATOR + (entry.category ?? '') + SUBSEP + entry.message;
  }
  const existing = expertLists.get(key);
  if (existing !== undefined) return existing as ExpertInfo[];
  if (expertLists.size >= MAX_POOLED) return entries;
  const frozen = Object.freeze(entries);
  expertLists.set(key, frozen);
  return frozen as ExpertInfo[];
}

/** Forgets every pooled list. For a capture ending, and for tests. */
export function clearTokenPool(): void {
  tokenLists.clear();
  expertLists.clear();
}

/** How many distinct lists are held, by kind. For the measurement scripts. */
export function pooledListCounts(): { tokens: number; expert: number } {
  return { tokens: tokenLists.size, expert: expertLists.size };
}
