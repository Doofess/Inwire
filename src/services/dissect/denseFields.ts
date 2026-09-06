import type { DenseKey } from './fieldBlock';

/**
 * The fields most frames carry, which are therefore worth a column.
 *
 * Measured over both fixtures' 27,640 frames: 123 distinct keys, 24.7 entries a
 * frame, and these hold 85.4% of them (`scripts/perf/fields-split-cost.ts`,
 * `docs/decisions/0017`).
 *
 * **Declared rather than learned from the capture**, for two reasons that both
 * bite. A set that changed as frames arrived would have to migrate a column
 * mid-capture; and a key written AFTER dissection cannot live in a column at
 * all, so which keys are dense has to be knowable before any frame arrives.
 * `scripts/dissect/dense-fields.ts` holds this list to both.
 *
 * Being wrong is cheap in one direction and not the other. A declared key that
 * turns out sparse costs one presence bit and an unused column slot; a dense
 * key left undeclared costs about 58 B a frame. The asymmetry says to declare
 * generously - which is why the IPv4 entries are here even though both fixtures
 * are IPv6-heavy and neither reached the threshold.
 *
 * **The widths are each field's size in its protocol, not the largest value the
 * fixtures happened to hold.** Two of them differ from what the captures
 * suggested and both would have been silent truncation on traffic nobody tested
 * with: `tcp.flags` measured a maximum of 25, which fits a `u8`, but the field
 * is 12 bits and a frame carrying ECN exceeds it; `tcp.len` measured 63,888,
 * just under a `u16`, but segment offload routinely presents segments past
 * 64 KB. Where a field is computed rather than read off the wire and no
 * protocol bounds it, the column widens at runtime instead (`fieldBlock.ts`).
 */
export const DENSE_FIELDS: readonly DenseKey[] = [
  // Ethernet: on every frame.
  { abbrev: 'eth.src', width: 'str' },
  { abbrev: 'eth.dst', width: 'str' },
  { abbrev: 'eth.ig', width: 'u8' },
  { abbrev: 'eth.type', width: 'u16' },

  // IPv4. Sparse in both fixtures, which are IPv6-heavy; dense on most networks.
  { abbrev: 'ip.src', width: 'str' },
  { abbrev: 'ip.dst', width: 'str' },
  { abbrev: 'ip.ttl', width: 'u8' },
  { abbrev: 'ip.proto', width: 'u8' },
  { abbrev: 'ip.checksum', width: 'u16' },
  { abbrev: 'ip.checksum.status', width: 'str' },

  { abbrev: 'ipv6.src', width: 'str' },
  { abbrev: 'ipv6.dst', width: 'str' },
  { abbrev: 'ipv6.hlim', width: 'u8' },
  { abbrev: 'ipv6.nxt', width: 'u8' },

  { abbrev: 'tcp.srcport', width: 'u16' },
  { abbrev: 'tcp.dstport', width: 'u16' },
  // 12 bits with the reserved and NS bits, not the 5 the fixtures used.
  { abbrev: 'tcp.flags', width: 'u16' },
  { abbrev: 'tcp.flags.syn', width: 'u8' },
  { abbrev: 'tcp.flags.fin', width: 'u8' },
  { abbrev: 'tcp.flags.reset', width: 'u8' },
  { abbrev: 'tcp.flags.push', width: 'u8' },
  { abbrev: 'tcp.flags.ack', width: 'u8' },
  // Segment offload hands the capture segments past 64 KB; the fixtures'
  // largest was 63,888, which is exactly the sort of near miss that ships.
  { abbrev: 'tcp.len', width: 'u32' },
  { abbrev: 'tcp.checksum', width: 'u16' },
  { abbrev: 'tcp.checksum.status', width: 'str' },
  // A scaled window exceeds 16 bits; the fixtures reached 8,388,352.
  { abbrev: 'tcp.window_size', width: 'u32' },
  { abbrev: 'tcp.seq', width: 'u32' },
  { abbrev: 'tcp.seq_raw', width: 'u32' },
  { abbrev: 'tcp.ack', width: 'u32' },
  { abbrev: 'tcp.ack_raw', width: 'u32' },
  { abbrev: 'tcp.analysis.bytes_in_flight', width: 'u32' },
  { abbrev: 'tcp.analysis.ack_rtt', width: 'f64' },

  // Published per frame so a colour rule and a display filter can ask about
  // severity without walking a tree; see `services/expertInfo.ts`.
  { abbrev: 'inwire.expert.category', width: 'str' },
];

/**
 * Keys written into `Packet.fields` after the frame was dissected, and
 * therefore after its row was filled.
 *
 * `processFields.writeProcessFields` publishes the owning process when a socket
 * table arrives, which can be seconds later and can retro-patch frames already
 * in the buffer; `clientFingerprints` labels a JA4 once it has learned which
 * program owns it. Neither can go in a column - a row is written once, as the
 * frame joins the buffer.
 *
 * **None of these may appear in `DENSE_FIELDS`.** They stay in the bag, which
 * remains an ordinary mutable object, and the assertion script enforces the
 * separation rather than leaving it to whoever adds the next annotator.
 */
export const POST_DISSECTION_KEYS: readonly string[] = [
  'inwire.process.name',
  'inwire.process.pid',
  'inwire.process.path',
  'inwire.process.ja4_match',
];
