/**
 * Rebuilding the protocol tree of a frame nobody kept.
 *
 * A frame's tree is not a function of its own bytes. The TLS record cursor,
 * the QUIC keys, the DNS and ICMP pairings and the TCP relative sequence
 * numbers are all state the frames before it built up, and dissecting a
 * mid-conversation segment on its own produces a tree that is confidently
 * wrong - absolute sequence numbers presented as relative ones, encrypted
 * payload shown as unparsed bytes, a ServerHello with no ClientHello to have
 * negotiated anything with.
 *
 * So the tree is rebuilt the way Wireshark rebuilds it: by dissecting the
 * conversation again from the start, through fresh trackers, and keeping the
 * tree of the frame that was asked about. Which frames make up "the
 * conversation" is `services/followStream.ts`'s five-tuple - the same
 * definition Follow Stream uses, which is bounded by the buffer and is usually
 * a few hundred frames.
 *
 * Deliberately free of React and the DOM (docs/decisions/0003): this runs in
 * the pipeline Worker.
 */
import { applyInfoPatch, decodeRawEthernetPacket, type InfoPatch } from '../pcapParser';
import type { HostIdentity } from '../direction';
import { fieldValue } from '../dissect/fieldAccess';
import { TcpStreamTracker } from '../tcpStreamTracker';
import { IcmpEchoTracker } from '../icmpEchoTracker';
import { QuicFlowTracker } from '../quicFlowTracker';
import { DnsTracker } from '../dnsTracker';
import { L3Tracker } from '../l3Tracker';
import type { Packet, ProtocolLayer } from '../../types/packet';
import type { ReplayFrame } from './protocol';

/**
 * How many frames a replay will dissect.
 *
 * A single stream can be most of a large buffer - the `inwire` fixture has one
 * of 3,395 frames and a 100,000-frame capture of a download is one stream
 * almost end to end. The cap turns the pathological case into a slightly
 * incomplete tree rather than a click that hangs; at ~180us a frame this is
 * about three and a half seconds of Worker time, spent off the main thread.
 */
export const MAX_REPLAY_FRAMES = 20000;

export interface ReplayResult {
  layers: ProtocolLayer[];
  /**
   * The replay did not start at the conversation's first frame, either because
   * it was capped or because the earlier frames have been trimmed out of the
   * buffer. The tree gets a row saying so: a reader has to know that what it
   * says about reassembly and sequence numbers is relative to where the replay
   * could start, not to where the conversation did.
   */
  truncated: boolean;
}

/**
 * Dissects `frames` in order through fresh trackers and returns the tree of
 * the last one. The caller supplies the frames; this decides nothing about
 * which they are.
 */
/** The conversation indices a replay has to be told, one per layer that has one. */
export interface StreamSeeds {
  eth?: number;
  ip?: number;
  ipv6?: number;
  udp?: number;
  tls?: number;
  /**
   * The QUIC connection index. Seeded like the rest and for the same reason -
   * a bundle holds one connection, and a fresh tracker calls it 0 - but this
   * one is the tracker's own counter rather than `L3Tracker`'s, so it is
   * handed to `QuicFlowTracker` directly.
   */
  quic?: number;
}

/**
 * Reads the seeds back off the frame whose tree is being rebuilt.
 *
 * The numbers were written into `Packet.fields` by the eager pass, so the
 * replay is told what the conversation was called rather than made to
 * recompute it from frames it cannot see.
 */
export function seedsFor(packet: Packet): StreamSeeds {
  const read = (abbrev: string): number | undefined => {
    const value = fieldValue(packet, abbrev);
    return typeof value === 'number' ? value : undefined;
  };
  return {
    eth: read('eth.stream'), ip: read('ip.stream'), ipv6: read('ipv6.stream'),
    udp: read('udp.stream'), tls: read('tls.stream'),
    quic: read('quic.connection.number'),
  };
}

/**
 * The literal `pcapParser.ts` gives a frame that had no capture interface.
 *
 * It is a real-looking adapter label and it is not one, which is the whole
 * reason this constant is named rather than inlined: `sessionRestore.ts`
 * records the same trap - trusting `Packet.interfaceName` whenever it is set
 * "turned every interface-less frame into one captured on an adapter named
 * eth0 and broke the round-trip equality this module exists to guarantee".
 */
export const NOT_AN_ADAPTER = 'eth0';

/**
 * The adapter list, keyed by the label a frame carries.
 *
 * `Packet.interfaceName` is the adapter's *label*, and it is the only thing a
 * frame remembers about where it came from - so a replay, which is handed
 * frames rather than a capture, has nothing else to look up with.
 *
 * Here rather than in `pipeline.worker.ts`, where it is used, because a Worker
 * is unreachable from the assertion suite and this is arithmetic worth
 * testing - the rule the root `CLAUDE.md` states after a `queue.shift()` in a
 * `find` predicate took the renderer down.
 */
export function interfacesByLabel<T extends { name: string; label: string }>(
  list: readonly T[],
): Map<string, T> {
  const byLabel = new Map<string, T>();
  for (const entry of list) {
    if (entry.label === NOT_AN_ADAPTER) continue;
    // First wins: two adapters sharing a label is not something to resolve by
    // picking the later one, and an unknown is not a guess.
    if (!byLabel.has(entry.label)) byLabel.set(entry.label, entry);
  }
  return byLabel;
}

export function dissectReplay(
  frames: ReplayFrame[],
  truncated: boolean,
  /**
   * The stream index the real capture gave this conversation. A tracker that
   * has only ever seen one stream calls it 0, and the tree shows that number -
   * so without this a replayed frame reports a stream index that belongs to
   * some other conversation entirely.
   */
  streamId?: number,
  /**
   * What a LATER frame told this one about itself.
   *
   * A replay stops at the frame it was asked about, so it never reaches the
   * frame that answers it - and `[Response In: 4]` on a DNS query is written
   * by frame 4. The fact is not lost, though: it was applied to the frame when
   * it was first learned and it is still in `Packet.fields`, so the rebuilt
   * tree is told rather than made to go and find out.
   *
   * The alternative - replaying past the target until the answer turns up -
   * costs an unbounded number of frames to recover one generated row, and
   * cannot be bounded without sometimes silently omitting it anyway.
   */
  retroactive?: InfoPatch,
  /**
   * Who took the capture.
   *
   * Needed for the same reason the summary pass needs it: the checksum verdict
   * reads it (`checksumVerdict`), so a replay without it decides `Bad` where
   * the summary decided `Unverified`, and the detail tree contradicts the row
   * that opened it. It is not an approximation of the eager tree - the parity
   * script below holds the two to exact equality, and this was the difference.
   */
  host?: HostIdentity,
  /**
   * The other conversation indices the real capture gave this frame.
   *
   * `streamId` above is the same problem for `tcp.stream`, and was the whole
   * of it until every layer gained an index of its own. A sixth trailing
   * parameter rather than folding the five into one object, because
   * `streamId` sits at position 3 and `scripts/pipeline/replay.ts` asserts
   * both that an unseeded replay gets the number wrong and that a seeded one
   * gets it right - moving it would rewrite the check that proves the
   * mechanism works.
   *
   * Recovered by the caller from the target packet's own fields, which is why
   * these five are the only new names in this wave written into the bag.
   */
  seeds?: StreamSeeds,
  /**
   * Turns a frame's adapter label back into the record the dissector wants.
   *
   * A seventh trailing parameter for the reason `seeds` above gives about the
   * sixth: `streamId` sits at position 3 and `scripts/pipeline/replay.ts`
   * asserts both halves of the seeding mechanism by its position, so the five
   * before it do not move.
   *
   * A function rather than the list itself, because only the Worker holds the
   * list and this module is imported by scripts that have no Worker. Absent -
   * or answering `undefined` - is the imported-file case, where there is
   * genuinely no adapter and `unknown` / `Imported capture` is the truth.
   */
  resolveInterface?: (label: string) => { name: string; label: string } | undefined,
): ReplayResult {
  if (frames.length === 0) return { layers: [], truncated };

  const tcp = new TcpStreamTracker();
  if (streamId !== undefined) tcp.seedNextStreamId(streamId);
  if (seeds?.tls !== undefined) tcp.seedNextTlsStreamId(seeds.tls);
  const icmp = new IcmpEchoTracker();
  const quic = new QuicFlowTracker();
  if (seeds?.quic !== undefined) quic.seedNextConnectionNumber(seeds.quic);
  const dns = new DnsTracker();
  const l3 = new L3Tracker();
  if (seeds !== undefined) l3.seedNextIndices(seeds);

  const start = Math.max(0, frames.length - MAX_REPLAY_FRAMES);
  const capped = truncated || start > 0;

  let layers: ProtocolLayer[] = [];
  for (let i = start; i < frames.length; i++) {
    const frame = frames[i];
    const { packet } = decodeRawEthernetPacket(
      frame.bytes, frame.id, frame.tsUs, frame.relativeTime, frame.timeDelta,
      frame.origLen, tcp, icmp, quic, dns,
      frame.interfaceName !== undefined ? resolveInterface?.(frame.interfaceName) : undefined,
      frame.linkType, l3, host,
      { nanosRemainder: frame.tsNanos !== undefined ? Number(frame.tsNanos % 1000n) : undefined },
    );
    // Only the last frame's tree is kept. The rest are dissected for their
    // effect on the trackers and thrown away, which is the whole mechanism.
    if (i === frames.length - 1) layers = packet.layers;
  }

  if (retroactive && layers.length > 0) {
    applyInfoPatch({ layers, info: '', fields: {} } as unknown as Packet, retroactive);
  }

  if (capped && layers.length > 0) {
    layers[0].fields.push({
      name: '[Reassembly context]',
      value: 'Rebuilt from part of the conversation - earlier frames are no longer in the buffer',
      generated: true,
      expertInfo: {
        category: 'CaptureGap',
        message: 'This tree was rebuilt from the frames still held, not from the start of the conversation.',
      },
    });
  }

  return { layers, truncated: capped };
}
