/**
 * A stream's frames as the ladder draws them: one arrow per frame that says
 * something, one band per quiet run (ADR 0055 §1). A band never spans a change
 * of colour rule, so its colour is never an average.
 *
 * ## What stands alone
 *
 * A frame carrying SYN, FIN or RST, one with any analysis flag, one with an
 * expert category, and the stream's first and last frame. Each of those is
 * what a ladder is read for; folding one into a band would hide the one frame
 * somebody opened the stream to find. Everything else is a quiet frame, and a
 * quiet frame joins the band in progress only while the band goes the same
 * way and matches the same rule - the chip takes the rule's colour, and a
 * band of two rules has no honest colour.
 *
 * ## Acknowledgements ride along
 *
 * A receiver acknowledges every second segment, so a band that broke on
 * every change of direction would fold a bulk transfer into runs of two. A
 * pure ACK - no payload, no flag but ACK, nothing the analysis said about it -
 * from the other lane joins the band it acknowledges and is counted apart
 * from it: `count` and `bytes` are the data's, `acks` the riders'. Its own
 * rule neither breaks the band nor colours it; the band is the data's, in the
 * data's rule. A band of pure ACKs carries no riders, so two lanes trading
 * bare ACKs still draw every one.
 *
 * ## Bands are keyed by their first frame
 *
 * `expanded` holds the ids of bands the user opened, and a band is named by
 * its first frame's id. The id rather than an index, because a live stream
 * grows: the band at index 3 is a different band after the next flush, and
 * the one somebody opened must stay open.
 */
import type { Packet } from '../../types/packet';
import { fieldValue } from '../../services/dissect/fieldAccess';
import { isFromClient } from '../../services/followStream';
import type { Endpoint } from '../../services/conversation/clientSide';
import type { Lane } from './ladderLayout';

export type LadderItem =
  | { kind: 'frame'; packet: Packet; from: Lane }
  | { kind: 'band'; from: Lane; first: Packet; last: Packet; count: number; bytes: number;
      acks: number; time: number; endTime: number; ruleKey: string };

/**
 * The most frames one band holds. A bound rather than a rule of the data: a
 * stream can be most of a capture, and a band of a million frames is one
 * click from a million arrows.
 */
const BAND_MAX = 100_000;

function standsAlone(p: Packet): boolean {
  return fieldValue(p, 'tcp.flags.syn') === 1 || fieldValue(p, 'tcp.flags.fin') === 1
    || fieldValue(p, 'tcp.flags.reset') === 1 || (p.analysisFlags?.length ?? 0) > 0
    || fieldValue(p, 'inwire.expert.category') !== undefined;
}

/** No payload and no flag but ACK. `standsAlone` has already taken the rest. */
function isPureAck(p: Packet): boolean {
  return fieldValue(p, 'tcp.len') === 0 && fieldValue(p, 'tcp.flags.ack') === 1
    && fieldValue(p, 'tcp.flags.push') !== 1 && fieldValue(p, 'tcp.flags.urg') !== 1;
}

/** When an item starts, which is where the ladder places it. */
export function itemTime(item: LadderItem): number {
  return item.kind === 'frame' ? item.packet.relativeTime : item.time;
}

/** The frame an item is painted from: the frame itself, or a band's first. */
export function itemPacket(item: LadderItem): Packet {
  return item.kind === 'frame' ? item.packet : item.first;
}

/**
 * Folds `frames`, which must be in capture order, into items. A band of one
 * is drawn as a frame.
 */
export function foldRuns(
  frames: readonly Packet[], client: Endpoint, ruleKeyOf: (p: Packet) => string,
  expanded: ReadonlySet<number>,
): LadderItem[] {
  const items: LadderItem[] = [];
  // Each frame keeps its own lane: a riding ACK is drawn in its own when the band opens.
  let run: { packet: Packet; from: Lane }[] = [];
  let runFrom: Lane = 'client';
  let runKey = '';
  let runCarriesData = false;
  let acks = 0;

  const flush = () => {
    // A band is a run of data: one segment and the ACKs riding on it are
    // drawn as themselves, as a band of one always was.
    if (run.length - acks < 2 || expanded.has(run[0].packet.id)) {
      for (const r of run) items.push({ kind: 'frame', ...r });
    } else {
      let bytes = 0;
      for (const r of run) if (r.from === runFrom) bytes += r.packet.length;
      const first = run[0].packet;
      const last = run[run.length - 1].packet;
      items.push({ kind: 'band', from: runFrom, first, last, count: run.length - acks, bytes, acks,
        time: first.relativeTime, endTime: last.relativeTime, ruleKey: runKey });
    }
    run = [];
    acks = 0;
  };

  frames.forEach((p, i) => {
    const from: Lane = isFromClient(p, client) ? 'client' : 'server';
    if (standsAlone(p) || i === 0 || i === frames.length - 1) {
      flush();
      items.push({ kind: 'frame', packet: p, from });
      return;
    }
    const pureAck = isPureAck(p);
    if (run.length > 0 && from !== runFrom && runCarriesData && pureAck && run.length < BAND_MAX) {
      run.push({ packet: p, from });
      acks++;
      return;
    }
    const key = ruleKeyOf(p);
    if (run.length === 0 || from !== runFrom || key !== runKey || run.length >= BAND_MAX) {
      flush();
      runFrom = from;
      runKey = key;
      runCarriesData = !pureAck;
    }
    run.push({ packet: p, from });
  });
  flush();
  return items;
}
