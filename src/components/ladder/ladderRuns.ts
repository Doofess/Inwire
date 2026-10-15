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
      time: number; endTime: number; ruleKey: string };

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
  let run: Packet[] = [];
  let runFrom: Lane = 'client';
  let runKey = '';

  const flush = () => {
    if (run.length === 1) items.push({ kind: 'frame', packet: run[0], from: runFrom });
    else if (run.length > 1) {
      if (expanded.has(run[0].id)) for (const p of run) items.push({ kind: 'frame', packet: p, from: runFrom });
      else {
        let bytes = 0;
        for (const p of run) bytes += p.length;
        items.push({ kind: 'band', from: runFrom, first: run[0], last: run[run.length - 1], count: run.length,
          bytes, time: run[0].relativeTime, endTime: run[run.length - 1].relativeTime, ruleKey: runKey });
      }
    }
    run = [];
  };

  frames.forEach((p, i) => {
    const from: Lane = isFromClient(p, client) ? 'client' : 'server';
    if (standsAlone(p) || i === 0 || i === frames.length - 1) {
      flush();
      items.push({ kind: 'frame', packet: p, from });
      return;
    }
    const key = ruleKeyOf(p);
    if (run.length === 0 || from !== runFrom || key !== runKey || run.length >= BAND_MAX) {
      flush();
      runFrom = from;
      runKey = key;
    }
    run.push(p);
  });
  flush();
  return items;
}
