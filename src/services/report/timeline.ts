/**
 * Traffic over time, as a fold that sees each frame once and a rebin that
 * picks the bar width afterwards.
 *
 * The split is the point. A report cannot choose its bar width before it has
 * read the capture, because the width depends on how long the capture turned
 * out to be - and on a capture read off disk in pages there is no second pass
 * to spend on finding out. So the fold keeps one cell per second, which is
 * O(seconds captured) whatever the frame count, and `rebin` merges those cells
 * into at most `maxBars` bars once the span is known.
 *
 * Whole seconds are the finest grain on purpose: the report draws at most a
 * few hundred bars, and no capture short enough to want sub-second bars at that
 * count is long enough to need a report.
 */
import type { Packet } from '../../types/packet';
import { categoryOfPacket, isFaultCategory } from '../expertInfo';

/**
 * The bucket a relative time falls in, at a given width.
 *
 * An INDEX rather than a time in seconds, which `TrafficTimelineChart` relies
 * on: keyed on the index its map stays small at a one-minute interval and exact
 * at 100 ms, where a float second would collide. Shared so the chart and the
 * report cannot disagree about which second a frame belongs to.
 */
export function timelineIndex(relativeTime: number, bucketSeconds: number): number {
  return Math.floor(relativeTime / bucketSeconds);
}

export interface TimelineCell {
  frames: number;
  bytes: number;
  /** Frames whose expert category is a fault (`isFaultCategory`). */
  faults: number;
}

/** One cell per whole second that saw a frame. */
export class TimelineFold {
  readonly seconds = new Map<number, TimelineCell>();
  frames = 0;
  bytes = 0;

  add(packet: Packet): void {
    const second = timelineIndex(packet.relativeTime, 1);
    let cell = this.seconds.get(second);
    if (!cell) {
      cell = { frames: 0, bytes: 0, faults: 0 };
      this.seconds.set(second, cell);
    }
    cell.frames += 1;
    cell.bytes += packet.length;
    if (isFaultCategory(categoryOfPacket(packet))) cell.faults += 1;
    this.frames += 1;
    this.bytes += packet.length;
  }
}

export interface TimelineBar {
  /** Seconds since the capture started, at the bar's left edge. */
  start: number;
  frames: number;
  bytes: number;
  faults: number;
}

export interface Timeline {
  /** Seconds per bar. */
  width: number;
  /** Dense: a quiet stretch is a run of empty bars, never a gap. */
  bars: TimelineBar[];
  frames: number;
  bytes: number;
}

/**
 * The widths a bar may have, in seconds.
 *
 * Numbers a reader can hold ("each bar is five minutes"), rather than whatever
 * span divided by bar count happens to come to - a 37-second bar makes every
 * rate on the chart a sum nobody can check in their head.
 */
export const NICE_WIDTHS: readonly number[] = [
  1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600,
];

/**
 * The fold, merged into at most `maxBars` bars of the narrowest nice width
 * that fits.
 *
 * Bars are aligned to the capture's first second rather than to zero, so a
 * capture of N seconds needs exactly ceil(N / width) bars whatever second it
 * began in. Past an hour, a bar is a whole number of hours, because a capture
 * longer than `maxBars` hours still has to fit.
 */
export function rebin(fold: TimelineFold, maxBars = 120): Timeline {
  const limit = Math.max(1, Math.floor(maxBars));
  if (fold.seconds.size === 0) return { width: 1, bars: [], frames: 0, bytes: 0 };

  let first = Number.POSITIVE_INFINITY;
  let last = Number.NEGATIVE_INFINITY;
  for (const second of fold.seconds.keys()) {
    if (second < first) first = second;
    if (second > last) last = second;
  }
  const span = last - first + 1;

  let width = NICE_WIDTHS.find((w) => Math.ceil(span / w) <= limit);
  if (width === undefined) {
    const hour = NICE_WIDTHS[NICE_WIDTHS.length - 1];
    width = Math.ceil(span / (limit * hour)) * hour;
  }

  const bars: TimelineBar[] = [];
  const count = Math.ceil(span / width);
  for (let i = 0; i < count; i++) {
    bars.push({ start: first + i * width, frames: 0, bytes: 0, faults: 0 });
  }
  for (const [second, cell] of fold.seconds) {
    const bar = bars[Math.floor((second - first) / width)];
    bar.frames += cell.frames;
    bar.bytes += cell.bytes;
    bar.faults += cell.faults;
  }

  return { width, bars, frames: fold.frames, bytes: fold.bytes };
}
