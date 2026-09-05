import type { Packet } from '../types/packet';

/**
 * How the packet list's Time column reads.
 *
 * Five formats rather than the one that used to be hardcoded, and none of them
 * costs anything to compute: `Packet` already carries `tsUs` (microseconds
 * since the epoch) and `relativeTime` (seconds since capture start), so all
 * five are derivable with no change to dissection.
 *
 * The two absolute formats are here because they are what you need the moment
 * you correlate a capture against anything else - a server log, an incident
 * timeline, a colleague in another timezone. The reference analyzer offers exactly these and
 * they are its two most-used alternates for that reason.
 */
export type TimeFormat = 'relative' | 'clock' | 'date' | 'utc' | 'delta';

export const TIME_FORMAT_LABELS: Record<TimeFormat, string> = {
  relative: 'Seconds since capture start',
  clock: 'Time of day',
  date: 'Date and time of day',
  utc: 'UTC date and time of day',
  delta: 'Since previous packet',
};

/**
 * Decimal places for the elapsed formats: the capture's own resolution, so a
 * nanosecond pcap shows nine and a microsecond one six. Live capture never sets
 * `tsPrecision` (the agent stamps in microseconds) and gets six. This was a
 * constant 6 for a while, which silently rounded nanosecond captures in the
 * list while the details pane showed all nine.
 */
function precisionOf(packet: Packet): number {
  return packet.tsPrecision ?? 6;
}

function pad(n: number, width = 2): string {
  return String(n).padStart(width, '0');
}

function clockParts(d: Date, utc: boolean) {
  return utc
    ? { h: d.getUTCHours(), m: d.getUTCMinutes(), s: d.getUTCSeconds(),
        Y: d.getUTCFullYear(), M: d.getUTCMonth() + 1, D: d.getUTCDate() }
    : { h: d.getHours(), m: d.getMinutes(), s: d.getSeconds(),
        Y: d.getFullYear(), M: d.getMonth() + 1, D: d.getDate() };
}

/**
 * Formats one packet's time.
 *
 * `previous` is the packet ABOVE this one in the list as currently filtered and
 * sorted - not the previous packet in the buffer. The delta a reader wants is
 * the gap between the two rows they can see; a delta against a frame that a
 * display filter has hidden would be a number with no visible referent.
 */
export function formatTimeColumn(
  format: TimeFormat,
  packet: Packet,
  previous: Packet | null,
): string {
  switch (format) {
    case 'relative':
      return packet.relativeTime.toFixed(precisionOf(packet));

    case 'delta': {
      // The first row of a capture has nothing to be relative to. Zero says
      // "no time has passed since the previous packet", which is a different
      // and false claim, so this reports the absence instead.
      if (!previous) return '-';
      const delta = (packet.tsUs - previous.tsUs) / 1_000_000;
      // Clamped at zero rather than shown negative: out-of-order timestamps
      // happen on multi-interface captures, and a negative gap in this column
      // reads as a bug in the clock rather than as what it is.
      return Math.max(0, delta).toFixed(precisionOf(packet));
    }

    case 'clock':
    case 'date':
    case 'utc': {
      const utc = format === 'utc';
      const d = new Date(packet.tsUs / 1000);
      const p = clockParts(d, utc);
      // Whole seconds. The six-digit fraction that used to be appended here
      // made a wall-clock reading twice as long as the column it sits in, for
      // precision nobody reads off a clock face - you correlate a capture
      // against a log or an incident timeline by the SECOND. The sub-second
      // detail is not lost: `relative` and `delta` both still carry all six
      // places, and those are the formats you switch to when the question is
      // about timing rather than about when.
      const time = `${pad(p.h)}:${pad(p.m)}:${pad(p.s)}`;
      if (format === 'clock') return time;
      return `${p.Y}-${pad(p.M)}-${pad(p.D)} ${time}`;
    }

    default:
      return packet.relativeTime.toFixed(precisionOf(packet));
  }
}
