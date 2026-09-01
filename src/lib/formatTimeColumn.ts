import type { Packet } from '../types/packet';

/**
 * How the packet list's Time column reads.
 *
 * Five formats rather than the one that used to be hardcoded, and none of them
 * costs anything to compute: `Packet` already carries `timestamp` (milliseconds
 * since the epoch) and `relativeTime` (seconds since capture start), so all
 * five are derivable with no change to dissection.
 *
 * The two absolute formats are here because they are what you need the moment
 * you correlate a capture against anything else - a server log, an incident
 * timeline, a colleague in another timezone. Wireshark offers exactly these and
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

/** Decimal places, matching the six the capture's own timestamps carry. */
const PRECISION = 6;

function pad(n: number, width = 2): string {
  return String(n).padStart(width, '0');
}

/**
 * The part of the timestamp below one second, as six digits.
 *
 * Taken modulo 1000 rather than as `ms - Math.floor(ms)`. That subtraction
 * yields only the SUB-millisecond remainder, so it silently dropped the
 * milliseconds - .694700 came out as .700000 - and doing the arithmetic on a
 * number in the trillions added float noise on top, which turned it into
 * .699951. Modulo keeps the value small before it is divided.
 *
 * Built from the number rather than from `toISOString`, because the displayed
 * precision is six places and an ISO string carries only three.
 */
function fraction(ms: number): string {
  // The double modulo keeps pre-epoch timestamps positive.
  const withinSecond = ((ms % 1000) + 1000) % 1000;
  return (withinSecond / 1000).toFixed(PRECISION).slice(2);
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
      return packet.relativeTime.toFixed(PRECISION);

    case 'delta': {
      // The first row of a capture has nothing to be relative to. Zero says
      // "no time has passed since the previous packet", which is a different
      // and false claim, so this reports the absence instead.
      if (!previous) return '-';
      const delta = (packet.timestamp - previous.timestamp) / 1000;
      // Clamped at zero rather than shown negative: out-of-order timestamps
      // happen on multi-interface captures, and a negative gap in this column
      // reads as a bug in the clock rather than as what it is.
      return Math.max(0, delta).toFixed(PRECISION);
    }

    case 'clock':
    case 'date':
    case 'utc': {
      const utc = format === 'utc';
      const d = new Date(packet.timestamp);
      const p = clockParts(d, utc);
      const time = `${pad(p.h)}:${pad(p.m)}:${pad(p.s)}.${fraction(packet.timestamp)}`;
      if (format === 'clock') return time;
      return `${p.Y}-${pad(p.M)}-${pad(p.D)} ${time}`;
    }

    default:
      return packet.relativeTime.toFixed(PRECISION);
  }
}
