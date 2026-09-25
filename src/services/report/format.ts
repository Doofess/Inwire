/**
 * How the report writes numbers, in one place.
 *
 * Fixed `en-US` and no time zone anywhere, for the reason `captureMeta.ts`
 * gives: a report is a file that leaves this machine, and its numbers must read
 * the same wherever it is opened and whichever machine wrote it. It is also
 * what lets `scripts/report/findings.ts` hold a finding's text to the analysis
 * it came from, digit for digit.
 *
 * Sizes are decimal (kB = 1,000 B), the way Wireshark's statistics and every
 * network rate are written; a "MB" that meant 1,048,576 here and 1,000,000 in
 * the rate beside it would be a second unit wearing the first one's name.
 */

const INTEGER = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });
const ONE_DECIMAL = new Intl.NumberFormat('en-US', { minimumFractionDigits: 1, maximumFractionDigits: 1 });

/** 12,858 */
export function count(n: number): string {
  return INTEGER.format(n);
}

/** 1 frame, 2 frames. */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${count(n)} ${n === 1 ? one : many}`;
}

/**
 * A share as a percentage with one decimal.
 *
 * A non-zero share that would round to 0.0% says "under 0.1%" instead: "0.0% of
 * frames were Telnet" reads as none, and a report must not round a finding away.
 */
export function percent(part: number, whole: number): string {
  if (whole <= 0) return '0.0%';
  const share = (part / whole) * 100;
  if (part > 0 && share < 0.05) return 'under 0.1%';
  return `${ONE_DECIMAL.format(share)}%`;
}

/** `percent` for a table cell, where "under 0.1%" would wrap: "<0.1%". */
export function percentCell(part: number, whole: number): string {
  const text = percent(part, whole);
  return text === 'under 0.1%' ? '<0.1%' : text;
}

const SIZE_UNITS = ['kB', 'MB', 'GB', 'TB'];

/** 845 B, 12.3 kB, 9.9 MB */
export function bytes(n: number): string {
  if (n < 1000) return `${count(n)} B`;
  let value = n / 1000;
  let unit = 0;
  while (value >= 999.95 && unit < SIZE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${ONE_DECIMAL.format(value)} ${SIZE_UNITS[unit]}`;
}

const RATE_UNITS = ['kbit/s', 'Mbit/s', 'Gbit/s'];

/** 950 bit/s, 372.1 kbit/s */
export function bitRate(bitsPerSecond: number): string {
  if (bitsPerSecond < 1000) return `${count(bitsPerSecond)} bit/s`;
  let value = bitsPerSecond / 1000;
  let unit = 0;
  while (value >= 999.95 && unit < RATE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${ONE_DECIMAL.format(value)} ${RATE_UNITS[unit]}`;
}

/** 60.6 frames/s */
export function frameRate(framesPerSecond: number): string {
  return `${ONE_DECIMAL.format(framesPerSecond)} frames/s`;
}

/**
 * A span of time: 0.412 s, 23.4 s, 3 min 32 s, 2 h 05 min.
 *
 * Precision falls as the span grows, because nobody reading "2 h 05 min" wants
 * to know the milliseconds, and the exact figure is in the metadata table.
 */
export function duration(seconds: number): string {
  if (seconds < 1) return `${seconds.toFixed(3)} s`;
  if (seconds < 60) return Number.isInteger(seconds) ? `${seconds} s` : `${ONE_DECIMAL.format(seconds)} s`;
  const whole = Math.round(seconds);
  if (whole < 3600) {
    const m = Math.floor(whole / 60);
    const s = whole % 60;
    return s === 0 ? `${m} min` : `${m} min ${s} s`;
  }
  const h = Math.floor(whole / 3600);
  const m = Math.floor((whole % 3600) / 60);
  return `${h} h ${String(m).padStart(2, '0')} min`;
}

/** A point in the capture, as an offset from its start: 0:07, 3:32, 1:02:05. */
export function offset(seconds: number): string {
  const whole = Math.max(0, Math.floor(seconds));
  const h = Math.floor(whole / 3600);
  const m = Math.floor((whole % 3600) / 60);
  const s = whole % 60;
  const ss = String(s).padStart(2, '0');
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${ss}` : `${m}:${ss}`;
}

/** Epoch microseconds as a UTC clock reading, `23:26:11 UTC`. */
export function utcClock(us: number): string {
  const date = new Date(Math.floor(us / 1000));
  return Number.isNaN(date.getTime()) ? '' : `${date.toISOString().slice(11, 19)} UTC`;
}

/** Epoch milliseconds as `2026-09-25 14:03 UTC` - never the viewer's zone. */
export function utcMinute(ms: number): string {
  const iso = new Date(ms).toISOString();
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}
