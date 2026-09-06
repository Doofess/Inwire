/**
 * A byte count as a person reads it.
 *
 * There were four of these, in four files, producing four different answers to
 * the same question - and one of them was wrong. `NetworkMatrix` formatted
 * inline with no MB tier at all, so a 40 MB conversation in Top Talkers read
 * `40960.0K`. The others disagreed on spacing (`1.5M` against `1.5 MB`) and on
 * precision (`ExportPanel` used one decimal for MB and none for KB).
 *
 * One tiering rule, then, and two presentations of it, because both are
 * deliberate rather than accidental drift:
 *
 *   - **compact** (`842B`, `1.5K`, `40.0M`) for the dashboard cards, where a
 *     row is 352px wide and shares it with two addresses and a protocol.
 *   - **spaced** (`842 B`, `2 KB`, `1.5 MB`) everywhere there is room, which
 *     is what the export panel and the settings readouts use.
 *
 * 1024, not 1000: this counts memory and wire bytes, and every other size in
 * the app - the buffer budget, the storage budget, the pcap writer - is binary.
 */

const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const;

export interface FormatBytesOptions {
  /** Tight single-letter units with no space, for narrow cells. */
  compact?: boolean;
}

export function formatBytes(bytes: number, options: FormatBytesOptions = {}): string {
  const compact = options.compact === true;
  // Not a number, or below zero: there is no honest rendering, so say nothing
  // rather than print `NaN B`.
  if (!Number.isFinite(bytes) || bytes < 0) return '—';

  let value = bytes;
  let unit = 0;
  // `>= 1024` rather than `> 1024`, so 1024 bytes reads as 1 KB and never as
  // `1024 B`. Stops at the largest unit rather than inventing one past TB.
  while (value >= 1024 && unit < UNITS.length - 1) {
    value /= 1024;
    unit++;
  }

  // Whole bytes are whole: `842 B`, never `842.0 B`. Above that one decimal,
  // which is what distinguishes 1.2 MB from 1.9 MB at a glance and is as much
  // precision as any of these readouts ever justified.
  const text = unit === 0 ? String(Math.round(value)) : value.toFixed(1);
  const suffix = compact ? UNITS[unit][0] : UNITS[unit];
  return compact ? `${text}${suffix}` : `${text} ${suffix}`;
}
