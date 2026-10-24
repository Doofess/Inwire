/** Packets per second between two samples of the capture's running total. */
export function packetRate(
  prev: { total: number; at: number },
  next: { total: number; at: number },
): number {
  if (!(next.at > prev.at) || !(next.total >= prev.total)) return 0;
  const rate = (next.total - prev.total) / ((next.at - prev.at) / 1000);
  return Number.isFinite(rate) && rate > 0 ? rate : 0;
}

/** One decimal under 10 of the unit, none at or above it. */
function scaled(value: number): string {
  return value < 10 ? value.toFixed(1) : String(Math.round(value));
}

/** `950/s`, `1.2k/s`, `36k/s`, `1.2M/s`. Negative and NaN read as `0/s`. */
export function formatRate(perSecond: number): string {
  if (!Number.isFinite(perSecond) || perSecond <= 0) return '0/s';
  if (Math.round(perSecond) < 1000) return `${Math.round(perSecond)}/s`;
  const k = perSecond / 1000;
  // 999.6k would print as "1000k"; carry it into the next unit instead.
  if (Math.round(k) < 1000) {
    // 9.96k rounds to "10.0"; print it as 10k.
    return `${k < 10 && Number(k.toFixed(1)) >= 10 ? '10' : scaled(k)}k/s`;
  }
  const m = perSecond / 1_000_000;
  return `${m < 10 && Number(m.toFixed(1)) >= 10 ? '10' : scaled(m)}M/s`;
}
