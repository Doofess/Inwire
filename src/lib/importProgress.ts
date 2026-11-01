const MB = 1024 * 1024;
const GB = 1024 * MB;

/**
 * How far an import has read, as a whole percent: floored, so 100 is only ever
 * the end. The width of the import zone's bar and its `aria-valuenow`.
 */
export function importProgressPercent(readBytes: number, totalBytes: number): number {
  return totalBytes > 0 ? Math.min(100, Math.floor((readBytes / totalBytes) * 100)) : 0;
}

/**
 * The sizes line under the import zone's bar: `1.2 of 2.5 GB (48%)`. The file's
 * name is the zone's own line above it.
 *
 * Binary units, because that is what Windows Explorer shows for the same file.
 * One unit for both figures, chosen by the total, so the pair reads as a
 * fraction.
 */
export function importProgressSizes(readBytes: number, totalBytes: number): string {
  const sizes = totalBytes >= GB
    ? `${(readBytes / GB).toFixed(1)} of ${(totalBytes / GB).toFixed(1)} GB`
    : `${Math.round(readBytes / MB)} of ${Math.round(totalBytes / MB)} MB`;
  return `${sizes} (${importProgressPercent(readBytes, totalBytes)}%)`;
}
