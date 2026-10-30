const MB = 1024 * 1024;
const GB = 1024 * MB;

/**
 * The import panel's progress line: `Importing cap.pcapng: 1.2 of 2.5 GB (48%)`.
 *
 * Binary units, because that is what Windows Explorer shows for the same file.
 * One unit for both figures, chosen by the total, so the pair reads as a
 * fraction; the percentage is floored, so 100% is only ever the end.
 */
export function importProgressText(fileName: string, readBytes: number, totalBytes: number): string {
  const percent = totalBytes > 0 ? Math.min(100, Math.floor((readBytes / totalBytes) * 100)) : 0;
  const sizes = totalBytes >= GB
    ? `${(readBytes / GB).toFixed(1)} of ${(totalBytes / GB).toFixed(1)} GB`
    : `${Math.round(readBytes / MB)} of ${Math.round(totalBytes / MB)} MB`;
  return `Importing ${fileName}: ${sizes} (${percent}%)`;
}
