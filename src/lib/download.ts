/**
 * Handing a generated file to the browser.
 *
 * The same five lines - create an object URL, synthesise an anchor, click it,
 * revoke - were inlined at four call sites before this existed, and every copy
 * revoked the URL on the line after `.click()`. That works in Chrome today
 * because the download is registered synchronously, but it is not guaranteed:
 * the fetch that backs the download is allowed to start after the current task,
 * by which point a revoked URL is a dead link and the download silently does
 * nothing. Revoking on a later macrotask costs one timer and removes the race.
 *
 * The anchor is attached to the document before clicking. A detached anchor is
 * enough for Chrome but not for Firefox, which ignores the click entirely.
 */
export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * The timestamped stem every export shares: `inwire_capture_1725300000000`.
 *
 * Callers append their own extension. Kept here so the zip wrapper and the file
 * it wraps cannot end up with two different timestamps, which is what happens
 * when each call site writes `Date.now()` for itself.
 */
export function exportStem(prefix = 'inwire_capture'): string {
  return `${prefix}_${Date.now()}`;
}
