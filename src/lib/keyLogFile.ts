/**
 * Reads a key log file the user loads once, for the Decryption panel.
 *
 * In chunks, never as one string: `file.text()` on a log at the cap is a
 * 512 MiB string, longer than V8's longest (2^29 - 24 characters), and well
 * short of that it puts the whole file on the page's heap at once. The store
 * is handed whole lines, which is what `keyLog.add` parses, from the newest
 * `cap` bytes of the file: the same cut main's follower makes, dropping the
 * line the cut lands in (`planFromTop` in `electron/keyLogTail.ts`, ADR 0073).
 */
import { KEYLOG_CAP_BYTES } from '../services/tls/keyLogLimits';

/** What one `add` is handed at most, before the carried partial line. */
export const KEYLOG_CHUNK_BYTES = 8 * 1024 * 1024;
/**
 * A line longer than this is not a key log line (the longest, a TLS 1.2
 * `CLIENT_RANDOM`, is 176 bytes): it is dropped rather than carried, so a file
 * with no newlines cannot become one string.
 */
export const KEYLOG_MAX_LINE_BYTES = 64 * 1024;

export interface ReadKeyLogOptions {
  cap?: number;
  chunkBytes?: number;
  maxLineBytes?: number;
}

export async function readKeyLogFile(
  file: Blob,
  add: (text: string) => void,
  options: ReadKeyLogOptions = {},
): Promise<{ skippedBytes: number }> {
  const cap = options.cap ?? KEYLOG_CAP_BYTES;
  const chunkBytes = options.chunkBytes ?? KEYLOG_CHUNK_BYTES;
  const maxLine = options.maxLineBytes ?? KEYLOG_MAX_LINE_BYTES;
  const from = Math.max(0, file.size - cap);
  // A streaming decoder, so a character a chunk boundary splits decodes whole.
  const decoder = new TextDecoder();
  let carry = '';
  // True while discarding up to the next newline: the line the cut landed in,
  // or one that ran past `maxLine`.
  let skipping = from > 0;

  const take = (decoded: string, last: boolean): void => {
    let text = carry + decoded;
    carry = '';
    if (skipping) {
      const nl = text.indexOf('\n');
      if (nl < 0) return;
      text = text.slice(nl + 1);
      skipping = false;
    }
    const end = text.lastIndexOf('\n');
    if (last) {
      if (text.length > 0 && text.length - end - 1 <= maxLine) add(text);
      else if (end >= 0) add(text.slice(0, end + 1));
      return;
    }
    if (end >= 0) add(text.slice(0, end + 1));
    carry = text.slice(end + 1);
    if (carry.length > maxLine) {
      carry = '';
      skipping = true;
    }
  };

  for (let at = from; at < file.size; at += chunkBytes) {
    const bytes = new Uint8Array(await file.slice(at, Math.min(file.size, at + chunkBytes)).arrayBuffer());
    take(decoder.decode(bytes, { stream: true }), false);
  }
  take(decoder.decode(), true);
  return { skippedBytes: from };
}
