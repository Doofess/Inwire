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
import type { KeyLogStore } from '../services/tls/keyLog';
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

/** `add` may return false to stop: nothing more is handed over and the rest of the file is not read. */
export async function readKeyLogFile(
  file: Blob,
  add: (text: string) => boolean | void,
  options: ReadKeyLogOptions = {},
): Promise<{ skippedBytes: number }> {
  const cap = options.cap ?? KEYLOG_CAP_BYTES;
  const chunkBytes = options.chunkBytes ?? KEYLOG_CHUNK_BYTES;
  const maxLine = options.maxLineBytes ?? KEYLOG_MAX_LINE_BYTES;
  const from = Math.max(0, file.size - cap);
  // Reading starts one byte early when there is a cut, so that a cut landing
  // exactly on a line start sees the newline before it and keeps that line;
  // the skip below then drops only the line the cut is inside of.
  const readFrom = from > 0 ? from - 1 : 0;
  // A streaming decoder, so a character a chunk boundary splits decodes whole.
  const decoder = new TextDecoder();
  let carry = '';
  // True while discarding up to the next newline: the line the cut landed in,
  // or one that ran past `maxLine`.
  let skipping = from > 0;
  let stopped = false;
  const give = (text: string): void => {
    if (!stopped && add(text) === false) stopped = true;
  };

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
      if (text.length > 0 && text.length - end - 1 <= maxLine) give(text);
      else if (end >= 0) give(text.slice(0, end + 1));
      return;
    }
    if (end >= 0) give(text.slice(0, end + 1));
    carry = text.slice(end + 1);
    if (carry.length > maxLine) {
      carry = '';
      skipping = true;
    }
  };

  for (let at = readFrom; at < file.size && !stopped; at += chunkBytes) {
    const bytes = new Uint8Array(await file.slice(at, Math.min(file.size, at + chunkBytes)).arrayBuffer());
    take(decoder.decode(bytes, { stream: true }), false);
  }
  if (!stopped) take(decoder.decode(), true);
  return { skippedBytes: from };
}

/** What a Load through the Decryption panel came to. */
export type KeyLogLoad =
  | { kind: 'loaded'; secrets: number; connections: number; skippedBytes: number }
  | { kind: 'failed'; error: string }
  /** The user pressed Clear while it read: it stopped there, and Clear's message stands. */
  | { kind: 'cleared' };

/**
 * The panel's Load: reads `file` into `store` and says what it added. Lifted
 * out of `DecryptionSettingsPanel.tsx` so a script can drive it.
 *
 * A Clear while it reads ends it. Reading a large file takes seconds, and the
 * rest of it used to go on loading under a panel that had just said "new
 * frames will not be decrypted", then reported a count measured across the
 * Clear, negative when the store had held more than the file brought back.
 */
export async function loadKeyLogFile(file: Blob, store: KeyLogStore, options: ReadKeyLogOptions = {}): Promise<KeyLogLoad> {
  const clears = store.clears;
  const before = store.stats();
  try {
    // The buffer moves once, here, for what will be read, instead of at every
    // overflow while the chunks arrive (each move strands the old buffer in
    // every reader). Absolute, with headroom: the file already being
    // followed, even a little longer since, finds the room and moves nothing.
    store.reserve(Math.min(file.size, options.cap ?? KEYLOG_CAP_BYTES));
    const { skippedBytes } = await readKeyLogFile(file, (text) => {
      if (store.clears !== clears) return false;
      store.add(text);
    }, options);
    if (store.clears !== clears) return { kind: 'cleared' };
    const after = store.stats();
    return {
      kind: 'loaded',
      secrets: after.secrets - before.secrets,
      connections: after.connections - before.connections,
      skippedBytes,
    };
  } catch (error) {
    if (store.clears !== clears) return { kind: 'cleared' };
    // Moved or deleted since it was picked; what was read before the error stays loaded.
    return { kind: 'failed', error: error instanceof Error ? error.message : String(error) };
  }
}
