/**
 * Reading a piece of the agent's own pcapng for the pipeline Worker, so the
 * live view can catch up from it after the stream skipped (ADR 0053 phase 4).
 *
 * **The Worker names a capture and a file, never a path** - the rule
 * `capturedFiles.ts` holds "Save as captured" to. The capture id must be one
 * this app would have made and the name one the agent gives its files; the
 * folder is main's own. What goes back is the file's bytes, unread: the
 * Worker parses them, and no captured frame passes through main's JavaScript
 * as anything but an opaque buffer.
 *
 * **Open, read, close, every time.** The agent writes the file being read and
 * a ring deletes the oldest; a handle held between reads is a handle a delete
 * has to wait for. Node opens with `FILE_SHARE_DELETE`, but a file that is
 * gone is then simply gone - which is an answer (`gone`), not an error.
 *
 * No Electron here, so `scripts/electron/captured-read.ts` drives it under
 * plain `tsx`; `agentPipe.ts` is the adapter.
 */
import { open } from 'node:fs/promises';
import { isCaptureId } from '../src/services/capture/captureDirectory';
import { CAPTURED_FILE_PATTERN, capturedFilePath } from './capturedFiles';

/** The most one read hands over: the Worker asks for 4 MB. */
export const MAX_CAPTURED_READ = 16 * 1024 * 1024;

export interface CapturedRead {
  /** The bytes from `offset` on, fewer than asked at the file's end; empty when there are none yet. */
  bytes: Uint8Array | null;
  /** The file is not there: a ring deleted it. */
  gone: boolean;
  /** Why the read was refused or failed, when it was. */
  error?: string;
}

export async function readCaptured(
  captureRoot: string, captureId: string, name: string, offset: number, length: number,
): Promise<CapturedRead> {
  if (!isCaptureId(captureId)) return { bytes: null, gone: false, error: 'not a capture id' };
  if (!CAPTURED_FILE_PATTERN.test(name)) return { bytes: null, gone: false, error: 'not a captured file name' };
  if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(length) || length < 0) {
    return { bytes: null, gone: false, error: 'not a byte range' };
  }
  const want = Math.min(length, MAX_CAPTURED_READ);
  let handle;
  try {
    handle = await open(capturedFilePath(captureRoot, captureId, name), 'r');
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === 'ENOENT') return { bytes: null, gone: true };
    return { bytes: null, gone: false, error: String(error) };
  }
  try {
    const out = new Uint8Array(want);
    let got = 0;
    // A read may come back short before the end; looped, as nodeBlockFile does.
    while (got < want) {
      const { bytesRead } = await handle.read(out, got, want - got, offset + got);
      if (bytesRead === 0) break;
      got += bytesRead;
    }
    return { bytes: got === want ? out : out.slice(0, got), gone: false };
  } catch (error) {
    return { bytes: null, gone: false, error: String(error) };
  } finally {
    await handle.close();
  }
}
