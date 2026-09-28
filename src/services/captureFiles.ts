import type { AgentCaptureFileMessage, AgentCaptureStoppedMessage } from './agentProtocol';

/**
 * The capture's own pcapng files, as the agent reports them (ADR 0052).
 *
 * The agent writes them into the capture's folder and says when each opens,
 * closes and - in a ring - is deleted. This is the app's record of that: one
 * entry per file, the latest report winning, in file order. Pure, so
 * `scripts/session/capture-files.ts` can hold the rules without React.
 */
export interface CaptureFile {
  /** 1-based, Wireshark's `_00001`. */
  index: number;
  /** A name within the capture's `pcapng` folder, never a path. */
  name: string;
  state: AgentCaptureFileMessage['state'];
  /** The sequence numbers of the frames it holds; null until it holds one. */
  firstSeq: number | null;
  lastSeq: number | null;
  frames: number;
  bytes: number;
}

/**
 * `files` with one report applied: the file's entry replaced, or added in
 * index order. A report for a file already deleted is not allowed to bring
 * it back - the agent reports a deletion last, and a closed report arriving
 * after it would otherwise list a file that is not on disk.
 */
export function applyCaptureFile(
  files: readonly CaptureFile[], report: AgentCaptureFileMessage,
): CaptureFile[] {
  const entry: CaptureFile = {
    index: report.index,
    name: report.name,
    state: report.state,
    firstSeq: report.firstSeq,
    lastSeq: report.lastSeq,
    frames: report.frames,
    bytes: report.bytes,
  };
  const at = files.findIndex((f) => f.index === report.index);
  if (at === -1) return [...files, entry].sort((a, b) => a.index - b.index);
  if (files[at].state === 'deleted') return [...files];
  const next = [...files];
  next[at] = entry;
  return next;
}

/** The files still on disk. */
export function keptFiles(files: readonly CaptureFile[]): CaptureFile[] {
  return files.filter((f) => f.state !== 'deleted');
}

/** Why the agent stopped the capture itself, as the end of a sentence. */
export function stopReasonText(reason: AgentCaptureStoppedMessage['reason']): string {
  switch (reason) {
    case 'packets': return 'it reached its packet limit';
    case 'bytes': return 'it reached its size limit';
    case 'seconds': return 'it reached its time limit';
    case 'files': return 'it reached its file limit';
  }
}
