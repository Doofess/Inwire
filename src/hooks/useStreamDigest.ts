/**
 * The store's stream digest, kept current by polling (ADR 0055).
 *
 * Polled rather than pushed: the store answers `changedSince(version)`, so a
 * quiet capture costs one empty message a second, and nothing is sent while
 * the Conversations tab is not showing the TCP level.
 *
 * The answer's `captureId` is the capture the version belongs to. A version
 * means nothing across captures, so when it changes everything held here is
 * dropped and the new capture is asked from zero at once - and the first
 * answer after a reopen may arrive before the store's `ready` does, which is
 * why the capture id is read from the answer and not from the client's state.
 *
 * The id is returned as well, because a reader that keeps anything of its own
 * per stream - the Follow Stream pane's frames, read once through a summary -
 * has the same problem one level up: a stream index is unique within one
 * capture only, and a restart or an import under an open view would leave it
 * showing the dead capture's frames as the live one's. Null when no capture
 * has answered, which a reader treats as a change like any other.
 */
import { useEffect, useState } from 'react';
import { captureStore } from '../services/capture/captureClient';
import type { StreamSummary } from '../services/conversation/streamDigest';

const POLL_MS = 1000;

export function useStreamDigest(enabled: boolean) {
  const [summaries, setSummaries] = useState<Map<number, StreamSummary>>(() => new Map());
  const [rebuilding, setRebuilding] = useState<{ done: number; total: number } | null>(null);
  const [captureId, setCaptureId] = useState<string | null>(null);

  useEffect(() => {
    if (!enabled) return;
    let version = 0;
    let answering: string | null = null;
    let alive = true;
    let timer = 0;
    const poll = async () => {
      const since = version;
      const answer = await captureStore.streamDigest(since);
      if (!alive) return;
      if (answer.captureId !== answering) {
        // Another capture answered. Whatever was held is the last one's.
        answering = answer.captureId;
        setCaptureId(answer.captureId);
        setSummaries(new Map());
        if (since !== 0) {
          // It was asked with the last capture's version, so this answer is
          // a partial one: ask it again from zero, now.
          version = 0;
          setRebuilding(answer.rebuilding);
          timer = window.setTimeout(poll, 0);
          return;
        }
        // Asked from zero, the answer is already the whole of the new
        // capture - the first poll on every enable - so it is used, not
        // thrown away and asked for a second time.
      }
      version = answer.version;
      if (answer.summaries.length > 0) {
        setSummaries((current) => {
          const next = new Map(current);
          for (const s of answer.summaries) next.set(s.streamId, s);
          return next;
        });
      }
      setRebuilding(answer.rebuilding);
      timer = window.setTimeout(poll, POLL_MS);
    };
    void poll();
    return () => { alive = false; window.clearTimeout(timer); };
  }, [enabled]);

  return { summaries, rebuilding, captureId };
}
