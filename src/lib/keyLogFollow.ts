/**
 * The renderer's end of the followed TLS key log.
 *
 * Main reads the file and sends complete lines as text
 * (`electron/keyLogFollower.ts`, which carries the reason a key log is
 * followed rather than read once). This hands each chunk to BOTH stores, for
 * the reason `DecryptionSettingsPanel` already gives: live capture is
 * dissected in the pipeline Worker with its own module instance of `keyLog`,
 * and an import is dissected here.
 *
 * Started once from `App`'s mount rather than from the panel, because the
 * panel only exists while Settings is open - and a follow that only ran while
 * somebody was looking at it would decrypt nothing.
 */
import { keyLog } from '../services/tls/keyLog';
import { pipeline } from '../services/pipelineClient';

/**
 * `KeyLogFollowStatus` from `electron/keyLogTail.ts`, restated.
 *
 * Restated rather than imported: `electron/` is excluded from the renderer's
 * program on purpose (`scripts/electron/tsconfigs.ts`), and reaching across
 * would pull main's module into it. `narrowStatus` below is what keeps the two
 * honest at runtime - a field main stops sending reads as absent, not as a
 * wrong value.
 */
export interface KeyLogFollowStatus {
  path: string | null;
  state: 'off' | 'following' | 'missing' | 'unreadable';
  bytes: number;
  suggested: string | null;
  error?: string;
}

const STATES = new Set(['off', 'following', 'missing', 'unreadable']);

export function narrowStatus(value: unknown): KeyLogFollowStatus | null {
  if (typeof value !== 'object' || value === null) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.state !== 'string' || !STATES.has(v.state)) return null;
  return {
    path: typeof v.path === 'string' ? v.path : null,
    state: v.state as KeyLogFollowStatus['state'],
    bytes: typeof v.bytes === 'number' ? v.bytes : 0,
    suggested: typeof v.suggested === 'string' ? v.suggested : null,
    ...(typeof v.error === 'string' ? { error: v.error } : {}),
  };
}

let status: KeyLogFollowStatus | null = null;
const listeners = new Set<() => void>();
let started = false;

const notify = (): void => {
  for (const listener of listeners) listener();
};

export function keyLogFollowStatus(): KeyLogFollowStatus | null {
  return status;
}

/** Called on every status change AND every chunk, so the panel's counts move. */
export function onKeyLogFollow(listener: () => void): () => void {
  listeners.add(listener);
  return () => { listeners.delete(listener); };
}

/** Starts receiving. Idempotent: `App` may mount twice under StrictMode. */
export function startKeyLogFollow(): void {
  if (started) return;
  const bridge = typeof window === 'undefined' ? undefined : window.inwire;
  if (!bridge?.attachKeyLog || !bridge.onKeyLogText || !bridge.onKeyLogStatus) return;
  started = true;

  // Subscribed BEFORE attaching, because attaching is what makes main send the
  // whole file from the top - a listener registered after would miss it.
  bridge.onKeyLogText((text) => {
    keyLog.add(text);
    pipeline.addKeyLog(text);
    notify();
  });
  bridge.onKeyLogStatus((value) => {
    const next = narrowStatus(value);
    if (next !== null) { status = next; notify(); }
  });
  void bridge.attachKeyLog().then((value) => {
    const next = narrowStatus(value);
    if (next !== null) { status = next; notify(); }
  });
}

/** The panel's three actions. Each answers with the new status. */
export async function chooseKeyLog(): Promise<void> {
  apply(await window.inwire?.chooseKeyLog?.());
}

export async function followSuggestedKeyLog(): Promise<void> {
  apply(await window.inwire?.followSuggestedKeyLog?.());
}

export async function forgetKeyLog(): Promise<void> {
  apply(await window.inwire?.forgetKeyLog?.());
}

function apply(value: unknown): void {
  const next = narrowStatus(value);
  if (next !== null) { status = next; notify(); }
}
