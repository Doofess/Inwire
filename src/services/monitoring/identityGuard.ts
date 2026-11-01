/**
 * The per-minute bound on an exporter's identities (ADR 0070).
 *
 * An exporter that rotates identities faster than once a minute would give a minute more rows than
 * `MAX_APPEND_BYTES` and the held-back fragments can carry. So within one receipt minute an exporter
 * is admitted at most `LIMITS.enginesPerExporter` distinct identities (source keys); a datagram of one
 * more is churn, and every reader counts it as unsupported.
 *
 * The held set is replaced only by a later minute; a datagram stamped earlier than the held minute (the receipt
 * clock stepped back) counts against the newest set. Which set is held depends only on the entries since the last
 * reset, so every reader holds the same one.
 *
 * Reset at a segment's first entry and at a stop, a suspend and an interrupted boundary, so every
 * checkpoint lies at a reset and the set is never checkpointed: live, rebuild and replay agree.
 * Pure: no `node:*`, no Electron.
 */
import { LIMITS } from './types';

const MINUTE_MS = 60_000;

interface Held { minuteMs: number; keys: Set<string> }

export class IdentityMinuteGuard {
  private readonly held = new Map<string, Held>();

  /** True when `sourceKey` may count in `exporter`'s minute; false when it would be one identity too many. */
  admit(exporter: string, sourceKey: string, receivedMs: number): boolean {
    const minuteMs = Math.floor(receivedMs / MINUTE_MS) * MINUTE_MS;
    let h = this.held.get(exporter);
    // Only a later minute replaces the set. A clock that steps back (B, A, B) must not hand minute B sixteen new
    // identities at every re-entry: the earlier datagram counts against the newest set held.
    if (h === undefined || minuteMs > h.minuteMs) {
      h = { minuteMs, keys: new Set() };
      this.held.set(exporter, h);
    }
    if (h.keys.has(sourceKey)) return true;
    if (h.keys.size >= LIMITS.enginesPerExporter) return false;
    h.keys.add(sourceKey);
    return true;
  }

  reset(): void { this.held.clear(); }
}
