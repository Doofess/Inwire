/**
 * The collector's template store for NetFlow v9 and IPFIX (ADRs 0064, 0065).
 *
 * The tree's `MemoryTemplateStore` keeps the first definition and never lets
 * one go; this is the opposite on purpose. A collector's history must decode
 * with exactly the templates that were in force, so here:
 *
 * - a template lives in one **scope** and in no other: v9 is (exporter, Source
 *   ID), IPFIX over UDP is (exporter, source port, Observation Domain);
 * - a redefinition with other specifiers replaces, the same specifiers refresh;
 * - a template **expires** unless it keeps being re-sent - both a time and a
 *   message condition must pass, because the exporters measured refresh by
 *   count, not by time;
 * - a restart (v9 `sysUptime` going back, an IPFIX source port changing, IE 160
 *   changing) invalidates the whole scope;
 * - the bounds refuse, never evict: an exporter opens at most `LIMITS.enginesPerExporter` scopes (`canOpen`),
 *   and a start boundary naming another exporter drops the old exporter's scopes (`retainExporter`), so a
 *   checkpoint never holds two exporters' scopes of one protocol, domain and port.
 *
 * Counting: a scope's message counter increments in `beginDatagram`, before the
 * expiry check, so the datagram doing the checking counts itself. A template
 * received in message m has been unseen for k messages at message m + k.
 *
 * The state is derived and is checkpointed (`checkpoint.ts`): every fact that
 * changes a later decision is a field of `ScopeSnapshot`, which is the
 * checkpoint's own shape. The counters are not durable.
 *
 * Pure: no `node:*`, no Electron, like everything under `src/services/`.
 */
import type { FlowTemplate, FlowTemplateField } from '../flow/flowExport';
import { LIMITS } from './types';

export interface TemplateScope {
  protocol: 'v9' | 'ipfix';
  exporter: string;
  /** The IPFIX scope's exporter source port; null for v9, whose scope has no port. */
  exporterPort: number | null;
  domain: number;
}

export type TemplateOutcome = 'defined' | 'refreshed' | 'replaced' | 'withdrawal-ignored' | 'refused-bound';

export interface StoredTemplate extends FlowTemplate {
  id: number;
  /** An options template: v9's, or IPFIX's with a scope. */
  options: boolean;
  definedEntryId: number;
  lastSeenMs: number;
  /** The scope's message count at the last receipt. */
  lastSeenMessage: number;
  /** The longest receipt-time interval observed between refreshes; 0 until one has been. */
  intervalMs: number;
  intervalMessages: number;
  /** Last received in an earlier collection session (ADR 0065): the next receipt measures no interval. */
  previousSession: boolean;
}

export interface TemplateInventory {
  scope: TemplateScope;
  id: number;
  options: boolean;
  fields: FlowTemplateField[];
  notInterpreted: { pen: number | null; ie: number }[];
  /** The counts are totals (IE 85/86), not deltas: a long-lived flow is counted again at each export. */
  totalCounts: boolean;
  /** A data template with no octet count: its records are counted, never totalled. */
  unsupported: boolean;
  definedEntryId: number;
  lastSeenMs: number;
}

/** One scope as the checkpoint holds it. */
export interface ScopeSnapshot {
  protocol: 'v9' | 'ipfix';
  exporter: string;
  /** IPFIX: the scope's source port. v9: the last one seen. */
  port: number;
  domain: number;
  uptimeMs: number | null;
  systemInitMs: number | null;
  /** A collection gap has ended since this scope's last datagram (ADR 0065). */
  gap: boolean;
  messages: number;
  templates: StoredTemplate[];
}

const HOUR = 3_600_000;
const U32 = 2 ** 32;

// --- what a template means ------------------------------------------------------------------------------

/** The reverse direction's enterprise number (RFC 5103). */
export const REVERSE_PEN = 29305;

const between = (lo: number, hi: number) => (n: number) => n >= lo && n <= hi;
const exactly = (n: number) => (len: number) => len === n;

/** The elements a data record is read for, and the lengths each may have. Anything else is kept, not interpreted. */
const DATA_ELEMENTS: Record<number, (length: number) => boolean> = {
  1: between(1, 8), 2: between(1, 8), 85: between(1, 8), 86: between(1, 8),
  4: exactly(1), 6: between(1, 2), 7: between(1, 2), 11: between(1, 2),
  8: exactly(4), 12: exactly(4), 27: exactly(16), 28: exactly(16),
  10: between(1, 4), 14: between(1, 4), 61: exactly(1),
  34: between(1, 4), 48: between(1, 4), 50: between(1, 4), 302: between(1, 8),
  21: exactly(4), 22: exactly(4),
  150: exactly(4), 151: exactly(4), 152: exactly(8), 153: exactly(8),
  154: exactly(8), 155: exactly(8), 156: exactly(8), 157: exactly(8),
  158: exactly(4), 159: exactly(4),
};

/** The elements an options record is read for. IE 82 is a string, so any length, variable included. */
const OPTIONS_ELEMENTS: Record<number, (length: number) => boolean> = {
  34: between(1, 4), 35: between(1, 2), 48: between(1, 4), 49: between(1, 2), 50: between(1, 4),
  82: () => true, 160: exactly(8), 302: between(1, 8), 304: between(1, 2), 305: between(1, 4), 306: between(1, 4),
};

const COUNT_ELEMENTS: ReadonlySet<number> = new Set([1, 2, 85, 86]);

/** Whether this field of a data template is one the decoder reads. */
export function isInterpretedDataField(f: FlowTemplateField): boolean {
  if (f.pen !== undefined) return f.pen === REVERSE_PEN && COUNT_ELEMENTS.has(f.type) && DATA_ELEMENTS[f.type](f.length);
  const ok = DATA_ELEMENTS[f.type];
  return ok !== undefined && ok(f.length);
}

export function isInterpretedOptionsField(f: FlowTemplateField): boolean {
  if (f.pen !== undefined) return false;
  const ok = OPTIONS_ELEMENTS[f.type];
  return ok !== undefined && ok(f.length);
}

export function isOptionsTemplate(t: FlowTemplate): boolean {
  return t.v9Options === true || t.scopeCount > 0;
}

export interface TemplateShape {
  options: boolean;
  /** The octet and packet counts come from IE 85/86: the template has no delta count (RFC 3954 and 7011 both warn of the double count). */
  totalCounts: boolean;
  /** A data template with no octet count of any usable kind. */
  unsupported: boolean;
  notInterpreted: { pen: number | null; ie: number }[];
}

const shapes = new WeakMap<FlowTemplate, TemplateShape>();

/** What a template is for, computed once per template object. */
export function templateShape(t: FlowTemplate): TemplateShape {
  const cached = shapes.get(t);
  if (cached !== undefined) return cached;
  const options = isOptionsTemplate(t);
  const notInterpreted: { pen: number | null; ie: number }[] = [];
  const seen = new Set<string>();
  const note = (f: FlowTemplateField) => {
    const key = `${f.pen ?? ''}/${f.type}`;
    if (seen.has(key)) return;
    seen.add(key);
    notInterpreted.push({ pen: f.pen ?? null, ie: f.type });
  };
  let totalCounts = false;
  let unsupported = false;
  if (options) {
    // The scope fields name what the record is about; only the option fields are listed.
    t.fields.forEach((f, i) => { if (i >= t.scopeCount && !isInterpretedOptionsField(f)) note(f); });
  } else {
    let deltas = false;
    let deltaOctets = false;
    let totalOctets = false;
    for (const f of t.fields) {
      if (!isInterpretedDataField(f)) { note(f); continue; }
      if (f.pen !== undefined) continue;
      if (f.type === 1 || f.type === 2) deltas = true;
      if (f.type === 1) deltaOctets = true;
      if (f.type === 85) totalOctets = true;
    }
    totalCounts = !deltas && totalOctets;
    unsupported = !(deltaOctets || totalCounts);
  }
  const shape = { options, totalCounts, unsupported, notInterpreted };
  shapes.set(t, shape);
  return shape;
}

// --- the store ---------------------------------------------------------------------------------------------

interface ScopeState {
  protocol: 'v9' | 'ipfix';
  exporter: string;
  port: number;
  domain: number;
  templates: Map<number, StoredTemplate>;
  messages: number;
  gap: boolean;
  uptimeMs: number | null;
  systemInitMs: number | null;
  withdrawalsIgnored: number;
  refused: number;
  restarts: number;
  /** Template ids refused under the bounds, so their data is counted as refused and not as awaiting. Not durable. */
  refusedIds: Set<number>;
}

const specifierBytes = (t: FlowTemplate): number => t.fields.reduce((n, f) => n + (f.pen !== undefined ? 8 : 4), 0);

function sameSpecifiers(a: FlowTemplate, b: FlowTemplate): boolean {
  if (a.scopeCount !== b.scopeCount || (a.v9Options === true) !== (b.v9Options === true) || a.fields.length !== b.fields.length) return false;
  for (let i = 0; i < a.fields.length; i++) {
    const x = a.fields[i];
    const y = b.fields[i];
    if (x.type !== y.type || x.length !== y.length || x.pen !== y.pen) return false;
  }
  return true;
}

const clamp32 = (n: number): number => Math.min(Math.max(n, 0), U32 - 1);

export class CollectorTemplateStore {
  private readonly scopes = new Map<string, ScopeState>();
  private templateCount = 0;
  private fieldBytes = 0;

  private static key(scope: { protocol: string; exporter: string; domain: number }): string {
    return `${scope.protocol}/${scope.exporter}/${scope.domain}`;
  }

  /** The scope's state when `scope` names it: an IPFIX scope is its source port too, so another port finds nothing. */
  private find(scope: TemplateScope): ScopeState | null {
    const st = this.scopes.get(CollectorTemplateStore.key(scope));
    if (st === undefined) return null;
    if (scope.protocol === 'ipfix' && st.port !== (scope.exporterPort ?? 0)) return null;
    return st;
  }

  private fresh(scope: TemplateScope): ScopeState {
    return {
      protocol: scope.protocol, exporter: scope.exporter, port: scope.exporterPort ?? 0, domain: scope.domain,
      templates: new Map(), messages: 0, gap: false, uptimeMs: null, systemInitMs: null,
      withdrawalsIgnored: 0, refused: 0, restarts: 0, refusedIds: new Set(),
    };
  }

  /**
   * Whether a datagram of `scope` may be counted by it: the scope exists, or its exporter has fewer than
   * `LIMITS.enginesPerExporter` scopes. A datagram that may not creates nothing - no scope, no source.
   */
  canOpen(scope: TemplateScope): boolean {
    if (this.scopes.has(CollectorTemplateStore.key(scope))) return true;
    let held = 0;
    for (const st of this.scopes.values()) if (st.exporter === scope.exporter) held++;
    return held < LIMITS.enginesPerExporter;
  }

  /** Drops every scope, templates included, that is not `exporter`'s: a start boundary naming another exporter (the owner changed it). */
  retainExporter(exporter: string): void {
    for (const [key, st] of [...this.scopes]) {
      if (st.exporter === exporter) continue;
      this.forget(st);
      this.scopes.delete(key);
    }
  }

  private forget(st: ScopeState): void {
    for (const t of st.templates.values()) { this.templateCount--; this.fieldBytes -= specifierBytes(t); }
    st.templates.clear();
    st.refusedIds.clear();
  }

  /**
   * Once per non-malformed datagram of the scope, before any set. It counts the
   * message, detects a restart, applies the gap flag, and expires templates
   * under both lifetime conditions. `remotePort` is a v9 datagram's sender
   * port, which the checkpoint keeps as "the last seen"; IPFIX has its own in
   * the scope.
   */
  beginDatagram(scope: TemplateScope, receivedMs: number, uptimeMs: number | null, remotePort: number | null = null): 'ok' | 'restart' {
    let restart = false;
    let st = this.find(scope);
    if (st === null) {
      const key = CollectorTemplateStore.key(scope);
      const old = this.scopes.get(key);
      st = this.fresh(scope);
      if (old !== undefined) {
        // The same exporter and domain from another source port: the old scope is dropped, its counters go on.
        this.forget(old);
        st.withdrawalsIgnored = old.withdrawalsIgnored;
        st.refused = old.refused;
        st.restarts = old.restarts + 1;
        st.messages = old.messages;
        restart = true;
      }
      this.scopes.set(key, st);
    }
    if (scope.protocol === 'v9' && remotePort !== null) st.port = remotePort;
    st.messages++;

    if (uptimeMs !== null) {
      const prev = st.uptimeMs;
      if (prev === null) {
        st.uptimeMs = uptimeMs;
      } else {
        const wrapped = prev > U32 - HOUR && uptimeMs < HOUR;
        const back = !wrapped && prev - uptimeMs > LIMITS.restartToleranceMs;
        if (back) {
          restart = true;
          this.forget(st);
          st.restarts++;
        }
        // A small step back is a reordered datagram: it moves nothing.
        if (back || wrapped || uptimeMs >= prev) st.uptimeMs = uptimeMs;
      }
    }

    const gap = st.gap;
    st.gap = false;
    for (const [id, t] of st.templates) {
      const timeOut = receivedMs - t.lastSeenMs > Math.max(LIMITS.templateLifetimeMinMs, 3 * t.intervalMs);
      const messagesOut = gap || st.messages - t.lastSeenMessage > Math.max(LIMITS.templateLifetimeMinMessages, 3 * t.intervalMessages);
      if (timeOut && messagesOut) {
        st.templates.delete(id);
        this.templateCount--;
        this.fieldBytes -= specifierBytes(t);
      }
    }
    return restart ? 'restart' : 'ok';
  }

  /** Defines or refreshes a template of a scope at the entry that carried it. */
  define(scope: TemplateScope, id: number, t: FlowTemplate, entryId: number, receivedMs: number): TemplateOutcome {
    let st = this.find(scope);
    if (st === null) {
      st = this.fresh(scope);
      this.scopes.set(CollectorTemplateStore.key(scope), st);
    }
    const existing = st.templates.get(id);
    if (existing !== undefined && sameSpecifiers(existing, t)) {
      if (existing.previousSession) {
        existing.previousSession = false;
      } else {
        existing.intervalMs = Math.max(existing.intervalMs, clamp32(receivedMs - existing.lastSeenMs));
        existing.intervalMessages = Math.max(existing.intervalMessages, clamp32(st.messages - existing.lastSeenMessage));
      }
      existing.lastSeenMs = receivedMs;
      existing.lastSeenMessage = st.messages;
      st.refusedIds.delete(id);
      return 'refreshed';
    }
    const bytes = specifierBytes(t);
    const others = existing === undefined ? 0 : 1;
    const refuse = st.templates.size - others >= LIMITS.templatesPerScope
      || this.templateCount - others >= LIMITS.templates
      || this.fieldBytes - (existing === undefined ? 0 : specifierBytes(existing)) + bytes > LIMITS.templateFieldBytes;
    if (existing !== undefined) {
      st.templates.delete(id);
      this.templateCount--;
      this.fieldBytes -= specifierBytes(existing);
    }
    if (refuse) {
      st.refused++;
      st.refusedIds.add(id);
      return 'refused-bound';
    }
    st.refusedIds.delete(id);
    st.templates.set(id, {
      scopeCount: t.scopeCount, fields: t.fields.map((f) => ({ ...f })), ...(t.v9Options === true ? { v9Options: true } : {}),
      id, options: isOptionsTemplate(t), definedEntryId: entryId, lastSeenMs: receivedMs, lastSeenMessage: st.messages,
      intervalMs: 0, intervalMessages: 0, previousSession: false,
    });
    this.templateCount++;
    this.fieldBytes += bytes;
    return existing === undefined ? 'defined' : 'replaced';
  }

  /** An IPFIX withdrawal or withdraw-all received over UDP: counted, changes nothing (RFC 7011 section 8.4). */
  withdrawalIgnored(scope: TemplateScope): void {
    let st = this.find(scope);
    if (st === null) {
      st = this.fresh(scope);
      this.scopes.set(CollectorTemplateStore.key(scope), st);
    }
    st.withdrawalsIgnored++;
  }

  lookup(scope: TemplateScope, id: number): StoredTemplate | null {
    return this.find(scope)?.templates.get(id) ?? null;
  }

  /** Whether `id` was refused under the bounds and not defined since: its data is counted as refused. */
  isRefused(scope: TemplateScope, id: number): boolean {
    return this.find(scope)?.refusedIds.has(id) === true;
  }

  /**
   * IE 160 from an options record. A change of more than 10 s is a restart: it
   * removes the scope's templates received in earlier datagrams and keeps those
   * received in this one (`keepDefinedAtEntry` is this datagram's entry id).
   */
  observeSystemInit(scope: TemplateScope, systemInitMs: number, keepDefinedAtEntry: number): 'ok' | 'restart' {
    const st = this.find(scope);
    if (st === null) return 'ok';
    const previous = st.systemInitMs;
    st.systemInitMs = systemInitMs;
    if (previous === null || Math.abs(systemInitMs - previous) <= LIMITS.restartToleranceMs) return 'ok';
    for (const [id, t] of st.templates) {
      if (t.definedEntryId >= keepDefinedAtEntry || t.lastSeenMessage === st.messages) continue;
      st.templates.delete(id);
      this.templateCount--;
      this.fieldBytes -= specifierBytes(t);
    }
    st.restarts++;
    return 'restart';
  }

  /** A start, resume or gap boundary (ADR 0065). */
  gapEnded(): void {
    for (const st of this.scopes.values()) {
      st.gap = true;
      for (const t of st.templates.values()) t.previousSession = true;
    }
  }

  /** The IE 160 a scope last stated, or null: IPFIX uptime-relative flow times need it. */
  systemInitMs(scope: TemplateScope): number | null {
    return this.find(scope)?.systemInitMs ?? null;
  }

  inventory(): TemplateInventory[] {
    const out: TemplateInventory[] = [];
    for (const snap of this.exportScopes()) {
      const scope: TemplateScope = { protocol: snap.protocol, exporter: snap.exporter, exporterPort: snap.protocol === 'ipfix' ? snap.port : null, domain: snap.domain };
      for (const t of snap.templates) {
        const shape = templateShape(t);
        out.push({
          scope, id: t.id, options: t.options, fields: t.fields.map((f) => ({ ...f })),
          notInterpreted: shape.notInterpreted.map((n) => ({ ...n })), totalCounts: shape.totalCounts, unsupported: shape.unsupported,
          definedEntryId: t.definedEntryId, lastSeenMs: t.lastSeenMs,
        });
      }
    }
    return out;
  }

  counters(scope: TemplateScope): { withdrawalsIgnored: number; refused: number; restarts: number; messages: number } {
    const st = this.find(scope);
    return st === null
      ? { withdrawalsIgnored: 0, refused: 0, restarts: 0, messages: 0 }
      : { withdrawalsIgnored: st.withdrawalsIgnored, refused: st.refused, restarts: st.restarts, messages: st.messages };
  }

  /** Every scope in the checkpoint's order: protocol, then Source ID or domain, then port; templates by id. */
  exportScopes(): ScopeSnapshot[] {
    return [...this.scopes.values()]
      .sort((a, b) => (a.protocol === b.protocol ? 0 : a.protocol === 'v9' ? -1 : 1) || a.domain - b.domain || a.port - b.port)
      .map((st) => ({
        protocol: st.protocol, exporter: st.exporter, port: st.port, domain: st.domain, uptimeMs: st.uptimeMs, systemInitMs: st.systemInitMs,
        gap: st.gap, messages: st.messages, templates: [...st.templates.values()].sort((a, b) => a.id - b.id),
      }));
  }

  /** A store holding exactly these scopes, or null if they break a bound or repeat a scope. */
  static fromScopes(scopes: ScopeSnapshot[]): CollectorTemplateStore | null {
    const store = new CollectorTemplateStore();
    const perExporter = new Map<string, number>();
    for (const snap of scopes) {
      const key = CollectorTemplateStore.key(snap);
      if (store.scopes.has(key) || snap.templates.length > LIMITS.templatesPerScope) return null;
      const held = (perExporter.get(snap.exporter) ?? 0) + 1;
      if (held > LIMITS.enginesPerExporter) return null;
      perExporter.set(snap.exporter, held);
      const st: ScopeState = {
        protocol: snap.protocol, exporter: snap.exporter, port: snap.port, domain: snap.domain, templates: new Map(),
        messages: snap.messages, gap: snap.gap, uptimeMs: snap.uptimeMs, systemInitMs: snap.systemInitMs,
        withdrawalsIgnored: 0, refused: 0, restarts: 0, refusedIds: new Set(),
      };
      for (const t of snap.templates) {
        st.templates.set(t.id, t);
        store.templateCount++;
        store.fieldBytes += specifierBytes(t);
      }
      store.scopes.set(key, st);
    }
    return store.templateCount > LIMITS.templates || store.fieldBytes > LIMITS.templateFieldBytes ? null : store;
  }
}
