/**
 * Everything the dissectors and the anomaly detector had to say, in one list.
 *
 * The app raised findings in two unrelated places. Dissectors attached
 * `expertInfo` to tree rows in Wireshark's `chat/note/warn/error`, and the
 * anomaly detector produced `AnomalyInfo` in `low/medium/high/critical`;
 * nothing related the two, so the same frame could be a "warning" in the tree
 * and a "high" in the alerts panel and no view could rank one against the
 * other. `ExpertSeverity` in `types/packet.ts` is now the single vocabulary,
 * and this module is the single list.
 *
 * Aggregation follows Wireshark's Expert Information dialog: identical
 * findings collapse into one row with a count and the frames behind it,
 * because a capture with four hundred retransmissions has one problem, not
 * four hundred - and the four hundred frame numbers are still there for
 * whoever wants to look at frame one.
 */

import {
  AnomalyInfo, ExpertGroup, ExpertSeverity, Packet, ProtocolField,
} from '../types/packet';

export const SEVERITY_ORDER: readonly ExpertSeverity[] = ['error', 'warn', 'note', 'chat'];

export const SEVERITY_LABELS: Record<ExpertSeverity, string> = {
  error: 'Error',
  warn: 'Warning',
  note: 'Note',
  chat: 'Chat',
};

/**
 * One colour per severity, here rather than in a component, because the packet
 * list, the detail tree and the Expert Information tab all draw it and a level
 * has to mean one thing in all three - which is the point of having unified
 * the two severity vocabularies at all.
 */
export const SEVERITY_DOT: Record<ExpertSeverity, string> = {
  error: 'bg-rose-500',
  warn: 'bg-amber-500',
  note: 'bg-sky-500',
  chat: 'bg-muted-foreground/50',
};

export const SEVERITY_TEXT: Record<ExpertSeverity, string> = {
  error: 'text-rose-600 dark:text-rose-400',
  warn: 'text-amber-600 dark:text-amber-400',
  note: 'text-sky-600 dark:text-sky-400',
  chat: 'text-muted-foreground',
};

/**
 * The anomaly detector's four levels onto the shared four.
 *
 * `critical` and `high` are both errors: the detector's split between them is
 * about how alarming the finding is, and Wireshark's `error` already means
 * "this is broken" rather than "this is the worst thing here". `low` is a
 * note rather than chat, because the detector does not raise anything it
 * considers routine - `chat` is for a dissector remarking on normal traffic.
 */
const ANOMALY_SEVERITY: Record<AnomalyInfo['severity'], ExpertSeverity> = {
  critical: 'error',
  high: 'error',
  medium: 'warn',
  low: 'note',
};

export interface ExpertItem {
  frame: number;
  severity: ExpertSeverity;
  group: ExpertGroup;
  summary: string;
  /** The protocol the frame was labelled as, for the "Protocol" column. */
  protocol: string;
}

/** Identical findings, collapsed. */
export interface ExpertGroupRow {
  key: string;
  severity: ExpertSeverity;
  group: ExpertGroup;
  summary: string;
  protocol: string;
  count: number;
  /** Frames that raised it, capped - the list is for jumping, not for export. */
  frames: number[];
}

/** How many frames a group row remembers. Enough to jump around, not a copy of the capture. */
const MAX_REMEMBERED_FRAMES = 200;

function severityRank(s: ExpertSeverity): number {
  return SEVERITY_ORDER.indexOf(s);
}

/**
 * The findings in one frame.
 *
 * Walks the tree rather than taking a channel of its own, so a dissector that
 * attaches an expert row is listed here with no further plumbing - which is
 * the same arrangement the name map uses, and for the same reason: one place
 * to add a fact, several places that read it.
 */
export function expertItemsFor(packet: Packet): ExpertItem[] {
  const out: ExpertItem[] = [];
  const protocol = packet.protocolLabel ?? packet.protocol;

  // The flat list the dissector published. It is the whole answer for a frame
  // that has one: the tree is dissected on demand now (docs/decisions/0007),
  // so aggregating over the buffer by walking trees would find nothing at all
  // for every frame nobody had clicked on.
  if (packet.expert) {
    for (const finding of packet.expert) {
      out.push({
        frame: packet.id,
        severity: finding.severity,
        group: finding.group ?? 'Protocol',
        summary: finding.message,
        protocol,
      });
    }
  }

  // The tree, for a frame that came from somewhere that predates the flat list
  // - a restored session written by an older build, or a custom dissector's
  // output. Skipped when the flat list is present, which is what stops a
  // hydrated frame's findings being counted twice.
  const visit = (fields: ProtocolField[]) => {
    for (const field of fields) {
      if (field.expertInfo) {
        out.push({
          frame: packet.id,
          severity: field.expertInfo.severity,
          group: field.expertInfo.group ?? 'Protocol',
          summary: field.expertInfo.message,
          protocol,
        });
      }
      if (field.children) visit(field.children);
    }
  };
  for (const layer of packet.layers) visit(layer.fields);

  for (const anomaly of packet.anomalies ?? []) {
    out.push({
      frame: packet.id,
      severity: ANOMALY_SEVERITY[anomaly.severity],
      group: 'Security',
      summary: anomaly.title,
      protocol,
    });
  }

  return out;
}

/**
 * The running expert log.
 *
 * A class with `add` rather than a function over the buffer, so it can be
 * folded one packet at a time by `useIncrementalAggregate` - a full walk of
 * every layer of 50,000 frames ten times a second is exactly the cost that
 * hook exists to avoid.
 */
export class ExpertLog {
  private rows = new Map<string, ExpertGroupRow>();
  /** The worst severity each frame raised, for the list's severity column. */
  private worst = new Map<number, ExpertSeverity>();
  private total = 0;

  add(packet: Packet): void {
    for (const item of expertItemsFor(packet)) {
      this.total++;
      const key = `${item.severity}|${item.group}|${item.summary}`;
      const row = this.rows.get(key);
      if (row) {
        row.count++;
        if (row.frames.length < MAX_REMEMBERED_FRAMES) row.frames.push(item.frame);
      } else {
        this.rows.set(key, {
          key, severity: item.severity, group: item.group, summary: item.summary,
          protocol: item.protocol, count: 1, frames: [item.frame],
        });
      }

      const current = this.worst.get(item.frame);
      if (current === undefined || severityRank(item.severity) < severityRank(current)) {
        this.worst.set(item.frame, item.severity);
      }
    }
  }

  /** Group rows, worst first, then commonest. */
  groups(): ExpertGroupRow[] {
    return [...this.rows.values()].sort(
      (a, b) => severityRank(a.severity) - severityRank(b.severity) || b.count - a.count,
    );
  }

  /** How many findings at each level, for the summary strip. */
  counts(): Record<ExpertSeverity, number> {
    const out: Record<ExpertSeverity, number> = { error: 0, warn: 0, note: 0, chat: 0 };
    for (const row of this.rows.values()) out[row.severity] += row.count;
    return out;
  }

  /** The worst thing this frame raised, for the packet list's severity dot. */
  severityOf(frame: number): ExpertSeverity | undefined {
    return this.worst.get(frame);
  }

  get size(): number {
    return this.total;
  }
}

/**
 * The read-only face, for components.
 *
 * Same reason as the name map's: the fold keeps one accumulator across ticks,
 * so handing the log itself to a memo would hand it a value whose identity
 * never changes.
 */
export interface ExpertLookup {
  groups(): ExpertGroupRow[];
  counts(): Record<ExpertSeverity, number>;
  severityOf(frame: number): ExpertSeverity | undefined;
  readonly size: number;
}

export function expertSnapshot(log: ExpertLog): ExpertLookup {
  return {
    groups: () => log.groups(),
    counts: () => log.counts(),
    severityOf: (frame) => log.severityOf(frame),
    get size() { return log.size; },
  };
}

/** Builds a log from a whole buffer, for tests and one-off analysis. */
export function buildExpertLog(packets: readonly Packet[]): ExpertLog {
  const log = new ExpertLog();
  for (const packet of packets) log.add(packet);
  return log;
}
