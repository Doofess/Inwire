/**
 * Everything the dissectors had to say about a frame, in one list.
 *
 * Findings used to carry a **severity** - Wireshark's `chat/note/warn/error` -
 * and it was removed rather than refined, because measured over both fixtures
 * it was mostly wrong. `error/Checksum` was the largest bucket in the capture
 * at 1,998 and 3,459 findings, and **100% of them were on frames this machine
 * sent**, where the NIC fills the checksum in after the sniffer has already
 * seen the bytes. A scale that cannot tell "damaged" from "not written yet" is
 * not measuring seriousness, and it is why the colour rule that painted rows
 * from it shipped switched off.
 *
 * What replaces it is `ExpertCategory` (`types/packet.ts`): eight values named
 * after what the reader should conclude. Triage does not disappear with the
 * severity - it moves somewhere better. Each category is a colour rule, the
 * chain is first-match-wins, and the chain is reorderable in Settings, so the
 * priority is the reader's rather than a fixed opinion of ours.
 *
 * Aggregation follows Wireshark's Expert Information dialog: identical findings
 * collapse into one row with a count and the frames behind it, because a
 * capture with four hundred retransmissions has one problem and not four
 * hundred - and the frame numbers are still there for whoever wants frame one.
 */

import { ExpertCategory, Packet, ProtocolField } from '../types/packet';
import { isDuplicate } from './direction';
import { fieldValue } from './dissect/fieldAccess';

/**
 * The categories, in the order the shipped colour rules sit in.
 *
 * The chain is first-match-wins, so this is also the answer to "a frame is both
 * Broken and a Capture gap - which colour does it get". Broken, because a frame
 * you cannot decode is a bigger fact than a frame the sniffer half-missed.
 *
 * The order runs damage -> network -> vantage point -> noise, and the last
 * three are deliberately at the bottom: they are the ones a reader stops
 * caring about first, so they are the ones whose rule gets disabled first.
 */
export const CATEGORY_ORDER: readonly ExpertCategory[] = [
  'Broken', 'Reset', 'Security', 'Loss',
  'CaptureGap', 'FlowControl', 'Unverifiable', 'Note',
];

/**
 * `CATEGORY_ORDER` as a lookup, derived rather than restated.
 *
 * `indexOf` is fine for a list of eight until it runs twice per finding per
 * frame, which is where `collectExpert` had it - a linear scan on the hot path
 * to compare two positions in a fixed array.
 */
export const CATEGORY_RANK: Record<ExpertCategory, number> = Object.fromEntries(
  CATEGORY_ORDER.map((category, index) => [category, index]),
) as Record<ExpertCategory, number>;

export const CATEGORY_LABELS: Record<ExpertCategory, string> = {
  Broken: 'Broken',
  Reset: 'Reset',
  Security: 'Security',
  Loss: 'Loss',
  CaptureGap: 'Capture gap',
  FlowControl: 'Flow control',
  Unverifiable: 'Unverifiable',
  Note: 'Note',
};

/** One sentence per category, for the tab's legend and the tree's tooltip. */
export const CATEGORY_HINTS: Record<ExpertCategory, string> = {
  Broken: 'The frame is damaged or could not be decoded.',
  Reset: 'A conversation was terminated.',
  Security: 'Certificates and address conflicts.',
  Loss: 'The network lost or reordered something.',
  CaptureGap: 'This capture is incomplete - the sniffer missed frames.',
  FlowControl: 'The peer is throttling rather than failing.',
  Unverifiable: 'Cannot be judged from where this capture was taken.',
  Note: 'Informational.',
};

/**
 * The colour rule each category paints its rows with, by rule id.
 *
 * For anything that wants a category's ROW colours outside the packet list -
 * the report's expert section - so it can take them from
 * `getPacketThemeForApp(...).rules` and agree with the list rather than keep a
 * third palette. `scripts/report/analysis.ts` holds every id to one that
 * exists in `DEFAULT_COLOR_RULES`, so a renamed band fails there rather than
 * printing an uncoloured chip.
 */
export const EXPERT_RULE_ID: Record<ExpertCategory, string> = {
  Broken: 'color-expert-broken',
  Reset: 'color-expert-reset',
  Security: 'color-expert-security',
  Loss: 'color-expert-loss',
  CaptureGap: 'color-expert-capture-gap',
  FlowControl: 'color-expert-flow-control',
  Unverifiable: 'color-expert-unverifiable',
  Note: 'color-expert-note',
};

/**
 * Text colour per category, for the detail tree and the Expert tab.
 *
 * Here rather than in a component because four separate copies of the severity
 * palette had accumulated - this module, the ladder view, the protocol tree and
 * the frame field table - and a category has to mean one colour in all of them.
 *
 * These are the *text* colours. A category's **row fill** is not here: it comes
 * from the colour-rules chain like every other row colour in the app, so that
 * one system owns what a row looks like (`services/packetThemes.ts`).
 */
export const CATEGORY_TEXT: Record<ExpertCategory, string> = {
  Broken: 'text-rose-600 dark:text-rose-400',
  Reset: 'text-red-700 dark:text-red-400',
  Security: 'text-fuchsia-600 dark:text-fuchsia-400',
  Loss: 'text-amber-600 dark:text-amber-400',
  CaptureGap: 'text-violet-600 dark:text-violet-400',
  FlowControl: 'text-sky-600 dark:text-sky-400',
  Unverifiable: 'text-muted-foreground',
  Note: 'text-teal-600 dark:text-teal-400',
};

/**
 * The category a frame reads as, straight off the field the dissector wrote.
 *
 * One dense-column read, so it is cheap enough for the dashboard folds that
 * run over the whole buffer. `expertItemsFor` is the other way to ask and
 * allocates a list per frame - right for the Expert tab, wrong for a counter.
 */
export function categoryOfPacket(packet: Packet): ExpertCategory | undefined {
  const v = fieldValue(packet, 'inwire.expert.category');
  return typeof v === 'string' ? (v as ExpertCategory) : undefined;
}

/**
 * Categories that mean something went wrong, for the counters and highlights
 * that used to key on `Packet.anomalies`.
 *
 * The four at the top of `CATEGORY_ORDER`. A capture gap, a keep-alive or an
 * unverifiable checksum is not a fault, and lighting a warning for them is how
 * the old alerts light came to mean nothing.
 */
export function isFaultCategory(category: ExpertCategory | undefined): boolean {
  return category !== undefined && CATEGORY_ORDER.indexOf(category) < 4;
}

export interface ExpertItem {
  frame: number;
  category: ExpertCategory;
  summary: string;
  /** The protocol the frame was labelled as, for the "Protocol" column. */
  protocol: string;
}

/** Identical findings, collapsed. */
export interface ExpertGroupRow {
  key: string;
  category: ExpertCategory;
  summary: string;
  protocol: string;
  count: number;
  /** Frames that raised it, capped - the list is for jumping, not for export. */
  frames: number[];
}

/** How many frames a group row remembers. Enough to jump around, not a copy of the capture. */
const MAX_REMEMBERED_FRAMES = 200;

/** Code-unit order, never the locale's: a report must sort the same everywhere. */
function compareText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function rank(c: ExpertCategory): number {
  return CATEGORY_RANK[c];
}

/**
 * The summary a finding is *counted* under.
 *
 * A finding's message is written for the frame it is on, and two of them name
 * a number that is different on every frame. That is right where the message
 * is read one frame at a time - the Info column, the tree row - and wrong as
 * an aggregation key: each occurrence became its own row, so the one table
 * that exists to collapse repeats did not collapse the findings that repeat
 * most. The numbers are not lost; the frames are kept per row and the tree
 * still says which.
 *
 * The two, both measured on real captures rather than imagined:
 *
 *   - **Dup ACK.** Wireshark's wording carries the frame being duplicated and
 *     how many times (`[TCP Dup ACK 3515#1]`), so a capture with 400 of them
 *     had 400 rows.
 *   - **Segmentation offload.** The message names the frame's size, and a
 *     browsing capture produces dozens of distinct sizes - three rows of one
 *     on a 620-frame session, and one row per size on a long one.
 */
function collapseSummary(summary: string): string {
  return summary
    .replace(/^\[TCP Dup ACK \d+#\d+\]$/, '[TCP Dup ACK]')
    .replace(/^Frame is \d+ bytes, past the /, 'Frame is past the ');
}

/**
 * The findings in one frame.
 *
 * Walks the tree rather than taking a channel of its own, so a dissector that
 * attaches an expert row is listed here with no further plumbing - the same
 * arrangement the name map uses, and for the same reason: one place to add a
 * fact, several places that read it.
 */
export function expertItemsFor(packet: Packet): ExpertItem[] {
  const out: ExpertItem[] = [];
  const protocol = packet.protocolLabel ?? packet.protocol;
  const push = (category: ExpertCategory, summary: string) => {
    out.push({ frame: packet.id, category, summary: collapseSummary(summary), protocol });
  };

  // The flat list the dissector published. It is the whole answer for a frame
  // that has one: the tree is dissected on demand now (docs/decisions/0007),
  // so aggregating over the buffer by walking trees would find nothing at all
  // for every frame nobody had clicked on.
  if (packet.expert) {
    for (const finding of packet.expert) push(finding.category ?? 'Note', finding.message);
  } else {
    // The tree, and ONLY when there is no flat list - a frame from a restored
    // session written by an older build, or a custom dissector's output.
    //
    // This guard is the whole point of the branch and it was missing: the
    // comment here claimed the walk was skipped when the flat list was
    // present, and it was not, so any frame carrying both counted everything
    // twice. It survived because `layers` is emptied on restore, which made it
    // unreachable rather than correct.
    const visit = (fields: ProtocolField[]) => {
      for (const field of fields) {
        if (field.expertInfo) push(field.expertInfo.category ?? 'Note', field.expertInfo.message);
        if (field.children) visit(field.children);
      }
    };
    for (const layer of packet.layers) visit(layer.fields);
  }

  // The same frame, captured twice on two adapters. A note rather than a
  // fault: nothing is wrong with the network, the capture is simply watching
  // one path from two places. Worth surfacing because it changes how the rest
  // of the capture reads - a doubled frame count, and what looks like a
  // retransmission that is not one.
  if (isDuplicate(packet.direction)) {
    push('Note', 'Frame also captured on another interface');
  }

  return out;
}

/**
 * The frames behind one group in a log that can forget them: a queue of
 * (frame id, protocol label) pairs in arrival order, in one `Uint32Array`.
 *
 * A group can no longer keep just its first 200 frames. Once the window trims
 * them, the next 200 are the answer, and the only way to know them is to have
 * kept every occurrence. That is 8 bytes a finding here, against a Map entry
 * apiece. The protocol rides along because a group's row reads it off its
 * first remaining occurrence, and a rebuild over the window would too: "Frame
 * also captured on another interface" is raised on frames of every protocol.
 *
 * Removal is only ever from the front - the buffer trims its head and frame
 * ids rise - so it is a head index. Once the head passes half of what has
 * been written the live part moves down, which keeps both ends O(1) amortised
 * and the array within twice what the group holds.
 */
class Occurrences {
  private data = new Uint32Array(8);
  /** First live pair and one past the last, in pairs. */
  private head = 0;
  private tail = 0;

  get length(): number {
    return this.tail - this.head;
  }

  push(frame: number, protocol: number): void {
    if (this.tail * 2 === this.data.length) {
      if (this.head * 2 >= this.tail) this.compact(this.data.length);
      else this.compact(this.data.length * 2);
    }
    this.data[this.tail * 2] = frame;
    this.data[this.tail * 2 + 1] = protocol;
    this.tail++;
  }

  /** Drops the oldest occurrence if it is `frame`'s; false when it is not. */
  shift(frame: number): boolean {
    if (this.head === this.tail || this.data[this.head * 2] !== frame) return false;
    this.head++;
    if (this.head === this.tail) {
      this.head = this.tail = 0;
    } else if (this.head * 2 >= this.tail && this.head >= 16) {
      // Past half of what was written: move the live part down, and let a
      // group that has shrunk a long way give its array back.
      const live = this.tail - this.head;
      this.compact(live * 4 <= this.data.length / 2 ? Math.max(8, live * 4) : this.data.length);
    }
    return true;
  }

  /** The protocol id of the oldest occurrence. */
  firstProtocol(): number {
    return this.data[this.head * 2 + 1];
  }

  /** Up to `max` of the oldest frame ids. */
  frames(max: number): number[] {
    const n = Math.min(max, this.tail - this.head);
    const out = new Array<number>(n);
    for (let i = 0; i < n; i++) out[i] = this.data[(this.head + i) * 2];
    return out;
  }

  private compact(capacity: number): void {
    const live = this.data.subarray(this.head * 2, this.tail * 2);
    const next = capacity === this.data.length ? this.data : new Uint32Array(capacity);
    next.set(live);
    this.data = next;
    this.tail -= this.head;
    this.head = 0;
  }
}

/** One group while it is being counted; `ExpertGroupRow` is what leaves the log. */
interface GroupState {
  key: string;
  category: ExpertCategory;
  summary: string;
  count: number;
  /** Report mode: the protocol of the first occurrence and the first 200 frames, as before. */
  protocol: string;
  frames: number[];
  /** Window mode: every occurrence still in the window. */
  occurrences: Occurrences | null;
}

/**
 * The running expert log.
 *
 * A class with `add` rather than a function over the buffer, so it can be
 * folded one packet at a time by `useIncrementalAggregate` - a full walk of
 * every layer of 50,000 frames ten times a second is exactly the cost that
 * hook exists to avoid.
 *
 * **In the app it also forgets.** The log covers the RAM window, and the
 * window's head moves every time it passes its budget. `remove` takes a
 * trimmed frame back out, so the log stays what a fold over the window would
 * give - counts, `frames` and `categoryOf` included - without refolding a
 * million rows each time. The name map makes the opposite choice on purpose
 * (a name learned from a trimmed frame is still a name).
 */
export class ExpertLog {
  private rows = new Map<string, GroupState>();
  /** The category each frame is painted by: the first one in chain order. */
  private strongest = new Map<number, ExpertCategory>();
  private total = 0;
  /** Protocol labels by number, for `Occurrences`. A few dozen at most. */
  private protocolIds = new Map<string, number>();
  private protocolNames: string[] = [];

  /**
   * @param perFrame keep `categoryOf`'s answer for every frame, and every
   * group's occurrences so that `remove` can work. The app's log needs both
   * and holds a window of frames; a report folding a whole capture off disk
   * needs neither, and one Map entry per flagged frame is what runs out - a
   * Map throws `RangeError` at about 16.7 million entries, which a long
   * capture full of keep-alives reaches. Without it a group keeps its first
   * 200 frames only, and `remove` throws.
   */
  constructor(private readonly perFrame = true) {}

  add(packet: Packet): void {
    for (const item of expertItemsFor(packet)) {
      this.total++;
      const key = `${item.category}|${item.summary}`;
      let row = this.rows.get(key);
      if (!row) {
        row = {
          key, category: item.category, summary: item.summary, protocol: item.protocol,
          count: 0, frames: [], occurrences: this.perFrame ? new Occurrences() : null,
        };
        this.rows.set(key, row);
      }
      row.count++;
      if (row.occurrences) row.occurrences.push(item.frame, this.protocolId(item.protocol));
      else if (row.frames.length < MAX_REMEMBERED_FRAMES) row.frames.push(item.frame);

      if (!this.perFrame) continue;
      const current = this.strongest.get(item.frame);
      if (current === undefined || rank(item.category) < rank(current)) {
        this.strongest.set(item.frame, item.category);
      }
    }
  }

  /**
   * Takes back what `add` recorded for a frame, which must be the oldest the
   * log still holds. Frames go in the order they came, so the frame is the
   * head of each queue it is in; one that is not is ignored rather than
   * allowed to drive a count negative.
   *
   * Reads `expertItemsFor`, which a patch does not change - the flat list, the
   * tree and the duplicate flag are all fixed when the frame is dissected.
   */
  remove(packet: Packet): void {
    if (!this.perFrame) throw new Error('ExpertLog.remove needs perFrame: a report log keeps no occurrences');
    for (const item of expertItemsFor(packet)) {
      const row = this.rows.get(`${item.category}|${item.summary}`);
      if (!row || !row.occurrences || !row.occurrences.shift(item.frame)) continue;
      this.total--;
      if (--row.count === 0) this.rows.delete(row.key);
    }
    this.strongest.delete(packet.id);
  }

  private protocolId(protocol: string): number {
    let id = this.protocolIds.get(protocol);
    if (id === undefined) {
      id = this.protocolNames.length;
      this.protocolNames.push(protocol);
      this.protocolIds.set(protocol, id);
    }
    return id;
  }

  /**
   * Group rows, most consequential first, then commonest.
   *
   * Every row is a copy, `frames` included: a caller keeps what it is handed,
   * and the log goes on changing under it.
   */
  groups(): ExpertGroupRow[] {
    const out: ExpertGroupRow[] = [];
    for (const row of this.rows.values()) {
      const queue = row.occurrences;
      out.push({
        key: row.key, category: row.category, summary: row.summary, count: row.count,
        protocol: queue ? this.protocolNames[queue.firstProtocol()] : row.protocol,
        frames: queue ? queue.frames(MAX_REMEMBERED_FRAMES) : row.frames.slice(),
      });
    }
    return out.sort(
      // Then a total order, so two rows with one count do not swap places
      // between runs that saw them first in a different order - a report
      // folded in pages and one folded whole must list them identically.
      (a, b) => rank(a.category) - rank(b.category) || b.count - a.count
        || compareText(a.summary, b.summary) || compareText(a.protocol, b.protocol),
    );
  }

  /** How many findings in each category, for the summary strip. */
  counts(): Record<ExpertCategory, number> {
    const out = Object.fromEntries(
      CATEGORY_ORDER.map((c) => [c, 0]),
    ) as Record<ExpertCategory, number>;
    for (const row of this.rows.values()) out[row.category] += row.count;
    return out;
  }

  /** The category this frame reads as - the first of its findings in chain order. */
  categoryOf(frame: number): ExpertCategory | undefined {
    return this.strongest.get(frame);
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
  counts(): Record<ExpertCategory, number>;
  categoryOf(frame: number): ExpertCategory | undefined;
  readonly size: number;
}

/**
 * A handle on the log that keeps what it has answered.
 *
 * The fold goes on changing the one log, and now removes from it too, so a
 * handle that read through would show an earlier tick's consumer a later
 * tick's capture. `size` is taken now, and `groups()` and `counts()` are
 * computed on first ask and kept - the log is only folded at the start of a
 * render, so a snapshot's first ask is made by the render it was built for.
 * `categoryOf` reads through: a point lookup per frame, which nothing in the
 * app calls, and copying the per-frame map each tick is the cost this exists
 * to avoid.
 */
export function expertSnapshot(log: ExpertLog): ExpertLookup {
  const size = log.size;
  let groups: ExpertGroupRow[] | undefined;
  let counts: Record<ExpertCategory, number> | undefined;
  return {
    groups: () => (groups ??= log.groups()),
    counts: () => (counts ??= log.counts()),
    categoryOf: (frame) => log.categoryOf(frame),
    size,
  };
}

/** Builds a log from a whole buffer, for tests and one-off analysis. */
export function buildExpertLog(packets: readonly Packet[]): ExpertLog {
  const log = new ExpertLog();
  for (const packet of packets) log.add(packet);
  return log;
}
