// The named export, not the default. jspdf's ESM default is a namespace
// object under Node, so `new jsPDF()` off the default throws "not a
// constructor" outside a bundler - which would leave the report generator
// untestable by the assertion script. The named export is a constructor in
// both environments.
import { jsPDF } from 'jspdf';
import autoTable, { type CellHookData, type RowInput, type Styles, type UserOptions } from 'jspdf-autotable';

import type { CaptureAnalysis } from '../../services/report/analysis';
import { findings, quoteFilter, type FindingTone } from '../../services/report/findings';
import { metaEntries, type CaptureMeta } from '../../services/export/captureMeta';
import {
  bitRate, bytes, count, duration, frameRate, offset, percent, percentCell, plural, utcClock, utcMinute,
} from '../../services/report/format';
import { SIZE_BUCKETS } from '../../services/report/sizeBuckets';
import { CATEGORY_HINTS, CATEGORY_LABELS, CATEGORY_ORDER, EXPERT_RULE_ID } from '../../services/expertInfo';
import { getPacketThemeForApp } from '../../services/packetThemes';
import { protocolColor } from '../../services/protocolColors';
import { themePalette } from '../../services/themePalettes';
import { SOURCE_LABELS } from '../../services/nameResolution';
import type { Conversation, Endpoint, HierarchyNode } from '../../services/statistics';
import type { ExpertCategory } from '../../types/packet';
import type { Anonymiser } from '../../services/anonymise';
import { redactAnalysis, redactMeta } from '../../services/report/redact';
import {
  drawBarChart, drawBrandMark, drawCategoryLabels, drawChip, drawHBar, drawTile, type Palette,
} from './pdfCharts';

/**
 * The PDF report: an analysis of the capture, not a copy of it.
 *
 * Statistics and findings, in the order an analyst reads them - what this is,
 * what is wrong with it, what it is made of, who is in it - and deliberately no
 * packet list. The frames belong in pcapng, CSV or JSON; a PDF of forty
 * thousand rows is a file nobody reads and everybody prints.
 *
 * It takes a finished `CaptureAnalysis` and never a packet, so what it draws
 * is exactly what `scripts/report/analysis.ts` asserted, and an anonymised
 * report is the same function handed a redacted analysis. It returns a `Blob`
 * rather than calling `doc.save()`, which is what lets the zip toggle wrap it
 * like every other format.
 *
 * ## The page
 *
 * A4, Helvetica (one of the PDF standard faces, so nothing is embedded and the
 * file opens identically everywhere), the Day palette from `themePalettes.ts`
 * and the app's own `--primary` for accents. Helvetica's figures are all one
 * width, so the numbers in a right-aligned column line up without asking.
 *
 * ## One encoding
 *
 * The standard faces are WinAnsi, and jsPDF silently DROPS what they cannot
 * draw - an en dash vanishes from the middle of a sentence. Every string passes
 * through `Ink.clean`, which spells the common typographic characters in ASCII
 * and replaces anything else with `?`, and the Methods note says so if it
 * happened.
 */

export interface PdfReportOptions {
  /** When the report was generated, epoch ms: the footer's timestamp. */
  now: number;
  /**
   * The export's anonymiser, which makes the report anonymised. The report
   * redacts its analysis AND its metadata with it - the filter, the file name
   * and the adapter labels are as identifying as any address in a table, and
   * a caller that redacted one and not the other is the leak this closes.
   */
  anonymiser?: Anonymiser;
  /** Deflate the content streams. Off by default so a test can read the text. */
  compress?: boolean;
}

const DAY = themePalette('light');
const PRIMARY = '#0b6bcb';
// The Day theme's --destructive, --warning and --muted, from index.css.
const DANGER = '#d32f3f';
const WARNING = '#a86600';
const P: Palette = {
  ink: DAY.surface.foreground,
  muted: '#5b6470',
  rule: DAY.surface.border,
  fill: '#eef1f5',
};
const TRACK = '#eef1f5';

const TONE_COLOR: Record<FindingTone, string> = { fault: DANGER, notice: WARNING, info: PRIMARY };
const TONE_LABEL: Record<FindingTone, string> = { fault: 'Fault', notice: 'Notice', info: 'Context' };

const PAGE_W = 210;
const PAGE_H = 297;
const M = 18;
const CW = PAGE_W - M * 2;
/** Where content starts on a continuation page, below the running header. */
const TOP = 24;
/** The last line content may reach, above the footer. */
const BOTTOM = PAGE_H - 21;

/** Tables list this many rows before saying how many more there were. */
const HIERARCHY_ROWS = 36;
const EXPERT_ROWS = 8;
const HOST_ROWS = 25;

/** Where the time axis may put a label, in seconds. */
const LABEL_STEPS = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];

/**
 * The section titles, in order. Exported for the assertion script, which
 * checks each is present in the file.
 */
export const SECTION_TITLES = [
  'Summary',
  'Findings',
  'Traffic over time',
  'Protocol hierarchy',
  'Packet sizes',
  'Top endpoints',
  'Top conversations',
  'Expert findings',
  'Hosts seen',
  'Processes',
  'Methods',
] as const;

/** Protocol tokens as a reader expects to see them named. */
const TOKEN_NAMES: Record<string, string> = {
  eth: 'Ethernet', ip: 'IPv4', ipv6: 'IPv6', tcp: 'TCP', udp: 'UDP', tls: 'TLS', quic: 'QUIC',
  dns: 'DNS', arp: 'ARP', icmp: 'ICMP', icmpv6: 'ICMPv6', http: 'HTTP', http2: 'HTTP/2', http3: 'HTTP/3',
  llc: 'LLC', stp: 'STP', dhcp: 'DHCP', dhcpv6: 'DHCPv6', igmp: 'IGMP', lldp: 'LLDP', ssdp: 'SSDP',
  data: 'Data', json: 'JSON', ieee1905: 'IEEE 1905.1', nbns: 'NBNS', mdns: 'mDNS', snmp: 'SNMP',
  ntp: 'NTP', smb2: 'SMB2', ldap: 'LDAP', sip: 'SIP', gre: 'GRE', vlan: '802.1Q VLAN', null: 'Loopback',
  sll: 'Linux cooked', 'ipv6.hopopts': 'IPv6 hop-by-hop', simple_service_discovery_protocol: 'SSDP (payload)',
};

/** Tokens onto the protocol names `protocolColor` keys on; unlisted ones are drawn neutral. */
const TOKEN_PROTOCOL: Record<string, string> = {
  tcp: 'TCP', udp: 'UDP', tls: 'TLS', quic: 'QUIC', dns: 'DNS', mdns: 'DNS', icmp: 'ICMP', icmpv6: 'ICMP',
  arp: 'ARP', http: 'HTTP', http2: 'HTTP', http3: 'HTTP', ssh: 'SSH', ldap: 'LDAP', smb2: 'SMB2', bgp: 'BGP', gre: 'GRE',
};

const SUBSTITUTES: Record<string, string> = {
  '‐': '-', '‑': '-', '‒': '-', '–': '-', '—': '-', '−': '-',
  '‘': "'", '’': "'", '‚': "'", '“': '"', '”': '"', '„': '"',
  '…': '...', '•': '·', '→': '->', '←': '<-', '↔': '<->',
  ' ': ' ', ' ': ' ', ' ': ' ', ' ': ' ', ' ': ' ',
};

/** The text filter, and a count of what it could not keep. */
class Ink {
  replaced = 0;

  clean(s: string): string {
    let out = '';
    for (const ch of s) {
      const code = ch.codePointAt(0)!;
      if (ch === '\n' || (code >= 0x20 && code <= 0x7e) || (code >= 0xa0 && code <= 0xff)) {
        out += ch;
      } else if (SUBSTITUTES[ch] !== undefined) {
        out += SUBSTITUTES[ch];
      } else if (code === 0x09) {
        out += ' ';
      } else {
        out += '?';
        this.replaced += 1;
      }
    }
    return out;
  }
}

function tokenName(token: string): string {
  return TOKEN_NAMES[token] ?? token.toUpperCase();
}

function tokenColor(token: string): string {
  const protocol = TOKEN_PROTOCOL[token];
  return protocol ? protocolColor(protocol, 'light') : DAY.hues.neutral;
}

function sourceLine(meta: CaptureMeta): string {
  switch (meta.source.kind) {
    case 'live':
      return meta.source.adapters.length > 0 ? `Live capture on ${meta.source.adapters.join(', ')}` : 'Live capture';
    case 'import':
      return `Imported from ${meta.source.fileName}`;
    case 'session':
      return 'Restored session';
  }
}

/** `addr:port`, bracketing an IPv6 address so its colons are not mistaken for the port's. */
function endpointWithPort(address: string, port: number | undefined): string {
  if (port === undefined) return address;
  return address.includes(':') ? `[${address}]:${port}` : `${address}:${port}`;
}

class Report {
  readonly doc: jsPDF;
  readonly ink = new Ink();
  y = 0;

  constructor(compress: boolean) {
    this.doc = new jsPDF({ unit: 'mm', format: 'a4', compress, putOnlyUsedFonts: true });
    this.doc.setLineHeightFactor(1.3);
  }

  t(s: string): string {
    return this.ink.clean(s);
  }

  newPage(): void {
    this.doc.addPage();
    this.y = TOP;
  }

  /** Starts a new page unless `h` more millimetres fit on this one. */
  ensure(h: number): void {
    if (this.y + h > BOTTOM) this.newPage();
  }

  /**
   * A section heading, never left alone at the foot of a page: it moves to
   * the next page with at least `minBody` millimetres of what it introduces.
   */
  section(title: string, intro: string | null, minBody = 32): void {
    const doc = this.doc;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(8.5);
    const introLines = intro ? doc.splitTextToSize(this.t(intro), CW) as string[] : [];
    const head = 9 + introLines.length * 3.9;
    const gap = this.y > TOP + 1 ? 9 : 0;
    if (this.y + gap + head + minBody > BOTTOM) this.newPage();
    else this.y += gap;

    doc.setFillColor(PRIMARY);
    doc.rect(M, this.y - 4.1, 1.1, 5.2, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(13);
    doc.setTextColor(P.ink);
    doc.text(this.t(title), M + 3.6, this.y);
    this.y += 5.5;
    if (introLines.length > 0) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8.5);
      doc.setTextColor(P.muted);
      doc.text(introLines, M, this.y);
      this.y += introLines.length * 3.9;
    }
    this.y += 2.5;
  }

  subheading(text: string, detail: string | null, minBody = 22): void {
    const doc = this.doc;
    this.ensure(8 + minBody);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(9.5);
    doc.setTextColor(P.ink);
    const label = this.t(text);
    doc.text(label, M, this.y + 3);
    if (detail) {
      const w = doc.getTextWidth(label);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(8);
      doc.setTextColor(P.muted);
      doc.text(this.t(detail), M + w + 2.5, this.y + 3);
    }
    this.y += 5.5;
  }

  paragraph(text: string, options: { size?: number; color?: string; indent?: number; after?: number } = {}): void {
    const doc = this.doc;
    const size = options.size ?? 9;
    const indent = options.indent ?? 0;
    const lineH = size * 0.3528 * 1.35;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(size);
    doc.setTextColor(options.color ?? P.ink);
    const lines = doc.splitTextToSize(this.t(text), CW - indent) as string[];
    for (const line of lines) {
      this.ensure(lineH);
      doc.text(line, M + indent, this.y + lineH * 0.75);
      this.y += lineH;
    }
    this.y += options.after ?? 1.5;
  }

  /**
   * A table in the report's one style: a quiet header fill, hairline rules
   * between rows and none between columns, numbers right-aligned.
   */
  table(options: {
    head: string[];
    body: RowInput[];
    numeric?: number[];
    widths?: Record<number, number>;
    fontSize?: number;
    didParseCell?: (data: CellHookData) => void;
    didDrawCell?: (data: CellHookData) => void;
  }): void {
    const numeric = new Set(options.numeric ?? []);
    const columnStyles: Record<number, Partial<Styles>> = {};
    options.head.forEach((_, i) => {
      columnStyles[i] = {
        ...(numeric.has(i) ? { halign: 'right' } : {}),
        ...(options.widths?.[i] !== undefined ? { cellWidth: options.widths[i] } : {}),
      };
    });
    const clean = (row: RowInput): RowInput => (Array.isArray(row)
      ? row.map((cell) => (typeof cell === 'string' ? this.t(cell) : cell))
      : row);
    // Enough room for the header and a few rows, or the table starts overleaf
    // rather than leaving its header stranded above the footer.
    this.ensure(22);
    const settings: UserOptions = {
      startY: this.y,
      head: [options.head.map((h) => this.t(h))],
      body: options.body.map(clean),
      theme: 'plain',
      margin: { left: M, right: M, top: TOP, bottom: PAGE_H - BOTTOM },
      showHead: 'everyPage',
      rowPageBreak: 'avoid',
      styles: {
        font: 'helvetica',
        fontSize: options.fontSize ?? 8.2,
        textColor: P.ink,
        cellPadding: { top: 1.3, bottom: 1.3, left: 1.8, right: 1.8 },
        lineColor: P.rule,
        lineWidth: { bottom: 0.15 },
        overflow: 'linebreak',
        valign: 'middle',
      },
      headStyles: {
        fillColor: P.fill,
        textColor: P.muted,
        fontStyle: 'bold',
        fontSize: 7.4,
        lineWidth: 0,
      },
      columnStyles,
      didParseCell: (data) => {
        // Header cells follow their column's alignment, so a number's heading
        // sits over the number.
        if (data.section === 'head' && numeric.has(data.column.index)) data.cell.styles.halign = 'right';
        options.didParseCell?.(data);
      },
      didDrawCell: options.didDrawCell,
    };
    autoTable(this.doc, settings);
    const last = (this.doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable;
    this.y = (last?.finalY ?? this.y) + 3;
  }

  /** A muted line under a table: what it left out. */
  note(text: string): void {
    this.paragraph(text, { size: 7.8, color: P.muted, after: 1 });
  }
}

// --- sections -----------------------------------------------------------------------

function cover(r: Report, meta: CaptureMeta, opts: PdfReportOptions): void {
  const doc = r.doc;
  doc.setFillColor(DAY.surface.background);
  doc.rect(0, 0, PAGE_W, 50, 'F');
  doc.setDrawColor(P.rule);
  doc.setLineWidth(0.3);
  doc.line(0, 50, PAGE_W, 50);

  drawBrandMark(doc, M - 1.5, 12, 27);

  const tx = M + 31;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(22);
  doc.setTextColor(P.ink);
  doc.text('Inwire capture analysis', tx, 24.5);
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(9.5);
  doc.setTextColor(P.muted);
  const source = doc.splitTextToSize(r.t(sourceLine(meta)), PAGE_W - tx - M) as string[];
  doc.text(source[0], tx, 32);
  doc.text(r.t(`Generated ${utcMinute(opts.now)}  ·  ${meta.app} ${meta.version}`), tx, 37.5);

  r.y = 58;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(9.5);
  doc.setTextColor(P.ink);
  doc.text('About this capture', M, r.y);
  r.y += 3;
  // The metadata as two columns of key and value: every format prints the
  // same `metaEntries`, and a reader checks this table before anything else.
  const entries = metaEntries(meta);
  const half = Math.ceil(entries.length / 2);
  const rows: RowInput[] = [];
  for (let i = 0; i < half; i++) {
    const left = entries[i];
    const right = entries[i + half];
    rows.push([left[0], left[1], right?.[0] ?? '', right?.[1] ?? '']);
  }
  autoTable(doc, {
    startY: r.y,
    body: rows.map((row) => (row as string[]).map((c) => r.t(c))),
    theme: 'plain',
    margin: { left: M, right: M },
    styles: { font: 'helvetica', fontSize: 7.8, textColor: P.ink, cellPadding: { top: 1, bottom: 1, left: 0, right: 3 }, overflow: 'linebreak' },
    columnStyles: {
      0: { textColor: P.muted, cellWidth: 38 },
      1: { cellWidth: 51 },
      2: { textColor: P.muted, cellWidth: 38 },
      3: { cellWidth: 47 },
    },
  });
  const last = (doc as unknown as { lastAutoTable?: { finalY: number } }).lastAutoTable;
  r.y = (last?.finalY ?? r.y) + 2;
}

function summary(r: Report, a: CaptureAnalysis): void {
  r.section('Summary', null, 62);
  const doc = r.doc;
  const faults = a.expert.counts.Broken + a.expert.counts.Reset + a.expert.counts.Security + a.expert.counts.Loss;
  const tiles: [string, string, string | null][] = [
    ['Frames', count(a.frames), a.frames > 0 ? `${bytes(a.bytes)} in all` : null],
    ['Duration', a.frames > 0 ? duration(a.durationSeconds) : '-', a.firstUs !== null ? `from ${utcClock(a.firstUs)}` : null],
    ['Average rate', bitRate(a.rates.avgBitsPerSecond), frameRate(a.rates.avgFramesPerSecond)],
    ['Busiest second', bitRate(a.rates.peakBitsPerSecond), plural(a.rates.peakFramesPerSecond, 'frame')],
    ['IP hosts', count(a.hosts), `${count(a.endpoints.ipv4.distinct)} IPv4, ${count(a.endpoints.ipv6.distinct)} IPv6`],
    ['Conversations', count(a.conversations.tcp.distinct + a.conversations.udp.distinct),
      `${count(a.conversations.tcp.distinct)} TCP, ${count(a.conversations.udp.distinct)} UDP`],
    ['TCP retransmissions', count(a.signals.tcp.retransmissions),
      a.signals.tcp.frames > 0 ? `${percent(a.signals.tcp.retransmissions, a.signals.tcp.frames)} of TCP frames` : 'no TCP'],
    ['Expert info', count(a.expert.total), `${count(faults)} ${faults === 1 ? 'is a fault' : 'are faults'}`],
  ];
  const gap = 4;
  const w = (CW - gap * 3) / 4;
  const h = 21;
  tiles.forEach(([label, value, sub], i) => {
    const col = i % 4;
    const row = Math.floor(i / 4);
    drawTile(doc, { x: M + col * (w + gap), y: r.y + row * (h + gap), w, h }, r.t(label), r.t(value), sub ? r.t(sub) : null, P, PRIMARY);
  });
  r.y += h * 2 + gap + 6;

  // The expert categories as chips in the packet list's own row colours, so
  // the report and the list agree about what a colour means.
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(8);
  doc.setTextColor(P.muted);
  doc.text('Expert findings by category', M, r.y + 1);
  r.y += 3.5;
  const theme = getPacketThemeForApp('light');
  let x = M;
  const present = CATEGORY_ORDER.filter((c) => a.expert.counts[c] > 0);
  if (present.length === 0) {
    r.paragraph('None: the dissectors raised no expert findings.', { size: 8.5, color: P.muted });
    return;
  }
  for (const c of present) {
    const colors = theme.rules[EXPERT_RULE_ID[c]];
    const label = r.t(`${CATEGORY_LABELS[c]}  ${count(a.expert.counts[c])}`);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8);
    const w2 = doc.getTextWidth(label) + 4.8;
    if (x + w2 > M + CW) {
      x = M;
      r.y += 6.2;
    }
    x += drawChip(doc, x, r.y, label, colors.background, colors.color) + 2.2;
  }
  r.y += 8;
}

function findingsSection(r: Report, a: CaptureAnalysis, meta: CaptureMeta): void {
  const list = findings(a, meta);
  r.section('Findings', 'What the numbers say, most of it worked out from the sections that follow. '
    + 'Red marks a fault worth acting on, amber something worth knowing, blue context.', 30);
  const doc = r.doc;
  // A fixed column of tone labels, then the sentence: the word as well as the
  // colour, because a printed report is often grey.
  const labelW = 15;
  const indent = labelW + 3.5;
  const lineH = 4.25;
  for (const f of list) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.2);
    const lines = doc.splitTextToSize(r.t(f.text), CW - indent) as string[];
    r.ensure(lines.length * lineH + 3);
    const color = TONE_COLOR[f.tone];
    doc.setFillColor(color);
    doc.roundedRect(M, r.y + 0.35, labelW, 3.9, 1.95, 1.95, 'F');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(6.4);
    doc.setTextColor('#ffffff');
    doc.text(TONE_LABEL[f.tone].toUpperCase(), M + labelW / 2, r.y + 2.55, { align: 'center', baseline: 'middle' });
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(9.2);
    doc.setTextColor(P.ink);
    lines.forEach((line, i) => doc.text(line, M + indent, r.y + 3.2 + i * lineH));
    r.y += lines.length * lineH + 2.8;
  }
}

function timelineSection(r: Report, a: CaptureAnalysis): void {
  const t = a.timeline;
  if (t.bars.length === 0) return;
  const width = t.width;
  r.section('Traffic over time',
    `Each bar is ${duration(width)} wide and shows the average rate across it. `
    + 'Red is the share of frames carrying a fault finding (broken, reset, security or loss).', 100);

  // The seconds a bar actually covers. The last one usually stops short of a
  // full width, where the capture ended, and dividing its frames by the full
  // width would draw the capture's final seconds as a lull.
  const span = (b: { start: number }) => Math.max(1, Math.min(width, t.end - b.start));
  const n = t.bars.length;
  // Labels at round times - every 30 s, every 5 min - rather than every k-th
  // bar, which lands them on 0:36 and 1:12. The step is the smallest one that
  // gives at most seven labels and is a whole number of bars.
  const axis = n * width;
  const step = LABEL_STEPS.find((s) => s >= width && s % width === 0 && axis / s <= 7)
    ?? Math.ceil(axis / 7 / width) * width;
  const xLabels: { index: number; text: string }[] = [];
  for (let at = 0; at <= axis + 1e-9; at += step) {
    xLabels.push({ index: at / width, text: offset(at) });
  }

  const box1 = { x: M, y: r.y, w: CW, h: 52 };
  drawBarChart(r.doc, box1, {
    values: t.bars.map((b) => b.frames / span(b)),
    overlay: t.bars.map((b) => b.faults / span(b)),
    color: PRIMARY,
    overlayColor: DANGER,
    xLabels,
    title: 'Frames per second',
  }, P);
  r.y += box1.h + 4;

  const box2 = { x: M, y: r.y, w: CW, h: 40 };
  drawBarChart(r.doc, box2, {
    values: t.bars.map((b) => (b.bytes * 8) / span(b)),
    color: '#3494f4',
    xLabels,
    title: 'Throughput, bits per second',
  }, P);
  r.y += box2.h + 2;
  const doc = r.doc;
  const legend = (x: number, color: string, label: string) => {
    doc.setFillColor(color);
    doc.rect(x, r.y + 0.4, 2.6, 2.6, 'F');
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(P.muted);
    doc.text(label, x + 4, r.y + 2.6);
    return x + 4 + doc.getTextWidth(label) + 6;
  };
  let lx = legend(M, PRIMARY, 'Frames');
  lx = legend(lx, DANGER, 'Frames with a fault finding');
  legend(lx, '#3494f4', 'Throughput');
  r.y += 5;
  r.note('Time runs from the first frame, in minutes and seconds.');
}

function hierarchySection(r: Report, a: CaptureAnalysis): void {
  const h = a.hierarchy;
  if (h.packets === 0) return;
  r.section('Protocol hierarchy',
    'Every frame counts once at each layer it passed through, so a layer\'s share includes everything nested under it.', 40);

  // The `frame` root is every frame by definition; its children are the tree.
  let roots: HierarchyNode[] = h.roots;
  if (roots.length === 1 && roots[0].token === 'frame') roots = roots[0].children;

  const flat: { node: HierarchyNode; depth: number }[] = [];
  let omitted = 0;
  const walk = (nodes: HierarchyNode[], depth: number) => {
    for (const node of nodes) {
      if (flat.length >= HIERARCHY_ROWS) { omitted += 1; continue; }
      flat.push({ node, depth });
      walk(node.children, depth + 1);
    }
  };
  walk(roots, 0);

  const barW = 34;
  r.table({
    head: ['Protocol', 'Frames', '% frames', 'Bytes', '% bytes', 'Share of frames'],
    body: flat.map(({ node }) => [
      tokenName(node.token),
      count(node.packets), percentCell(node.packets, h.packets), bytes(node.bytes), percentCell(node.bytes, h.bytes), '',
    ]),
    numeric: [1, 2, 3, 4],
    widths: { 1: 20, 2: 18, 3: 20, 4: 18, 5: barW + 4 },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 0) {
        const depth = flat[data.row.index]?.depth ?? 0;
        data.cell.styles.cellPadding = { top: 1.3, bottom: 1.3, left: 1.8 + depth * 4, right: 1.8 };
        if (depth === 0) data.cell.styles.fontStyle = 'bold';
      }
    },
    didDrawCell: (data) => {
      if (data.section !== 'body' || data.column.index !== 5) return;
      const { node } = flat[data.row.index];
      const cell = data.cell;
      drawHBar(r.doc, cell.x + 2, cell.y + cell.height / 2 - 1.2, barW, 2.4, node.packets / h.packets, tokenColor(node.token), TRACK);
    },
  });
  if (omitted > 0) r.note(`${plural(omitted, 'smaller protocol')} not listed.`);

  if (a.colorRules.length > 0) {
    r.subheading('Frames by colour rule', 'each frame counted once, under the first rule that matches it', 26);
    const theme = getPacketThemeForApp('light');
    const rows = [
      ...a.colorRules.map((c) => ({ id: c.id as string | null, name: c.name, frames: c.frames })),
      ...(a.uncoloured > 0 ? [{ id: null, name: 'No rule matched', frames: a.uncoloured }] : []),
    ];
    const swatchW = 12;
    r.table({
      head: ['', 'Colour rule', 'Frames', 'Share'],
      body: rows.map((c) => ['', c.name, count(c.frames), percentCell(c.frames, a.frames)]),
      numeric: [2, 3],
      widths: { 0: swatchW + 3.6, 2: 24, 3: 22 },
      didDrawCell: (data) => {
        if (data.section !== 'body' || data.column.index !== 0) return;
        const row = rows[data.row.index];
        const colors = row.id ? theme.rules[row.id] : undefined;
        const cell = data.cell;
        const y = cell.y + cell.height / 2 - 1.9;
        // A swatch of the row as the packet list paints it: its ground and
        // its text colour, so the legend reads as a row and not as a chip.
        r.doc.setFillColor(colors?.background ?? '#ffffff');
        r.doc.setDrawColor(P.rule);
        r.doc.setLineWidth(0.15);
        r.doc.rect(cell.x + 1.8, y, swatchW, 3.8, colors ? 'F' : 'FD');
        r.doc.setFont('helvetica', 'normal');
        r.doc.setFontSize(6.5);
        r.doc.setTextColor(colors?.color ?? P.muted);
        r.doc.text('Frame', cell.x + 1.8 + swatchW / 2, y + 1.9, { align: 'center', baseline: 'middle' });
      },
    });
  }
}

function sizesSection(r: Report, a: CaptureAnalysis): void {
  if (a.frames === 0) return;
  r.section('Packet sizes', 'Frame lengths as captured, in the buckets the Graphs tab uses.', 60);
  const box = { x: M, y: r.y, w: 118, h: 56 };
  const counts = a.sizes.counts;
  drawBarChart(r.doc, box, {
    values: counts,
    color: PRIMARY,
    xLabels: [],
    title: 'Frames',
    integer: true,
    valueLabels: counts.map((c) => (c > 0 ? percent(c, a.sizes.total) : '')),
  }, P);
  drawCategoryLabels(r.doc, box, SIZE_BUCKETS.map((b) => (b.short === 'JUMBO' ? '>1518' : `<=${b.short}`)), P);

  // The figures beside the chart, where the eye goes after the shape.
  const doc = r.doc;
  const sx = M + box.w + 10;
  let sy = r.y + 8;
  const stat = (label: string, value: string) => {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(P.muted);
    doc.text(r.t(label), sx, sy);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.setTextColor(P.ink);
    doc.text(r.t(value), sx, sy + 5);
    sy += 12;
  };
  stat('Mean frame', `${count(Math.round(a.sizes.mean))} B`);
  stat('Smallest', `${count(a.sizes.min)} B`);
  stat('Largest', `${count(a.sizes.max)} B`);
  const big = counts[counts.length - 1];
  stat('Over 1,518 B', big > 0 ? `${count(big)} frames` : 'none');
  r.y += box.h + 3;
  if (big > 0) {
    r.note('Frames over 1,518 B are jumbo frames, or segmentation offload handing the sniffer a '
      + 'frame the network card will split before it reaches the wire.');
  }
}

function endpointsSection(r: Report, a: CaptureAnalysis): void {
  const { ipv4, ipv6 } = a.endpoints;
  if (ipv4.distinct + ipv6.distinct === 0) return;
  r.section('Top endpoints', `The busiest addresses by bytes sent and received. Share is of all IP bytes (${bytes(a.ip.bytes)}).`, 40);
  const names = new Map(a.names.map((n) => [n.address, n.name]));
  const block = (label: string, ranked: typeof ipv4) => {
    if (ranked.distinct === 0) return;
    r.subheading(label, ranked.distinct > ranked.rows.length
      ? `top ${ranked.rows.length} of ${count(ranked.distinct)}` : `${plural(ranked.distinct, 'address', 'addresses')}`);
    const rows = ranked.rows;
    const barW = 18;
    // No Name column when nothing is named - an anonymised report, or a
    // capture with no DNS in it - rather than a column of blanks.
    const withNames = a.names.length > 0;
    const shareCol = withNames ? 6 : 5;
    r.table({
      head: ['Address', ...(withNames ? ['Name'] : []), 'Frames', 'Bytes', 'Sent', 'Received', 'Share'],
      body: rows.map((e: Endpoint) => [
        e.address, ...(withNames ? [names.get(e.address) ?? ''] : []),
        count(e.packets), bytes(e.bytes), bytes(e.bytesTx), bytes(e.bytesRx), '',
      ]),
      numeric: withNames ? [2, 3, 4, 5] : [1, 2, 3, 4],
      widths: withNames
        ? { 0: label === 'IPv6' ? 52 : 32, 2: 15, 3: 16, 4: 16, 5: 16, 6: barW + 4 }
        : { 1: 18, 2: 20, 3: 20, 4: 20, 5: barW + 4 },
      fontSize: 7.8,
      didParseCell: (data) => {
        // An IPv6 address at the table's size would take the name's room.
        if (label === 'IPv6' && data.section === 'body' && data.column.index === 0) data.cell.styles.fontSize = 7.2;
      },
      didDrawCell: (data) => {
        if (data.section !== 'body' || data.column.index !== shareCol) return;
        const e = rows[data.row.index];
        const cell = data.cell;
        drawHBar(r.doc, cell.x + 2, cell.y + cell.height / 2 - 1.1, barW, 2.2, a.ip.bytes > 0 ? e.bytes / a.ip.bytes : 0, PRIMARY, TRACK);
      },
    });
  };
  block('IPv4', ipv4);
  block('IPv6', ipv6);
}

function conversationsSection(r: Report, a: CaptureAnalysis): void {
  const c = a.conversations;
  if (c.ipv4.distinct + c.ipv6.distinct + c.tcp.distinct + c.udp.distinct === 0) return;
  r.section('Top conversations', 'The largest exchanges by bytes in both directions. A is the side heard from first, '
    + 'which for TCP is normally the one that opened the connection.', 40);
  const block = (label: string, ranked: typeof c.ipv4, ports: boolean) => {
    if (ranked.distinct === 0) return;
    r.subheading(label, ranked.distinct > ranked.rows.length
      ? `top ${ranked.rows.length} of ${count(ranked.distinct)}` : plural(ranked.distinct, 'conversation'));
    const ends = ranked.rows.map((x: Conversation) => [
      ports ? endpointWithPort(x.addressA, x.portA) : x.addressA,
      ports ? endpointWithPort(x.addressB, x.portB) : x.addressB,
    ]);
    // The two ends share what the numbers leave. When the longest of them
    // will not fit its half on one line at a readable size - an IPv6 address
    // with a port is 46 characters - the ends stack in one column instead,
    // A over B: an address broken across two lines is a string nobody can
    // copy, and type shrunk to fit it is a string nobody can read.
    const numbersW = 16 + 14 + 16 + 17 + 14;
    const halfW = (CW - numbersW) / 2;
    const doc = r.doc;
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.6);
    const widest = Math.max(...ends.flat().map((e) => doc.getTextWidth(r.t(e))));
    const stacked = widest > halfW - 3.8;
    const numbers = (x: Conversation) => [
      x.protocol, count(x.packets), bytes(x.bytes), duration(x.duration), percentCell(x.bytes, a.bytes),
    ];
    const tail = { 3: 14, 4: 16, 5: 17, 6: 14 };
    if (stacked) {
      r.table({
        head: ['A, then B', 'Protocol', 'Frames', 'Bytes', 'Duration', 'Share'],
        body: ranked.rows.map((x: Conversation, i) => [`${ends[i][0]}\n${ends[i][1]}`, ...numbers(x)]),
        numeric: [2, 3, 4, 5],
        widths: { 0: CW - numbersW, 1: 16, 2: 14, 3: 16, 4: 17, 5: 14 },
        fontSize: 7.6,
      });
    } else {
      r.table({
        head: ['A', 'B', 'Protocol', 'Frames', 'Bytes', 'Duration', 'Share'],
        body: ranked.rows.map((x: Conversation, i) => [ends[i][0], ends[i][1], ...numbers(x)]),
        numeric: [3, 4, 5, 6],
        widths: { 0: halfW, 1: halfW, 2: 16, ...tail },
        fontSize: 7.6,
      });
    }
  };
  block('IPv4', c.ipv4, false);
  block('IPv6', c.ipv6, false);
  block('TCP', c.tcp, true);
  block('UDP', c.udp, true);
}

function expertSection(r: Report, a: CaptureAnalysis): void {
  if (a.frames === 0) return;
  r.section('Expert findings', 'What the dissectors flagged, grouped the way the Expert tab groups them: identical '
    + 'findings collapse into one row with a count and the first frames that raised them.', 30);
  const present = CATEGORY_ORDER.filter((c) => a.expert.counts[c] > 0);
  if (present.length === 0) {
    r.paragraph('None. The dissectors raised no expert findings in this capture.', { color: P.muted });
    return;
  }
  const theme = getPacketThemeForApp('light');
  const doc = r.doc;
  for (const category of present as ExpertCategory[]) {
    const groups = a.expert.groups.filter((g) => g.category === category);
    r.ensure(30);
    const colors = theme.rules[EXPERT_RULE_ID[category]];
    const w = drawChip(doc, M, r.y, r.t(CATEGORY_LABELS[category]), colors.background, colors.color, 8.5);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(P.ink);
    doc.text(r.t(plural(a.expert.counts[category], 'finding')), M + w + 3, r.y + 3.4);
    const cw = doc.getTextWidth(r.t(plural(a.expert.counts[category], 'finding')));
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(P.muted);
    doc.text(r.t(CATEGORY_HINTS[category]), M + w + 3 + cw + 3, r.y + 3.4);
    r.y += 6.5;
    const shown = groups.slice(0, EXPERT_ROWS);
    r.table({
      head: ['Finding', 'Protocol', 'Count', 'First frames'],
      body: shown.map((g) => [g.summary, g.protocol, count(g.count), g.frames.slice(0, 4).map((f) => count(f)).join(', ')]),
      numeric: [2],
      widths: { 1: 20, 2: 15, 3: 44 },
      fontSize: 7.8,
    });
    if (groups.length > shown.length) {
      const rest = groups.slice(shown.length);
      const restCount = rest.reduce((s, g) => s + g.count, 0);
      r.note(`And ${plural(rest.length, 'other kind')} of ${CATEGORY_LABELS[category].toLowerCase()} finding (${plural(restCount, 'finding')}).`);
    }
    r.y += 2;
  }
}

function hostsSection(r: Report, a: CaptureAnalysis, meta: CaptureMeta): void {
  if (a.frames === 0) return;
  r.section('Hosts seen', null, 24);
  const named = a.names.length;
  r.paragraph(`${plural(a.hosts, 'distinct IP address', 'distinct IP addresses')}: ${count(a.endpoints.ipv4.distinct)} IPv4 and `
    + `${count(a.endpoints.ipv6.distinct)} IPv6.`
    + (meta.flags.anonymised
      ? ' Host names are left out because this report is anonymised.'
      : named > 0
        ? ` ${count(named)} of them were named by the capture itself - DNS answers, TLS and QUIC server names, DHCP, `
          + 'NBNS and LLDP. Nothing was looked up.'
        : ' None of them was named by anything in the capture.'));
  if (meta.flags.anonymised || named === 0) return;
  const shown = a.names.slice(0, HOST_ROWS);
  r.table({
    head: ['Address', 'Name', 'Learned from', 'Frames', 'Bytes'],
    body: shown.map((n) => [n.address, n.name, SOURCE_LABELS[n.source], count(n.frames), bytes(n.bytes)]),
    numeric: [3, 4],
    widths: { 2: 22, 3: 16, 4: 18 },
    fontSize: 7.6,
  });
  if (named > shown.length) r.note(`${plural(named - shown.length, 'more named host')} not listed; the busiest are shown.`);
}

function processesSection(r: Report, a: CaptureAnalysis): void {
  if (a.processes.length === 0) return;
  r.section('Processes', 'Traffic attributed to programs on the capturing machine, from its socket table. '
    + 'Frames the operating system could not attribute are not counted here.', 24);
  const shown = a.processes.slice(0, 20);
  r.table({
    head: ['Process', 'PID', 'Frames', 'Bytes', 'Share', 'First seen'],
    body: shown.map((p) => [p.name, String(p.pid), count(p.packets), bytes(p.bytes), percentCell(p.bytes, a.bytes), offset(p.firstSeen)]),
    numeric: [1, 2, 3, 4, 5],
    widths: { 1: 16, 2: 18, 3: 20, 4: 16, 5: 20 },
  });
  if (a.processes.length > shown.length) r.note(`${plural(a.processes.length - shown.length, 'more process', 'more processes')} not listed.`);
}

function methodsSection(r: Report, a: CaptureAnalysis, meta: CaptureMeta): void {
  r.section('Methods', null, 40);
  const scope = meta.scope === 'filtered'
    ? `the ${plural(a.frames, 'frame')} matching the display filter ${quoteFilter(meta.filter)}, out of ${count(meta.frames.inCapture)} in the capture`
    : `all ${plural(a.frames, 'frame')} in the capture`;
  const paras = [
    `Scope. Computed in one pass over ${scope}. It is a report on those frames as a whole, `
      + 'not on what happened to be on screen, and it lists no individual packets.',
    'Dissection. Frames were decoded by Inwire\'s own dissectors. Protocol and field names follow Wireshark\'s, '
      + 'and TCP analysis (retransmissions, duplicate acknowledgements, lost segments) follows Wireshark\'s sequence analysis.',
    'Findings. Expert findings are grouped into eight categories named for what a reader should conclude. '
      + 'A frame this machine sent whose checksum was not yet filled in is counted as unverifiable, not as damaged.',
    'Figures. Rates are averages over the span from the first frame to the last; the busiest second is the '
      + 'whole second with the most traffic. Sizes are decimal (1 kB = 1,000 bytes). Times are UTC. '
      + `Ranked tables show the top ${a.top} by bytes, ties broken by frames and then address.`,
    'Names. Host names are passive: they come only from the capture itself. Nothing in this report was looked up.',
    meta.flags.anonymised
      ? 'Anonymisation. Addresses were mapped with a prefix-preserving scheme (Crypto-PAn) under a key generated for '
        + 'this export alone, so subnets survive and MAC addresses keep their vendor half. Host names, process '
        + 'paths and the names of DNS resolvers were removed.'
      : 'Anonymisation. None: addresses are shown as captured.',
  ];
  for (const p of paras) {
    const dot = p.indexOf('. ');
    leadParagraph(r, p.slice(0, dot + 1), p.slice(dot + 2));
  }
  // Last, because only now is every string on the page and the count final.
  if (r.ink.replaced > 0) {
    leadParagraph(r, 'Characters.', `${plural(r.ink.replaced, 'character')} outside the PDF's standard font `
      + '(Windows-1252) are shown as "?".');
  }
}

/** A paragraph that opens with a bold run-in lead, the way a methods note reads. */
function leadParagraph(r: Report, lead: string, rest: string): void {
  const doc = r.doc;
  const size = 8.8;
  const lineH = size * 0.3528 * 1.4;
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(size);
  const leadText = r.t(lead);
  const leadW = doc.getTextWidth(leadText) + 1.6;
  doc.setFont('helvetica', 'normal');
  const clean = r.t(rest);
  const first = (doc.splitTextToSize(clean, CW - leadW) as string[])[0] ?? '';
  const remainder = clean.slice(first.length).trimStart();
  const lines = [first, ...(remainder ? doc.splitTextToSize(remainder, CW) as string[] : [])];
  r.ensure(Math.min(lines.length, 3) * lineH);
  lines.forEach((line, i) => {
    if (i > 0) r.ensure(lineH);
    const y = r.y + lineH * 0.75;
    if (i === 0) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(P.ink);
      doc.text(leadText, M, y);
    }
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(P.ink);
    doc.text(line, i === 0 ? M + leadW : M, y);
    r.y += lineH;
  });
  r.y += 2.4;
}

function frame(r: Report, meta: CaptureMeta, opts: PdfReportOptions): void {
  const doc = r.doc;
  const total = doc.getNumberOfPages();
  const stamp = `Inwire ${meta.version} · generated ${utcMinute(opts.now)}`;
  for (let page = 1; page <= total; page++) {
    doc.setPage(page);
    if (page > 1) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.5);
      doc.setTextColor(P.ink);
      doc.text('Inwire capture analysis', M, 13);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(P.muted);
      const source = doc.splitTextToSize(r.t(sourceLine(meta)), CW - 40) as string[];
      doc.text(source[0], PAGE_W - M, 13, { align: 'right' });
      doc.setDrawColor(P.rule);
      doc.setLineWidth(0.2);
      doc.line(M, 15.5, PAGE_W - M, 15.5);
    }
    doc.setDrawColor(P.rule);
    doc.setLineWidth(0.2);
    doc.line(M, PAGE_H - 14.5, PAGE_W - M, PAGE_H - 14.5);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.5);
    doc.setTextColor(P.muted);
    doc.text(r.t(`Page ${page} of ${total} · ${stamp}`), PAGE_W / 2, PAGE_H - 10, { align: 'center' });
  }
}

export function buildPdfReport(real: CaptureAnalysis, realMeta: CaptureMeta, opts: PdfReportOptions): Blob {
  if (realMeta.flags.anonymised && !opts.anonymiser) {
    // Said loudly rather than printed: a report that claims to be anonymised
    // and was handed nothing to anonymise it with would say so on its cover
    // while printing every address.
    throw new Error('An anonymised report needs the export\'s Anonymiser.');
  }
  const analysis = opts.anonymiser ? redactAnalysis(real, opts.anonymiser) : real;
  const meta = opts.anonymiser ? redactMeta(realMeta, opts.anonymiser) : realMeta;
  const r = new Report(opts.compress ?? false);
  r.doc.setProperties({
    title: 'Inwire capture analysis',
    creator: 'Inwire',
    subject: 'Capture analysis report',
  });

  cover(r, meta, opts);
  summary(r, analysis);
  findingsSection(r, analysis, meta);
  timelineSection(r, analysis);
  hierarchySection(r, analysis);
  sizesSection(r, analysis);
  endpointsSection(r, analysis);
  conversationsSection(r, analysis);
  expertSection(r, analysis);
  hostsSection(r, analysis, meta);
  processesSection(r, analysis);
  methodsSection(r, analysis, meta);
  frame(r, meta, opts);

  return r.doc.output('blob');
}
