/**
 * The report's drawing primitives: the mark, tiles, chips and bar charts,
 * drawn with jsPDF's own vector operators.
 *
 * No DOM, no canvas and no rasterising. A chart drawn as paths stays sharp at
 * any zoom and in print, and - the reason that decides it - it runs under plain
 * `tsx`, so `scripts/export/pdf-report.ts` exercises exactly the code that
 * ships. A chart library would want a document to draw into.
 *
 * Every function takes the document and a box in millimetres and returns
 * nothing it did not draw. Colours are passed in rather than chosen here, so
 * the report decides what a colour means and these only draw it.
 */
import type { jsPDF } from 'jspdf';
import { brandMarkPaths, MARK_SIZE } from '../../lib/brandMark';

export interface Box { x: number; y: number; w: number; h: number }

/**
 * The brand mark, as filled polygons, `size` millimetres square.
 *
 * Read from `brandMarkPaths` rather than redrawn, so the report's mark is the
 * app icon's mark: the path data is absolute M/L/Z, which `markBounds` already
 * relies on, and each plate becomes one closed `lines` call in painter's order.
 */
export function drawBrandMark(doc: jsPDF, x: number, y: number, size: number): void {
  const scale = size / MARK_SIZE;
  for (const { d, fill } of brandMarkPaths('primary')) {
    const nums = (d.match(/-?\d+(?:\.\d+)?/g) ?? []).map(Number);
    const points: [number, number][] = [];
    for (let i = 0; i + 1 < nums.length; i += 2) points.push([x + nums[i] * scale, y + nums[i + 1] * scale]);
    if (points.length < 3) continue;
    const deltas = points.slice(1).map((p, i) => [p[0] - points[i][0], p[1] - points[i][1]]);
    doc.setFillColor(fill);
    doc.lines(deltas, points[0][0], points[0][1], [1, 1], 'F', true);
  }
}

/**
 * A step for an axis: 1, 2, 2.5 or 5 times a power of ten, so a gridline
 * reads as a number somebody would have chosen.
 */
export function niceStep(max: number, targetTicks = 4, integer = false): number {
  if (!(max > 0)) return 1;
  const raw = max / targetTicks;
  const magnitude = 10 ** Math.floor(Math.log10(raw));
  const norm = raw / magnitude;
  const step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 2.5 ? 2.5 : norm <= 5 ? 5 : 10) * magnitude;
  return integer ? Math.max(1, Math.ceil(step)) : step;
}

/** 0, 250, 1.5k, 2M - an axis label, where the unit is in the title. */
export function compactNumber(v: number): string {
  const abs = Math.abs(v);
  const trim = (n: number) => {
    const fixed = n >= 100 ? n.toFixed(0) : n >= 10 ? n.toFixed(1) : n.toFixed(2);
    return fixed.includes('.') ? fixed.replace(/\.?0+$/, '') : fixed;
  };
  if (abs >= 1e9) return `${trim(v / 1e9)}G`;
  if (abs >= 1e6) return `${trim(v / 1e6)}M`;
  if (abs >= 1e3) return `${trim(v / 1e3)}k`;
  return trim(v);
}

export interface Palette {
  ink: string;
  muted: string;
  rule: string;
  fill: string;
}

/** A labelled figure in a bordered tile. */
export function drawTile(
  doc: jsPDF, box: Box, label: string, value: string, sub: string | null, p: Palette, accent: string,
): void {
  doc.setDrawColor(p.rule);
  doc.setLineWidth(0.25);
  doc.setFillColor('#ffffff');
  doc.roundedRect(box.x, box.y, box.w, box.h, 1.4, 1.4, 'FD');
  // A short accent rule rather than a coloured tile: eight tiles in the brand
  // colour would shout, and the accent is only there to say "this is a figure".
  doc.setFillColor(accent);
  doc.rect(box.x + 4, box.y + 3.6, 6, 0.7, 'F');

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.5);
  doc.setTextColor(p.muted);
  doc.text(label, box.x + 4, box.y + 8);

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(p.ink);
  doc.text(value, box.x + 4, box.y + 14.6);

  if (sub) {
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7);
    doc.setTextColor(p.muted);
    doc.text(sub, box.x + 4, box.y + box.h - 2.8);
  }
}

/**
 * A rounded label in a colour pair; returns its width so a row of them can be
 * laid out left to right.
 */
export function drawChip(
  doc: jsPDF, x: number, y: number, text: string, background: string, color: string, fontSize = 8,
): number {
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(fontSize);
  const padX = 2.4;
  const h = fontSize * 0.55;
  const w = doc.getTextWidth(text) + padX * 2;
  doc.setFillColor(background);
  doc.roundedRect(x, y, w, h, h / 2, h / 2, 'F');
  doc.setTextColor(color);
  // Helvetica's middle baseline sits above the optical centre of a run of
  // capitals and figures, so the text drops a hair to look centred.
  doc.text(text, x + padX, y + h / 2 + fontSize * 0.03, { baseline: 'middle' });
  return w;
}

/** A horizontal proportion bar on a quiet track. */
export function drawHBar(
  doc: jsPDF, x: number, y: number, w: number, h: number, fraction: number, color: string, track: string,
): void {
  doc.setFillColor(track);
  doc.rect(x, y, w, h, 'F');
  const f = Math.max(0, Math.min(1, fraction));
  if (f > 0) {
    doc.setFillColor(color);
    // Never narrower than a hairline: a real share that rounds to nothing
    // would otherwise draw as an empty track and read as zero.
    doc.rect(x, y, Math.max(w * f, 0.3), h, 'F');
  }
}

export interface BarChartSpec {
  values: number[];
  /** Drawn from the baseline up inside each bar, in `overlayColor` - a share of the bar. */
  overlay?: number[];
  color: string;
  overlayColor?: string;
  /** Labels under the axis, at bar indices; a label at `values.length` marks the right edge. */
  xLabels: { index: number; text: string }[];
  /** Axis title, top left. */
  title: string;
  integer?: boolean;
  /** Printed above each bar, when there are few enough bars to have room. */
  valueLabels?: string[];
}

/**
 * A vertical bar chart with a labelled y axis and light gridlines.
 *
 * The axis is scaled to a nice step above the tallest bar, so the top gridline
 * is a round number rather than the data's maximum. Bars are separated by a
 * gap while they are wide enough to afford one; at a hundred bars in 150 mm a
 * gap would be most of the ink.
 */
export function drawBarChart(doc: jsPDF, box: Box, spec: BarChartSpec, p: Palette): void {
  const gutter = 13;
  const bottom = 6;
  const top = 6;
  const plot: Box = { x: box.x + gutter, y: box.y + top, w: box.w - gutter, h: box.h - top - bottom };

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7);
  doc.setTextColor(p.muted);
  doc.text(spec.title, box.x, box.y + 2.5);

  const max = Math.max(0, ...spec.values);
  const step = niceStep(max, 4, spec.integer);
  const axisMax = max > 0 ? Math.ceil(max / step) * step : step;

  doc.setLineWidth(0.15);
  for (let v = 0; v <= axisMax + step / 1000; v += step) {
    const y = plot.y + plot.h - (v / axisMax) * plot.h;
    doc.setDrawColor(v === 0 ? p.muted : p.rule);
    doc.setLineWidth(v === 0 ? 0.3 : 0.15);
    doc.line(plot.x, y, plot.x + plot.w, y);
    doc.setFontSize(6.5);
    doc.setTextColor(p.muted);
    doc.text(compactNumber(v), plot.x - 1.8, y, { align: 'right', baseline: 'middle' });
  }

  const n = spec.values.length;
  if (n === 0) return;
  const slot = plot.w / n;
  const gap = slot >= 2.4 ? slot * 0.22 : slot >= 1.2 ? slot * 0.12 : 0;
  const barW = slot - gap;

  for (let i = 0; i < n; i++) {
    const v = spec.values[i];
    if (v <= 0) continue;
    const h = (v / axisMax) * plot.h;
    const x = plot.x + i * slot + gap / 2;
    const yTop = plot.y + plot.h - h;
    doc.setFillColor(spec.color);
    doc.rect(x, yTop, barW, h, 'F');
    const o = spec.overlay?.[i] ?? 0;
    if (o > 0 && spec.overlayColor) {
      // A red sliver that rounds away would hide the one bucket with a fault
      // in it, so any overlay gets at least a hairline.
      const oh = Math.max((o / axisMax) * plot.h, 0.35);
      doc.setFillColor(spec.overlayColor);
      doc.rect(x, plot.y + plot.h - oh, barW, oh, 'F');
    }
    const label = spec.valueLabels?.[i];
    if (label) {
      doc.setFontSize(6.5);
      doc.setTextColor(p.ink);
      doc.text(label, x + barW / 2, yTop - 1.2, { align: 'center' });
    }
  }

  doc.setFontSize(6.5);
  doc.setTextColor(p.muted);
  for (const { index, text } of spec.xLabels) {
    const x = plot.x + index * slot;
    doc.setDrawColor(p.muted);
    doc.setLineWidth(0.15);
    doc.line(x, plot.y + plot.h, x, plot.y + plot.h + 0.9);
    doc.text(text, x, plot.y + plot.h + 3.6, { align: index === 0 ? 'left' : index >= n ? 'right' : 'center' });
  }
}

/** Category labels centred under each bar, for a chart whose bars are categories. */
export function drawCategoryLabels(doc: jsPDF, box: Box, labels: string[], p: Palette): void {
  const gutter = 13;
  const plotX = box.x + gutter;
  const slot = (box.w - gutter) / labels.length;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(p.muted);
  labels.forEach((text, i) => {
    doc.text(text, plotX + slot * (i + 0.5), box.y + box.h - 2.4, { align: 'center' });
  });
}
