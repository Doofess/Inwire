/**
 * What an Excel export costs, per cell, on real captures.
 *
 *   node --expose-gc --import tsx scripts/perf/xlsx-cost.ts
 *
 * The workbook is the one format that cannot stream: exceljs's browser build
 * has only `Workbook`, which holds every cell until `writeBuffer`. So an Excel
 * export has a size past which it takes the renderer down, and
 * `XLSX_BUDGET` in `src/services/export/writers/xlsx.ts` is where it stops
 * short of that. This measures the number that budget is derived from rather
 * than guessing it - the plan's own "measured, not guessed" rule.
 *
 * For each real capture, three workbooks - the standard columns alone, with
 * every dissected field, and with fields and raw bytes - and for each:
 *
 *   retained   heap the finished model holds after every row is added (gc'd)
 *   peak       the highest heap seen while `writeBuffer` serialises it,
 *              sampled on a 1 ms timer, above the baseline
 *   build/write  wall time for the rows, and for `writeBuffer`
 *
 * both per Packets-sheet cell as the writer counts them - every standard cell,
 * every non-empty field cell. The peak is the one the budget divides: it is
 * the moment the model and its serialised form are both alive.
 *
 * The largest capture is also written 4 and 12 times over (renumbered copies),
 * because the small workbooks' peak is dominated by fixed costs - the young
 * generation, exceljs's own tables - spread over few cells. The figure that
 * matters is the one the curve settles to at a size near the budget.
 *
 * A measurement, not a test: it has no pass mark, so `scripts/check.ts` lists
 * it under NOT_TESTS. Skips cleanly without the fixtures.
 */
import { loadRealCaptures } from '../export/realCaptures';
import { FieldSurvey } from '../../src/services/export/fieldColumns';
import {
  createXlsxWriter, XLSX_BYTES_PER_CELL, XLSX_BUDGET, XLSX_HEAP_BUDGET,
} from '../../src/services/export/writers/xlsx';
import type { Packet } from '../../src/types/packet';

const PAGE = 4096;
/**
 * How many times over the largest capture is written, to see the figure at
 * scale. 4 by default: 12 is ~8M cells, past V8's 4 GB heap, and dies rather
 * than measuring - which is the budget's point made the hard way.
 */
const REPEATS = (process.env.XLSX_COST_REPEATS ?? '4').split(',').map(Number).filter((n) => n > 1);
const MB = 1024 * 1024;

function settle(): number {
  if (global.gc) for (let i = 0; i < 4; i++) global.gc();
  return process.memoryUsage().heapUsed;
}

interface Result {
  label: string;
  frames: number;
  cells: number;
  retainedPerCell: number;
  peakPerCell: number;
  buildMs: number;
  writeMs: number;
  fileBytes: number;
  /** Heap in use before the workbook: the captures themselves. */
  baseBytes: number;
  peakBytes: number;
}

async function measure(label: string, packets: readonly Packet[], fields: boolean, raw: boolean): Promise<Result> {
  const survey = new FieldSurvey();
  survey.addPage(packets);
  const columns = fields ? survey.columns() : [];
  const base = settle();

  const t0 = performance.now();
  const writer = await createXlsxWriter({
    includeRawBytes: raw,
    fields: columns,
    expectedFrames: packets.length,
    expectedFieldCells: fields ? survey.cells : 0,
    budget: { rows: 1_048_575, cells: Number.MAX_SAFE_INTEGER },
  });
  for (let at = 0; at < packets.length; at += PAGE) writer.write(packets.slice(at, at + PAGE));
  const buildMs = performance.now() - t0;
  const retained = settle() - base;

  let peak = process.memoryUsage().heapUsed;
  const sampler = setInterval(() => {
    const used = process.memoryUsage().heapUsed;
    if (used > peak) peak = used;
  }, 1);
  const t1 = performance.now();
  const chunks = await writer.finish();
  const writeMs = performance.now() - t1;
  clearInterval(sampler);
  peak = Math.max(peak, process.memoryUsage().heapUsed);
  const fileBytes = chunks.reduce((a, c) => a + c.byteLength, 0);
  const cells = writer.cellsWritten;

  return {
    label, frames: packets.length, cells,
    retainedPerCell: retained / cells,
    peakPerCell: (peak - base) / cells,
    buildMs, writeMs, fileBytes, baseBytes: base, peakBytes: peak - base,
  };
}

/** The capture n times over, renumbered and re-timed so it reads as one longer capture. */
function repeated(packets: readonly Packet[], times: number): Packet[] {
  const out: Packet[] = [];
  const span = packets.length > 0 ? packets[packets.length - 1].tsUs - packets[0].tsUs + 1_000_000 : 0;
  for (let t = 0; t < times; t++) {
    for (const p of packets) out.push({ ...p, id: out.length + 1, tsUs: p.tsUs + t * span });
  }
  return out;
}

async function main() {
  if (!global.gc) {
    console.log('Run with --expose-gc, or the heap numbers are noise:');
    console.log('  node --expose-gc --import tsx scripts/perf/xlsx-cost.ts');
    process.exit(1);
  }
  const captures = await loadRealCaptures();
  if (captures.length === 0) process.exit(0);

  const results: Result[] = [];
  for (const capture of captures) {
    results.push(await measure(`${capture.name} standard`, capture.packets, false, false));
    results.push(await measure(`${capture.name} +fields`, capture.packets, true, false));
    results.push(await measure(`${capture.name} +fields +raw`, capture.packets, true, true));
  }
  const largest = captures.reduce((a, b) => (b.packets.length > a.packets.length ? b : a));
  for (const times of REPEATS) {
    results.push(await measure(`${largest.name} x${times} +fields`, repeated(largest.packets, times), true, false));
  }

  const pad = (s: string, n: number) => s.padEnd(n);
  const num = (n: number, d = 0) => n.toLocaleString('en-US', { maximumFractionDigits: d, minimumFractionDigits: d });
  console.log();
  console.log(`${pad('workbook', 22)}${pad('frames', 9)}${pad('cells', 11)}${pad('retained B/cell', 17)}`
    + `${pad('peak B/cell', 13)}${pad('peak MB', 9)}${pad('base MB', 9)}${pad('build ms', 10)}${pad('write ms', 10)}`
    + `${pad('us/cell', 9)}file MB`);
  for (const r of results) {
    console.log(`${pad(r.label, 22)}${pad(num(r.frames), 9)}${pad(num(r.cells), 11)}`
      + `${pad(num(r.retainedPerCell), 17)}${pad(num(r.peakPerCell), 13)}`
      + `${pad(num(r.peakBytes / MB), 9)}${pad(num(r.baseBytes / MB), 9)}`
      + `${pad(num(r.buildMs), 10)}${pad(num(r.writeMs), 10)}`
      + `${pad(num(((r.buildMs + r.writeMs) * 1000) / r.cells, 2), 9)}${num(r.fileBytes / MB, 1)}`);
  }

  // The small workbooks' per-cell peak is fixed cost over few cells; the
  // figure the budget should follow is the largest workbook's.
  const largestRun = results.reduce((a, b) => (b.cells > a.cells ? b : a));
  console.log();
  console.log(`peak at the largest workbook (${num(largestRun.cells)} cells): ${num(largestRun.peakPerCell)} B a cell`);
  console.log(`XLSX_BYTES_PER_CELL is ${XLSX_BYTES_PER_CELL}; at the ${num(XLSX_HEAP_BUDGET / MB)} MB heap budget `
    + `the cell budget is ${num(XLSX_BUDGET.cells)} cells`);
  console.log(`the whole-field workbook of the largest capture is `
    + `${num(results.find((r) => r.label === `${largest.name} +fields`)!.cells)} cells`);
  if (largestRun.peakPerCell > XLSX_BYTES_PER_CELL) {
    console.log(`NOTE  the peak is above XLSX_BYTES_PER_CELL - raise it to at least ${Math.ceil(largestRun.peakPerCell)}.`);
  }
  console.log('The sampled peak understates a constrained heap: also run a repeat under a');
  console.log('--max-old-space-size near its peak MB, and take the limit it needs.');
  process.exit(0);
}

main().catch((err) => {
  console.log(`FAIL  ${err instanceof Error ? err.stack : String(err)}`);
  process.exit(1);
});
