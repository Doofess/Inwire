/**
 * No switch in a dissector has the same `case` label twice.
 *
 *   npx tsx scripts/dissect/switch-cases.ts
 *
 * ## Why this exists
 *
 * A duplicate case label is legal JavaScript. The first one wins and the
 * second is dead code, and nothing in this repository could see it:
 *
 * - `tsc` does not diagnose it. There is no compiler flag that does -
 *   `noFallthroughCasesInSwitch` is on and is a different question, and the
 *   rule that would catch this (`no-duplicate-case`) lives in ESLint, which
 *   this project does not run.
 * - `scripts/dissect/registry.ts` reads the dissector sources as **text**,
 *   looking for an `abbrev:` literal and a writer. A row inside a dead branch
 *   has both, so a field registered for it passes.
 * - `scripts/dissect/wireshark-abbrevs.ts` asks whether the name exists in
 *   `tshark -G fields`. A correctly spelled name for a row that never runs
 *   passes.
 * - `scripts/parity/tree-coverage.ts` would notice - the name simply never
 *   appears - but its floors are written **from** the measurement, so the
 *   absence is recorded as normal on the commit that introduced it.
 *
 * So three gates agreed while `tls.ts` carried two `case 11:` blocks: an old
 * one drawing EC point formats with no abbrevs, and a newer named one, after
 * it, that had never executed. Three names were missing from the tree for as
 * long as both existed, and every check said PASS.
 *
 * ## What this can and cannot see
 *
 * This is a brace-counting scan, not a parser - the same trade
 * `registry.ts` makes, for the same reason: it runs under plain `tsx` with no
 * dependency. Comments are blanked and string literals defused first, so a
 * brace or a colon inside either cannot be read as structure.
 *
 * What it cannot see is the other half of the same bug: a case whose label is
 * a **wrong constant**, which is unique and unreachable rather than duplicated
 * and unreachable. `case 17513` for an extension every capture sends as 17613
 * is invisible here and was found the only way it can be - by the measurement
 * not moving by the amount the change predicted.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..');

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (/\.tsx?$/.test(entry)) out.push(full);
  }
  return out;
}

const SOURCES = [
  join(root, 'src', 'services', 'pcapParser.ts'),
  ...walk(join(root, 'src', 'services', 'dissectors')),
  ...walk(join(root, 'src', 'services', 'dissect')),
  ...walk(join(root, 'src', 'services', 'filter')),
];

/**
 * Neutralises comments and string literals, keeping every offset where it was.
 *
 * Same length so line numbers survive, which is what makes the failure message
 * point at a line somebody can open. A comment is blanked outright; a string
 * is defused - see `SUBSTITUTE` below for why those are not the same thing.
 */
function blankOut(text: string): string {
  const out = text.split('');
  let i = 0;
  const blank = (from: number, to: number): void => {
    for (let k = from; k < to && k < out.length; k++) if (out[k] !== '\n') out[k] = ' ';
  };
  /**
   * Rewrites what could be read as structure, and keeps everything else.
   *
   * **Substituted, not blanked**, and it took two wrong versions to get here.
   * Blanking a string wholesale turned every `case 'tcp':` in the filter
   * engine into `case :`, so five labels collapsed into one; keeping only
   * `\w` did the same to the operator cases, where `'=='` and `'!='` are
   * punctuation to the last character. A structural character inside a string
   * still has to *differ* from the other structural characters, because in
   * `json.ts` the label content **is** one - `case '"':` beside
   * `case '\\':`. So each maps to a distinct letter that cannot be read as
   * structure, and the reported line comes from the original text rather than
   * from this mangling.
   */
  const SUBSTITUTE: Record<string, string> = {
    '{': 'L', '}': 'R', ':': 'C', "'": 'Q', '"': 'D', '`': 'T', '\\': 'B', '(': 'P', ')': 'E',
  };
  const defuse = (from: number, to: number): void => {
    for (let k = from; k < to && k < out.length; k++) {
      const swap = SUBSTITUTE[out[k]];
      if (swap !== undefined) out[k] = swap;
    }
  };
  while (i < text.length) {
    const two = text.slice(i, i + 2);
    if (two === '//') {
      const end = text.indexOf('\n', i);
      blank(i, end === -1 ? text.length : end);
      i = end === -1 ? text.length : end;
    } else if (two === '/*') {
      const end = text.indexOf('*/', i + 2);
      blank(i, end === -1 ? text.length : end + 2);
      i = end === -1 ? text.length : end + 2;
    } else if (text[i] === '"' || text[i] === "'" || text[i] === '`') {
      const quote = text[i];
      let k = i + 1;
      while (k < text.length && text[k] !== quote) k += text[k] === '\\' ? 2 : 1;
      defuse(i, k + 1);
      i = k + 1;
    } else {
      i++;
    }
  }
  return out.join('');
}

interface Duplicate { file: string; source: string; first: number; again: number }

/**
 * Every `case` label, grouped by the switch that owns it.
 *
 * A switch's body is the brace that opens immediately after its `(...)`, so a
 * label belongs to the innermost switch whose body depth is one below the
 * current depth. Nested switches and the braces a `case X: { ... }` block puts
 * around its own body are both handled by that one rule.
 */
function duplicatesIn(file: string, text: string): Duplicate[] {
  const src = blankOut(text);
  const found: Duplicate[] = [];
  /** Open switches: the brace depth of each one's body, and its labels. */
  const open: { depth: number; seen: Map<string, number> }[] = [];
  let depth = 0;
  let line = 1;
  /** A `switch (...)` whose body brace has not been seen yet. */
  let pending = false;

  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (ch === '\n') { line++; continue; }
    if (src.startsWith('switch', i) && /\W/.test(src[i - 1] ?? ' ') && /[\s(]/.test(src[i + 6] ?? '')) {
      pending = true;
      i += 5;
      continue;
    }
    if (ch === '{') {
      depth++;
      if (pending) { open.push({ depth, seen: new Map() }); pending = false; }
      continue;
    }
    if (ch === '}') {
      if (open.length > 0 && open[open.length - 1].depth === depth) open.pop();
      depth--;
      continue;
    }
    if (src.startsWith('case', i) && /\W/.test(src[i - 1] ?? ' ') && /\s/.test(src[i + 4] ?? '')) {
      const colon = src.indexOf(':', i);
      if (colon === -1) continue;
      const owner = open[open.length - 1];
      // Only a label at the switch's own body depth belongs to it. A `case`
      // inside a nested block that is not itself a switch cannot exist, but a
      // nested switch's labels sit one deeper and must not merge upward.
      if (owner !== undefined && depth === owner.depth) {
        const label = src.slice(i + 4, colon).trim();
        const first = owner.seen.get(label);
        if (first !== undefined) {
          found.push({ file, source: (text.split('\n')[line - 1] ?? '').trim(), first, again: line });
        } else {
          owner.seen.set(label, line);
        }
      }
      i = colon;
    }
  }
  return found;
}

let failures = 0;
const duplicates: Duplicate[] = [];
let labels = 0;
let switches = 0;
for (const file of SOURCES) {
  const text = readFileSync(file, 'utf8');
  switches += (blankOut(text).match(/\bswitch\s*\(/g) ?? []).length;
  labels += (blankOut(text).match(/\bcase\s/g) ?? []).length;
  duplicates.push(...duplicatesIn(relative(root, file).split(sep).join('/'), text));
}

if (duplicates.length === 0) {
  console.log(`PASS  ${labels} case labels across ${switches} switches, none duplicated`);
} else {
  failures++;
  console.log(`FAIL  ${duplicates.length} duplicate case label(s) - the later block is dead code`);
  for (const d of duplicates) {
    console.log(`        ${d.file}:${d.again}  ${d.source}`);
    console.log(`          already handled at line ${d.first}; this block never runs`);
  }
}

// The check is worthless if the scan is not actually finding switches - an
// expression that silently matched nothing would print PASS for ever. This is
// the same argument `wireshark-abbrevs.ts` makes about an exemption nobody
// observes.
if (switches < 10 || labels < 100) {
  failures++;
  console.log(`FAIL  scanned only ${switches} switches and ${labels} labels - the scan has stopped finding them`);
} else {
  console.log(`PASS  the scan reaches ${SOURCES.length} dissector sources`);
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All switch-case checks passed.');
process.exit(0);
