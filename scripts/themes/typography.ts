/**
 * Two heading levels, both in the sans face; the mono face is for data.
 *
 *   npx tsx scripts/themes/typography.ts
 *
 * A pane or panel is named by a TITLE (sentence case, semibold) and a group
 * inside it by a MICRO_LABEL (uppercase, tracked, Segoe). Both live in
 * `src/components/common/typography.ts`. Uppercase in Cascadia Mono was the
 * second header system the 2026-10-24 audit found beside them - the same job
 * done in another face - so a class string that sets both is the failure, and
 * the check names every one by file and line.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) walk(path, out);
    else if (/\.tsx?$/.test(name)) out.push(path);
  }
  return out;
}

/**
 * Every string and template literal in a source file, with the line it starts
 * on. A small lexer rather than a regex, so a quote inside a comment is not a
 * string and a template literal over several lines is one class list. Quoted
 * strings end at the line, as they must in JS, which keeps an apostrophe in
 * JSX text from swallowing the file.
 */
function literals(source: string): { text: string; line: number }[] {
  const found: { text: string; line: number }[] = [];
  let line = 1;
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\n') { line++; continue; }
    if (c === '/' && source[i + 1] === '/') {
      while (i < source.length && source[i] !== '\n') i++;
      line++;
      continue;
    }
    if (c === '/' && source[i + 1] === '*') {
      const end = source.indexOf('*/', i + 2);
      const stop = end === -1 ? source.length : end + 2;
      for (let j = i; j < stop; j++) if (source[j] === '\n') line++;
      i = stop - 1;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') {
      const start = line;
      let j = i + 1;
      while (j < source.length && source[j] !== c) {
        if (source[j] === '\\') j++;
        else if (source[j] === '\n') {
          if (c !== '`') break;
          line++;
        }
        j++;
      }
      found.push({ text: source.slice(i + 1, j), line: start });
      i = j;
    }
  }
  return found;
}

/** A utility, with or without variants: `font-mono`, `md:font-mono`. */
const has = (classes: string, utility: string): boolean =>
  classes.split(/\s+/).some((token) => token === utility || token.endsWith(`:${utility}`));

// --- No uppercase in the mono face -------------------------------------------

const hits: string[] = [];
for (const path of walk('src')) {
  for (const { text, line } of literals(readFileSync(path, 'utf8'))) {
    if (has(text, 'font-mono') && has(text, 'uppercase')) hits.push(`${path.replace(/\\/g, '/')}:${line}`);
  }
}
check('no class string sets uppercase in the mono face', hits.length === 0,
  `${hits.length} site(s), each to TITLE or MICRO_LABEL:\n        ${hits.join('\n        ')}`);

// --- The two levels ----------------------------------------------------------

const typography = readFileSync('src/components/common/typography.ts', 'utf8');
check("TITLE is 'font-sans text-xs font-semibold text-foreground'",
  typography.includes("export const TITLE = 'font-sans text-xs font-semibold text-foreground';"));
check("MICRO_LABEL is 'font-sans text-[10px] font-bold uppercase tracking-widest text-muted-foreground'",
  typography.includes("export const MICRO_LABEL = 'font-sans text-[10px] font-bold uppercase tracking-widest text-muted-foreground';"));

const paneHeader = readFileSync('src/components/common/PaneHeader.tsx', 'utf8');
check('PaneHeader uses TITLE and no font-mono',
  /\{TITLE\}|\$\{TITLE\}/.test(paneHeader) && !paneHeader.includes('font-mono') && !has(paneHeader, 'uppercase'));

// A TITLE is sentence case: every word after the first starts lower case,
// unless the whole word is an acronym ("DNS"). Literal titles only; the side
// bar's come from PANEL_TITLES, which is one word each.
const titleCase: string[] = [];
for (const path of walk('src')) {
  const source = readFileSync(path, 'utf8');
  for (const match of source.matchAll(/<PaneHeader[\s\S]*?title="([^"]+)"/g)) {
    if (match[1].split(' ').slice(1).some((word) => /^[A-Z][a-z]/.test(word))) {
      titleCase.push(`${path.replace(/\\/g, '/')}: "${match[1]}"`);
    }
  }
}
check('PaneHeader titles are sentence case', titleCase.length === 0, titleCase.join('\n        '));

// A header row inherits its table's face, so the per-string check above cannot
// see an uppercase header under a mono table. The first row after each one
// must name the sans face itself.
const inheritedMono: string[] = [];
for (const path of walk('src')) {
  const source = readFileSync(path, 'utf8');
  for (const table of source.matchAll(/<table className="([^"]*)"/g)) {
    if (!has(table[1], 'font-mono')) continue;
    const row = /<tr\b[\s\S]*?\bclassName=(?:"([^"]*)"|\{`([^`]*)`\})/.exec(source.slice(table.index!))?.slice(1).join('') ?? '';
    if (!has(row, 'font-sans') && !row.includes('${MICRO_LABEL}')) {
      inheritedMono.push(`${path.replace(/\\/g, '/')}:${source.slice(0, table.index).split('\n').length}`);
    }
  }
}
check('a mono table\'s header row is set in the sans face', inheritedMono.length === 0, inheritedMono.join('\n        '));

const settingsLayout = readFileSync('src/components/common/settingsLayout.tsx', 'utf8');
check('SECTION_CLASS is MICRO_LABEL', /export const SECTION_CLASS = MICRO_LABEL;/.test(settingsLayout));

// --- Chrome is sans: the wrappers that held counts and labels ----------------

// The outermost element's class list: the first `className="..."` after the
// opening of the component's returned JSX.
const wrapperClasses = (source: string, anchor: RegExp): string => {
  const at = source.search(anchor);
  const match = /className="([^"]*)"/.exec(source.slice(at));
  return at === -1 || !match ? 'font-mono' : match[1];
};
const statusBar = readFileSync('src/components/status/StatusBar.tsx', 'utf8');
const countsReadout = readFileSync('src/components/common/PacketCountsReadout.tsx', 'utf8');
check('the status bar and PacketCountsReadout set no font-mono on their wrappers',
  !has(wrapperClasses(statusBar, /<footer/), 'font-mono')
    && !has(wrapperClasses(countsReadout, /<div className="min-w-0 flex items-center gap-2/), 'font-mono'),
  'the wrapper is chrome; put font-mono on the spans that hold packet data');

if (failures > 0) {
  console.log(`\n${failures} check(s) FAILED`);
  process.exit(1);
}
