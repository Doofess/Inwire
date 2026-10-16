/**
 * Motion tokens: two durations and one curve, for the surfaces that open.
 *
 *   npx tsx scripts/themes/motion-tokens.ts
 *
 * Side bar, sheets, the palette and toasts animate; selection, arrow keys and
 * filter results never do. The tokens are declared once, are not theme colours
 * (so they stay out of the block `registry.ts` requires every theme to repeat),
 * and are zeroed by BOTH reduced-motion routes: the OS media query (so the very
 * first paint, before lib/motion.ts has run, is already still) and the app's own
 * `data-motion` attribute (so "Animations: Never" works with an OS that allows
 * motion, and "Always" can still override an OS that does not).
 */
import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const css = readFileSync('src/index.css', 'utf8');

/** Body of the first rule whose selector line is exactly `selector {`. */
function ruleBody(source: string, selector: string): string | null {
  const re = new RegExp(`(^|\\n)[ \\t]*${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*\\{`);
  const m = re.exec(source);
  if (!m) return null;
  const start = m.index + m[0].length;
  let depth = 1;
  for (let i = start; i < source.length; i++) {
    if (source[i] === '{') depth++;
    else if (source[i] === '}' && --depth === 0) return source.slice(start, i);
  }
  return null;
}
const decl = (body: string | null, name: string): string | null =>
  body?.match(new RegExp(`${name}\\s*:\\s*([^;]+);`))?.[1].trim() ?? null;

// --- The tokens --------------------------------------------------------------

const base = ruleBody(css, 'html');
check('an `html` rule declares the motion tokens', base !== null);
check('--motion-fast is 120ms', decl(base, '--motion-fast') === '120ms', `got ${decl(base, '--motion-fast')}`);
check('--motion-panel is 180ms', decl(base, '--motion-panel') === '180ms', `got ${decl(base, '--motion-panel')}`);
check('--ease-out is cubic-bezier(0.2, 0, 0, 1)',
  decl(base, '--ease-out')?.replace(/\s+/g, '') === 'cubic-bezier(0.2,0,0,1)', `got ${decl(base, '--ease-out')}`);

// --- Reduced motion, both routes ---------------------------------------------

const attr = ruleBody(css, "[data-motion='reduce']");
check("[data-motion='reduce'] zeroes --motion-fast", decl(attr, '--motion-fast') === '0ms', `got ${decl(attr, '--motion-fast')}`);
check("[data-motion='reduce'] zeroes --motion-panel", decl(attr, '--motion-panel') === '0ms', `got ${decl(attr, '--motion-panel')}`);

const media = ruleBody(css, '@media (prefers-reduced-motion: reduce)');
const inMedia = media === null ? null : ruleBody(media, "html:not([data-motion='full'])");
check('the OS media query zeroes --motion-fast', decl(inMedia, '--motion-fast') === '0ms', `got ${decl(inMedia, '--motion-fast')}`);
check('the OS media query zeroes --motion-panel', decl(inMedia, '--motion-panel') === '0ms', `got ${decl(inMedia, '--motion-panel')}`);
check("the media query yields to data-motion='full' (the app setting wins)", inMedia !== null);

// --- Keyframes ----------------------------------------------------------------

const frames: Record<string, string> = {
  'palette-in': 'translateY(-4px)',
  'sheet-in': 'translateY(6px)',
  'sidebar-in': 'translateX(-8px)',
};
for (const [name, from] of Object.entries(frames)) {
  const body = ruleBody(css, `@keyframes ${name}`);
  check(`@keyframes ${name} exists`, body !== null);
  const flat = (body ?? '').replace(/\s+/g, ' ');
  check(`${name} fades opacity 0 -> 1`, /opacity: 0/.test(flat) && /opacity: 1/.test(flat));
  check(`${name} starts from ${from}`, flat.includes(from), flat);
  check(`${name} never animates width`, !/width/.test(flat));
}

// --- Uses ----------------------------------------------------------------------

check('a class applies sidebar-in over --motion-fast with --ease-out',
  /animation:\s*sidebar-in\s+var\(--motion-fast\)\s+var\(--ease-out\)/.test(css));
check('a class applies sheet-in over --motion-panel with --ease-out',
  /animation:\s*sheet-in\s+var\(--motion-panel\)\s+var\(--ease-out\)/.test(css));
check('the palette applies palette-in over --motion-panel',
  readFileSync('src/components/common/CommandPalette.tsx', 'utf8').includes('palette-in var(--motion-panel'));

// --- Where motion must not be -------------------------------------------------

function sourcesUnder(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sourcesUnder(join(dir, e.name)) : /\.(tsx?|css)$/.test(e.name) ? [join(dir, e.name)] : []);
}
const still = [...sourcesUnder('src/components/packet-list'), 'src/components/common/FilterBar.tsx'];
for (const file of still) {
  const text = readFileSync(file, 'utf8');
  check(`${file} uses no motion token or motion class`,
    !/--motion-|palette-in|sheet-in|sidebar-in|motion-sheet|motion-sidebar/.test(text));
}

if (failures > 0) {
  console.log(`\n${failures} failed`);
  process.exit(1);
}
console.log('\nall motion-token checks passed');
