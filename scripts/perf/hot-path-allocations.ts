/**
 * Expensive objects must be built once, not once per call.
 *
 *   npx tsx scripts/perf/hot-path-allocations.ts
 *
 * `formatArrivalTime` constructed a `new Intl.DateTimeFormat(...)` on every
 * call, and it is called twice per frame. Constructing one resolves a locale
 * and sets up ICU - it measured at ~49 us - so a 12,858 frame capture spent
 * 1.27 seconds building 25,716 formatters it then threw away. A CPU profile put
 * that one function at **38% of the entire run, and more than half of all
 * dissection time**. Caching the two formatters took the pipeline from ~5,900
 * frames/s to ~19,000.
 *
 * Nothing would have caught that. It is not a correctness bug, no test could
 * fail on it, and it is invisible in review because the expensive part is the
 * constructor, not the call. So this is a static check instead: inside
 * `src/services/`, a `new Intl.*` / `new TextDecoder` / `new TextEncoder` must
 * sit at module scope, where it is built once, and not inside a function.
 *
 * The rule is deliberately about *where the line is*, not about how hot the
 * caller is, because "this one is not on a hot path" is exactly the reasoning
 * that put the formatter where it was.
 */
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

const ROOT = join(process.cwd(), 'src', 'services');

/** Constructors whose cost is in the constructor, not the call. */
const EXPENSIVE = /new\s+(Intl\.[A-Za-z]+|TextDecoder|TextEncoder)\s*\(/;

/**
 * Lines that may construct one anywhere.
 *
 * Only for a construction that genuinely cannot be hoisted - one whose
 * arguments are not known until the call. Add with a reason, never to silence
 * the check.
 */
const ALLOWED: { file: string; reason: string }[] = [];

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) out.push(...walk(full));
    else if (entry.endsWith('.ts')) out.push(full);
  }
  return out;
}

let failures = 0;
const offenders: string[] = [];
let checked = 0;
let hoisted = 0;

for (const file of walk(ROOT)) {
  const rel = relative(process.cwd(), file).split(sep).join('/');
  const lines = readFileSync(file, 'utf8').split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!EXPENSIVE.test(line)) continue;
    // A doc comment describing the rule is not a construction.
    if (/^\s*(\*|\/\/)/.test(line)) continue;
    checked++;
    // Module scope, by this repo's formatting: a top-level `const` starts at
    // column 0. Anything indented is inside a function, a class or a block.
    const atModuleScope = /^(export\s+)?const\s/.test(line)
      // `x ??= new Intl...` inside a getter is the lazy-singleton form: the
      // construction runs at most once, which is the property this checks for.
      // Locale data is not work to do at module init in a Worker that may
      // never dissect anything, so this form is preferred, not merely allowed.
      || /\?\?=\s*new\s/.test(line);
    if (atModuleScope) { hoisted++; continue; }
    if (ALLOWED.some((a) => a.file === rel)) { hoisted++; continue; }
    failures++;
    offenders.push(`${rel}:${i + 1}\n      ${line.trim()}`);
  }
}

console.log(`Scanned src/services for per-call construction of expensive objects.`);
console.log(`  ${checked} construction(s) found, ${hoisted} at module scope\n`);

if (failures > 0) {
  for (const o of offenders) {
    console.log(`FAIL  built inside a function, so once per call:`);
    console.log(`      ${o}\n`);
  }
  console.log(`${failures} check(s) FAILED`);
  console.log('Hoist it to a module-level const, or add it to ALLOWED with a reason.');
  process.exit(1);
}

console.log('PASS  every expensive object is constructed once, at module scope');
console.log('\nAll hot-path allocation checks passed.');
process.exit(0);
