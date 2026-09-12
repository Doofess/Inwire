/**
 * The two TypeScript programs stay equally strict, and stay separate.
 *
 *   npx tsx scripts/electron/tsconfigs.ts
 *
 * `tsconfig.electron.json`'s own comment has said this script asserts the
 * strictness flags since it was written, and this script did not exist. That
 * is the failure mode being fixed as much as any drift: a comment naming a
 * guard is worth less than no comment at all, because it stops anyone looking.
 *
 * ## What the split is for
 *
 * The root config gives the renderer `lib: ["DOM"]` and `types:
 * ["vite/client"]`. Under it, `electron/main.ts` could reference `window`,
 * `localStorage` or `import.meta.env` and compile perfectly clean - then throw
 * in a process that has none of them. `tsconfig.electron.json` has no DOM at
 * all, which turns that from a runtime surprise into a build failure, and the
 * root config excludes `electron/` so the strict config is the only one that
 * sees it.
 *
 * Both halves have to hold. A `lib` that quietly gained DOM, or an `exclude`
 * that quietly lost `electron`, would each put main back under the permissive
 * program with nothing to show for it.
 *
 * ## And equally strict
 *
 * The four flags are **copied** between the files rather than extended from a
 * shared base - which is a deliberate trade, because extending would hide the
 * DOM difference that matters. The cost of copying is that they can drift, and
 * the drift would land in exactly the code nothing else checks: the main
 * process, the preload and the store host.
 */
import { readFileSync } from 'node:fs';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);

/**
 * The flags `CLAUDE.md` opens the Commands section with.
 *
 * `noImplicitReturns` is deliberately absent from both and stays absent: the
 * root config records that it was 34 errors, nearly all a switch whose
 * branches all return, which is a style argument rather than a correctness
 * one.
 */
const STRICTNESS = [
  'strict', 'noUnusedLocals', 'noUnusedParameters', 'noFallthroughCasesInSwitch',
] as const;

interface TsConfig {
  compilerOptions?: Record<string, unknown>;
  include?: string[];
  exclude?: string[];
}

/**
 * Both files are JSONC - they are mostly comment, and the comments are the
 * reasoning.
 *
 * Scanned character by character rather than stripped with a regex, because
 * the regex version is wrong on this repository's own config: `tsconfig.json`
 * has `"paths": { "@/*": ["./*"] }`, and a pattern looking for `/*` finds one
 * **inside a string**, opens a comment there and swallows everything up to the
 * next `*&#47;` - which is the closing line of a real comment forty lines
 * further down. It parsed as a syntax error, which is the lucky outcome; the
 * unlucky one is a config that parses with half its keys missing.
 */
function stripJsonc(text: string): string {
  let out = '';
  let inString = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      out += c;
      if (c === '\\') { out += text[++i] ?? ''; continue; }
      if (c === '"') inString = false;
      continue;
    }
    if (c === '"') { inString = true; out += c; continue; }
    if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      out += '\n';
      continue;
    }
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 1;
      continue;
    }
    out += c;
  }
  // A trailing comma left behind by a removed entry is legal in JSONC.
  return out.replace(/,(\s*[}\]])/g, '$1');
}

function readJsonc(file: string): TsConfig {
  const text = stripJsonc(readFileSync(file, 'utf8'));
  try {
    return JSON.parse(text) as TsConfig;
  } catch (error) {
    throw new Error(`${file} did not parse after stripping comments: `
      + `${error instanceof Error ? error.message : String(error)}`);
  }
}

const root = readJsonc('tsconfig.json');
const electron = readJsonc('tsconfig.electron.json');

console.log('--- equally strict ---\n');

for (const flag of STRICTNESS) {
  check(`${flag} is on in the renderer program`, root.compilerOptions?.[flag], true);
  check(`...and in the electron program`, electron.compilerOptions?.[flag], true);
}

check('neither turns on noImplicitReturns, which is a separate argument',
  [root.compilerOptions?.noImplicitReturns, electron.compilerOptions?.noImplicitReturns],
  [undefined, undefined]);

console.log('\n--- and separate, which is the point of two ---\n');

{
  const lib = (electron.compilerOptions?.lib ?? []) as string[];
  check('the electron program has no DOM',
    lib.filter((entry) => /dom/i.test(entry)), []);
  // The other half of the same rule. Without the exclude, `electron/` compiles
  // under the root program too - which has DOM - and a reference to `window`
  // in main passes one of the two checks `npm run lint` runs.
  checkTrue('...and the renderer program does not compile electron/',
    (root.exclude ?? []).includes('electron'));

  const rootLib = (root.compilerOptions?.lib ?? []) as string[];
  checkTrue('the renderer program does have DOM',
    rootLib.some((entry) => /^dom$/i.test(entry)));

  // `scripts/` stays in the root program on purpose: every assertion script
  // imports `src/` directly and must type-check against the same lib the
  // renderer uses. An exclude here would let a script drift from what it
  // asserts about.
  check('the assertion scripts type-check with the renderer',
    (root.exclude ?? []).filter((entry) => entry.startsWith('scripts')), []);
  check('the electron program covers electron/ and nothing else',
    electron.include, ['electron/**/*.ts']);
}

console.log('\n--- and `npm run lint` runs both ---\n');

{
  const scripts = (JSON.parse(readFileSync('package.json', 'utf8')) as {
    scripts: Record<string, string>;
  }).scripts;
  // Two programs are worth nothing if the build only checks one of them.
  checkTrue('lint type-checks the renderer program', /tsc --noEmit/.test(scripts.lint ?? ''));
  checkTrue('...and the electron program',
    /tsconfig\.electron\.json/.test(scripts.lint ?? ''));
}

console.log(failures === 0
  ? '\nAll tsconfig checks passed.'
  : `\n${failures} tsconfig check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
