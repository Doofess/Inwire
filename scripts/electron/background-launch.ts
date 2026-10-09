/**
 * Test launches run in the background, and stay that way.
 *
 *   npx tsx scripts/electron/background-launch.ts
 *
 * The owner works on this machine while the suite runs, so no script may start
 * the app any way but `launchApp`, which sets `INWIRE_BACKGROUND_WINDOW=1`, and
 * `electron/main.ts` must act on it. Pure source reading: no Electron, no build.
 */
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || !detail ? '' : `\n      ${detail}`}`);
  if (!ok) failures++;
}

function walk(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? walk(path.join(dir, e.name)) : e.name.endsWith('.ts') ? [path.join(dir, e.name)] : []);
}

/**
 * Removes comments without cutting into strings, template literals or regex-free
 * code: a small scanner, because `//` appears inside `'app://inwire'`.
 */
function stripComments(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    const n = src[i + 1];
    if (c === '/' && n === '/') { while (i < src.length && src[i] !== '\n') i++; continue; }
    if (c === '/' && n === '*') { const e = src.indexOf('*/', i + 2); i = e < 0 ? src.length : e + 2; continue; }
    if (c === '"' || c === "'" || c === '`') {
      let j = i + 1;
      while (j < src.length && src[j] !== c) j += src.charCodeAt(j) === 92 ? 2 : 1;
      out += src.slice(i, j + 1);
      i = j + 1;
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

const HELPER = path.join('scripts', 'electron', 'launchApp.ts');
const self = path.join('scripts', 'electron', 'background-launch.ts');
const files = walk('scripts').filter((f) => f !== self && f !== HELPER);
const code = new Map(files.map((f) => [f, stripComments(readFileSync(f, 'utf8'))]));

const usesElectronApi = [...code].filter(([, t]) => /\b_electron\b/.test(t)).map(([f]) => f);
check('no script references playwright\'s _electron outside launchApp', usesElectronApi.length === 0,
  usesElectronApi.join(', '));

// Anchored on the spawned BINARY - the first argument - never on the word anywhere in the
// arguments: scripts/electron/preload-sandbox.ts runs `node electron/build.cjs` and must stay clean.
const SPAWNS_ELECTRON =
  /\b(spawn|spawnSync|exec|execSync|execFile|execFileSync|fork)\s*\(\s*['"`]([^'"`]*[\\/])?electron(\.exe|\.cmd)?['"`]|\.bin[\\/]electron/;
const spawnsElectron = [...code].filter(([, t]) => SPAWNS_ELECTRON.test(t)).map(([f]) => f);
check('the spawn check flags electron binaries',
  [String.raw`spawn('electron', [])`, String.raw`execFileSync("C:\x\node_modules\.bin\electron", [])`, String.raw`spawnSync('a/electron.exe')`]
    .every((x) => SPAWNS_ELECTRON.test(x)));
check('the spawn check leaves preload-sandbox.ts\'s build.cjs call clean',
  !SPAWNS_ELECTRON.test(`execFileSync('node', [path.join('electron', 'build.cjs')], {})`));
check('no script spawns electron through child_process', spawnsElectron.length === 0, spawnsElectron.join(', '));

const helper = stripComments(readFileSync(HELPER, 'utf8'));
check('launchApp sets INWIRE_BACKGROUND_WINDOW', /INWIRE_BACKGROUND_WINDOW:\s*'1'/.test(helper));
check('launchApp has an explicit visible opt-out that clears the flag',
  /if \(visible\)[\s\S]*delete env\.INWIRE_BACKGROUND_WINDOW/.test(helper));

const main = stripComments(readFileSync(path.join('electron', 'main.ts'), 'utf8'));
check('main reads the flag into a const',
  /const BACKGROUND_WINDOW\s*=\s*process\.env\.INWIRE_BACKGROUND_WINDOW\s*===\s*'1'/.test(main));
check('main shows the window without activation only in the background',
  /if \(BACKGROUND_WINDOW\) \{[\s\S]*?showInactive\(\)[\s\S]*?\} else \{\s*window\.once\('ready-to-show', \(\) => window\.show\(\)\)/.test(main));
check('main does not maximize a background window', /state\.maximized && !BACKGROUND_WINDOW\) window\.maximize\(\)/.test(main));
check('main does not track (save) a background window\'s state',
  /if \(!BACKGROUND_WINDOW\) trackWindowState\(window\)/.test(main));
check('main keeps a parked window out of occlusion throttling',
  /if \(BACKGROUND_WINDOW\) app\.commandLine\.appendSwitch\('disable-features', 'CalculateNativeWinOcclusion'\)/.test(main));

process.exit(failures === 0 ? 0 : 1);
