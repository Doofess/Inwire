/**
 * Test launches run in the background, and stay that way.
 *
 *   npx tsx scripts/electron/background-launch.ts
 *
 * The owner works on this machine while the suite runs, so no script may start
 * the app through Playwright directly - every one goes through `launchApp`,
 * which sets `INWIRE_BACKGROUND_WINDOW=1`, and `electron/main.ts` must read it.
 * Pure source reading: no Electron, no build.
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

const HELPER = path.join('scripts', 'electron', 'launchApp.ts');
const self = path.join('scripts', 'electron', 'background-launch.ts');
const direct = /\b_electron\s*\.\s*launch\s*\(|\belectron\s*\.\s*launch\s*\(/;
const offenders = walk('scripts')
  .filter((f) => f !== self && f !== HELPER)
  .filter((f) => direct.test(readFileSync(f, 'utf8').replace(/\/\/.*$/gm, '')));
check('no script launches Electron except through launchApp', offenders.length === 0, offenders.join(', '));

const helper = readFileSync(HELPER, 'utf8');
check('launchApp sets INWIRE_BACKGROUND_WINDOW', /INWIRE_BACKGROUND_WINDOW:\s*'1'/.test(helper));
check('launchApp has an explicit visible opt-out', /visible/.test(helper));

const main = readFileSync(path.join('electron', 'main.ts'), 'utf8');
check('main reads INWIRE_BACKGROUND_WINDOW', /process\.env\.INWIRE_BACKGROUND_WINDOW/.test(main));
check('main skips window.show() in the background',
  /if \(BACKGROUND_WINDOW\)[\s\S]*?else \{\s*window\.once\('ready-to-show', \(\) => window\.show\(\)\)/.test(main));

process.exit(failures === 0 ? 0 : 1);
