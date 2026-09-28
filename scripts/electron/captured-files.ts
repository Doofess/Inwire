/**
 * "Save as captured": which files leave, and that they leave whole (ADR 0052).
 *
 *   npx tsx scripts/electron/captured-files.ts
 *
 * `electron/capturedFiles.ts` copies the agent's own pcapng files out of a
 * capture's folder. The renderer names a capture id and main does the rest, so
 * the rules worth holding are main's: only files the agent names are copied,
 * only from a folder an id this app makes can name, byte for byte, and a set
 * lands whole or not at all.
 *
 * Driven with the real dumpcap-written captures in `test/fixtures/` standing
 * in for the agent's files - the agent writes the same layout, and a copy
 * does not look inside. Skips cleanly without them.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  capturedFilePath, capturedFiles, copyRing, copyWhole, freshFolder,
} from '../../electron/capturedFiles';
import { OPTIONAL_CAPTURES } from '../export/realCaptures';

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

const fixtures = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'test', 'fixtures');
const sources = Object.values(OPTIONAL_CAPTURES).map((name) => path.join(fixtures, name)).filter(existsSync);
if (sources.length < 2) {
  console.log('SKIP  the dumpcap-written fixtures are not present (test/fixtures/README.md)');
  process.exit(0);
}
const bytes = sources.map((file) => readFileSync(file));
const same = (file: string, i: number) => Buffer.compare(readFileSync(file), bytes[i]) === 0;

const root = mkdtempSync(path.join(tmpdir(), 'inwire-captured-files-'));
try {
  const captures = path.join(root, 'captures');
  const single = 'cap-20260928-120000-0a01';
  const ring = 'cap-20260928-120000-0a02';
  mkdirSync(path.join(captures, single, 'pcapng'), { recursive: true });
  mkdirSync(path.join(captures, ring, 'pcapng'), { recursive: true });
  writeFileSync(path.join(captures, single, 'pcapng', 'capture.pcapng'), bytes[0]);
  const ringNames = ['capture_00008_20260928120001.pcapng', 'capture_00009_20260928120002.pcapng'];
  writeFileSync(path.join(captures, ring, 'pcapng', ringNames[1]), bytes[1]);
  writeFileSync(path.join(captures, ring, 'pcapng', ringNames[0]), bytes[0]);
  // What else a folder can hold, none of it the agent's.
  for (const stray of ['notes.txt', 'capture.pcapng.1a2b.partial', 'capture_8.pcapng', 'other.pcapng']) {
    writeFileSync(path.join(captures, ring, 'pcapng', stray), 'not the agent\'s');
  }

  console.log('--- which files ---\n');
  check('a single capture\'s one file', capturedFiles(captures, single), ['capture.pcapng']);
  check('a ring\'s files, in the order they were written, and nothing else in the folder',
    capturedFiles(captures, ring), ringNames);
  const resumed = 'cap-20260928-120000-0a04';
  mkdirSync(path.join(captures, resumed, 'pcapng'), { recursive: true });
  for (const name of ['capture.pcapng', 'capture-2.pcapng', 'capture_00001_20260928120000-3.pcapng', 'capture-x.pcapng']) {
    writeFileSync(path.join(captures, resumed, 'pcapng', name), bytes[0]);
  }
  check('a name the agent took because the first was taken is the agent\'s too',
    capturedFiles(captures, resumed), ['capture-2.pcapng', 'capture.pcapng', 'capture_00001_20260928120000-3.pcapng']);
  for (const bad of ['..', `${single}\\..\\${ring}`, 'cap-2026-bad', '', 'captures']) {
    check(`an id this app would not make names nothing: ${JSON.stringify(bad)}`, capturedFiles(captures, bad), []);
  }
  check('a capture with no files has none', capturedFiles(captures, 'cap-20260928-120000-0a03'), []);

  console.log('\n--- a copy is the file ---\n');
  const out = path.join(root, 'out');
  mkdirSync(out);
  const target = path.join(out, `${single}.pcapng`);
  copyWhole([capturedFilePath(captures, single, 'capture.pcapng')], [target]);
  check('one file lands where it was sent, byte for byte', same(target, 0), true);
  check('...and no partial is left beside it', readdirSync(out), [`${single}.pcapng`]);

  const folder = copyRing(captures, ring, capturedFiles(captures, ring), out);
  check('a ring goes into a new folder named for the capture', path.basename(folder), ring);
  check('...holding its files by their own names, byte for byte',
    [readdirSync(folder).sort(), same(path.join(folder, ringNames[0]), 0), same(path.join(folder, ringNames[1]), 1)],
    [ringNames, true, true]);
  const second = copyRing(captures, ring, capturedFiles(captures, ring), out);
  check('saving it again never lands among the first copy', path.basename(second), `${ring}-2`);
  check('freshFolder never answers a folder that exists', existsSync(freshFolder(out, ring)), false);

  console.log('\n--- whole or not at all ---\n');
  const partialOut = path.join(root, 'partial');
  mkdirSync(partialOut);
  let threw = false;
  try {
    copyWhole(
      [capturedFilePath(captures, ring, ringNames[0]), capturedFilePath(captures, ring, ringNames[1])],
      [path.join(partialOut, 'a.pcapng'), path.join(partialOut, 'missing', 'b.pcapng')],
    );
  } catch {
    threw = true;
  }
  check('a copy that fails half way says so', threw, true);
  check('...and leaves nothing behind, not even the file that had finished', readdirSync(partialOut), []);
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log();
if (failures > 0) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All captured-file checks passed.');
process.exit(0);
