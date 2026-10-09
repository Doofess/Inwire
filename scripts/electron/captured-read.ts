/**
 * Main's half of catching the live view up: reading a piece of the agent's
 * own pcapng for the Worker (ADR 0053 phase 4, `electron/capturedRead.ts`).
 *
 *   npx tsx scripts/electron/captured-read.ts
 *
 * The Worker parses hostile bytes, so what it may ask main for is the rule
 * worth holding: a capture this app would have made, a file the agent would
 * have named, a byte range - never a path. And the answers it relies on: the
 * bytes asked for, fewer at the end of a file still being written, none when
 * nothing new is there, and `gone` - not an error - for a file a ring
 * deleted.
 */
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { MAX_CAPTURED_READ, readCaptured } from '../../electron/capturedRead';

let failures = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${!ok && detail ? `\n        ${detail}` : ''}`);
}

const root = mkdtempSync(path.join(tmpdir(), 'inwire-captured-read-'));
try {
  const id = 'cap-20261009-120000-ab12';
  mkdirSync(path.join(root, id, 'pcapng'), { recursive: true });
  const file = path.join(root, id, 'pcapng', 'capture.pcapng');
  const bytes = new Uint8Array(10_000).map((_, i) => (i * 13) & 0xff);
  writeFileSync(file, bytes);
  // Something beside the agent's files, which no name may reach.
  writeFileSync(path.join(root, id, 'index.iwidx'), 'not for the Worker');
  writeFileSync(path.join(root, 'secret.txt'), 'not for the Worker');

  const a = await readCaptured(root, id, 'capture.pcapng', 1000, 500);
  check('the bytes asked for, from the offset asked',
    a.bytes !== null && a.bytes.length === 500 && a.bytes.every((b, i) => b === bytes[1000 + i]) && !a.gone && a.error === undefined);

  const b = await readCaptured(root, id, 'capture.pcapng', 9_800, 4096);
  check('fewer at the end of the file', b.bytes !== null && b.bytes.length === 200 && b.bytes[0] === bytes[9_800]);

  const c = await readCaptured(root, id, 'capture.pcapng', 10_000, 4096);
  check('none past the end - nothing written yet, which is not an error', c.bytes !== null && c.bytes.length === 0 && !c.gone && c.error === undefined);

  appendFileSync(file, new Uint8Array([1, 2, 3]));
  const d = await readCaptured(root, id, 'capture.pcapng', 10_000, 4096);
  check('...and what the agent writes next is there on the next read', d.bytes !== null && d.bytes.length === 3 && d.bytes[2] === 3);

  const ring = 'capture_00002_20261009120000.pcapng';
  writeFileSync(path.join(root, id, 'pcapng', ring), new Uint8Array([9, 9, 9, 9]));
  const e = await readCaptured(root, id, ring, 0, 4096);
  check('a ring file, by the name the agent gave it', e.bytes !== null && e.bytes.length === 4);
  unlinkSync(path.join(root, id, 'pcapng', ring));
  const f = await readCaptured(root, id, ring, 0, 4096);
  check('a file a ring deleted is gone - an answer, not an error', f.gone && f.bytes === null && f.error === undefined);

  const big = await readCaptured(root, id, 'capture.pcapng', 0, MAX_CAPTURED_READ * 4);
  check('no more than the most one read hands over', big.bytes !== null && big.bytes.length <= MAX_CAPTURED_READ);

  const refused: [string, string, string, number, number][] = [
    ['a capture id this app would not make', '..', 'capture.pcapng', 0, 10],
    ['a capture id that walks out of the folder', `${id}/../..`, 'capture.pcapng', 0, 10],
    ['a path for a name', id, '../index.iwidx', 0, 10],
    ['a name the agent never gives', id, 'index.iwidx', 0, 10],
    ['a name that walks up', id, '..\\..\\secret.txt', 0, 10],
    ['a negative offset', id, 'capture.pcapng', -1, 10],
    ['a fractional length', id, 'capture.pcapng', 0, 1.5],
  ];
  for (const [what, cap, name, offset, length] of refused) {
    const r = await readCaptured(root, cap, name, offset, length);
    check(`refused: ${what}`, r.bytes === null && !r.gone && typeof r.error === 'string');
  }
} finally {
  rmSync(root, { recursive: true, force: true });
}

console.log(failures === 0 ? '\nAll captured-read checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
