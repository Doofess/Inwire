/**
 * Drives the real app to show trees rebuilt from frame records (ADR 0049).
 *
 *   npm run build && npx tsx scripts/electron/revisit-drive.ts
 *
 * Imports the real `inwire` fixture into the built app and opens frames whose
 * correct tree depends on the frames before them - relative sequence numbers
 * deep in a TCP stream, a DNS query's `[Response In]`, a QUIC connection
 * number. An import is dissected on the renderer's thread, so the pipeline
 * Worker's tree cache holds none of these frames: every one is answered by
 * rebuilding its tree from its record in the capture store. The values that
 * need the conversation must be on screen, and the row a partial replay adds -
 * `[Reassembly context]` - must not be.
 *
 * The values are chosen to DISCRIMINATE: a TCP segment is only picked where its
 * relative sequence number differs from the raw one, so a tree built from the
 * frame alone, with no context, could not pass. Each is checked as its whole
 * `name: value` row, not as a number that could appear anywhere in the pane.
 *
 * **And the path is observed, not inferred.** A full replay of the
 * conversation would draw the same tree, so a correct tree alone proves
 * nothing about how it was built. An init script wraps the Worker's
 * `postMessage` before the app creates it, and a click that fell back sends the
 * Worker a `replay` - which must never happen here.
 *
 * **And a second run with a key log**: the key-log capture, imported with its
 * key log followed the way a person's is, opening HTTP/3 and HTTP/2 frames.
 * Their trees are decrypted content, which a record never holds - so they
 * come from the Worker's memory, where the import handed them (ADR 0049).
 *
 * Not in `npm run check` (listed in `check.ts`'s NOT_TESTS): it launches the
 * app and needs a build and the fixture. Real capture only; no stub agent.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { arrive, FIXTURES, type Arrived } from '../pipeline/arrival';
import { keyLog } from '../../src/services/tls/keyLog';
import { installWorkerSpy, openFrames, sentToWorker, type FrameCase } from './openFrame';
import type { ProtocolField, ProtocolLayer } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`.slice(0, 300));
    console.log(`        actual   ${JSON.stringify(actual)}`.slice(0, 300));
  }
}
const checkTrue = (name: string, condition: boolean) => check(name, condition, true);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function skip(why: string): never {
  console.log(`SKIP  ${why}`);
  process.exit(0);
}

/** A field anywhere in a tree, by abbrev. */
function fieldOf(layers: ProtocolLayer[], abbrev: string): ProtocolField | undefined {
  const walk = (fields: ProtocolField[]): ProtocolField | undefined => {
    for (const f of fields) {
      if (f.abbrev === abbrev) return f;
      const inner = f.children ? walk(f.children) : undefined;
      if (inner !== undefined) return inner;
    }
    return undefined;
  };
  for (const layer of layers) {
    const found = walk(layer.fields);
    if (found !== undefined) return found;
  }
  return undefined;
}
const valueOf = (layers: ProtocolLayer[], abbrev: string) => {
  const f = fieldOf(layers, abbrev);
  return f === undefined ? undefined : String(f.value);
};
/** The row as the pane draws it, `name: value`, with no whitespace to disagree on. */
const lineOf = (layers: ProtocolLayer[], abbrev: string): [string, string] | null => {
  const f = fieldOf(layers, abbrev);
  return f === undefined ? null : [abbrev, `${f.name}:${String(f.value)}`.replace(/\s+/g, '')];
};
/** The leading number of a value like `1234 (relative sequence number)`. */
const numberOf = (value: string | undefined) => (value === undefined ? NaN : Number.parseInt(value, 10));

if (process.platform !== 'win32') skip('the desktop app is Windows-only');
if (!existsSync(path.join('dist', 'index.html')) || !existsSync(path.join('dist-electron', 'main.cjs'))) {
  skip('no build to launch - run `npm run build` first');
}
let electron: typeof import('playwright')['_electron'];
try {
  ({ _electron: electron } = await import('playwright'));
} catch {
  skip('playwright is not installed');
}

/** Adds a case, once per frame: two picks landing on one frame would open it twice. */
const casePusher = (cases: FrameCase[]) => (label: string, layers: ProtocolLayer[], id: number, abbrevs: string[]) => {
  if (cases.some((c) => c.id === id)) return;
  const expect = abbrevs.map((a) => lineOf(layers, a)).filter((l): l is [string, string] => l !== null);
  if (expect.length > 0) cases.push({ label, id, expect });
};
/** The first field under an abbrev prefix, for a layer whose field names vary by frame. */
function firstAbbrev(layers: ProtocolLayer[], prefix: string): string | undefined {
  const walk = (fields: ProtocolField[]): string | undefined => {
    for (const f of fields) {
      if (f.abbrev?.startsWith(prefix)) return f.abbrev;
      const inner = f.children ? walk(f.children) : undefined;
      if (inner !== undefined) return inner;
    }
    return undefined;
  };
  for (const layer of layers) {
    const found = walk(layer.fields);
    if (found !== undefined) return found;
  }
  return undefined;
}

/** Frames whose tree needs the frames before them: deep TCP and TLS, DNS, QUIC. */
function contextCases(arrived: Arrived[]): FrameCase[] {
  const cases: FrameCase[] = [];
  const push = casePusher(cases);
  const untaken = (a: Arrived) => !cases.some((c) => c.id === a.packet.id);
  // TCP segments where the relative sequence number is not the raw one, spread
  // through the capture - early, middle and late.
  const tcpDeep = arrived.filter((a) => {
    const rel = numberOf(valueOf(a.packet.layers, 'tcp.seq'));
    const raw = numberOf(valueOf(a.packet.layers, 'tcp.seq_raw'));
    return rel > 1000 && rel !== raw;
  });
  checkTrue('the capture has TCP segments deep in their streams to open', tcpDeep.length > 0);
  for (const at of [0.1, 0.5, 0.9]) {
    const a = tcpDeep[Math.floor(at * (tcpDeep.length - 1))];
    if (a === undefined) continue;
    push(`TCP segment deep in its stream (${Math.round(at * 100)}% through the capture)`,
      a.packet.layers, a.packet.id, ['tcp.seq', 'tcp.stream']);
  }
  // A TLS record deep in its stream: the record cursor is state from before it.
  const tls = arrived.find((a) => untaken(a) && valueOf(a.packet.layers, 'tls.record.length') !== undefined
    && numberOf(valueOf(a.packet.layers, 'tcp.seq')) > 100_000);
  if (tls) push('a TLS record deep in its stream', tls.packet.layers, tls.packet.id, ['tls.record.length', 'tcp.seq']);
  const dns = arrived.find((a) => untaken(a) && valueOf(a.packet.layers, 'dns.response_in') !== undefined);
  if (dns) push('a DNS query, whose answer is a later frame', dns.packet.layers, dns.packet.id, ['dns.response_in']);
  const quic = arrived.find((a) => untaken(a) && numberOf(valueOf(a.packet.layers, 'quic.connection.number')) > 3);
  if (quic) push('a QUIC packet on a later connection', quic.packet.layers, quic.packet.id, ['quic.connection.number']);
  return cases;
}

/**
 * Frames whose tree is decrypted content: HTTP/3 out of 1-RTT QUIC and HTTP/2
 * out of TLS. Their records hold none of it; the Worker's memory does.
 */
function decryptedCases(arrived: Arrived[]): FrameCase[] {
  const cases: FrameCase[] = [];
  const push = casePusher(cases);
  const kinds = [['http3.', 'HTTP/3 out of a 1-RTT QUIC packet'], ['http2.', 'HTTP/2 out of a TLS record']] as const;
  for (const [prefix, what] of kinds) {
    const found = arrived.filter((a) => firstAbbrev(a.packet.layers, prefix) !== undefined);
    checkTrue(`the capture decrypts to ${prefix.slice(0, -1)}`, found.length > 0);
    for (const at of [0.2, 0.8]) {
      const a = found[Math.floor(at * (found.length - 1))];
      if (a === undefined) continue;
      push(`${what} (${Math.round(at * 100)}% through them)`, a.packet.layers, a.packet.id,
        [firstAbbrev(a.packet.layers, prefix)!]);
    }
  }
  return cases;
}

/** Imports one real capture into the built app and opens each case's frame. */
async function drive(name: string, capture: string, keysPath: string | null, pick: (arrived: Arrived[]) => FrameCase[]) {
  keyLog.clear();
  if (keysPath !== null) keyLog.add(readFileSync(keysPath, 'utf8'));
  const { arrived } = await arrive(capture);
  keyLog.clear();
  const cases = pick(arrived);

  const profile = mkdtempSync(path.join(tmpdir(), 'inwire-revisit-drive-'));
  const app = await electron.launch({
    args: ['.'],
    // The key log goes in the way a person's does: main follows the file its
    // own SSLKEYLOGFILE names, when asked to (ADR 0045).
    env: {
      ...process.env, INWIRE_USER_DATA: profile,
      ...(keysPath !== null ? { SSLKEYLOGFILE: path.resolve(keysPath) } : {}),
    } as Record<string, string>,
  });
  try {
    const page = await app.firstWindow();
    page.setDefaultTimeout(30_000);
    // Every command the renderer sends a Worker - installed before the reload
    // below, so it is in place before the app creates its pipeline Worker.
    await installWorkerSpy(page);
    const sentTypes = async () => (await sentToWorker(page)).map((s) => s.type);
    await page.waitForLoadState('domcontentloaded');
    await page.evaluate(() => localStorage.setItem('inwire.tour', JSON.stringify({ completed: true })));
    await page.reload();
    await page.waitForLoadState('domcontentloaded');
    await sleep(1500);

    if (keysPath !== null) {
      await page.evaluate(() => window.inwire?.followSuggestedKeyLog?.());
      const until = Date.now() + 15_000;
      while (Date.now() < until && !(await sentTypes()).includes('keylog')) await sleep(200);
      checkTrue(`${name}: the key log reached the Worker before the import`, (await sentTypes()).includes('keylog'));
    }

    const counts = () => page.evaluate(() => {
      const text = document.querySelector('[data-packet-counts]')?.textContent ?? '';
      const m = text.match(/([\d,]+)\s*\/\s*([\d,]+)/);
      return m ? [Number(m[1].replace(/,/g, '')), Number(m[2].replace(/,/g, ''))] : [0, 0];
    });

    console.log(`\n--- ${name}: importing ${arrived.length.toLocaleString()} real frames ---\n`);
    await page.getByLabel('Export or import a capture').click();
    await sleep(600);
    await page.getByRole('button', { name: /^import$/i }).click().catch(() => { /* already there */ });
    await sleep(400);
    await page.locator('input[type="file"]').first().setInputFiles(path.resolve(capture));
    const deadline = Date.now() + 120_000;
    let seen = [0, 0];
    while (Date.now() < deadline) {
      seen = await counts();
      if (seen[1] >= arrived.length) break;
      await sleep(1000);
    }
    check(`${name}: the whole capture was imported`, seen[1], arrived.length);
    await page.keyboard.press('Escape');
    await sleep(2500);
    if (keysPath !== null) {
      checkTrue(`${name}: the import handed its decrypted answers to the Worker`, (await sentTypes()).includes('derived'));
    }

    await openFrames(page, cases, checkTrue);
  } finally {
    // In `finally`: with frames in the buffer, closing asks "Quit Inwire?" in a
    // native box no test can answer, and a failed drive hung on it.
    const page = app.windows()[0];
    if (page !== undefined) await page.evaluate(() => window.inwire?.setUnsavedCapture?.(false)).catch(() => {});
    await app.close().catch(() => {});
    rmSync(profile, { recursive: true, force: true });
  }
}

const inwire = FIXTURES.find((f) => f.name === 'inwire')!;
if (!existsSync(inwire.path)) skip(`${inwire.path} is not present - see test/fixtures/README.md`);
await drive('inwire', inwire.path, null, contextCases);

const keyed = FIXTURES.find((f) => f.name === 'keyLog')!;
const keyedKeys = keyed.path.replace(/\.pcapng$/, '.keys');
if (existsSync(keyed.path) && existsSync(keyedKeys)) {
  await drive('keyLog, with its key log', keyed.path, keyedKeys, decryptedCases);
} else {
  console.log(`\nSKIP  keyLog: ${keyed.path} or its key log is not present (optional)`);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All revisit-drive checks passed.');
process.exit(0);
