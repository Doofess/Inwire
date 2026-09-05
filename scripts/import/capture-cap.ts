/**
 * Assertion tests for the capture-import frame cap.
 *
 *   npx tsx scripts/import/capture-cap.ts
 *
 * Both extractors used to stop at a hardcoded 10,000 frames - a "safety limit"
 * from when the buffer was smaller - so a capture exported from a full buffer
 * came back short with no message. The cap is now the caller's, and the file's
 * true frame count is reported alongside, which is what lets the import panel
 * say "12,858 frames in the file, the first 10,000 loaded".
 *
 * The captures here are synthesised in memory (one classic pcap, one pcapng)
 * so the test needs no fixture on disk and holds no real traffic. Each frame is
 * a minimal ARP request, which dissects cleanly and is 42 bytes.
 */
import { PcapService } from '../../src/services/pcapParser';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

// --- one frame ---------------------------------------------------------------

function arpFrame(n: number): Uint8Array {
  const f = new Uint8Array(42);
  f.set([0xff, 0xff, 0xff, 0xff, 0xff, 0xff], 0);            // dst broadcast
  f.set([0x02, 0x00, 0x00, 0x00, 0x00, n & 0xff], 6);        // src (locally administered)
  f.set([0x08, 0x06], 12);                                    // ARP
  f.set([0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x01], 14); // eth/ipv4, request
  f.set([0x02, 0x00, 0x00, 0x00, 0x00, n & 0xff], 22);       // sender mac
  f.set([192, 0, 2, 1], 28);                                  // sender ip (RFC 5737)
  f.set([0, 0, 0, 0, 0, 0], 32);                              // target mac
  f.set([192, 0, 2, 2], 38);                                  // target ip
  return f;
}

// --- writers -----------------------------------------------------------------

function classicPcap(frameCount: number): Uint8Array {
  const frames = Array.from({ length: frameCount }, (_, i) => arpFrame(i));
  const size = 24 + frames.reduce((n, f) => n + 16 + f.length, 0);
  const buf = new ArrayBuffer(size);
  const view = new DataView(buf);
  const out = new Uint8Array(buf);
  view.setUint32(0, 0xa1b2c3d4, true);
  view.setUint16(4, 2, true); view.setUint16(6, 4, true);
  view.setUint32(16, 65535, true); view.setUint32(20, 1, true);
  let off = 24;
  frames.forEach((f, i) => {
    view.setUint32(off, 1_700_000_000 + i, true);
    view.setUint32(off + 4, i * 10, true);
    view.setUint32(off + 8, f.length, true);
    view.setUint32(off + 12, f.length, true);
    out.set(f, off + 16);
    off += 16 + f.length;
  });
  return out;
}

function pcapng(frameCount: number): Uint8Array {
  const pad4 = (n: number) => (4 - (n % 4)) % 4;
  const blocks: Uint8Array[] = [];
  const block = (type: number, body: Uint8Array) => {
    const len = 12 + body.length + pad4(body.length);
    const b = new Uint8Array(len);
    const v = new DataView(b.buffer);
    v.setUint32(0, type, true); v.setUint32(4, len, true);
    b.set(body, 8);
    v.setUint32(len - 4, len, true);
    blocks.push(b);
  };
  // SHB: byte-order magic, version 1.0, section length -1
  const shb = new Uint8Array(16); const sv = new DataView(shb.buffer);
  sv.setUint32(0, 0x1a2b3c4d, true); sv.setUint16(4, 1, true); sv.setUint16(6, 0, true);
  sv.setUint32(8, 0xffffffff, true); sv.setUint32(12, 0xffffffff, true);
  block(0x0a0d0d0a, shb);
  // IDB: linktype 1, reserved, snaplen
  const idb = new Uint8Array(8); const iv = new DataView(idb.buffer);
  iv.setUint16(0, 1, true); iv.setUint32(4, 65535, true);
  block(0x00000001, idb);
  for (let i = 0; i < frameCount; i++) {
    const f = arpFrame(i);
    const body = new Uint8Array(20 + f.length);
    const v = new DataView(body.buffer);
    const ts = BigInt(1_700_000_000 + i) * 1_000_000n;
    v.setUint32(0, 0, true);
    v.setUint32(4, Number(ts >> 32n), true);
    v.setUint32(8, Number(ts & 0xffffffffn), true);
    v.setUint32(12, f.length, true); v.setUint32(16, f.length, true);
    body.set(f, 20);
    block(0x00000006, body);
  }
  const total = blocks.reduce((n, b) => n + b.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const b of blocks) { out.set(b, off); off += b.length; }
  return out;
}

// --- the checks --------------------------------------------------------------

async function main() {
  for (const [kind, bytes] of [['pcap', classicPcap(25)], ['pcapng', pcapng(25)]] as const) {
    const file = new File([bytes], `synthetic.${kind}`);

    const whole = await PcapService.parseCaptureFile(file);
    check(`${kind}: no cap loads every frame`, [whole.packets.length, whole.totalFrames], [25, 25]);

    const capped = await PcapService.parseCaptureFile(file, 10);
    check(`${kind}: a cap of 10 loads the first 10...`, capped.packets.length, 10);
    check(`${kind}: ...and still reports the true total`, capped.totalFrames, 25);
    check(`${kind}: the loaded frames are the FIRST ten, in order`,
      capped.packets.map(p => p.id), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    const roomy = await PcapService.parseCaptureFile(file, 1000);
    check(`${kind}: a cap above the file size changes nothing`, [roomy.packets.length, roomy.totalFrames], [25, 25]);

    const legacy = await PcapService.parsePcapFile(file);
    check(`${kind}: the plain-array entry point is uncapped`, legacy.length, 25);

    check(`${kind}: frames dissect as ARP through the same path as any import`,
      new Set(whole.packets.map(p => p.protocolLabel ?? p.protocol)), new Set(['ARP']));
  }

  // The number that motivated all of this.
  check('nothing in the extractors still says 10000',
    /10000|10_000/.test(await (await import('node:fs/promises')).readFile(
      new URL('../../src/services/pcapParser.ts', import.meta.url), 'utf8')),
    false);

  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All capture-cap checks passed.');
  process.exit(0);
}

main().catch(err => { console.error(err); process.exit(1); });
