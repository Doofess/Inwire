/**
 * The seams an import in a Worker is built on, asserted before anything uses them:
 *
 * - `onSecrets`: a Decryption Secrets Block's key log goes to the injected hook,
 *   once, and the walk waits for what the hook returns before it reads on.
 * - the store messages a batch becomes: what `CaptureClient.append` and
 *   `appendRecords` post, written out by hand as the literal of what the client
 *   posted before `storeMessagesFor` existed, and compared under `v8.serialize`
 *   (the store's process boundary), so neither side is computed by the other.
 *
 * Run: npx tsx scripts/capture/import-seams.ts
 */
import { serialize } from 'node:v8';
import { PcapService } from '../../src/services/pcapParser';
import { DSB_SECRETS_TYPE_TLS_KEY_LOG } from '../../src/services/dissect/types';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function pass(name: string, ok: boolean, detail?: unknown): void {
  if (!ok) failures++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok && detail !== undefined) console.log(`        ${JSON.stringify(detail)}`.slice(0, 400));
}

// --- a pcapng with a DSB after three frames ------------------------------------

const u32 = (v: number) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
const u16 = (v: number) => [v & 0xff, (v >>> 8) & 0xff];
const pad = (n: number) => new Array((4 - (n % 4)) % 4).fill(0);
function block(type: number, body: number[]): Uint8Array {
  const out = new Uint8Array(12 + body.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, type, true);
  view.setUint32(4, out.length, true);
  out.set(body, 8);
  view.setUint32(out.length - 4, out.length, true);
  return out;
}
const shb = () => block(0x0a0d0d0a, [
  ...u32(0x1a2b3c4d), ...u16(1), ...u16(0), ...u32(0xffffffff), ...u32(0xffffffff),
]);
const idb = () => block(0x00000001, [...u16(1), ...u16(0), ...u32(0)]);
const epb = (i: number) => {
  const data = Array.from({ length: 20 + i }, (_, k) => (i * 7 + k) & 0xff);
  return block(0x00000006, [
    ...u32(0), ...u32(0), ...u32(1_000_000 + i), ...u32(data.length), ...u32(data.length),
    ...data, ...pad(data.length),
  ]);
};
const SECRETS = 'CLIENT_RANDOM 00 11\n';
const dsb = () => {
  const text = [...new TextEncoder().encode(SECRETS)];
  return block(0x0000000a, [
    ...u32(DSB_SECRETS_TYPE_TLS_KEY_LOG), ...u32(text.length), ...text, ...pad(text.length),
  ]);
};
const parts = [shb(), idb(), epb(0), epb(1), epb(2), dsb(), epb(3), epb(4)];
const file = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
{
  let at = 0;
  for (const p of parts) { file.set(p, at); at += p.length; }
}
const asBuffer = file.buffer.slice(file.byteOffset, file.byteOffset + file.byteLength) as ArrayBuffer;
const asFile = new File([file as unknown as BlobPart], 'secrets.pcapng');

const wait = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

// The walk, pulled by hand: frames the consumer has taken when the hook settles.
{
  const texts: string[] = [];
  let seen = 0;
  let seenWhenResolved = -1;
  const walk = await PcapService.frameWalk(asBuffer, undefined, async (text) => {
    texts.push(text);
    await wait(20);
    seenWhenResolved = seen;
  });
  for await (const _frame of walk.frames()) seen++;
  pass('onSecrets receives the DSB text once and the walk waits for it',
    texts.length === 1 && texts[0] === SECRETS && seenWhenResolved === 3 && seen === 5,
    { texts, seenWhenResolved, seen });
}

// Through streamCaptureFile, in windows small enough to split the file.
{
  const texts: string[] = [];
  const outcome = await PcapService.streamCaptureFile(asFile, () => {}, {
    windowBytes: 64, onSecrets: (text) => { texts.push(text); },
  });
  pass('streamCaptureFile hands the DSB over once, with windowBytes forcing several windows',
    texts.length === 1 && texts[0] === SECRETS && outcome.totalFrames === 5,
    { texts, totalFrames: outcome.totalFrames });
}

// --- what a batch becomes on the store's port ----------------------------------

const packet = (id: number): Packet => ({
  id, timestamp: 1000 + id, source: '10.0.0.1', destination: '10.0.0.2', protocol: 'UDP',
  length: 60 + id, info: `frame ${id}`, rawBytes: new Uint8Array([id, id + 1]), fields: { 'frame.number': id },
}) as unknown as Packet;
const batch = [packet(1), packet(2), packet(3)];
// An import's entries carry decrypted answers beside the record: never posted.
const records = batch.map((p) => ({
  id: p.id, record: new Uint8Array([9, p.id]), decrypted: { secret: 'never sent' },
}));

/** What `appendRecords` then `append` posted for `batch`, written out by hand. */
const characterized = [
  {
    type: 'appendRecords',
    frames: [
      { id: 1, record: new Uint8Array([9, 1]) },
      { id: 2, record: new Uint8Array([9, 2]) },
      { id: 3, record: new Uint8Array([9, 3]) },
    ],
  },
  {
    type: 'append',
    packets: [1, 2, 3].map((id) => ({
      id, timestamp: 1000 + id, source: '10.0.0.1', destination: '10.0.0.2', protocol: 'UDP',
      length: 60 + id, info: `frame ${id}`, rawBytes: new Uint8Array([id, id + 1]), fields: { 'frame.number': id },
    })),
  },
];
const sameBytes = (a: unknown, b: unknown) => Buffer.compare(serialize(a), serialize(b)) === 0;

{
  // A stub port that keeps what it is handed: a real channel re-clones the
  // message into other array shapes, which `v8.serialize` then tells apart.
  const posted: unknown[] = [];
  const port1 = { postMessage: (message: unknown) => { posted.push(message); }, start: () => {}, onmessage: null };
  let onMessage: ((event: unknown) => void) | null = null;
  const fakeWindow = {
    addEventListener: (_type: string, listener: (event: unknown) => void) => { onMessage = listener; },
    removeEventListener: () => { onMessage = null; },
    inwire: {
      isDesktop: true,
      requestCaptureStorePort: () => {
        onMessage?.({ source: fakeWindow, data: { channel: 'inwire:capture-port' }, ports: [port1] });
      },
      onCaptureStoreExit: () => {},
    },
  };
  (globalThis as { window?: unknown }).window = fakeWindow;
  const { captureStore } = await import('../../src/services/capture/captureClient');
  captureStore.appendRecords(records);
  captureStore.append(batch);
  for (let i = 0; i < 50 && posted.length < 2; i++) await wait(10);
  pass('CaptureClient posts the characterized store sequence',
    posted.length === 2 && sameBytes(posted, characterized), posted);
}

{
  const { storeMessagesFor } = await import('../../src/services/capture/storePacket');
  const messages = storeMessagesFor(batch, records);
  pass('storeMessagesFor equals the same literal', sameBytes(messages, characterized), messages);
  const tagged = storeMessagesFor(batch, records, 'cap-x');
  pass('storeMessagesFor tags both messages when given a capture id, and only then',
    tagged.length === 2 && tagged.every((m) => (m as { captureId?: string }).captureId === 'cap-x')
    && messages.every((m) => !('captureId' in m)));
  pass('storeMessagesFor leaves an empty half out',
    storeMessagesFor([], undefined).length === 0 && storeMessagesFor(batch, []).length === 1);
}

console.log(failures === 0 ? '\nAll import seam checks passed.' : `\n${failures} import seam check(s) failed.`);
process.exit(failures === 0 ? 0 : 1);
