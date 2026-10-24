/**
 * Assertion tests for the renderer's side of the stream digest (ADR 0055).
 *
 *   npx tsx scripts/session/digest-rows.ts
 *
 * Three things, in the order the data flows:
 *
 * - **`digestConversation`** turns a `StreamSummary` into the conversation
 *   table's row, with the client as A. The store chose the client once, on
 *   the evidence `clientSide.ts` names, and the row must carry that choice
 *   rather than re-deriving it from whichever end spoke first.
 * - **`CaptureClient.streamDigest` / `streamOrdinals`** send the protocol's
 *   two requests and settle on their answers - driven here over a real
 *   `MessageChannel`, with a fake `window` standing in for the preload bridge,
 *   because nothing else in the suite reaches the client's port path.
 * - **A request the store never answers still settles.** The store going
 *   away (`onCaptureStoreExit`) must answer every pending digest request with
 *   its fallback, or the hook's poll hangs for the life of the window.
 */
import { readFileSync } from 'node:fs';
import { conversationRows, digestConversation, outcomeText, tcpScopeNote } from '../../src/services/conversation/digestRows';
import type { StreamSummary } from '../../src/services/conversation/streamDigest';
import type { ToCapture, FromCapture } from '../../src/services/capture/captureProtocol';

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

/** A stream the store would summarise: a short TLS exchange, closed cleanly. */
function summary(overrides: Partial<StreamSummary> = {}): StreamSummary {
  return {
    streamId: 3,
    client: { address: '10.0.0.5', port: 51000 },
    server: { address: '93.184.216.34', port: 443 },
    clientBasis: 'well-known-port',
    toServer: { packets: 7, bytes: 1_200, first: 0.5, last: 2.0 },
    toClient: { packets: 9, bytes: 8_000, first: 0.6, last: 2.5 },
    firstId: 12, lastId: 40,
    start: 0.5, end: 2.5,
    protocol: 'TLSv1.3',
    state: { client: 'TIME_WAIT', server: 'CLOSED' },
    steps: [], stepsDropped: 0,
    retransmissions: 1, lostSegments: 0, zeroWindows: 0,
    joinedMidStream: false,
    outcome: 'closed cleanly',
    version: 17,
    ...overrides,
  };
}

console.log('\n--- a summary as the conversation table\'s row ---\n');

{
  const s = summary();
  const row = digestConversation(s);
  check('the client is A', [row.addressA, row.portA], ['10.0.0.5', 51000]);
  check('the server is B', [row.addressB, row.portB], ['93.184.216.34', 443]);
  check('packetsAtoB is toServer.packets', row.packetsAtoB, 7);
  check('bytesAtoB is toServer.bytes', row.bytesAtoB, 1_200);
  check('packetsBtoA is toClient.packets', row.packetsBtoA, 9);
  check('bytesBtoA is toClient.bytes', row.bytesBtoA, 8_000);
  check('firstAtoB is toServer.first', row.firstAtoB, 0.5);
  check('lastAtoB is toServer.last', row.lastAtoB, 2.0);
  check('firstBtoA is toClient.first', row.firstBtoA, 0.6);
  check('lastBtoA is toClient.last', row.lastBtoA, 2.5);
  check('packets and bytes are both directions together', [row.packets, row.bytes], [16, 9_200]);
  check('key is tcp:<streamId>', row.key, 'tcp:3');
  check('startRel is start', row.startRel, 0.5);
  check('duration is end - start', row.duration, 2.0);
  check('firstFrame is firstId', row.firstFrame, 12);
  check('streamId and protocol come across', [row.streamId, row.protocol], [3, 'TLSv1.3']);
  check('outcome and joinedMidStream come across', [row.outcome, row.joinedMidStream], ['closed cleanly', false]);
  check('the summary itself rides along', row.summary === s, true);
}

{
  // A direction that never spoke keeps its nulls: the table draws them as
  // "never", and a 0 would read as the capture's first instant.
  const row = digestConversation(summary({
    toClient: { packets: 0, bytes: 0, first: null, last: null },
    outcome: 'no reply',
  }));
  check('a silent direction keeps its nulls', [row.firstBtoA, row.lastBtoA], [null, null]);
  check('...and counts nothing', [row.packetsBtoA, row.bytesBtoA], [0, 0]);
}

console.log('\n--- the outcome, in the ADR\'s words ---\n');

check('a joined open stream', outcomeText({ outcome: 'open', joinedMidStream: true }), 'open · joined mid-stream');
check('a clean close', outcomeText({ outcome: 'closed cleanly', joinedMidStream: false }), 'closed cleanly');
check('a joined stream that was reset', outcomeText({ outcome: 'reset by server', joinedMidStream: true }),
  'reset by server · joined mid-stream');
check('a joined stream whose start the ring removed does not claim it was never seen',
  outcomeText({ outcome: 'open', joinedMidStream: true, startExpired: true }), 'open · start removed by the ring');
check('...and the flag alone changes nothing on a stream that was seen', outcomeText({ outcome: 'open', joinedMidStream: false }), 'open');
check('the row itself is enough', outcomeText(digestConversation(summary())), 'closed cleanly');

console.log('\n--- the conversation table, TCP from the digest ---\n');

{
  const digest = new Map([[3, summary()], [4, summary({ streamId: 4 })]]);
  check('TCP reads the digest, one row per stream', conversationRows('tcp', digest)?.map((r) => r.streamId), [3, 4]);
  check('...and an empty digest leaves TCP to the buffer', conversationRows('tcp', new Map()), null);
  check('UDP has no digest and reads the buffer', conversationRows('udp', digest), null);
  check('so do the address levels', [conversationRows('ipv4', digest), conversationRows('eth', digest)], [null, null]);

  // The ADR: the pane says which scope it is showing.
  check('a digest answers for the whole capture', tcpScopeNote(digest, null), 'Whole capture');
  check('a rebuild says how far it has got', tcpScopeNote(digest, { done: 3, total: 12 }),
    'Rebuilding the stream digest: 3 of 12 chunks');
  check('...even before its first summary', tcpScopeNote(new Map(), { done: 0, total: 12 }),
    'Rebuilding the stream digest: 0 of 12 chunks');
  check('a rebuild that dropped rows says the answer is not the whole capture', tcpScopeNote(digest, null, true),
    'Not the whole capture: the stream digest missed some frames while rebuilding. Reopen the capture to rebuild it');
  check('...but a rebuild still running reports its progress first', tcpScopeNote(digest, { done: 1, total: 2 }, true),
    'Rebuilding the stream digest: 1 of 2 chunks');
  check('...and partial with nothing to show makes no claim', tcpScopeNote(new Map(), null, true), null);
  check('no digest, no claim: the buffer\'s own note stands', tcpScopeNote(new Map(), null), null);
}

// Following a conversation lands on the stream. The pane's
// `onReturnToPackets` is `setView('packets')`, and called after
// `onFollowStream` it wins the batch: the follow items went to Packets.
{
  const pane = readFileSync('src/components/statistics/StatisticsPane.tsx', 'utf8');
  // Each call, up to the end of the handler it sits in.
  const follows: string[] = [];
  for (let at = pane.indexOf('onFollowStream?.('); at >= 0; at = pane.indexOf('onFollowStream?.(', at + 1)) {
    follows.push(pane.slice(at, pane.indexOf('}', pane.indexOf(';', at))));
  }
  check('the pane follows streams from the row and the menu', follows.length >= 3, true);
  check('...and no follow then returns to Packets', follows.filter((f) => f.includes('onReturnToPackets')).length, 0);

  // The level buttons are how the TCP level is reached. At a 1024 window with
  // the side bar open the tab row is wider than the pane, and the pane clips:
  // TCP and UDP sat past its edge where nothing could scroll to them. The row
  // wraps instead, and a tab's label never breaks inside itself.
  const tabRow = pane.slice(pane.indexOf('<div', pane.indexOf("setTab('hierarchy')") - 200), pane.indexOf("setTab('hierarchy')"));
  check('the tab row wraps rather than clipping the level buttons', /\bflex-wrap\b/.test(tabRow), true);
  const tabClass = pane.slice(pane.indexOf('const tabClass'), pane.indexOf('const kindClass'));
  check('...and a tab label stays on one line', /\bwhitespace-nowrap\b/.test(tabClass), true);
}

console.log('\n--- the client, with no store at all ---\n');

// Imported after the row checks on purpose: nothing above should need the
// client, and the module's singleton is what the rest of this file drives.
const { captureStore } = await import('../../src/services/capture/captureClient');

check('streamDigest falls back to nothing, at the version it was asked from',
  await captureStore.streamDigest(42),
  { captureId: null, version: 42, summaries: [], rebuilding: null, partial: false });
check('streamOrdinals falls back to nothing, with no next page',
  await captureStore.streamOrdinals(3, 12, 40, 0),
  { ordinals: [], nextChunk: null });

console.log('\n--- the client, over a real port ---\n');

/**
 * The preload bridge, as far as `captureClient.ts` touches it: `isDesktop`,
 * the port handed over by a window message, and the store-exit callback.
 */
const { port1, port2 } = new MessageChannel();
let onMessage: ((event: unknown) => void) | null = null;
let onExit: ((reason: string) => void) | null = null;
const fakeWindow = {
  addEventListener: (_type: string, listener: (event: unknown) => void) => { onMessage = listener; },
  removeEventListener: () => { onMessage = null; },
  inwire: {
    isDesktop: true,
    requestCaptureStorePort: () => {
      onMessage?.({ source: fakeWindow, data: { channel: 'inwire:capture-port' }, ports: [port1] });
    },
    onCaptureStoreExit: (callback: (reason: string) => void) => { onExit = callback; },
  },
};
(globalThis as { window?: unknown }).window = fakeWindow;

/** What the store side saw, and how it answers. */
const received: ToCapture[] = [];
let answer: ((message: ToCapture) => FromCapture | null) | null = null;
port2.onmessage = (event: MessageEvent<ToCapture>) => {
  received.push(event.data);
  const reply = answer?.(event.data);
  if (reply) port2.postMessage(reply);
};

const changed = summary({ version: 5 });
answer = (message) => {
  if (message.type === 'streamDigest') {
    return {
      type: 'streamDigest', requestId: message.requestId, captureId: 'cap-20261009-120000-abcd',
      version: 5, summaries: [changed], rebuilding: { done: 3, total: 9 }, partial: true,
    };
  }
  if (message.type === 'streamOrdinals') {
    return { type: 'streamOrdinals', requestId: message.requestId, ordinals: [100, 101, 104], nextChunk: 2 };
  }
  return null;
};

{
  const digest = await captureStore.streamDigest(0);
  const sent = received.find((m) => m.type === 'streamDigest');
  check('streamDigest sends the protocol\'s request',
    sent && { type: sent.type, since: sent.since }, { type: 'streamDigest', since: 0 });
  check('...and settles on the store\'s answer',
    { captureId: digest.captureId, version: digest.version, rebuilding: digest.rebuilding, partial: digest.partial },
    { captureId: 'cap-20261009-120000-abcd', version: 5, rebuilding: { done: 3, total: 9 }, partial: true });
  check('...with the summaries it sent', digest.summaries.map((s) => [s.streamId, s.version]), [[3, 5]]);
}

{
  const page = await captureStore.streamOrdinals(3, 12, 40, 1);
  const sent = received.find((m) => m.type === 'streamOrdinals');
  check('streamOrdinals sends the protocol\'s request',
    sent && { ...sent, requestId: undefined },
    { type: 'streamOrdinals', requestId: undefined, streamId: 3, fromId: 12, toId: 40, startChunk: 1 });
  check('...and settles on the page it was given', page, { ordinals: [100, 101, 104], nextChunk: 2 });
}

{
  // A `since` the store has nothing past: the answer is empty and the version
  // is whatever the store says, which the hook takes as its next `since`.
  answer = (message) => message.type === 'streamDigest'
    ? { type: 'streamDigest', requestId: message.requestId, captureId: 'cap-20261009-120000-abcd', version: 5, summaries: [], rebuilding: null, partial: false }
    : null;
  check('an empty answer settles too', await captureStore.streamDigest(5),
    { captureId: 'cap-20261009-120000-abcd', version: 5, summaries: [], rebuilding: null, partial: false });
}

console.log('\n--- the store goes away with requests in flight ---\n');

{
  answer = () => null;
  const digest = captureStore.streamDigest(7);
  const page = captureStore.streamOrdinals(3, 12, 40, 0);
  // Both requests are on the wire before the store dies: the client awaits
  // the port before registering, so give it a turn.
  await new Promise((resolve) => setTimeout(resolve, 20));
  check('both requests reached the store', received.slice(-2).map((m) => m.type), ['streamDigest', 'streamOrdinals']);
  check('the exit callback was registered', onExit !== null, true);
  onExit!('the capture store stopped');
  check('a pending streamDigest settles with its fallback', await digest,
    { captureId: null, version: 0, summaries: [], rebuilding: null, partial: false });
  check('a pending streamOrdinals settles with its fallback', await page, { ordinals: [], nextChunk: null });
  check('the store is reported gone', captureStore.snapshot.error, 'the capture store stopped');
  check('and nothing is asked of it again',
    [await captureStore.streamDigest(1), received.filter((m) => m.type === 'streamDigest').length],
    [{ captureId: null, version: 1, summaries: [], rebuilding: null, partial: false }, 3]);
}

port1.close();
port2.close();

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All digest-rows checks passed.');
process.exit(0);
