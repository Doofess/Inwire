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
import { QUIET_SECONDS, conversationRows, digestConversation, digestScopeNote, dnsOutcomeText, followNoun, outcomeText } from '../../src/services/conversation/digestRows';
import type { StreamSummary } from '../../src/services/conversation/streamDigest';
import type { DnsTally, QuicSummary, UdpSummary } from '../../src/services/conversation/flowSummary';
import type { TlsPhaseStep, TlsSummary } from '../../src/services/conversation/tlsSummary';
import type { DhcpSummary } from '../../src/services/conversation/dhcpSummary';
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

/** A UDP flow the store would summarise: a query and its answer. */
function udpSummary(overrides: Partial<UdpSummary> = {}): UdpSummary {
  return {
    kind: 'udp', key: 5,
    client: { address: '10.0.0.5', port: 50000 }, server: { address: '93.184.216.34', port: 5353 },
    clientBasis: 'well-known-port',
    toServer: { packets: 1, bytes: 80, first: 10, last: 10 },
    toClient: { packets: 1, bytes: 120, first: 10.1, last: 10.1 },
    firstId: 30, lastId: 31, start: 10, end: 10.1, protocol: 'DNS', version: 3,
    outcome: 'request/response',
    ...overrides,
  };
}

/** A QUIC connection, established. */
function quicSummary(overrides: Partial<QuicSummary> = {}): QuicSummary {
  return {
    kind: 'quic', key: 2,
    client: { address: '10.0.0.5', port: 50001 }, server: { address: '93.184.216.34', port: 443 },
    clientBasis: 'well-known-port',
    toServer: { packets: 10, bytes: 3_000, first: 20, last: 25 },
    toClient: { packets: 12, bytes: 9_000, first: 20.1, last: 25 },
    firstId: 50, lastId: 90, start: 20, end: 25, protocol: 'QUIC', version: 4,
    outcome: 'established', quicVersion: 1, phases: [], joinedMidStream: false, migrated: false,
    ...overrides,
  } as QuicSummary;
}

/** A TLS summary with the given phases (words only), all from the client. */
function tlsSummary(key: number, phases: TlsPhaseStep[], fatalAlert: TlsSummary['fatalAlert'] = null): TlsSummary {
  return { kind: 'tls', key, phases, fatalAlert, version: 1 };
}
const step = (phase: TlsPhaseStep['phase'], side: TlsPhaseStep['side'] = 'client', alertName?: string): TlsPhaseStep =>
  ({ phase, side, frameId: 1, time: 0.1, ...(alertName === undefined ? {} : { alertName }) });

/** A DHCP exchange, acked, with a hostname. The key is past 2^31 on purpose: it is unsigned. */
function dhcpSummary(overrides: Partial<DhcpSummary> = {}): DhcpSummary {
  return {
    kind: 'dhcp', key: 0xdeadbeef,
    client: { address: '02:00:00:00:00:01', port: 68 }, server: { address: '192.0.2.1', port: 67 },
    hostname: 'host-a', offered: '192.0.2.50',
    toServer: { packets: 2, bytes: 684, first: 1, last: 1.2 },
    toClient: { packets: 2, bytes: 684, first: 1.1, last: 1.3 },
    firstId: 60, lastId: 63, start: 1, end: 1.3,
    phases: [], outcome: 'acked', version: 5,
    ...overrides,
  };
}

const NO_FLOWS = {
  udp: new Map<number, UdpSummary>(), quic: new Map<number, QuicSummary>(),
  tls: new Map<number, TlsSummary>(), dhcp: new Map<number, DhcpSummary>(), captureEnd: 0,
};
const flows = (over: { summaries?: ReadonlyMap<number, StreamSummary>; udp?: ReadonlyMap<number, UdpSummary>; quic?: ReadonlyMap<number, QuicSummary>; tls?: ReadonlyMap<number, TlsSummary>; dhcp?: ReadonlyMap<number, DhcpSummary>; captureEnd?: number }) =>
  ({ summaries: new Map<number, StreamSummary>(), ...NO_FLOWS, ...over });

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
  const tcp = flows({ summaries: new Map([[3, summary()], [4, summary({ streamId: 4 })]]) });
  check('TCP reads the digest, one row per stream', conversationRows('tcp', tcp)?.map((r) => r.streamId), [3, 4]);
  check('...and an empty digest leaves TCP to the buffer', conversationRows('tcp', flows({})), null);
  check('UDP with nothing in the digest reads the buffer', conversationRows('udp', tcp), null);
  check('so do the address levels', [conversationRows('ipv4', tcp), conversationRows('eth', tcp)], [null, null]);

  // The ADR: the pane says which scope it is showing.
  check('a digest answers for the whole capture', digestScopeNote('tcp', tcp, null), 'Whole capture');
  check('a rebuild says how far it has got', digestScopeNote('tcp', tcp, { done: 3, total: 12 }),
    'Rebuilding the stream digest: 3 of 12 chunks');
  check('...even before its first summary', digestScopeNote('tcp', flows({}), { done: 0, total: 12 }),
    'Rebuilding the stream digest: 0 of 12 chunks');
  check('a rebuild that dropped rows says the answer is not the whole capture', digestScopeNote('tcp', tcp, null, true),
    'Not the whole capture: the stream digest missed some frames while rebuilding. Reopen the capture to rebuild it');
  check('...but a rebuild still running reports its progress first', digestScopeNote('tcp', tcp, { done: 1, total: 2 }, true),
    'Rebuilding the stream digest: 1 of 2 chunks');
  check('...and partial with nothing to show makes no claim', digestScopeNote('tcp', flows({}), null, true), null);
  check('no digest, no claim: the buffer\'s own note stands', digestScopeNote('tcp', flows({}), null), null);
}

console.log('\n--- UDP and QUIC from the digest ---\n');

{
  const udp = flows({ udp: new Map([[5, udpSummary()], [6, udpSummary({ key: 6 })]]), captureEnd: 11 });
  const rows = conversationRows('udp', udp);
  check('udp rows come from the digest: one per flow, keyed udp:<key>', rows?.map((r) => r.key), ['udp:5', 'udp:6']);
  const row = rows![0];
  check('...the client is A, the server B', [row.addressA, row.portA, row.addressB, row.portB],
    ['10.0.0.5', 50000, '93.184.216.34', 5353]);
  check('...streamId is the flow\'s key, protocol and first frame come from the summary',
    [row.streamId, row.protocol, row.firstFrame], [5, 'DNS', 30]);
  check('...never joined mid-stream', row.joinedMidStream, false);
  check('...counts and times from both directions', [row.packets, row.bytes, row.startRel, row.duration],
    [2, 200, 10, 10.1 - 10]);
  check('...outcome rides along', row.outcome, 'request/response');
  check('...and the TCP level is left alone by a UDP-only digest', conversationRows('tcp', udp), null);

  const quic = flows({ quic: new Map([[2, quicSummary()]]), captureEnd: 25 });
  const q = conversationRows('quic', quic);
  check('quic rows come from the digest, keyed quic:<key>', q?.map((r) => [r.key, r.streamId, r.protocol, r.outcome]),
    [['quic:2', 2, 'QUIC', 'established']]);
  check('...and an empty QUIC map leaves the level to the buffer, which has none', conversationRows('quic', flows({})), null);
}

console.log('\n--- DHCP exchanges from the digest ---\n');

{
  const dhcp = flows({ dhcp: new Map([[0xdeadbeef, dhcpSummary()]]), captureEnd: 2 });
  const rows = conversationRows('dhcp', dhcp);
  check('dhcp rows come from the digest, client as A',
    rows?.map((r) => [r.key, r.streamId, r.kind, r.protocol, r.addressA, r.portA, r.addressB, r.portB, r.outcome]),
    [['dhcp:3735928559', 3735928559, 'dhcp', 'DHCP', 'host-a (02:00:00:00:00:01)', 68, '192.0.2.1', 67, 'acked']]);
  const row = rows![0];
  check('...A to B is toServer, B to A is toClient',
    [row.packetsAtoB, row.bytesAtoB, row.packetsBtoA, row.bytesBtoA, row.packets, row.firstFrame],
    [2, 684, 2, 684, 4, 60]);
  const noName = conversationRows('dhcp', flows({ dhcp: new Map([[7, dhcpSummary({ key: 7, hostname: null })]]) }));
  check('...with no hostname, A is the client MAC', noName?.[0].addressA, '02:00:00:00:00:01');
  // A server that never spoke has no address at all; an empty cell reads as a bug.
  const unseen = conversationRows('dhcp', flows({ dhcp: new Map([[8, dhcpSummary({ key: 8, server: { address: '', port: 67 } })]]) }));
  check('...a server never seen reads not seen in B', [unseen?.[0].addressB, unseen?.[0].portB], ['not seen', 67]);
  check('...and a seen server keeps its address', rows![0].addressB, '192.0.2.1');
  const udpUnseen = digestConversation(udpSummary({ server: { address: '', port: 53 } }));
  check('...only a DHCP row says it: a UDP row\'s address is left alone', udpUnseen.addressB, '');
  check('...the outcome is the summary\'s alone, with no modifier even long after the end',
    outcomeText(row, 9_999), 'acked');
  check('...an empty DHCP map leaves the level to the buffer', conversationRows('dhcp', flows({})), null);
  check('...and a DHCP-only digest leaves the UDP level alone', conversationRows('udp', dhcp), null);
}

console.log('\n--- went quiet ---\n');

{
  const flow = (end: number) => digestConversation(udpSummary({ end }) as UdpSummary);
  check('went quiet at 30 s, not at 29.9 s',
    [outcomeText(flow(10), 40), outcomeText(flow(10), 39.9)],
    ['request/response · went quiet', 'request/response']);
  check('QUIET_SECONDS is 30', QUIET_SECONDS, 30);
  // The same flow, the live capture moving on: quiet while the capture's end
  // is 30 s past it, and not once the flow itself speaks at the capture's end.
  check('went quiet follows the capture\'s end',
    [outcomeText(flow(10), 10 + QUIET_SECONDS), outcomeText(flow(10 + QUIET_SECONDS), 10 + QUIET_SECONDS)],
    ['request/response · went quiet', 'request/response']);
  check('a TCP row never says it went quiet',
    outcomeText(digestConversation(summary({ end: 1 })), 1000), 'closed cleanly');
  const q = (over: Partial<QuicSummary>) => digestConversation(quicSummary(over));
  check('joined mid-stream and migrated read in that order, then went quiet',
    outcomeText(q({ joinedMidStream: true, migrated: true }), 100),
    'established · joined mid-stream · migrated · went quiet');
  check('migrated alone', outcomeText(q({ migrated: true }), 25), 'established · migrated');
  check('a UDP row is never joined mid-stream', outcomeText(digestConversation(udpSummary()), 10.1), 'request/response');
}

console.log('\n--- TLS on a TCP row ---\n');

{
  const rowText = (s: StreamSummary, tls?: TlsSummary) => {
    const rows = conversationRows('tcp', flows({
      summaries: new Map([[s.streamId, s]]), tls: new Map(tls === undefined ? [] : [[s.streamId, tls]]),
    }))!;
    return outcomeText(rows[0]);
  };
  const alert = tlsSummary(3, [step('ClientHello'), step('ServerHello', 'server'), step('alert', 'server', 'handshake_failure')],
    { side: 'server', name: 'handshake_failure' });
  check('a TCP row says TLS alert after its outcome',
    rowText(summary({ outcome: 'closed cleanly', joinedMidStream: true }), alert),
    'closed cleanly · joined mid-stream · TLS alert');
  check('a TCP row with a ClientHello and no answer says TLS unanswered once closed',
    rowText(summary({ outcome: 'reset by server' }), tlsSummary(3, [step('ClientHello')])),
    'reset by server · TLS unanswered');
  check('an open TCP row with no ServerHello yet says nothing about TLS',
    rowText(summary({ outcome: 'open' }), tlsSummary(3, [step('ClientHello')])), 'open');
  check('a UDP row never takes a TLS note',
    outcomeText(digestConversation(udpSummary()), 10.1), 'request/response');
}

console.log('\n--- DNS answers on a UDP row ---\n');

{
  const tally = (over: Partial<DnsTally>): DnsTally =>
    ({ answered: 0, errors: 0, evictedUnanswered: 0, evicted: [], settled: [], open: [], ...over });
  const dnsRow = (dns: DnsTally, end = 10) => digestConversation(udpSummary({ dns, end }));
  const q = (id: number, time: number) => ({ id, frameId: id, time });
  const open1 = dnsRow(tally({ open: [q(1, 100)] }));
  check('dns: waiting turns unanswered as the capture\'s end moves',
    [outcomeText(open1, 104.9), outcomeText(open1, 105)], ['1 waiting', '1 unanswered']);
  check('dns: the text orders answered, errors, unanswered, waiting and drops zeros',
    [
      outcomeText(dnsRow(tally({ answered: 11, errors: 2, evictedUnanswered: 1, open: [q(1, 100), q(2, 104)] })), 105),
      outcomeText(dnsRow(tally({ answered: 1, errors: 1 })), 105),
      outcomeText(dnsRow(tally({ answered: 3 })), 105),
    ],
    ['11 answered · 2 errors · 2 unanswered · 1 waiting', '1 answered · 1 error', '3 answered']);
  check('dns: a DNS flow never says went quiet',
    outcomeText(dnsRow(tally({ answered: 2 }), 10), 1000), '2 answered');
  check('dns: an empty tally falls back to the UDP text',
    outcomeText(dnsRow(tally({})), 10.1), 'request/response');
  // A finished capture (a file, or a stopped or paused capture) gains no
  // answers, so nothing in it is still waiting.
  check('dns: in a finished capture a query inside the wait window is unanswered',
    [outcomeText(open1, 104.9, true), outcomeText(open1, 104.9, false), outcomeText(open1, 104.9)],
    ['1 unanswered', '1 waiting', '1 waiting']);
  check('dns: finished counts evicted and stale queries too, and waiting never shows',
    outcomeText(dnsRow(tally({ answered: 1, evictedUnanswered: 1, open: [q(1, 100), q(2, 104)] })), 105, true),
    '1 answered · 3 unanswered');
  check('dns: dnsOutcomeText takes finished too',
    [dnsOutcomeText(tally({ open: [q(1, 100)] }), 100.1, true), dnsOutcomeText(tally({ open: [q(1, 100)] }), 100.1)],
    ['1 unanswered', '1 waiting']);
  // The Outcome column sorts by what its cell shows, not by the bare outcome.
  const pane = readFileSync('src/components/statistics/StatisticsPane.tsx', 'utf8');
  const outcomeColumn = pane.slice(pane.indexOf("key: 'outcome'"), pane.indexOf("key: 'packets'"));
  check('the Outcome column sorts by the text it shows',
    /sortValue: \(r: Conversation\) => outcomeText\(r as DigestConversation, held\.captureEnd, held\.finished\)/.test(outcomeColumn), true);
  check('...and the pane hands the same finished flag to the cell',
    /const text = outcomeText\(d, held\.captureEnd, held\.finished\);/.test(outcomeColumn)
      && /\{text\}/.test(outcomeColumn), true);
}

console.log('\n--- what Follow Stream calls each kind ---\n');

{
  check('a QUIC target is a connection, a DHCP one an exchange, the rest streams',
    (['tcp', 'udp', 'quic', 'dhcp'] as const).map(followNoun), ['Stream', 'Stream', 'Connection', 'Exchange']);
  // The menu and the pane's title are one word each from the one function.
  const list = readFileSync('src/components/packet-list/PacketList.tsx', 'utf8');
  const follower = readFileSync('src/components/stream-follower/StreamFollowerPane.tsx', 'utf8');
  check('the packet list\'s menu item takes its noun from followNoun, for every kind',
    [/\$\{followNoun\(streamTarget\.kind\)\}/.test(list), list.includes('Follow DHCP Exchange'), /UPPER|Stream\$\{/.test(list.slice(list.indexOf('onFollowStream(streamTarget)}'), list.indexOf('Show conversation')))],
    [true, false, false]);
  check('...and the pane\'s title from the same function', /const noun = followNoun\(target\.kind\)/.test(follower), true);
}

console.log('\n--- the scope note for each level ---\n');

{
  const all = flows({
    summaries: new Map([[3, summary()]]), udp: new Map([[5, udpSummary()]]), quic: new Map([[2, quicSummary()]]),
  });
  check('the scope note names the whole capture for udp and quic, nothing for ipv4',
    [digestScopeNote('udp', all, null), digestScopeNote('quic', all, null), digestScopeNote('ipv4', all, null),
      digestScopeNote('ipv6', all, null), digestScopeNote('eth', all, { done: 1, total: 2 })],
    ['Whole capture', 'Whole capture', null, null, null]);
  check('...an empty level and no rebuild makes no claim', [digestScopeNote('udp', flows({}), null), digestScopeNote('quic', flows({ udp: all.udp }), null)], [null, null]);
  const withDhcp = flows({ dhcp: new Map([[1, dhcpSummary({ key: 1 })]]) });
  check('the scope note names the whole capture for dhcp',
    [digestScopeNote('dhcp', withDhcp, null), digestScopeNote('dhcp', flows({}), null),
      digestScopeNote('dhcp', flows({}), { done: 1, total: 4 })],
    ['Whole capture', null, 'Rebuilding the stream digest: 1 of 4 chunks']);
  check('...a rebuild is reported on udp and quic too', digestScopeNote('quic', flows({}), { done: 1, total: 4 }),
    'Rebuilding the stream digest: 1 of 4 chunks');
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
  // A QUIC row opens the stream like a TCP or UDP one: the interim filter-on-click is gone.
  const streamOf = pane.slice(pane.indexOf('const streamOf'), pane.indexOf('const endpointRows'));
  check('a QUIC row is a stream to follow, like TCP and UDP rows', /'quic'/.test(streamOf) && /streamId: r\.streamId/.test(streamOf), true);
  check('...and it is built with the kind of its own level', /\{ kind,/.test(streamOf), true);

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
  { captureId: null, version: 42, summaries: [], udp: [], quic: [], tls: [], dhcp: [], captureEnd: 0, rebuilding: null, partial: false });
check('streamOrdinals falls back to nothing, with no next page',
  await captureStore.streamOrdinals(3, 12, 40, 0),
  { ordinals: [], nextChunk: null });
check('flowOrdinals falls back to nothing, with no next page',
  await captureStore.flowOrdinals('quic', 3, 12, 40, 0),
  { ordinals: [], nextChunk: null, searched: 1 });

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
      version: 5, summaries: [changed], udp: [], quic: [], tls: [], dhcp: [], captureEnd: 0, rebuilding: { done: 3, total: 9 }, partial: true,
    };
  }
  if (message.type === 'streamOrdinals') {
    return { type: 'streamOrdinals', requestId: message.requestId, ordinals: [100, 101, 104], nextChunk: 2 };
  }
  if (message.type === 'flowOrdinals') {
    return { type: 'flowOrdinals', requestId: message.requestId, ordinals: [7, 9], nextChunk: null, searched: 0.4 };
  }
  return null;
};

{
  const page = await captureStore.flowOrdinals('udp', 4, 12, 40, 1);
  const sent = received.find((m) => m.type === 'flowOrdinals');
  check('flowOrdinals sends the protocol\'s request',
    sent && { ...sent, requestId: undefined },
    { type: 'flowOrdinals', requestId: undefined, kind: 'udp', key: 4, fromId: 12, toId: 40, startChunk: 1 });
  check('...and settles on the page it was given, with how far it searched', page, { ordinals: [7, 9], nextChunk: null, searched: 0.4 });
}

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
    ? { type: 'streamDigest', requestId: message.requestId, captureId: 'cap-20261009-120000-abcd', version: 5, summaries: [], udp: [], quic: [], tls: [], dhcp: [], captureEnd: 0, rebuilding: null, partial: false }
    : null;
  check('an empty answer settles too', await captureStore.streamDigest(5),
    { captureId: 'cap-20261009-120000-abcd', version: 5, summaries: [], udp: [], quic: [], tls: [], dhcp: [], captureEnd: 0, rebuilding: null, partial: false });
}

console.log('\n--- the store goes away with requests in flight ---\n');

{
  answer = () => null;
  const digest = captureStore.streamDigest(7);
  const page = captureStore.streamOrdinals(3, 12, 40, 0);
  const flowPage = captureStore.flowOrdinals('quic', 3, 12, 40, 0);
  // All three requests are on the wire before the store dies: the client awaits
  // the port before registering, so give it a turn.
  await new Promise((resolve) => setTimeout(resolve, 20));
  check('all requests reached the store', received.slice(-3).map((m) => m.type), ['streamDigest', 'streamOrdinals', 'flowOrdinals']);
  check('the exit callback was registered', onExit !== null, true);
  onExit!('the capture store stopped');
  check('a pending flowOrdinals settles with its fallback', await flowPage, { ordinals: [], nextChunk: null, searched: 1 });
  check('a pending streamDigest settles with its fallback', await digest,
    { captureId: null, version: 0, summaries: [], udp: [], quic: [], tls: [], dhcp: [], captureEnd: 0, rebuilding: null, partial: false });
  check('a pending streamOrdinals settles with its fallback', await page, { ordinals: [], nextChunk: null });
  check('the store is reported gone', captureStore.snapshot.error, 'the capture store stopped');
  check('and nothing is asked of it again',
    [await captureStore.streamDigest(1), received.filter((m) => m.type === 'streamDigest').length],
    [{ captureId: null, version: 1, summaries: [], udp: [], quic: [], tls: [], dhcp: [], captureEnd: 0, rebuilding: null, partial: false }, 3]);
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
