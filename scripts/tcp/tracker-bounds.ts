/**
 * Assertion tests for the bounds on cross-frame tracker state.
 *
 *   npx tsx scripts/tcp/tracker-bounds.ts
 *
 * The trackers accumulate per *connection*, and until this work nothing bounded
 * them: the packet buffer's cap trims frames, trims the session store and
 * evicts raw bytes, and has never touched a tracker. Measured at 2,162 B a
 * connection and 275 B an unanswered echo, retained for the length of a capture
 * (`scripts/perf/tracker-cost.ts`, `docs/decisions/0014`).
 *
 * A cap is easy. What these hold is the part that is not: **what eviction must
 * never do.** Every check below is a way the bound could have been implemented
 * that would lose or corrupt something -
 *
 *   - dropping a connection but leaving its stream index behind, so the leak
 *     moves from one map to another;
 *   - reusing a stream index, so two unrelated conversations become one to
 *     Follow Stream and to every filter that names an index;
 *   - evicting by age rather than by use, so the long-lived connection someone
 *     is actually watching is the first one dropped;
 *   - sweeping a socket that is still open because it has been open a while.
 *
 * None of those would fail a memory measurement. They would all fail here.
 */
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { FlowAnnotationStore } from '../../src/services/flowAnnotations';

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
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

/** Reads a private collection's size without pretending `private` is a runtime thing. */
function sizeOf(target: object, field: string): number {
  const value = (target as Record<string, unknown>)[field];
  if (value instanceof Map || value instanceof Set) return value.size;
  return -1;
}

/** The cap in tcpStreamTracker.ts. Read from behaviour, not imported. */
function findTcpCap(): number {
  const tracker = new TcpStreamTracker();
  for (let i = 0; i < 20_000; i++) {
    tracker.getStreamId('10.0.0.1', 1024 + i, '93.184.0.1', 443);
  }
  return tracker.connectionCount;
}

const TCP_CAP = findTcpCap();

// --- The cap holds, and holds exactly ------------------------------------------
{
  checkTrue('the TCP tracker has a cap at all', TCP_CAP > 0 && TCP_CAP < 20_000);

  const tracker = new TcpStreamTracker();
  const wanted = TCP_CAP + 500;
  for (let i = 0; i < wanted; i++) {
    tracker.getStreamId('10.0.0.1', 1024 + i, '93.184.0.1', 443);
  }
  check('past the cap, the count stops at the cap', tracker.connectionCount, TCP_CAP);
  check('...and the overflow is counted, not hidden', tracker.evictedConnections, 500);

  // The second map has to shrink with the first. Dropping a connection while
  // keeping its stream index would move the leak rather than fix it - and
  // nothing would notice, because `byStreamId` is only read by frame.
  check('the stream index map shrinks with it',
    sizeOf(tracker, 'byStreamId'), TCP_CAP);
}

// --- Least-recently-used, not oldest-first ---------------------------------------
//
// The distinction is the whole reason a plain cap is safe here. A connection
// that closes stops receiving frames, so LRU drops finished conversations on
// its own. Oldest-first would drop the long-lived connection someone opened at
// the start of the capture and is still watching - which is the single worst
// choice available.
{
  const tracker = new TcpStreamTracker();
  const busyId = tracker.getStreamId('10.0.0.1', 1024, '93.184.0.1', 443);

  for (let i = 0; i < TCP_CAP + 100; i++) {
    tracker.getStreamId('10.0.0.1', 2000 + i, '93.184.0.2', 443);
    // The long-lived connection keeps carrying traffic, as a real one would.
    if (i % 10 === 0) tracker.getStreamId('10.0.0.1', 1024, '93.184.0.1', 443);
  }

  check('a connection still carrying traffic keeps its stream index',
    tracker.getStreamId('10.0.0.1', 1024, '93.184.0.1', 443), busyId);
  checkTrue('...while others were evicted around it', tracker.evictedConnections > 0);
}

// --- A stream index is never handed out twice -------------------------------------
//
// Follow Stream, the statistics tables and any filter naming an index all
// assume an index means one conversation. Reusing a freed index would silently
// merge two.
{
  const tracker = new TcpStreamTracker();
  const seen = new Set<number>();
  let reused: number | null = null;
  const total = TCP_CAP + 1000;
  for (let i = 0; i < total; i++) {
    const id = tracker.getStreamId('10.0.0.1', 1024 + (i % 60000), '93.184.' + (i >> 8) + '.1', 443);
    if (seen.has(id) && reused === null) reused = id;
    seen.add(id);
  }
  check('no stream index was handed out twice', reused, null);
  check('...so every connection got its own', seen.size, total);
}

// --- An evicted connection reads as one never seen, not as a wrong one ------------
//
// This is the cost of the cap, and it must be the SAME cost as a capture
// started mid-connection - which the tracker has always handled by basing
// relative sequence numbers on "first seen minus one".
{
  const tracker = new TcpStreamTracker();
  const first = tracker.getStreamId('10.0.0.9', 5555, '93.184.9.9', 443);
  tracker.getRelativeSeq('10.0.0.9', 5555, '93.184.9.9', 443, 1000, true);
  check('a captured SYN reports Seq=0',
    tracker.getRelativeSeq('10.0.0.9', 5555, '93.184.9.9', 443, 1000, true), 0);

  for (let i = 0; i < TCP_CAP + 10; i++) {
    tracker.getStreamId('10.0.0.1', 3000 + i, '93.184.7.7', 443);
  }

  const again = tracker.getStreamId('10.0.0.9', 5555, '93.184.9.9', 443);
  checkTrue('the evicted connection comes back as a new one', again !== first);
  check('...with the mid-stream base, so its next segment reads Seq=1',
    tracker.getRelativeSeq('10.0.0.9', 5555, '93.184.9.9', 443, 9000, false), 1);
}

// --- Nothing survives a reset ------------------------------------------------------
{
  const tracker = new TcpStreamTracker();
  for (let i = 0; i < 100; i++) tracker.getStreamId('10.0.0.1', 1024 + i, '93.184.0.1', 443);
  tracker.reset();
  check('reset empties the connections', tracker.connectionCount, 0);
  check('...and the stream index map', sizeOf(tracker, 'byStreamId'), 0);
  check('...and the eviction count', tracker.evictedConnections, 0);
  check('...and numbering restarts', tracker.getStreamId('10.0.0.1', 1, '10.0.0.2', 2), 0);
}

// --- Echo requests: bounded, and the newest survive ---------------------------------
//
// A ping sweep leaves one entry per probe, for ever, and it was the traffic
// that produced the most entries that had no bound at all.
{
  const tracker = new IcmpEchoTracker();
  for (let i = 0; i < 10_000; i++) {
    tracker.recordRequest('10.0.0.1', '10.1.' + (i >> 8) + '.' + (i & 0xff), 1, i, i + 1);
  }
  const cap = tracker.pendingCount;
  checkTrue('unanswered echoes are capped', cap > 0 && cap < 10_000);

  // The newest are the ones a reply is still plausibly coming for.
  const lastTarget = '10.1.' + (9999 >> 8) + '.' + (9999 & 0xff);
  check('the newest request still pairs with its reply',
    tracker.matchReply(lastTarget, '10.0.0.1', 1, 9999), 10_000);
  check('...and consuming it frees the entry', tracker.pendingCount, cap - 1);

  // A reply whose request was evicted loses its cross-reference and nothing
  // else: the frame is still dissected, filtered and exported.
  check('the oldest request is gone, and says so by being absent',
    tracker.matchReply('10.1.0.0', '10.0.0.1', 1, 0), undefined);
}

// --- QUIC connection ids per flow ----------------------------------------------------
//
// A peer may issue new connection ids for the life of a connection, and every
// one was kept. Capped oldest-first, because `matchConnectionId` scans the set
// per short-header packet - so an unbounded set was a growing per-packet cost
// as well.
{
  const tracker = new QuicFlowTracker();
  for (let i = 0; i < 500; i++) {
    tracker.noteLongHeader('10.0.0.1', 50000, '93.184.0.1', 443,
      [i.toString(16).padStart(16, '0')]);
  }
  const ids = (tracker as unknown as { flowConnectionIds: Map<string, Set<string>> })
    .flowConnectionIds;
  const only = [...ids.values()][0];
  checkTrue('a flow\'s connection ids are capped', only.size > 0 && only.size < 500);
  checkTrue('...keeping the most recently issued',
    only.has((499).toString(16).padStart(16, '0')));
  checkTrue('...and dropping the first', !only.has((0).toString(16).padStart(16, '0')));

  checkTrue('the flow is still recognised as QUIC',
    tracker.isKnownFlow('10.0.0.1', 50000, '93.184.0.1', 443));
}

// --- QUIC flows are capped, and a capped flow forgets ALL of its state -----------------
{
  const tracker = new QuicFlowTracker();
  for (let i = 0; i < 6000; i++) {
    tracker.noteLongHeader('10.0.0.1', 50000 + i, '93.184.1.1', 443, ['aabbccdd']);
  }
  const flows = sizeOf(tracker, 'flowConnectionIds');
  checkTrue('QUIC flows are capped', flows > 0 && flows < 6000);
  checkTrue('the earliest flow is forgotten',
    !tracker.isKnownFlow('10.0.0.1', 50000, '93.184.1.1', 443));
  checkTrue('the most recent flow is kept',
    tracker.isKnownFlow('10.0.0.1', 55999, '93.184.1.1', 443));

  // Forgetting a flow has to reach the maps keyed by flow-and-sender too, or
  // the eviction frees the small half and leaves the large one.
  check('a forgotten flow leaves no session behind',
    tracker.sniFor('10.0.0.1', 50000, '93.184.1.1', 443), undefined);
}

// --- Socket lives: closed ones are swept, open ones never are --------------------------
{
  const store = new FlowAnnotationStore();
  const T0 = 1_700_000_000_000_000;

  store.apply({
    full: false,
    procs: { '10': { name: 'chrome.exe', exe: 'C:\\chrome.exe' } },
    add: [['tcp', '10.0.0.5', 40000, 10], ['tcp', '10.0.0.5', 40001, 10]],
    gone: [],
  }, T0);

  check('a live socket is attributed',
    store.lookup('tcp', '10.0.0.5', 40000, T0)?.name, 'chrome.exe');

  // One closes; the other stays open.
  store.apply({ full: false, procs: {}, add: [], gone: [['tcp', '10.0.0.5', 40000]] }, T0 + 1_000_000);

  // Long enough after the close that no frame can still fall inside it.
  const LATER = T0 + 600_000_000;
  store.apply({ full: false, procs: {}, add: [], gone: [] }, LATER);

  check('the closed socket is swept',
    store.lookup('tcp', '10.0.0.5', 40000, LATER), null);
  check('the socket still open is NOT swept, however long it has been open',
    store.lookup('tcp', '10.0.0.5', 40001, LATER)?.name, 'chrome.exe');

  // A frame from before the sweep is unaffected: its process was written into
  // `Packet.fields` when it was dissected, and dissection runs forwards - which
  // is the whole reason a closed life can be dropped at all.
  checkTrue('the store did not empty itself', !store.isEmpty);
}

// --- A port reused many times keeps only recent lives ------------------------------------
{
  const store = new FlowAnnotationStore();
  const T0 = 1_700_000_000_000_000;
  // Three seconds apart, which is more than twice the one-second poll
  // uncertainty each edge is widened by. Closer together than that and two
  // lives genuinely do cover the same instant, which the store answers with
  // nothing on purpose - a reused port is ambiguous, not attributable.
  const REUSE_GAP_US = 3_000_000;
  for (let i = 0; i < 50; i++) {
    store.apply({
      full: false,
      procs: { [String(i)]: { name: 'proc' + i + '.exe', exe: '' } },
      add: [['tcp', '10.0.0.5', 40000, i]],
      gone: [],
    }, T0 + i * REUSE_GAP_US);
  }
  const lives = (store as unknown as { lives: Map<string, unknown[]> }).lives;
  const history = lives.get('tcp|10.0.0.5|40000') ?? [];
  checkTrue('one endpoint\'s history is capped', history.length > 0 && history.length < 50);

  // The last life pushed is the open one, and truncating from the front is
  // what keeps it: dropping the newest would leave the endpoint looking closed
  // while it is in use.
  //
  // Asked two seconds INTO that life rather than at the instant it began: the
  // previous life closed exactly then, and one poll interval of uncertainty
  // either side makes that moment cover both. Which is correct - a port handed
  // over is ambiguous at the handover - so the question has to be asked at a
  // time only one life can claim.
  check('the process currently holding the port is still known',
    store.lookup('tcp', '10.0.0.5', 40000, T0 + 49 * REUSE_GAP_US + 2_000_000)?.name,
    'proc49.exe');
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All tracker-bounds checks passed.');
process.exit(0);
