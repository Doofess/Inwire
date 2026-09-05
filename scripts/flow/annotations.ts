/**
 * Assertion tests for the flow-annotation store.
 *
 *   npx tsx scripts/flow/annotations.ts
 *
 * The store answers "which process sent this frame", and every way it can be
 * wrong produces a plausible-looking process name on a packet row rather than a
 * crash. That is the kind of fault that ships and then gets believed, so the
 * cases here are the ones where a wrong answer would look right:
 *
 *   - a local port freed by one process and taken by another
 *   - a frame sent TO a server on a port some local process happens to listen on
 *   - a UDP socket bound to the wildcard, which is how Chrome binds QUIC
 *   - a capture of somebody else's traffic, where neither end is this machine
 *
 * Every one of those must answer with NOTHING rather than a guess.
 */
import { FlowAnnotationStore, isWildcardAddress } from '../../src/services/flowAnnotations';
import { sendingProcessName } from '../../src/services/dissect/processFields';

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
function checkTrue(name: string, condition: boolean) {
  check(name, condition, true);
}

const SECOND = 1_000_000;
const T0 = 1_700_000_000 * SECOND;

const chrome = { name: 'chrome.exe', exe: 'C:/chrome.exe' };
const curl = { name: 'curl.exe', exe: 'C:/curl.exe' };

function snapshot(add: [string, string, number, number][], procs: Record<string, { name: string; exe: string }>) {
  return { full: true, procs, add, gone: [] as [string, string, number][] };
}
function delta(
  add: [string, string, number, number][],
  gone: [string, string, number][],
  procs: Record<string, { name: string; exe: string }> = {},
) {
  return { full: false, procs, add, gone };
}

// --- 1. The basic claim ------------------------------------------------------
{
  const store = new FlowAnnotationStore();
  checkTrue('an empty store knows nothing', store.isEmpty);

  store.apply(snapshot([['tcp', '10.0.0.4', 54321, 100]], { 100: chrome }), T0);
  checkTrue('...and is no longer empty once a table arrives', !store.isEmpty);
  check('a local endpoint resolves to its process',
    store.lookup('tcp', '10.0.0.4', 54321, T0)?.name, 'chrome.exe');
  check('a port nothing is bound to resolves to nothing',
    store.lookup('tcp', '10.0.0.4', 9999, T0), null);
  check('the right port on the wrong transport resolves to nothing',
    store.lookup('udp', '10.0.0.4', 54321, T0), null);
}

// --- 2. Which end of the frame is local --------------------------------------
//
// The failure this prevents: a frame sent TO a server on port 443 must not be
// attributed to whatever local process is listening on 443. Deciding by port
// alone gets that wrong on every HTTPS packet a web server's own machine sends.
{
  const store = new FlowAnnotationStore();
  store.apply(snapshot([
    ['tcp', '10.0.0.4', 54321, 100],
    ['tcp', '0.0.0.0', 443, 200],
  ], { 100: chrome, 200: curl }), T0);

  check('a frame leaving this machine is attributed to the sender',
    store.forEndpoints('tcp', '10.0.0.4', 54321, '1.1.1.1', 443, T0)?.name, 'chrome.exe');
  check('...and the reply to the same process',
    store.forEndpoints('tcp', '1.1.1.1', 443, '10.0.0.4', 54321, T0)?.name, 'chrome.exe');
  check('a remote port is never treated as a local one',
    store.forEndpoints('tcp', '10.0.0.4', 54321, '1.1.1.1', 443, T0)?.name, 'chrome.exe');
  check('a capture of two other hosts is attributed to nobody',
    store.forEndpoints('tcp', '192.168.9.9', 1234, '1.1.1.1', 443, T0), null);
}

// --- 3. Wildcard binds -------------------------------------------------------
//
// 34 of 59 UDP sockets on a real machine were bound to a wildcard, Chrome's
// QUIC sockets among them. Without this fallback the transport carrying most of
// a browser's traffic is the one that never gets a name.
{
  checkTrue('0.0.0.0 is a wildcard', isWildcardAddress('0.0.0.0'));
  checkTrue(':: is a wildcard', isWildcardAddress('::'));
  checkTrue('a real address is not', !isWildcardAddress('10.0.0.4'));

  const store = new FlowAnnotationStore();
  store.apply(snapshot([
    ['tcp', '10.0.0.4', 1, 100],
    ['udp', '0.0.0.0', 62664, 100],
  ], { 100: chrome }), T0);

  check('a wildcard-bound socket answers for a concrete local address',
    store.forEndpoints('udp', '10.0.0.4', 62664, '142.250.0.1', 443, T0)?.name, 'chrome.exe');
  check('...and an exact bind is still preferred where one exists',
    store.lookup('tcp', '10.0.0.4', 1, T0)?.name, 'chrome.exe');
}

// --- 4. A reused local port --------------------------------------------------
//
// The case the whole time model exists for. A port freed by chrome and taken by
// curl must not leave curl's frames labelled chrome.
{
  const store = new FlowAnnotationStore();
  store.apply(snapshot([['tcp', '10.0.0.4', 54321, 100]], { 100: chrome }), T0);
  store.apply(delta([], [['tcp', '10.0.0.4', 54321]]), T0 + 10 * SECOND);
  store.apply(delta([['tcp', '10.0.0.4', 54321, 200]], [], { 200: curl }), T0 + 20 * SECOND);

  check('a frame from before the handover keeps the first process',
    store.lookup('tcp', '10.0.0.4', 54321, T0 + 5 * SECOND)?.name, 'chrome.exe');
  check('a frame from after it gets the second',
    store.lookup('tcp', '10.0.0.4', 54321, T0 + 25 * SECOND)?.name, 'curl.exe');
  check('a frame from the gap between them belongs to neither',
    store.lookup('tcp', '10.0.0.4', 54321, T0 + 15 * SECOND), null);

  // A handover fast enough that the two lives overlap inside the polling
  // uncertainty. There is genuinely no way to tell which process sent the
  // frame, so the answer is nothing.
  const fast = new FlowAnnotationStore();
  fast.apply(snapshot([['tcp', '10.0.0.4', 5555, 100]], { 100: chrome }), T0);
  fast.apply(delta([], [['tcp', '10.0.0.4', 5555]]), T0 + SECOND);
  fast.apply(delta([['tcp', '10.0.0.4', 5555, 200]], [], { 200: curl }), T0 + 2 * SECOND);
  check('a port reused inside the uncertainty window is ambiguous, so unattributed',
    fast.lookup('tcp', '10.0.0.4', 5555, T0 + 1.5 * SECOND), null);
}

// --- 5. A socket replaced without a close being seen -------------------------
//
// The table is a poll, so a close and a re-open inside one tick arrive as a
// bare pid change. Left unhandled both lives stay open and every later frame is
// ambiguous - which would silently turn attribution off for that port for ever.
{
  const store = new FlowAnnotationStore();
  store.apply(snapshot([['udp', '0.0.0.0', 5353, 100]], { 100: chrome }), T0);
  store.apply(delta([['udp', '0.0.0.0', 5353, 200]], [], { 200: curl }), T0 + 10 * SECOND);

  check('a pid change closes the old life rather than opening a rival one',
    store.lookup('udp', '0.0.0.0', 5353, T0 + 20 * SECOND)?.name, 'curl.exe');
  check('...and the earlier frames still belong to the old owner',
    store.lookup('udp', '0.0.0.0', 5353, T0 - 5 * SECOND)?.name, 'chrome.exe');
}

// --- 6. What the boundaries mean ---------------------------------------------
{
  const store = new FlowAnnotationStore();
  // A socket already open when the app subscribed. How long it had been open
  // is not knowable, so frames from before the subscription still resolve -
  // which is what makes attribution work for a connection that predates it.
  store.apply(snapshot([['tcp', '10.0.0.4', 443, 100]], { 100: chrome }), T0);
  check('a socket from the opening snapshot answers for earlier frames too',
    store.lookup('tcp', '10.0.0.4', 443, T0 - 3600 * SECOND)?.name, 'chrome.exe');

  // A socket that appeared in a delta did not exist arbitrarily far back.
  const later = new FlowAnnotationStore();
  later.apply(snapshot([], {}), T0);
  later.apply(delta([['tcp', '10.0.0.4', 8080, 100]], [], { 100: chrome }), T0 + 60 * SECOND);
  check('a socket that appeared later does not answer for much earlier frames',
    later.lookup('tcp', '10.0.0.4', 8080, T0 + 10 * SECOND), null);
  check('...but does for one inside the polling uncertainty before it',
    later.lookup('tcp', '10.0.0.4', 8080, T0 + 59.5 * SECOND)?.name, 'chrome.exe');
}

// --- 7. A socket the OS would not name ---------------------------------------
//
// Distinct from a socket that was never seen, and it has to stay distinct: the
// endpoint IS known, so it must not fall through to a wildcard entry for a
// different process.
{
  const store = new FlowAnnotationStore();
  store.apply(snapshot([
    ['tcp', '10.0.0.4', 135, 0],
    ['tcp', '0.0.0.0', 135, 100],
  ], { 100: chrome }), T0);
  check('an unnamed socket resolves to nothing, not to the wildcard behind it',
    store.lookup('tcp', '10.0.0.4', 135, T0), null);
}

// --- 8. A snapshot replaces, a delta merges ----------------------------------
{
  const store = new FlowAnnotationStore();
  store.apply(snapshot([['tcp', '10.0.0.4', 1, 100]], { 100: chrome }), T0);
  store.apply(snapshot([['tcp', '10.0.0.4', 2, 200]], { 200: curl }), T0 + SECOND);
  check('a full snapshot discards what came before it',
    store.lookup('tcp', '10.0.0.4', 1, T0 + 2 * SECOND), null);
  check('...and holds what it carried', store.lookup('tcp', '10.0.0.4', 2, T0 + 2 * SECOND)?.name, 'curl.exe');

  const before = store.generation;
  store.apply(delta([['tcp', '10.0.0.4', 3, 200]], [], { 200: curl }), T0 + 3 * SECOND);
  checkTrue('every change moves the generation', store.generation > before);
  check('...and a delta keeps what was already known',
    store.lookup('tcp', '10.0.0.4', 2, T0 + 4 * SECOND)?.name, 'curl.exe');

  store.clear();
  checkTrue('clear empties the store', store.isEmpty);
  check('...and it answers nothing afterwards', store.lookup('tcp', '10.0.0.4', 2, T0), null);
}

// --- 9. What the Source column is allowed to say --------------------------------
//
// The column renders `<address>\<program>`, and the rule that keeps it honest
// is that only frames this machine SENT get one. Attribution belongs to the
// local socket, so the reply from a server carries it too - and rendering that
// would put the browser's name on the web server that answered.
{
  const store = new FlowAnnotationStore();
  store.apply(snapshot([['tcp', '10.0.0.4', 54321, 100]], { 100: chrome }), T0);

  const frame = (source: string, destination: string, fields?: Record<string, string | number>) => ({
    source, destination, fields,
  } as unknown as Parameters<typeof sendingProcessName>[0]);

  const outbound = frame('10.0.0.4', '1.1.1.1', { 'inwire.process.name': 'chrome.exe' });
  check('a frame this machine sent names the program that sent it',
    sendingProcessName(outbound, store), 'chrome.exe');

  // The same flow, the other way. Attributed, and must still say nothing.
  const inbound = frame('1.1.1.1', '10.0.0.4', { 'inwire.process.name': 'chrome.exe' });
  check('the reply to it does NOT, though it carries the same attribution',
    sendingProcessName(inbound, store), null);

  check('an unattributed frame says nothing',
    sendingProcessName(frame('10.0.0.4', '1.1.1.1'), store), null);

  // Traffic between two other hosts, seen on a mirror port. Neither end is
  // this machine, so neither end has a program to name.
  check('a frame between two other hosts says nothing',
    sendingProcessName(frame('192.168.9.9', '1.1.1.1', { 'inwire.process.name': 'chrome.exe' }), store),
    null);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All flow annotation checks passed.');
process.exit(0);
