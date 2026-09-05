/**
 * Assertion tests for JA4 → process learning.
 *
 *   npx tsx scripts/flow/fingerprints.ts
 *
 * This store makes a claim about traffic it could NOT attribute, on the
 * strength of traffic it could. That is the most dangerous shape a feature can
 * have: every failure produces a confident, plausible, wrong name on somebody
 * else's packets. So the cases below are all about restraint -
 *
 *   - a fingerprint two programs share must never name either
 *   - a frame the OS already named must teach, not be labelled by, the store
 *   - a fingerprint never seen must produce nothing
 *   - a label must never itself become evidence
 */
import {
  ClientFingerprintStore,
  learnOrLabelFingerprint,
} from '../../src/services/dissect/clientFingerprints';

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

const CHROME_JA4 = 't13d1516h2_8daaf6152771_02713d6af862';
const CURL_JA4 = 't13d1912h1_e8f1e7e78f70_5ac7197df9d2';

// --- 1. Learning from what the OS named ---------------------------------------
{
  const store = new ClientFingerprintStore();
  check('a fingerprint nobody has sent matches nothing', store.match(CHROME_JA4), null);

  store.learn(CHROME_JA4, 'chrome.exe');
  check('one sighting is enough to match', store.match(CHROME_JA4)?.name, 'chrome.exe');
  check('...and it counts the frames behind it', store.match(CHROME_JA4)?.frames, 1);

  store.learn(CHROME_JA4, 'chrome.exe');
  check('a second sighting of the same program strengthens it',
    store.match(CHROME_JA4)?.frames, 2);
  check('...and does not make it ambiguous', store.isAmbiguous(CHROME_JA4), false);
}

// --- 2. The shared-library case, which is the whole risk ----------------------
//
// Every Electron app carries Chrome's TLS stack; anything on schannel carries
// Windows'. A fingerprint seen from two programs cannot name either, and must
// not go back to naming one if the second program is never seen again.
{
  const store = new ClientFingerprintStore();
  store.learn(CHROME_JA4, 'chrome.exe');
  store.learn(CHROME_JA4, 'slack.exe');

  check('a fingerprint two programs share names neither', store.match(CHROME_JA4), null);
  checkTrue('...and says so', store.isAmbiguous(CHROME_JA4));

  store.learn(CHROME_JA4, 'chrome.exe');
  store.learn(CHROME_JA4, 'chrome.exe');
  check('...and stays ambiguous however lopsided the counts get',
    store.match(CHROME_JA4), null);
}

// --- 3. Teach or label, never both ---------------------------------------------
{
  const store = new ClientFingerprintStore();

  // A frame the OS attributed. It teaches, and takes no label of its own -
  // labelling it would be telling us what we already know, and would let the
  // store treat its own output as evidence.
  const attributed: Record<string, string | number> = {
    'tls.handshake.ja4': CHROME_JA4,
    'inwire.process.name': 'chrome.exe',
  };
  learnOrLabelFingerprint(attributed, store);
  check('an attributed hello teaches the store', store.match(CHROME_JA4)?.name, 'chrome.exe');
  check('...and is not labelled with what it already says',
    attributed['inwire.process.ja4_match'], undefined);

  // A frame the OS could not attribute - another machine on the segment, or a
  // socket gone before the table was read. This is what the learning is for.
  const unattributed: Record<string, string | number> = { 'tls.handshake.ja4': CHROME_JA4 };
  learnOrLabelFingerprint(unattributed, store);
  check('an unattributed hello is labelled from what was learned',
    unattributed['inwire.process.ja4_match'], 'chrome.exe');

  // And the label did not become evidence: the store still knows exactly one
  // program for this fingerprint, from exactly one frame.
  check('a label does not feed back into the store', store.match(CHROME_JA4)?.frames, 1);
}

// --- 4. Nothing to say, said as nothing ----------------------------------------
{
  const store = new ClientFingerprintStore();
  store.learn(CHROME_JA4, 'chrome.exe');

  const unknown: Record<string, string | number> = { 'tls.handshake.ja4': CURL_JA4 };
  learnOrLabelFingerprint(unknown, store);
  check('an unseen fingerprint gets no label', unknown['inwire.process.ja4_match'], undefined);

  const ambiguous = new ClientFingerprintStore();
  ambiguous.learn(CURL_JA4, 'curl.exe');
  ambiguous.learn(CURL_JA4, 'git.exe');
  const shared: Record<string, string | number> = { 'tls.handshake.ja4': CURL_JA4 };
  learnOrLabelFingerprint(shared, ambiguous);
  check('an ambiguous fingerprint gets no label', shared['inwire.process.ja4_match'], undefined);

  const notTls: Record<string, string | number> = { 'inwire.process.name': 'chrome.exe' };
  learnOrLabelFingerprint(notTls, store);
  check('a frame with no fingerprint is left alone',
    Object.keys(notTls), ['inwire.process.name']);
  check('...and taught the store nothing', store.size, 1);

  learnOrLabelFingerprint(undefined, store);
  check('a frame with no fields at all is not a crash', store.size, 1);
}

// --- 5. A cleared capture clears its evidence ----------------------------------
{
  const store = new ClientFingerprintStore();
  store.learn(CHROME_JA4, 'chrome.exe');
  const before = store.generation;
  store.clear();
  check('clearing forgets what was learned', store.match(CHROME_JA4), null);
  check('...and empties it', store.size, 0);
  checkTrue('...and moves the generation', store.generation > before);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All client fingerprint checks passed.');
process.exit(0);
