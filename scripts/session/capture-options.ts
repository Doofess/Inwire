/**
 * The capture filter and snaplen, from the panel to the agent (ADR 0050).
 *
 *   npx tsx scripts/session/capture-options.ts
 *
 * Every rule here decides what a capture is asked to do, and each one fails
 * silently when wrong: a start that dropped its filter captures everything
 * while the panel says it is narrowed; an answer about `tcp port 44` that is
 * taken to be about `tcp port 443` lets a filter through that will not
 * compile; a reconnect that resumes with a plain start undoes the filter
 * halfway through a capture; an export that names no filter describes a
 * capture of everything. None of it involves a frame, so none of it needs a
 * capture file - the frames that a filter and a snaplen act on are held by
 * `agent-rs`'s own tests, `scripts/parity/snaplen.ts` and
 * `scripts/export/pcapng.ts`.
 */
import {
  DEFAULT_CAPTURE_OPTIONS, MAX_CAPTURE_FILTER_CHARS, MAX_SNAPLEN, SUGGESTED_SNAPLEN,
  effectiveFilter, filterBlocksStart, filterVerdict, normalizeCaptureOptions, recordOf,
  startCaptureCommand, type CaptureOptions,
} from '../../src/services/captureOptions';
import { planResync } from '../../src/services/captureResync';
import { metaEntries, type CaptureMeta } from '../../src/services/export/captureMeta';
import { WITHHELD_CAPTURE_FILTER, redactMeta } from '../../src/services/report/redact';
import { Anonymiser } from '../../src/services/anonymise';

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

const opts = (patch: Partial<CaptureOptions>): CaptureOptions => ({ ...DEFAULT_CAPTURE_OPTIONS, ...patch });

console.log('--- what Start sends ---\n');

check('nothing asked: the plain start it always was', startCaptureCommand(DEFAULT_CAPTURE_OPTIONS), { type: 'start_capture' });
check('a filter travels trimmed', startCaptureCommand(opts({ filter: '  tcp port 443 ' })),
  { type: 'start_capture', filter: 'tcp port 443' });
check('a blank filter is no filter, not an empty one', startCaptureCommand(opts({ filter: '   ' })), { type: 'start_capture' });
check('a snaplen travels only when it is switched on', [
  startCaptureCommand(opts({ snaplen: 96 })),
  startCaptureCommand(opts({ limitBytes: true, snaplen: 96 })),
], [{ type: 'start_capture' }, { type: 'start_capture', snaplen: 96 }]);
check('...and keeping every byte is no snaplen at all', startCaptureCommand(opts({ limitBytes: true, snaplen: MAX_SNAPLEN })),
  { type: 'start_capture' });

console.log('\n--- what the panel says about the filter ---\n');

const typed = opts({ filter: 'tcp port 443' });
check('blank: everything is captured', filterVerdict(DEFAULT_CAPTURE_OPTIONS, null), { kind: 'none' });
check('typed and not yet answered: checking', filterVerdict(typed, null), { kind: 'checking' });
check('an answer about other text is not an answer about this text',
  filterVerdict(typed, { type: 'capture_filter_check', filter: 'tcp port 44', error: null }), { kind: 'checking' });
check('the answer about exactly this text decides',
  filterVerdict(typed, { type: 'capture_filter_check', filter: 'tcp port 443', error: null }), { kind: 'ok' });
check('...in libpcap\'s words when it refuses',
  filterVerdict(opts({ filter: 'tcp prot 443' }),
    { type: 'capture_filter_check', filter: 'tcp prot 443', error: "can't parse filter expression: syntax error" }),
  { kind: 'error', message: "can't parse filter expression: syntax error" });
check('the text is compared as it is sent, trimmed',
  filterVerdict(opts({ filter: ' arp ' }), { type: 'capture_filter_check', filter: 'arp', error: null }), { kind: 'ok' });
check('a refused filter blocks Start, saying why',
  filterBlocksStart({ kind: 'error', message: 'syntax error' }), 'The capture filter does not compile: syntax error');
check('a filter still being checked does not: the agent refuses a bad one per adapter anyway',
  [filterBlocksStart({ kind: 'checking' }), filterBlocksStart({ kind: 'ok' }), filterBlocksStart({ kind: 'none' })],
  [null, null, null]);

console.log('\n--- what is remembered ---\n');

check('a stored value that is not options is refused', normalizeCaptureOptions('tcp'), null);
check('a snaplen outside what the agent takes falls back to the suggestion', [
  normalizeCaptureOptions({ filter: 'arp', limitBytes: true, snaplen: 0 })?.snaplen,
  normalizeCaptureOptions({ filter: 'arp', limitBytes: true, snaplen: 262145 })?.snaplen,
  normalizeCaptureOptions({ filter: 'arp', limitBytes: true, snaplen: 1.5 })?.snaplen,
], [SUGGESTED_SNAPLEN, SUGGESTED_SNAPLEN, SUGGESTED_SNAPLEN]);
check('a stored filter is bounded as the agent bounds it',
  normalizeCaptureOptions({ filter: 'a'.repeat(MAX_CAPTURE_FILTER_CHARS + 50) })?.filter.length, MAX_CAPTURE_FILTER_CHARS);
check('the snaplen is kept while switched off, so switching it on restores it',
  normalizeCaptureOptions({ limitBytes: false, snaplen: 200 }), { filter: '', limitBytes: false, snaplen: 200 });

console.log('\n--- a reconnect resumes the same capture ---\n');

const narrowed = startCaptureCommand(opts({ filter: 'udp', limitBytes: true, snaplen: 64 }));
check('the resync resumes with the options that started it',
  planResync({ ownedElsewhere: false, selected: ['\\Device\\NPF_{A}'], capturing: true, start: narrowed }).commands,
  [{ type: 'set_interfaces', interfaces: ['\\Device\\NPF_{A}'] }, narrowed]);
check('...and a plain start when none is given, as before',
  planResync({ ownedElsewhere: false, selected: [], capturing: true }).commands, [{ type: 'start_capture' }]);

console.log('\n--- what an export says about it ---\n');

const meta = (source: CaptureMeta['source']): CaptureMeta => ({
  app: 'Inwire', version: '0.4.1', os: null, generatedAt: 0, source, firstUs: null, lastUs: null,
  scope: 'capture', filter: '', frames: { exported: 0, inCapture: 0, unreadable: 0 },
  drops: { kernel: null, agent: null, pipe: null },
  flags: { anonymised: false, rawBytes: true, fields: false, secrets: false },
});
const rows = (m: CaptureMeta) => Object.fromEntries(metaEntries(m).filter(([k]) => k === 'Capture filter' || k === 'Snapshot length'));
const record = recordOf(opts({ filter: 'host 10.0.0.4 and tcp', limitBytes: true, snaplen: 128 }));
check('a narrowed capture names its filter and snaplen', rows(meta({ kind: 'live', adapters: ['Ethernet'], ...record })),
  { 'Capture filter': 'host 10.0.0.4 and tcp', 'Snapshot length': '128 bytes' });
check('...and an unnarrowed one says so rather than saying nothing',
  rows(meta({ kind: 'live', adapters: ['Ethernet'], ...recordOf(DEFAULT_CAPTURE_OPTIONS) })),
  { 'Capture filter': 'none', 'Snapshot length': 'whole frames' });
check('a capture from before either existed is not recorded, which is not "none"',
  rows(meta({ kind: 'live', adapters: ['Ethernet'] })),
  { 'Capture filter': 'not available', 'Snapshot length': 'not available' });
check('an import has neither row: nobody here chose them', rows(meta({ kind: 'import', fileName: 'x.pcap' })), {});
check('the filter as sent is the one recorded', effectiveFilter(opts({ filter: ' arp ' })), 'arp');

const redacted = redactMeta(meta({ kind: 'live', adapters: ['Ethernet'], ...record }), new Anonymiser());
check('anonymised: the filter is withheld whole - it names hosts - and the snaplen kept',
  rows(redacted), { 'Capture filter': WITHHELD_CAPTURE_FILTER, 'Snapshot length': '128 bytes' });
check('...and a capture with no filter still says none',
  rows(redactMeta(meta({ kind: 'live', adapters: ['Ethernet'], filter: null, snaplen: null }), new Anonymiser())),
  { 'Capture filter': 'none', 'Snapshot length': 'whole frames' });

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All capture-options checks passed.');
process.exit(0);
