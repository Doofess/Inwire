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
  ringProblem, startCaptureCommand, startLiveCapture, type CaptureOptions,
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

{
  // The Worker drops every frame that reaches it before it hears it is
  // capturing, and the first frame it keeps starts the run, so the ones before
  // it are no hole and are never read back from the file. Both go down one
  // port, which keeps their order: capturing first, then the agent's start.
  const heard: string[] = [];
  startLiveCapture({
    setCapturing: (on) => heard.push(`capturing ${on}`),
    command: (command) => heard.push(command.type),
  }, startCaptureCommand(DEFAULT_CAPTURE_OPTIONS, 'cap-1'));
  check('Start tells the Worker it is capturing before the agent can send a frame', heard, ['capturing true', 'start_capture']);
}

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
const snaplenOf = (o: CaptureOptions | null) => o && { limitBytes: o.limitBytes, snaplen: o.snaplen };
check('the snaplen is kept while switched off, so switching it on restores it',
  snaplenOf(normalizeCaptureOptions({ limitBytes: false, snaplen: 200 })), { limitBytes: false, snaplen: 200 });

console.log('\n--- the capture\'s own files (ADR 0052) ---\n');

const ID = 'cap-20260928-120000-0af3';
check('a start names its capture, which is what makes the agent write its pcapng',
  startCaptureCommand(DEFAULT_CAPTURE_OPTIONS, ID), { type: 'start_capture', captureId: ID });
check('a ring travels in bytes, with what it keeps',
  startCaptureCommand(opts({ ringOn: true, ringMegabytes: 2, ringKeep: 3 }), ID),
  { type: 'start_capture', captureId: ID, ring: { fileBytes: 2 * 1024 * 1024, keep: 3 } });
check('...by duration and packets too, and keeping every file sends no keep',
  startCaptureCommand(opts({ ringOn: true, ringMegabytes: null, ringSeconds: 60, ringPackets: 1000, ringKeep: null }), ID),
  { type: 'start_capture', captureId: ID, ring: { fileSeconds: 60, filePackets: 1000 } });
check('a ring switched off is not sent, whatever it was set to',
  startCaptureCommand(opts({ ringOn: false, ringMegabytes: 2 }), ID), { type: 'start_capture', captureId: ID });
check('an autostop travels, megabytes as bytes',
  startCaptureCommand(opts({ stopPackets: 5000, stopMegabytes: 5, stopSeconds: 10 }), ID),
  { type: 'start_capture', captureId: ID, autostop: { packets: 5000, bytes: 5 * 1024 * 1024, seconds: 10 } });
check('...and a file count only with a ring',
  [startCaptureCommand(opts({ stopFiles: 3 }), ID),
    startCaptureCommand(opts({ ringOn: true, stopFiles: 3 }), ID)],
  [{ type: 'start_capture', captureId: ID },
    { type: 'start_capture', captureId: ID, ring: { fileBytes: 100 * 1024 * 1024, keep: 10 }, autostop: { files: 3 } }]);
check('without a capture to write, neither is sent - the agent would refuse them',
  startCaptureCommand(opts({ ringOn: true, stopPackets: 10 })), { type: 'start_capture' });
check('a ring with nothing to rotate at blocks Start, with the reason',
  ringProblem(opts({ ringOn: true, ringMegabytes: null })),
  'Multiple files needs a size, a duration or a packet count to start a new file at.');
check('...and a file count without a ring', ringProblem(opts({ stopFiles: 3 })),
  'Stopping after a number of files needs multiple files: one file never becomes two.');
check('the defaults start', ringProblem(DEFAULT_CAPTURE_OPTIONS), null);
check('options stored before rings existed get the defaults, so a ring switched on has a size',
  (({ ringOn, ringMegabytes, ringKeep, stopPackets }) => ({ ringOn, ringMegabytes, ringKeep, stopPackets }))(
    normalizeCaptureOptions({ filter: 'arp', limitBytes: false, snaplen: 128 })!),
  { ringOn: false, ringMegabytes: 100, ringKeep: 10, stopPackets: null });
check('a ring keeping fewer than two, or a limit that is not a count, is not stored',
  (({ ringKeep, stopPackets }) => ({ ringKeep, stopPackets }))(
    normalizeCaptureOptions({ ringKeep: 1, stopPackets: -5 })!),
  { ringKeep: null, stopPackets: null });

console.log('\n--- a reconnect resumes the same capture ---\n');

const narrowed = startCaptureCommand(opts({ filter: 'udp', limitBytes: true, snaplen: 64 }));
check('the resync resumes with the options that started it',
  planResync({ ownedElsewhere: false, selected: ['\\Device\\NPF_{A}'], capturing: true, start: narrowed }).commands,
  [{ type: 'set_interfaces', interfaces: ['\\Device\\NPF_{A}'] }, narrowed]);
check('...and a plain start when none is given, as before',
  planResync({ ownedElsewhere: false, selected: [], capturing: true }).commands, [{ type: 'start_capture' }]);

console.log('\n--- what an export says about it ---\n');

const meta = (source: CaptureMeta['source']): CaptureMeta => ({
  app: 'Inwire', version: '0.5.0', os: null, generatedAt: 0, source, firstUs: null, lastUs: null,
  scope: 'capture', filter: '', frames: { exported: 0, inCapture: 0, unreadable: 0 },
  drops: { kernel: null, agent: null, pipe: null },
  flags: { anonymised: false, rawBytes: true, fields: false, secrets: false },
});
const rows = (m: CaptureMeta) => Object.fromEntries(metaEntries(m).filter(([k]) => k === 'Capture filter' || k === 'Snapshot length'));
const fileRows = (m: CaptureMeta) => Object.fromEntries(metaEntries(m).filter(([k]) => k === 'Capture files' || k === 'Autostop'));
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
check('a ring and an autostop are said in words',
  fileRows(meta({ kind: 'live', adapters: ['Ethernet'],
    ...recordOf(opts({ ringOn: true, ringMegabytes: 100, ringSeconds: 60, ringKeep: 3, stopPackets: 5000 })) })),
  { 'Capture files': 'a new file every 100 MB or 60 s, newest 3 kept', Autostop: '5,000 packets' });
check('...one file and no autostop are said too, not left out',
  fileRows(meta({ kind: 'live', adapters: ['Ethernet'], ...recordOf(DEFAULT_CAPTURE_OPTIONS) })),
  { 'Capture files': 'one file', Autostop: 'none' });
check('...and survive anonymising: they name no host',
  fileRows(redactMeta(meta({ kind: 'live', adapters: ['Ethernet'],
    ...recordOf(opts({ ringOn: true, ringKeep: 3 })) }), new Anonymiser())),
  { 'Capture files': 'a new file every 100 MB, newest 3 kept', Autostop: 'none' });
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
