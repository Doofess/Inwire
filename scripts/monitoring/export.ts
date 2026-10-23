/**
 * The history CSV exporter (Task 7A): format, exact bigints, hostile cells,
 * and the sink's ownership rules - one end only, close or abort, never both.
 * Plain `tsx`.
 */
import type { ByteSink } from '../../src/lib/saveSink';
import type { SaveOutcome } from '../../src/lib/saveFile';
import { ExportCancelled, exportHistory, historyCsvName } from '../../src/services/monitoring/export';
import type { HistoryResult } from '../../src/services/monitoring/types';

let failed = 0;
function ok(name: string, cond: boolean, detail = ''): void {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${cond ? '' : ` ${detail}`}`);
  if (!cond) failed++;
}

class TestSink implements ByteSink {
  chunks: Uint8Array[] = [];
  closes = 0;
  aborts = 0;
  writes = 0;
  constructor(private failOn = 0, private onWrite?: (n: number) => void) {}
  async write(chunk: Uint8Array): Promise<void> {
    this.writes++;
    if (this.writes === this.failOn) throw new Error('disk full');
    this.chunks.push(chunk.slice());
    this.onWrite?.(this.writes);
  }
  async close(): Promise<SaveOutcome> { this.closes++; return { saved: true, path: 'x.csv' }; }
  async abort(): Promise<void> { this.aborts++; }
  bytes(): Uint8Array {
    const out = new Uint8Array(this.chunks.reduce((n, c) => n + c.length, 0));
    let at = 0;
    for (const c of this.chunks) { out.set(c, at); at += c.length; }
    return out;
  }
  text(): string { return new TextDecoder().decode(this.bytes()); }
}

/** A tiny RFC 4180 parser: returns rows of cells. */
function parseCsv(text: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQ = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQ) {
      if (ch === '"') { if (text[i + 1] === '"') { cell += '"'; i++; } else inQ = false; } else cell += ch;
    } else if (ch === '"') inQ = true;
    else if (ch === ',') { row.push(cell); cell = ''; }
    else if (ch === '\r' && text[i + 1] === '\n') { row.push(cell); rows.push(row); row = []; cell = ''; i++; }
    else cell += ch;
  }
  if (cell !== '' || row.length > 0) { row.push(cell); rows.push(row); }
  return rows;
}

const T0 = Date.UTC(2026, 9, 17, 10, 0, 0);
function result(over: Partial<HistoryResult> = {}): HistoryResult {
  return {
    snapshot: { generation: 'ab'.repeat(16), throughEntryId: 42 },
    query: { sourceKey: '192.0.2.1:2055', fromMs: T0, toMs: T0 + 3_600_000, bucketCount: 2 },
    buckets: [
      { fromMs: T0, toMs: T0 + 1_800_000, reportedOctets: 2n ** 63n - 1n, reportedPackets: 2n ** 64n - 1n, records: 5, coverage: 'observed-records' },
      { fromMs: T0 + 1_800_000, toMs: T0 + 3_600_000, reportedOctets: null, reportedPackets: null, records: 0, coverage: 'collection-gap' },
    ],
    gaps: [{ fromMs: T0 + 1_800_000, toMs: T0 + 3_600_000, reason: 'app closed' }],
    endpoints: { status: 'ok', rows: [{ address: '10.0.0.1', sentOctets: 2n ** 63n - 1n, receivedOctets: 7n }] },
    conversations: { status: 'ok', rows: [{ srcAddr: '10.0.0.1', dstAddr: '10.0.0.2', reportedOctets: 2n ** 64n - 1n, reportedPackets: 3n }] },
    malformed: 1, unsupported: 2, samplingKnown: true, matchingRecords: 5,
    answeredFrom: { rollupMinutes: 30, rawMinutes: 2 },
    evidence: [],
    awaitingTemplate: 0, awaitingBytes: 0, unsupportedTemplates: 0, sampling: { kind: 'known', interval: 1 },
    clock: { latestSkewMs: null, minSkewMs: null, maxSkewMs: null, flagged: false },
    ...over,
  };
}

function section(rows: string[][], name: string): string[][] {
  const at = rows.findIndex((r) => r[0] === `# section: ${name}`);
  const out: string[][] = [];
  for (let i = at + 1; i < rows.length && !(rows[i].length === 1 && rows[i][0].startsWith('# section:')); i++) {
    if (rows[i].length === 1 && rows[i][0] === '') continue;
    out.push(rows[i]);
  }
  return out;
}

async function main(): Promise<void> {
  // Basic shape
  {
    const sink = new TestSink();
    const outcome = await exportHistory(result(), sink);
    const text = sink.text();
    ok('close returns its outcome', outcome.saved === true && sink.closes === 1 && sink.aborts === 0);
    ok('no BOM', sink.bytes()[0] === 0x22);
    ok('CRLF only', !/(^|[^\r])\n/.test(text));
    for (const k of ['# source: 192.0.2.1:2055', '# from: 2026-10-17T10:00:00.000Z', '# to: 2026-10-17T11:00:00.000Z',
      '# time basis: receipt time at this collector', '# counters: as reported by the exporter', '# sampling:',
      '# snapshot: generation ' + 'ab'.repeat(16) + ' through entry 42', '# matching records: 5',
      '# malformed datagrams: 1', '# unsupported datagrams: 2', '# answered from: 30 rollup minutes, 2 raw minutes',
      '# gap: 2026-10-17T10:30:00.000Z - 2026-10-17T11:00:00.000Z']) {
      ok(`preamble has ${k.slice(0, 28)}`, parseCsv(text).some((r) => r.length === 1 && r[0].startsWith(k)));
    }
    const rows = parseCsv(text);
    const b = section(rows, 'buckets');
    ok('bucket header', b[0].join() === 'from_utc,to_utc,coverage,records,reported_octets,reported_packets');
    ok('bigint exact', b[1][4] === '9223372036854775807' && b[1][5] === '18446744073709551615');
    ok('null counters are empty cells', b[2][4] === '' && b[2][5] === '' && b[2][2] === 'collection-gap');
    const e = section(rows, 'endpoints');
    ok('endpoints', e[0].join() === 'address,sent_octets,received_octets' && e[1].join() === '10.0.0.1,9223372036854775807,7');
    const c = section(rows, 'conversations');
    ok('conversations', c[0].join() === 'src_addr,dst_addr,reported_octets,reported_packets' && c[1][2] === '18446744073709551615');
    ok('row counts', b.length - 1 === 2 && e.length - 1 === 1 && c.length - 1 === 1);
  }
  // Hostile cells and range-too-large
  {
    const evil = 'a,"b"\r\nc';
    const sink = new TestSink();
    await exportHistory(result({
      endpoints: { status: 'ok', rows: [{ address: evil, sentOctets: 1n, receivedOctets: 2n }] },
      conversations: { status: 'range-too-large', message: 'too, "big"\nreally' },
      query: { sourceKey: 'k\r\n# injected: 1', fromMs: T0, toMs: T0 + 1000, bucketCount: 1 },
    }), sink);
    const text = sink.text();
    const rows = parseCsv(text);
    ok('hostile address round-trips', section(rows, 'endpoints')[1][0] === evil);
    ok('range-too-large line instead of header', section(rows, 'conversations').length === 1
      && section(rows, 'conversations')[0][0].startsWith('# not available: '));
    ok('preamble value cannot start a new line', !/^# injected/m.test(text));
    ok('not-available message is one record', !text.includes('\nreally') && text.includes('too'));
  }
  // Expired evidence (ADR 0062): the coverage column carries the new values, expired tables say so
  {
    const sink = new TestSink();
    await exportHistory(result({
      buckets: [
        { fromMs: T0, toMs: T0 + 1_800_000, reportedOctets: 10n, reportedPackets: 2n, records: 0, coverage: 'aggregate-only' },
        { fromMs: T0 + 1_800_000, toMs: T0 + 3_600_000, reportedOctets: null, reportedPackets: null, records: 0, coverage: 'history-lost' },
      ],
      endpoints: { status: 'evidence-expired', expiredMs: T0 + 900_000, expiry: null, incomplete: false },
      conversations: { status: 'evidence-expired', expiredMs: T0 + 900_000, expiry: null, incomplete: false },
    }), sink);
    const rows = parseCsv(sink.text());
    const b = section(rows, 'buckets');
    ok('expired: aggregate-only keeps its counters', b[1][2] === 'aggregate-only' && b[1][4] === '10' && b[1][5] === '2');
    ok('expired: history-lost has empty counters', b[2][2] === 'history-lost' && b[2][4] === '' && b[2][5] === '');
    for (const name of ['endpoints', 'conversations']) {
      const s = section(rows, name);
      ok(`expired: ${name} is one not-available line`, s.length === 1 && s[0][0].startsWith('# not available: ')
        && s[0][0].includes('2026-10-17T10:15:00.000Z'), String(s[0]));
    }
  }
  // Empty
  {
    const sink = new TestSink();
    await exportHistory(result({
      buckets: [], gaps: [], endpoints: { status: 'ok', rows: [] }, conversations: { status: 'ok', rows: [] },
    }), sink);
    const rows = parseCsv(sink.text());
    ok('empty: headers only', section(rows, 'buckets').length === 1 && section(rows, 'endpoints').length === 1
      && section(rows, 'conversations').length === 1 && sink.closes === 1 && sink.aborts === 0);
    ok('empty: no gap line', !sink.text().includes('# gap:'));
  }
  // Sampling wording follows samplingKnown
  {
    const a = new TestSink(); const b = new TestSink();
    await exportHistory(result({ samplingKnown: true }), a);
    await exportHistory(result({ samplingKnown: false }), b);
    const line = (s: TestSink) => parseCsv(s.text()).find((r) => r[0].startsWith('# sampling:'))?.[0];
    ok('sampling line reflects samplingKnown', line(a) !== line(b) && !!line(a) && !!line(b));
  }
  // Big result, totals, chunking
  const bigBuckets = Array.from({ length: 1000 }, (_, i) => ({
    fromMs: T0 + i * 1000, toMs: T0 + (i + 1) * 1000, reportedOctets: i % 7 === 0 ? null : BigInt(i) * 2n ** 40n,
    reportedPackets: i % 7 === 0 ? null : BigInt(i), records: i, coverage: 'observed-records' as const,
  }));
  const bigEndpoints = Array.from({ length: 1000 }, (_, i) => ({ address: `10.1.${i >> 8}.${i & 255}`, sentOctets: BigInt(i), receivedOctets: 1n }));
  const big = result({ buckets: bigBuckets, endpoints: { status: 'ok', rows: bigEndpoints } });
  {
    const sink = new TestSink();
    await exportHistory(big, sink);
    ok('large result uses several writes', sink.writes >= 4, String(sink.writes));
    const rows = parseCsv(sink.text());
    const b = section(rows, 'buckets').slice(1);
    const sum = b.reduce((s, r) => s + (r[4] === '' ? 0n : BigInt(r[4])), 0n);
    const want = bigBuckets.reduce((s, x) => s + (x.reportedOctets ?? 0n), 0n);
    ok('bucket rows and octet total match', b.length === 1000 && sum === want);
    ok('endpoint rows match', section(rows, 'endpoints').length - 1 === 1000);
  }
  // Cancellation
  {
    const sink = new TestSink();
    const ctl = new AbortController(); ctl.abort();
    let err: unknown;
    await exportHistory(big, sink, { signal: ctl.signal }).catch((e) => { err = e; });
    ok('pre-aborted: ExportCancelled, abort once, no close', err instanceof ExportCancelled && sink.aborts === 1 && sink.closes === 0);
  }
  {
    const ctl = new AbortController();
    const sink = new TestSink(0, (n) => { if (n === 2) ctl.abort(); });
    let err: unknown;
    await exportHistory(big, sink, { signal: ctl.signal }).catch((e) => { err = e; });
    ok('aborted between chunks: ExportCancelled, abort once, no close',
      err instanceof ExportCancelled && sink.aborts === 1 && sink.closes === 0 && sink.writes === 2, `writes ${sink.writes}`);
  }
  // Write failure
  {
    const sink = new TestSink(2);
    let err: unknown;
    await exportHistory(big, sink).catch((e) => { err = e; });
    ok('write failure: that error, abort once, no close',
      err instanceof Error && err.message === 'disk full' && !(err instanceof ExportCancelled) && sink.aborts === 1 && sink.closes === 0);
  }
  // Abort that rejects too
  {
    class BadSink extends TestSink {
      async write(): Promise<void> { throw new Error('disk full'); }
      async abort(): Promise<void> { this.aborts++; throw new Error('abort failed'); }
    }
    const sink = new BadSink();
    let err: unknown;
    await exportHistory(big, sink).catch((e) => { err = e; });
    ok('write and abort both reject: original error surfaces', err instanceof Error && err.message === 'disk full' && sink.aborts === 1);
    const ctl = new AbortController(); ctl.abort();
    const sink2 = new BadSink();
    err = undefined;
    await exportHistory(big, sink2, { signal: ctl.signal }).catch((e) => { err = e; });
    ok('cancel and abort rejects: ExportCancelled surfaces', err instanceof ExportCancelled);
  }
  // Preamble lines are one quoted cell each; gap carries its reason; focus line
  {
    const lineOf = (text: string, prefix: string): string | undefined =>
      parseCsv(text).find((r) => r.length === 1 && r[0].startsWith(prefix))?.[0];
    const sink = new TestSink();
    await exportHistory(result({ gaps: [{ fromMs: T0, toMs: T0 + 1000, reason: 'app closed\r\nnow' }] }), sink);
    const text = sink.text();
    ok('time basis line is a single cell despite its comma',
      lineOf(text, '# time basis: ')?.includes('collector (when Inwire received each export), not flow') === true);
    ok('gap line carries its reason, one line', lineOf(text, '# gap: ')?.endsWith(': app closed now') === true, String(lineOf(text, '# gap: ')));
    ok('focus none', lineOf(text, '# focus: ') === '# focus: none');
    const preambleStart = text.split('\r\n').slice(0, 3).join('|');
    ok('focus line follows source', preambleStart === '"# source: 192.0.2.1:2055"|"# focus: none"|"# from: 2026-10-17T10:00:00.000Z"', preambleStart);

    const q = { sourceKey: '192.0.2.1:2055', fromMs: T0, toMs: T0 + 1000, bucketCount: 1 };
    const ep = new TestSink();
    const epResult = result({ query: { ...q, focus: { kind: 'endpoint', address: '10.0.0.5' } } });
    await exportHistory(epResult, ep);
    ok('focus endpoint line', lineOf(ep.text(), '# focus: ') === '# focus: endpoint 10.0.0.5');
    const epName = historyCsvName(epResult);
    ok('focus endpoint name', epName.endsWith('-endpoint-10.0.0.5.csv') && !/[\\/:*?"<>|]/.test(epName), epName);

    const cv = new TestSink();
    const cvResult = result({ query: { ...q, focus: { kind: 'conversation', srcAddr: '2001:db8::1', dstAddr: '10.0.0.2' } } });
    await exportHistory(cvResult, cv);
    ok('focus conversation line', lineOf(cv.text(), '# focus: ') === '# focus: conversation 2001:db8::1 -> 10.0.0.2');
    const cvName = historyCsvName(cvResult);
    ok('focus conversation name', cvName.endsWith('-conv-2001_db8_1-10.0.0.2.csv') && !/[\\/:*?"<>|]/.test(cvName), cvName);
  }
  // Name
  {
    const n = historyCsvName(result({ query: { sourceKey: '192.0.2.1:2055', fromMs: T0, toMs: T0 + 1000, bucketCount: 1 } }));
    ok('file name has no illegal characters', !/[\\/:*?"<>|]/.test(n) && n.endsWith('.csv') && n.startsWith('inwire-flows-'), n);
    const h = historyCsvName(result({ query: { sourceKey: 'a/b:c*"<>|?\\', fromMs: T0, toMs: T0 + 1000, bucketCount: 1 } }));
    ok('hostile source key sanitised', !/[\\/:*?"<>|]/.test(h), h);
  }
  console.log(failed === 0 ? 'ALL PASS' : `${failed} FAILED`);
  process.exit(failed === 0 ? 0 : 1);
}

void main();
