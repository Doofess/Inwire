/**
 * Assertion tests for the DNS dissector: record parsing, the sections in the
 * tree, EDNS, SVCB/HTTPS, and query/response pairing.
 *
 *   npx tsx scripts/dns/records.ts
 *
 * The messages are built here byte by byte rather than lifted from a capture,
 * so the test carries no real traffic and every field it checks is one the
 * test itself put there. `example.com` and RFC 5737 / RFC 3849 addresses
 * throughout.
 *
 * The HTTPS record is the shape that matters most: an `ech` parameter in one
 * means the site's TLS handshakes will hide the real server name, which is
 * what tells the TLS dissector an outer SNI is a decoy rather than the answer.
 */
import { parseDnsMessage, dnsInfoLine, buildDnsLayer } from '../../src/services/dissectors/dns';
import { DnsTracker } from '../../src/services/dnsTracker';
import type { ProtocolField } from '../../src/types/packet';

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

// --- a tiny DNS message builder ------------------------------------------------

class Writer {
  bytes: number[] = [];
  u8(...v: number[]) { this.bytes.push(...v); return this; }
  u16(v: number) { this.bytes.push((v >> 8) & 0xff, v & 0xff); return this; }
  u32(v: number) { this.bytes.push((v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff); return this; }
  name(n: string) {
    for (const label of n.split('.')) {
      if (!label) continue;
      this.u8(label.length);
      for (const ch of label) this.u8(ch.charCodeAt(0));
    }
    this.u8(0);
    return this;
  }
  /** A compression pointer to an absolute offset. */
  pointer(off: number) { this.u16(0xc000 | off); return this; }
  ascii(s: string) { for (const ch of s) this.u8(ch.charCodeAt(0)); return this; }
  get out() { return Uint8Array.from(this.bytes); }
}

const header = (w: Writer, id: number, flags: number, counts: [number, number, number, number]) =>
  w.u16(id).u16(flags).u16(counts[0]).u16(counts[1]).u16(counts[2]).u16(counts[3]);

const findField = (fields: ProtocolField[], name: string): ProtocolField | undefined => {
  for (const f of fields) {
    if (f.name === name) return f;
    const hit = f.children ? findField(f.children, name) : undefined;
    if (hit) return hit;
  }
  return undefined;
};

// --- a query and its answer ------------------------------------------------------

{
  const q = new Writer();
  header(q, 0x1a2b, 0x0100, [1, 0, 0, 0]).name('www.example.com').u16(1).u16(1);
  const query = parseDnsMessage(q.out, 0)!;
  check('a query parses', !!query, true);
  check('...with its question', [query.questions[0].name, query.questions[0].type], ['www.example.com', 1]);
  check('...and Wireshark\'s Info line', dnsInfoLine(query, false), 'Standard query 0x1a2b A www.example.com');

  const r = new Writer();
  header(r, 0x1a2b, 0x8180, [1, 2, 0, 0]).name('www.example.com').u16(1).u16(1);
  r.pointer(12).u16(5).u16(1).u32(300).u16(2).pointer(12);         // CNAME -> www.example.com (self, for brevity)
  r.pointer(12).u16(1).u16(1).u32(300).u16(4).u8(192, 0, 2, 1);    // A 192.0.2.1
  const response = parseDnsMessage(r.out, 0)!;
  check('a response lists its answers', response.records.map((x) => x.type), [5, 1]);
  check('...rendering each one', dnsInfoLine(response, false),
    'Standard query response 0x1a2b A www.example.com CNAME www.example.com A 192.0.2.1');
  check('...and reports the address for name resolution',
    buildDnsLayer(r.out, 0)!.resolved, [{ name: 'www.example.com', addresses: ['192.0.2.1'] }]);

  const layer = buildDnsLayer(r.out, 0)!.layer;
  check('the tree has an Answers section', layer.fields.some((f) => f.name === 'Answers'), true);
  check('...with the address as a row', findField(layer.fields, 'Address')?.value, '192.0.2.1');
  check('...and the name as a filterable field', buildDnsLayer(r.out, 0)!.fields['dns.a'], '192.0.2.1');
  check('a TTL reads as Wireshark writes it', findField(layer.fields, 'Time to live')?.value, '300 (5 minutes)');
}

// --- NXDOMAIN carries its SOA in the authority section ---------------------------

{
  const w = new Writer();
  header(w, 0x0007, 0x8183, [1, 0, 1, 0]).name('nope.example.com').u16(1).u16(1);
  const soaStart = w.bytes.length;
  w.pointer(17).u16(6).u16(1).u32(60);   // name -> "example.com" inside the question
  const rdlenAt = w.bytes.length;
  w.u16(0);
  const rdataStart = w.bytes.length;
  w.name('ns.example.com').name('hostmaster.example.com').u32(1).u32(2).u32(3).u32(4).u32(5);
  const rdlen = w.bytes.length - rdataStart;
  w.bytes[rdlenAt] = (rdlen >> 8) & 0xff;
  w.bytes[rdlenAt + 1] = rdlen & 0xff;

  const msg = parseDnsMessage(w.out, 0)!;
  check('the SOA is in the authority section', msg.records[0].section, 'authority');
  check('...and its fields are decoded', msg.records[0].soa?.mname, 'ns.example.com');
  check('the Info line names the failure', dnsInfoLine(msg, false).startsWith('Standard query response 0x0007 No such name'), true);

  const dns = buildDnsLayer(w.out, 0)!;
  check('NXDOMAIN is reported', dns.nxdomain, true);
  check('...as an expert note', findField(dns.layer.fields, '[Expert Info]')?.expertInfo?.severity, 'note');
  check('...in the Authoritative nameservers section', dns.layer.fields.some((f) => f.name === 'Authoritative nameservers'), true);
  check('the reply code is filterable', dns.fields['dns.flags.rcode'], 3);
  check('soaStart is where the record began', msg.records[0].start, soaStart);
}

// --- HTTPS/SVCB, including the ech parameter -------------------------------------

{
  const w = new Writer();
  header(w, 0x00aa, 0x8180, [1, 1, 0, 0]).name('example.com').u16(65).u16(1);
  w.pointer(12).u16(65).u16(1).u32(90);
  const rdlenAt = w.bytes.length;
  w.u16(0);
  const start = w.bytes.length;
  w.u16(1).u8(0);                                    // priority 1, TargetName = root
  w.u16(1).u16(6).u8(2).ascii('h3').u8(2).ascii('h2'); // alpn = h3,h2
  w.u16(4).u16(8).u8(192, 0, 2, 1, 192, 0, 2, 2);      // ipv4hint
  w.u16(5).u16(3).u8(1, 2, 3);                         // ech
  const rdlen = w.bytes.length - start;
  w.bytes[rdlenAt] = (rdlen >> 8) & 0xff;
  w.bytes[rdlenAt + 1] = rdlen & 0xff;

  const msg = parseDnsMessage(w.out, 0)!;
  const rec = msg.records[0];
  check('the HTTPS record parses', [rec.type, rec.svcb?.priority, rec.svcb?.target], [65, 1, '<Root>']);
  check('...with its parameters named', rec.svcb?.params.map((p) => p.name), ['alpn', 'ipv4hint', 'ech']);
  check('...the ALPN list', rec.svcb?.params[0].values, ['h3', 'h2']);
  check('...the address hints, which resolve the name', rec.addresses, ['192.0.2.1', '192.0.2.2']);
  const layer = buildDnsLayer(w.out, 0)!.layer;
  check('the tree names the alpn parameter', findField(layer.fields, 'SvcParam: alpn=h3,h2') !== undefined, true);
  check('...and explains what ech means for TLS',
    (findField(layer.fields, 'SvcParam: ech=3 bytes')?.description ?? '').includes('Encrypted Client Hello'), true);
}

// --- EDNS(0) --------------------------------------------------------------------

{
  const w = new Writer();
  header(w, 0x00bb, 0x0100, [1, 0, 0, 1]).name('example.com').u16(1).u16(1);
  w.u8(0).u16(41).u16(1232).u8(0, 0, 0x80, 0);       // root name, OPT, size 1232, DO set
  w.u16(4);                                          // rdlen
  w.u16(10).u16(0);                                  // COOKIE, empty

  const msg = parseDnsMessage(w.out, 0)!;
  const opt = msg.records[0];
  check('OPT parses as EDNS', [opt.type, opt.edns?.udpPayloadSize, opt.edns?.dnssecOk], [41, 1232, true]);
  check('...with its options named', opt.edns?.options.map((o) => o.name), ['COOKIE']);
  check('OPT is not shown as an answer in the Info line', dnsInfoLine(msg, false), 'Standard query 0x00bb A example.com');
  const layer = buildDnsLayer(w.out, 0)!.layer;
  check('...but is in the Additional records section', layer.fields.some((f) => f.name === 'Additional records'), true);
  check('...with the payload size', findField(layer.fields, 'UDP payload size')?.value, 1232);
}

// --- mDNS: the QM/QU bit and every section in the Info line ----------------------

{
  const w = new Writer();
  header(w, 0x0000, 0x0000, [1, 0, 0, 0]).name('_spotify-connect._tcp.local').u16(12).u16(0x0001);
  const msg = parseDnsMessage(w.out, 0)!;
  check('a multicast question asks for a multicast answer',
    dnsInfoLine(msg, true), 'Standard query 0x0000 PTR _spotify-connect._tcp.local, "QM" question');

  const unicast = new Writer();
  header(unicast, 0x0000, 0x0000, [1, 0, 0, 0]).name('_rdlink._tcp.local').u16(12).u16(0x8001);
  check('...and a unicast-requested one says so',
    dnsInfoLine(parseDnsMessage(unicast.out, 0)!, true), 'Standard query 0x0000 PTR _rdlink._tcp.local, "QU" question');

  // A response whose records live in the ADDITIONAL section still lists them.
  const resp = new Writer();
  header(resp, 0x0000, 0x8400, [0, 1, 0, 1]);
  resp.name('_svc._tcp.local').u16(12).u16(1).u32(4500).u16(2).pointer(12);
  const srvNameAt = resp.bytes.length;
  resp.name('host.local').u16(33).u16(1).u32(120);
  const rdlenAt = resp.bytes.length;
  resp.u16(0);
  const start = resp.bytes.length;
  resp.u16(0).u16(0).u16(56752).name('host.local');
  const rdlen = resp.bytes.length - start;
  resp.bytes[rdlenAt] = (rdlen >> 8) & 0xff;
  resp.bytes[rdlenAt + 1] = rdlen & 0xff;
  const respMsg = parseDnsMessage(resp.out, 0)!;
  check('an answer and an additional record are both listed',
    dnsInfoLine(respMsg, true),
    'Standard query response 0x0000 PTR _svc._tcp.local SRV 0 0 56752 host.local');
  check('...and the sections are distinguished', respMsg.records.map((r) => r.section), ['answer', 'additional']);
  check('srvNameAt is where the additional record began', respMsg.records[1].start, srvNameAt);
}

// --- query/response pairing ---------------------------------------------------------

{
  const t = new DnsTracker();
  t.recordQuery(0x1234, '192.0.2.10', 51000, 'example.com', false, 10, 1_000_000);
  const hit = t.matchResponse(0x1234, '192.0.2.10', 51000, 'example.com', false, 1_004_300);
  check('a response finds its query', hit?.frameId, 10);
  check('...and how long it took', hit?.elapsedUs, 4_300);
  check('the pairing is consumed, so a duplicate response finds nothing',
    t.matchResponse(0x1234, '192.0.2.10', 51000, 'example.com', false, 1_005_000), undefined);

  t.recordQuery(0x1234, '192.0.2.11', 51000, 'example.com', false, 11, 2_000_000);
  check('another client\'s identical transaction id is a different query',
    t.matchResponse(0x1234, '192.0.2.10', 51000, 'example.com', false, 2_001_000), undefined);

  // mDNS uses transaction id 0 for everything, so the question is the key.
  t.recordQuery(0, '192.0.2.20', 5353, '_svc._tcp.local', true, 20, 3_000_000);
  check('a multicast answer pairs on the question name',
    t.matchResponse(0, '192.0.2.99', 5353, '_svc._tcp.local', true, 3_000_500)?.frameId, 20);
  t.recordQuery(0, '192.0.2.20', 5353, '_late._tcp.local', true, 21, 4_000_000);
  check('...but not one that arrives a minute later',
    t.matchResponse(0, '192.0.2.20', 5353, '_late._tcp.local', true, 64_000_000), undefined);

  const lonely = new DnsTracker();
  lonely.recordQuery(0x5555, '192.0.2.30', 5000, 'never.example.com', false, 30, 5_000_000);
  check('a query with no answer is reported as unanswered', lonely.unanswered(11_000_000), [30]);
  check('...and not before the timeout', lonely.unanswered(5_500_000), []);
}

// --- malformed input ----------------------------------------------------------------

{
  check('a short datagram is not DNS', parseDnsMessage(new Uint8Array(4), 0), null);
  check('an unknown opcode is not DNS', parseDnsMessage(Uint8Array.from([0, 1, 0x78, 0, 0, 0, 0, 0, 0, 0, 0, 0]), 0), null);
  // A record claiming more data than the message holds must not read past it.
  const w = new Writer();
  header(w, 1, 0x8180, [0, 1, 0, 0]).name('example.com').u16(1).u16(1).u32(60).u16(9999);
  check('a record longer than the message is dropped, not misread', parseDnsMessage(w.out, 0)!.records.length, 0);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All DNS checks passed.');
process.exit(0);
