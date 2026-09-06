import { mkdtempSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Bytes, pcapOf, udpFrame } from '../scripts/parity/synthetic';

const TSHARK = 'C:/Program Files/Wireshark/tshark.exe';

const ascii = (t: string) => new Bytes().ascii(t).build();

// --- Syslog, RFC 3164 and RFC 5424 -------------------------------------------
const syslogBsd = ascii('<34>Oct 11 22:14:15 mymachine su: \'su root\' failed for lonvick on /dev/pts/8');
const syslog5424 = ascii('<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 '
  + '[exampleSDID@32473 iut="3" eventSource="Application"] BOMAn application event log entry...');
const syslogInfo = ascii('<14>Jan  1 00:00:00 host app: hello');

// --- RADIUS, RFC 2865 --------------------------------------------------------
const radiusRequest = (() => {
  const attrs = new Bytes()
    .u8(1, 8).ascii('alice')                     // User-Name
    .u8(4, 6).ipv4('192.0.2.1')                  // NAS-IP-Address
    .u8(5, 6).u32(7)                             // NAS-Port
    .build();
  return new Bytes().u8(1, 42).u16(20 + attrs.length)
    .raw(new Array(16).fill(0xaa)).raw(attrs).build();
})();
const radiusAccept = (() => {
  const attrs = new Bytes().u8(8, 6).ipv4('192.0.2.50').build();  // Framed-IP-Address
  return new Bytes().u8(2, 42).u16(20 + attrs.length)
    .raw(new Array(16).fill(0xbb)).raw(attrs).build();
})();

// --- SNMP, RFC 1157 (BER/ASN.1) ----------------------------------------------
// A GetRequest for 1.3.6.1.2.1.1.1.0 (sysDescr.0) with community "public".
const snmpGet = (() => {
  const oid = new Bytes().u8(0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00).build();
  const varbind = new Bytes().u8(0x30, oid.length + 2).raw(oid).u8(0x05, 0x00).build();
  const varbinds = new Bytes().u8(0x30, varbind.length).raw(varbind).build();
  const pdu = new Bytes()
    .u8(0x02, 0x04).u32(0x0000162e)      // request-id
    .u8(0x02, 0x01, 0x00)                // error-status
    .u8(0x02, 0x01, 0x00)                // error-index
    .raw(varbinds).build();
  const pduWrapped = new Bytes().u8(0xa0, pdu.length).raw(pdu).build();
  const body = new Bytes()
    .u8(0x02, 0x01, 0x00)                                 // version 1 (0 = v1)
    .u8(0x04, 0x06).ascii('public')                       // community
    .raw(pduWrapped).build();
  return new Bytes().u8(0x30, body.length).raw(body).build();
})();

// --- SIP, RFC 3261 -----------------------------------------------------------
const sipInvite = ascii([
  'INVITE sip:bob@example.com SIP/2.0',
  'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds',
  'Max-Forwards: 70',
  'To: Bob <sip:bob@example.com>',
  'From: Alice <sip:alice@example.com>;tag=1928301774',
  'Call-ID: a84b4c76e66710',
  'CSeq: 314159 INVITE',
  'Contact: <sip:alice@192.0.2.1>',
  'Content-Length: 0',
  '', '',
].join('\r\n'));
const sipOk = ascii([
  'SIP/2.0 200 OK',
  'Via: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK776asdhds',
  'To: Bob <sip:bob@example.com>;tag=a6c85cf',
  'From: Alice <sip:alice@example.com>;tag=1928301774',
  'Call-ID: a84b4c76e66710',
  'CSeq: 314159 INVITE',
  'Content-Length: 0',
  '', '',
].join('\r\n'));

const labelled: [string, Uint8Array][] = [
  ['syslog RFC 3164', udpFrame(50000, 514, syslogBsd)],
  ['syslog RFC 5424', udpFrame(50000, 514, syslog5424)],
  ['syslog info-level', udpFrame(50000, 514, syslogInfo)],
  ['RADIUS Access-Request', udpFrame(50000, 1812, radiusRequest)],
  ['RADIUS Access-Accept', udpFrame(1812, 50000, radiusAccept)],
  ['SNMP GetRequest', udpFrame(50000, 161, snmpGet)],
  ['SIP INVITE', udpFrame(5060, 5060, sipInvite)],
  ['SIP 200 OK', udpFrame(5060, 5060, sipOk)],
];

const dir = mkdtempSync(join(tmpdir(), 'batch-'));
const file = join(dir, 'b.pcap');
writeFileSync(file, pcapOf(labelled.map(([, f]) => f)));
const run = spawnSync(TSHARK, [
  '-r', file, '-T', 'fields',
  '-e', '_ws.col.Protocol', '-e', 'frame.protocols', '-e', '_ws.col.Info', '-E', 'separator=|',
], { encoding: 'utf8' });
const rows = (run.stdout || run.stderr).split('\n').filter((l) => l.length);
rows.forEach((r, i) => {
  const [proto, chain, ...info] = r.split('|');
  console.log(`${labelled[i]?.[0] ?? i}\n   Protocol=${JSON.stringify(proto)}  chain=${chain}\n   Info=${JSON.stringify(info.join('|'))}`);
});
