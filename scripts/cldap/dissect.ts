/**
 * CLDAP - the domain-controller locator - against the reference, row for row.
 *
 *   npx tsx scripts/cldap/dissect.ts
 *
 * A domain-joined Windows machine finds a domain controller by sending a
 * CLDAP search for the `Netlogon` attribute over UDP 389, with the domain,
 * its own name and the response version it understands in the filter. The
 * controller answers with a LOGON_SAM_LOGON_RESPONSE_EX (MS-ADTS 6.3.1.9):
 * its roles as flags, the domain GUID, the forest, domain and host names, the
 * NetBIOS names, and the sites it and the client are in - the whole answer to
 * "why did this laptop log on against a controller in another city". Built
 * here from MS-ADTS's layouts, names compressed the way a controller sends
 * them, and compared with tshark's reading of the same file.
 */
import { udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

/** A BER TLV with a definite length. */
const tlv = (tag: number, body: number[]): number[] => {
  const n = body.length;
  return n < 128 ? [tag, n, ...body] : n < 256 ? [tag, 0x81, n, ...body] : [tag, 0x82, n >> 8, n & 255, ...body];
};
const utf8 = (text: string) => [...new TextEncoder().encode(text)];
const octets = (text: string) => tlv(0x04, utf8(text));
const equality = (attribute: string, value: number[]) => tlv(0xa3, [...octets(attribute), ...tlv(0x04, value)]);
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];

/** A DNS-style name: labels, ending in a zero byte or a two-byte pointer. */
const labels = (name: string, pointer?: number) => [
  ...name.split('.').filter(Boolean).flatMap((label) => [label.length, ...utf8(label)]),
  ...(pointer === undefined ? [0] : [0xc0 | (pointer >> 8), pointer & 255]),
];

/** LOGON_SAM_LOGON_RESPONSE_EX, names compressed against the forest name as a controller sends them. */
function netlogonResponse(flags: number): number[] {
  const head = [23, 0, 0, 0, ...le32(flags), ...new Array(16).fill(0).map((_, i) => 0x10 + i)];
  const forestAt = head.length;
  const forest = labels('corp.example.com');
  const domain = [0xc0, forestAt];                       // same as the forest
  const host = labels('DC01', forestAt);                  // DC01.corp.example.com
  const netbiosDomain = labels('CORP');
  const netbiosHost = labels('DC01');
  const user = [0];
  const siteAt = head.length + forest.length + domain.length + host.length + netbiosDomain.length + netbiosHost.length + user.length;
  const dcSite = labels('Default-First-Site-Name');
  const clientSite = [0xc0, siteAt];
  return [...head, ...forest, ...domain, ...host, ...netbiosDomain, ...netbiosHost, ...user, ...dcSite, ...clientSite,
    ...le32(5), 0xff, 0xff, 0xff, 0xff];
}

const CLIENT = '192.0.2.1';
const DC = '192.0.2.2';
const request = tlv(0x30, [0x02, 1, 7, ...tlv(0x63, [
  ...octets(''), 0x0a, 1, 0, 0x0a, 1, 0, 0x02, 1, 0, 0x02, 1, 0, 0x01, 1, 0,
  ...tlv(0xa0, [...equality('DnsDomain', utf8('corp.example.com')), ...equality('Host', utf8('LAPTOP1')),
    ...equality('NtVer', [0x16, 0, 0, 0])]),
  ...tlv(0x30, octets('Netlogon')),
])]);
const entry = (flags: number) => tlv(0x30, [0x02, 1, 7, ...tlv(0x64, [
  ...octets(''), ...tlv(0x30, tlv(0x30, [...octets('Netlogon'), ...tlv(0x31, tlv(0x04, netlogonResponse(flags)))])),
])]);
const done = tlv(0x30, [0x02, 1, 7, ...tlv(0x65, [0x0a, 1, 0, ...octets(''), ...octets('')])]);

const cases: OracleCase[] = [
  { label: 'the locator search', frame: udpFrameTo(CLIENT, DC, 50000, 389, Uint8Array.from(request)) },
  { label: 'a writable global-catalog DC answers', frame: udpFrameTo(DC, CLIENT, 389, 50000, Uint8Array.from([...entry(0x0001f3fd), ...done])) },
  { label: 'a read-only DC answers', frame: udpFrameTo(DC, CLIENT, 389, 50001, Uint8Array.from([...entry(0x0000f1bc), ...done])) },
];

const packets = await compareWithReference(cases, { rows: /^(ldap|mscldap)\./ });
await checkRevisit(cases);
check('CLDAP is the `cldap` layer', packets[0]?.frameProtocols?.at(-1) === 'cldap');
finish('CLDAP');
