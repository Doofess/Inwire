/**
 * The Windows browser protocol - and the NetBIOS datagram, SMB Trans and
 * mailslot it travels in - against the reference, row for row.
 *
 *   npx tsx scripts/browser/dissect.ts
 *
 * Every Windows machine on a LAN broadcasts a Host Announcement to UDP 138
 * every twelve minutes: its name, its comment, its Windows version and every
 * role it plays, written as an SMB Transaction to `\MAILSLOT\BROWSE` inside a
 * NetBIOS datagram. Neither fixture holds one, so they are built here from
 * MS-BRWS, MS-CIFS and RFC 1002's layouts and compared with tshark's reading
 * of the same file: every command the browser has, every flag of every flag
 * word set and clear, the reserved timeouts, and the Windows versions the
 * reference names.
 */
import { udpFrameTo } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const le16 = (n: number) => [n & 255, (n >> 8) & 255];
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
const ascii = (text: string) => [...new TextEncoder().encode(text)];
const utf16 = (text: string) => [...text].flatMap((c) => le16(c.charCodeAt(0)));
/** A sixteen-byte name field, NUL-padded. */
const name16 = (text: string) => [...ascii(text), ...new Array(16 - text.length).fill(0)];

/** RFC 1001 first-level encoding of a NetBIOS name and its suffix. */
function netbiosName(name: string, suffix: number): number[] {
  const raw = [...ascii(name.padEnd(15, ' ')).slice(0, 15), suffix];
  return [32, ...raw.flatMap((c) => [0x41 + (c >> 4), 0x41 + (c & 15)]), 0];
}

interface TransOptions { flags?: number; flags2?: number; status?: number; timeout?: number; transFlags?: number; mailslotClass?: number }

/** An SMB1 Trans request writing `data` to `mailslot` (MS-CIFS 2.2.4.33.1). */
function transToMailslot(mailslot: string, data: number[], o: TransOptions = {}): number[] {
  const flags2 = o.flags2 ?? 0;
  const status = (flags2 & 0x4000) !== 0 ? le32(o.status ?? 0) : [0, 0, 0, 0];
  const header = [0xff, 0x53, 0x4d, 0x42, 0x25, ...status, o.flags ?? 0, ...le16(flags2), 0, 0,
    ...new Array(8).fill(0), 0, 0, ...le16(0), ...le16(0xfeff), ...le16(0), ...le16(0)];
  const unicode = (flags2 & 0x8000) !== 0;
  const wordCount = 17;
  const bccAt = header.length + 1 + wordCount * 2;
  // A Unicode name is aligned to two bytes from the start of the message.
  const name = unicode ? [...((bccAt + 2) % 2 === 1 ? [0] : []), ...utf16(mailslot), 0, 0] : [...ascii(mailslot), 0];
  const dataOffset = bccAt + 2 + name.length;
  const words = [
    ...le16(0), ...le16(data.length), ...le16(0), ...le16(0), 0, 0, ...le16(o.transFlags ?? 0), ...le32(o.timeout ?? 0),
    ...le16(0), ...le16(0), ...le16(dataOffset), ...le16(data.length), ...le16(dataOffset), 3, 0,
    ...le16(1), ...le16(1), ...le16(o.mailslotClass ?? 2),
  ];
  const bytes = [...name, ...data];
  return [...header, wordCount, ...words, ...le16(bytes.length), ...bytes];
}

const HOST = '192.168.1.20';
const BROADCAST = '192.168.1.255';

/** A NetBIOS datagram of `type` from HOST, carrying `user`. */
function datagram(type: number, flags: number, from: [string, number], to: [string, number], user: number[]): Uint8Array {
  const names = [...netbiosName(...from), ...netbiosName(...to)];
  const length = names.length + user.length;
  return udpFrameTo(HOST, BROADCAST, 138, 138, Uint8Array.from([
    type, flags, 0x12, 0x34, ...HOST.split('.').map(Number), ...[0, 138], length >> 8, length & 255, 0, 0, ...names, ...user,
  ]));
}
const toBrowse = (data: number[], o: TransOptions = {}, to: [string, number] = ['WORKGROUP', 0x1d]) =>
  datagram(0x11, 0x02, ['LAPTOP1', 0x00], to, transToMailslot('\\MAILSLOT\\BROWSE', data, o));

/** HostAnnouncement, DomainAnnouncement and LocalMasterAnnouncement share a layout. */
const announcement = (command: number, server: string, major: number, minor: number, type: number, comment: string, period = 720000) =>
  [command, 0, ...le32(period), ...name16(server), major, minor, ...le32(type), 15, 1, 0x55, 0xaa, ...ascii(comment), 0];
const election = (criteria: number, uptime: number, server: string) =>
  [0x08, 0x01, ...le32(criteria), ...le32(uptime), ...le32(0), ...ascii(server), 0];

const cases: OracleCase[] = [
  { label: 'a host announcement', frame: toBrowse(announcement(0x01, 'LAPTOP1', 10, 0, 0x00011003, 'Rotem laptop')) },
  { label: 'a local master announcement', frame: datagram(0x11, 0x02, ['DESKTOP', 0x00], ['WORKGROUP', 0x1e],
    transToMailslot('\\MAILSLOT\\BROWSE', announcement(0x0f, 'DESKTOP', 6, 1, 0x00051203, ''))) },
  { label: 'a workgroup announcement to __MSBROWSE__', frame: datagram(0x11, 0x02, ['DESKTOP', 0x00], ['\u0001\u0002__MSBROWSE__\u0002', 0x01],
    transToMailslot('\\MAILSLOT\\BROWSE', announcement(0x0c, 'WORKGROUP', 10, 0, 0x80001000, 'DESKTOP'))) },
  { label: 'a request announcement', frame: toBrowse([0x02, 0x00, ...ascii('LAPTOP1'), 0]) },
  { label: 'an election request', frame: toBrowse(election(0x20011f01, 3600000, 'LAPTOP1'), {}, ['WORKGROUP', 0x1e]) },
  { label: 'an election with every criterion set', frame: toBrowse(election(0xffffffff, 90061000, '')) },
  { label: 'an election with none', frame: toBrowse(election(0, 1500, 'PC')) },
  { label: 'a backup list request', frame: toBrowse([0x09, 0x04, ...le32(7)]) },
  { label: 'a backup list response', frame: datagram(0x10, 0x02, ['DESKTOP', 0x00], ['LAPTOP1', 0x00],
    transToMailslot('\\MAILSLOT\\BROWSE', [0x0a, 0x02, ...le32(7), ...ascii('DESKTOP'), 0, ...ascii('SERVER2'), 0])) },
  { label: 'become backup browser', frame: toBrowse([0x0b, 0x00, ...ascii('LAPTOP1'), 0]) },
  { label: 'a master announcement', frame: toBrowse([0x0d, 0x00, ...ascii('DESKTOP'), 0]) },
  ...[1, 2, 4, 7].map((reset) => ({ label: `reset browser state ${reset}`, frame: toBrowse([0x0e, reset]) })),
  { label: 'every server type bit', frame: toBrowse(announcement(0x01, 'X', 10, 0, 0xffffffff, '', 60000)) },
  { label: 'no server type bit', frame: toBrowse(announcement(0x01, 'X', 10, 0, 0, '', 0)) },
  ...[[4, 0], [5, 0], [5, 1], [5, 2], [6, 0], [6, 1], [6, 2], [10, 0]].map(([major, minor]) => ({
    label: `Windows ${major}.${minor}`, frame: toBrowse(announcement(0x01, 'X', major, minor, 1, 'c', 86400000)),
  })),
  // The SMB header and the Trans request around them.
  { label: 'every SMB flag but the response bit', frame: toBrowse([0x02, 0x00, ...ascii('PC'), 0], { flags: 0x7f, flags2: 0x7fff }) },
  { label: 'a Unicode transaction name', frame: toBrowse([0x02, 0x00, ...ascii('PC'), 0], { flags2: 0x8000 }) },
  { label: 'an NT status', frame: toBrowse([0x02, 0x00, ...ascii('PC'), 0], { flags2: 0x4000, status: 0xc0000022 }) },
  { label: 'an unnamed NT status', frame: toBrowse([0x02, 0x00, ...ascii('PC'), 0], { flags2: 0x4000, status: 0x12345678 }) },
  ...[[1000, 1, 1], [0xffffffff, 2, 3], [1500, 3, 2], [0xfffffffe, 0, 2]].map(([timeout, transFlags, mailslotClass]) => ({
    label: `timeout ${timeout}, flags ${transFlags}, class ${mailslotClass}`,
    frame: toBrowse([0x02, 0x00, ...ascii('PC'), 0], { timeout, transFlags, mailslotClass }),
  })),
  // The datagram's own flags and the names' roles.
  ...[0x00, 0x01, 0x03, 0x04, 0x08, 0x0e].map((flags) => ({
    label: `datagram flags ${flags}`, frame: datagram(0x10, flags, ['A', 0x00], ['B', 0x20], transToMailslot('\\MAILSLOT\\BROWSE', [0x0d, 0, 0])),
  })),
  ...[0x03, 0x1b, 0x1c, 0x1f, 0x21, 0xbf, 0x77].map((suffix) => ({
    label: `a name with suffix ${suffix}`, frame: datagram(0x11, 0x02, ['A', 0x00], ['B', suffix], transToMailslot('\\MAILSLOT\\BROWSE', [0x0d, 0, 0])),
  })),
  { label: 'a datagram error', frame: udpFrameTo(HOST, BROADCAST, 138, 138, Uint8Array.from([0x13, 0x02, 0, 1, 192, 168, 1, 20, 0, 138, 0x82])) },
  { label: 'a datagram query', frame: udpFrameTo(HOST, BROADCAST, 138, 138, Uint8Array.from([0x14, 0x02, 0, 1, 192, 168, 1, 20, 0, 138, ...netbiosName('B', 0x20)])) },
];

const packets = await compareWithReference(cases, { rows: /^(nbdgm|smb|mailslot|browser)\./ });
await checkRevisit(cases);
check('a host announcement is the `browser` layer over `mailslot` and `smb`',
  packets[0]?.frameProtocols?.slice(-4).join(':') === 'nbdgm:smb:mailslot:browser', packets[0]?.frameProtocols?.join(':'));
check('the announcing host is a field', packets[0]?.fields?.['browser.server'] === 'LAPTOP1');
finish('browser');
