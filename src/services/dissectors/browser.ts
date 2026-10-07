/**
 * The SMB mailslot and the Windows browser protocol inside it (MS-BRWS) - the
 * announcements every Windows machine on a LAN broadcasts on UDP 138.
 *
 *   Host Announcement LAPTOP1, Workstation, Server, NT Workstation, Potential Browser
 *   Domain/Workgroup Announcement WORKGROUP, NT Workstation, Domain Enum
 *   Browser Election Request
 *
 * What a laptop says about itself to everybody on its network: its name, the
 * comment its owner gave it, the Windows version it runs, and every role it
 * plays (server, print queue, master browser). Carried as an SMB Transaction
 * written to `\MAILSLOT\BROWSE`, inside a NetBIOS datagram - `dissectors/smb.ts`
 * reads the transaction and hands the data here.
 *
 * Every name and every true/false sentence is the reference's own, read from
 * tshark one flag at a time, including its typo (`THis is NOT a DFS server`)
 * and the Info column's longer spelling of a server type than the tree's
 * (`Apple Server` where the tree says `Apple`).
 */
import type { ProtocolField, ProtocolLayer } from '../../types/packet';

/** The mailslot the browser protocol is written to. */
export const BROWSE_MAILSLOT = '\\MAILSLOT\\BROWSE';

const hex = (n: number, digits: number) => `0x${n.toString(16).padStart(digits, '0')}`;
const le32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const le16 = (b: Uint8Array, at: number) => b[at] | (b[at + 1] << 8);
const LATIN1 = new TextDecoder('latin1');

/** A NUL-terminated string, or the rest of `limit` when there is no NUL. */
function cString(b: Uint8Array, at: number, limit: number): { text: string; after: number } {
  let p = at;
  while (p < limit && b[p] !== 0) p++;
  return { text: LATIN1.decode(b.subarray(at, p)), after: Math.min(limit, p + 1) };
}

/**
 * `time_msecs_to_str`: "1 day, 1 hour, 1 minute, 1 second", zero parts left
 * out, and a part second as "1.500 seconds".
 */
export function msecsText(total: number): string {
  const ms = total % 1000;
  let seconds = Math.floor(total / 1000);
  const parts: string[] = [];
  const add = (n: number, unit: string) => { if (n > 0) parts.push(`${n} ${unit}${n === 1 ? '' : 's'}`); };
  add(Math.floor(seconds / 86400), 'day');
  add(Math.floor((seconds % 86400) / 3600), 'hour');
  add(Math.floor((seconds % 3600) / 60), 'minute');
  seconds %= 60;
  if (ms !== 0) parts.push(`${seconds}.${String(ms).padStart(3, '0')} seconds`);
  else if (seconds !== 0 || parts.length === 0) parts.push(`${seconds} second${seconds === 1 ? '' : 's'}`);
  return parts.join(', ');
}

// --- the mailslot ------------------------------------------------------------

const MAILSLOT_OPCODES: Record<number, string> = { 1: 'Write Mail Slot' };
const MAILSLOT_CLASSES: Record<number, string> = { 1: 'Reliable', 2: 'Unreliable & Broadcast' };

/**
 * The mailslot layer: the transaction's three setup words and its name.
 * `size` is the transaction's byte count, which is what the reference shows.
 */
export function mailslotLayer(b: Uint8Array, setupAt: number, size: number, sizeAt: number, name: string,
  nameRange: [number, number]): ProtocolLayer {
  const opcode = le16(b, setupAt);
  const cls = le16(b, setupAt + 4);
  return {
    name: 'SMB MailSlot Protocol',
    summary: 'SMB MailSlot Protocol',
    rawBytesRange: [setupAt, nameRange[1]],
    fields: [
      { name: 'Opcode', value: `${MAILSLOT_OPCODES[opcode] ?? 'Unknown'} (${opcode})`, abbrev: 'mailslot.opcode', rawBytesRange: [setupAt, setupAt + 1] },
      { name: 'Priority', value: le16(b, setupAt + 2), abbrev: 'mailslot.priority', rawBytesRange: [setupAt + 2, setupAt + 3] },
      { name: 'Class', value: `${MAILSLOT_CLASSES[cls] ?? 'Unknown'} (${cls})`, abbrev: 'mailslot.class', rawBytesRange: [setupAt + 4, setupAt + 5] },
      { name: 'Size', value: size, abbrev: 'mailslot.size', rawBytesRange: [sizeAt, sizeAt + 1] },
      { name: 'Mailslot Name', value: name, abbrev: 'mailslot.name', rawBytesRange: nameRange },
    ],
  };
}

// --- the browser protocol ----------------------------------------------------

const COMMANDS: Record<number, string> = {
  0x01: 'Host Announcement', 0x02: 'Request Announcement', 0x08: 'Browser Election Request',
  0x09: 'Get Backup List Request', 0x0a: 'Get Backup List Response', 0x0b: 'Become Backup Browser',
  0x0c: 'Domain/Workgroup Announcement', 0x0d: 'Master Announcement', 0x0e: 'Reset Browser State Announcement',
  0x0f: 'Local Master Announcement',
};

/** One bit of a flag word: mask, field, the tree's short name, and its two sentences. */
export type Bit = [mask: number, abbrev: string, name: string, set: string, clear: string];

/** "This is a Workstation" / "This is NOT a Workstation", the reference's pattern. */
const isA = (mask: number, abbrev: string, name: string, what: string): Bit => {
  // By sound, not spelling: `an SQL server`, `an NT Server`.
  const article = /^([aeiou]|SQL|NT )/i.test(what) ? 'an' : 'a';
  return [mask, abbrev, name, `This is ${article} ${what}`, `This is NOT ${article} ${what}`];
};
const SERVER_TYPE_BITS: Bit[] = [
  isA(0x00000001, 'browser.server_type.workstation', 'Workstation', 'Workstation'),
  isA(0x00000002, 'browser.server_type.server', 'Server', 'Server'),
  isA(0x00000004, 'browser.server_type.sql', 'SQL', 'SQL server'),
  isA(0x00000008, 'browser.server_type.domain_controller', 'Domain Controller', 'Domain Controller'),
  isA(0x00000010, 'browser.server_type.backup_controller', 'Backup Controller', 'Backup Controller'),
  isA(0x00000020, 'browser.server_type.time', 'Time Source', 'Time Source'),
  isA(0x00000040, 'browser.server_type.apple', 'Apple', 'Apple host'),
  isA(0x00000080, 'browser.server_type.novell', 'Novell', 'Novell server'),
  isA(0x00000100, 'browser.server_type.member', 'Member', 'Domain Member server'),
  isA(0x00000200, 'browser.server_type.print', 'Print', 'Print Queue server'),
  isA(0x00000400, 'browser.server_type.dialin', 'Dialin', 'Dialin server'),
  isA(0x00000800, 'browser.server_type.xenix', 'Xenix', 'Xenix server'),
  isA(0x00001000, 'browser.server_type.ntw', 'NT Workstation', 'NT Workstation'),
  isA(0x00002000, 'browser.server_type.wfw', 'WfW', 'WfW host'),
  isA(0x00008000, 'browser.server_type.nts', 'NT Server', 'NT Server'),
  isA(0x00010000, 'browser.server_type.browser.potential', 'Potential Browser', 'Potential Browser'),
  isA(0x00020000, 'browser.server_type.browser.backup', 'Backup Browser', 'Backup Browser'),
  isA(0x00040000, 'browser.server_type.browser.master', 'Master Browser', 'Master Browser'),
  isA(0x00080000, 'browser.server_type.browser.domain_master', 'Domain Master Browser', 'Domain Master Browser'),
  isA(0x00100000, 'browser.server_type.osf', 'OSF', 'OSF host'),
  isA(0x00200000, 'browser.server_type.vms', 'VMS', 'VMS host'),
  isA(0x00400000, 'browser.server_type.w95', 'Windows 95+', 'Windows 95 or above host'),
  // The reference's own capital H.
  [0x00800000, 'browser.server_type.dfs', 'DFS', 'This is a DFS server', 'THis is NOT a DFS server'],
  [0x40000000, 'browser.server_type.local', 'Local', 'This is a local list only request', 'This is NOT a local list only request'],
  [0x80000000, 'browser.server_type.domainenum', 'Domain Enum', 'This is a Domain Enum request', 'This is NOT a Domain Enum request'],
];

/** The Info column's names for the same bits, by bit number - longer than the tree's, and every bit has one. */
const SERVER_TYPE_INFO: Record<number, string> = {
  0: 'Workstation', 1: 'Server', 2: 'SQL Server', 3: 'Domain Controller', 4: 'Backup Controller', 5: 'Time Source',
  6: 'Apple Server', 7: 'Novell Server', 8: 'Domain Member Server', 9: 'Print Queue Server', 10: 'Dialin Server',
  11: 'Xenix Server', 12: 'NT Workstation', 13: 'Windows for Workgroups', 15: 'NT Server', 16: 'Potential Browser',
  17: 'Backup Browser', 18: 'Master Browser', 19: 'Domain Master Browser', 20: 'OSF', 21: 'VMS',
  22: 'Windows 95 or above', 23: 'DFS server', 30: 'Local List Only', 31: 'Domain Enum',
};
function serverTypeInfo(type: number): string {
  let out = '';
  for (let bit = 0; bit < 32; bit++) {
    if ((type & (2 ** bit)) !== 0) out += `, ${SERVER_TYPE_INFO[bit] ?? `Unknown server type:${bit}`}`;
  }
  return out;
}

const DESIRE_BITS: Bit[] = [
  [0x01, 'browser.election.desire.backup', 'Backup', 'Backup Browse Server', 'NOT Backup Browse Server'],
  [0x02, 'browser.election.desire.standby', 'Standby', 'Standby Browse Server', 'NOT Standby Browse Server'],
  [0x04, 'browser.election.desire.master', 'Master', 'Master Browser', 'NOT Master Browser'],
  [0x08, 'browser.election.desire.domain_master', 'Domain Master', 'Domain Master Browse Server', 'NOT Domain Master Browse Server'],
  [0x20, 'browser.election.desire.wins', 'WINS', 'WINS Client', 'NOT WINS Client'],
  [0x80, 'browser.election.desire.nt', 'NT', 'Windows NT Advanced Server', 'NOT Windows NT Advanced Server'],
];
const OS_BITS: Bit[] = [
  [0x01, 'browser.election.os.wfw', 'WfW', 'Windows for Workgroups', 'Not Windows for Workgroups'],
  [0x10, 'browser.election.os.ntw', 'NT Workstation', 'Windows NT Workstation', 'Not Windows NT Workstation'],
  [0x20, 'browser.election.os.nts', 'NT Server', 'Windows NT Server', 'Not Windows NT Server'],
];
const RESET_BITS: Bit[] = [
  [0x01, 'browser.reset_cmd.demote', 'Demote LMB', 'Demote an LMB to a Backup Browser', 'Do not demote an LMB to a Backup Browser'],
  [0x02, 'browser.reset_cmd.flush', 'Flush Browse List', 'Flush the Browse List', 'Do not Flush the Browse List'],
  [0x04, 'browser.reset_cmd.stop_lmb', 'Stop Being LMB', 'Stop Being a Local Master Browser', 'Do not Stop Being a Local Master Browser'],
];
const RESET_COMMANDS: Record<number, string> = {
  1: 'Stop being a master browser and become a backup browser',
  2: 'Discard browse lists, stop being a master browser, and try again',
  4: 'Stop being a master browser for ever',
};

/** Only the versions the reference names; any other leaves the row empty. */
const WINDOWS_VERSIONS: Record<string, string> = {
  '5.0': 'Windows 2000', '5.1': 'Windows XP', '5.2': 'Windows Server 2003 R2 or Windows Server 2003',
  '6.0': 'Windows Vista or Windows Server 2008', '6.1': 'Windows 7 or Windows Server 2008 R2',
};

/** A flag word as a heading, `0x… , Set, Names`, over one row per bit. Little-endian when wider than a byte. */
export function flagsRow(name: string, abbrev: string, word: number, bytes: number, at: number, bits: Bit[], heading = ''): ProtocolField {
  const totalBits = bytes * 8;
  const set = bits.filter(([mask]) => (word & mask) !== 0).map(([, , n]) => `, ${n}`).join('');
  return {
    name, value: `${heading === '' ? hex(word, bytes * 2) : heading}${set}`, abbrev, rawBytesRange: [at, at + bytes - 1],
    children: bits.map(([mask, bitAbbrev, bitName, yes, no]): ProtocolField => ({
      name: bitName, value: (word & mask) !== 0 ? yes : no, abbrev: bitAbbrev, rawBytesRange: [at, at + bytes - 1],
      bitfield: { bitOffset: totalBits - 1 - Math.log2(mask), bitLength: 1, totalBits },
    })),
  };
}

export interface BrowserResult {
  info: string;
  layer: ProtocolLayer;
  fields: Record<string, string | number>;
}

/** MS-BRWS 2.2: one browser message, the whole of a mailslot write. */
export function dissectBrowser(b: Uint8Array, start: number, end: number): BrowserResult | null {
  if (start >= end) return null;
  const command = b[start];
  const commandName = COMMANDS[command];
  if (commandName === undefined) return null;
  const rows: ProtocolField[] = [
    { name: 'Command', value: `${commandName} (${hex(command, 2)})`, abbrev: 'browser.command', rawBytesRange: [start, start] },
  ];
  const fields: Record<string, string | number> = { 'browser.command': command };
  let info = commandName;
  let p = start + 1;
  const need = (n: number) => p + n <= end;

  if (command === 0x01 || command === 0x0c || command === 0x0f) {
    // HostAnnouncement, DomainAnnouncement, LocalMasterAnnouncement: one layout.
    if (!need(27)) return null;
    const period = le32(b, p + 1);
    const server = cString(b, p + 5, p + 21).text;
    const major = b[p + 21];
    const minor = b[p + 22];
    const type = le32(b, p + 23);
    rows.push(
      { name: 'Update Count', value: b[p], abbrev: 'browser.update_count', rawBytesRange: [p, p] },
      { name: 'Update Periodicity', value: msecsText(period), abbrev: 'browser.period', rawBytesRange: [p + 1, p + 4] },
      { name: command === 0x0c ? 'Domain/Workgroup' : 'Host Name', value: server, abbrev: 'browser.server', rawBytesRange: [p + 5, p + 20] },
      { name: 'Windows version', value: WINDOWS_VERSIONS[`${major}.${minor}`] ?? '', abbrev: 'browser.windows_version', rawBytesRange: [p + 21, p + 22] },
      { name: 'OS Major Version', value: major, abbrev: 'browser.os_major', rawBytesRange: [p + 21, p + 21] },
      { name: 'OS Minor Version', value: minor, abbrev: 'browser.os_minor', rawBytesRange: [p + 22, p + 22] },
      flagsRow('Server Type', 'browser.server_type', type, 4, p + 23, SERVER_TYPE_BITS),
    );
    fields['browser.server'] = server;
    fields['browser.server_type'] = type;
    info = `${commandName} ${server}${serverTypeInfo(type)}`;
    p += 27;
    if (need(4)) {
      rows.push(
        { name: 'Browser Protocol Major Version', value: b[p], abbrev: 'browser.proto_major', rawBytesRange: [p, p] },
        { name: 'Browser Protocol Minor Version', value: b[p + 1], abbrev: 'browser.proto_minor', rawBytesRange: [p + 1, p + 1] },
        { name: 'Signature', value: hex(le16(b, p + 2), 4), abbrev: 'browser.sig', rawBytesRange: [p + 2, p + 3] },
      );
      p += 4;
      const comment = cString(b, p, end);
      // A domain announcement's comment is the master browser's name.
      if (command === 0x0c) {
        rows.push({ name: 'Master Browser Server Name', value: comment.text, abbrev: 'browser.mb_server', rawBytesRange: [p, comment.after - 1] });
      } else {
        rows.push({ name: 'Host Comment', value: comment.text, abbrev: 'browser.comment', rawBytesRange: [p, Math.max(p, comment.after - 1)] });
        fields['browser.comment'] = comment.text;
      }
    }
  } else if (command === 0x02) {
    if (!need(1)) return null;
    const name = cString(b, p + 1, end);
    rows.push(
      { name: 'Unused flags', value: hex(b[p], 2), abbrev: 'browser.unused', rawBytesRange: [p, p] },
      { name: 'Response Computer Name', value: name.text, abbrev: 'browser.response_computer_name', rawBytesRange: [p + 1, Math.max(p + 1, name.after - 1)] },
    );
    info = `${commandName} ${name.text}`;
  } else if (command === 0x08) {
    // RequestElection: the criteria word is desire, version and OS, low byte first.
    if (!need(13)) return null;
    const criteria = le32(b, p + 1);
    const uptime = le32(b, p + 5);
    const at = p + 1;
    rows.push(
      { name: 'Election Version', value: b[p], abbrev: 'browser.election.version', rawBytesRange: [p, p] },
      {
        name: 'Election Criteria', value: hex(criteria, 8), abbrev: 'browser.election.criteria', rawBytesRange: [at, at + 3],
        children: [
          flagsRow('Election Desire', 'browser.election.desire', b[at], 1, at, DESIRE_BITS),
          { name: 'Browser Protocol Major Version', value: b[at + 1], abbrev: 'browser.proto_major', rawBytesRange: [at + 1, at + 1] },
          { name: 'Browser Protocol Minor Version', value: b[at + 2], abbrev: 'browser.proto_minor', rawBytesRange: [at + 2, at + 2] },
          flagsRow('Election OS', 'browser.election.os', b[at + 3], 1, at + 3, OS_BITS),
        ],
      },
      { name: 'Uptime', value: msecsText(uptime), abbrev: 'browser.uptime', rawBytesRange: [p + 5, p + 8] },
    );
    // Four reserved bytes the reference does not draw, then the sender's name.
    const name = cString(b, p + 13, end);
    rows.push({ name: 'Server Name', value: name.text, abbrev: 'browser.server', rawBytesRange: [p + 13, Math.max(p + 13, name.after - 1)] });
    fields['browser.server'] = name.text;
  } else if (command === 0x09 || command === 0x0a) {
    if (!need(5)) return null;
    const count = b[p];
    rows.push(
      { name: 'Backup List Requested Count', value: count, abbrev: 'browser.backup.count', rawBytesRange: [p, p] },
      { name: 'Backup Request Token', value: le32(b, p + 1), abbrev: 'browser.backup.token', rawBytesRange: [p + 1, p + 4] },
    );
    p += 5;
    if (command === 0x0a) {
      for (let i = 0; i < count && p < end; i++) {
        const server = cString(b, p, end);
        rows.push({ name: 'Backup Server', value: server.text, abbrev: 'browser.backup.server', rawBytesRange: [p, Math.max(p, server.after - 1)] });
        p = server.after;
      }
    }
  } else if (command === 0x0b || command === 0x0d) {
    const name = cString(b, p, end);
    rows.push(command === 0x0b
      ? { name: 'Browser to Promote', value: name.text, abbrev: 'browser.browser_to_promote', rawBytesRange: [p, Math.max(p, name.after - 1)] }
      : { name: 'Master Browser Server Name', value: name.text, abbrev: 'browser.mb_server', rawBytesRange: [p, Math.max(p, name.after - 1)] });
  } else if (command === 0x0e) {
    if (!need(1)) return null;
    const reset = b[p];
    rows.push(flagsRow('ResetBrowserState Command', 'browser.reset_cmd', reset, 1, p, RESET_BITS,
      `${RESET_COMMANDS[reset] ?? 'Unknown'} (${hex(reset, 2)})`));
  }

  return {
    info,
    fields,
    layer: {
      name: 'Microsoft Windows Browser Protocol',
      summary: 'Microsoft Windows Browser Protocol',
      rawBytesRange: [start, Math.max(start, end - 1)],
      fields: rows,
    },
  };
}
