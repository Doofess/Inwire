/**
 * Writes `src/services/dissectors/cflowNames.ts` - NetFlow v9 and IPFIX
 * information elements as the reference names and draws them.
 *
 *   npx tsx scripts/parity/gen-cflow-tables.ts
 *
 * The reference knows some 480 standard IPFIX elements, each drawn by a field
 * of its own (`cflow.octets`, `cflow.post_natsource_ipv4_address`), and which
 * field an element number reaches is a `switch` in its C source that no table
 * it prints says. So this asks it: one message per element, a template naming
 * just that element and a record holding it, read back as PDML. The field a
 * record's one row carries is that element's abbrev; `tshark -G fields` gives
 * its label and type, and `-G values` its value names.
 *
 * An element whose row is not one plain field - TCP flags with a bit tree, the
 * forwarding status, a start/end time pair - is still listed, with the abbrev
 * of its first row, and `dissectors/cflow.ts` draws it by hand.
 *
 * The enterprise names (`PEN: ciscoSystems (9)`) are asked the same way, for a
 * list of the vendors whose exporters are common; the reference carries all of
 * IANA's 60,000 and this build does not.
 *
 * A generator, not a test: it writes a source file and never exits with a
 * status, which is how `check.ts` knows not to run it. Rerun it after a
 * Wireshark upgrade.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { findWiresharkTool } from '../export/realCaptures';
import { pcapOf, udpFrameTo } from './synthetic';

const tshark = findWiresharkTool('tshark');
if (tshark === null) throw new Error('tshark not found');
const run = (args: string[]) => spawnSync(tshark, args, { encoding: 'utf8', maxBuffer: 1 << 29 }).stdout;

const values = run(['-G', 'values']).split(/\r?\n/).map((l) => l.split('\t'));
const fields = new Map<string, string[]>();
for (const l of run(['-G', 'fields']).split(/\r?\n/)) {
  const c = l.split('\t');
  if (c[0] === 'F' && c[4] === 'cflow') fields.set(c[2], c);
}
const valueTable = (abbrev: string) => {
  const out = new Map<number, string>();
  for (const c of values) if (c[0] === 'V' && c[1] === abbrev && !out.has(Number(c[2]))) out.set(Number(c[2]), c[3].trim());
  return out;
};

const u16 = (n: number) => [(n >> 8) & 255, n & 255];
const u32 = (n: number) => [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
/** One IPFIX message: a template set naming `elements`, and one record of `data`. */
function message(domain: number, elements: number[][], data: number[]): Uint8Array {
  const template = [...u16(256), ...u16(elements.length), ...elements.flat()];
  const sets = [...u16(2), ...u16(4 + template.length), ...template, ...u16(256), ...u16(4 + data.length), ...data];
  return udpFrameTo('192.0.2.1', '192.0.2.9', 50000, 4739,
    Uint8Array.from([...u16(10), ...u16(16 + sets.length), ...u32(1700000000), ...u32(0), ...u32(domain), ...sets]));
}

interface Row { abbrev: string; showname: string; depth: number }
/** The rows of each message's one record, by message. */
function recordRows(frames: Uint8Array[]): Row[][] {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-cflow-gen-'));
  try {
    const file = join(dir, 'probe.pcap');
    writeFileSync(file, pcapOf(frames));
    return run(['-n', '-r', file, '-T', 'pdml']).split('<packet>').slice(1).map((packet) => {
      const lines = packet.split(/\r?\n/);
      const at = lines.findIndex((l) => l.includes('show="Flow 1"'));
      if (at < 0) return [];
      const base = lines[at].match(/^\s*/)![0].length;
      const rows: Row[] = [];
      for (const line of lines.slice(at + 1)) {
        const depth = line.match(/^\s*/)![0].length;
        if (depth <= base) break;
        const m = line.match(/<field (.*?)\/?>$/);
        if (m === null) continue;
        const a = Object.fromEntries([...m[1].matchAll(/([a-z_]+)="([^"]*)"/g)].map((x) => [x[1], x[2]]));
        if (a.hide === 'yes') continue;
        rows.push({ abbrev: a.name ?? '', showname: a.showname ?? '', depth: depth - base });
      }
      return rows;
    });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// --- the elements -------------------------------------------------------------

const TYPE_NAMES = valueTable('cflow.template_field_type');
const standard = [...TYPE_NAMES.keys()].filter((id) => id < 0x8000);
/** Each element at a length its type takes, until the reference reads it. */
const LENGTHS = [4, 6, 16, 8, 3, 2, 1];
const found = new Map<number, Row[]>();
for (const length of LENGTHS) {
  const pending = standard.filter((id) => !found.has(id));
  const rows = recordRows(pending.map((id, i) => message(i + 1, [[...u16(id), ...u16(length)]],
    Array.from({ length }, (_, k) => 0x41 + k))));
  pending.forEach((id, i) => {
    const r = rows[i] ?? [];
    const named = r.find((row) => row.abbrev.startsWith('cflow.') && row.depth <= 2 && fields.has(row.abbrev));
    if (named !== undefined && !r.some((row) => row.abbrev === '_ws.type_length.mismatch' || row.abbrev === 'cflow.mpls_label.bad_length')) found.set(id, r);
  });
}

/** How a plain field's value is written, from its type and base. */
function kindOf(abbrev: string): string | null {
  const f = fields.get(abbrev);
  if (f === undefined) return null;
  const [type, base] = [f[3], f[5]];
  const width = ({ FT_UINT8: 1, FT_UINT16: 2, FT_UINT24: 3, FT_UINT32: 4, FT_UINT64: 8 } as Record<string, number>)[type];
  if (abbrev === 'cflow.protocol') return 'p';
  if (width !== undefined) {
    if (valueTable(abbrev).size > 0) return `e${width}`;
    if (base === 'BASE_HEX') return `x${width}`;
    if (base === 'BASE_HEX_DEC') return `X${width}`;
    if (base === 'BASE_OCT') return `o${width}`;
    return `u${width}`;
  }
  switch (type) {
    case 'FT_INT32': return 'i4';
    case 'FT_IPv4': return 'a4';
    case 'FT_IPv6': return 'a6';
    case 'FT_ETHER': return 'm';
    case 'FT_BYTES': return 'b';
    case 'FT_STRING': return 's';
    case 'FT_BOOLEAN': return 'B';
    case 'FT_FLOAT': return 'f';
    case 'FT_DOUBLE': return 'F';
    case 'FT_ABSOLUTE_TIME': return 't';
    case 'FT_RELATIVE_TIME': return 'r';
    default: return null;
  }
}

/** An absolute time's unit, from the element's name - RFC 7011's naming. */
function timeUnit(name: string): string {
  if (/Delta/i.test(name)) return 'd';
  if (/Nanoseconds$/i.test(name)) return 'n';
  if (/Microseconds$/i.test(name)) return 'u';
  if (/Milliseconds$/i.test(name)) return 'm';
  return 's';
}

const elements: string[] = [];
const enums = new Set<string>();
for (const id of standard) {
  const rows = found.get(id);
  if (rows === undefined) continue;
  const first = rows.find((row) => row.abbrev.startsWith('cflow.') && fields.has(row.abbrev))!;
  // A standard element the reference has no field for is drawn as an
  // enterprise entry with no enterprise (basicList, subTemplateMultiList), and
  // `cflow.ts` draws it that way for any number this table leaves out.
  if (first.abbrev === 'cflow.enterprise_private_entry') continue;
  // One row and nothing under it: a plain field. Anything else is drawn by hand.
  const plain = rows.length === 1 || (rows.length === 2 && rows[1].abbrev.startsWith('cflow.string_len_'));
  let kind = plain ? kindOf(first.abbrev) : null;
  if (kind === 't') kind = `t${timeUnit(TYPE_NAMES.get(id) ?? '')}`;
  if (kind === 'r') kind = `r${timeUnit(TYPE_NAMES.get(id) ?? '') === 'u' ? 'u' : 'm'}`;
  // Two fields can share an abbrev and not a format: the TCP and UDP port
  // elements are `cflow.srcport` drawn as a port, `38563 (38563)` with names
  // off - the port being the element's first two bytes - where the v9 one is
  // a plain number. The record's own row says which.
  if (kind?.startsWith('u') && /: \d+ \(\d+\)$/.test(first.showname)) kind = `P${kind.slice(1)}`;
  if (kind?.startsWith('e')) enums.add(first.abbrev);
  const label = fields.get(first.abbrev)![1];
  // An element drawn by hand keeps no abbrev here: `cflow.ts` names its rows
  // itself, and one it does not draw is shown by name with its bytes.
  elements.push(`  ${id}: ['${kind === null ? '' : first.abbrev}', ${JSON.stringify(kind === null ? TYPE_NAMES.get(id) ?? label : label)}, '${kind ?? '-'}'],`);
}

// --- the enterprises ----------------------------------------------------------

/** Vendors whose exporters are common, asked of the reference by number. */
const PENS = [
  9, 11, 674, 1916, 1991, 2011, 2620, 2636, 3076, 3375, 4413, 5624, 5951, 6486, 6876, 8072, 8741,
  10704, 12356, 13745, 14988, 25461, 26866, 29305, 30065, 35632, 39885, 43874,
];
const penNames: string[] = [];
const dir = mkdtempSync(join(tmpdir(), 'inwire-cflow-pen-'));
try {
  // The name is on the template row, which `recordRows` does not read.
  const file = join(dir, 'pens.pcap');
  writeFileSync(file, pcapOf(PENS.map((pen, i) => message(i + 1, [[...u16(0x8000 | 1), ...u16(4), ...u32(pen)]], [0, 0, 0, 1]))));
  const pdml = run(['-n', '-r', file, '-T', 'pdml']).split('<packet>').slice(1);
  PENS.forEach((pen, i) => {
    const m = pdml[i]?.match(/name="cflow\.template_ipfix_field_pen" showname="PEN: (.*?) \(\d+\)"/);
    if (m !== null && m !== undefined) penNames.push(`  ${pen}: ${JSON.stringify(m[1].replace(/&#x27;/g, "'").replace(/&quot;/g, '"').replace(/&amp;/g, "&"))},`);
  });
} finally {
  rmSync(dir, { recursive: true, force: true });
}

// --- the file ------------------------------------------------------------------

const table = (name: string, map: Map<number, string>, comment: string) =>
  `\n/** ${comment} */\nexport const ${name}: Readonly<Record<number, string>> = {\n${[...map]
    .map(([v, n]) => `  ${v}: ${JSON.stringify(n)},`).join('\n')}\n};\n`;

let out = `/**
 * NetFlow v9 and IPFIX names as the reference writes them. GENERATED by
 * \`scripts/parity/gen-cflow-tables.ts\` from \`tshark -G fields\`, \`-G values\`
 * and the reference's own reading of a record per element - edit that, not this.
 */

/**
 * A standard element: the reference's field, its label, and how its value is
 * written - \`u\`/\`x\`/\`X\`/\`o\`/\`e\` an unsigned number (decimal, hex, hex and
 * decimal, octal, named) of the field's width in bytes, \`p\` an IP protocol,
 * \`i4\` signed, \`a4\`/\`a6\` an address, \`m\` a MAC, \`b\` bytes, \`s\` text, \`B\` a
 * boolean, \`f\`/\`F\` a float, \`t\` an absolute time and \`r\` a duration with
 * their unit (\`s\`, \`m\`, \`u\`, \`n\`, or \`d\` microseconds before the export), and \`-\` drawn by hand, or by name and bytes.
 */
export type CflowElement = readonly [abbrev: string, label: string, kind: string];

export const ELEMENTS: Readonly<Record<number, CflowElement>> = {
${elements.join('\n')}
};
`;
out += table('TYPE_NAMES', TYPE_NAMES, 'Every element number the reference names, v9 vendor numbers included: `Type: IP_SRC_ADDR (8)`.');
out += table('CISCO_TYPE_NAMES', valueTable('cflow.template_cisco_field_type'), 'Cisco\'s enterprise elements (PEN 9).');
out += `\n/** Enterprise numbers, for the vendors listed in the generator. */\nexport const PEN_NAMES: Readonly<Record<number, string>> = {\n${penNames.join('\n')}\n};\n`;
out += `\n/** The value names of every named element, by its field. */\nexport const ELEMENT_VALUES: Readonly<Record<string, Readonly<Record<number, string>>>> = {\n${[...enums].sort()
  .map((abbrev) => `  '${abbrev}': {${[...valueTable(abbrev)].map(([v, n]) => ` ${v}: ${JSON.stringify(n)}`).join(',')} },`).join('\n')}\n};\n`;
for (const [name, abbrev] of [
  ['ENGINE_TYPES', 'cflow.engine_type'], ['SAMPLING_MODES', 'cflow.samplingmode'], ['SCOPE_TYPES', 'cflow.scope_field_type'],
  ['FORWARDING_STATUS', 'cflow.forwarding_status'], ['FORWARD_CODES', 'cflow.forwarding_status_forward_code'],
  ['DROP_CODES', 'cflow.forwarding_status_drop_code'], ['CONSUME_CODES', 'cflow.forwarding_status_consume_code'],
  ['CLASSIFICATION_ENGINES', 'cflow.appl_id.classification_engine_id'],
] as const) out += table(name, valueTable(abbrev), `\`${abbrev}\`.`);
writeFileSync('src/services/dissectors/cflowNames.ts', out);
console.log(`wrote ${elements.length} elements, ${penNames.length} enterprises, ${enums.size} value tables`);
