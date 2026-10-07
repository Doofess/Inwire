/**
 * Writes `src/services/dissectors/dcerpcNames.ts` from the reference's own
 * reading of DCE/RPC.
 *
 *   npx tsx scripts/parity/gen-dcerpc-tables.ts
 *
 * The reference names an RPC interface by its UUID - `EPMv4`, `SRVSVC`,
 * `DRSUAPI` - and each call by its operation number, and neither is in a
 * table it exports whole: the operation names are (`tshark -G values`, one
 * `<filter>.opnum` per interface), the interface names are not. So the
 * candidate UUIDs below are put to tshark in a Bind, one each, and an
 * interface is kept only when the reference names it: a UUID mistyped here
 * comes back as itself and is dropped, never shipped as a guess. The Protocol
 * column for each comes from a Request to it.
 *
 * A generator, not a test: it writes a source file and never exits with a
 * status, which is how `check.ts` knows not to run it. Rerun it after a Wireshark
 * upgrade.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { findWiresharkTool } from '../export/realCaptures';
import { ethernet, ipv4, pcapOf, tcp } from './synthetic';

const tshark = findWiresharkTool('tshark');
if (tshark === null) throw new Error('tshark not found');

/** [uuid, major version, the reference's filter name for its operations]. */
const CANDIDATES: [string, number, string][] = [
  ['e1af8308-5d1f-11c9-91a4-08002b14a0fa', 3, 'epm'],
  ['4b324fc8-1670-01d3-1278-5a47bf6ee188', 3, 'srvsvc'],
  ['6bffd098-a112-3610-9833-46c3f87e345a', 1, 'wkssvc'],
  ['12345778-1234-abcd-ef00-0123456789ab', 0, 'lsarpc'],
  ['12345778-1234-abcd-ef00-0123456789ac', 1, 'samr'],
  ['12345678-1234-abcd-ef00-01234567cffb', 1, 'netlogon'],
  ['338cd001-2244-31f1-aaaa-900038001003', 1, 'winreg'],
  ['367abb81-9844-35f1-ad32-98f038001003', 2, 'svcctl'],
  ['12345678-1234-abcd-ef00-0123456789ab', 1, 'spoolss'],
  ['e3514235-4b06-11d1-ab04-00c04fc2dcd2', 4, 'drsuapi'],
  ['3919286a-b10c-11d0-9ba8-00c04fd92ef5', 0, 'dssetup'],
  ['1ff70682-0a51-30e8-076d-740be8cee98b', 1, 'atsvc'],
  ['afa8bd80-7d8a-11c9-bef4-08002b102989', 1, 'mgmt'],
  ['99fcfec4-5260-101b-bbcb-00aa0021347a', 0, 'oxid'],
  ['000001a0-0000-0000-c000-000000000046', 0, 'isystemactivator'],
  ['00000131-0000-0000-c000-000000000046', 0, 'remunk'],
  ['00000143-0000-0000-c000-000000000046', 0, 'remunk'],
  ['86d35949-83c9-4044-b424-db363231fd0c', 1, 'taskschedulerservice'],
  ['82273fdc-e32a-18c3-3f78-827929dc23ea', 0, 'eventlog'],
  ['4fc742e0-4a10-11cf-8273-00aa004ae673', 3, 'netdfs'],
  ['6bffd098-a112-3610-9833-012892020162', 0, 'browser'],
  ['50abc2a4-574d-40b3-9d66-ee4fd5fba076', 5, 'dnsserver'],
  ['76f03f96-cdfd-44fc-a22c-64950a001209', 1, 'iremotewinspool'],
  ['894de0c0-0d55-11d3-a322-00c04fa321a1', 1, 'initshutdown'],
  ['a8e0653c-2744-4389-a61d-7373df8b2292', 1, 'fsrvp'],
  ['ccd8c074-d0e5-4a40-92b4-d074faa6ba28', 1, 'witness'],
  ['f5cc59b4-4264-101a-8c59-08002b2f8426', 1, 'frsrpc'],
  ['897e2e5f-93f3-4376-9c9c-fd2277495c27', 1, 'frstrans'],
  ['f5cc5a18-4264-101a-8c59-08002b2f8426', 56, 'nspi'],
  ['c681d488-d850-11d0-8c52-00c04fd90f7e', 1, 'efs'],
  ['8d9f4e40-a03d-11ce-8f69-08003e30051b', 1, 'pnp'],
  ['b97db8b2-4c63-11cf-bff6-08002be23f2f', 3, 'clusapi'],
  ['8f09f000-b7ed-11ce-bbd2-00001a181cad', 0, 'rras'],
  ['621dff68-3c39-4c6c-aae3-e68e2c6503ad', 1, 'wzcsvc'],
  ['a4f1db00-ca47-1067-b31f-00dd010662da', 0, 'mapi'],
  ['2f5f6520-ca46-1067-b319-00dd010662da', 1, 'tapi'],
  ['4da1c422-943d-11d1-acae-00c04fc2aa3f', 1, 'trksvr'],
  ['885d85fb-c754-4062-a0e7-6872ce0064f4', 1, 'mdssvc'],
  ['1544f5e0-613c-11d1-93df-00c04fd7bd09', 1, 'rfr'],
  ['3dde7c30-165d-11d1-ab8f-00805f14db40', 1, 'backupkey'],
  ['91ae6020-9e3c-11cf-8d7c-00aa00c091be', 0, 'icpr'],
  ['f6beaff7-1e19-4fbb-9f8f-b89e2018337c', 1, 'even6'],
];

/** The transfer syntaxes a Bind offers, by the name the tree gives them. */
const SYNTAXES: [string, number][] = [
  ['8a885d04-1ceb-11c9-9fe8-08002b104860', 2],
  ['71710533-beba-4937-8319-b5dbef9ccc36', 1],
  ['6cb71c2c-9812-4540-0300-000000000000', 1],
];

const le16 = (n: number) => [n & 255, (n >> 8) & 255];
const le32 = (n: number) => [n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255];
function uuidBytes(text: string): number[] {
  const b = text.replace(/-/g, '').match(/../g)!.map((x) => parseInt(x, 16));
  return [...b.slice(0, 4).reverse(), ...b.slice(4, 6).reverse(), ...b.slice(6, 8).reverse(), ...b.slice(8)];
}
const pdu = (type: number, callId: number, body: number[]) =>
  [5, 0, type, 3, 0x10, 0, 0, 0, ...le16(16 + body.length), 0, 0, ...le32(callId), ...body];
const bind = (uuid: string, major: number, syntax: [string, number]) => pdu(11, 1, [...le16(5840), ...le16(5840), ...le32(0), 1, 0, 0, 0,
  0, 0, 1, 0, ...uuidBytes(uuid), ...le16(major), 0, 0, ...uuidBytes(syntax[0]), ...le32(syntax[1])]);
const request = pdu(0, 2, [...le32(0), 0, 0, 0, 0]);

/** One connection per frame pair, so each Bind names the context its Request uses. */
function frames(pairs: number[][][]): Uint8Array[] {
  return pairs.flatMap((payloads, i) => {
    let seq = 1000;
    return payloads.map((p) => {
      const body = Uint8Array.from(p);
      const frame = Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(6, tcp(40000 + i, 135, seq, 1, body))]);
      seq += body.length;
      return frame;
    });
  });
}

/** Each frame's Protocol and Info, and the name of every protocol in its tree. */
function columns(list: Uint8Array[]): { cols: string[][]; protos: Map<string, string>[] } {
  const dir = mkdtempSync(join(tmpdir(), 'inwire-dcerpc-'));
  try {
    const file = join(dir, 'f.pcap');
    writeFileSync(file, pcapOf(list));
    const run = spawnSync(tshark!, ['-n', '-r', file, '-T', 'fields', '-e', '_ws.col.Protocol', '-e', '_ws.col.Info', '-E', 'separator=/t'],
      { encoding: 'utf8', maxBuffer: 1 << 26 });
    const pdml = spawnSync(tshark!, ['-n', '-r', file, '-T', 'pdml'], { encoding: 'utf8', maxBuffer: 1 << 28 }).stdout;
    return {
      cols: run.stdout.split(/\r?\n/).filter((l) => l !== '').map((l) => l.split('\t')),
      protos: pdml.split('<packet>').slice(1).map((packet) =>
        new Map([...packet.matchAll(/<proto name="([^"]+)" showname="([^"]*)"/g)].map((m) => [m[1], m[2]]))),
    };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// The first connection of a capture is read as bare TCP however it is built,
// so one is spent on nothing before the candidates.
const probed = columns(frames([
  [request],
  ...CANDIDATES.map(([uuid, major]) => [bind(uuid, major, SYNTAXES[0]), request]),
  ...SYNTAXES.map((s) => [bind(CANDIDATES[0][0], 3, s)]),
]));
const read = probed.cols.slice(1);
const trees = probed.protos.slice(1);

const values = spawnSync(tshark, ['-G', 'values'], { encoding: 'utf8', maxBuffer: 1 << 28 }).stdout.split(/\r?\n/);
const operations = (filter: string): Map<number, string> => {
  const ops = new Map<number, string>();
  for (const line of values) {
    const cols = line.split('\t');
    if (cols[0] === 'V' && cols[1] === `${filter}.opnum` && !ops.has(Number(cols[2]))) ops.set(Number(cols[2]), cols[3].trim());
  }
  return ops;
};

let out = `/**
 * DCE/RPC's names as the reference writes them. GENERATED by
 * \`scripts/parity/gen-dcerpc-tables.ts\` - edit that, not this.
 *
 * An interface is listed only when tshark named its UUID in a Bind; its
 * operations are tshark's \`<filter>.opnum\` table.
 */

export interface DcerpcInterface {
  /** What a Bind and the tree call it: \`EPMv4\`. */
  name: string;
  /** The Protocol column of a call to it: \`EPM\`. */
  protocol: string;
  /** Its layer in the tree, \`Server Service\`, and the filter name that layer has. */
  layer: string;
  token: string;
  /** Its operation row's field, when the layer token owns one. */
  opnumField: string | null;
  operations: Readonly<Record<number, string>>;
}

export const INTERFACES: Readonly<Record<string, DcerpcInterface>> = {
`;
let kept = 0;
CANDIDATES.forEach(([uuid, , filter], i) => {
  const bindInfo = read[i * 2]?.[1] ?? '';
  const name = /context items: (.*?) V\d+\.\d+ /.exec(bindInfo)?.[1];
  const protocol = read[i * 2 + 1]?.[0];
  if (name === undefined || name === uuid || protocol === undefined || protocol === 'DCERPC') {
    console.log(`dropped ${uuid} (${filter}): ${bindInfo}`);
    return;
  }
  const ops = operations(filter);
  // The call's own layer, the protocol after DCE/RPC's: its showname is the
  // layer's name, then the operation's. Its filter name is not always the
  // operations' prefix - `rpc_netlogon` keeps its fields under `netlogon.` -
  // and then the operation row is not drawn, as no layer token owns it.
  const tree = trees[i * 2 + 1];
  const protos = [...(tree?.keys() ?? [])];
  const token = protos[protos.indexOf('dcerpc') + 1];
  const layer = token === undefined ? undefined : tree?.get(token)?.split(', ')[0];
  if (token === undefined || layer === undefined || token.startsWith('_ws')) {
    console.log(`no layer for ${uuid} (${filter})`);
    return;
  }
  const opnumField = token === filter ? `'${filter}.opnum'` : 'null';
  out += `  ${JSON.stringify(uuid)}: {\n    name: ${JSON.stringify(name)}, protocol: ${JSON.stringify(protocol)}, layer: ${JSON.stringify(layer)}, token: ${JSON.stringify(token)},\n    opnumField: ${opnumField},\n    operations: {${[...ops]
    .map(([n, op]) => ` ${n}: ${JSON.stringify(op)}`).join(',')} },\n  },\n`;
  kept++;
});
out += '};\n\n/** Transfer syntaxes, by the name the tree gives them. */\nexport const SYNTAXES: Readonly<Record<string, string>> = {\n';
SYNTAXES.forEach(([uuid], i) => {
  const info = read[CANDIDATES.length * 2 + i]?.[1] ?? '';
  const name = /\((.*)\)$/.exec(info)?.[1];
  if (name !== undefined && name !== uuid) out += `  ${JSON.stringify(uuid)}: ${JSON.stringify(name)},\n`;
  else console.log(`syntax ${uuid}: ${info}`);
});
out += '};\n';
writeFileSync('src/services/dissectors/dcerpcNames.ts', out);
console.log(`wrote ${kept} interfaces`);
