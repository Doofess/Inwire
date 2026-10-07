/**
 * HomePlug AV's management header against the reference, row for row.
 *
 *   npx tsx scripts/homeplug/dissect.ts
 *
 * Every powerline adapter on a home's wiring talks HomePlug AV on ethertype
 * 0x88e1, and the host behind one sees its broadcasts. Neither fixture holds
 * any, so the frames are built here from the HomePlug AV 2.1 header layout -
 * both versions, standard and vendor messages, each OUI the reference knows
 * and one it does not - and compared with tshark's reading of the same file.
 *
 * Only the header is held: the body is drawn as bytes. Every message type
 * below is one whose body the reference reads without complaint from 60
 * bytes of zero padding, so its Info carries no `[Malformed Packet]` that a
 * real adapter's frame would not.
 */
import { ethernet } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';

const QUALCOMM = [0x00, 0xb0, 0x52];
const ST_IOTECHA = [0x00, 0x80, 0xe1];
const DSPACE = [0x64, 0x4d, 0x70];
const NOBODY = [0x12, 0x34, 0x56];

/** A management message, padded to Ethernet's minimum as an adapter sends it. */
function mme(version: number, mmtype: number, rest: number[]): Uint8Array {
  const frame = ethernet(0x88e1).u8(version, mmtype & 0xff, mmtype >> 8, ...rest);
  return frame.zeros(Math.max(0, 60 - frame.build().length)).build();
}
const v10 = (mmtype: number, ...rest: number[][]) => mme(0, mmtype, rest.flat());
const v11 = (mmtype: number, fmi: [number, number], ...rest: number[][]) => mme(1, mmtype, [...fmi, ...rest.flat()]);

const cases: OracleCase[] = [
  { label: 'a Qualcomm firmware query', frame: v10(0xa000, QUALCOMM) },
  { label: 'a Qualcomm network info request', frame: v10(0xa038, QUALCOMM) },
  { label: 'a Qualcomm link statistics request', frame: v10(0xa030, QUALCOMM) },
  { label: 'a Qualcomm type the table lacks', frame: v10(0xa002, QUALCOMM) },
  { label: 'a Qualcomm type with MSB 6', frame: v10(0xc000, QUALCOMM) },
  { label: 'a 1.1 Qualcomm message, fragmented', frame: v11(0xa000, [0x21, 0x07], QUALCOMM) },
  { label: 'an ST/IoTecha key set', frame: v10(0x8000, ST_IOTECHA) },
  { label: 'an ST/IoTecha type its table lacks', frame: v10(0xa002, ST_IOTECHA) },
  { label: 'an ST type under Qualcomm\'s OUI', frame: v10(0x8000, QUALCOMM) },
  { label: 'a dSPACE message', frame: v10(0xa002, DSPACE) },
  { label: 'an OUI nobody names', frame: v10(0x8000, NOBODY) },
  { label: 'a manufacturer message in 1.1', frame: v11(0x8123, [0, 0], [1, 2, 3]) },
  { label: 'a 1.0 public message', frame: v10(0x0014) },
  { label: 'a 1.0 public message with a sequence number', frame: v10(0x6000, [0x00, 0x80]) },
  { label: 'an error indication', frame: v10(0x6046) },
  { label: 'a 1.1 public message', frame: v11(0x6008, [0, 0]) },
  { label: 'a 1.1 type nobody names, every FMI bit', frame: v11(0x0002, [0x5a, 0xa5]) },
  { label: 'an unnamed 1.1 indication', frame: v11(0x6012, [0, 0]) },
  // Version byte 2: the reference shows bit 0 as the version, "1.0", and
  // reads an FMI because the byte is not zero.
  { label: 'a version byte of 2', frame: mme(2, 0x0014, [0, 0]) },
];

const packets = await compareWithReference(cases, {
  rows: /^homeplug_av\.(mmhdr|vendor|public|st_iotecha\.(mmever|rsvd))/,
});
await checkRevisit(cases);
check('a HomePlug AV frame is the `homeplug-av` layer',
  packets[0]?.frameProtocols?.at(-1) === 'homeplug-av', packets[0]?.frameProtocols?.join(':'));
check('a Qualcomm message type is a field under its vendor\'s name',
  packets[0]?.fields?.['homeplug_av.mmhdr.mmtype.qualcomm'] === 0xa000);
check('the OUI is a field', packets[0]?.fields?.['homeplug_av.vendor.oui'] === 0x00b052);
finish('homeplug');
