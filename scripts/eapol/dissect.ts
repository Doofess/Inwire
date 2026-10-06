/**
 * 802.1X - EAPOL and EAP - against the reference, row for row.
 *
 *   npx tsx scripts/eapol/dissect.ts
 *
 * What a laptop sends joining protected Wi-Fi: the four-way handshake, the
 * group-key handshake, and on an enterprise network the EAP exchange before
 * them. Neither fixture holds any, so the frames are built from IEEE 802.11's
 * key descriptor and RFC 3748's EAP packet, and tshark reads the same file.
 *
 * The property most worth holding is the **message number**, which is not on
 * the wire: it is inferred from the Key Information bits, the key data length
 * and the nonce, and the reference's rule has corners - a message 4 with the
 * Secure bit clear, a message 2 with no key data but a nonce - that a
 * reading of the standard alone would number differently.
 */
import { Bytes, ethernet } from '../parity/synthetic';
import { check, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import { keyMessage } from '../../src/services/dissectors/eapol';

const eapol = (body: Uint8Array) => new Bytes().raw(ethernet(0x888e).build()).raw(body).build();
/** An EAPOL-Key frame: RSN (2) or WPA (254) descriptor, Key Information, nonce, MIC, key data. */
const key = (info: number, replay: number, nonce: number, mic: boolean, data: number[], descriptor = 2, version = 2) =>
  eapol(new Bytes().u8(version, 3).u16(95 + data.length).u8(descriptor).u16(info).u16(16).u32(0, replay)
    .raw(new Array(32).fill(nonce)).raw(new Array(16).fill(0)).raw(new Array(8).fill(0)).raw(new Array(8).fill(0))
    .raw(new Array(16).fill(mic ? 0x77 : 0)).u16(data.length).raw(data).build());
/** An EAP packet in an EAPOL frame; `length` counts the EAP header. */
const eap = (code: number, id: number, body: number[] = [], version = 1) =>
  eapol(new Bytes().u8(version, 0).u16(4 + body.length).u8(code, id).u16(4 + body.length).raw(body).build());
const ascii = (text: string) => [...new TextEncoder().encode(text)];

/** The station's RSN element in message 2: CCMP, PSK. */
const RSN = [0x30, 0x14, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 2, 0x0c, 0];

// Each EAP request takes an id of its own: the reference marks a request that
// repeats an earlier one's id as a retransmission, which this build does not
// track, and a suite reusing ids would be testing that instead.
const cases: OracleCase[] = [
  { label: 'message 1 of 4', frame: key(0x008a, 1, 0x11, false, []) },
  { label: 'message 2 of 4, with the RSN element', frame: key(0x010a, 1, 0x22, true, RSN) },
  { label: 'message 3 of 4, encrypted key data', frame: key(0x13ca, 2, 0x11, true, new Array(56).fill(0x99)) },
  { label: 'message 4 of 4', frame: key(0x030a, 2, 0, true, []) },
  // Secure clear and a zero nonce: still 4. Some supplicants send it so.
  { label: 'a message 4 without Secure', frame: key(0x010a, 2, 0, true, []) },
  // No key data, but a nonce and no Secure: the reference calls it 2.
  { label: 'a message 2 with no key data', frame: key(0x010a, 1, 0x11, true, []) },
  { label: 'group message 1 of 2', frame: key(0x1382, 3, 0, true, new Array(24).fill(0x55)) },
  { label: 'group message 2 of 2', frame: key(0x0302, 3, 0, true, []) },
  { label: 'a WPA (not RSN) descriptor', frame: key(0x0089, 1, 0x11, false, [], 254, 1) },
  { label: 'an AES-128-CMAC descriptor version', frame: key(0x008b, 1, 0x11, false, []) },
  { label: 'a key request', frame: key(0x0b0a, 4, 0, true, []) },
  { label: 'a key request reporting an error', frame: key(0x0f0a, 4, 0, true, []) },
  { label: 'EAPOL-Start', frame: eapol(new Bytes().u8(1, 1).u16(0).build()) },
  { label: 'EAPOL-Logoff', frame: eapol(new Bytes().u8(1, 2).u16(0).build()) },
  { label: 'an encapsulated ASF alert', frame: eapol(new Bytes().u8(1, 4).u16(0).build()) },
  { label: 'an unknown EAPOL type', frame: eapol(new Bytes().u8(1, 9).u16(0).build()) },
  { label: 'EAP Request, Identity', frame: eap(1, 1, [1]) },
  { label: 'EAP Response, Identity', frame: eap(2, 1, [1, ...ascii('alice@example.com')]) },
  { label: 'EAP Response, Legacy Nak', frame: eap(2, 2, [3, 25]) },
  { label: 'EAP Request, MD5-Challenge', frame: eap(1, 4, [4, 16, ...new Array(16).fill(0xab)]) },
  { label: 'EAP Request, PEAP Start', frame: eap(1, 2, [25, 0x21], 2) },
  { label: 'EAP Response, PEAP acknowledgement', frame: eap(2, 5, [25, 0x00]) },
  { label: 'EAP Request, TLS Start', frame: eap(1, 6, [13, 0x20]) },
  { label: 'EAP Request, TTLS Start', frame: eap(1, 7, [21, 0x20]) },
  { label: 'EAP Request, LEAP', frame: eap(1, 11, [17, 1, 0, 8, ...new Array(8).fill(0x5c), ...ascii('alice')]) },
  { label: 'EAP Request, GTC (no decoder: its data)', frame: eap(1, 12, [6, ...ascii('Password: ')]) },
  { label: 'EAP Success', frame: eap(3, 9) },
  { label: 'EAP Failure', frame: eap(4, 10) },
];

const packets = await compareWithReference(cases, {
  rows: /^(eapol|eap|wlan_rsna_eapol)\./,
});

// --- the message number, at unit level ----------------------------------------
check('Key ACK and Install is message 3', keyMessage(0x13ca, 56, false)?.n === 3);
check('a request is numbered as none', keyMessage(0x0b0a, 0, true) === null);
check('a group key with Key ACK is group message 1', JSON.stringify(keyMessage(0x1382, 24, true)) === '{"group":true,"n":1}');

// --- filters reach it ---------------------------------------------------------
const third = packets[2];
check('message 3 answers `wlan_rsna_eapol.keydes.msgnr == 3`', third?.fields?.['wlan_rsna_eapol.keydes.msgnr'] === 3);
check('an EAP frame is `eapol` and `eap` both', JSON.stringify(packets[16]?.frameProtocols?.slice(-2)) === '["eapol","eap"]');
check('an identity is filterable', packets[17]?.fields?.['eap.identity'] === 'alice@example.com');

finish('EAPOL');
