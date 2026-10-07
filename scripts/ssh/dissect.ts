/**
 * SSH against the reference, row for row, across four key exchanges.
 *
 *   npx tsx scripts/ssh/dissect.ts
 *
 * What an SSH connection shows before it goes dark: both banners, both
 * KEXINITs (and the hassh pair computed from them), the key exchange the
 * client's preference settled on, the host key and its signature, New Keys,
 * and then encrypted packets with the negotiated MAC's length. Built here as
 * conversations - neither fixture holds SSH - and compared with the
 * reference's two-pass reading, which is what this build's tree shows.
 *
 * The four exchanges are the ones a client meets: curve25519 (the long-time
 * default), mlkem768x25519 (OpenSSH 10's post-quantum hybrid), group14
 * Diffie-Hellman with an RSA host key, and group exchange with an ECDSA one
 * from an older client. The curve25519 client's KEXINIT carries OpenSSH's
 * full algorithm lists and is split across two segments, so the packet is
 * reassembled - the first segment reading as TCP that the second completes.
 */
import { ethernet, ipv4, tcp } from '../parity/synthetic';
import { check, checkRevisit, compareWithReference, finish, type OracleCase } from '../parity/treeOracle';
import { md5Hex } from '../../src/services/crypto/md5';

const CLIENT = '192.0.2.1';
const SERVER = '192.0.2.2';
const u32 = (n: number) => [(n >>> 24) & 255, (n >> 16) & 255, (n >> 8) & 255, n & 255];
const str = (text: string) => { const b = new TextEncoder().encode(text); return [...u32(b.length), ...b]; };
const blob = (bytes: number[]) => [...u32(bytes.length), ...bytes];
const fill = (n: number, v: number) => new Array(n).fill(v);
/** A binary packet (RFC 4253 §6), padded to a multiple of eight with at least four. */
const packet = (body: number[]) => {
  const padding = 8 - ((5 + body.length) % 8) + 4;
  return [...u32(1 + body.length + padding), padding, ...body, ...fill(padding, 0)];
};

/** One TCP connection to port 22, sequence numbers kept in both directions. */
function connection(clientPort: number) {
  let up = 1000;
  let down = 5000;
  return (fromClient: boolean, payload: number[] | Uint8Array): Uint8Array => {
    const bytes = Uint8Array.from(payload);
    const segment = tcp(fromClient ? clientPort : 22, fromClient ? 22 : clientPort, fromClient ? up : down, fromClient ? down : up, bytes);
    if (fromClient) up += bytes.length; else down += bytes.length;
    return Uint8Array.from([...ethernet(0x0800).build(), ...ipv4(6, segment, fromClient ? CLIENT : SERVER, fromClient ? SERVER : CLIENT)]);
  };
}

const kexinit = (kex: string, hostKeys: string, cipher: string, mac: string, client: boolean) => packet([
  20, ...fill(16, client ? 0xc1 : 0x51), ...str(kex), ...str(hostKeys), ...str(cipher), ...str(cipher),
  ...str(mac), ...str(mac), ...str('none,zlib@openssh.com'), ...str('none,zlib@openssh.com'), ...str(''), ...str(''), 0, ...u32(0),
]);
const ed25519Key = blob([...str('ssh-ed25519'), ...blob(fill(32, 0x4b))]);
const ed25519Sig = blob([...str('ssh-ed25519'), ...blob(fill(64, 0x53))]);
const banner = (text: string) => [...new TextEncoder().encode(`${text}\r\n`)];

const OPENSSH_KEX = 'mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,'
  + 'curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,'
  + 'diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,'
  + 'diffie-hellman-group14-sha256,ext-info-c,kex-strict-c-v00@openssh.com';
const OPENSSH_HOSTKEYS = 'ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,'
  + 'rsa-sha2-512-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,'
  + 'sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256';
const OPENSSH_CIPHERS = 'chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com';
const OPENSSH_MACS = 'umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,'
  + 'hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,'
  + 'hmac-sha2-256,hmac-sha2-512,hmac-sha1';

const cases: OracleCase[] = [];
const add = (label: string, frame: Uint8Array) => cases.push({ label, frame });

{
  // curve25519, the client's KEXINIT split across two segments.
  const s = connection(50001);
  const clientInit = kexinit(`curve25519-sha256,${OPENSSH_KEX}`, OPENSSH_HOSTKEYS, OPENSSH_CIPHERS, OPENSSH_MACS, true);
  add('curve25519: client banner', s(true, banner('SSH-2.0-OpenSSH_9.9')));
  add('curve25519: server banner', s(false, banner('SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5')));
  add('curve25519: client KEXINIT, first segment', s(true, clientInit.slice(0, 900)));
  add('curve25519: client KEXINIT, completed', s(true, clientInit.slice(900)));
  add('curve25519: server KEXINIT', s(false, kexinit('curve25519-sha256,ecdh-sha2-nistp256', 'ssh-ed25519', OPENSSH_CIPHERS, OPENSSH_MACS, false)));
  add('curve25519: ECDH init', s(true, packet([30, ...blob(fill(32, 0x01))])));
  add('curve25519: ECDH reply and New Keys', s(false, [...packet([31, ...ed25519Key, ...blob(fill(32, 0x02)), ...ed25519Sig]), ...packet([21])]));
  add('curve25519: client New Keys and its first encrypted packet', s(true, [...packet([21]), ...fill(36, 0xee)]));
  add('curve25519: an encrypted packet from the server', s(false, fill(52, 0xdd)));
}
{
  // OpenSSH 10's default: the ML-KEM hybrid, AES-GCM.
  const s = connection(50002);
  add('mlkem768x25519: client banner', s(true, banner('SSH-2.0-OpenSSH_10.0')));
  add('mlkem768x25519: server banner', s(false, banner('SSH-2.0-OpenSSH_10.0')));
  add('mlkem768x25519: client KEXINIT', s(true, kexinit('mlkem768x25519-sha256,curve25519-sha256', 'ssh-ed25519', 'aes256-gcm@openssh.com', 'hmac-sha2-256', true)));
  add('mlkem768x25519: server KEXINIT', s(false, kexinit('mlkem768x25519-sha256', 'ssh-ed25519', 'aes256-gcm@openssh.com', 'hmac-sha2-256', false)));
  add('mlkem768x25519: hybrid init', s(true, packet([30, ...blob(fill(1216, 0x03))])));
  add('mlkem768x25519: hybrid reply and New Keys', s(false, [...packet([31, ...ed25519Key, ...blob(fill(1120, 0x04)), ...ed25519Sig]), ...packet([21])]));
}
{
  // group14 Diffie-Hellman, an RSA host key, HMAC-SHA2-256 over AES-CTR.
  const s = connection(50003);
  const rsaKey = blob([...str('ssh-rsa'), ...blob([1, 0, 1]), ...blob([0, ...fill(64, 0xa5)])]);
  add('group14: client banner', s(true, banner('SSH-2.0-PuTTY_Release_0.81')));
  add('group14: server banner', s(false, banner('SSH-2.0-OpenSSH_8.0')));
  add('group14: client KEXINIT', s(true, kexinit('diffie-hellman-group14-sha256', 'rsa-sha2-256', 'aes256-ctr', 'hmac-sha2-256', true)));
  add('group14: server KEXINIT', s(false, kexinit('diffie-hellman-group14-sha256', 'rsa-sha2-256', 'aes256-ctr', 'hmac-sha2-256', false)));
  add('group14: DH init', s(true, packet([30, ...blob([0, ...fill(64, 0x05)])])));
  add('group14: DH reply and New Keys', s(false, [...packet([31, ...rsaKey, ...blob([0, ...fill(64, 0x06)]),
    ...blob([...str('rsa-sha2-256'), ...blob(fill(64, 0x07))])]), ...packet([21])]));
  add('group14: client New Keys and an encrypted packet with a 32-byte MAC', s(true, [...packet([21]), ...fill(68, 0xee)]));
}
{
  // Group exchange, an old client's request, an ECDSA host key.
  const s = connection(50004);
  const ecdsaKey = blob([...str('ecdsa-sha2-nistp256'), ...str('nistp256'), ...blob([4, ...fill(64, 0x45)])]);
  add('group exchange: client banner', s(true, banner('SSH-2.0-OpenSSH_7.4')));
  add('group exchange: server banner', s(false, banner('SSH-2.0-OpenSSH_7.4')));
  add('group exchange: client KEXINIT', s(true, kexinit('diffie-hellman-group-exchange-sha256', 'ecdsa-sha2-nistp256', 'aes128-ctr', 'hmac-sha2-512-etm@openssh.com', true)));
  add('group exchange: server KEXINIT', s(false, kexinit('diffie-hellman-group-exchange-sha256', 'ecdsa-sha2-nistp256', 'aes128-ctr', 'hmac-sha2-512-etm@openssh.com', false)));
  add('group exchange: request (old)', s(true, packet([30, ...u32(2048)])));
  add('group exchange: group', s(false, packet([31, ...blob([0, ...fill(64, 0x50)]), ...blob([2])])));
  add('group exchange: init', s(true, packet([32, ...blob([0, ...fill(64, 0x08)])])));
  add('group exchange: reply and New Keys', s(false, [...packet([33, ...ecdsaKey, ...blob([0, ...fill(64, 0x09)]),
    ...blob([...str('ecdsa-sha2-nistp256'), ...blob(fill(72, 0x53))])]), ...packet([21])]));
}
{
  // A client that gives up before the key exchange finishes.
  const s = connection(50005);
  add('a disconnect: client banner', s(true, banner('SSH-2.0-OpenSSH_9.9')));
  add('a disconnect: server banner', s(false, banner('SSH-2.0-OpenSSH_9.9')));
  add('a disconnect: client KEXINIT', s(true, kexinit('diffie-hellman-group-exchange-sha256', 'ssh-ed25519', 'aes128-ctr', 'hmac-sha1', true)));
  add('a disconnect: server KEXINIT', s(false, kexinit('diffie-hellman-group-exchange-sha256', 'ssh-ed25519', 'aes128-ctr', 'hmac-sha1', false)));
  add('a disconnect: request', s(true, packet([34, ...u32(2048), ...u32(4096), ...u32(8192)])));
  add('a disconnect: the disconnect', s(true, packet([1, ...u32(11), ...str('bye'), ...str('')])));
}

const packets = await compareWithReference(cases, { rows: /^ssh\./, twoPass: true });
await checkRevisit(cases);

// --- what a filter reaches ------------------------------------------------------
const hassh = md5Hex(`curve25519-sha256,${OPENSSH_KEX};${OPENSSH_CIPHERS};${OPENSSH_MACS};none,zlib@openssh.com`);
check('the reassembled client KEXINIT carries its hassh', packets[3]?.fields?.['ssh.kex.hassh'] === hassh,
  String(packets[3]?.fields?.['ssh.kex.hassh']));
check('the server KEXINIT carries its hasshServer', typeof packets[4]?.fields?.['ssh.kex.hasshserver'] === 'string');
check('a banner is filterable', packets[1]?.fields?.['ssh.protocol'] === 'SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5');
check('`ssh` is the layer token', packets[0]?.frameProtocols?.at(-1) === 'ssh');

finish('SSH');
