/**
 * Checks the synchronous crypto primitives against published test vectors.
 *
 *   npx tsx scripts/parity/crypto-vectors.ts
 *
 * These back QUIC Initial packet decryption, where a subtle error would not
 * announce itself - it would just fail the authentication tag and silently
 * drop back to a header-only summary. Vectors make that failure loud.
 *
 * Sources: FIPS 180-4 (SHA-256), RFC 4231 (HMAC), FIPS 197 (AES-128),
 * RFC 5869 (HKDF), and RFC 9001 Appendix A (QUIC Initial keys, which
 * exercises the whole stack end to end).
 */
import { sha256, hmacSha256 } from '../../src/services/crypto/sha256';
import { md5Hex } from '../../src/services/crypto/md5';
import { expandKey128, encryptBlock128, aes128GcmDecrypt } from '../../src/services/crypto/aes';
import { hkdfExtract, hkdfExpand } from '../../src/services/crypto/hkdf';
import { deriveInitialKeys, QUIC_V1_INITIAL_SALT } from '../../src/services/dissectors/quicCrypto';

const hex = (bytes: Uint8Array) => Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
const fromHex = (text: string) => new Uint8Array((text.match(/.{2}/g) ?? []).map(b => parseInt(b, 16)));
const ascii = (text: string) => new TextEncoder().encode(text);

let failures = 0;
function check(name: string, actual: string, expected: string) {
  const pass = actual === expected;
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${expected}`);
    console.log(`        actual   ${actual}`);
  }
}

// --- MD5 (RFC 1321 A.5) - only because JA3 is defined as one ---
check('md5("")', md5Hex(''), 'd41d8cd98f00b204e9800998ecf8427e');
check('md5("abc")', md5Hex('abc'), '900150983cd24fb0d6963f7d28e17f72');
check('md5("message digest")', md5Hex('message digest'), 'f96b697d7cb7938d525a2f31aaf161d0');
check('md5(2-block)', md5Hex('12345678901234567890123456789012345678901234567890123456789012345678901234567890'),
  '57edf4a22be3c955ac49da2e2107b67a');

// --- SHA-256 (FIPS 180-4) ---
check('sha256("")', hex(sha256(ascii(''))),
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
check('sha256("abc")', hex(sha256(ascii('abc'))),
  'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
// 56 bytes: forces a second block, exercising the length-field placement.
check('sha256(2-block)', hex(sha256(ascii('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq'))),
  '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1');
// 1,000,000 'a' - checks the multi-block loop and the 64-bit length.
check('sha256(1e6 x "a")', hex(sha256(new Uint8Array(1000000).fill(0x61))),
  'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0');

// --- HMAC-SHA256 (RFC 4231) ---
check('hmac case 1', hex(hmacSha256(new Uint8Array(20).fill(0x0b), ascii('Hi There'))),
  'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7');
check('hmac case 2', hex(hmacSha256(ascii('Jefe'), ascii('what do ya want for nothing?'))),
  '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
// 131-byte key - longer than the block size, so it must be hashed down first.
check('hmac long key', hex(hmacSha256(new Uint8Array(131).fill(0xaa),
  ascii('Test Using Larger Than Block-Size Key - Hash Key First'))),
  '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54');

// --- AES-128 block encryption (FIPS 197 Appendix B / C.1) ---
check('aes-128 FIPS 197 C.1',
  hex(encryptBlock128(expandKey128(fromHex('000102030405060708090a0b0c0d0e0f')),
    fromHex('00112233445566778899aabbccddeeff'))),
  '69c4e0d86a7b0430d8cdb78070b4c55a');
check('aes-128 FIPS 197 B',
  hex(encryptBlock128(expandKey128(fromHex('2b7e151628aed2a6abf7158809cf4f3c')),
    fromHex('3243f6a8885a308d313198a2e0370734'))),
  '3925841d02dc09fbdc118597196a0b32');

// --- HKDF-SHA256 (RFC 5869 Test Case 1) ---
{
  const prk = hkdfExtract(fromHex('000102030405060708090a0b0c'), fromHex('0b'.repeat(22)));
  check('hkdf extract', hex(prk),
    '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5');
  check('hkdf expand', hex(hkdfExpand(prk, fromHex('f0f1f2f3f4f5f6f7f8f9'), 42)),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
}

// --- AES-128-GCM (NIST GCM test vectors) ---
{
  // Empty plaintext and AAD: exercises the length block and tag comparison.
  const empty = aes128GcmDecrypt(fromHex('11754cd72aec309bf52f7687212e8957'),
    fromHex('3c819d9a9bed087615030b65'), new Uint8Array(0), new Uint8Array(0),
    fromHex('250327c674aaf477aef2675748cf6971'));
  check('gcm empty', empty === null ? 'null' : hex(empty), '');

  // A wrong tag must be rejected rather than returning noise.
  const badTag = aes128GcmDecrypt(fromHex('11754cd72aec309bf52f7687212e8957'),
    fromHex('3c819d9a9bed087615030b65'), new Uint8Array(0), new Uint8Array(0),
    fromHex('250327c674aaf477aef2675748cf6900'));
  check('gcm rejects bad tag', badTag === null ? 'null' : 'accepted', 'null');
}

// --- QUIC v1 Initial keys (RFC 9001 Appendix A.1) ---
{
  const dcid = fromHex('8394c8f03e515708');
  const { client, server } = deriveInitialKeys(dcid, QUIC_V1_INITIAL_SALT, false);
  check('quic client initial key', hex(client.key), '1f369613dd76d5467730efcbe3b1a22d');
  check('quic client initial iv', hex(client.iv), 'fa044b2f42a3fd3b46fb255c');
  check('quic client initial hp', hex(client.headerProtection), '9f50449e04a0e810283a1e9933adedd2');
  check('quic server initial key', hex(server.key), 'cf3a5331653c364c88f0f379b6067e37');
  check('quic server initial iv', hex(server.iv), '0ac1493ca1905853b0bba03e');
  check('quic server initial hp', hex(server.headerProtection), 'c206b8d9b9f0f37644430b490eeaa314');
}

console.log(failures === 0 ? '\nAll vectors passed.' : `\n${failures} vector(s) FAILED.`);
process.exit(failures === 0 ? 0 : 1);
