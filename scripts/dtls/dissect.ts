/**
 * DTLS against the reference, row for row, on two real handshakes.
 *
 *   npx tsx scripts/dtls/dissect.ts
 *
 * `openssl-dtls12.pcapng` is OpenSSL 3.5's own DTLS 1.2 client and server on
 * loopback, captured with dumpcap - real traffic with nothing personal in it:
 * 127.0.0.1, and a throwaway P-256 certificate made for the occasion, which
 * is why it can live in the repository where the parity fixtures cannot.
 *
 * - The first handshake offers SRTP, as a WebRTC call does, and its path MTU
 *   (300 bytes) splits the ClientHello, the certificate and the key exchange
 *   across datagrams: the fragments and their reassembly are what is tested.
 * - The second is a plain handshake that splits only the certificate.
 * Both start with a cookie exchange (HelloVerifyRequest), and both end in an
 * encrypted alert.
 *
 * The Protocol column is compared with the reference's two-pass reading,
 * where every frame is DTLSv1.2; the tree with its single-pass reading, which
 * is what each frame knew when it arrived and what a revisit rebuilds.
 */
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, checkRevisitFile, compareCaptureFile, finish } from '../parity/treeOracle';

const capture = path.join(path.dirname(fileURLToPath(import.meta.url)), 'openssl-dtls12.pcapng');
const labels = [
  'SRTP: client hello, no cookie', 'SRTP: hello verify request', 'SRTP: client hello, first fragment',
  'SRTP: client hello, reassembled', 'SRTP: server hello, certificate begins', 'SRTP: certificate continues',
  'SRTP: certificate reassembled, key exchange begins', 'SRTP: key exchange reassembled, hello done',
  'SRTP: client key exchange, change cipher spec, finished', 'SRTP: new session ticket',
  'SRTP: change cipher spec, finished', 'SRTP: client alert', 'SRTP: server alert',
  'plain: client hello, no cookie', 'plain: hello verify request', 'plain: client hello with cookie',
  'plain: server hello, certificate begins', 'plain: certificate reassembled', 'plain: key exchange, hello done',
  'plain: client key exchange, change cipher spec, finished', 'plain: ticket, change cipher spec, finished',
  'plain: finished again', 'plain: client alert', 'plain: server alert',
];

// A hello's random_time is a local time whose zone the reference names from
// Windows ("Jerusalem Daylight Time") and this build from Intl ("Israel
// Daylight Time"); it is left out of the comparison.
const packets = await compareCaptureFile(capture, labels, { rows: /^dtls\.(?!handshake\.random_time)/, twoPass: 'columns' });
await checkRevisitFile(capture);

check('each handshake is a DTLS stream of its own', packets[0]?.fields?.['dtls.stream'] === 0 && packets[13]?.fields?.['dtls.stream'] === 1);
check('`dtls` is the layer token', packets[0]?.frameProtocols?.at(-1) === 'dtls');

finish('DTLS');
