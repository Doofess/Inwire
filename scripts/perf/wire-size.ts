/**
 * What the binary packet frame costs on the wire, against what JSON cost.
 *
 *   npx tsx scripts/perf/wire-size.ts
 *
 * Measured on a real capture rather than argued from the format, because the
 * ratio depends entirely on frame size: a 60-byte ARP was mostly envelope, a
 * 1514-byte segment mostly base64 overhead, and a real capture is a mix of the
 * two whose proportions nobody guesses correctly.
 *
 * This is not an assertion script - there is no right answer to hold it to. It
 * is the number quoted in docs/decisions/0005 and in the Phase 11 notes, kept
 * runnable so it can be re-measured rather than trusted.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import { BATCH_HEADER_BYTES, BATCH_RECORD_BYTES } from '../../src/services/agentBinary';

const FIXTURE = 'test/fixtures/inwire_capture_1788478187989.pcap';
/** local-agent/agent.py: MAX_BATCH_RECORDS. */
const BATCH_RECORDS = 512;

async function main() {
  if (!existsSync(FIXTURE)) {
    console.log(`${FIXTURE} is not present (see test/fixtures/README.md)`);
    return;
  }
  const file = new File([new Uint8Array(readFileSync(FIXTURE))], 'fixture.pcap');
  const { packets } = await PcapService.parseCaptureFile(file);

  let json = 0;
  let binary = 0;
  for (const p of packets) {
    // The message a 3.1 agent sent per frame, rebuilt field for field from
    // `packet_to_dict` as it stood.
    json += JSON.stringify({
      type: 'packet',
      id: 'c0ffee00',
      seq: p.id,
      iface: 0,
      tsUs: p.tsUs,
      timestamp: p.tsUs / 1000,
      source: p.source,
      destination: p.destination,
      protocol: p.protocol,
      sourcePort: p.sourcePort ?? null,
      destPort: p.destPort ?? null,
      length: p.length,
      info: `${p.protocol} Traffic`,
      raw: 'x'.repeat(Math.ceil(p.rawBytes.length / 3) * 4), // base64 of the frame
    }).length;
    binary += BATCH_RECORD_BYTES + p.rawBytes.length;
  }
  binary += Math.ceil(packets.length / BATCH_RECORDS) * BATCH_HEADER_BYTES;

  const mb = (n: number) => `${(n / 1e6).toFixed(1)} MB`;
  console.log(`frames                 ${packets.length.toLocaleString()}`);
  console.log(`frame bytes on the wire ${mb(packets.reduce((a, p) => a + p.rawBytes.length, 0))}`);
  console.log();
  console.log(`JSON, one message/frame ${mb(json)}`);
  console.log(`binary, batched         ${mb(binary)}`);
  console.log(`                        ${(100 - binary / json * 100).toFixed(0)}% smaller`);
  console.log();
  console.log(`WebSocket messages: ${packets.length.toLocaleString()} -> ${Math.ceil(packets.length / BATCH_RECORDS).toLocaleString()}`);
}

main();
