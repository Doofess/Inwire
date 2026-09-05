/**
 * Assertion tests for stream selection and direction.
 *
 *   npx tsx scripts/stream/follow.ts
 *
 * The follower used to filter on `packet.streamId`, which the TCP tracker
 * assigns and nothing else does - so a DNS exchange or a QUIC connection had
 * no id and Follow Stream was not offered on them at all. Selection is by
 * five-tuple now, which works for both and needs no numbering to exist.
 *
 * The direction check is the one that matters most. "Whoever sent the first
 * frame is the client" is right on a complete TCP conversation and wrong on a
 * capture that started in the middle of one, and getting it backwards reverses
 * the labels and the colours of the whole window - the kind of wrong that
 * reads as a fact.
 */
import { clientEnd, isFromClient, streamPackets, targetForPacket } from '../../src/services/followStream';
import type { Packet, ProtocolType } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown) {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

let nextId = 1;
function packet(
  src: string, sport: number, dst: string, dport: number,
  layers: string[], over: Partial<Packet> = {},
): Packet {
  return {
    id: nextId++,
    tsUs: 0, relativeTime: 0, timeDelta: 0,
    source: src, destination: dst, sourcePort: sport, destPort: dport,
    protocol: 'TCP' as ProtocolType, length: 100, info: '', status: 'ok',
    frameProtocols: ['frame', 'eth', 'ip', ...layers],
    layers: [], rawBytes: new Uint8Array(0), interfaceName: 'test',
    ...over,
  };
}

// --- what a frame says its stream is -------------------------------------------

{
  nextId = 1;
  const tcp = packet('10.0.0.1', 51000, '93.184.216.34', 443, ['tcp'], { streamId: 7 });
  check('a TCP frame names its five-tuple', targetForPacket(tcp),
    { kind: 'tcp', addressA: '10.0.0.1', portA: 51000, addressB: '93.184.216.34', portB: 443, streamId: 7 });

  const udp = packet('10.0.0.1', 51001, '1.1.1.1', 53, ['udp', 'dns']);
  check('a UDP frame names one too, with no index', targetForPacket(udp)?.kind, 'udp');
  check('...and that is the point: it has no stream id', targetForPacket(udp)?.streamId, undefined);

  const arp = packet('a', 0, 'b', 0, ['arp']);
  arp.frameProtocols = ['frame', 'eth', 'arp'];
  arp.sourcePort = undefined;
  arp.destPort = undefined;
  check('a frame on no transport has no stream', targetForPacket(arp), null);
}

// --- selection -------------------------------------------------------------------

{
  nextId = 1;
  const a = packet('10.0.0.1', 51000, '93.184.216.34', 443, ['tcp'], { streamId: 7 });
  const b = packet('93.184.216.34', 443, '10.0.0.1', 51000, ['tcp'], { streamId: 7 });
  const otherPort = packet('10.0.0.1', 51001, '93.184.216.34', 443, ['tcp'], { streamId: 8 });
  const otherHost = packet('10.0.0.1', 51000, '1.1.1.1', 443, ['tcp'], { streamId: 9 });
  // Same ports, same hosts, different transport - which is exactly why the
  // target carries the transport at all.
  const udpTwin = packet('10.0.0.1', 51000, '93.184.216.34', 443, ['udp', 'quic']);
  const all = [a, b, otherPort, otherHost, udpTwin];

  const target = targetForPacket(a)!;
  check('both directions are on the stream', streamPackets(all, target).map(p => p.id), [1, 2]);
  check('a different port is a different stream', streamPackets(all, target).some(p => p.id === 3), false);
  check('a different host is too', streamPackets(all, target).some(p => p.id === 4), false);
  check('and so is the same tuple over UDP', streamPackets(all, target).some(p => p.id === 5), false);
  check('the UDP flow selects its own frame', streamPackets(all, targetForPacket(udpTwin)!).map(p => p.id), [5]);
  check('a stream with nothing in the buffer selects nothing', streamPackets([], target), []);
}

// --- which end is the client ------------------------------------------------------

{
  nextId = 1;
  // The server spoke first, which happens on any capture that started
  // mid-connection. The well-known port is what saves this.
  const serverFirst = packet('93.184.216.34', 443, '10.0.0.1', 51000, ['tcp']);
  const clientReply = packet('10.0.0.1', 51000, '93.184.216.34', 443, ['tcp']);
  const target = targetForPacket(serverFirst)!;
  const frames = [serverFirst, clientReply];

  check('a well-known port on one end names the server, whoever spoke first',
    clientEnd(frames, target), { address: '10.0.0.1', port: 51000 });
  check('...so the server\'s frame is not from the client',
    isFromClient(serverFirst, clientEnd(frames, target)), false);
  check('...and the client\'s is', isFromClient(clientReply, clientEnd(frames, target)), true);
}

{
  nextId = 1;
  // Two ephemeral ports - a peer-to-peer flow. Nothing to go on but arrival.
  const first = packet('10.0.0.1', 51000, '10.0.0.2', 52000, ['udp']);
  const second = packet('10.0.0.2', 52000, '10.0.0.1', 51000, ['udp']);
  const target = targetForPacket(first)!;
  check('with no well-known port, the first speaker is the client',
    clientEnd([first, second], target), { address: '10.0.0.1', port: 51000 });
  check('...and the reverse capture order gives the reverse answer',
    clientEnd([second, first], target), { address: '10.0.0.2', port: 52000 });
}

{
  nextId = 1;
  // Both ends well-known - a router talking BGP to a router. Falls through to
  // arrival order rather than picking arbitrarily.
  const first = packet('10.0.0.1', 179, '10.0.0.2', 179, ['tcp']);
  const target = targetForPacket(first)!;
  check('two well-known ports fall back to arrival order',
    clientEnd([first], target), { address: '10.0.0.1', port: 179 });
  check('an empty stream still yields an end rather than throwing',
    clientEnd([], target), { address: '10.0.0.1', port: 179 });
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All follow-stream checks passed.');
process.exit(0);
