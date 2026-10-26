/**
 * The stream digest folds rows into one summary per TCP stream (ADR 0055).
 *
 *   npx tsx scripts/conversation/stream-digest.ts
 */
import { RECENT_FRAMES, StreamDigest } from '../../src/services/conversation/streamDigest';
import { DEFAULT_HORIZON_FRAMES } from '../../src/services/capture/captureWriter';
import type { Packet } from '../../src/types/packet';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}`);
  if (!pass) {
    console.log(`        expected ${JSON.stringify(expected)}`);
    console.log(`        actual   ${JSON.stringify(actual)}`);
  }
}

let nextId = 1;
function row(fromClient: boolean, flags: string, extra: Partial<Packet> & { seq?: number; ack?: number; len?: number } = {}): Packet {
  const { seq, ack, len, ...rest } = extra;
  const fields: Record<string, number> = {
    'tcp.flags.syn': flags.includes('S') ? 1 : 0, 'tcp.flags.ack': flags.includes('A') ? 1 : 0,
    'tcp.flags.fin': flags.includes('F') ? 1 : 0, 'tcp.flags.reset': flags.includes('R') ? 1 : 0,
    ...(seq !== undefined ? { 'tcp.seq': seq } : {}), ...(ack !== undefined ? { 'tcp.ack': ack } : {}),
    'tcp.len': len ?? 0,
  };
  const id = nextId++;
  return {
    id, tsUs: id * 1000, timeDelta: 0, relativeTime: id / 1000,
    source: fromClient ? '10.0.0.2' : '93.184.216.34', destination: fromClient ? '93.184.216.34' : '10.0.0.2',
    sourcePort: fromClient ? 50000 : 443, destPort: fromClient ? 443 : 50000,
    protocol: 'TCP', frameProtocols: ['eth', 'ethertype', 'ip', 'tcp'], fields,
    length: 60 + (len ?? 0), info: '', status: 'ok', streamId: 7, ...rest,
  } as Packet;
}

{
  nextId = 1;
  const d = new StreamDigest();
  const rows = [
    row(true, 'S', { seq: 0 }), row(false, 'SA', { seq: 0, ack: 1 }), row(true, 'A', { seq: 1, ack: 1 }),
    row(true, 'A', { seq: 1, ack: 1, len: 100, protocolLabel: 'TLSv1.3' }),
    row(false, 'A', { seq: 1, ack: 101, len: 1000, analysisFlags: ['retransmission'] }),
    row(true, 'FA', { seq: 101, ack: 1001 }), row(false, 'FA', { seq: 1001, ack: 102 }), row(true, 'A', { seq: 102, ack: 1002 }),
  ];
  for (const r of rows) d.feed(r);
  const s = d.get(7)!;
  check('client by well-known port', [s.client, s.clientBasis], [{ address: '10.0.0.2', port: 50000 }, 'well-known-port']);
  check('per-direction counts', [s.toServer.packets, s.toClient.packets, s.toServer.bytes, s.toClient.bytes], [5, 3, 400, 1180]);
  check('outcome and states', [s.outcome, s.state], ['closed cleanly', { client: 'TIME_WAIT', server: 'CLOSED' }]);
  check('protocol label is the most specific seen', s.protocol, 'TLSv1.3');
  check('retransmissions counted', s.retransmissions, 1);
  check('steps carry their frame ids', s.steps.slice(0, 2).map((t) => [t.frameId, t.side, t.to]), [[1, 'client', 'SYN_SENT'], [1, 'server', 'LISTEN']]);
  check('a repeated id folds once', (() => { d.feed(rows[3]); return d.get(7)!.toServer.packets; })(), 5);
  check('ids are bounded', [s.firstId, s.lastId], [1, 8]);

  const before = d.version;
  d.relabel(4, 'TLSv1.2');
  check('a protocolLabel patch relabels and bumps the version', [d.get(7)!.protocol, d.version > before], ['TLSv1.2', true]);
  check('changedSince returns only changed streams', d.changedSince(d.version).tcp.length, 0);

  const back = StreamDigest.restore(JSON.parse(JSON.stringify(d.snapshot())));
  check('snapshot round-trips', back.get(7), d.get(7));
  const snap = d.snapshot();
  const snapJson = JSON.stringify(snap);
  // The contract is "serialise it now": snapshot() hands out the digest's own
  // entries (a copy was 2.4 s and 239 MB at 100k streams), so the text taken
  // before a feed is what stays fixed, and `encodeDigest` is that text.
  const first = snap.entries[0];
  check('snapshot() is the digest\'s own entries, not a copy', first.kind === 'tcp' && first.entry.summary === d.get(7), true);
  const data = JSON.parse(snapJson);
  const restored = StreamDigest.restore(data);
  nextId = 9;
  restored.feed(row(true, 'RA'));
  // restore() adopts what it is handed (a copy was 6 s of a reopen's 8 at
  // 500k streams), so the restored digest folds into the decoded entries.
  check('restore() adopts the entries it is handed, not a copy', restored.get(7) === data.entries[0].entry.summary, true);
  nextId = 9;
  back.feed(row(true, 'RA'));
  check('a restored digest keeps folding', [back.get(7)!.lastId, back.get(7)!.outcome], [9, 'closed cleanly']);
}

{
  nextId = 1;
  const d = new StreamDigest();
  d.feed(row(false, 'A', { seq: 5, ack: 9, len: 10 }));
  check('joined mid-stream is flagged', [d.get(7)!.joinedMidStream, d.get(7)!.outcome], [true, 'open']);
  d.feed({ ...row(true, 'A'), frameProtocols: ['eth', 'ethertype', 'ip', 'udp'], streamId: 8 } as Packet);
  check('UDP rows are not TCP streams', d.get(8), undefined);
}

{
  // A patch can come as late as the writer's horizon in frames (ADR 0055): at
  // 50k frames a second its two seconds are 100,000 frames, and the digest's
  // memory of which stream a frame was in has to reach that far.
  check('the ring covers the horizon', RECENT_FRAMES >= DEFAULT_HORIZON_FRAMES, true);
  nextId = 1;
  const d = new StreamDigest();
  d.feed(row(true, 'S', { seq: 0 }));
  for (let i = 1; i < 120_000; i++) {
    // Every tenth id is another stream's, so a lookup must land on the right one.
    if (i % 10 === 0) d.feed(row(true, 'A', { seq: 1, ack: 1, streamId: 8, sourcePort: 50001 }));
    else d.feed(row(true, 'A', { seq: 1, ack: 1 }));
  }
  // Ids 1 mod 10 are stream 8's: the first of stream 7's at 100,000 back is one past.
  const target = nextId - 100_000 + 1;
  d.relabel(target, 'HTTP');
  check('relabel reaches 100,000 frames back', [d.get(7)!.protocol, d.get(8)!.protocol], ['HTTP', 'TCP']);
  d.relabel(target + 9, 'DNS');
  check('...and finds the other stream\'s frame', [d.get(7)!.protocol, d.get(8)!.protocol], ['HTTP', 'DNS']);
  const before = d.version;
  d.relabel(nextId + 5, 'QUIC');
  d.relabel(0, 'QUIC');
  check('relabel of an id never fed is ignored', [d.get(7)!.protocol, d.get(8)!.protocol, d.version], ['HTTP', 'DNS', before]);

  nextId = 1;
  const gaps = new StreamDigest();
  gaps.feed(row(true, 'S', { seq: 0 }));
  nextId = 5;
  gaps.feed(row(true, 'A', { seq: 1, ack: 1 }));
  gaps.relabel(3, 'HTTP');
  check('...nor one between two that were', gaps.get(7)!.protocol, 'TCP');
}

console.log(failures === 0 ? '\nall passed' : `\n${failures} failed`);
process.exit(failures === 0 ? 0 : 1);
