/**
 * A replay sends each frame's own bytes, never the flush slab they came in (#17).
 *
 *   npx tsx scripts/pipeline/replay-bytes.ts
 *
 * A live row's `rawBytes` in the renderer is a view into its flush's one
 * transferred slab (`rowPack.ts`). A structured clone of a view copies the
 * view's whole buffer, so a replay bundle holding those views would send every
 * flush its conversation touched: a slow connection in a busy capture, one
 * frame in each of hundreds of multi-megabyte flushes, is a gigabyte a click.
 * The rows here come out of a real `PackReader`, as the window has them, and
 * every frame of the bundle must be exactly its own buffer and its own bytes.
 */
import { deserialize, serialize } from 'node:v8';
import { PcapService } from '../../src/services/pcapParser';
import { TcpStreamTracker } from '../../src/services/tcpStreamTracker';
import { IcmpEchoTracker } from '../../src/services/icmpEchoTracker';
import { QuicFlowTracker } from '../../src/services/quicFlowTracker';
import { DnsTracker } from '../../src/services/dnsTracker';
import { L3Tracker } from '../../src/services/l3Tracker';
import { FrameClock, Sequencer } from '../../src/services/dissect/sequencer';
import { FrameDissector } from '../../src/services/pipeline/frameDissector';
import { PackReader, PackedFlush } from '../../src/services/pipeline/rowPack';
import { replayBundleFor } from '../../src/lib/usePacketDetail';
import type { Packet } from '../../src/types/packet';
import { evictionCapture } from './evictionCapture';

let failures = 0;

function check(name: string, ok: boolean, detail = ''): void {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok || detail === '' ? '' : `: ${detail}`}`);
  if (!ok) failures++;
}

/** The capture's first frames as the window gets them: one flush, its bytes one slab. */
async function windowRows(): Promise<{ rows: Packet[]; own: Map<number, Uint8Array> }> {
  const file = new File([evictionCapture()], 'capture.pcap');
  const { frames } = await PcapService.extractFrames(file, 400);
  const clock = new FrameClock();
  const sequencer = new Sequencer();
  const dissector = new FrameDissector({
    tcp: new TcpStreamTracker(sequencer), icmp: new IcmpEchoTracker(), quic: new QuicFlowTracker(),
    dns: new DnsTracker(), l3: new L3Tracker(sequencer),
  }, undefined, null);
  const builder = new PackedFlush();
  const own = new Map<number, Uint8Array>();
  frames.forEach((frame, i) => {
    const { relativeTime, timeDelta } = clock.fromNanos(frame.tsNanos);
    const { packet } = dissector.dissect({
      id: i + 1, bytes: frame.rawBytes, tsUs: Number(frame.tsNanos / 1000n), relativeTime, timeDelta,
      origLen: frame.origLen, linktype: frame.linktype,
    });
    own.set(packet.id, frame.rawBytes);
    packet.layers = [];
    builder.object(packet, frame.rawBytes);
  });
  const sealed = builder.seal(new Map());
  // The window post: the rows keep no bytes of their own, the slab is
  // transferred, everything else cloned.
  for (const packet of sealed.objects) packet.rawBytes = new Uint8Array(0);
  const moved = structuredClone(sealed, { transfer: [sealed.bytes.buffer as ArrayBuffer] });
  return { rows: new PackReader().read(deserialize(serialize(moved))), own };
}

async function main(): Promise<void> {
  const { rows, own } = await windowRows();
  const slab = rows.find((row) => row.rawBytes.byteLength > 0)?.rawBytes.buffer;
  check('the window rows are views into one slab (the case under test)',
    slab !== undefined && rows.filter((row) => row.rawBytes.byteLength > 0).every((row) => row.rawBytes.buffer === slab));

  // The last TCP row with a conversation before it in the window.
  const target = [...rows].reverse().find((row) => row.protocol === 'TCP' && row.id > 1)!;
  const bundle = await replayBundleFor(target, rows);
  check(`the bundle has the conversation (${bundle.frames.length} frames)`, bundle.frames.length > 0);
  const wrongBuffer = bundle.frames.filter((f) =>
    f.bytes.byteOffset !== 0 || f.bytes.buffer.byteLength !== f.bytes.byteLength);
  check('every frame of the bundle is exactly its own buffer', wrongBuffer.length === 0,
    `${wrongBuffer.length} hold a bigger buffer, first ${wrongBuffer[0]?.bytes.buffer.byteLength} bytes for ${wrongBuffer[0]?.bytes.byteLength}`);
  const wrongBytes = bundle.frames.filter((f) => {
    const want = own.get(f.id);
    return want === undefined || want.length !== f.bytes.length || want.some((b, i) => b !== f.bytes[i]);
  });
  check('...and holds that frame\'s own bytes', wrongBytes.length === 0, `${wrongBytes.length} differ`);
  // Not measured by cloning here: node's v8.serialize writes only a view's own
  // bytes, where a browser's structured clone writes its whole buffer.
}

main().then(() => {
  console.log();
  if (failures) {
    console.log(`${failures} check(s) FAILED`);
    process.exit(1);
  }
  console.log('All replay-bytes checks passed.');
  process.exit(0);
}).catch((error) => {
  console.error(error);
  process.exit(1);
});
