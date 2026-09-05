/**
 * How much of a frame's dissection is BUILDING the tree, as opposed to reading
 * the bytes?
 *
 *   npx tsx scripts/perf/tree-cost.ts [--fixture inwire|netview]
 *
 * ADR 0001 says the summary pass "must be O(bytes) and allocate no tree nodes",
 * and that migration was never done - `decodeRawEthernetPacket` still builds
 * the full `ProtocolLayer[]` for every frame and the Worker throws ~92% of them
 * away. The obvious conclusion is that not building it would make dissection
 * dramatically cheaper.
 *
 * That is an assumption, and it is a large refactor to act on: every dissector
 * attaches its expert findings to individual `ProtocolField`s, and both
 * `Packet.expert` and `Packet.frameProtocols` are derived by walking the
 * finished tree. So the assumption is worth testing before the refactor rather
 * than after.
 *
 * This counts the tree nodes a real capture actually produces, then times
 * allocating that many equivalent objects. That is an upper bound on what
 * removing the tree can save: the parsing, the checksums, the TCP analysis, the
 * TLS reassembly and the QUIC decryption all have to happen either way, because
 * the summary is derived from them.
 *
 * Requires the fixtures (test/fixtures/README.md); skips cleanly without them.
 */
import { existsSync, readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';
import type { ProtocolField, ProtocolLayer } from '../../src/types/packet';

const FIXTURES: Record<string, string> = {
  inwire: 'test/fixtures/inwire_capture_1788478187989.pcap',
  netview: 'test/fixtures/netview_capture_1788426090876.pcap',
};

function arg(name: string, fallback: string): string {
  const i = process.argv.indexOf('--' + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

const FIXTURE = FIXTURES[arg('fixture', 'inwire')];

/** Layers, fields and nested children, counted separately. */
function countNodes(layers: ProtocolLayer[]): { layers: number; fields: number; strings: number } {
  let fields = 0;
  let strings = 0;
  const visit = (list: ProtocolField[]) => {
    for (const f of list) {
      fields++;
      strings += (f.name?.length ?? 0) + String(f.value ?? '').length;
      if (f.children) visit(f.children);
    }
  };
  for (const l of layers) {
    strings += l.name.length + (l.summary?.length ?? 0);
    visit(l.fields);
  }
  return { layers: layers.length, fields, strings };
}

async function main() {
  if (!existsSync(FIXTURE)) {
    console.log('SKIP  fixture missing: ' + FIXTURE + ' (see test/fixtures/README.md)');
    process.exit(0);
  }

  const buf = readFileSync(FIXTURE);
  // keepTrees, or there is nothing here to count.
  const t0 = performance.now();
  const parsed = await PcapService.parseCaptureFile(
    new File([new Uint8Array(buf)], 'fixture.pcap'), 1_000_000, true,
  );
  const dissectMs = performance.now() - t0;
  const packets = parsed.packets;
  const n = packets.length;

  let totalLayers = 0;
  let totalFields = 0;
  let totalStrings = 0;
  for (const p of packets) {
    const c = countNodes(p.layers);
    totalLayers += c.layers;
    totalFields += c.fields;
    totalStrings += c.strings;
  }

  // Allocate the same shape, the same number of times. Objects with the same
  // key set as ProtocolField, and the strings each one carries, because the
  // strings are allocated per frame too - a field's value is built from the
  // bytes, not shared.
  const fieldsPerFrame = totalFields / n;
  const layersPerFrame = totalLayers / n;
  const charsPerField = totalStrings / totalFields;

  const sink: unknown[] = [];
  const t1 = performance.now();
  for (let frame = 0; frame < n; frame++) {
    const layers: { name: string; summary: string; fields: unknown[] }[] = [];
    for (let l = 0; l < layersPerFrame; l++) {
      const fields: unknown[] = [];
      for (let f = 0; f < fieldsPerFrame / layersPerFrame; f++) {
        fields.push({
          name: 'Field name ' + f,
          value: ('v' + f).padEnd(Math.max(1, Math.round(charsPerField / 2)), 'x'),
        });
      }
      layers.push({ name: 'Layer ' + l, summary: 'summary of layer ' + l, fields });
    }
    if (frame % 2000 === 0) sink.push(layers);   // keep some live, as the cache does
  }
  const allocMs = performance.now() - t1;

  const per = (ms: number) => (ms / n * 1000);
  console.log('fixture                ' + FIXTURE);
  console.log('frames                 ' + n);
  console.log();
  console.log('tree shape, per frame');
  console.log('  layers               ' + layersPerFrame.toFixed(1));
  console.log('  fields (incl nested) ' + fieldsPerFrame.toFixed(1));
  console.log('  chars of value/name  ' + (totalStrings / n).toFixed(0));
  console.log();
  console.log('dissect (tree built)   ' + per(dissectMs).toFixed(2) + ' us/frame');
  console.log('allocating that shape  ' + per(allocMs).toFixed(2) + ' us/frame');
  console.log();
  // The number that decides whether ADR 0001's migration is worth doing for
  // throughput, as opposed to for memory or for the contract's own sake.
  console.log('upper bound on saving  ' + ((per(allocMs) / per(dissectMs)) * 100).toFixed(1)
    + '% of dissection');
  console.log('  i.e. dissection would fall no lower than ~'
    + (per(dissectMs) - per(allocMs)).toFixed(0) + ' us/frame');
  console.log('\n(sink ' + sink.length + ')');
}

main();
