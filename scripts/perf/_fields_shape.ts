import { readFileSync } from 'node:fs';
import { PcapService } from '../../src/services/pcapParser';

const FIXTURES = [
  'test/fixtures/inwire_capture_1788478187989.pcap',
  'test/fixtures/netview_capture_1788426090876.pcap',
];

/**
 * What is in `Packet.fields`, key by key, and how concentrated is the cost?
 *
 * The question this answers: is there a subset of keys whose removal would
 * matter, or is the bag flat? A flat bag cannot be trimmed by dropping
 * features - only by changing how all of it is stored.
 */
async function main() {
  const occurrences = new Map<string, number>();
  const distinctValues = new Map<string, Set<string>>();
  const charCost = new Map<string, number>();
  let frames = 0;
  let entries = 0;

  for (const path of FIXTURES) {
    const parsed = await PcapService.parseCaptureFile(
      new File([new Uint8Array(readFileSync(path))], 'f.pcap'), 1_000_000,
    );
    for (const p of parsed.packets) {
      frames++;
      const bag = p.fields ?? {};
      for (const key of Object.keys(bag)) {
        entries++;
        occurrences.set(key, (occurrences.get(key) ?? 0) + 1);
        const v = bag[key];
        let set = distinctValues.get(key);
        if (!set) { set = new Set(); distinctValues.set(key, set); }
        if (set.size < 200_000) set.add(String(v));
        if (typeof v === 'string') {
          charCost.set(key, (charCost.get(key) ?? 0) + v.length);
        }
      }
    }
  }

  console.log('frames                 ' + frames.toLocaleString());
  console.log('entries                ' + entries.toLocaleString()
    + '   (' + (entries / frames).toFixed(1) + ' per frame)');
  console.log('distinct keys          ' + occurrences.size);
  console.log();

  // An entry costs roughly the same whatever it holds once strings are pooled,
  // so occurrences is the honest proxy for share of the bag.
  const rows = [...occurrences.entries()].sort((a, b) => b[1] - a[1]);
  console.log('the twelve most common keys, and their share of all entries');
  let running = 0;
  for (const [key, count] of rows.slice(0, 12)) {
    running += count;
    console.log('    ' + key.padEnd(30) + String(count).padStart(9)
      + '   ' + ((count / entries) * 100).toFixed(1).padStart(5) + '%'
      + '   running ' + ((running / entries) * 100).toFixed(1) + '%'
      + '   ' + String(distinctValues.get(key)!.size).padStart(7) + ' distinct');
  }
  console.log();

  const processKeys = [...occurrences.keys()].filter(k => k.startsWith('inwire.process.'));
  const processEntries = processKeys.reduce((a, k) => a + (occurrences.get(k) ?? 0), 0);
  console.log('what export actually constrains');
  console.log('    CSV/XLSX (packetToRow) reads       0 keys');
  console.log('    pcapng EPB comment reads           ' + processKeys.length + ' keys: '
    + processKeys.join(', '));
  console.log('    those keys are                     ' + processEntries.toLocaleString()
    + ' entries, ' + ((processEntries / entries) * 100).toFixed(2) + '% of the bag');
  console.log();

  // How flat is it? If half the entries are in a handful of keys, dropping
  // features could matter; if the top twelve are a third, nothing short of a
  // representation change will do.
  const half = (() => {
    let acc = 0;
    for (let i = 0; i < rows.length; i++) {
      acc += rows[i][1];
      if (acc >= entries / 2) return i + 1;
    }
    return rows.length;
  })();
  console.log('concentration');
  console.log('    keys holding the first half of all entries   ' + half
    + ' of ' + occurrences.size);
}
main();
