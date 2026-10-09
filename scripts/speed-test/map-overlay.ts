/**
 * The speed test's server on the globe: placed from the test itself, drawn as
 * an overlay, never counted as traffic (ADR 0054).
 *
 *   npx tsx scripts/speed-test/map-overlay.ts
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { coloPlace } from '../../src/services/speedTest/colos';
import { placeServer } from '../../electron/speedTest/engine';
import {
  onMapFocusRequest, overlayArcEnds, requestMapFocus, speedTestOverlay, takeMapFocus,
} from '../../src/services/speedTest/mapOverlay';
import type { SpeedHistoryEntry } from '../../src/services/speedTest/history';
import type { SpeedServer } from '../../src/services/speedTest/protocol';

let failures = 0;
function check(name: string, actual: unknown, expected: unknown): void {
  const pass = JSON.stringify(actual) === JSON.stringify(expected);
  if (!pass) failures++;
  console.log(`${pass ? 'PASS' : 'FAIL'}  ${name}${pass ? '' : `\n        expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`}`);
}

console.log('--- the data-centre table ---');
check('a known code', coloPlace('TLV'), { iata: 'TLV', latitude: 32.01, longitude: 34.89, country: 'IL', city: 'Tel Aviv' });
check('...in lower case, with space around it', coloPlace(' tlv ')?.city, 'Tel Aviv');
check('an unknown code is unknown, not a guess', coloPlace('ZZZ'), null);
check('...and so is nothing', [coloPlace(null), coloPlace(undefined), coloPlace('')], [null, null, null]);
check('a city with an apostrophe survives the table', coloPlace('GND')?.city, "Saint George's");

console.log('\n--- placing the server ---');
const bare: SpeedServer = { colo: null, coloCity: null, coloLat: null, coloLon: null, isp: null, asn: null, ip: null, city: null };
check('/meta\'s own coordinates win',
  placeServer({ ...bare, colo: 'TLV', coloCity: 'Tel Aviv', coloLat: 32.011, coloLon: 34.886 }, 'TLV'),
  { ...bare, colo: 'TLV', coloCity: 'Tel Aviv', coloLat: 32.011, coloLon: 34.886 });
check('without them, the colo header against the table',
  placeServer(bare, 'FRA'),
  { ...bare, colo: 'FRA', coloCity: coloPlace('FRA')!.city, coloLat: coloPlace('FRA')!.latitude, coloLon: coloPlace('FRA')!.longitude });
check('a colo the table does not know stays unplaced', placeServer(bare, 'QQQ'), { ...bare, colo: 'QQQ' });
check('and no colo at all, unplaced', placeServer(bare, null), bare);

console.log('\n--- the overlay ---');
const entry: SpeedHistoryEntry = {
  at: 1_791_550_000_000, downMbps: 1615.6, upMbps: 225.4, pingMs: 2.9, jitterMs: 0.9, grade: 'A',
  server: 'Tel Aviv', isp: 'Bezeq', colo: 'TLV', lat: 32.01, lon: 34.89,
};
const overlay = speedTestOverlay(entry);
check('the latest test, placed', overlay, {
  lngLat: [34.89, 32.01], label: 'Speed test · Cloudflare Tel Aviv',
  summary: '↓ 1616 · ↑ 225 Mb/s · 2.9 ms', at: entry.at,
});
check('no test, no overlay', speedTestOverlay(null), null);
check('a test that was not placed has none', speedTestOverlay({ ...entry, lat: null, lon: null }), null);
check('...nor one placed nowhere on earth', speedTestOverlay({ ...entry, lat: 120 }), null);
check('an arc from home to the server', overlayArcEnds(overlay, { latitude: 31.77, longitude: 35.21 }),
  { from: [35.21, 31.77], to: [34.89, 32.01] });
check('...and none without a home', overlayArcEnds(overlay, null), null);

console.log('\n--- "Show on map" ---');
let heard = 0;
const off = onMapFocusRequest(() => { heard++; });
requestMapFocus([34.89, 32.01]);
check('a request is heard', heard, 1);
check('...taken once', [takeMapFocus(), takeMapFocus()], [[34.89, 32.01], null]);
off();

console.log('\n--- an overlay, not traffic ---');
const geo = readFileSync('src/components/analytics/GeoMap.tsx', 'utf8');
const lines = geo.split('\n');
// Whatever the map counts, lists or exports is built from `routes`, `locations`
// and the pins; the overlay must touch none of them.
const leaks = lines.filter((l) => /speed(Overlay|History|ArcRef)/.test(l)
  && /\b(routes|locations|pins\.push|legend|topRoutes|aggregateRoutes|placeCount|setPins)\b/.test(l));
check('nothing that counts, lists or exports reads the overlay', leaks, []);
const setArcs = lines.filter((l) => /layer\.setArcs\(/.test(l));
check('the arc joins only at the arc layer\'s final setArcs', setArcs.length === 1 && /speedArcs/.test(setArcs[0]), true);
check('...where the routes\' own arcs are unchanged by it', /arcsForSync\(\)/.test(setArcs[0] ?? ''), true);

// The table is the engine's: the window's bundle never carries it.
const importers: string[] = [];
const walk = (dir: string) => {
  for (const name of readdirSync(dir)) {
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) walk(full);
    else if (/\.tsx?$/.test(name) && /speedTest\/colos'/.test(readFileSync(full, 'utf8'))) importers.push(full.split(path.sep).join('/'));
  }
};
walk('src');
check('nothing in the renderer imports the data-centre table', importers, []);

console.log(failures === 0 ? '\nAll map-overlay checks passed.' : `\n${failures} check(s) FAILED`);
process.exit(failures === 0 ? 0 : 1);
