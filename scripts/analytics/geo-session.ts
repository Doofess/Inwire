/**
 * Assertion tests for the geo map's session state.
 *
 *   npx tsx scripts/analytics/geo-session.ts
 *
 * The session holds what the map has learned - the places seen, the addresses
 * already asked about, the city-level locations the pins are drawn from - at
 * module scope rather than in the component, so minimising the dashboard does
 * not throw it away and re-ask a third party where the user is.
 *
 * That makes `resetGeoSession` the only way any of it goes away, and it had a
 * bug worth a test: it **replaced** the session object. `GeoMap` takes the
 * session once, in a `useRef` at mount, so a map that was already open went on
 * reading the object that had just been abandoned - the reset reached nothing
 * on screen. Clearing the buffer left the previous capture's pins standing
 * while its arcs vanished, because the arcs are folded from the packet buffer
 * and had really emptied.
 *
 * So what is held here is identity as much as emptiness: a reset must be
 * visible through a reference taken beforehand, which is the whole failure.
 */
import {
  geoSession, onGeoSessionReset, resetGeoSession,
} from '../../src/components/analytics/geoSession';

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
function checkTrue(name: string, condition: boolean) { check(name, condition, true); }

const location = (lat: number, lon: number) => ({
  ip: '93.184.216.34', latitude: lat, longitude: lon,
  city: 'Somewhere', country: 'Nowhere', countryCode: 'XX',
} as never);

// --- A reset reaches a reference taken before it -------------------------------
//
// This is the bug. `GeoMap` captures the session in a `useRef` at mount, so a
// reset that swaps the module's object leaves every mounted map reading the old
// one - and the pins, which are drawn from `locations`, stay on screen.
{
  const held = geoSession();          // what a mounted component would hold
  held.locations.set('93.184.216.34', location(51.5, -0.1));
  held.places.set('51.5,-0.1', { key: '51.5,-0.1', city: 'Somewhere', country: 'Nowhere', countryCode: 'XX', count: 1 } as never);
  held.seenIps.add('93.184.216.34');
  held.unresolved.add('10.0.0.1');
  held.hostnames.set('93.184.216.34', 'example.invalid');
  held.scan.scannedCount = 1234;
  held.scan.firstPacketId = 7;

  resetGeoSession();

  checkTrue('the reference taken before the reset is the same object',
    geoSession() === held);
  check('...and its locations are gone, which is what the pins are drawn from',
    held.locations.size, 0);
  check('...its places too, which is what the counter shows', held.places.size, 0);
  check('...the addresses already asked about', held.seenIps.size, 0);
  check('...the ones that resolved to nothing', held.unresolved.size, 0);
  check('...and the hostnames', held.hostnames.size, 0);
  check('the scan starts again from the beginning',
    [held.scan.firstPacketId, held.scan.scannedCount], [-1, 0]);
}

// --- The camera survives, because it is not about packets ------------------------
{
  const session = geoSession();
  session.camera = { center: [12.5, 41.9], zoom: 6 };
  session.locations.set('1.1.1.1', location(41.9, 12.5));
  resetGeoSession();
  check('clearing the buffer does not fly the map home',
    session.camera, { center: [12.5, 41.9], zoom: 6 });
  check('...but the capture it was showing is gone', session.locations.size, 0);
}

// --- Mounted maps are told, so they can re-render ---------------------------------
//
// Emptying the maps fixes what the data says; a component that copied them into
// React state when it learned them still has to be told to look again.
{
  let notified = 0;
  const unsubscribe = onGeoSessionReset(() => { notified++; });
  resetGeoSession();
  check('a listener is called on reset', notified, 1);
  resetGeoSession();
  check('...every time', notified, 2);

  // The session is already empty by the time a listener runs, or it would copy
  // the old maps straight back into the component's state.
  let sizeWhenNotified = -1;
  const unsubscribe2 = onGeoSessionReset(() => { sizeWhenNotified = geoSession().locations.size; });
  geoSession().locations.set('8.8.8.8', location(37.4, -122.1));
  resetGeoSession();
  check('the session is empty before listeners run', sizeWhenNotified, 0);

  unsubscribe();
  unsubscribe2();
  const before = notified;
  resetGeoSession();
  check('an unsubscribed listener is not called', notified, before);
}

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All geo-session checks passed.');
process.exit(0);
