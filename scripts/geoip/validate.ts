/**
 * Assertion tests for parseGeoResponse.
 *
 *   npx tsx scripts/geoip/validate.ts
 *
 * Two things are being pinned down here.
 *
 * **Rejection.** The version this replaces applied `parseFloat` to whatever
 * arrived and cached the result as a success, so a missing field became NaN
 * coordinates stored as a resolved location, and the provider's 0,0
 * unknown-sentinel became a pin in the Gulf of Guinea. Every `null` expected
 * below is a pin that no longer appears.
 *
 * **Precision.** A record with no city is a country-level answer - the
 * provider knows the country and returned its centroid. That is the single
 * largest source of confidently-wrong pins, and the only thing that lets the
 * map refuse them is this field being derived correctly.
 */
import { parseGeoResponse } from '../../src/services/geoIpService';

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

const IP = '8.8.8.8';

// --- a good city-level record ---------------------------------------------
const city = parseGeoResponse(IP, {
  ip: IP,
  latitude: '32.0853',
  longitude: '34.7818',
  city: 'Tel Aviv',
  region: 'Tel Aviv District',
  country: 'IL',
  country_name: 'Israel',
  country_code: 'IL',
});
check('city-level record resolves', city !== null, true);
check('city-level precision is "city"', city?.precision, 'city');
check('city is kept', city?.city, 'Tel Aviv');
check('country_name is preferred over country', city?.country, 'Israel');
check('country code is kept', city?.countryCode, 'IL');
check('region is kept', city?.region, 'Tel Aviv District');
check('coordinates parse from strings', [city?.latitude, city?.longitude], [32.0853, 34.7818]);

// --- country-only: the Kansas problem -------------------------------------
const countryOnly = parseGeoResponse(IP, {
  ip: IP,
  latitude: '37.751',
  longitude: '-97.822',   // the geographic centre of the United States
  city: '',
  country: 'US',
  country_name: 'United States',
  country_code: 'US',
});
check('country-only record still resolves', countryOnly !== null, true);
check('country-only precision is "country"', countryOnly?.precision, 'country');
check('country-only city is null, not "Unknown"', countryOnly?.city, null);

const missingCity = parseGeoResponse(IP, {
  ip: IP, latitude: 1, longitude: 1, country_name: 'Nowhere',
});
check('an absent city field is country-level too', missingCity?.precision, 'country');

const whitespaceCity = parseGeoResponse(IP, {
  ip: IP, latitude: 1, longitude: 1, city: '   ', country_name: 'Nowhere',
});
check('a whitespace-only city is country-level', whitespaceCity?.precision, 'country');

// --- rejections ------------------------------------------------------------
check('missing coordinates reject', parseGeoResponse(IP, { ip: IP, country_name: 'X' }), null);
check('non-numeric coordinates reject', parseGeoResponse(IP, { latitude: 'abc', longitude: 'def', country_name: 'X' }), null);
check('null coordinates reject', parseGeoResponse(IP, { latitude: null, longitude: null, country_name: 'X' }), null);
check('NaN never becomes a location', parseGeoResponse(IP, { latitude: NaN, longitude: NaN, country_name: 'X' }), null);
check('Null Island rejects', parseGeoResponse(IP, { latitude: 0, longitude: 0, country_name: 'X' }), null);
check('Null Island as strings rejects', parseGeoResponse(IP, { latitude: '0', longitude: '0.0', country_name: 'X' }), null);
check('out-of-range latitude rejects', parseGeoResponse(IP, { latitude: 91, longitude: 0.5, country_name: 'X' }), null);
check('out-of-range longitude rejects', parseGeoResponse(IP, { latitude: 10, longitude: 181, country_name: 'X' }), null);
check('a record with no country rejects', parseGeoResponse(IP, { latitude: 10, longitude: 10 }), null);
check('a non-object rejects', parseGeoResponse(IP, 'not a record'), null);
check('null rejects', parseGeoResponse(IP, null), null);
check('undefined rejects', parseGeoResponse(IP, undefined), null);

// The old 0.1-degree Null Island guard was about 11km wide and threw away real
// places. Accra is at 5.6°N, 0.19°W - close enough to the prime meridian that
// the old filter discarded it, and far enough from 0,0 to be a real location.
const accra = parseGeoResponse(IP, {
  ip: IP, latitude: 5.6037, longitude: -0.187, city: 'Accra', country_name: 'Ghana',
});
check('a real location near the prime meridian is kept', accra?.city, 'Accra');

console.log();
if (failures) {
  console.log(`${failures} check(s) FAILED`);
  process.exit(1);
}
console.log('All checks passed.');
