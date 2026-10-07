/**
 * Absolute times as the reference writes them in a tree:
 * `Oct  7, 2026 02:39:32.311738200 Israel Daylight Time`.
 *
 * The Frame layer's arrival times, and any protocol that carries a wall-clock
 * time of its own (OpenVPN's tls-auth timestamp), format through here - so a
 * protocol module need not import the parser that imports it.
 */
/**
 * The two formatters, built once.
 *
 * `new Intl.DateTimeFormat(...)` was being constructed inside
 * `formatArrivalTime`, which is called twice for every frame - so a 12,858
 * frame capture built 25,716 of them. Constructing one is among the most
 * expensive things in the language: it resolves a locale and sets up ICU, and
 * it measured at ~49 us a call. A CPU profile of a full dissection put this one
 * function at **38% of the entire profile, and more than half of all dissection
 * time** - far and away the largest single cost in the pipeline, for two rows
 * of a tree that 92% of frames never show anyone.
 *
 * Lazily, because the locale data load is not work to do at module init in a
 * Worker that may never dissect anything.
 */
let localArrivalFormat: Intl.DateTimeFormat | undefined;
let utcArrivalFormat: Intl.DateTimeFormat | undefined;

function arrivalFormatter(utc: boolean): Intl.DateTimeFormat {
  if (utc) {
    utcArrivalFormat ??= new Intl.DateTimeFormat('en-US', {
      month: 'short', day: 'numeric', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false, timeZone: 'UTC', timeZoneName: 'long',
    });
    return utcArrivalFormat;
  }
  localArrivalFormat ??= new Intl.DateTimeFormat('en-US', {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
    hour12: false, timeZoneName: 'long',
  });
  return localArrivalFormat;
}

/**
 * The formatted text for one whole second, kept so the next frame in it is free.
 *
 * Caching the `Intl.DateTimeFormat` OBJECT (above) removed the cost of building
 * one per frame. It did not remove the cost of USING one: `formatToParts` is an
 * ICU call that allocates a part array, and a later profile still put this
 * function at **15.2% of the entire pipeline** - the largest single item in it,
 * ahead of the whole TCP transport decoder.
 *
 * Everything it produces except the fractional digits is a function of the
 * whole second: the date, the wall clock to the second, and the zone name. A
 * capture delivers thousands of frames inside one of those - the fixture
 * averages ~3,300 a second and bursts past 9,000 - so a single-entry cache per
 * formatter hits essentially always, and misses only on the second boundary.
 *
 * Keyed on the second rather than the day, which costs nothing extra and is
 * what makes a DST transition come out right: the zone name is re-resolved
 * whenever the second changes, so the frame either side of the change is
 * formatted by ICU rather than by an assumption about how often zones move.
 */
interface ArrivalSecond {
  second: number;
  /** "Sep 11, 2026 00:13:50" - everything before the fractional part. */
  head: string;
  /** The zone name, which follows the fractional part. */
  zone: string;
}

let localArrivalSecond: ArrivalSecond | undefined;
let utcArrivalSecond: ArrivalSecond | undefined;

function arrivalSecond(tsUs: number, utc: boolean): ArrivalSecond {
  const second = Math.floor(tsUs / 1_000_000);
  const cached = utc ? utcArrivalSecond : localArrivalSecond;
  if (cached !== undefined && cached.second === second) return cached;

  const parts = arrivalFormatter(utc).formatToParts(new Date(second * 1000));
  // One pass over the parts rather than a `find` per field: there are six
  // fields and about ten parts, so the old form was sixty scans a frame.
  let month = '', day = '', year = '', hour = '', minute = '', sec = '', zone = '';
  for (const p of parts) {
    switch (p.type) {
      case 'month': month = p.value; break;
      case 'day': day = p.value; break;
      case 'year': year = p.value; break;
      case 'hour': hour = p.value; break;
      case 'minute': minute = p.value; break;
      case 'second': sec = p.value; break;
      case 'timeZoneName': zone = p.value; break;
    }
  }
  const fresh: ArrivalSecond = {
    second,
    // The day is space-padded to two (`Oct  7, 2026`), as the reference's
    // `%e` writes it - unpadded, the first nine days of every month differed.
    head: `${month} ${day.padStart(2, ' ')}, ${year} ${hour}:${minute}:${sec}`,
    // The reference writes the local zone out in full and UTC as `UTC`, which
    // Intl would spell "Coordinated Universal Time".
    zone: utc ? 'UTC' : zone,
  };
  if (utc) utcArrivalSecond = fresh; else localArrivalSecond = fresh;
  return fresh;
}

/**
 * The reference's arrival-time format: `Aug 25, 2026 20:16:40.351587600
 * Jerusalem Daylight Time`, the zone spelled out by Intl because that is what
 * the reference prints. The digits past the microsecond are the capture's own
 * when it measured them, and zeros when it did not - unknown, not invented.
 */
export function formatArrivalTime(tsUs: number, utc = false, nanosRemainder = 0): string {
  const { head, zone } = arrivalSecond(tsUs, utc);
  const fractional = String((tsUs % 1_000_000) * 1000 + nanosRemainder).padStart(9, '0');
  return `${head}.${fractional} ${zone}`;
}
