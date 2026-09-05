import React, { useEffect, useRef, useState } from 'react';
import { TbMapPin, TbMapPinOff, TbChevronUp } from 'react-icons/tb';

/**
 * One PLACE, not one host.
 *
 * Keyed by rounded coordinates for the same reason the routes are: ten servers
 * in one datacentre are one place, and counting them as ten would answer a
 * question nobody asked.
 */
export interface GeoPlace {
  /**
   * Stable identity across the session: rounded `lat,lon` for a city-level
   * place, the country code for a country-level one - so every host the
   * provider could only put in Germany collapses to a single Germany row rather
   * than one per address.
   */
  key: string;
  latitude: number;
  longitude: number;
  /** The city, or the country when that is as precise as the lookup got. */
  label: string;
  country: string;
  countryCode: string;
  /** Distinct addresses resolved to this place so far. */
  hosts: number;
  /**
   * `country` rows are listed but never plotted.
   *
   * A country-level answer is the provider's centroid for the whole country - a
   * real coordinate, but not this host's - so drawing it would put a pin in a
   * field in Kansas and give it the same weight as a real fix. That is the
   * accuracy rule the map is built on and it does not change. What changes is
   * that these are no longer reported as a bare count of things withheld: "31
   * hidden" tells you nothing you can act on, while "Germany, 4 hosts" is the
   * actual answer to where the traffic went, just at a coarser resolution than
   * the map can honestly draw.
   */
  precision: 'city' | 'country';
}

interface GeoLocationCounterProps {
  /** Distinct places seen since the session began, plotted or not. */
  places: GeoPlace[];
  /** Hosts the provider had nothing usable for at all. */
  unresolved: number;
  /**
   * Whether the counter may open into the full list.
   *
   * False in the compact card. The list is the same information at a size that
   * cannot show it: the card is 256px tall, so a panel deep enough to be worth
   * opening would cover the map it describes. Expanding the map is what makes
   * room for it, so that is where it lives.
   */
  expandable?: boolean;
  /** Centres the map on a place picked from the list. */
  onSelectPlace?: (place: GeoPlace) => void;
}

/**
 * How many places have talked to this machine, and - once the map is expanded -
 * which ones.
 *
 * Monotonic across the session rather than a live gauge of what is currently on
 * screen: the question it answers is "how many places have I been in contact
 * with", and a number that fell as older traffic aged out would answer a
 * different one.
 *
 * The tooltip carries what the headline number deliberately leaves out. The map
 * refuses to plot anything the provider could only place at country level -
 * that suppression is the whole point of the accuracy work, but silent
 * suppression is indistinguishable from a broken lookup, so the counts of what
 * was withheld and why live one hover away, and in the panel's own footer.
 */
export const GeoLocationCounter: React.FC<GeoLocationCounterProps> = ({
  places,
  unresolved,
  expandable = false,
  onSelectPlace,
}) => {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);

  const count = places.length;
  const countryOnly = places.filter((p) => p.precision === 'country').length;

  const detail = [
    `${count} distinct ${count === 1 ? 'location' : 'locations'} this session`,
    countryOnly > 0
      ? `${countryOnly} of them located to a country only, so not drawn on the map`
      : null,
    unresolved > 0
      ? `${unresolved} host${unresolved === 1 ? '' : 's'} could not be located at all`
      : null,
  ]
    .filter(Boolean)
    .join('\n');

  // Collapsing the map must close the list with it - otherwise the panel is
  // left hanging over a card far too short to hold it.
  useEffect(() => {
    if (!expandable) setOpen(false);
  }, [expandable]);

  // Escape and a click anywhere else, which is what every other transient
  // surface in the app answers to. Registered only while open, so the map keeps
  // its own handlers the rest of the time.
  useEffect(() => {
    if (!open) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      // Stopped here so the same keystroke does not also collapse the expanded
      // map behind this panel - one Escape, one thing dismissed.
      e.stopPropagation();
      setOpen(false);
    };
    const onPointerDown = (e: PointerEvent) => {
      if (rootRef.current?.contains(e.target as Node)) return;
      setOpen(false);
    };
    window.addEventListener('keydown', onKeyDown, true);
    window.addEventListener('pointerdown', onPointerDown, true);
    return () => {
      window.removeEventListener('keydown', onKeyDown, true);
      window.removeEventListener('pointerdown', onPointerDown, true);
    };
  }, [open]);

  // Plotted places first, then busiest, then by name.
  //
  // Precision leads because it is the difference between a row that takes you
  // somewhere and one that cannot: the country-level entries are the only rows
  // in this list with no marker to fly to, so grouping them at the bottom keeps
  // the clickable half of the list contiguous instead of interleaving two
  // kinds of row. Within each group, busiest first - a place reached by thirty
  // hosts is a different answer from one reached by a single stray lookup - and
  // then by name, so the order is deterministic rather than dependent on which
  // lookup happened to settle first.
  const ordered = [...places].sort(
    (a, b) =>
      Number(a.precision === 'country') - Number(b.precision === 'country') ||
      b.hosts - a.hosts ||
      a.label.localeCompare(b.label),
  );

  const pill = (
    <>
      <TbMapPin className="h-3 w-3 shrink-0 text-primary" />
      <span className="tabular-nums font-bold">{count.toLocaleString()}</span>
      <span className="text-muted-foreground uppercase tracking-wider">
        {count === 1 ? 'location' : 'locations'}
      </span>
    </>
  );

  const pillClass =
    'flex items-center gap-1.5 rounded-md border border-border bg-card/80 px-2 py-1 backdrop-blur-sm font-mono text-[10px] text-foreground shadow-sm';

  return (
    <div
      ref={rootRef}
      // Sits in the one corner of the canvas nothing else claims: the nav
      // control is top-right and attribution is disabled.
      className="absolute bottom-2 left-2 z-10 pointer-events-auto"
    >
      {/* Opens UPWARD. Anchored to the pill's top edge rather than its bottom,
          because the pill is already sitting on the floor of the map - a menu
          dropping from it would open straight off the canvas. */}
      {open && (
        <div className="absolute bottom-full left-0 mb-1 w-64 max-w-[min(16rem,calc(100vw-2rem))] overflow-hidden rounded-md border border-border bg-card/95 shadow-lg backdrop-blur-sm">
          <div className="border-b border-border px-2.5 py-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            Pinged this session
          </div>

          <ul className="max-h-64 overflow-y-auto custom-scrollbar">
            {ordered.length === 0 && (
              <li className="px-2.5 py-3 text-center font-mono text-[10px] text-muted-foreground">
                Nothing located yet.
              </li>
            )}
            {ordered.map((place) => {
              const hostCount = `${place.hosts} host${place.hosts === 1 ? '' : 's'}`;
              const plotted = place.precision === 'city';

              const body = (
                <>
                  {/* Country-only rows carry a struck-through pin, which is the
                      one thing that explains why they do not respond to a click
                      when the rows above them do. */}
                  {!plotted && (
                    <TbMapPinOff className="h-3 w-3 shrink-0 self-center text-muted-foreground" />
                  )}
                  <span
                    className={`min-w-0 flex-1 truncate ${plotted ? 'text-foreground' : 'text-muted-foreground'}`}
                  >
                    {place.label}
                  </span>
                  <span className="shrink-0 text-[9px] uppercase tracking-wider text-muted-foreground">
                    {place.countryCode || place.country}
                  </span>
                  {/* Only shown when it says something the row does not: one
                      host per place is the common case. */}
                  {place.hosts > 1 && (
                    <span className="shrink-0 tabular-nums text-[10px] font-bold text-muted-foreground">
                      {place.hosts}
                    </span>
                  )}
                </>
              );

              const rowClass = 'flex w-full items-baseline gap-2 px-2.5 py-1.5 text-left font-mono text-[11px]';

              return (
                <li key={place.key}>
                  {plotted ? (
                    <button
                      type="button"
                      onClick={() => {
                        onSelectPlace?.(place);
                        setOpen(false);
                      }}
                      className={`${rowClass} transition-colors hover:bg-accent cursor-pointer`}
                      title={`${place.label}, ${place.country} - ${hostCount}`}
                    >
                      {body}
                    </button>
                  ) : (
                    // Not a button: there is no marker to fly to. Flying to the
                    // provider's country centroid would put the camera on the
                    // exact coordinate the map refuses to draw a pin at.
                    <div
                      className={rowClass}
                      title={`${place.country} - ${hostCount}. Located to country level only, so not drawn on the map.`}
                    >
                      {body}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>

          {/* Country-level places used to be reported here as a bare count of
              things withheld. They are rows in the list now, so the only thing
              left for this footer is what genuinely has nowhere to go. */}
          {unresolved > 0 && (
            <div className="border-t border-border px-2.5 py-1.5 font-mono text-[9px] leading-relaxed text-muted-foreground">
              {unresolved} host{unresolved === 1 ? '' : 's'} could not be located
            </div>
          )}
        </div>
      )}

      {expandable ? (
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
          className={`${pillClass} transition-colors hover:bg-card cursor-pointer`}
          title={detail}
        >
          {pill}
          <TbChevronUp
            className={`h-3 w-3 shrink-0 text-muted-foreground transition-transform ${open ? 'rotate-180' : ''}`}
          />
        </button>
      ) : (
        <div className={pillClass} title={detail}>
          {pill}
        </div>
      )}
    </div>
  );
};
