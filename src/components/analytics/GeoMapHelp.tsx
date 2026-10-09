import React from 'react';
import { CircleQuestionMark } from 'lucide-react';
import { Popover, PopoverArrow, PopoverContent, PopoverTrigger } from '../ui/popover';

/**
 * What the map is showing, how to move the camera, and who the tiles belong to.
 *
 * This replaced MapLibre's compact attribution control - the (i) in the same
 * corner - and is a strictly better trade for the same square of space. That
 * control could only ever say one thing, the credit, and the credit is the
 * least useful thing anybody clicking a question mark on a map wants to know.
 * The gestures are the useful thing, and two of them are not guessable: the
 * rotate gesture is right-drag, and this map deliberately turns the opposite
 * way to every other MapLibre map (see the drag-to-rotate effect in GeoMap).
 *
 * The credit is still here, at the bottom, because it is a licence condition
 * rather than a nicety - OpenStreetMap's terms require it and OpenFreeMap
 * serves these tiles for nothing. Shortened to the two names that have to
 * appear: the full copyright line was three wrapped lines of legal text where
 * the map should be, which it had to be short enough to survive at the 256px
 * card size this panel once also had to fit. There is one map size now and the
 * short form is still the right one.
 */

const GESTURES: [string, string][] = [
  ['Pan', 'Drag with the left button'],
  ['Zoom', 'Scroll - on the globe it holds the centre, on the flat map it comes to the pointer'],
  ['Rotate and tilt', 'Right-drag, or Ctrl / ⌘ with the left button'],
  ['Undo rotate and tilt', 'Double right-click - level again, north up, where you are'],
  ['Projection', 'The globe button below switches between the sphere and the flat map'],
];

export const GeoMapHelp: React.FC = () => (
  <Popover>
    <PopoverTrigger asChild>
      <button
        type="button"
        aria-label="About this map"
        title="About this map"
        // The same shell as ZoomControls and the location counter, so every
        // floating control on this map is recognisably one kind of object.
        className={
          'absolute right-2 top-2 z-10 flex h-7 w-7 items-center justify-center rounded-full '
          + 'border border-border bg-card/80 text-muted-foreground shadow-sm backdrop-blur-sm '
          + 'transition-colors hover:bg-accent hover:text-foreground active:scale-95 cursor-pointer'
        }
      >
        <CircleQuestionMark className="h-4 w-4" />
      </button>
    </PopoverTrigger>
    <PopoverContent side="bottom" align="end" className="w-72 p-3.5">
      <PopoverArrow />
      <h3 className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
        The map
      </h3>
      <p className="mt-1 text-xs leading-relaxed text-foreground">
        Every pin is an address in the capture that resolved to a place. Arcs join the two ends
        of a connection, and leave the surface so crossing paths stay apart. Your own network is
        the green pin.
      </p>

      <h3 className="mt-3.5 text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
        Camera
      </h3>
      <dl className="mt-1 space-y-1.5">
        {GESTURES.map(([action, how]) => (
          <div key={action}>
            <dt className="text-xs font-semibold text-foreground">{action}</dt>
            <dd className="text-[11px] leading-snug text-muted-foreground">{how}</dd>
          </div>
        ))}
      </dl>

      {/* The licence condition, kept to the two names that have to appear. */}
      <p className="mt-3.5 border-t border-border pt-2 text-[10px] leading-snug text-muted-foreground">
        Tiles{' '}
        <a
          href="https://openfreemap.org/"
          target="_blank"
          rel="noreferrer"
          className="underline underline-offset-2 hover:text-foreground"
        >
          OpenFreeMap
        </a>
        , data &copy;{' '}
        <a
          href="https://www.openstreetmap.org/copyright"
          target="_blank"
          rel="noreferrer"
          className="underline underline-offset-2 hover:text-foreground"
        >
          OpenStreetMap
        </a>
      </p>
    </PopoverContent>
  </Popover>
);
