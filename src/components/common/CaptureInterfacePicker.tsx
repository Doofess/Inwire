import React from 'react';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
import { shortInterfaceLabel } from '../../services/captureInterfaces';
import { Sparkline } from './Sparkline';

// A silent adapter still draws a short baseline stub rather than nothing, so
// the column reads as "no traffic" instead of "no chart here".
const MIN_SPARKLINE_WIDTH = 26;
// The ceiling. The menu is w-72 (288px); after the row's padding and the radio
// indicator that leaves roughly 240px, so stopping at 130 keeps a clear gap
// between the busiest chart and the interface name beside it.
const MAX_SPARKLINE_WIDTH = 130;

interface CaptureInterfacePickerProps {
  interfaces: { name: string; label: string }[];
  selectedInterface: string | null;
  onSelect: (interfaceName: string) => void;
  children: React.ReactNode;
  align?: 'start' | 'center' | 'end';
  /**
   * Which edge the menu opens from.
   *
   * `'right'` since the trigger moved into the activity rail: a 56px strip
   * has no room for a 288px menu below it, and Radix flips a `bottom` menu
   * to wherever it fits, which is not a decision worth leaving to a
   * collision.
   */
  side?: 'top' | 'bottom' | 'left' | 'right';
  /** Recent packets/sec per interface name, oldest sample first. */
  interfaceRates?: Record<string, number[]>;
  /**
   * Called with true when the menu opens and false when it closes. The agent
   * samples adapter counters only while somebody is subscribed, so this is
   * what keeps the sampling scoped to a menu that is actually on screen.
   */
  onOpenChange?: (open: boolean) => void;
}

/**
 * Wraps a Start Capture control so pressing it asks which adapter to capture
 * from instead of silently reusing whatever was selected last.
 *
 * Capture is single-interface: picking here replaces the selection outright
 * rather than adding to it, which is why this is a radio group and not the
 * checkbox list this UI used to carry. The agent's `set_interfaces` still
 * takes an array - it just always receives exactly one name now.
 *
 * The caller is responsible for NOT wrapping its control in this when the
 * interface list is empty: an agent that has not connected yet has no
 * adapters to offer, and a picker with nothing in it would leave the user
 * with a Start button that cannot start anything.
 */
export const CaptureInterfacePicker: React.FC<CaptureInterfacePickerProps> = ({
  interfaces,
  selectedInterface,
  onSelect,
  children,
  align = 'center',
  side = 'bottom',
  interfaceRates,
  onOpenChange,
}) => {
  // One scale across every sparkline. Scaled individually, an adapter idling
  // at 2 packets/sec would draw the same mountain as the one carrying the
  // capture, which inverts the one comparison this list exists to support.
  const peakRate = Math.max(
    0,
    ...Object.values(interfaceRates ?? {}).flatMap((series) => series),
  );

  /**
   * How wide to draw one adapter's sparkline, in px.
   *
   * A busy adapter earns more room than a silent one, so the list can be read
   * by shape alone before any of the labels are: at a glance the widest line
   * is the one worth capturing on. Growth is bounded well short of the menu
   * width so the chart stops before it crowds the interface name - the label
   * keeps its space rather than truncating to make room for a decoration.
   */
  const sparklineWidth = (name: string): number => {
    const series = interfaceRates?.[name] ?? [];
    if (!series.length || peakRate <= 0) return MIN_SPARKLINE_WIDTH;
    // The window's peak rather than the newest sample: sizing off the latest
    // value alone makes the chart flap between wide and narrow every 500ms on
    // traffic that is merely bursty.
    const ratio = Math.max(...series) / peakRate;
    // Square root rather than linear, so an adapter carrying a tenth of the
    // busiest one's traffic still visibly grows instead of staying a stub.
    const eased = Math.sqrt(Math.min(Math.max(ratio, 0), 1));
    return MIN_SPARKLINE_WIDTH + eased * (MAX_SPARKLINE_WIDTH - MIN_SPARKLINE_WIDTH);
  };

  return (
    <DropdownMenu onOpenChange={onOpenChange}>
      <DropdownMenuTrigger asChild>{children}</DropdownMenuTrigger>
      {/* border-0 drops the outline the shared primitive draws: under the mono
          theme --border is near-white, which put a hard white rectangle around
          this menu. The heavier shadow keeps the panel separated from the page
          without it - which matters in the light theme, where the popover and
          the background are both close to white. */}
      <DropdownMenuContent
        align={align}
        side={side}
        className="w-72 max-h-80 overflow-y-auto custom-scrollbar border-0 shadow-lg"
      >
        <DropdownMenuLabel className="text-[10px] font-bold uppercase tracking-wider font-mono text-muted-foreground">
          Capture from
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuRadioGroup
          // A null selection has to become '' rather than staying null:
          // Radix treats the group as uncontrolled when value is undefined,
          // which would let it track its own selection separately from ours.
          value={selectedInterface ?? ''}
          onValueChange={onSelect}
        >
          {interfaces.map((iface) => (
            // Short name in the row, full label in the tooltip: the driver
            // description is what makes these unreadable, and three of this
            // machine's adapters differ only inside their parentheses.
            <DropdownMenuRadioItem
              key={iface.name}
              value={iface.name}
              title={iface.label}
              // The theme's accent, not the success green. Green means "this is
              // healthy" everywhere else in the app - the agent link, the
              // capture state - and using it for "this is the one you picked"
              // makes a chosen adapter look like a passing check. Selection is
              // the accent's job, which is what --primary is for.
              // The selected adapter reads as selected even while the pointer
              // is somewhere else in the list, which a focus-only highlight
              // cannot do - and it is the one thing worth knowing at a glance
              // when reopening this menu mid-session.
              //
              // The success colour rather than the theme accent, matching the
              // Interfaces button's own green-once-chosen state: the row and the
              // button it opens from are showing the same fact, so they say it
              // the same way - and now in the same colour, per theme, instead of
              // a hardcoded emerald that only agreed with the button by
              // coincidence. `success-muted` for the text, which is the variant
              // guaranteed readable on a card rather than on the fill.
              className="group cursor-pointer data-[state=checked]:bg-primary/15 data-[state=checked]:text-primary data-[state=checked]:font-semibold"
            >
              {/* Accent bar, drawn only for the selected row. Scales out of
                  the left edge rather than appearing, so the selection reads
                  as moving between rows. */}
              <span
                aria-hidden
                className="absolute left-0 top-1 bottom-1 w-0.5 origin-center scale-y-0 rounded-full bg-primary transition-transform duration-150 ease-out group-data-[state=checked]:scale-y-100"
              />
              <span className="flex-1 truncate transition-transform duration-150 ease-out group-hover:translate-x-0.5">
                {shortInterfaceLabel(iface.label)}
              </span>
              {/* Live traffic on that adapter, the way the reference analyzer's welcome
                  screen shows it - so an adapter can be ruled in or out before
                  committing to a capture on it. Muted until the row is
                  selected, so the list reads as names first and charts
                  second. */}
              <Sparkline
                values={interfaceRates?.[iface.name] ?? []}
                max={peakRate}
                width={sparklineWidth(iface.name)}
                // Matches App.tsx's INTERFACE_RATE_SAMPLES, so a full history
                // exactly fills the chart and no sample is ever squeezed.
                capacity={30}
                className="shrink-0 text-muted-foreground group-data-[state=checked]:text-primary"
              />
            </DropdownMenuRadioItem>
          ))}
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  );
};
