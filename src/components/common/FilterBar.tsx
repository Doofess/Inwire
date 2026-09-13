import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion } from 'motion/react';
import {
  TbAlertCircle,
  TbX,
  TbBookmark,
  TbSearch,
  TbInfoCircle,
} from 'react-icons/tb';
import { FilterEngine, FilterValidationResult } from '../../services/filterEngine';
import { allPresets } from '../../services/filterPresets';
import { FilterPreset, FilterPresetLibrary } from '../../types/packet';
import type { CaptureFilterState } from '../../lib/useCaptureFilter';

/**
 * Which surface this bar is standing on.
 *
 * A named variant rather than a `compact` boolean, matching `WidgetVariant` in
 * `dashboardWidgets.tsx`: the two differ in more than size, and a boolean
 * called "compact" would be answering the wrong question by the second thing
 * it had to control.
 *
 * `header` is the app header - the full bar, with the packet-search field and
 * the PACKETS count beside it. `compact` is inside a dialog: the same filter
 * field, the same presets, the same validation, and nothing else. The search
 * field is dropped because it filters what is *displayed* in the packet list,
 * which an export knows nothing about, and the count is dropped because the
 * export panel states its own - "412 of 5,231" against a different total.
 */
export type FilterBarVariant = 'header' | 'compact';

interface FilterBarProps {
  filterText: string;
  onFilterChange: (filter: string) => void;
  onApplyFilter: (newFilter?: string) => void;
  variant?: FilterBarVariant;
  /**
   * Both counts are over the CAPTURE, not the RAM window.
   *
   * The same numbers on a capture that fits in memory, and different ones the
   * moment it does not - which is the whole point: "412 / 5,231" while four
   * million frames sit on disk unexamined is an answer to a question nobody
   * asked. `App.tsx` derives them; see `matchesBeforeWindow`.
   */
  totalPackets?: number;
  filteredPackets?: number;
  /**
   * The whole-capture scan behind those numbers. Header variant only.
   *
   * The counts above are worth nothing without it: while a scan is running
   * they describe the RAM window alone, and saying so is the difference
   * between a number that is settling and a number that is wrong.
   */
  filterScan?: CaptureFilterState;
  /** Rows below the window the scan did not reach - a capture that grew. */
  scanUncovered?: number;
  /** Runs the scan again, to take in what the last one missed. */
  onRescan?: () => void;
  /** Required by the `header` variant; unused and omitted by `compact`. */
  packetSearchText?: string;
  onPacketSearchChange?: (text: string) => void;
  /**
   * The preset library, owned by App.tsx and edited in
   * Settings > Display Filters. Read-only here apart from the bookmark button,
   * which appends through `onSaveCurrentFilter` - so the dropdown and the
   * settings panel can never disagree about what exists.
   */
  filterPresetLibrary: FilterPresetLibrary;
  /** Omit to hide the bookmark button - saving a preset from a dialog would
   *  edit library state the dialog does not own. */
  onSaveCurrentFilter?: (filter: string) => void;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filterText,
  onFilterChange,
  onApplyFilter,
  variant = 'header',
  totalPackets = 0,
  filteredPackets = 0,
  filterScan,
  scanUncovered = 0,
  onRescan,
  packetSearchText = '',
  onPacketSearchChange,
  filterPresetLibrary,
  onSaveCurrentFilter,
}) => {
  const isCompact = variant === 'compact';
  const [validation, setValidation] = useState<FilterValidationResult>({ isValid: true });
  const [showPresetsDropdown, setShowPresetsDropdown] = useState(false);
  /**
   * Which completion is highlighted, or -1 for none.
   *
   * The autocomplete this bar used to have was a hand-typed list of twenty-odd
   * example expressions that had drifted out of step with what the engine
   * accepted, so it was removed rather than maintained. It is back because it
   * no longer needs maintaining: the candidates come from the field registry
   * (`FilterEngine.getSuggestions`), so a field becomes completable the moment
   * a dissector registers it and can never be offered after it is retired.
   */
  const [highlighted, setHighlighted] = useState(-1);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const isSearchExpanded = isSearchOpen || packetSearchText.trim().length > 0;

  const clearSearch = () => {
    onPacketSearchChange?.('');
    setIsSearchOpen(false);
  };

  const toggleSearch = () => {
    if (isSearchExpanded) {
      clearSearch();
    } else {
      setIsSearchOpen(true);
      requestAnimationFrame(() => searchInputRef.current?.focus());
    }
  };

  // Validate syntax as the user types.
  useEffect(() => {
    setValidation(FilterEngine.validateFilter(filterText));
  }, [filterText]);

  /**
   * The word being typed, and where it starts.
   *
   * Completion replaces exactly this span, so `tcp.port == 44 && tls.han`
   * completes the second name and leaves the first expression alone.
   */
  const token = useMemo(() => {
    const match = filterText.match(/[A-Za-z0-9_.]*$/);
    const text = match?.[0] ?? '';
    return { text, start: filterText.length - text.length };
  }, [filterText]);

  const suggestions = useMemo(
    () => (token.text.length >= 2 ? FilterEngine.getSuggestions(token.text) : []),
    [token.text],
  );
  // The completions and the presets share the space under the field, so only
  // one can be up. Completing what is half-typed is the more immediate of the
  // two, and the presets are one Escape away.
  const showSuggestions = suggestions.length > 0 && !(suggestions.length === 1 && suggestions[0] === token.text);

  useEffect(() => setHighlighted(-1), [token.text]);

  const acceptSuggestion = (name: string) => {
    const next = filterText.slice(0, token.start) + name + ' ';
    onFilterChange(next);
    setHighlighted(-1);
    inputRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (showSuggestions && (e.key === 'ArrowDown' || e.key === 'ArrowUp')) {
      e.preventDefault();
      const step = e.key === 'ArrowDown' ? 1 : -1;
      setHighlighted(prev => {
        const next = prev + step;
        if (next < 0) return suggestions.length - 1;
        return next >= suggestions.length ? 0 : next;
      });
      return;
    }
    if (e.key === 'Enter') {
      // Enter takes the highlighted completion if there is one, and applies
      // the filter otherwise - so the key never does both, and never applies
      // an expression the user was still in the middle of naming.
      if (showSuggestions && highlighted >= 0) {
        e.preventDefault();
        acceptSuggestion(suggestions[highlighted]);
        return;
      }
      setShowPresetsDropdown(false);
      onApplyFilter();
    } else if (e.key === 'Escape') {
      setShowPresetsDropdown(false);
      setHighlighted(-1);
    }
  };

  const handleSelectPreset = (preset: FilterPreset) => {
    onFilterChange(preset.filter);
    setShowPresetsDropdown(false);
    onApplyFilter(preset.filter);
  };

  const handleSaveCurrentFilter = () => {
    if (!filterText.trim()) return;
    onSaveCurrentFilter?.(filterText);
  };

  /**
   * The two chips inside the filter field.
   *
   * `primary-foreground` on `primary`, which is the pairing every other filled
   * control in the app uses - the tokens move together per theme, so this stays
   * legible on Mono's white accent and on Dracula's purple without either being
   * special-cased here.
   */
  const filterActionClass =
    'flex items-center justify-center h-5 w-5 rounded bg-primary text-primary-foreground '
    + 'hover:bg-primary/90 transition-colors cursor-pointer shrink-0';

  const presetCount = allPresets(filterPresetLibrary).length;
  const isNotEmpty = filterText.trim().length > 0;
  const filterPercentage = totalPackets > 0 ? ((filteredPackets / totalPackets) * 100).toFixed(1) : '100.0';

  // Read out here rather than in the JSX so the badge below stays legible, and
  // so `off` and `ready` are one case: neither has anything to say.
  const scanState = filterScan?.status ?? 'off';
  const scanDone = filterScan?.status === 'scanning' ? filterScan.framesDone : 0;
  const scanTotal = filterScan?.status === 'scanning' ? filterScan.frameCount : 0;
  const scanMessage = filterScan?.status === 'failed' ? filterScan.message : '';

  // Escape closes the presets list from anywhere, which the input's own keydown
  // handler cannot do: the list is opened from a button, so the field often does
  // not have focus while it is up. Registered only while open, and stopped from
  // propagating so one Escape dismisses one thing - without that, the same key
  // would also reach the packet detail window's window-level handler underneath.
  useEffect(() => {
    if (!showPresetsDropdown) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      e.stopPropagation();
      setShowPresetsDropdown(false);
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, [showPresetsDropdown]);

  // Click outside closes the presets list.
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setShowPresetsDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    // Renders inline inside the header rather than as its own row: it has no
    // background, border or vertical padding of its own, and takes the width
    // the header gives it. flex-nowrap because the header is a fixed 4rem
    // tall - wrapping here would push controls out of the bar entirely
    // instead of onto a second line.
    <div
      ref={containerRef}
      className={`relative z-30 min-w-0 ${isCompact ? 'w-full' : 'flex-1'}`}
    >
      <div className="flex flex-nowrap items-center gap-2">
        {/* The filter field, which is now also the preset picker.
            Presets used to be a labelled button of its own to the left of this
            box. Two controls, one job: a preset IS a filter expression, and
            choosing one only ever wrote into this field - so the button was a
            second front door to the thing standing next to it, and the two
            could show different states at the same time. Folded in as a
            combobox chevron at the field's own right edge, which is where a
            text input that also has a list of choices puts one. */}
        <div className="relative flex-1 min-w-[140px]">
          <div
            className={`flex items-center rounded-md border w-full px-3 py-1.5 transition-all shadow-inner bg-background border-border ${
              isNotEmpty && !validation.isValid
                ? '!border-rose-500 bg-rose-100 dark:bg-rose-950/20'
                : isNotEmpty && validation.isValid
                ? '!border-primary/80'
                : ''
            }`}
          >
            {/* Geometric FILTER prefix */}
            <span className="text-primary font-mono text-xs font-bold mr-2.5 select-none shrink-0">
              FILTER:
            </span>

            <input
              ref={inputRef}
              type="text"
              value={filterText}
              onChange={e => {
                onFilterChange(e.target.value);
                // Typing is the decision not to pick a preset. The list would
                // otherwise sit over the packet list for the whole time an
                // expression is being written, hiding the thing being filtered.
                setShowPresetsDropdown(false);
              }}
              // Clicking into the field IS the request to see the presets:
              // one control, one gesture. onClick as well as onFocus, so
              // clicking a field that already has focus reopens the list
              // rather than doing nothing.
              onFocus={() => setShowPresetsDropdown(true)}
              onClick={() => setShowPresetsDropdown(true)}
              onKeyDown={handleKeyDown}
              placeholder='ip.addr == 192.168.1.1 || tcp.port == 443 || proto == http'
              className="bg-transparent outline-none text-xs font-mono w-full text-foreground placeholder:text-muted-foreground"
            />

            {/* Clear and Save, inside the input.
                A primary-coloured Apply tick used to sit at the end of this
                row. It was the only control here that did nothing the rest of
                the bar did not already do: choosing a preset applies it on
                selection, Enter applies a typed expression, and the X applies
                the empty filter - so the tick was a second button for a thing
                that had already happened.

                A chevron used to sit here too, opening the presets. It went the
                same way and for the same reason: clicking the field already
                opens them, so the chevron was a second door onto a room whose
                first door is the whole width of the bar.

                Both survivors are filled rather than bare glyphs. At 12px on
                the inside edge of a field they read as part of the text
                otherwise - the X in particular looked like a character someone
                had typed - and only appear once there is a filter to act on, so
                the field is empty chrome until they have something to do. */}
            <div className="flex items-center gap-1.5 ml-2 shrink-0">
              {isNotEmpty && (
                <button
                  onClick={() => {
                    onFilterChange('');
                    onApplyFilter('');
                  }}
                  className={filterActionClass}
                  title="Clear filter"
                >
                  <TbX className="w-3 h-3" />
                </button>
              )}

              {isNotEmpty && validation.isValid && onSaveCurrentFilter && (
                <button
                  onClick={handleSaveCurrentFilter}
                  className={filterActionClass}
                  title="Save current filter expression"
                >
                  <TbBookmark className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>

          {/* Presets, anchored under the field they write into and matching
              its width rather than the fixed 320px the old popover used. */}
          {showSuggestions && (
            <div className="absolute left-0 right-0 top-full mt-1.5 rounded-lg border p-1 shadow-2xl z-50 bg-popover border-border text-popover-foreground">
              <div className="max-h-64 overflow-y-auto custom-scrollbar">
                {suggestions.map((name, i) => (
                  <button
                    key={name}
                    // mousedown, not click: the input loses focus first
                    // otherwise, which closes this list before the click lands.
                    onMouseDown={e => { e.preventDefault(); acceptSuggestion(name); }}
                    onMouseEnter={() => setHighlighted(i)}
                    className={`w-full text-left px-2.5 py-1 rounded text-[11px] font-mono cursor-pointer ${
                      i === highlighted ? 'bg-accent text-primary' : 'hover:bg-accent/60'
                    }`}
                  >
                    {name}
                  </button>
                ))}
              </div>
            </div>
          )}

          {showPresetsDropdown && !showSuggestions && (
            <div className="absolute left-0 right-0 top-full mt-1.5 rounded-lg border p-1.5 shadow-2xl z-50 transition-all bg-popover border-border text-popover-foreground">
              <div className="text-[10px] font-bold text-muted-foreground px-2 py-1 uppercase tracking-wider flex items-center justify-between font-mono">
                <span>Display Filter Presets</span>
                <span className="text-[10px] text-muted-foreground">{presetCount} presets</span>
              </div>
              {/* Grouped, in the order set in Settings > Display Filters. The
                  group name is a section heading rather than the per-row badge
                  it used to be: with user-defined groups the same badge would
                  have repeated on every row of a section. */}
              <div className="max-h-64 overflow-y-auto space-y-0.5 custom-scrollbar">
                {presetCount === 0 && (
                  <div className="px-2.5 py-3 text-xs text-muted-foreground italic">
                    No presets. Add some in Settings &gt; Display Filters.
                  </div>
                )}
                {filterPresetLibrary.groups.map(group => (
                  group.presets.length === 0 ? null : (
                    <div key={group.id}>
                      <div className="text-[10px] font-bold text-muted-foreground px-2.5 pt-2 pb-1 uppercase tracking-wider font-mono">
                        {group.name}
                      </div>
                      {group.presets.map(p => (
                        <button
                          key={p.id}
                          onClick={() => handleSelectPreset(p)}
                          title={p.description || undefined}
                          className={`w-full text-left px-2.5 py-1.5 rounded text-xs transition-colors flex flex-col cursor-pointer ${
                            filterText === p.filter
                              ? 'bg-accent border border-border text-primary'
                              : 'hover:bg-accent/60'
                          }`}
                        >
                          <span className="font-semibold text-foreground truncate">{p.name}</span>
                          {p.filter ? (
                            <code className="text-[10px] text-primary font-mono mt-0.5 truncate">{p.filter}</code>
                          ) : (
                            <span className="text-[10px] text-muted-foreground italic">No filter (Show All)</span>
                          )}
                        </button>
                      ))}
                    </div>
                  )
                ))}
              </div>
            </div>
          )}

          {/* Syntax Error Notice */}
          {!validation.isValid && validation.errorMessage && (
            <div className="absolute left-0 top-full mt-1.5 z-40 flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 text-[11px] border border-rose-300 dark:border-rose-800 shadow-lg">
              <TbAlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
              <span>{validation.errorMessage}</span>
            </div>
          )}

          {/* A valid expression naming something this build does not dissect.
              It runs, and it will match nothing - which is worth saying, and
              is not an error: the filter is correct, the dissector is missing. */}
          {validation.isValid && validation.warnings && !showSuggestions && (
            <div className="absolute left-0 top-full mt-1.5 z-40 flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 text-[11px] border border-amber-300 dark:border-amber-800 shadow-lg">
              <TbInfoCircle className="w-3.5 h-3.5 shrink-0" />
              <span>{validation.warnings[0]}</span>
            </div>
          )}
        </div>

        {/* Find Packet - quick substring search applied on top of the
            display filter above (relocated from PacketList's own toolbar
            row, which no longer exists). Absent in `compact`: it narrows what
            the packet list DISPLAYS, which is a different question from what
            an export contains. */}
        {!isCompact && <div
          className={`flex items-center gap-1.5 px-1.5 py-1.5 rounded-md border transition-colors overflow-hidden shrink-0 ${
            isSearchExpanded ? 'bg-background border-border' : 'bg-transparent border-transparent'
          }`}
        >
          <button
            onMouseDown={e => e.preventDefault()}
            onClick={toggleSearch}
            title="Find packet"
            // Both states are the same pair now, and that is a simplification
            // the new chrome bought. This used to sit on the saturated `--chrome`
            // header bar when collapsed - where a muted grey all but disappeared -
            // and on its own field when expanded, where `--chrome-foreground`
            // would have been the thing that disappeared. There is no accent bar
            // any more: the filter row is `--background`, so one pair is correct
            // on both surfaces.
            className="p-0.5 shrink-0 rounded transition-colors hover:bg-accent
              text-muted-foreground hover:text-foreground"
          >
            <TbSearch className="w-3.5 h-3.5" />
          </button>
          <motion.input
            ref={searchInputRef}
            type="text"
            placeholder="Find packet (IP, protocol, info)..."
            value={packetSearchText}
            onChange={e => onPacketSearchChange?.(e.target.value)}
            onFocus={() => setIsSearchOpen(true)}
            onBlur={() => {
              if (!packetSearchText.trim()) setIsSearchOpen(false);
            }}
            onKeyDown={e => {
              if (e.key === 'Escape') {
                clearSearch();
                searchInputRef.current?.blur();
              }
            }}
            initial={false}
            animate={{ width: isSearchExpanded ? 224 : 0 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="bg-transparent outline-none text-xs font-mono text-foreground placeholder-muted-foreground"
          />
          {packetSearchText && (
            <button onClick={clearSearch} className="p-0.5 shrink-0 rounded-full hover:bg-accent text-muted-foreground">
              <TbX className="w-3 h-3" />
            </button>
          )}
        </div>}

        {/* Packet Count Status Badge. The compact variant leaves this to its
            host, which counts against a different total.

            The badge carries the scan's state beside the counts rather than
            somewhere else on screen, because the state is a statement ABOUT
            those counts: while a scan runs they describe the RAM window
            alone, and a percentage that quietly changes meaning as the answer
            lands is worse than one that says which question it answered. */}
        {!isCompact && (
          <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-md border shrink-0 bg-background border-border text-foreground/80">
            <span className="text-muted-foreground">PACKETS:</span>
            <span className="font-semibold text-foreground">
              {filteredPackets.toLocaleString()} <span className="text-muted-foreground">/</span> {totalPackets.toLocaleString()}
            </span>
            {scanState === 'scanning' ? (
              <span
                className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 font-bold"
                title={`Filtering the stored capture: ${scanDone.toLocaleString()} of ${scanTotal.toLocaleString()} frames`}
              >
                {/* Indeterminate until the first progress message, which is
                    150,000 frames in - a percentage of an unknown total is a
                    number, and a wrong one. */}
                SCANNING{scanTotal > 0 ? ` ${Math.floor((scanDone / scanTotal) * 100)}%` : ''}
              </span>
            ) : (
              <span className="text-[10px] px-1.5 py-0.2 rounded bg-primary/20 text-primary font-bold">
                {filterPercentage}%
              </span>
            )}
            {scanState === 'failed' && (
              <span
                className="text-[10px] px-1.5 py-0.2 rounded bg-destructive/20 text-destructive font-bold"
                title={scanMessage}
              >
                STORED FRAMES NOT SEARCHED
              </span>
            )}
            {/* A capture that grew after the scan started, which while one is
                running it always does. Clickable rather than automatic: a scan
                that re-ran itself would be a whole-capture pass about once a
                second, competing with the frames still arriving. */}
            {scanUncovered > 0 && onRescan && (
              <button
                type="button"
                onClick={onRescan}
                className="text-[10px] px-1.5 py-0.2 rounded bg-amber-500/20 text-amber-600 dark:text-amber-400 font-bold hover:bg-amber-500/30 transition-colors"
                title={`${scanUncovered.toLocaleString()} stored frames arrived after this filter was run over the capture. Click to run it again.`}
              >
                +{scanUncovered.toLocaleString()} UNSEARCHED
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
