import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'motion/react';
import {
  TbAlertCircle,
  TbX,
  TbBookmark,
  TbSearch,
} from 'react-icons/tb';
import { FilterEngine, FilterValidationResult } from '../../services/filterEngine';
import { allPresets } from '../../services/filterPresets';
import { FilterPreset, FilterPresetLibrary } from '../../types/packet';

interface FilterBarProps {
  filterText: string;
  onFilterChange: (filter: string) => void;
  onApplyFilter: (newFilter?: string) => void;
  totalPackets: number;
  filteredPackets: number;
  packetSearchText: string;
  onPacketSearchChange: (text: string) => void;
  /**
   * The preset library, owned by App.tsx and edited in
   * Settings > Display Filters. Read-only here apart from the bookmark button,
   * which appends through `onSaveCurrentFilter` - so the dropdown and the
   * settings panel can never disagree about what exists.
   */
  filterPresetLibrary: FilterPresetLibrary;
  onSaveCurrentFilter: (filter: string) => void;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filterText,
  onFilterChange,
  onApplyFilter,
  totalPackets,
  filteredPackets,
  packetSearchText,
  onPacketSearchChange,
  filterPresetLibrary,
  onSaveCurrentFilter,
}) => {
  const [validation, setValidation] = useState<FilterValidationResult>({ isValid: true });
  const [showPresetsDropdown, setShowPresetsDropdown] = useState(false);
  const [isSearchOpen, setIsSearchOpen] = useState(false);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);
  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const isSearchExpanded = isSearchOpen || packetSearchText.trim().length > 0;

  const clearSearch = () => {
    onPacketSearchChange('');
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

  // Validate syntax as user types. The autocomplete that used to be computed
  // here is gone - see the field below.
  useEffect(() => {
    setValidation(FilterEngine.validateFilter(filterText));
  }, [filterText]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      setShowPresetsDropdown(false);
      onApplyFilter();
    } else if (e.key === 'Escape') {
      setShowPresetsDropdown(false);
    }
  };

  const handleSelectPreset = (preset: FilterPreset) => {
    onFilterChange(preset.filter);
    setShowPresetsDropdown(false);
    onApplyFilter(preset.filter);
  };

  const handleSaveCurrentFilter = () => {
    if (!filterText.trim()) return;
    onSaveCurrentFilter(filterText);
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
      className="relative z-30 flex-1 min-w-0"
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

              {isNotEmpty && validation.isValid && (
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
          {showPresetsDropdown && (
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
        </div>

        {/* Find Packet - quick substring search applied on top of the
            display filter above (relocated from PacketList's own toolbar
            row, which no longer exists). */}
        <div
          className={`flex items-center gap-1.5 px-1.5 py-1.5 rounded-md border transition-colors overflow-hidden shrink-0 ${
            isSearchExpanded ? 'bg-background border-border' : 'bg-transparent border-transparent'
          }`}
        >
          <button
            onMouseDown={e => e.preventDefault()}
            onClick={toggleSearch}
            title="Find packet"
            // Collapsed, this glyph sits directly on the header bar, which is
            // `--chrome` in every theme and where a muted grey all but
            // disappears. Expanded, it sits on the field it opens, where
            // chrome-foreground would be the thing that disappears instead. So
            // it follows the surface underneath it rather than picking one
            // colour and being wrong half the time.
            className={`p-0.5 shrink-0 rounded transition-colors hover:bg-accent ${
              isSearchExpanded
                ? 'text-muted-foreground hover:text-foreground'
                : 'text-chrome-foreground/80 hover:text-chrome-foreground'
            }`}
          >
            <TbSearch className="w-3.5 h-3.5" />
          </button>
          <motion.input
            ref={searchInputRef}
            type="text"
            placeholder="Find packet (IP, protocol, info)..."
            value={packetSearchText}
            onChange={e => onPacketSearchChange(e.target.value)}
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
        </div>

        {/* Packet Count Status Badge */}
        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-md border shrink-0 bg-background border-border text-foreground/80">
          <span className="text-muted-foreground">PACKETS:</span>
          <span className="font-semibold text-foreground">
            {filteredPackets.toLocaleString()} <span className="text-muted-foreground">/</span> {totalPackets.toLocaleString()}
          </span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-primary/20 text-primary font-bold">
            {filterPercentage}%
          </span>
        </div>
      </div>
    </div>
  );
};
