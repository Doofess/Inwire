import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'motion/react';
import {
  Filter,
  Check,
  AlertCircle,
  X,
  Bookmark,
  ChevronDown,
  Sparkles,
  Search,
} from 'lucide-react';
import { FilterEngine, DEFAULT_FILTER_PRESETS, FilterValidationResult } from '../../services/filterEngine';
import { FilterPreset } from '../../types/packet';

interface FilterBarProps {
  filterText: string;
  onFilterChange: (filter: string) => void;
  onApplyFilter: (newFilter?: string) => void;
  totalPackets: number;
  filteredPackets: number;
  packetSearchText: string;
  onPacketSearchChange: (text: string) => void;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filterText,
  onFilterChange,
  onApplyFilter,
  totalPackets,
  filteredPackets,
  packetSearchText,
  onPacketSearchChange,
}) => {
  const [validation, setValidation] = useState<FilterValidationResult>({ isValid: true });
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showPresetsDropdown, setShowPresetsDropdown] = useState(false);
  const [presets, setPresets] = useState<FilterPreset[]>(DEFAULT_FILTER_PRESETS);
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

  // Validate syntax as user types
  useEffect(() => {
    const res = FilterEngine.validateFilter(filterText);
    setValidation(res);

    if (filterText.trim()) {
      setSuggestions(FilterEngine.getSuggestions(filterText));
    } else {
      setSuggestions(FilterEngine.getSuggestions(''));
    }
  }, [filterText]);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      setShowSuggestions(false);
      onApplyFilter();
    } else if (e.key === 'Escape') {
      setShowSuggestions(false);
    }
  };

  const handleSelectSuggestion = (sug: string) => {
    onFilterChange(sug);
    setShowSuggestions(false);
    if (inputRef.current) inputRef.current.focus();
  };

  const handleSelectPreset = (preset: FilterPreset) => {
    onFilterChange(preset.filter);
    setShowPresetsDropdown(false);
    setShowSuggestions(false);
    onApplyFilter(preset.filter);
  };

  const handleSaveCurrentFilter = () => {
    if (!filterText.trim()) return;
    const newPreset: FilterPreset = {
      id: `custom-${Date.now()}`,
      name: `Custom (${filterText.slice(0, 16)}...)`,
      filter: filterText,
      category: 'Custom',
      description: 'User saved display filter',
    };
    setPresets([newPreset, ...presets]);
  };

  const isNotEmpty = filterText.trim().length > 0;
  const filterPercentage = totalPackets > 0 ? ((filteredPackets / totalPackets) * 100).toFixed(1) : '100.0';

  // Click outside to close suggestions
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setShowSuggestions(false);
        setShowPresetsDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  return (
    <div
      ref={containerRef}
      className="px-4 py-2 border-b transition-colors z-30 relative shrink-0 bg-secondary border-border"
    >
      <div className="flex flex-wrap items-center gap-3">
        {/* Preset Selector Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowPresetsDropdown(!showPresetsDropdown)}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border font-medium transition-colors cursor-pointer bg-card hover:bg-accent border-border text-foreground"
            title="Choose a filter preset"
          >
            <Bookmark className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline font-mono">Presets</span>
            <ChevronDown className="w-3 h-3 text-muted-foreground" />
          </button>

          {showPresetsDropdown && (
            <div className="absolute left-0 top-full mt-2 w-80 rounded-lg border p-1.5 shadow-2xl z-50 transition-all bg-popover border-border text-popover-foreground">
              <div className="text-[10px] font-bold text-muted-foreground px-2 py-1 uppercase tracking-wider flex items-center justify-between font-mono">
                <span>Display Filter Presets</span>
                <span className="text-[10px] text-muted-foreground">{presets.length} presets</span>
              </div>
              <div className="max-h-64 overflow-y-auto space-y-0.5 custom-scrollbar">
                {presets.map(p => (
                  <button
                    key={p.id}
                    onClick={() => handleSelectPreset(p)}
                    className={`w-full text-left px-2.5 py-1.5 rounded text-xs transition-colors flex flex-col ${
                      filterText === p.filter
                        ? 'bg-accent border border-border text-cyan-700 dark:text-cyan-300'
                        : 'hover:bg-accent/60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-foreground">{p.name}</span>
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-muted text-muted-foreground font-mono">
                        {p.category}
                      </span>
                    </div>
                    {p.filter ? (
                      <code className="text-[10px] text-cyan-400 font-mono mt-0.5 truncate">{p.filter}</code>
                    ) : (
                      <span className="text-[10px] text-muted-foreground italic">No filter (Show All)</span>
                    )}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Geometric Balance Filter Box Container */}
        <div className="relative flex-1 min-w-[260px]">
          <div
            className={`flex items-center rounded-md border w-full px-3 py-1.5 transition-all shadow-inner bg-card border-border ${
              isNotEmpty && !validation.isValid
                ? '!border-rose-500 bg-rose-100 dark:bg-rose-950/20'
                : isNotEmpty && validation.isValid
                ? '!border-cyan-500/80'
                : ''
            }`}
          >
            {/* Geometric FILTER prefix */}
            <span className="text-cyan-500 font-mono text-xs font-bold mr-2.5 select-none shrink-0">
              FILTER:
            </span>

            <input
              ref={inputRef}
              type="text"
              value={filterText}
              onChange={e => {
                onFilterChange(e.target.value);
                setShowSuggestions(true);
              }}
              onFocus={() => setShowSuggestions(true)}
              onKeyDown={handleKeyDown}
              placeholder='ip.addr == 192.168.1.1 || tcp.port == 443 || proto == http'
              className="bg-transparent outline-none text-xs font-mono w-full text-foreground placeholder:text-muted-foreground"
            />

            {/* Clear, Bookmark & Apply Controls inside input */}
            <div className="flex items-center gap-1 ml-2 shrink-0">
              {isNotEmpty && (
                <button
                  onClick={() => {
                    onFilterChange('');
                    onApplyFilter('');
                  }}
                  className="p-1 rounded text-muted-foreground hover:text-foreground transition-colors"
                  title="Clear filter"
                >
                  <X className="w-3 h-3" />
                </button>
              )}

              {isNotEmpty && validation.isValid && (
                <button
                  onClick={handleSaveCurrentFilter}
                  className="p-1 rounded text-cyan-400 hover:text-cyan-300 transition-colors"
                  title="Save current filter expression"
                >
                  <Bookmark className="w-3 h-3" />
                </button>
              )}

              <button
                onClick={() => {
                  setShowSuggestions(false);
                  onApplyFilter(filterText);
                }}
                className="p-1 px-1.5 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold transition-all shadow-sm active:scale-95 cursor-pointer"
                title="Apply display filter (Enter)"
              >
                <Check className="w-3 h-3 stroke-[3]" />
              </button>
            </div>
          </div>

          {/* Autocomplete Suggestions Box */}
          {showSuggestions && suggestions.length > 0 && (
            <div className="absolute left-0 top-full mt-1.5 w-full rounded-lg border p-1.5 shadow-2xl z-50 transition-all bg-popover border-border text-popover-foreground">
              <div className="text-[10px] font-bold text-muted-foreground px-2 py-0.5 uppercase tracking-wider flex items-center justify-between font-mono">
                <span>Filter Suggestions</span>
                <span className="text-muted-foreground">Click to autofill</span>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-1 mt-1">
                {suggestions.map((sug, idx) => (
                  <button
                    key={idx}
                    onClick={() => handleSelectSuggestion(sug)}
                    className="text-left px-2 py-1 rounded text-xs font-mono text-cyan-400 hover:bg-cyan-500/10 hover:text-cyan-300 transition-colors truncate"
                  >
                    {sug}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Syntax Error Notice */}
          {!validation.isValid && validation.errorMessage && (
            <div className="absolute left-0 top-full mt-1.5 z-40 flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-100 dark:bg-rose-950 text-rose-800 dark:text-rose-300 text-[11px] border border-rose-300 dark:border-rose-800 shadow-lg">
              <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
              <span>{validation.errorMessage}</span>
            </div>
          )}
        </div>

        {/* Find Packet - quick substring search applied on top of the
            display filter above (relocated from PacketList's own toolbar
            row, which no longer exists). */}
        <div
          className={`flex items-center gap-1.5 px-1.5 py-1.5 rounded-md border transition-colors overflow-hidden shrink-0 ${
            isSearchExpanded ? 'bg-card border-border' : 'bg-transparent border-transparent'
          }`}
        >
          <button
            onMouseDown={e => e.preventDefault()}
            onClick={toggleSearch}
            title="Find packet"
            className="p-0.5 shrink-0 rounded text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          >
            <Search className="w-3.5 h-3.5" />
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
              <X className="w-3 h-3" />
            </button>
          )}
        </div>

        {/* Packet Count Status Badge */}
        <div className="flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-md border shrink-0 bg-card border-border text-foreground/80">
          <span className="text-muted-foreground">PACKETS:</span>
          <span className="font-semibold text-foreground">
            {filteredPackets.toLocaleString()} <span className="text-muted-foreground">/</span> {totalPackets.toLocaleString()}
          </span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-400 font-bold">
            {filterPercentage}%
          </span>
        </div>
      </div>
    </div>
  );
};
