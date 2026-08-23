import React, { useState, useEffect, useRef } from 'react';
import {
  Filter,
  Check,
  AlertCircle,
  X,
  Bookmark,
  ChevronDown,
  Sparkles,
} from 'lucide-react';
import { FilterEngine, DEFAULT_FILTER_PRESETS, FilterValidationResult } from '../../services/filterEngine';
import { FilterPreset } from '../../types/packet';

interface FilterBarProps {
  filterText: string;
  onFilterChange: (filter: string) => void;
  onApplyFilter: (newFilter?: string) => void;
  totalPackets: number;
  filteredPackets: number;
  isDark: boolean;
}

export const FilterBar: React.FC<FilterBarProps> = ({
  filterText,
  onFilterChange,
  onApplyFilter,
  totalPackets,
  filteredPackets,
  isDark,
}) => {
  const [validation, setValidation] = useState<FilterValidationResult>({ isValid: true });
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showPresetsDropdown, setShowPresetsDropdown] = useState(false);
  const [presets, setPresets] = useState<FilterPreset[]>(DEFAULT_FILTER_PRESETS);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const containerRef = useRef<HTMLDivElement | null>(null);

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
      className={`px-4 py-2 border-b transition-colors z-30 relative shrink-0 ${
        isDark ? 'bg-slate-900 border-slate-800' : 'bg-slate-100 border-slate-200'
      }`}
    >
      <div className="flex flex-wrap items-center gap-3">
        {/* Preset Selector Dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowPresetsDropdown(!showPresetsDropdown)}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border font-medium transition-colors cursor-pointer ${
              isDark
                ? 'bg-slate-800 border-slate-700 hover:bg-slate-700 text-slate-200'
                : 'bg-white border-slate-300 hover:bg-slate-50 text-slate-800'
            }`}
            title="Choose a filter preset"
          >
            <Bookmark className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline font-mono">Presets</span>
            <ChevronDown className="w-3 h-3 text-slate-400" />
          </button>

          {showPresetsDropdown && (
            <div
              className={`absolute left-0 top-full mt-2 w-80 rounded-lg border p-1.5 shadow-2xl z-50 transition-all ${
                isDark ? 'bg-slate-950 border-slate-700 text-slate-200' : 'bg-white border-slate-200 text-slate-800 shadow-md rounded-lg'
              }`}
            >
              <div className="text-[10px] font-bold text-slate-400 px-2 py-1 uppercase tracking-wider flex items-center justify-between font-mono">
                <span>Display Filter Presets</span>
                <span className="text-[10px] text-slate-500">{presets.length} presets</span>
              </div>
              <div className="max-h-64 overflow-y-auto space-y-0.5 custom-scrollbar">
                {presets.map(p => (
                  <button
                    key={p.id}
                    onClick={() => handleSelectPreset(p)}
                    className={`w-full text-left px-2.5 py-1.5 rounded text-xs transition-colors flex flex-col ${
                      filterText === p.filter
                        ? isDark
                          ? 'bg-slate-800 border border-slate-700 text-cyan-300'
                          : 'bg-slate-100 border border-slate-300'
                        : 'hover:bg-slate-800/60'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-100">{p.name}</span>
                      <span className="text-[9px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">
                        {p.category}
                      </span>
                    </div>
                    {p.filter ? (
                      <code className="text-[10px] text-cyan-400 font-mono mt-0.5 truncate">{p.filter}</code>
                    ) : (
                      <span className="text-[10px] text-slate-500 italic">No filter (Show All)</span>
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
            className={`flex items-center rounded-md border w-full px-3 py-1.5 transition-all shadow-inner ${
              isDark ? 'bg-slate-800 border-slate-700' : 'bg-white border-slate-300'
            } ${
              isNotEmpty && !validation.isValid
                ? 'border-rose-500 bg-rose-950/20'
                : isNotEmpty && validation.isValid
                ? 'border-cyan-500/80'
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
              className={`bg-transparent outline-none text-xs font-mono w-full ${
                isDark ? 'text-slate-100 placeholder:text-slate-500' : 'text-slate-900 placeholder:text-slate-400'
              }`}
            />

            {/* Clear, Bookmark & Apply Controls inside input */}
            <div className="flex items-center gap-1 ml-2 shrink-0">
              {isNotEmpty && (
                <button
                  onClick={() => {
                    onFilterChange('');
                    onApplyFilter('');
                  }}
                  className="p-1 rounded text-slate-400 hover:text-slate-200 transition-colors"
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
            <div
              className={`absolute left-0 top-full mt-1.5 w-full rounded-lg border p-1.5 shadow-2xl z-50 transition-all ${
                isDark ? 'bg-slate-950 border-slate-700 text-slate-200' : 'bg-white border-slate-200 text-slate-800 shadow-md rounded-lg'
              }`}
            >
              <div className="text-[10px] font-bold text-slate-500 px-2 py-0.5 uppercase tracking-wider flex items-center justify-between font-mono">
                <span>Filter Suggestions</span>
                <span className="text-slate-600">Click to autofill</span>
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
            <div className="absolute left-0 top-full mt-1.5 z-40 flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-950 text-rose-300 text-[11px] border border-rose-800 shadow-lg">
              <AlertCircle className="w-3.5 h-3.5 text-rose-400 shrink-0" />
              <span>{validation.errorMessage}</span>
            </div>
          )}
        </div>

        {/* Packet Count Status Badge */}
        <div
          className={`flex items-center gap-2 text-xs font-mono px-3 py-1.5 rounded-md border shrink-0 ${
            isDark ? 'bg-slate-800/80 border-slate-700 text-slate-300' : 'bg-white border-slate-300 text-slate-700'
          }`}
        >
          <span className="text-slate-500">PACKETS:</span>
          <span className="font-semibold text-slate-100">
            {filteredPackets.toLocaleString()} <span className="text-slate-500">/</span> {totalPackets.toLocaleString()}
          </span>
          <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-500/20 text-cyan-400 font-bold">
            {filterPercentage}%
          </span>
        </div>
      </div>
    </div>
  );
};
