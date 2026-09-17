import React, { useEffect, useRef, useState } from 'react';
import { CircleAlert, Check, X } from 'lucide-react';
import { FilterEngine } from '../../services/filterEngine';

interface FilterPresetEditorProps {
  initialName?: string;
  initialFilter?: string;
  initialDescription?: string;
  /** Label on the confirm button - "Add filter" or "Save". */
  submitLabel: string;
  onSubmit: (values: { name: string; filter: string; description: string }) => void;
  onCancel: () => void;
}

/**
 * The add/edit form for a single display-filter preset.
 *
 * Validates the expression with the same FilterEngine the filter bar uses, so
 * a preset cannot be saved in a state that would fail the moment it is
 * applied. An empty expression is allowed and means "match everything" - that
 * is what the shipped "All Traffic" preset is.
 */
export const FilterPresetEditor: React.FC<FilterPresetEditorProps> = ({
  initialName = '',
  initialFilter = '',
  initialDescription = '',
  submitLabel,
  onSubmit,
  onCancel,
}) => {
  const [name, setName] = useState(initialName);
  const [filter, setFilter] = useState(initialFilter);
  const [description, setDescription] = useState(initialDescription);
  const nameRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    nameRef.current?.focus();
    nameRef.current?.select();
  }, []);

  const validation = FilterEngine.validateFilter(filter);
  const trimmedName = name.trim();
  const canSubmit = trimmedName.length > 0 && validation.isValid;

  const submit = () => {
    if (!canSubmit) return;
    onSubmit({ name: trimmedName, filter: filter.trim(), description: description.trim() });
  };

  // Enter submits from any of the single-line inputs, Escape always cancels.
  // Without this the form can only be dismissed by mousing to a button, which
  // is jarring in a list where every other row responds to the keyboard.
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      submit();
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onCancel();
    }
  };

  const inputClass =
    'w-full rounded border border-border bg-background px-2 py-1 text-xs text-foreground outline-none focus:border-primary';

  return (
    <div className="rounded-md border border-primary/40 bg-muted/30 p-2.5 flex flex-col gap-2">
      <div className="flex flex-col gap-1">
        <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground font-mono">
          Name
        </label>
        <input
          ref={nameRef}
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="TLS handshakes"
          className={inputClass}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground font-mono">
          Expression
        </label>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="tls || tcp.port == 443"
          className={`${inputClass} font-mono ${
            filter.trim() && !validation.isValid ? '!border-rose-500' : ''
          }`}
        />
        {filter.trim() && !validation.isValid && validation.errorMessage ? (
          <div className="flex items-center gap-1.5 text-[11px] text-rose-600 dark:text-rose-400">
            <CircleAlert className="w-3.5 h-3.5 shrink-0" />
            <span>{validation.errorMessage}</span>
          </div>
        ) : !filter.trim() ? (
          <span className="text-[10px] text-muted-foreground italic">
            Empty expression - matches every packet
          </span>
        ) : null}
      </div>

      <div className="flex flex-col gap-1">
        <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground font-mono">
          Description <span className="normal-case font-normal tracking-normal">(optional)</span>
        </label>
        <input
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="What this filter is for"
          className={inputClass}
        />
      </div>

      <div className="flex items-center gap-2 pt-0.5">
        <button
          onClick={submit}
          disabled={!canSubmit}
          className={`flex items-center gap-1.5 px-3 py-1 rounded bg-primary text-primary-foreground text-xs font-medium transition-colors ${
            canSubmit ? 'hover:bg-primary/90 cursor-pointer' : 'opacity-50 cursor-not-allowed'
          }`}
        >
          <Check className="w-3.5 h-3.5" />
          {submitLabel}
        </button>
        <button
          onClick={onCancel}
          className="flex items-center gap-1.5 px-3 py-1 rounded bg-secondary hover:bg-accent text-foreground text-xs font-medium transition-colors cursor-pointer"
        >
          <X className="w-3.5 h-3.5" />
          Cancel
        </button>
      </div>
    </div>
  );
};
