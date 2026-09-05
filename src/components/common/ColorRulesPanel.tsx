import React, { useState } from 'react';
import {
  TbAlertCircle, TbArrowDown, TbArrowUp, TbCheck, TbInfoCircle,
  TbPencil, TbPlus, TbRestore, TbTrash, TbX,
} from 'react-icons/tb';

import { ColorRule } from '../../types/packet';
import { FilterEngine } from '../../services/filterEngine';
import { defaultColorRules } from '../../services/colorRules';
import { resolveRuleColors } from '../../services/colorRules';
import type { PacketTheme } from '../../services/packetThemes';

/**
 * Settings → Colouring Rules.
 *
 * There was no editor at all: the chain was a constant, `canChangeColorRules`
 * gated nothing, and the only way to stop a rule painting your list was to
 * change the source. That is a strange gap for the one piece of the UI whose
 * entire job is to be opinionated about which frames matter.
 *
 * **Order is the feature.** The chain is first-match-wins, which is how a
 * retransmitted RST reads as "Bad TCP" rather than "TCP RST" and how an ARP
 * broadcast reads as "ARP" rather than "Broadcast" - relationships a
 * protocol-to-colour map cannot express. So the list is ordered, the arrows
 * are the primary control, and the preview swatch beside each row is painted
 * by the same code the packet list uses rather than by a copy of it.
 *
 * Every edit applies immediately, as in the Display Filters panel: there is
 * one chain in App state and this is the only thing that writes it, so a Save
 * button could only introduce a state where the panel and the list disagree.
 */

interface ColorRulesPanelProps {
  rules: ColorRule[];
  onChange: (rules: ColorRule[]) => void;
  /** The active packet theme, so a row previews in the colours it will use. */
  theme: PacketTheme;
  /** False for a role that may not change them; the panel then reads only. */
  canEdit: boolean;
}

interface Draft {
  /** The rule being edited, or null when adding. */
  id: string | null;
  name: string;
  filter: string;
}

export const ColorRulesPanel: React.FC<ColorRulesPanelProps> = ({ rules, onChange, theme, canEdit }) => {
  const [draft, setDraft] = useState<Draft | null>(null);

  const validation = draft ? FilterEngine.validateFilter(draft.filter, { strict: true }) : null;
  const canSave = !!draft && draft.name.trim().length > 0 && (validation?.isValid ?? false);

  const move = (index: number, by: number) => {
    const next = [...rules];
    const target = index + by;
    if (target < 0 || target >= next.length) return;
    [next[index], next[target]] = [next[target], next[index]];
    onChange(next);
  };

  const commit = () => {
    if (!draft || !canSave) return;
    if (draft.id === null) {
      // A new rule goes to the TOP. A chain is first-match-wins, so appending
      // would put it behind twenty rules that already match most traffic - it
      // would be saved, enabled, and invisible.
      onChange([
        {
          id: `color-user-${Date.now().toString(36)}`,
          name: draft.name.trim(),
          filter: draft.filter.trim(),
          enabled: true,
        },
        ...rules,
      ]);
    } else {
      onChange(rules.map((r) => (r.id === draft.id ? { ...r, name: draft.name.trim(), filter: draft.filter.trim() } : r)));
    }
    setDraft(null);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-3">
        <p className="text-[11px] text-muted-foreground leading-relaxed max-w-xl">
          The packet list paints each frame with the <strong>first</strong> rule that matches it,
          top to bottom. That order is what makes a retransmitted RST read as Bad TCP rather than
          TCP RST — moving a rule up gives it priority over everything below.
        </p>
        {canEdit && (
          <div className="flex items-center gap-1.5 shrink-0">
            <button
              onClick={() => setDraft({ id: null, name: '', filter: '' })}
              className="flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium bg-primary text-primary-foreground hover:bg-primary/90 cursor-pointer"
            >
              <TbPlus className="w-3.5 h-3.5" /> New rule
            </button>
            <button
              onClick={() => onChange(defaultColorRules())}
              title="Restore the shipped chain"
              className="flex items-center gap-1 px-2 py-1 rounded-md text-[11px] font-medium hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
            >
              <TbRestore className="w-3.5 h-3.5" /> Reset
            </button>
          </div>
        )}
      </div>

      {draft && (
        <div className="rounded-lg border border-border bg-muted/40 p-3 space-y-2">
          <div className="flex items-center gap-2">
            <input
              value={draft.name}
              onChange={(e) => setDraft({ ...draft, name: e.target.value })}
              placeholder="Rule name"
              className="flex-1 bg-background border border-border rounded px-2 py-1 text-xs outline-none focus:border-primary"
            />
            <button
              onClick={commit}
              disabled={!canSave}
              className="p-1.5 rounded-md bg-primary text-primary-foreground disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
              aria-label="Save rule"
            >
              <TbCheck className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setDraft(null)}
              className="p-1.5 rounded-md hover:bg-accent text-muted-foreground cursor-pointer"
              aria-label="Cancel"
            >
              <TbX className="w-3.5 h-3.5" />
            </button>
          </div>
          <input
            value={draft.filter}
            onChange={(e) => setDraft({ ...draft, filter: e.target.value })}
            placeholder='tls.handshake.type == 1'
            className="w-full bg-background border border-border rounded px-2 py-1 text-xs font-mono outline-none focus:border-primary"
          />
          {/* Validated strictly, unlike the filter bar: a colour rule has no
              free-text fallback, so a bare word that names nothing would be
              saved as a rule that can never match. */}
          {validation && !validation.isValid && (
            <div className="flex items-center gap-1.5 text-[11px] text-rose-500">
              <TbAlertCircle className="w-3.5 h-3.5 shrink-0" />
              <span>{validation.errorMessage}</span>
            </div>
          )}
          {validation?.warnings?.map((w) => (
            <div key={w} className="flex items-center gap-1.5 text-[11px] text-amber-500">
              <TbInfoCircle className="w-3.5 h-3.5 shrink-0" />
              <span>{w}</span>
            </div>
          ))}
        </div>
      )}

      <div className="rounded-lg border border-border divide-y divide-border/60 overflow-hidden">
        {rules.map((rule, index) => {
          const colors = resolveRuleColors(rule, theme);
          return (
            <div
              key={rule.id}
              className={`flex items-center gap-2 px-2.5 py-1.5 ${rule.enabled ? '' : 'opacity-45'}`}
            >
              {/* The swatch is painted by the same resolveRuleColors the packet
                  list uses, so what the panel shows is what the list will do -
                  including a user rule with no theme entry falling back to its
                  own colours. */}
              <span
                className="shrink-0 w-24 text-center rounded px-1.5 py-0.5 text-[10px] font-mono truncate"
                style={{ backgroundColor: colors.background, color: colors.color }}
                title={rule.name}
              >
                {rule.name}
              </span>

              <code className="flex-1 min-w-0 truncate text-[10px] font-mono text-muted-foreground" title={rule.filter}>
                {rule.filter}
              </code>

              {canEdit && (
                <div className="flex items-center gap-0.5 shrink-0">
                  <button
                    onClick={() => onChange(rules.map((r) => (r.id === rule.id ? { ...r, enabled: !r.enabled } : r)))}
                    title={rule.enabled ? 'Disable' : 'Enable'}
                    className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
                  >
                    {rule.enabled ? <TbCheck className="w-3.5 h-3.5" /> : <TbX className="w-3.5 h-3.5" />}
                  </button>
                  <button
                    onClick={() => move(index, -1)}
                    disabled={index === 0}
                    title="Move up"
                    className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
                  >
                    <TbArrowUp className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => move(index, 1)}
                    disabled={index === rules.length - 1}
                    title="Move down"
                    className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
                  >
                    <TbArrowDown className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setDraft({ id: rule.id, name: rule.name, filter: rule.filter })}
                    title="Edit"
                    className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
                  >
                    <TbPencil className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => onChange(rules.filter((r) => r.id !== rule.id))}
                    disabled={rules.length === 1}
                    title={rules.length === 1 ? 'The chain cannot be emptied' : 'Delete'}
                    className="p-1 rounded hover:bg-accent text-muted-foreground hover:text-rose-500 disabled:opacity-30 disabled:cursor-not-allowed cursor-pointer"
                  >
                    <TbTrash className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {!canEdit && (
        <p className="text-[11px] text-muted-foreground italic">
          Your role can view the colouring rules but not change them.
        </p>
      )}
    </div>
  );
};
