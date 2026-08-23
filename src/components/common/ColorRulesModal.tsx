import React, { useState } from 'react';
import { ColorRule, UserRolePermissions } from '../../types/packet';
import { ColorRulesEngine } from '../../services/colorRules';
import { Palette, Plus, Trash2, Check, X, Shield } from 'lucide-react';

interface ColorRulesModalProps {
  colorEngine: ColorRulesEngine;
  onUpdateRules: () => void;
  onClose: () => void;
  permissions: UserRolePermissions;
  isDark: boolean;
}

export const ColorRulesModal: React.FC<ColorRulesModalProps> = ({
  colorEngine,
  onUpdateRules,
  onClose,
  permissions,
  isDark,
}) => {
  const [rules, setRules] = useState<ColorRule[]>([...colorEngine.getRules()]);

  const handleToggle = (id: string, enabled: boolean) => {
    const updated = rules.map(r => (r.id === id ? { ...r, enabled } : r));
    setRules(updated);
    colorEngine.setRules(updated);
    onUpdateRules();
  };

  const handleDelete = (id: string) => {
    const updated = rules.filter(r => r.id !== id);
    setRules(updated);
    colorEngine.setRules(updated);
    onUpdateRules();
  };

  const handleAddRule = () => {
    const newRule: ColorRule = {
      id: `rule-${Date.now()}`,
      name: 'Custom Filter Rule',
      filter: 'tcp.port == 8080',
      bgColor: 'rgba(59, 130, 246, 0.15)',
      textColor: '#3b82f6',
      enabled: true,
    };
    const updated = [newRule, ...rules];
    setRules(updated);
    colorEngine.setRules(updated);
    onUpdateRules();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div
        className={`w-full max-w-3xl max-h-[85vh] rounded-xl border flex flex-col shadow-2xl transition-colors ${
          isDark ? 'bg-zinc-950 border-zinc-700 text-zinc-100' : 'bg-white border-zinc-300 text-zinc-900'
        }`}
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-pink-500/20 text-pink-400">
              <Palette className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-base">Packet Coloring Rules</div>
              <p className="text-xs text-zinc-400">Customize visual highlighting based on protocol, port, or alert expressions</p>
            </div>
          </div>

          <button onClick={onClose} className="p-1.5 rounded-md hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Rules Table */}
        <div className="flex-1 overflow-y-auto p-5 space-y-2 custom-scrollbar">
          {rules.map(rule => (
            <div
              key={rule.id}
              className={`p-3 rounded-lg border flex items-center justify-between gap-3 text-xs transition-colors ${
                isDark ? 'bg-zinc-900/60 border-zinc-800' : 'bg-zinc-50 border-zinc-200'
              }`}
              style={{ borderLeftColor: rule.textColor, borderLeftWidth: '4px' }}
            >
              <div className="flex items-center gap-3 flex-1 min-w-0">
                <input
                  type="checkbox"
                  checked={rule.enabled}
                  onChange={e => handleToggle(rule.id, e.target.checked)}
                  className="accent-pink-400"
                />

                <div className="min-w-0">
                  <div className="font-semibold text-zinc-100">{rule.name}</div>
                  <code className="text-[11px] text-zinc-400 font-mono block truncate">{rule.filter}</code>
                </div>
              </div>

              {/* Color swatch preview */}
              <div
                className="px-3 py-1 rounded font-mono text-[11px] font-semibold border"
                style={{ backgroundColor: rule.bgColor, color: rule.textColor, borderColor: rule.textColor }}
              >
                Sample Frame
              </div>

              {permissions.canChangeColorRules && (
                <button
                  onClick={() => handleDelete(rule.id)}
                  className="p-1 text-red-400 hover:text-red-300 transition-colors"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              )}
            </div>
          ))}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-zinc-800 flex items-center justify-between text-xs">
          <button
            onClick={handleAddRule}
            disabled={!permissions.canChangeColorRules}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-pink-600 hover:bg-pink-500 text-white font-medium transition-colors"
          >
            <Plus className="w-4 h-4" />
            <span>Add Custom Rule</span>
          </button>

          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-medium transition-colors"
          >
            Save Rules
          </button>
        </div>
      </div>
    </div>
  );
};
