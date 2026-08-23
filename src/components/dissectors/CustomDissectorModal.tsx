import React, { useState } from 'react';
import { CustomDissectorRule, CustomDissectorFieldDef, UserRolePermissions } from '../../types/packet';
import { CustomDissectorEngine } from '../../services/customDissectorEngine';
import {
  Code,
  Plus,
  Trash2,
  Check,
  X,
  Play,
  Layers,
  Settings,
  HelpCircle,
  Shield,
} from 'lucide-react';

interface CustomDissectorModalProps {
  dissectorEngine: CustomDissectorEngine;
  onUpdateDissectors: () => void;
  onClose: () => void;
  permissions: UserRolePermissions;
  isDark: boolean;
}

export const CustomDissectorModal: React.FC<CustomDissectorModalProps> = ({
  dissectorEngine,
  onUpdateDissectors,
  onClose,
  permissions,
  isDark,
}) => {
  const [dissectors, setDissectors] = useState<CustomDissectorRule[]>(dissectorEngine.getDissectors());
  const [selectedDissector, setSelectedDissector] = useState<CustomDissectorRule>(dissectors[0] || null);
  const [isCreating, setIsCreating] = useState(false);

  // Test sandbox state
  const [testPayloadHex, setTestPayloadHex] = useState('49 4F 54 01 0A 2B 02 42 8E 66 66 00 00 12 34 FA 1C');
  const [testDissectionResult, setTestDissectionResult] = useState<any>(null);

  // New dissector form state
  const [formName, setFormName] = useState('');
  const [formProtoName, setFormProtoName] = useState('');
  const [formPort, setFormPort] = useState<number | undefined>(undefined);
  const [formTransport, setFormTransport] = useState<'TCP' | 'UDP' | 'ANY'>('UDP');
  const [formMagicHex, setFormMagicHex] = useState('');
  const [formDescription, setFormDescription] = useState('');
  const [formFields, setFormFields] = useState<CustomDissectorFieldDef[]>([
    { name: 'Magic Header', offset: 0, length: 2, type: 'string', description: 'Magic Token' },
    { name: 'Opcode', offset: 2, length: 1, type: 'uint8', description: 'Message Opcode' },
    { name: 'Sequence No', offset: 3, length: 2, type: 'uint16', description: 'Counter' },
    { name: 'Data Payload', offset: 5, length: 8, type: 'hex', description: 'Payload bytes' },
  ]);

  const handleToggleDissector = (id: string, enabled: boolean) => {
    dissectorEngine.updateDissector(id, { enabled });
    setDissectors([...dissectorEngine.getDissectors()]);
    onUpdateDissectors();
  };

  const handleDeleteDissector = (id: string) => {
    dissectorEngine.deleteDissector(id);
    const updated = dissectorEngine.getDissectors();
    setDissectors(updated);
    if (selectedDissector?.id === id) {
      setSelectedDissector(updated[0] || null);
    }
    onUpdateDissectors();
  };

  const handleAddField = () => {
    const lastField = formFields[formFields.length - 1];
    const newOffset = lastField ? lastField.offset + lastField.length : 0;
    setFormFields([
      ...formFields,
      { name: `Field_${formFields.length + 1}`, offset: newOffset, length: 2, type: 'uint16', description: '' },
    ]);
  };

  const handleRemoveField = (idx: number) => {
    setFormFields(formFields.filter((_, i) => i !== idx));
  };

  const handleFieldChange = (idx: number, key: keyof CustomDissectorFieldDef, value: any) => {
    const updated = [...formFields];
    updated[idx] = { ...updated[idx], [key]: value };
    setFormFields(updated);
  };

  const handleSaveNewDissector = () => {
    if (!formName || !formProtoName) return;

    const newRule: CustomDissectorRule = {
      id: `dissector-${Date.now()}`,
      name: formName,
      protocolName: formProtoName.toUpperCase().replace(/\s+/g, '_'),
      port: formPort || undefined,
      transport: formTransport,
      magicHeaderHex: formMagicHex.replace(/\s+/g, '') || undefined,
      description: formDescription || 'Custom protocol plugin dissector',
      enabled: true,
      fields: formFields,
    };

    dissectorEngine.addDissector(newRule);
    setDissectors([...dissectorEngine.getDissectors()]);
    setSelectedDissector(newRule);
    setIsCreating(false);
    onUpdateDissectors();
  };

  const handleRunSandboxTest = () => {
    const cleanHex = testPayloadHex.replace(/[^0-9A-Fa-f]/g, '');
    const bytes: number[] = [];
    for (let i = 0; i < cleanHex.length; i += 2) {
      bytes.push(parseInt(cleanHex.substring(i, i + 2), 16));
    }
    const uint8 = new Uint8Array(bytes);

    const activeRule = isCreating
      ? {
          id: 'temp',
          name: formName || 'Testing Rule',
          protocolName: formProtoName || 'TEST',
          port: formPort,
          transport: formTransport,
          magicHeaderHex: formMagicHex.replace(/\s+/g, ''),
          description: '',
          enabled: true,
          fields: formFields,
        }
      : selectedDissector;

    const tempEngine = new CustomDissectorEngine([activeRule]);
    const result = tempEngine.dissectPayload(uint8, activeRule.transport === 'TCP' ? 'TCP' : 'UDP', activeRule.port, activeRule.port, 0);
    setTestDissectionResult(result);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4">
      <div
        className={`w-full max-w-5xl max-h-[90vh] rounded-xl border flex flex-col shadow-2xl transition-colors ${
          isDark ? 'bg-zinc-950 border-zinc-700 text-zinc-100' : 'bg-white border-zinc-300 text-zinc-900'
        }`}
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-zinc-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-500/20 text-cyan-400">
              <Code className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2 font-bold text-base">
                <span>Modular Custom Protocol Dissector Plugin Engine</span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">
                  Active Plugins ({dissectors.length})
                </span>
              </div>
              <p className={`text-xs ${isDark ? "text-zinc-400" : "text-slate-600"}`}>
                Extend packet analysis capabilities for proprietary, IoT, and custom application network standards
              </p>
            </div>
          </div>

          <button onClick={onClose} className={`p-1.5 rounded-md hover:bg-zinc-800 ${isDark ? "text-zinc-400" : "text-slate-600"} hover:text-zinc-200`}>
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body: Left sidebar (list of plugins) + Right Editor/Viewer */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          {/* Left Sidebar */}
          <div className="w-full md:w-72 border-r border-zinc-800 p-3 flex flex-col justify-between bg-zinc-900/30">
            <div className="space-y-1 overflow-y-auto custom-scrollbar pr-1 max-h-[300px] md:max-h-none">
              <div className={`text-[11px] font-bold ${isDark ? "text-zinc-400" : "text-slate-600"} px-1 py-1 uppercase tracking-wider`}>
                Installed Dissectors
              </div>

              {dissectors.map(d => (
                <div
                  key={d.id}
                  onClick={() => {
                    setSelectedDissector(d);
                    setIsCreating(false);
                  }}
                  className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-colors ${
                    !isCreating && selectedDissector?.id === d.id
                      ? 'bg-cyan-950/40 border-cyan-500/60 text-cyan-200'
                      : isDark
                      ? 'bg-zinc-900/50 border-zinc-800 hover:bg-zinc-800 text-zinc-300'
                      : 'bg-zinc-50 border-zinc-200 hover:bg-zinc-100 text-zinc-800'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="font-semibold">{d.name}</span>
                    <input
                      type="checkbox"
                      checked={d.enabled}
                      onChange={e => {
                        e.stopPropagation();
                        handleToggleDissector(d.id, e.target.checked);
                      }}
                      className="accent-cyan-400"
                      title="Enable / Disable Dissector"
                    />
                  </div>
                  <div className={`flex items-center gap-2 mt-1 font-mono text-[10px] ${isDark ? "text-zinc-400" : "text-slate-600"}`}>
                    <span className="text-cyan-400 font-bold">{d.protocolName}</span>
                    <span>•</span>
                    <span>{d.transport}</span>
                    {d.port && <span>:{d.port}</span>}
                  </div>
                </div>
              ))}
            </div>

            {permissions.canEditDissectors ? (
              <button
                onClick={() => {
                  setIsCreating(true);
                  setFormName('Custom MyProto Protocol');
                  setFormProtoName('MYPROTO');
                  setFormPort(8899);
                  setFormTransport('UDP');
                  setFormMagicHex('4D59'); // "MY"
                  setFormDescription('Proprietary microservice messaging protocol');
                }}
                className="mt-3 w-full py-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-zinc-950 font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 shadow-sm"
              >
                <Plus className="w-4 h-4" />
                <span>Create New Dissector</span>
              </button>
            ) : (
              <div className={`mt-3 p-2 rounded bg-zinc-800/60 ${isDark ? "text-zinc-400" : "text-slate-600"} text-[10px] flex items-center gap-1.5`}>
                <Shield className={`w-3.5 h-3.5 ${isDark ? "text-zinc-500" : "text-slate-600"} shrink-0`} />
                <span>Dissector editing disabled for current user role</span>
              </div>
            )}
          </div>

          {/* Right Editor / Details Pane */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
            {isCreating ? (
              // Create New Dissector Form
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                  <div className="font-bold text-sm text-cyan-400">Define New Custom Protocol Dissector</div>
                  <button
                    onClick={() => setIsCreating(false)}
                    className={`text-xs ${isDark ? "text-zinc-400" : "text-slate-600"} hover:text-zinc-200`}
                  >
                    Cancel
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className={`block ${isDark ? "text-zinc-400" : "text-slate-600"} mb-1 font-medium`}>Protocol Display Name</label>
                    <input
                      type="text"
                      value={formName}
                      onChange={e => setFormName(e.target.value)}
                      placeholder="e.g. Smart Meter Sensor v2"
                      className={`w-full px-3 py-1.5 rounded border border-zinc-700 bg-zinc-900 ${isDark ? "text-zinc-100" : "text-slate-800"} text-xs font-mono`}
                    />
                  </div>

                  <div>
                    <label className={`block ${isDark ? "text-zinc-400" : "text-slate-600"} mb-1 font-medium`}>Protocol Acronym (Filter Tag)</label>
                    <input
                      type="text"
                      value={formProtoName}
                      onChange={e => setFormProtoName(e.target.value)}
                      placeholder="e.g. SMRTV2"
                      className={`w-full px-3 py-1.5 rounded border border-zinc-700 bg-zinc-900 ${isDark ? "text-zinc-100" : "text-slate-800"} text-xs font-mono uppercase`}
                    />
                  </div>

                  <div>
                    <label className={`block ${isDark ? "text-zinc-400" : "text-slate-600"} mb-1 font-medium`}>Transport Layer</label>
                    <select
                      value={formTransport}
                      onChange={e => setFormTransport(e.target.value as any)}
                      className={`w-full px-3 py-1.5 rounded border border-zinc-700 bg-zinc-900 ${isDark ? "text-zinc-100" : "text-slate-800"} text-xs font-mono`}
                    >
                      <option value="UDP">UDP</option>
                      <option value="TCP">TCP</option>
                      <option value="ANY">ANY (Match Magic Bytes)</option>
                    </select>
                  </div>

                  <div>
                    <label className={`block ${isDark ? "text-zinc-400" : "text-slate-600"} mb-1 font-medium`}>Target Port (Optional)</label>
                    <input
                      type="number"
                      value={formPort ?? ''}
                      onChange={e => setFormPort(e.target.value ? Number(e.target.value) : undefined)}
                      placeholder="e.g. 8899"
                      className={`w-full px-3 py-1.5 rounded border border-zinc-700 bg-zinc-900 ${isDark ? "text-zinc-100" : "text-slate-800"} text-xs font-mono`}
                    />
                  </div>

                  <div className="md:col-span-2">
                    <label className={`block ${isDark ? "text-zinc-400" : "text-slate-600"} mb-1 font-medium`}>Magic Header Bytes (Hex)</label>
                    <input
                      type="text"
                      value={formMagicHex}
                      onChange={e => setFormMagicHex(e.target.value)}
                      placeholder="e.g. 4D 59 (Hex for 'MY')"
                      className={`w-full px-3 py-1.5 rounded border border-zinc-700 bg-zinc-900 ${isDark ? "text-zinc-100" : "text-slate-800"} text-xs font-mono`}
                    />
                  </div>

                  <div className="md:col-span-2">
                    <label className={`block ${isDark ? "text-zinc-400" : "text-slate-600"} mb-1 font-medium`}>Description</label>
                    <input
                      type="text"
                      value={formDescription}
                      onChange={e => setFormDescription(e.target.value)}
                      placeholder="Protocol functionality description"
                      className={`w-full px-3 py-1.5 rounded border border-zinc-700 bg-zinc-900 ${isDark ? "text-zinc-100" : "text-slate-800"} text-xs`}
                    />
                  </div>
                </div>

                {/* Field Definitions Table */}
                <div className="border border-zinc-800 rounded-lg p-3 space-y-2">
                  <div className={`flex items-center justify-between text-xs font-bold ${isDark ? "text-zinc-300" : "text-slate-700"}`}>
                    <span>Protocol Header & Payload Field Layout</span>
                    <button
                      onClick={handleAddField}
                      className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded bg-cyan-600 hover:bg-cyan-500 text-zinc-950 font-semibold"
                    >
                      <Plus className="w-3 h-3" />
                      Add Field
                    </button>
                  </div>

                  <div className="space-y-1.5 text-xs font-mono">
                    {formFields.map((f, idx) => (
                      <div key={idx} className="flex items-center gap-2 bg-zinc-900/60 p-1.5 rounded border border-zinc-800">
                        <input
                          type="text"
                          value={f.name}
                          onChange={e => handleFieldChange(idx, 'name', e.target.value)}
                          placeholder="Field Name"
                          className={`flex-1 px-2 py-1 rounded bg-zinc-950 border border-zinc-700 ${isDark ? "text-zinc-200" : "text-slate-800"} text-xs`}
                        />
                        <div className="flex items-center gap-1">
                          <span className={`text-[10px] ${isDark ? "text-zinc-500" : "text-slate-600"}`}>Off:</span>
                          <input
                            type="number"
                            value={f.offset}
                            onChange={e => handleFieldChange(idx, 'offset', Number(e.target.value))}
                            className={`w-12 px-1.5 py-1 rounded bg-zinc-950 border border-zinc-700 ${isDark ? "text-zinc-200" : "text-slate-800"} text-xs`}
                          />
                        </div>
                        <div className="flex items-center gap-1">
                          <span className={`text-[10px] ${isDark ? "text-zinc-500" : "text-slate-600"}`}>Len:</span>
                          <input
                            type="number"
                            value={f.length}
                            onChange={e => handleFieldChange(idx, 'length', Number(e.target.value))}
                            className={`w-12 px-1.5 py-1 rounded bg-zinc-950 border border-zinc-700 ${isDark ? "text-zinc-200" : "text-slate-800"} text-xs`}
                          />
                        </div>
                        <select
                          value={f.type}
                          onChange={e => handleFieldChange(idx, 'type', e.target.value)}
                          className={`px-2 py-1 rounded bg-zinc-950 border border-zinc-700 ${isDark ? "text-zinc-200" : "text-slate-800"} text-xs`}
                        >
                          <option value="uint8">uint8</option>
                          <option value="uint16">uint16 (BE)</option>
                          <option value="uint32">uint32 (BE)</option>
                          <option value="string">string</option>
                          <option value="hex">hex</option>
                        </select>
                        <button
                          onClick={() => handleRemoveField(idx)}
                          className="p-1 text-red-400 hover:text-red-300"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setIsCreating(false)}
                    className={`px-3 py-1.5 rounded-md border border-zinc-700 ${isDark ? "text-zinc-300" : "text-slate-700"} text-xs hover:bg-zinc-800`}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveNewDissector}
                    className="px-4 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-zinc-950 font-bold text-xs shadow-sm"
                  >
                    Save & Register Dissector
                  </button>
                </div>
              </div>
            ) : selectedDissector ? (
              // Selected Dissector View & Sandbox
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-base text-cyan-300">{selectedDissector.name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded bg-zinc-800 ${isDark ? "text-zinc-300" : "text-slate-700"} font-mono`}>
                        {selectedDissector.protocolName}
                      </span>
                    </div>
                    <p className={`text-xs ${isDark ? "text-zinc-400" : "text-slate-600"} mt-0.5`}>{selectedDissector.description}</p>
                  </div>

                  {permissions.canEditDissectors && (
                    <button
                      onClick={() => handleDeleteDissector(selectedDissector.id)}
                      className="p-1.5 rounded text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors"
                      title="Delete Dissector"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>

                {/* Field Blueprint Breakdown */}
                <div className="border border-zinc-800 rounded-lg p-3">
                  <div className={`text-xs font-bold ${isDark ? "text-zinc-300" : "text-slate-700"} mb-2`}>Protocol Header Layout Spec</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 font-mono text-xs">
                    {selectedDissector.fields.map((field, idx) => (
                      <div key={idx} className="p-2 rounded bg-zinc-900 border border-zinc-800">
                        <div className="font-semibold text-cyan-400">{field.name}</div>
                        <div className={`text-[10px] ${isDark ? "text-zinc-400" : "text-slate-600"} mt-1`}>
                          Offset: {field.offset} • Len: {field.length}B • Type: {field.type}
                        </div>
                        {field.description && (
                          <div className={`text-[10px] ${isDark ? "text-zinc-500" : "text-slate-600"} italic mt-0.5`}>{field.description}</div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Live Sandbox Test Harness */}
                <div className="border border-zinc-800 rounded-lg p-3 bg-zinc-950/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-400">
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Live Dissection Sandbox & Hex Evaluator</span>
                    </div>
                    <button
                      onClick={handleRunSandboxTest}
                      className="px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-zinc-950 font-bold text-xs transition-colors shadow-sm"
                    >
                      Run Dissector
                    </button>
                  </div>

                  <div>
                    <label className={`block text-[11px] ${isDark ? "text-zinc-400" : "text-slate-600"} mb-1 font-mono`}>
                      Input Raw Payload Hex Bytes:
                    </label>
                    <textarea
                      value={testPayloadHex}
                      onChange={e => setTestPayloadHex(e.target.value)}
                      rows={2}
                      className="w-full p-2 rounded bg-zinc-900 border border-zinc-700 font-mono text-xs text-sky-300 outline-none"
                    />
                  </div>

                  {testDissectionResult && (
                    <div className="p-3 rounded bg-zinc-900/90 border border-emerald-500/40 space-y-2">
                      <div className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                        <Check className="w-4 h-4 text-emerald-400" />
                        <span>Dissection Successful ({testDissectionResult.matchedDissector?.protocolName})</span>
                      </div>

                      <div className="space-y-1 font-mono text-xs pl-2 border-l border-emerald-500/40">
                        {testDissectionResult.layer?.fields.map((f: any, idx: number) => (
                          <div key={idx} className="flex items-center gap-2">
                            <span className={`${isDark ? "text-zinc-400" : "text-slate-600"}`}>{f.name}:</span>
                            <span className={`${isDark ? "text-zinc-100" : "text-slate-800"} font-semibold`}>{String(f.value)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className={`text-center py-16 ${isDark ? "text-zinc-500" : "text-slate-600"}`}>Select a dissector plugin from the list</div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-zinc-800 flex items-center justify-between text-xs">
          <span className={`${isDark ? "text-zinc-500" : "text-slate-600"}`}>
            Dissector rules are compiled and evaluated in real time on all incoming packets.
          </span>
          <button
            onClick={onClose}
            className={`px-4 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 ${isDark ? "text-zinc-200" : "text-slate-800"} font-medium transition-colors`}
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
