import React, { useState } from 'react';
import { motion } from 'motion/react';
import { CustomDissectorRule, CustomDissectorFieldDef, UserRolePermissions } from '../../types/packet';
import { CustomDissectorEngine } from '../../services/customDissectorEngine';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import {
  TbCode,
  TbPlus,
  TbTrash,
  TbCheck,
  TbX,
  TbPlayerPlay,
  TbShield,
  TbChevronUp,
  TbChevronDown,
} from 'react-icons/tb';

interface CustomDissectorModalProps {
  dissectorEngine: CustomDissectorEngine;
  onUpdateDissectors: () => void;
  onClose: () => void;
  permissions: UserRolePermissions;
}

export const CustomDissectorModal: React.FC<CustomDissectorModalProps> = ({
  dissectorEngine,
  onUpdateDissectors,
  onClose,
  permissions,
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

  const handleMoveDissector = (id: string, direction: 'up' | 'down') => {
    dissectorEngine.moveDissector(id, direction);
    setDissectors([...dissectorEngine.getDissectors()]);
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
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className={`w-full max-w-5xl max-h-[90vh] rounded-xl border flex flex-col shadow-2xl transition-colors ${
          'bg-card border-border text-card-foreground'
        }`}
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <TbCode className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="flex items-center gap-2 font-bold text-base">
                <span>Modular Custom Protocol Dissector Plugin Engine</span>
                <span className="text-xs px-2 py-0.5 rounded bg-primary/20 text-primary font-mono">
                  Active Plugins ({dissectors.length})
                </span>
              </div>
              <p className={`text-xs ${"text-muted-foreground"}`}>
                Extend packet analysis capabilities for proprietary, IoT, and custom application network standards
              </p>
            </div>
          </div>

          <button onClick={onClose} className={`p-1.5 rounded-md hover:bg-accent ${"text-muted-foreground"} hover:text-foreground`}>
            <TbX className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body: Left sidebar (list of plugins) + Right Editor/Viewer */}
        <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
          {/* Left Sidebar */}
          <div className="w-full md:w-72 border-r border-border p-3 flex flex-col justify-between bg-muted/30">
            <div className="space-y-1 overflow-y-auto custom-scrollbar pr-1 max-h-[300px] md:max-h-none">
              <div className={`text-[11px] font-bold ${"text-muted-foreground"} px-1 py-1 uppercase tracking-wider`}>
                Installed Dissectors
              </div>

              {dissectors.map((d, idx) => (
                <div
                  key={d.id}
                  onClick={() => {
                    setSelectedDissector(d);
                    setIsCreating(false);
                  }}
                  className={`p-2.5 rounded-lg border text-xs cursor-pointer transition-colors ${
                    !isCreating && selectedDissector?.id === d.id
                      ? 'bg-primary/15 border-primary/60 text-primary'
                      : 'bg-muted/50 border-border hover:bg-accent text-foreground/80'
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
                      className="accent-primary"
                      title="Enable / Disable Dissector"
                    />
                  </div>
                  <div className={`flex items-center justify-between mt-1`}>
                    <div className={`flex items-center gap-2 font-mono text-[10px] ${"text-muted-foreground"}`}>
                      <span className="text-primary font-bold">{d.protocolName}</span>
                      <span>•</span>
                      <span>{d.transport}</span>
                      {d.port && <span>:{d.port}</span>}
                    </div>

                    {permissions.canEditDissectors && (
                      <div className="flex items-center gap-0.5" title="Match precedence - earlier wins when two dissectors could both claim the same traffic">
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            handleMoveDissector(d.id, 'up');
                          }}
                          disabled={idx === 0}
                          className="p-0.5 rounded hover:bg-accent text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:pointer-events-none"
                          title="Higher precedence"
                        >
                          <TbChevronUp className="w-3 h-3" />
                        </button>
                        <button
                          onClick={e => {
                            e.stopPropagation();
                            handleMoveDissector(d.id, 'down');
                          }}
                          disabled={idx === dissectors.length - 1}
                          className="p-0.5 rounded hover:bg-accent text-muted-foreground hover:text-foreground disabled:opacity-30 disabled:pointer-events-none"
                          title="Lower precedence"
                        >
                          <TbChevronDown className="w-3 h-3" />
                        </button>
                      </div>
                    )}
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
                className="mt-3 w-full py-2 px-3 rounded-lg bg-primary hover:bg-primary/90 text-zinc-950 font-semibold text-xs transition-colors flex items-center justify-center gap-1.5 shadow-sm"
              >
                <TbPlus className="w-4 h-4" />
                <span>Create New Dissector</span>
              </button>
            ) : (
              <div className={`mt-3 p-2 rounded bg-secondary/60 ${"text-muted-foreground"} text-[10px] flex items-center gap-1.5`}>
                <TbShield className="w-3.5 h-3.5 text-foreground shrink-0" />
                <span>Dissector editing disabled for current user role</span>
              </div>
            )}
          </div>

          {/* Right Editor / Details Pane */}
          <div className="flex-1 overflow-y-auto p-4 space-y-4 custom-scrollbar">
            {isCreating ? (
              // Create New Dissector Form
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <div className="font-bold text-sm text-primary">Define New Custom Protocol Dissector</div>
                  <button
                    onClick={() => setIsCreating(false)}
                    className={`text-xs ${"text-muted-foreground"} hover:text-foreground`}
                  >
                    Cancel
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className={`block ${"text-muted-foreground"} mb-1 font-medium`}>Protocol Display Name</label>
                    <input
                      type="text"
                      value={formName}
                      onChange={e => setFormName(e.target.value)}
                      placeholder="e.g. Smart Meter Sensor v2"
                      className={`w-full px-3 py-1.5 rounded border border-border bg-muted ${"text-foreground"} text-xs font-mono`}
                    />
                  </div>

                  <div>
                    <label className={`block ${"text-muted-foreground"} mb-1 font-medium`}>Protocol Acronym (Filter Tag)</label>
                    <input
                      type="text"
                      value={formProtoName}
                      onChange={e => setFormProtoName(e.target.value)}
                      placeholder="e.g. SMRTV2"
                      className={`w-full px-3 py-1.5 rounded border border-border bg-muted ${"text-foreground"} text-xs font-mono uppercase`}
                    />
                  </div>

                  <div>
                    <label className={`block ${"text-muted-foreground"} mb-1 font-medium`}>Transport Layer</label>
                    <select
                      value={formTransport}
                      onChange={e => setFormTransport(e.target.value as any)}
                      className={`w-full px-3 py-1.5 rounded border border-border bg-muted ${"text-foreground"} text-xs font-mono`}
                    >
                      <option value="UDP">UDP</option>
                      <option value="TCP">TCP</option>
                      <option value="ANY">ANY (Match Magic Bytes)</option>
                    </select>
                  </div>

                  <div>
                    <label className={`block ${"text-muted-foreground"} mb-1 font-medium`}>Target Port (Optional)</label>
                    <input
                      type="number"
                      value={formPort ?? ''}
                      onChange={e => setFormPort(e.target.value ? Number(e.target.value) : undefined)}
                      placeholder="e.g. 8899"
                      className={`w-full px-3 py-1.5 rounded border border-border bg-muted ${"text-foreground"} text-xs font-mono`}
                    />
                  </div>

                  <div className="md:col-span-2">
                    <label className={`block ${"text-muted-foreground"} mb-1 font-medium`}>Magic Header Bytes (Hex)</label>
                    <input
                      type="text"
                      value={formMagicHex}
                      onChange={e => setFormMagicHex(e.target.value)}
                      placeholder="e.g. 4D 59 (Hex for 'MY')"
                      className={`w-full px-3 py-1.5 rounded border border-border bg-muted ${"text-foreground"} text-xs font-mono`}
                    />
                  </div>

                  <div className="md:col-span-2">
                    <label className={`block ${"text-muted-foreground"} mb-1 font-medium`}>Description</label>
                    <input
                      type="text"
                      value={formDescription}
                      onChange={e => setFormDescription(e.target.value)}
                      placeholder="Protocol functionality description"
                      className={`w-full px-3 py-1.5 rounded border border-border bg-muted ${"text-foreground"} text-xs`}
                    />
                  </div>
                </div>

                {/* Field Definitions Table */}
                <div className="border border-border rounded-lg p-3 space-y-2">
                  <div className={`flex items-center justify-between text-xs font-bold ${"text-foreground/80"}`}>
                    <span>Protocol Header & Payload Field Layout</span>
                    <button
                      onClick={handleAddField}
                      className="flex items-center gap-1 text-[11px] px-2 py-0.5 rounded bg-primary hover:bg-primary/90 text-zinc-950 font-semibold"
                    >
                      <TbPlus className="w-3 h-3" />
                      Add Field
                    </button>
                  </div>

                  <div className="space-y-1.5 text-xs font-mono">
                    {formFields.map((f, idx) => (
                      <div key={idx} className="flex items-center gap-2 bg-muted/60 p-1.5 rounded border border-border">
                        <input
                          type="text"
                          value={f.name}
                          onChange={e => handleFieldChange(idx, 'name', e.target.value)}
                          placeholder="Field Name"
                          className={`flex-1 px-2 py-1 rounded bg-background border border-border ${"text-foreground"} text-xs`}
                        />
                        <div className="flex items-center gap-1">
                          <span className={`text-[10px] ${"text-muted-foreground"}`}>Off:</span>
                          <input
                            type="number"
                            value={f.offset}
                            onChange={e => handleFieldChange(idx, 'offset', Number(e.target.value))}
                            className={`w-12 px-1.5 py-1 rounded bg-background border border-border ${"text-foreground"} text-xs`}
                          />
                        </div>
                        <div className="flex items-center gap-1">
                          <span className={`text-[10px] ${"text-muted-foreground"}`}>Len:</span>
                          <input
                            type="number"
                            value={f.length}
                            onChange={e => handleFieldChange(idx, 'length', Number(e.target.value))}
                            className={`w-12 px-1.5 py-1 rounded bg-background border border-border ${"text-foreground"} text-xs`}
                          />
                        </div>
                        <select
                          value={f.type}
                          onChange={e => handleFieldChange(idx, 'type', e.target.value)}
                          className={`px-2 py-1 rounded bg-background border border-border ${"text-foreground"} text-xs`}
                        >
                          <option value="uint8">uint8</option>
                          <option value="uint16">uint16 (BE)</option>
                          <option value="uint32">uint32 (BE)</option>
                          <option value="string">string</option>
                          <option value="hex">hex</option>
                        </select>
                        <button
                          onClick={() => handleRemoveField(idx)}
                          className="p-1 text-foreground hover:text-foreground/70"
                        >
                          <TbTrash className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2">
                  <button
                    onClick={() => setIsCreating(false)}
                    className={`px-3 py-1.5 rounded-md border border-border ${"text-foreground/80"} text-xs hover:bg-accent`}
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleSaveNewDissector}
                    className="px-4 py-1.5 rounded-md bg-primary hover:bg-primary/90 text-zinc-950 font-bold text-xs shadow-sm"
                  >
                    Save & Register Dissector
                  </button>
                </div>
              </div>
            ) : selectedDissector ? (
              // Selected Dissector View & Sandbox
              <div className="space-y-4">
                <div className="flex items-center justify-between border-b border-border pb-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-base text-primary">{selectedDissector.name}</span>
                      <span className={`text-xs px-2 py-0.5 rounded bg-secondary ${"text-foreground/80"} font-mono`}>
                        {selectedDissector.protocolName}
                      </span>
                    </div>
                    <p className={`text-xs ${"text-muted-foreground"} mt-0.5`}>{selectedDissector.description}</p>
                  </div>

                  {permissions.canEditDissectors && (
                    <button
                      onClick={() => handleDeleteDissector(selectedDissector.id)}
                      className="p-1.5 rounded text-foreground hover:bg-accent transition-colors"
                      title="Delete Dissector"
                    >
                      <TbTrash className="w-4 h-4" />
                    </button>
                  )}
                </div>

                {/* Field Blueprint Breakdown */}
                <div className="border border-border rounded-lg p-3">
                  <div className={`text-xs font-bold ${"text-foreground/80"} mb-2`}>Protocol Header Layout Spec</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 font-mono text-xs">
                    {selectedDissector.fields.map((field, idx) => (
                      <div key={idx} className="p-2 rounded bg-muted border border-border">
                        <div className="font-semibold text-primary">{field.name}</div>
                        <div className={`text-[10px] ${"text-muted-foreground"} mt-1`}>
                          Offset: {field.offset} • Len: {field.length}B • Type: {field.type}
                        </div>
                        {field.description && (
                          <div className={`text-[10px] ${"text-muted-foreground"} italic mt-0.5`}>{field.description}</div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Live Sandbox Test Harness */}
                <div className="border border-border rounded-lg p-3 bg-background/80 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-400">
                      <TbPlayerPlay className="w-3.5 h-3.5 fill-current text-foreground" />
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
                    <label className={`block text-[11px] ${"text-muted-foreground"} mb-1 font-mono`}>
                      Input Raw Payload Hex Bytes:
                    </label>
                    <textarea
                      value={testPayloadHex}
                      onChange={e => setTestPayloadHex(e.target.value)}
                      rows={2}
                      className="w-full p-2 rounded bg-muted border border-border font-mono text-xs text-sky-700 dark:text-sky-300 outline-none"
                    />
                  </div>

                  {testDissectionResult && (
                    <div className="p-3 rounded bg-muted/90 border border-emerald-500/40 space-y-2">
                      <div className="text-xs font-bold text-emerald-400 flex items-center gap-1.5">
                        <TbCheck className="w-4 h-4 text-emerald-400" />
                        <span>Dissection Successful ({testDissectionResult.matchedDissector?.protocolName})</span>
                      </div>

                      <div className="space-y-1 font-mono text-xs pl-2 border-l border-emerald-500/40">
                        {testDissectionResult.layer?.fields.map((f: any, idx: number) => (
                          <div key={idx} className="flex items-center gap-2">
                            <span className={`${"text-muted-foreground"}`}>{f.name}:</span>
                            <span className={`${"text-foreground"} font-semibold`}>{String(f.value)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className={`text-center py-16 ${"text-muted-foreground"}`}>Select a dissector plugin from the list</div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border flex items-center justify-between text-xs">
          <span className={`${"text-muted-foreground"}`}>
            Dissector rules are compiled and evaluated in real time on all incoming packets.
          </span>
          <button
            onClick={onClose}
            className={`px-4 py-1.5 rounded-md bg-secondary hover:bg-accent ${"text-foreground"} font-medium transition-colors`}
          >
            Done
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
};
