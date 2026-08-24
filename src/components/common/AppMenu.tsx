import React, { useEffect, useRef, useState } from 'react';
import { Command } from 'cmdk';
import { AnimatePresence, motion } from 'motion/react';
import {
  Menu,
  ChevronRight,
  Play,
  Pause,
  Trash2,
  Download,
  BarChart2,
  Code,
  Palette,
  Globe,
  Bookmark,
  Settings,
} from 'lucide-react';
import { UserRolePermissions } from '../../types/packet';
import { DEFAULT_FILTER_PRESETS } from '../../services/filterEngine';

interface AppMenuProps {
  isCapturing: boolean;
  onStartCapture: () => void;
  onPauseCapture: () => void;
  onClearPackets: () => void;
  onOpenDissectorModal: () => void;
  onOpenStatsModal: () => void;
  onOpenExportModal: () => void;
  onOpenColorRulesModal: () => void;
  onOpenIspModal?: () => void;
  onOpenSettingsModal: () => void;
  onApplyFilterPreset: (filter: string) => void;
  permissions: UserRolePermissions;
  totalPacketsCount: number;
}

const itemClass =
  'flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm cursor-pointer text-foreground ' +
  'data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground ' +
  'data-[disabled=true]:opacity-40 data-[disabled=true]:pointer-events-none';

// Presets without a filter expression ("All Traffic") don't make sense as a
// menu action - there's nothing to jump to, so they're left to the
// FilterBar's own preset dropdown instead.
const NAMED_PRESETS = DEFAULT_FILTER_PRESETS.filter((p) => p.filter);

export const AppMenu: React.FC<AppMenuProps> = ({
  isCapturing,
  onStartCapture,
  onPauseCapture,
  onClearPackets,
  onOpenDissectorModal,
  onOpenStatsModal,
  onOpenExportModal,
  onOpenColorRulesModal,
  onOpenIspModal,
  onOpenSettingsModal,
  onApplyFilterPreset,
  permissions,
  totalPacketsCount,
}) => {
  const [open, setOpen] = useState(false);
  // Selecting an item closes the menu differently from Escape/backdrop-click:
  // instead of morphing back into the trigger button (the "returning to
  // idle" motion), it plays a plain shrink+fade in place, timed to overlap
  // with the destination modal's own fade+grow-in, so the two read as one
  // continuous handoff rather than a close followed by a separate pop-in.
  const [closingViaSelection, setClosingViaSelection] = useState(false);
  const [presetsExpanded, setPresetsExpanded] = useState(false);
  const commandRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (open) {
      setClosingViaSelection(false);
      // No search input to autofocus - focus the command root itself so
      // arrow keys/Enter work immediately without the user clicking first.
      commandRef.current?.focus();
    } else {
      setPresetsExpanded(false);
    }
  }, [open]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((o) => !o);
      } else if (e.key === 'Escape') {
        setOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const run = (action: () => void) => {
    setClosingViaSelection(true);
    setOpen(false);
    action();
  };

  return (
    <>
      <motion.button
        layoutId="app-menu-shell"
        onClick={() => setOpen(true)}
        title="Menu (Ctrl/Cmd + K)"
        className="flex items-center justify-center w-9 h-9 rounded-md border transition-colors cursor-pointer bg-secondary hover:bg-accent border-border text-foreground"
      >
        <Menu className="w-4 h-4" />
      </motion.button>

      <AnimatePresence>
        {open && (
          <React.Fragment key="app-menu-overlay">
            {/* Invisible click-outside layer - a corner menu shouldn't dim
                the whole app the way the old full-screen search overlay did. */}
            <motion.div
              key="app-menu-backdrop"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              onClick={() => setOpen(false)}
              className="fixed inset-0 z-40"
            />
            <motion.div
              layoutId={closingViaSelection ? undefined : 'app-menu-shell'}
              exit={{ opacity: 0, scale: closingViaSelection ? 0.96 : 1 }}
              transition={
                closingViaSelection
                  ? { duration: 0.18, ease: 'easeOut' }
                  : { type: 'spring', stiffness: 420, damping: 38 }
              }
              className="fixed top-20 right-4 sm:right-6 z-50 w-80 max-w-[calc(100vw-2rem)]"
            >
              <Command
                ref={commandRef}
                label="App Menu"
                loop
                shouldFilter={false}
                tabIndex={0}
                className="w-full rounded-xl border shadow-2xl overflow-hidden bg-popover border-border text-popover-foreground outline-none"
              >
                <div className="flex items-center justify-between border-b border-border px-3.5 py-2.5">
                  <span className="text-xs font-bold text-foreground">Menu</span>
                  <kbd className="text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0 border-border text-muted-foreground">
                    ESC
                  </kbd>
                </div>

                <Command.List
                  className="max-h-[28rem] overflow-y-auto custom-scrollbar p-1.5
                    [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5
                    [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-bold
                    [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider
                    [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:text-muted-foreground"
                >
                  <Command.Group heading="Actions">
                    {isCapturing ? (
                      <Command.Item
                        value="stop-capture"
                        onSelect={() => run(onPauseCapture)}
                        className={itemClass}
                      >
                        <Pause className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                        <span>Stop Capture</span>
                      </Command.Item>
                    ) : (
                      <Command.Item
                        value="start-capture"
                        disabled={!permissions.canCapture}
                        onSelect={() => run(onStartCapture)}
                        className={itemClass}
                      >
                        <Play className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                        <span>Start Capture</span>
                      </Command.Item>
                    )}
                    <Command.Item
                      value="clear-buffer"
                      disabled={!permissions.canClearBuffer || totalPacketsCount === 0}
                      onSelect={() => run(onClearPackets)}
                      className={itemClass}
                    >
                      <Trash2 className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                      <span>Clear Packet Buffer</span>
                    </Command.Item>
                    <Command.Item
                      value="export-import"
                      onSelect={() => run(onOpenExportModal)}
                      className={itemClass}
                    >
                      <Download className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                      <span>Export / Import PCAP</span>
                    </Command.Item>
                  </Command.Group>

                  <Command.Separator className="my-1 h-px bg-border" />

                  <Command.Group heading="Views">
                    <Command.Item
                      value="statistics"
                      onSelect={() => run(onOpenStatsModal)}
                      className={itemClass}
                    >
                      <BarChart2 className="w-3.5 h-3.5 text-purple-400 shrink-0" />
                      <span>Statistics</span>
                    </Command.Item>
                    <Command.Item
                      value="custom-dissectors"
                      onSelect={() => run(onOpenDissectorModal)}
                      className={itemClass}
                    >
                      <Code className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                      <span>Custom Dissectors</span>
                    </Command.Item>
                    <Command.Item
                      value="color-rules"
                      onSelect={() => run(onOpenColorRulesModal)}
                      className={itemClass}
                    >
                      <Palette className="w-3.5 h-3.5 text-pink-400 shrink-0" />
                      <span>Color Rules</span>
                    </Command.Item>
                    {onOpenIspModal && (
                      <Command.Item
                        value="isp-stats"
                        onSelect={() => run(onOpenIspModal)}
                        className={itemClass}
                      >
                        <Globe className="w-3.5 h-3.5 text-sky-400 shrink-0" />
                        <span>ISP Stats</span>
                      </Command.Item>
                    )}
                    <Command.Item
                      value="settings"
                      onSelect={() => run(onOpenSettingsModal)}
                      className={itemClass}
                    >
                      <Settings className="w-3.5 h-3.5 text-amber-400 shrink-0" />
                      <span>Settings</span>
                    </Command.Item>
                  </Command.Group>

                  <Command.Separator className="my-1 h-px bg-border" />

                  <Command.Group heading="Filter Presets">
                    <Command.Item
                      value="toggle-filter-presets"
                      onSelect={() => setPresetsExpanded((v) => !v)}
                      className={itemClass}
                    >
                      <motion.span
                        animate={{ rotate: presetsExpanded ? 90 : 0 }}
                        transition={{ duration: 0.15 }}
                        className="shrink-0 flex items-center justify-center w-3.5 h-3.5"
                      >
                        <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />
                      </motion.span>
                      <span className="flex-1">
                        {presetsExpanded ? 'Hide' : 'Show'} {NAMED_PRESETS.length} Presets
                      </span>
                    </Command.Item>

                    <AnimatePresence initial={false}>
                      {presetsExpanded && (
                        <motion.div
                          key="presets-list"
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.18, ease: 'easeOut' }}
                          style={{ overflow: 'hidden' }}
                        >
                          {NAMED_PRESETS.map((preset) => (
                            <Command.Item
                              key={preset.id}
                              value={`preset-${preset.id}`}
                              onSelect={() => run(() => onApplyFilterPreset(preset.filter))}
                              className={itemClass}
                            >
                              <Bookmark className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                              <div className="flex flex-col min-w-0">
                                <span className="truncate">{preset.name}</span>
                                <code className="text-[10px] text-muted-foreground truncate">
                                  {preset.filter}
                                </code>
                              </div>
                            </Command.Item>
                          ))}
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </Command.Group>
                </Command.List>
              </Command>
            </motion.div>
          </React.Fragment>
        )}
      </AnimatePresence>
    </>
  );
};
