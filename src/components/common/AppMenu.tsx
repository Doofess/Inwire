import React, { useEffect, useRef, useState } from 'react';
import { Command } from 'cmdk';
import { AnimatePresence, motion } from 'motion/react';
import { HamburgerIcon } from './HamburgerIcon';
import {
  TbChevronRight,
  TbPlayerPlay,
  TbPlayerPause,
  TbTrash,
  TbDownload,
  TbCloudDownload,
  TbChartBar,
  TbCode,
  TbHome,
  TbBookmark,
  TbSettings,
  TbX,
} from 'react-icons/tb';
import { UserRolePermissions } from '../../types/packet';
import { DEFAULT_FILTER_PRESETS } from '../../services/filterEngine';
import { getAgentDownloadForCurrentOS } from '../../services/platformDetect';
import type { AgentCommand } from '../../services/agentProtocol';

interface AppMenuProps {
  isCapturing: boolean;
  onStartCapture: () => void;
  onStartCaptureOn: (interfaceName: string) => void;
  onPauseCapture: () => void;
  onSendAgentCommand: (command: AgentCommand) => void;
  onClearPackets: () => void;
  agentInterfaces: { name: string; label: string }[];
  selectedInterfaces: string[];
  onSelectInterface: (interfaceName: string) => void;
  onOpenDissectorModal: () => void;
  onOpenStatsModal: () => void;
  onOpenExportModal: () => void;
  onOpenIspModal?: () => void;
  onOpenSettingsModal: () => void;
  onApplyFilterPreset: (filter: string) => void;
  permissions: UserRolePermissions;
  totalPacketsCount: number;
  agentOutdated: boolean;
}

const itemClass =
  'flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm cursor-pointer text-foreground ' +
  'data-[selected=true]:bg-accent data-[selected=true]:text-accent-foreground ' +
  'data-[disabled=true]:opacity-40 data-[disabled=true]:pointer-events-none';

// Presets without a filter expression ("All Traffic") don't make sense as a
// menu action - there's nothing to jump to, so they're left to the
// FilterBar's own preset dropdown instead.
const NAMED_PRESETS = DEFAULT_FILTER_PRESETS.filter((p) => p.filter);

function downloadAgentInstaller() {
  const { url, filename } = getAgentDownloadForCurrentOS();
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
}

export const AppMenu: React.FC<AppMenuProps> = ({
  isCapturing,
  onStartCapture,
  onStartCaptureOn,
  onPauseCapture,
  onSendAgentCommand,
  onClearPackets,
  agentInterfaces,
  selectedInterfaces,
  onSelectInterface,
  onOpenDissectorModal,
  onOpenStatsModal,
  onOpenExportModal,
  onOpenIspModal,
  onOpenSettingsModal,
  onApplyFilterPreset,
  permissions,
  totalPacketsCount,
  agentOutdated,
}) => {
  const [open, setOpen] = useState(false);
  const [presetsExpanded, setPresetsExpanded] = useState(false);
  // Start Capture expands in place into the adapter list rather than opening
  // a nested popover: this is a command palette, and a dropdown inside a
  // dropdown fights its keyboard navigation. Mirrors the Filter Presets
  // expander directly below.
  const [startExpanded, setStartExpanded] = useState(false);
  const commandRef = useRef<HTMLDivElement | null>(null);
  const agentDownload = getAgentDownloadForCurrentOS();

  useEffect(() => {
    if (open) {
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
    setOpen(false);
    action();
  };

  return (
    <>
      {/* The trigger stays put and its icon morphs to a cross, rather than the
          button itself expanding into the panel as it used to. A shared-layout
          morph and a hamburger-to-cross morph are mutually exclusive: the first
          consumes the button, leaving nothing on screen to become the cross.
          Sits above the backdrop so clicking it closes the menu directly. */}
      <button
        onClick={() => setOpen((o) => !o)}
        title="Menu (Ctrl/Cmd + K)"
        aria-expanded={open}
        aria-label="Toggle menu"
        className="relative z-50 flex items-center justify-center w-9 h-9 rounded-md border transition-colors cursor-pointer bg-secondary hover:bg-accent border-border text-foreground"
      >
        <HamburgerIcon open={open} />
      </button>

      <AnimatePresence>
        {open && (
          <React.Fragment key="app-menu-overlay">
            {/* GitHub dims the page behind its Global navigation menu (a
                scrim, not the near-opaque backdrop a centered modal gets) -
                appropriate now that this is a full-height drawer rather than
                a corner popover that only needed an invisible click-outside
                layer. */}
            <motion.div
              key="app-menu-backdrop"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              onClick={() => setOpen(false)}
              className="fixed inset-0 z-40 bg-black/40"
            />
            {/* Measured from GitHub's own Global navigation menu (the ☰
                trigger at the top-LEFT of github.com's header, not the
                avatar menu - that one is a small anchored dropdown with no
                slide at all): a 320px-wide, full-height panel flush against
                the left edge, sliding in as translate(-100%) -> none over
                250ms on cubic-bezier(0.33, 1, 0.68, 1). Unlike that trigger,
                which stays a plain three-bar glyph, this one keeps the
                hamburger-to-cross morph from the marketing header - GitHub
                doesn't animate this particular icon, but a static icon next
                to a quarter-second panel slide reads as unfinished here. */}
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: 0 }}
              exit={{ x: '-100%' }}
              transition={{ duration: 0.25, ease: [0.33, 1, 0.68, 1] }}
              className="fixed inset-y-0 left-0 z-50 w-80 max-w-full"
            >
              <Command
                ref={commandRef}
                label="App Menu"
                loop
                shouldFilter={false}
                tabIndex={0}
                className="flex flex-col h-full rounded-r-xl border shadow-2xl overflow-hidden bg-popover border-border text-popover-foreground outline-none"
              >
                <div className="flex items-center justify-between border-b border-border px-3.5 py-2.5 shrink-0">
                  <span className="text-xs font-bold text-foreground">Menu</span>
                  {/* Was an inert "ESC" hint; Escape itself still closes the
                      menu via the keydown handler above, this just gives the
                      hint something to do when clicked instead of typed. */}
                  <button
                    onClick={() => setOpen(false)}
                    aria-label="Close menu"
                    className="p-1 rounded-md shrink-0 text-muted-foreground hover:text-foreground hover:bg-accent transition-colors cursor-pointer"
                  >
                    <TbX className="w-4 h-4" />
                  </button>
                </div>

                <Command.List
                  className="flex-1 overflow-y-auto custom-scrollbar p-1.5
                    [&_[cmdk-group-heading]]:px-2 [&_[cmdk-group-heading]]:py-1.5
                    [&_[cmdk-group-heading]]:text-[10px] [&_[cmdk-group-heading]]:font-bold
                    [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider
                    [&_[cmdk-group-heading]]:font-mono [&_[cmdk-group-heading]]:text-muted-foreground"
                >
                  <Command.Group heading="Actions">
                    {isCapturing ? (
                      <Command.Item
                        value="stop-capture"
                        onSelect={() => run(() => { onPauseCapture(); onSendAgentCommand({ type: 'stop_capture' }); })}
                        className={itemClass}
                      >
                        <TbPlayerPause className="w-3.5 h-3.5 text-rose-500 shrink-0" />
                        <span>Stop Capture</span>
                      </Command.Item>
                    ) : agentInterfaces.length === 0 ? (
                      // No agent, so no adapters to choose between. Start
                      // immediately rather than expanding into an empty list.
                      <Command.Item
                        value="start-capture"
                        disabled={!permissions.canCapture}
                        onSelect={() => run(onStartCapture)}
                        className={itemClass}
                      >
                        <TbPlayerPlay className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                        <span>Start Capture</span>
                      </Command.Item>
                    ) : (
                      <>
                        <Command.Item
                          value="start-capture"
                          disabled={!permissions.canCapture}
                          onSelect={() => setStartExpanded((v) => !v)}
                          className={itemClass}
                        >
                          <TbPlayerPlay className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                          <span className="flex-1">Start Capture</span>
                          <motion.span
                            animate={{ rotate: startExpanded ? 90 : 0 }}
                            transition={{ duration: 0.15 }}
                            className="shrink-0 flex items-center justify-center w-3.5 h-3.5"
                          >
                            <TbChevronRight className="w-3.5 h-3.5 text-muted-foreground" />
                          </motion.span>
                        </Command.Item>

                        <AnimatePresence initial={false}>
                          {startExpanded && (
                            <motion.div
                              key="start-interfaces"
                              initial={{ height: 0, opacity: 0 }}
                              animate={{ height: 'auto', opacity: 1 }}
                              exit={{ height: 0, opacity: 0 }}
                              transition={{ duration: 0.18, ease: 'easeOut' }}
                              style={{ overflow: 'hidden' }}
                            >
                              {agentInterfaces.map((iface) => (
                                <Command.Item
                                  key={iface.name}
                                  value={`start-on-${iface.name}`}
                                  onSelect={() => run(() => onStartCaptureOn(iface.name))}
                                  className={`${itemClass} pl-8`}
                                  title={iface.name}
                                >
                                  <TbPlayerPlay className="w-3 h-3 text-cyan-500 shrink-0" />
                                  <span className="truncate">{iface.label}</span>
                                </Command.Item>
                              ))}
                            </motion.div>
                          )}
                        </AnimatePresence>
                      </>
                    )}
                    <Command.Item
                      value="clear-buffer"
                      disabled={!permissions.canClearBuffer || totalPacketsCount === 0}
                      onSelect={() => run(onClearPackets)}
                      className={itemClass}
                    >
                      <TbTrash className="w-3.5 h-3.5 text-foreground shrink-0" />
                      <span>Clear Packet Buffer</span>
                    </Command.Item>
                    <Command.Item
                      value="export-import"
                      onSelect={() => run(onOpenExportModal)}
                      className={itemClass}
                    >
                      <TbDownload className="w-3.5 h-3.5 text-foreground shrink-0" />
                      <span>Export / Import PCAP</span>
                    </Command.Item>
                    {/* Was its own always-visible header button; folded in here
                        now that the header has nothing right of the trigger
                        for it to sit next to. */}
                    <Command.Item
                      value="download-driver"
                      onSelect={() => run(downloadAgentInstaller)}
                      className={itemClass}
                    >
                      <TbCloudDownload className="w-3.5 h-3.5 text-foreground shrink-0" />
                      <span className="flex-1">Download Driver ({agentDownload.label})</span>
                      {agentOutdated && (
                        <span
                          className="shrink-0 text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-600 dark:text-amber-400"
                          title="A newer agent build is available"
                        >
                          Update
                        </span>
                      )}
                    </Command.Item>
                  </Command.Group>

                  <Command.Separator className="my-1 h-px bg-border" />

                  <Command.Group heading="Views">
                    <Command.Item
                      value="statistics"
                      onSelect={() => run(onOpenStatsModal)}
                      className={itemClass}
                    >
                      <TbChartBar className="w-3.5 h-3.5 text-foreground shrink-0" />
                      <span>Statistics</span>
                    </Command.Item>
                    <Command.Item
                      value="custom-dissectors"
                      onSelect={() => run(onOpenDissectorModal)}
                      className={itemClass}
                    >
                      <TbCode className="w-3.5 h-3.5 text-foreground shrink-0" />
                      <span>Custom Dissectors</span>
                    </Command.Item>
                    {onOpenIspModal && (
                      <Command.Item
                        value="isp-stats"
                        onSelect={() => run(onOpenIspModal)}
                        className={itemClass}
                      >
                        <TbHome className="w-3.5 h-3.5 text-foreground shrink-0" />
                        <span>ISP Stats</span>
                      </Command.Item>
                    )}
                    <Command.Item
                      value="settings"
                      onSelect={() => run(onOpenSettingsModal)}
                      className={itemClass}
                    >
                      <TbSettings className="w-3.5 h-3.5 text-foreground shrink-0" />
                      <span>Settings</span>
                    </Command.Item>
                    {agentInterfaces.length > 0 && (
                      <>
                        <Command.Separator className="my-1 h-px bg-border" />
                        <div className="px-2 py-1.5 text-[10px] font-bold uppercase tracking-wider font-mono text-muted-foreground">
                          Capture Interfaces
                        </div>
                        {/* Round markers, not square boxes: capture reads from
                            exactly one adapter, so this is a radio group and
                            picking one deselects the rest. Checkboxes here
                            would promise a multi-adapter capture the app no
                            longer performs. */}
                        {agentInterfaces.map((iface) => {
                          const isSelected = selectedInterfaces[0] === iface.name;
                          return (
                            <Command.Item
                              key={iface.name}
                              value={`interface-${iface.name}`}
                              onSelect={() => onSelectInterface(iface.name)}
                              className={itemClass}
                              title={iface.name}
                            >
                              <span className={`w-3.5 h-3.5 shrink-0 rounded-full border flex items-center justify-center ${isSelected ? 'bg-cyan-500 border-cyan-500' : 'border-border'}`}>
                                {isSelected && <span className="w-1.5 h-1.5 rounded-full bg-slate-950" />}
                              </span>
                              <span className="truncate">{iface.label}</span>
                            </Command.Item>
                          );
                        })}
                      </>
                    )}
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
                        <TbChevronRight className="w-3.5 h-3.5 text-foreground" />
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
                              <TbBookmark className="w-3.5 h-3.5 text-foreground shrink-0" />
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
