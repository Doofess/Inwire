import React, { useEffect, useRef, useState } from 'react';
import { Command } from 'cmdk';
import { AnimatePresence, motion } from 'motion/react';
import { HamburgerIcon } from './HamburgerIcon';
import {
  TbDownload,
  TbCloudDownload,
  TbChartBar,
  TbCode,
  TbHome,
  TbSettings,
  TbX,
} from 'react-icons/tb';
import { getAgentDownloadForCurrentOS } from '../../services/platformDetect';

/**
 * The menu holds only what has no permanent control elsewhere. Capture
 * start/stop, Clear Packet Buffer and the interface picker all live in the
 * header, so this deliberately does not take capture state, capture
 * callbacks, the agent command channel, or the role permissions that gated
 * them - a menu entry that duplicates a visible button is a second thing to
 * keep in sync for no gain.
 */
interface AppMenuProps {
  onOpenDissectorModal: () => void;
  onOpenStatsModal: () => void;
  onOpenExportModal: () => void;
  onOpenIspModal?: () => void;
  onOpenSettingsModal: () => void;
  agentOutdated: boolean;
}

/**
 * The drawer is `--chrome`, in every theme - the same surface as the header bar
 * it hangs from, and now the same single set of classes.
 *
 * The selected row is a translucent wash of the FOREGROUND colour rather than
 * `--accent`. Accent is a near-neutral in these themes - designed to sit on a
 * card - and on a saturated ground it reads as a smear rather than as a
 * highlight.
 */
const itemClass =
  'flex items-center gap-2.5 px-2.5 py-2 rounded-md text-sm cursor-pointer ' +
  'text-chrome-foreground ' +
  'data-[selected=true]:bg-chrome-foreground/15 data-[selected=true]:text-chrome-foreground ' +
  'data-[disabled=true]:opacity-40 data-[disabled=true]:pointer-events-none';

/** Icons follow their row. */
const itemIconClass = 'w-3.5 h-3.5 shrink-0 text-chrome-foreground';

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
  onOpenDissectorModal,
  onOpenStatsModal,
  onOpenExportModal,
  onOpenIspModal,
  onOpenSettingsModal,
  agentOutdated,
}) => {
  const [open, setOpen] = useState(false);
  const commandRef = useRef<HTMLDivElement | null>(null);
  const agentDownload = getAgentDownloadForCurrentOS();

  useEffect(() => {
    if (open) {
      // No search input to autofocus - focus the command root itself so
      // arrow keys/Enter work immediately without the user clicking first.
      commandRef.current?.focus();
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
        className="relative z-50 flex items-center justify-center w-9 h-9 rounded-md border transition-colors cursor-pointer bg-secondary hover:bg-accent border-border text-foreground dark:text-primary"
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
                // Filtering on, and an input below to drive it.
                //
                // This was bound to Ctrl+K and built on cmdk from the start,
                // but with no input and filtering switched off it was a drawer
                // of links wearing a palette's keybinding. Six entries fit on
                // screen, so it did not matter; adding view commands to a flat
                // list is where it starts to.
                shouldFilter
                tabIndex={0}
                className="flex flex-col h-full rounded-r-xl border shadow-2xl overflow-hidden bg-chrome border-chrome-foreground/20 text-chrome-foreground outline-none"
              >
                <div className="flex items-center justify-between border-b border-chrome-foreground/20 px-3.5 py-2.5 shrink-0">
                  <span className="text-xs font-bold text-chrome-foreground">Menu</span>
                  {/* Was an inert "ESC" hint; Escape itself still closes the
                      menu via the keydown handler above, this just gives the
                      hint something to do when clicked instead of typed. */}
                  <button
                    onClick={() => setOpen(false)}
                    aria-label="Close menu"
                    className="p-1 rounded-md shrink-0 transition-colors cursor-pointer text-chrome-foreground/70 hover:text-chrome-foreground hover:bg-chrome-foreground/15"
                  >
                    <TbX className="w-4 h-4" />
                  </button>
                </div>

                <div className="border-b border-chrome-foreground/20 px-3 py-2 shrink-0">
                  <Command.Input
                    autoFocus
                    placeholder="Search commands..."
                    className="w-full bg-transparent text-xs outline-none text-chrome-foreground placeholder:text-chrome-foreground/60"
                  />
                </div>

                <Command.Empty className="px-3 py-6 text-center text-[11px] text-chrome-foreground/70">
                  No matching command.
                </Command.Empty>

                {/* One flat list. There is no Command.Group here on purpose:
                    with a handful of entries, an Actions/Views split cost two
                    heading rows to sort items that fit on screen at once, and
                    the headings are not selectable, so arrowing through the
                    menu skipped past them anyway. The cmdk-group-heading
                    styling this list used to carry went with them. */}
                <Command.List className="flex-1 overflow-y-auto custom-scrollbar p-1.5">
                  {/* The two pane commands that used to head this list now live
                      only in Settings -> Interface, beside the rest of the
                      layout controls. Two ways to flip the same switch, worded
                      differently in each place, is how a menu starts drifting
                      from the panel it duplicates. */}
                  <Command.Item
                    value="export-import"
                    onSelect={() => run(onOpenExportModal)}
                    className={itemClass}
                  >
                    <TbDownload className={itemIconClass} />
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
                    <TbCloudDownload className={itemIconClass} />
                    <span className="flex-1">Download Driver ({agentDownload.label})</span>
                    {agentOutdated && (
                      <span
                        className="shrink-0 text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-full bg-chrome-foreground/15 border border-chrome-foreground/30 text-chrome-foreground"
                        title="A newer driver build is available"
                      >
                        Update
                      </span>
                    )}
                  </Command.Item>
                  {/* Named for what it opens rather than for its category:
                      the window is a protocol hierarchy, and the panel in the
                      sidebar that leads here is already called Protocol
                      Breakdown - two names for one thing read as two things. */}
                  <Command.Item
                    value="protocol-breakdown"
                    onSelect={() => run(onOpenStatsModal)}
                    className={itemClass}
                  >
                    <TbChartBar className={itemIconClass} />
                    <span>Protocol Breakdown</span>
                  </Command.Item>
                  <Command.Item
                    value="custom-dissectors"
                    onSelect={() => run(onOpenDissectorModal)}
                    className={itemClass}
                  >
                    <TbCode className={itemIconClass} />
                    <span>Custom Dissectors</span>
                  </Command.Item>
                  {onOpenIspModal && (
                    <Command.Item
                      // cmdk matches typed search text against this value, so
                      // it tracks the label rather than staying "isp-stats".
                      value="isp-information"
                      onSelect={() => run(onOpenIspModal)}
                      className={itemClass}
                    >
                      <TbHome className={itemIconClass} />
                      <span>ISP Information</span>
                    </Command.Item>
                  )}
                  <Command.Item
                    value="settings"
                    onSelect={() => run(onOpenSettingsModal)}
                    className={itemClass}
                  >
                    <TbSettings className={itemIconClass} />
                    <span>Settings</span>
                  </Command.Item>
                </Command.List>
              </Command>
            </motion.div>
          </React.Fragment>
        )}
      </AnimatePresence>
    </>
  );
};
