import React, { useEffect, useRef, useState } from 'react';
import { Command } from 'cmdk';
import { AnimatePresence, motion } from 'motion/react';
import { BrandMark } from './BrandMark';
import { HamburgerIcon } from './HamburgerIcon';
import { headerIconButtonClass } from './headerButton';
import {
  TbDownload,
  TbCode,
  TbNetwork,
  TbSettings,
  TbChartBar,
  TbCheck,
  TbTag,
  TbX,
} from 'react-icons/tb';
import type { NameResolutionPrefs } from '../../services/interfacePrefs';

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
  onOpenExportModal: () => void;
  onOpenStatistics: () => void;
  onOpenNetwork?: () => void;
  /**
   * Wireshark puts name resolution under a View menu; this app's only menu is
   * this one, so the two passive switches live here beside the views they
   * change. The two outbound lookups stay in Settings, where the sentence
   * explaining what they send has room to be read.
   */
  nameResolution: NameResolutionPrefs;
  onNameResolutionChange: (patch: Partial<NameResolutionPrefs>) => void;
  onOpenSettingsModal: () => void;
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

export const AppMenu: React.FC<AppMenuProps> = ({
  onOpenDissectorModal,
  onOpenExportModal,
  onOpenStatistics,
  onOpenNetwork,
  nameResolution,
  onNameResolutionChange,
  onOpenSettingsModal,
}) => {
  const [open, setOpen] = useState(false);
  const commandRef = useRef<HTMLDivElement | null>(null);

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
        // Anchors the tour's driver step. See components/tour/tourSteps.
        data-tour="menu"
        // The same style as the adapter picker and the capture button beside
        // it - see headerButton.ts. `relative z-50` is this button's own: it
        // has to sit above the drawer's backdrop so that clicking it closes
        // the menu rather than the scrim swallowing the click.
        className={`${headerIconButtonClass} relative z-50 active:scale-95 cursor-pointer`}
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
                // Filtering OFF, because there is no input to drive it. cmdk
                // is still what this is built on - it gives the drawer its
                // arrow-key navigation, its Enter-to-select and its
                // roving-focus handling, and those are the parts a list of
                // links actually needs. Left on, `shouldFilter` would score
                // every item against a search string nothing can ever set.
                shouldFilter={false}
                tabIndex={0}
                className="flex flex-col h-full rounded-r-xl border shadow-2xl overflow-hidden bg-chrome border-chrome-foreground/20 text-chrome-foreground outline-none"
              >
                <div className="flex items-center justify-between border-b border-chrome-foreground/20 px-3.5 py-2.5 shrink-0">
                  {/* The mark, not the word. A drawer that has slid out from
                      under the hamburger does not need a label reading "Menu"
                      - the thing it is was settled by the gesture that opened
                      it - so the row carries the app's own icon instead.

                      `currentColor` from the drawer, which is
                      `--chrome-foreground`: this is standing in for a heading,
                      so it takes the heading's colour rather than the
                      deliberately low-contrast `--chrome-brand` the header
                      lockup uses.

                      Titled, because it is now the only thing naming this row.
                      That switches BrandMark from aria-hidden to a labelled
                      img - see the component. */}
                  <BrandMark className="w-6 h-6 shrink-0" title="Inwire" />
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
                  <Command.Item
                    value="capture-statistics"
                    onSelect={() => run(onOpenStatistics)}
                    className={itemClass}
                  >
                    <TbChartBar className={itemIconClass} />
                    <span>Capture Statistics</span>
                  </Command.Item>
                  {/* Wireshark's View -> Name Resolution. Both switches are
                      passive - every name they show came out of the capture -
                      so they toggle in place rather than opening a dialog to
                      explain themselves. The two lookups that DO send an
                      address somewhere stay in Settings. */}
                  <Command.Item
                    value="resolve-network-addresses"
                    onSelect={() => onNameResolutionChange({ network: !nameResolution.network })}
                    className={itemClass}
                  >
                    <TbTag className={itemIconClass} />
                    <span className="flex-1">Resolve Network Addresses</span>
                    {nameResolution.network && <TbCheck className="w-3.5 h-3.5 shrink-0" />}
                  </Command.Item>
                  <Command.Item
                    value="resolve-transport-ports"
                    onSelect={() => onNameResolutionChange({ transport: !nameResolution.transport })}
                    className={itemClass}
                  >
                    <TbTag className={itemIconClass} />
                    <span className="flex-1">Resolve Transport Ports</span>
                    {nameResolution.transport && <TbCheck className="w-3.5 h-3.5 shrink-0" />}
                  </Command.Item>
                  <Command.Item
                    value="custom-dissectors"
                    onSelect={() => run(onOpenDissectorModal)}
                    className={itemClass}
                  >
                    <TbCode className={itemIconClass} />
                    <span>Custom Dissectors</span>
                  </Command.Item>
                  {onOpenNetwork && (
                    <Command.Item
                      // cmdk matches typed search text against this value, so
                      // it tracks the label rather than staying "isp-stats".
                      // "network" rather than "isp" because the panel is no
                      // longer about the provider: the ISP is one of its seven
                      // sections, and the other six are this machine's own.
                      value="network"
                      onSelect={() => run(onOpenNetwork)}
                      className={itemClass}
                    >
                      <TbNetwork className={itemIconClass} />
                      <span>Network</span>
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
