import React, { useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { Download, Upload, X } from 'lucide-react';

import { FilterPresetLibrary, Packet, Capabilities } from '../../types/packet';
import { ImportFailure } from '../../services/exportSchema';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import type { CaptureDropStats } from '../../services/agentProtocol';
import { ExportPanel } from './ExportPanel';
import { ImportPanel } from './ImportPanel';
import { ImportErrorDialog } from './ImportErrorDialog';

/**
 * The Import/Export centre.
 *
 * Two tabs rather than the single scrolling panel this used to be. The export
 * side gained a filter bar, two option switches and a fifth format card, and
 * stacking all of that above the import dropzone made a dialog taller than most
 * laptop screens. The tab strip is the one `StatisticsPane` already uses.
 */

interface ExportImportModalProps {
  /** The full live buffer; the export panel derives its own filtered view. */
  packets: Packet[];
  onImportPackets: (imported: Packet[]) => void;
  /**
   * Every frame the import produced, in order, on its way to the capture
   * store. Passed straight through: this modal decides nothing about where
   * frames are kept.
   */
  onImportBatch?: (batch: Packet[]) => void;
  onClose: () => void;
  permissions: Capabilities;
  isDark: boolean;
  /** The filter active in the main window, which the export filter starts from. */
  appliedFilter: string;
  filterPresetLibrary: FilterPresetLibrary;
  /** Forwarded to the export panel for the pcapng file's statistics block. */
  captureStats?: CaptureDropStats | null;
}

type Tab = 'export' | 'import';

export const ExportImportModal: React.FC<ExportImportModalProps> = ({
  packets,
  onImportPackets,
  onImportBatch,
  onClose,
  permissions,
  isDark,
  appliedFilter,
  filterPresetLibrary,
  captureStats,
}) => {
  const [tab, setTab] = useState<Tab>('export');
  const [rejected, setRejected] = useState<{ filename: string; failure: ImportFailure } | null>(null);
  const [retryToken, setRetryToken] = useState(0);

  const handleImport = (imported: Packet[]) => {
    onImportPackets(imported);
    // Deliberately not auto-closing. The import notes - no wire bytes, rows
    // skipped, times anchored at import - are worth reading, and the old
    // one-second timer took them off screen before anyone could.
  };

  const tabClass = (id: Tab) =>
    `px-3 py-1.5 rounded-md font-medium transition-colors flex items-center gap-1.5 ${
      tab === id
        ? 'bg-primary text-primary-foreground shadow-sm'
        : 'text-muted-foreground hover:text-foreground hover:bg-accent'
    }`;

  return (
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className="w-full max-w-3xl max-h-[90vh] rounded-xl border flex flex-col shadow-2xl transition-colors bg-card border-border text-card-foreground"
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2.5">
            <Download className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="font-bold text-base">Capture Import &amp; Export Center</div>
              <p className="text-xs text-muted-foreground">
                Libpcap binaries, Excel workbooks, CSV, JSON and PDF reports
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground"
            aria-label="Close"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tabs */}
        <div className="px-5 py-2 border-b border-border flex items-center gap-2 text-xs shrink-0">
          <button onClick={() => setTab('export')} className={tabClass('export')}>
            <Download className="w-3.5 h-3.5" />
            <span>Export</span>
          </button>
          <button onClick={() => setTab('import')} className={tabClass('import')}>
            <Upload className="w-3.5 h-3.5" />
            <span>Import</span>
          </button>
        </div>

        {/* Content */}
        <div className="p-5 overflow-y-auto custom-scrollbar">
          {tab === 'export' ? (
            <ExportPanel
              packets={packets}
              initialFilter={appliedFilter}
              filterPresetLibrary={filterPresetLibrary}
              permissions={permissions}
              isDark={isDark}
              captureStats={captureStats}
            />
          ) : (
            <ImportPanel
              onImportPackets={handleImport}
              onImportBatch={onImportBatch}
              onFailure={(filename, failure) => setRejected({ filename, failure })}
              retryToken={retryToken}
            />
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border flex justify-end shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-md bg-secondary hover:bg-accent text-foreground font-medium transition-colors"
          >
            Close
          </button>
        </div>
      </motion.div>

      <AnimatePresence>
        {rejected && (
          <ImportErrorDialog
            key="import-error"
            filename={rejected.filename}
            failure={rejected.failure}
            onClose={() => setRejected(null)}
            onRetry={() => {
              setRejected(null);
              setRetryToken(token => token + 1);
            }}
          />
        )}
      </AnimatePresence>
    </motion.div>
  );
};
