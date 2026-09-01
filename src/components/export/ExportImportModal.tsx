import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Packet, UserRolePermissions } from '../../types/packet';
import { PcapService } from '../../services/pcapParser';
import { modalBackdropMotion, modalPanelMotion } from '../../lib/modalMotion';
import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';
import {
  TbDownload,
  TbUpload,
  TbFileCode,
  TbFileText,
  TbCheck,
  TbAlertCircle,
  TbX,
  TbShield,
  TbPhoto,
} from 'react-icons/tb';

interface ExportImportModalProps {
  packets: Packet[];
  onImportPackets: (imported: Packet[]) => void;
  onClose: () => void;
  permissions: UserRolePermissions;
  isDark: boolean;
}

export const ExportImportModal: React.FC<ExportImportModalProps> = ({
  packets,
  onImportPackets,
  onClose,
  permissions,
  isDark,
}) => {
  const [importStatus, setImportStatus] = useState<string | null>(null);
  const [importError, setImportError] = useState<string | null>(null);
  const [isExporting, setIsExporting] = useState(false);

  const handleExportPcap = () => {
    if (packets.length === 0) return;
    setIsExporting(true);
    try {
      const blob = PcapService.generatePcapBinary(packets);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `netview_capture_${Date.now()}.pcap`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setIsExporting(false);
    }
  };

  const handleExportJson = () => {
    if (packets.length === 0) return;
    const jsonStr = PcapService.exportToJson(packets);
    const blob = new Blob([jsonStr], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netview_capture_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportCsv = () => {
    if (packets.length === 0) return;
    const csvStr = PcapService.exportToCsv(packets);
    const blob = new Blob([csvStr], { type: 'text/csv;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `netview_capture_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleExportPdf = () => {
    if (packets.length === 0) return;
    const doc = new jsPDF();
    const dateStr = new Date().toLocaleString();

    // 1. Title
    doc.setFontSize(20);
    doc.text('Net View Analysis Report', 14, 22);
    
    doc.setFontSize(10);
    doc.text(`Generated on: ${dateStr}`, 14, 30);
    doc.text(`Total Packets Captured: ${packets.length}`, 14, 35);

    // 2. Protocol Stats
    const protoCounts: Record<string, number> = {};
    for (const p of packets) {
      protoCounts[p.protocol] = (protoCounts[p.protocol] || 0) + 1;
    }
    const protoData = Object.entries(protoCounts)
      .sort((a, b) => b[1] - a[1])
      .map(([proto, count]) => [proto, count.toString(), ((count / packets.length) * 100).toFixed(1) + '%']);

    doc.setFontSize(14);
    doc.text('Protocol Hierarchy Statistics', 14, 45);
    autoTable(doc, {
      startY: 50,
      head: [['Protocol', 'Packet Count', 'Percentage']],
      body: protoData,
      theme: 'grid',
      styles: { fontSize: 10 },
      headStyles: { fillColor: [59, 130, 246] }
    });

    // 3. Active Alerts
    const alerts = packets.filter(p => (p.anomalies && p.anomalies.length > 0) || p.status === 'alert');
    let currentY = (doc as any).lastAutoTable.finalY + 15;
    
    doc.setFontSize(14);
    doc.text('Active Security Alerts', 14, currentY);
    
    if (alerts.length > 0) {
      const alertData = alerts.slice(-50).map(a => [
        a.id.toString(),
        a.protocol,
        a.source,
        a.destination,
        a.anomalies?.[0]?.title || 'Unknown Alert'
      ]);
      
      autoTable(doc, {
        startY: currentY + 5,
        head: [['ID', 'Proto', 'Source', 'Destination', 'Alert Details']],
        body: alertData,
        theme: 'grid',
        styles: { fontSize: 9 },
        headStyles: { fillColor: [239, 68, 68] }
      });
      currentY = (doc as any).lastAutoTable.finalY + 15;
    } else {
      doc.setFontSize(10);
      doc.text('No active alerts detected in this capture session.', 14, currentY + 7);
      currentY += 15;
    }

    // 4. Packet List (Summary)
    doc.setFontSize(14);
    doc.text('Packet List (Latest 100)', 14, currentY);
    
    const packetData = packets.slice(-100).map(p => [
      p.id.toString(),
      p.protocol,
      p.source,
      p.destination,
      `${p.length} bytes`,
      p.info.substring(0, 50) + (p.info.length > 50 ? '...' : '')
    ]);

    autoTable(doc, {
      startY: currentY + 5,
      head: [['ID', 'Proto', 'Source', 'Destination', 'Length', 'Info']],
      body: packetData,
      theme: 'grid',
      styles: { fontSize: 8 },
      headStyles: { fillColor: [71, 85, 105] },
      columnStyles: {
        5: { cellWidth: 60 }
      }
    });

    doc.save(`netview_report_${Date.now()}.pdf`);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setImportStatus('Parsing capture file...');
    setImportError(null);

    try {
      const parsed = await PcapService.parsePcapFile(file);
      if (parsed.length === 0) {
        throw new Error('No valid packets could be decoded from this capture file.');
      }
      onImportPackets(parsed);
      setImportStatus(`Successfully imported ${parsed.length} packets from ${file.name}`);
      setTimeout(() => {
        onClose();
      }, 1000);
    } catch (err: any) {
      setImportError(err.message || 'Failed to parse PCAP file.');
      setImportStatus(null);
    }
  };

  return (
    <motion.div
      {...modalBackdropMotion}
      className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4"
    >
      <motion.div
        {...modalPanelMotion}
        className={`w-full max-w-2xl rounded-xl border flex flex-col shadow-2xl transition-colors ${
          'bg-card border-border text-card-foreground'
        }`}
      >
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <TbDownload className="w-7 h-7 shrink-0 text-primary" />
            <div>
              <div className="font-bold text-base">Capture Import & Export Center</div>
              <p className={`text-xs ${"text-muted-foreground"}`}>Libpcap 2.4 binary format, JSON telemetry & CSV reports</p>
            </div>
          </div>

          <button onClick={onClose} className={`p-1.5 rounded-md hover:bg-accent ${"text-muted-foreground"} hover:text-foreground`}>
            <TbX className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-5 space-y-5 text-xs">
          {/* Permission notice */}
          {!permissions.canExportPcap && (
            <div className="p-2.5 rounded bg-amber-500/10 border border-amber-500/30 text-amber-700 dark:text-amber-300 flex items-center gap-2">
              <TbShield className="w-4 h-4 text-foreground shrink-0" />
              <span>Exporting raw captures is restricted for the Auditor / Guest role.</span>
            </div>
          )}

          {/* Export Options */}
          <div>
            <div className={`font-bold ${"text-foreground/80"} text-sm mb-2`}>Export Active Capture Stream</div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {/* PCAP Binary */}
              <button
                onClick={handleExportPcap}
                disabled={!permissions.canExportPcap || packets.length === 0}
                className={`p-3 rounded-lg border text-left transition-all flex flex-col justify-between gap-2 ${
                  permissions.canExportPcap && packets.length > 0
                    ? isDark
                      ? 'bg-sky-950/30 border-sky-600/50 hover:bg-sky-900/40 text-sky-200'
                      : 'bg-sky-50 border-sky-300 hover:bg-sky-100 text-sky-900'
                    : 'opacity-40 cursor-not-allowed border-border'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs">Libpcap (.pcap)</span>
                  <TbDownload className="w-4 h-4 text-foreground" />
                </div>
                <p className={`text-[11px] ${"text-muted-foreground"}`}>
                  Standard binary libpcap 2.4 file, readable by tcpdump and any standard capture tool
                </p>
              </button>

              {/* JSON */}
              <button
                onClick={handleExportJson}
                disabled={packets.length === 0}
                className={`p-3 rounded-lg border text-left transition-all flex flex-col justify-between gap-2 ${
                  packets.length > 0
                    ? 'bg-muted border-border hover:bg-accent text-foreground'
                    : 'opacity-40 cursor-not-allowed border-border'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs">JSON Telemetry</span>
                  <TbFileCode className="w-4 h-4 text-foreground" />
                </div>
                <p className={`text-[11px] ${"text-muted-foreground"}`}>
                  Structured packet metadata with decoded protocol layer fields
                </p>
              </button>

              {/* CSV */}
              <button
                onClick={handleExportCsv}
                disabled={packets.length === 0}
                className={`p-3 rounded-lg border text-left transition-all flex flex-col justify-between gap-2 ${
                  packets.length > 0
                    ? 'bg-muted border-border hover:bg-accent text-foreground'
                    : 'opacity-40 cursor-not-allowed border-border'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs">Spreadsheet CSV</span>
                  <TbFileText className="w-4 h-4 text-foreground" />
                </div>
                <p className={`text-[11px] ${"text-muted-foreground"}`}>
                  Tabular packet summary for reports, Excel, and SIEM pipelines
                </p>
              </button>

              {/* PDF Report */}
              <button
                onClick={handleExportPdf}
                disabled={packets.length === 0}
                className={`p-3 rounded-lg border text-left transition-all flex flex-col justify-between gap-2 ${
                  packets.length > 0
                    ? isDark
                      ? 'bg-red-950/30 border-red-900/50 hover:bg-red-900/40 text-red-200'
                      : 'bg-red-50 border-red-300 hover:bg-red-100 text-red-900'
                    : 'opacity-40 cursor-not-allowed border-border'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs">PDF Report</span>
                  <TbPhoto className="w-4 h-4 text-foreground" />
                </div>
                <p className={`text-[11px] ${"text-muted-foreground"}`}>
                  Formatted document with stats, alerts, and packet summary
                </p>
              </button>
            </div>
          </div>

          <div className="border-t border-border pt-4">
            <div className={`font-bold ${"text-foreground/80"} text-sm mb-2`}>Import External PCAP Capture</div>
            <label
              className={`border-2 border-dashed rounded-lg p-6 flex flex-col items-center justify-center cursor-pointer transition-colors ${
                'border-border hover:border-sky-500 bg-muted/30'
              }`}
            >
              <TbUpload className="w-8 h-8 text-foreground mb-2" />
              <span className={`font-semibold ${"text-foreground"}`}>Click to upload .pcap or drag & drop</span>
              <span className={`text-[11px] ${"text-muted-foreground"} mt-1 font-mono`}>Supports standard Libpcap 2.4 captures</span>
              <input type="file" accept=".pcap,.pcapng,.cap,.json" onChange={handleFileUpload} className="hidden" />
            </label>

            {importStatus && (
              <div className="mt-2 text-emerald-400 flex items-center gap-1.5 font-medium">
                <TbCheck className="w-4 h-4 text-emerald-400" />
                <span>{importStatus}</span>
              </div>
            )}

            {importError && (
              <div className="mt-2 text-rose-400 flex items-center gap-1.5 font-medium">
                <TbAlertCircle className="w-4 h-4 text-rose-400" />
                <span>{importError}</span>
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border flex justify-end">
          <button
            onClick={onClose}
            className={`px-4 py-1.5 rounded-md bg-secondary hover:bg-accent ${"text-foreground"} font-medium transition-colors`}
          >
            Close
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
};
