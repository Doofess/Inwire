import React from 'react';
import { AnomalyInfo } from '../../types/packet';

/**
 * The security-alert banners for a frame.
 *
 * Extracted so the bottom pane and the packet detail window show identical
 * alerts. In the pane they sit above a narrow tree; in the detail window they
 * span the full width above both columns, which is where a wide window should
 * put the one thing on screen that says something is wrong.
 */
export const AnomalyBanners: React.FC<{ anomalies?: AnomalyInfo[]; className?: string }> = ({
  anomalies,
  className,
}) => {
  if (!anomalies || anomalies.length === 0) return null;

  return (
    <div className={`space-y-2 ${className ?? ''}`}>
      {anomalies.map((anomaly, idx) => (
        <div
          key={idx}
          className="p-3 rounded-lg border text-xs bg-rose-50 dark:bg-rose-500/10 border-rose-300 dark:border-rose-500/30 text-rose-900 dark:text-rose-200"
        >
          <div className="flex items-center gap-2 font-bold uppercase tracking-wider">
            <div className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
            <span className="text-rose-500 text-[10px]">Alert Active</span>
            <span className="text-rose-950 dark:text-slate-200 font-semibold">{anomaly.title}</span>
          </div>
          <p className="mt-1 text-[11px] text-rose-900/80 dark:text-rose-200/90 leading-relaxed font-sans">
            {anomaly.description}
          </p>
          {anomaly.recommendation && (
            <div className="mt-1.5 pt-1.5 border-t border-rose-300 dark:border-rose-500/20 text-[10px] text-rose-700 dark:text-rose-300 font-mono">
              <b>RECOMMENDED ACTION:</b> {anomaly.recommendation}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};
