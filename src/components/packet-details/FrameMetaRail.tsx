import React from 'react';
import type { StreamTarget } from '../../services/followStream';
import {
  Clock,
  Ruler,
  TriangleAlert,
  ArrowRight,
  EyeOff,
  MessageSquare,
  PanelLeftClose,
  PanelLeftOpen,
} from 'lucide-react';
import { FrameSummary, RelatedFrame } from './packetDetailModel';
import { CATEGORY_HINTS, CATEGORY_LABELS, CATEGORY_TEXT, type ExpertItem } from '../../services/expertInfo';

/**
 * Everything about the frame that is READ rather than WORKED IN.
 *
 * The window's content divides by how it is used, not by what it is: the field
 * table and the dump are scrolled, hovered and correlated against each other,
 * while the frame's own facts are glanced at and never scrolled. Giving the
 * second kind a column of its own is what lets the first kind stop being the
 * residue of however much vertical space the chrome happened to take.
 *
 * These facts used to be a `flex-wrap` row of eight items above the body, with
 * a second wrapping row of chips beneath it. Two problems a rail fixes by
 * construction:
 *
 *   - The strip's height depended on the window width and on how long the
 *     values happened to be, so the body below it was a different size every
 *     time the window opened. A column is the same width always.
 *   - Eight flat items in one row have no hierarchy - a timestamp sat at the
 *     same altitude as a navigation button. Here they are grouped by what they
 *     answer: WHEN (timing), WHAT (the frame itself), WHAT IS WRONG
 *     (analysis), WHERE ELSE (navigation).
 *
 * Values WRAP rather than truncate. The strip had to truncate because it had
 * one line; a column has vertical room, and a silently cut-off interface name
 * is worse than a two-line one.
 */

interface FrameMetaRailProps {
  summary: FrameSummary;
  colorRuleName?: string;
  related: RelatedFrame[];
  streamTarget: StreamTarget | null;
  hiddenByFilter: boolean;
  /** What the dissectors found in this frame, each with its category. */
  expert: readonly ExpertItem[];
  /** The go-to-frame control, passed in so the rail owns no lookup logic. */
  frameBox: React.ReactNode;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onFollowStream: (target: StreamTarget) => void;
  onShowFrame: (frameNumber: number) => void;
  /**
   * Width, background, border and positioning, supplied by the caller.
   *
   * The rail appears in four shapes - a column, an icon strip, an overlay
   * floating over the canvas, and a full-width disclosure - and the caller is
   * the only one that knows which. Keeping these OUT of here matters because
   * the app does not run tailwind-merge on these strings: a `w-[17rem]` baked
   * in below and a `w-full` passed in would both survive into the class list,
   * and which won would come down to their order in the generated stylesheet.
   *
   * The BACKGROUND is here for a second reason. In flow the rail is a tint
   * over the card (`bg-secondary/30`); floating over the canvas that same tint
   * is 70% transparent and the field table reads straight through it, so the
   * overlay has to pass an opaque surface instead.
   */
  className?: string;
}

const MetaGroup: React.FC<{
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
}> = ({ label, icon: Icon, children }) => (
  <section className="px-4 py-3 border-b border-border/60 last:border-b-0">
    <h3 className="flex items-center gap-1.5 mb-2 text-[10px] font-bold uppercase tracking-widest text-foreground/70">
      <Icon className="w-3 h-3 shrink-0" />
      <span>{label}</span>
    </h3>
    <div className="flex flex-col gap-2">{children}</div>
  </section>
);

/**
 * One labelled fact. The label sits ABOVE the value rather than beside it - at
 * 17rem a side-by-side label would leave a timestamp about nine characters
 * before it wrapped anyway.
 */
const MetaItem: React.FC<{ label: string; value: string }> = ({ label, value }) => (
  <div className="min-w-0">
    <div className="text-[9px] uppercase tracking-wider text-muted-foreground">{label}</div>
    <div className="font-mono text-[11px] leading-snug text-foreground break-words" title={value}>
      {value}
    </div>
  </div>
);

/** Shared by the stream button and every related-frame link. */
const RailLink: React.FC<{
  onClick: () => void;
  title: string;
  children: React.ReactNode;
}> = ({ onClick, title, children }) => (
  <button
    onClick={onClick}
    title={title}
    // Capped for the same reason as the frame box: full-width on a narrow
    // window this would strand the frame number a thousand pixels from
    // the label it belongs to.
    className="flex w-full max-w-xs items-center gap-1.5 px-2 py-1 rounded border border-border bg-background hover:bg-accent text-[11px] font-mono text-left text-foreground cursor-pointer transition-colors"
  >
    {children}
  </button>
);

export const FrameMetaRail: React.FC<FrameMetaRailProps> = ({
  summary,
  colorRuleName,
  related,
  streamTarget,
  hiddenByFilter,
  expert,
  frameBox,
  collapsed,
  onToggleCollapse,
  onFollowStream,
  onShowFrame,
  className = '',
}) => {
  const hasAnalysis = expert.length > 0 || summary.analysisFlags.length > 0 || hiddenByFilter;

  if (collapsed) {
    return (
      <div
        className={`flex flex-col items-center gap-1 py-2 ${className}`}
      >
        <button
          onClick={onToggleCollapse}
          title="Show frame details"
          aria-label="Show frame details"
          className="p-1.5 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
        >
          <PanelLeftOpen className="w-4 h-4" />
        </button>

        {/* Not buttons: the strip is a reminder of what is behind it, and every
            one of them would open the same panel anyway. The alert icon earns
            its place by being the one thing worth knowing is there while the
            rail is shut. */}
        <div className="mt-1 flex flex-col items-center gap-3 text-muted-foreground">
          <Clock className="w-3.5 h-3.5" />
          <Ruler className="w-3.5 h-3.5" />
          {hasAnalysis && (
            <TriangleAlert className="w-3.5 h-3.5 text-amber-600 dark:text-amber-400" />
          )}
          {(streamTarget !== null || related.length > 0) && (
            <ArrowRight className="w-3.5 h-3.5" />
          )}
        </div>
      </div>
    );
  }

  return (
    <div className={`flex flex-col ${className}`}>
      <div className="flex items-center justify-between px-4 pt-2.5 pb-1 shrink-0">
        <span className="text-[9px] font-bold uppercase tracking-widest text-muted-foreground">
          Frame details
        </span>
        <button
          onClick={onToggleCollapse}
          title="Hide frame details"
          aria-label="Hide frame details"
          className="p-1 rounded-md hover:bg-accent text-muted-foreground hover:text-foreground cursor-pointer"
        >
          <PanelLeftClose className="w-4 h-4" />
        </button>
      </div>

      <div className="flex-1 min-h-0 overflow-y-auto custom-scrollbar">
        <MetaGroup label="Timing" icon={Clock}>
          <MetaItem label="Arrived" value={summary.localTime} />
          <MetaItem label="UTC" value={summary.utcTime} />
          <MetaItem label="Since start" value={`${summary.relativeTime}s`} />
          <MetaItem label="Δ previous" value={`${summary.timeDelta}s`} />
        </MetaGroup>

        <MetaGroup label="Frame" icon={Ruler}>
          <MetaItem
            label="Length"
            value={
              summary.captureLength === null
                ? `${summary.frameLength} bytes`
                : `${summary.frameLength} on wire, ${summary.captureLength} captured`
            }
          />
          <MetaItem label="Interface" value={summary.interfaceName} />
          {colorRuleName && <MetaItem label="Coloring rule" value={colorRuleName} />}
          {summary.protocolChain.length > 0 && (
            <MetaItem label="Layers" value={summary.protocolChain.join(' › ')} />
          )}
        </MetaGroup>

        {/* Omitted entirely rather than rendered empty - a clean frame should
            not carry a heading announcing that nothing is wrong with it. */}
        {hasAnalysis && (
          <MetaGroup label="Analysis" icon={TriangleAlert}>
            {/* Category above summary rather than beside it: at 17rem a
                finding like "[TCP Previous segment not captured]" beside its
                label would wrap anyway, and wrap mid-phrase. */}
            {expert.map((item, i) => (
              <div
                // Index in the key: a frame can carry the same finding twice -
                // two fragments of one datagram both overlapping, say.
                key={`${item.category}|${item.summary}|${i}`}
                className="min-w-0"
                title={CATEGORY_HINTS[item.category]}
              >
                <div className={`text-[9px] uppercase tracking-wider font-semibold ${CATEGORY_TEXT[item.category]}`}>
                  {CATEGORY_LABELS[item.category]}
                </div>
                <div className="font-mono text-[11px] leading-snug text-foreground break-words">
                  {item.summary}
                </div>
              </div>
            ))}

            {summary.analysisFlags.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {summary.analysisFlags.map(flag => (
                  <span
                    key={flag}
                    className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-500/15 text-amber-600 dark:text-amber-400 border border-amber-500/30"
                  >
                    {flag}
                  </span>
                ))}
              </div>
            )}

            {/* A frame reachable by number is not necessarily on screen behind
                this window. Saying so beats letting the user close it and hunt
                for a row the filter is hiding. */}
            {hiddenByFilter && (
              <div
                className="flex items-start gap-1.5 text-[10px] font-mono leading-snug text-muted-foreground"
                title="This frame does not match the active display filter, so it is not in the list behind this window."
              >
                <EyeOff className="w-3 h-3 shrink-0 mt-0.5" />
                <span>Hidden by display filter</span>
              </div>
            )}
          </MetaGroup>
        )}

        <MetaGroup label="Go to" icon={ArrowRight}>
          {frameBox}

          {streamTarget !== null && (
            <RailLink
              onClick={() => onFollowStream(streamTarget)}
              title={`Follow this ${streamTarget.kind.toUpperCase()} stream`}
            >
              <MessageSquare className="w-3 h-3 shrink-0" />
              <span className="truncate">
                {streamTarget.kind.toUpperCase()} stream
                {streamTarget.streamId !== undefined ? ` ${streamTarget.streamId}` : ''}
              </span>
            </RailLink>
          )}

          {related.map(ref => (
            <RailLink
              key={`${ref.label}-${ref.frameNumber}`}
              onClick={() => onShowFrame(ref.frameNumber)}
              title={`Show frame ${ref.frameNumber}`}
            >
              <span className="truncate text-muted-foreground">{ref.label}</span>
              <span className="ml-auto shrink-0 text-primary">{ref.frameNumber}</span>
            </RailLink>
          ))}
        </MetaGroup>
      </div>
    </div>
  );
};
