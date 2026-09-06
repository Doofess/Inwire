import React from 'react';
import type { Packet } from '../../types/packet';
import {
  CATEGORY_HINTS, CATEGORY_LABELS, CATEGORY_TEXT, expertItemsFor,
} from '../../services/expertInfo';

/**
 * What the dissectors found in this frame, above its tree.
 *
 * This replaced `AnomalyBanners`, which drew a rose panel per `AnomalyInfo` -
 * and there were exactly **two** anomalies in the whole app, both TCP, both
 * duplicating an analysis flag that already raised a finding. So the banner
 * that looked like the app's headline warning could only ever say
 * "retransmission" or "out of order", while a bad checksum, an expired
 * certificate, a fragment overlap and an ignored TLS record all passed it by
 * in silence.
 *
 * Every finding on the frame appears here instead, each carrying its category.
 * It is smaller and quieter than what it replaced on purpose: the banners were
 * a wall of description and recommendation prose for two conditions, and the
 * thing a reader actually needs is which findings are on this frame - the row
 * colour and the Expert Information tab carry the rest.
 */
export const ExpertFindings: React.FC<{
  packet: Packet;
  className?: string;
}> = ({ packet, className }) => {
  const items = expertItemsFor(packet);
  if (items.length === 0) return null;

  return (
    <div className={`flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs ${className ?? ''}`}>
      {items.map((item, i) => (
        <span
          // Index in the key: a frame can legitimately carry the same finding
          // twice - two fragments of one datagram both overlapping, say - and
          // the summary alone would collide.
          key={`${item.category}|${item.summary}|${i}`}
          className="flex items-center gap-1.5 min-w-0"
          title={CATEGORY_HINTS[item.category]}
        >
          <span className={`font-semibold shrink-0 ${CATEGORY_TEXT[item.category]}`}>
            {CATEGORY_LABELS[item.category]}
          </span>
          <span className="text-foreground/80 truncate">{item.summary}</span>
        </span>
      ))}
    </div>
  );
};
