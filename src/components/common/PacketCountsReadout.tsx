import React from 'react';
import { scanPercentage, usePacketCounts } from '../../services/packetCounts';

/**
 * The packet counter, in the middle of the title row.
 *
 * It has been three things. A badge in the filter bar reading
 * `PACKETS: 2,224 / 2,224  100.0%`; then a dock widget you chose to have open;
 * now a permanent fixture of the title row, which is the one strip that is
 * always on screen whatever view is up. The widget is gone - there is no
 * `counts` entry in `WIDGET_TYPE_IDS` any more - because a number that is
 * always visible and a panel you can close are answers to the same question,
 * and keeping both would put the same figures in two places with nothing
 * saying which to trust.
 *
 * **This replaced the window title**, which read `Inwire` when idle and
 * `Ethernet - capturing - Inwire` during a capture. That string still exists
 * and still names the window - `useWindowTitle` sends it to main, so the
 * taskbar and Alt-Tab are unchanged. What it no longer does is take the centre
 * of a row that a person cannot look away from in order to repeat the app's own
 * name back at them.
 *
 * **`windowChrome.ts` argues against exactly this**, and the argument is worth
 * reading before undoing it: a count in the title row "is the most distracting
 * thing that could be put in it", and the count was "already on screen, in the
 * filter bar". Both halves have since stopped being true. The filter bar's
 * badge is gone, and so is the widget that replaced it, so this is the only
 * copy rather than a second one - and the figure is now the *answer to the
 * filter*, which is the question the row below it asks. It is still a number
 * that changes ten times a second, and that is the accepted cost.
 *
 * **It subscribes for itself**, through `usePacketCounts`, and that matters
 * more out of the dock than it did in it. `App` re-renders on every 100ms
 * flush, and this row is on screen in EVERY view - so taking the counts through
 * props would re-render the whole tree to move one number. The old reason was a
 * `React.memo` boundary on `Dock`; there is no memo boundary anywhere in `src/`
 * now, and the reason survives it - see `services/packetCounts.ts`.
 *
 * **The share badge is deleted.** It read `100%` beside `2,224 / 2,224` and
 * `0%` beside `44 / 178,200`, which is the same fact a second time in a weaker
 * unit - the two numbers already say what the filter selected, and they say it
 * exactly rather than rounded. `filterPercentage` went with it: it had one
 * caller and no other, so keeping the arithmetic would have been keeping a
 * tested function nothing reads.
 *
 * The badges that remain are not that. `SCANNING` and `NOT SEARCHED` report a
 * whole-capture pass the two numbers cannot describe, and `+N UNSEARCHED` is a
 * button.
 *
 * ## The one control in the title row
 *
 * `TitleRow`'s comment used to say it holds no control at all. It holds one
 * now: the rescan button below, which is the **only** way to re-run a
 * whole-capture filter scan over frames that arrived after it started. Deleting
 * the widget without bringing that with it would have made it unreachable.
 *
 * It therefore carries `app-no-drag`, and that is load-bearing rather than
 * tidy: the row is `app-drag`, so a control without it moves the window instead
 * of being pressed and the only symptom is a click that does nothing.
 */
const BADGE = 'text-[10px] leading-none px-1.5 py-0.5 rounded font-bold shrink-0';

export const PacketCountsReadout: React.FC = () => {
  const counts = usePacketCounts();
  const scanning = counts.scan?.status === 'scanning';
  const scanPct = scanPercentage(counts.scan);

  return (
    // `data-packet-counts` is a TEST HOOK and the only one in this component.
    //
    // The four Electron drivers under `scripts/electron/` have to find this
    // readout to answer "did frames arrive". They used to do it by matching the
    // string `PACKETS:` in `document.body.innerText` - a label this component
    // rendered when it was a dock widget and stopped rendering when it moved
    // into the title row, where the row's whole argument is that it does not
    // spend space on words. The locator then matched nothing, `rows()` returned
    // `'0'` for ever, and `smoke.ts` reported "frames arrive and are counted"
    // as the failure - which points at the pipe, the Worker and the dissector
    // rather than at itself.
    //
    // An attribute rather than a label, because the fix must not put a word back
    // on screen to satisfy a test. `scripts/session/packet-counts.ts` asserts
    // that this attribute is here AND that every driver queries it, so the two
    // cannot drift apart again in silence.
    <div className="min-w-0 flex items-center gap-2">
      {/* 11px, matching the title this replaced - the row is 32px and these
          numbers are read at a glance rather than studied. The card version was
          20px because a card is a place you look ON PURPOSE; this one has to
          sit in the chrome without becoming the loudest thing in the window. */}
      {/* The hook is on THIS span and not on the row above it: the row also
          holds the scan badges, and its `textContent` runs them straight on to
          the total with no separator - "44 / 178,200" "SCANNING" reads back as
          one string. This span is exactly the two numbers and the slash
          between them, which is what the drivers parse. */}
      <span data-packet-counts className="min-w-0 flex items-baseline gap-1 text-[11px] truncate">
        <span className="font-semibold tabular-nums text-foreground">
          {counts.filtered.toLocaleString()}
        </span>
        <span className="text-muted-foreground">/</span>
        <span className="tabular-nums text-muted-foreground">
          {counts.total.toLocaleString()}
        </span>
      </span>

      {scanning ? (
        <span
          className={`${BADGE} bg-warning/20 text-warning`}
          title={
            counts.scan?.status === 'scanning'
              ? `Filtering the stored capture: ${counts.scan.framesDone.toLocaleString()} of `
                + `${counts.scan.frameCount.toLocaleString()} frames`
              : undefined
          }
        >
          {/* Indeterminate until the first progress message, which is 150,000
              frames in. A percentage of an unknown total is a number, and a
              wrong one. */}
          SCANNING{scanPct === null ? '' : ` ${scanPct}%`}
        </span>
      ) : null}

      {counts.scan?.status === 'failed' && (
        <span
          className={`${BADGE} bg-destructive/20 text-destructive`}
          title={counts.scan.message}
        >
          NOT SEARCHED
        </span>
      )}

      {/* A capture that grew after the scan started, which while one is running
          it always does. Clickable rather than automatic: a scan that re-ran
          itself would be a whole-capture pass about once a second, competing
          with the frames still arriving.

          `app-no-drag` because the row around it is the window's drag region.
          Without it this button moves the window and never fires, and nothing
          reports that - see the class rule in `index.css`. */}
      {counts.uncovered > 0 && counts.onRescan !== undefined && (
        <button
          type="button"
          onClick={counts.onRescan}
          className={`${BADGE} app-no-drag bg-warning/20 text-warning
            hover:bg-warning/30 transition-colors cursor-pointer
            focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-ring`}
          title={`${counts.uncovered.toLocaleString()} stored frames arrived after this filter was `
            + 'run over the capture. Click to run it again.'}
        >
          +{counts.uncovered.toLocaleString()} UNSEARCHED
        </button>
      )}
    </div>
  );
};
