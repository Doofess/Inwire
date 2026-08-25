import React from 'react';
import { motion, useReducedMotion } from 'motion/react';

/**
 * A three-bar menu icon that morphs into a close cross, ported from GitHub's
 * marketing header (`HeaderMenuToggle-module__toggleBar`).
 *
 * The timing is theirs, measured off the live element: 500ms on `opacity` and
 * `transform` with `cubic-bezier(0.16, 1, 0.3, 1)` - the ease-out-expo curve,
 * which spends almost all its travel in the first third and then glides. It is
 * a long duration for an icon, and that is the point: the bars are still
 * settling after the panel has arrived.
 *
 * The detail that gives it its character is that the bars pivot from their
 * *right end* rather than their centre, so the left ends sweep a wide arc into
 * place while the right ends barely move. GitHub anchors the top bar at its
 * right-bottom corner and the bottom bar at its right-top corner; anchoring
 * both at right-centre is within half a pixel at this size and is easier to
 * reason about, so that is what this uses.
 */

/** Bar length. Everything else is derived from it, so the icon scales as a unit. */
const BAR_WIDTH = 18;
const BAR_HEIGHT = 2;
/** Distance between bar centre lines. Chosen for the closed state's proportions. */
const BAR_PITCH = 5;

/**
 * Offsets that land a centred cross when the rotation is anchored at the right
 * end of each bar.
 *
 * Rotating about the right end leaves the bar's midpoint off-centre by a fixed
 * amount, so a translation has to bring it back. Solving `translate(dx, dy)
 * rotate(±45°)` about `right center` for a midpoint at the icon's centre gives
 * dx = -(1 - cos45°)·W/2 and dy = ∓(cos45°·W/2 - pitch). GitHub hand-tuned the
 * equivalent numbers and lands about half a pixel off centre; deriving them
 * keeps this exact at whatever BAR_WIDTH and BAR_PITCH are set to.
 */
const COS_45 = Math.SQRT1_2;
const OPEN_DX = -(1 - COS_45) * (BAR_WIDTH / 2);
const OPEN_DY = COS_45 * (BAR_WIDTH / 2) - BAR_PITCH;

const TRANSITION = {
  duration: 0.5,
  // GitHub's exact curve.
  ease: [0.16, 1, 0.3, 1] as const,
};

const barStyle: React.CSSProperties = {
  width: BAR_WIDTH,
  height: BAR_HEIGHT,
  borderRadius: BAR_HEIGHT,
  backgroundColor: 'currentColor',
};

interface HamburgerIconProps {
  open: boolean;
}

export const HamburgerIcon: React.FC<HamburgerIconProps> = ({ open }) => {
  const reduceMotion = useReducedMotion();
  const transition = reduceMotion ? { duration: 0 } : TRANSITION;

  return (
    <span
      aria-hidden="true"
      className="flex flex-col items-center justify-center"
      style={{ width: BAR_WIDTH, gap: BAR_PITCH - BAR_HEIGHT }}
    >
      <motion.span
        style={{ ...barStyle, transformOrigin: 'right center' }}
        animate={open ? { x: OPEN_DX, y: -OPEN_DY, rotate: -45 } : { x: 0, y: 0, rotate: 0 }}
        transition={transition}
      />
      {/* The middle bar has nowhere to go in a two-stroke cross, so it leaves
          from where it stands rather than sliding out and drawing the eye. */}
      <motion.span
        style={barStyle}
        animate={open ? { scale: 0, opacity: 0 } : { scale: 1, opacity: 1 }}
        transition={transition}
      />
      <motion.span
        style={{ ...barStyle, transformOrigin: 'right center' }}
        animate={open ? { x: OPEN_DX, y: OPEN_DY, rotate: 45 } : { x: 0, y: 0, rotate: 0 }}
        transition={transition}
      />
    </span>
  );
};
