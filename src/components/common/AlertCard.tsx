import React from 'react';
import { motion } from 'motion/react';

import { modalPanelMotion } from '../../lib/modalMotion';

/**
 * The card an alert dialog is drawn on: icon, bold title, message, muted
 * detail, and a bordered footer for its buttons.
 *
 * Shared by `QuitConfirmDialog` and `CrashScreen` so the two read as one
 * family. The crash screen is a separate page with its own React root, so it
 * cannot reuse the quit dialog itself, and a second copy of this markup would
 * drift the first time one of them was touched.
 */
export interface AlertCardProps {
  /** The glyph, already coloured: the token says what kind of alert this is. */
  icon: React.ReactNode;
  title: string;
  /** Ids the host's `aria-labelledby` / `aria-describedby` point at. */
  titleId: string;
  message: string;
  messageId: string;
  detail?: string;
  /** The footer's buttons, secondary first and the primary last. */
  children: React.ReactNode;
}

export function AlertCard(
  { icon, title, titleId, message, messageId, detail, children }: AlertCardProps,
): React.ReactElement {
  return (
    <motion.div
      {...modalPanelMotion}
      className="rounded-xl border border-border bg-card shadow-2xl"
    >
      <div className="flex items-start gap-3 px-5 pt-4 pb-3">
        {icon}
        <div className="min-w-0 space-y-1.5">
          <h2 id={titleId} className="text-base font-bold text-balance">
            {title}
          </h2>
          <p id={messageId} className="text-sm text-foreground/90 text-pretty">
            {message}
          </p>
          {detail !== undefined && (
            <p className="text-xs leading-relaxed text-muted-foreground text-pretty">
              {detail}
            </p>
          )}
        </div>
      </div>
      <div className="flex justify-end gap-2 border-t border-border px-5 py-3">
        {children}
      </div>
    </motion.div>
  );
}

const BUTTON = 'rounded-md px-4 py-1.5 text-xs font-medium transition-[background-color,scale] active:scale-95';

/** A footer button: `secondary` is the quieter answer, `primary` the default. */
export function AlertButton(
  { variant, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
    variant: 'primary' | 'secondary';
    ref?: React.Ref<HTMLButtonElement>;
  },
): React.ReactElement {
  const look = variant === 'primary'
    ? 'bg-primary text-primary-foreground hover:bg-primary/90'
    : 'bg-secondary text-foreground hover:bg-accent';
  return <button type="button" {...rest} className={`${BUTTON} ${look}`} />;
}
