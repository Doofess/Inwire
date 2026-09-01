import React, {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {ThemeProvider} from 'next-themes';
import {MotionConfig} from 'motion/react';
import {TooltipProvider} from './components/ui/tooltip';
import {RETIRED_THEMES, THEME_NAMES, normalizeThemeName} from './lib/themeOptions';
import {motionStore} from './services/interfacePrefs';
import {usePreferenceValue} from './services/preferenceStore';
import App from './App.tsx';
import './index.css';

/**
 * Coerce a stored theme that no longer exists, before anything reads it.
 *
 * next-themes does NOT validate the stored value against the `themes` array it
 * is given. Its pre-hydration script does `classList.add(stored)`
 * unconditionally, and its cleanup only removes classes it currently knows
 * about - so a localStorage holding `dracula` would put `class="dracula"` on
 * <html> with no `.dracula` block behind it. The chrome would fall back to the
 * `:root` light baseline while `themePalette()` fell back to the DARK palette,
 * Tailwind's `dark:` utilities would not apply at all, and the settings picker
 * would show nothing selected. Mixed, which is worse than either extreme.
 *
 * Module scope, before `render`, is the right place: next-themes' script is
 * rendered inside the React tree, so this has already run by the time it looks.
 */
function migrateStoredTheme(): void {
  try {
    const stored = localStorage.getItem('theme');
    const next = normalizeThemeName(stored);
    if (stored !== next) localStorage.setItem('theme', next);
    // Belt and braces: nothing should have applied a retired class yet, but a
    // stale one left on the element would out-specify the theme that follows.
    document.documentElement.classList.remove(...Object.keys(RETIRED_THEMES));
  } catch {
    // A blocked or full localStorage. The app still runs; it just starts on the
    // default theme, which is the same thing next-themes would do.
  }
}

migrateStoredTheme();

/**
 * The app's motion setting, in the form motion/react wants.
 *
 * The mapping is an INVERSION, not the one-to-one this used to claim: the
 * app's setting says whether to animate, motion's says whether to reduce. With
 * "user" hardwired here, choosing Always or Never changed the CSS - which is
 * keyed on a `data-motion` attribute App writes - and left every motion/react
 * component still following the OS. The dashboard's morph and the capture
 * button's icon swap are both motion/react, so that gap is now visible.
 */
function MotionPreference({children}: {children: React.ReactNode}) {
  const [setting] = usePreferenceValue(motionStore);
  return (
    <MotionConfig
      reducedMotion={setting === 'always' ? 'never' : setting === 'never' ? 'always' : 'user'}
    >
      {children}
    </MotionConfig>
  );
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* `themes` has to list every value explicitly once there is more than
        light/dark - next-themes will not apply a class it was not told about.
        Taken from the theme registry so the picker, this list and the CSS
        cannot drift apart; the dark ones among them are also named in
        index.css's @custom-variant. */}
    {/* No `system`. Every entry in the picker now names a real palette, and
        the packet list derives its colours from whichever one is active - so a
        theme that resolves to a different theme at runtime would leave the
        list following something the user never picked. The cost is real and
        worth naming: the app no longer follows the OS light/dark setting. */}
    <ThemeProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem={false}
      themes={THEME_NAMES}
    >
      <MotionPreference>
        <TooltipProvider>
          <App />
        </TooltipProvider>
      </MotionPreference>
    </ThemeProvider>
  </StrictMode>,
);
