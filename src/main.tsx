import React, {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {ThemeProvider, useTheme} from 'next-themes';
import {MotionConfig} from 'motion/react';
import {RETIRED_THEMES, THEME_NAMES, isDarkTheme, normalizeThemeName} from './lib/themeOptions';
import {motionStore} from './services/interfacePrefs';
import {accentColorStore} from './services/themePrefs';
import {usePreferenceValue} from './services/preferenceStore';
import App from './App.tsx';
import {QuitConfirmDialog} from './components/common/QuitConfirmDialog';
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
 * The host OS, on <html>, for the stylesheet.
 *
 * `data-platform` carries `process.platform` as the preload reports it -
 * `win32`, `darwin`, `linux` - so a rule can be true of one OS and not the
 * others. The one consumer today is index.css's `--font-weight-medium` remap,
 * which encodes a fact about DirectWrite and has no business applying to Core
 * Text. Read from the bridge rather than sniffed from `navigator`, for the
 * reason preload.ts gives: main simply knows. Module scope, before `render`,
 * so the first paint is already in the right weights.
 */
function stampPlatform(): void {
  document.documentElement.dataset.platform = window.inwire?.platform ?? 'unknown';
}

stampPlatform();

/**
 * The accent swatch, as `data-accent-color` on <html> (ADR 0056). Module scope
 * for the reason the platform is: the first paint is already in the chosen
 * accent rather than Blue corrected a frame later. Re-stamped on change, so the
 * picker needs no path of its own to the document.
 */
function stampAccentColor(): void {
  document.documentElement.dataset.accentColor = accentColorStore.get();
}

stampAccentColor();
accentColorStore.subscribe(stampAccentColor);

/**
 * The app's motion setting, in the form motion/react wants.
 *
 * The mapping is an INVERSION, not the one-to-one this used to claim: the
 * app's setting says whether to animate, motion's says whether to reduce. With
 * "user" hardwired here, choosing Always or Never changed the CSS - which is
 * keyed on a `data-motion` attribute App writes - and left every motion/react
 * component still following the OS. The modals' enter/exit (Settings,
 * Export/Import, the import error dialog - see `lib/modalMotion.ts`) and the
 * tour overlay are motion/react, so that gap is visible on them.
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

/**
 * Tells the browser which way to draw its OWN widgets.
 *
 * next-themes writes `color-scheme` inline on `<html>`, and it only understands
 * the literal strings `light` and `dark` - so any theme stored under another
 * id resolved to `light`, which is what every theme this app has shipped and
 * retired did (`RETIRED_THEMES`), Night included while it was `midnight`. An
 * inline style beats any rule a stylesheet could carry. The visible
 * result was a light-grey native calendar popping out of a near-black app, and
 * the same applies to scrollbars, form controls and focus rings: they are
 * rendered by the browser outside the page and no selector here can reach them.
 *
 * `color-scheme` is the one thing they honour, so it is set from the app's own
 * `isDarkTheme` rather than left to a library that cannot know.
 */
function ColorScheme({children}: {children: React.ReactNode}) {
  const {resolvedTheme} = useTheme();
  React.useEffect(() => {
    document.documentElement.style.colorScheme = isDarkTheme(resolvedTheme) ? 'dark' : 'light';
  }, [resolvedTheme]);
  return <>{children}</>;
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* `themes` is taken from the theme registry rather than written out here,
        so the picker, this list and the CSS cannot drift apart - next-themes
        will not apply a class it was not told about. The dark ones among them
        are also named in index.css's @custom-variant. */}
    {/* `enableSystem={false}`, and the app DOES still follow the OS - those
        two are not in tension. next-themes' own system mode resolves the OS
        preference to whichever themes are literally named `light` and `dark`,
        which is a naming coincidence rather than a decision: it was the wrong
        answer outright while the `dark` id belonged to Graphite, and it would
        be wrong again the moment a third theme arrives. So System is a MODE
        over a declared pair instead - `SYSTEM_THEME_PAIR` and
        `useSystemThemePreference` in lib/useSystemTheme.ts, offered in the
        picker as `SYSTEM_THEME_OPTION` and stored as its own boolean. What
        next-themes holds here is always a concrete theme, which is what the
        packet list needs: it derives its colours from the active theme, and a
        value that resolves to a different theme at runtime would leave the
        list following something the user never picked. */}
    <ThemeProvider
      attribute="class"
      defaultTheme="dark"
      enableSystem={false}
      themes={THEME_NAMES}
    >
      <ColorScheme>
      <MotionPreference>
        {/* Before App, and outside it: App renders ten times a second during a
            capture and this need not, and its key guard has to be the first
            capture-phase listener on `window` - see the component. */}
        <QuitConfirmDialog />
        <App />
      </MotionPreference>
      </ColorScheme>
    </ThemeProvider>
  </StrictMode>,
);
