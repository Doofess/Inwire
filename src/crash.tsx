import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {CrashScreen} from './components/common/CrashScreen';
import {QuitConfirmDialog} from './components/common/QuitConfirmDialog';
import {RootProviders, prepareDocument} from './components/common/RootProviders';
import './index.css';

// The entry main loads into the window when the renderer dies (`crash.html`).
// It deliberately imports nothing of `App`: the page exists because the app's
// graph just failed, and a second copy of that failure is the one outcome it
// cannot afford. The theme, accent and platform setup is the app's own, shared
// through RootProviders so the two cannot drift.
prepareDocument();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RootProviders>
      {/* Quit is the window's close, and with an unsaved capture the quit guard
          asks through this dialog; nothing else on this page would answer it. */}
      <QuitConfirmDialog />
      <CrashScreen />
    </RootProviders>
  </StrictMode>,
);
