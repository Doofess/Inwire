import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {CrashScreen} from './components/common/CrashScreen';
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
      {/* No QuitConfirmDialog: main clears its unsaved-capture flag when the
          page dies, so the quit guard never asks this page anything. */}
      <CrashScreen />
    </RootProviders>
  </StrictMode>,
);
