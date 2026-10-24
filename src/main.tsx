import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import App from './App.tsx';
import {QuitConfirmDialog} from './components/common/QuitConfirmDialog';
import {RootProviders, prepareDocument} from './components/common/RootProviders';
import './index.css';

// Theme migration, platform and accent stamps: shared with the crash page
// (`crash.tsx`), so they live in RootProviders. Before `render`, for the
// first paint.
prepareDocument();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RootProviders>
      {/* Before App, and outside it: App renders ten times a second during a
          capture and this need not, and its key guard has to be the first
          capture-phase listener on `window` - see the component. */}
      <QuitConfirmDialog />
      <App />
    </RootProviders>
  </StrictMode>,
);
