import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import {ThemeProvider} from 'next-themes';
import {TooltipProvider} from './components/ui/tooltip';
import App from './App.tsx';
import './index.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {/* `themes` has to list every value explicitly once there is more than
        light/dark - next-themes will not apply a class it was not told about.
        "mono" is a second DARK theme, so it is also named in the dark array
        below via index.css's @custom-variant. */}
    <ThemeProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      themes={['light', 'dark', 'mono']}
    >
      <TooltipProvider>
        <App />
      </TooltipProvider>
    </ThemeProvider>
  </StrictMode>,
);
