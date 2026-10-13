import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
// TraceMap's typefaces: Archivo (condensed display), Public Sans (body), JetBrains Mono.
import '@fontsource-variable/archivo'
import '@fontsource/public-sans/400.css'
import '@fontsource/public-sans/600.css'
import '@fontsource/public-sans/700.css'
import '@fontsource/jetbrains-mono/400.css'
import '@fontsource/jetbrains-mono/500.css'
import './index.css'
import App from './App.tsx'

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
