import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { configureAmplify } from './lib/auth'
import { registerServiceWorker } from './lib/swUpdate'
import './index.css'

configureAmplify()
registerServiceWorker()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
