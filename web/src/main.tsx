import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App'
import { configureAmplify } from './lib/auth'
import './index.css'

configureAmplify()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
