import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
      // Emit the registration inside the app bundle instead of the standalone
      // registerSW.js, so src/lib/swUpdate.ts can react to a waiting worker.
      // Without this, `autoUpdate` installs the new SW but the open tab keeps
      // rendering the precached index.html until the user hard-reloads — the
      // reason a shipped feature stayed invisible after a successful deploy.
      injectRegister: null,
      includeAssets: ['icons/icon.svg'],
      manifest: {
        name: 'Agentic AI Industry Use Cases',
        short_name: 'Agentic AI',
        description:
          'Unified console for industry agentic AI use cases: dashboards + AgentCore chat.',
        theme_color: '#0f172a',
        background_color: '#0f172a',
        display: 'standalone',
        start_url: '/',
        icons: [
          {
            src: 'icons/icon.svg',
            sizes: 'any',
            type: 'image/svg+xml',
            purpose: 'any',
          },
          {
            src: 'icons/icon.svg',
            sizes: 'any',
            type: 'image/svg+xml',
            purpose: 'maskable',
          },
        ],
      },
      workbox: {
        // Never let the SW intercept API / agent streaming calls.
        navigateFallbackDenylist: [/^\/api\//, /^\/agent\//],
        runtimeCaching: [],
      },
    }),
  ],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          react: ['react', 'react-dom', 'react-router-dom'],
          amplify: ['aws-amplify', 'aws-amplify/auth'],
          charts: ['recharts'],
        },
      },
    },
  },
  server: {
    port: 5173,
  },
})
