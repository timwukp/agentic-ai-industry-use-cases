import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { VitePWA } from 'vite-plugin-pwa'

export default defineConfig({
  plugins: [
    react(),
    VitePWA({
      registerType: 'autoUpdate',
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
