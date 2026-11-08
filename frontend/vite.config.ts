/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// The dev server proxies API / Sanctum calls to nginx so that the SPA and the API stay
// same-origin from the browser's point of view (Cookie session + CSRF, no CORS).
const apiTarget = process.env.VITE_PROXY_TARGET ?? 'http://nginx'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': { target: apiTarget, changeOrigin: false },
      '/sanctum': { target: apiTarget, changeOrigin: false },
    },
  },
  build: {
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    restoreMocks: true,
    // docs/test-strategy.md §3: 70% of lines. Measured 94.8% on 2026-11-08 (COV-02). Tests and the lint probes are not code under test.
    coverage: {
      provider: 'v8',
      include: ['src/**'],
      exclude: ['src/**/*.test.*', 'src/test/**'],
      reporter: ['text-summary'],
      thresholds: { lines: 70 },
    },
  },
})
