import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8080',
      '/healthz': 'http://127.0.0.1:8080',
    },
  },
  build: {
    chunkSizeWarningLimit: 4000, // Monaco is large and self-hosted
  },
  test: {
    coverage: {
      provider: 'v8',
      // Report on everything under src/, not only files a test imported,
      // so the untested areas stay visible instead of silently absent.
      all: true,
      include: ['src/**/*.{ts,tsx}'],
      exclude: ['src/**/*.test.ts', 'src/vite-env.d.ts', 'src/main.tsx'],
      reporter: ['text-summary', 'lcov'],
      reportsDirectory: 'coverage',
    },
  },
});
