/// <reference types="vitest/config" />
import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// `pnpm dev` talks to a UwULock Server on this machine (docs/development.md): the web vault and
// the API have to share one origin, as they do when the server serves the build.
const server = process.env.UWULOCK_DEV_SERVER ?? 'http://127.0.0.1:8443';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      ['/api', '/identity', '/uwu', '/alive', '/healthz'].map((path) => [
        path,
        { target: server, changeOrigin: false, secure: false },
      ]),
    ),
  },
  build: {
    target: 'es2022',
    // The server embeds every file; no source maps, and the WebAssembly as a file of its own.
    sourcemap: false,
    assetsInlineLimit: 0,
    chunkSizeWarningLimit: 1500,
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
