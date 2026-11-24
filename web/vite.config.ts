/// <reference types="vitest/config" />
import tailwindcss from '@tailwindcss/vite';
import { bootScript } from '@uwusuite/design';
import react from '@vitejs/plugin-react';
import { defineConfig, type Plugin } from 'vite';

// `pnpm dev` talks to a UwULock Server on this machine (docs/development.md): the web vault and
// the API have to share one origin, as they do when the server serves the build.
const server = process.env.UWULOCK_DEV_SERVER ?? 'http://127.0.0.1:8443';

/**
 * Theme, contrast and motion go onto <html> before the first paint, so a dark page never flashes
 * white. As the file /boot.js, not inline, because the server's CSP allows only script-src 'self'
 * (as in UwUMail). The key is KEY in src/lib/settings.ts.
 */
function boot(): Plugin {
  // Without a stored theme this app is dark (DEFAULT_SETTINGS), the package's script says "system".
  const source = bootScript('uwulock.settings').replace('s.theme||"system"', 's.theme||"dark"');
  if (!source.includes('s.theme||"dark"'))
    throw new Error('bootScript changed: set the dark default again');
  return {
    name: 'uwulock-boot',
    configureServer(dev) {
      dev.middlewares.use('/boot.js', (_request, response) => {
        response.setHeader('content-type', 'text/javascript');
        response.end(source);
      });
    },
    generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'boot.js', source });
    },
  };
}

export default defineConfig({
  plugins: [react(), tailwindcss(), boot()],
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
    // The WebAuthn and SSO connectors are pages of their own, at the paths Bitwarden's clients open.
    rollupOptions: {
      input: {
        main: 'index.html',
        webauthn: 'webauthn-connector.html',
        'webauthn-mobile': 'webauthn-mobile-connector.html',
        'webauthn-fallback': 'webauthn-fallback-connector.html',
        sso: 'sso-connector.html',
      },
    },
  },
  test: {
    environment: 'jsdom',
    include: ['src/**/*.test.{ts,tsx}'],
  },
});
