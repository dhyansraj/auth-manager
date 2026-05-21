import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/admin/',
  server: {
    port: 5173,
    proxy: {
      // Dev proxy: the SPA fetches /admin/api/v1/* — strip the /admin prefix
      // and forward to the auth-manager backend on :8080 (which serves /api/v1/*).
      '/admin/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (p) => p.replace(/^\/admin/, ''),
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: true,
  },
});
