import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'bff/index': 'src/bff/index.ts',
    'pkce/index': 'src/pkce/index.ts',
    'vite-preset/index': 'src/vite-preset/index.ts',
  },
  format: ['esm'],
  dts: true,
  clean: true,
  external: ['react', 'react-oidc-context', '@tanstack/react-query'],
});
