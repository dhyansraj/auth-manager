/**
 * Vite plugin that adds the dedupe config needed when @mcpmesh/auth-lib-react
 * is installed via file: path or workspace symlink. Without this, Vite resolves
 * React from the lib's symlinked node_modules → two React instances → null
 * dispatcher error → blank page on render.
 *
 * Usage in tenant SPA's vite.config.ts:
 *   import { mcpmeshAuth } from '@mcpmesh/auth-lib-react/vite-preset';
 *   export default defineConfig({ plugins: [react(), mcpmeshAuth()] });
 */
export function mcpmeshAuth() {
  return {
    name: '@mcpmesh/auth-lib-react/vite-preset',
    config() {
      return {
        resolve: {
          dedupe: ['react', 'react-dom', '@tanstack/react-query'],
        },
      };
    },
  };
}
