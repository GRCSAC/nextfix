import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5190,
    proxy: { '/api': 'http://127.0.0.1:8790' },
  },
  build: { outDir: 'dist', emptyOutDir: true, sourcemap: false },
});
