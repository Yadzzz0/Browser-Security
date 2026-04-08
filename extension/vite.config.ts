import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'path';
import { copyFileSync, mkdirSync, existsSync, readdirSync } from 'fs';

// Chrome Extension Multi-Entry Vite Config
export default defineConfig({
  plugins: [
    react(),
    // Custom plugin to copy static assets after build
    {
      name: 'copy-extension-assets',
      closeBundle() {
        const distDir = resolve(__dirname, 'dist');
        const popupDir = resolve(distDir, 'popup');
        const iconsDir = resolve(distDir, 'icons');
        
        if (!existsSync(popupDir)) mkdirSync(popupDir, { recursive: true });
        if (!existsSync(iconsDir)) mkdirSync(iconsDir, { recursive: true });

        // Copy popup.html
        try {
          copyFileSync(resolve(__dirname, 'src/popup/popup.html'), resolve(distDir, 'popup/popup.html'));
        } catch (e) { console.warn('Could not copy popup.html:', e); }

        // Copy manifest.json
        try {
          copyFileSync(resolve(__dirname, 'manifest.json'), resolve(distDir, 'manifest.json'));
        } catch (e) { console.warn('Could not copy manifest.json:', e); }

        // Copy icons
        try {
          const srcIcons = resolve(__dirname, 'icons');
          if (existsSync(srcIcons)) {
            readdirSync(srcIcons).forEach(file => {
              copyFileSync(resolve(srcIcons, file), resolve(iconsDir, file));
            });
          }
        } catch (e) { console.warn('Could not copy icons:', e); }
        
        console.log('✅ All Extension assets (manifest, forms, icons) copied to dist/');
      }
    }
  ],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      input: {
        // Background service worker
        background: resolve(__dirname, 'src/background.ts'),
        // Content script
        content: resolve(__dirname, 'src/content.ts'),
        // Extension popup
        popup: resolve(__dirname, 'src/popup/popup.tsx'),
      },
      output: {
        // Flat output - no hashed filenames (Chrome extension requirement)
        entryFileNames: (chunkInfo) => {
          if (chunkInfo.name === 'popup') return 'popup/popup.js';
          return '[name].js';
        },
        chunkFileNames: 'chunks/[name].js',
        assetFileNames: 'assets/[name].[ext]',
        // Single format for content scripts and background
        format: 'esm',
        inlineDynamicImports: false,
      }
    }
  },
  resolve: {
    alias: {
      '@': resolve(__dirname, 'src'),
    }
  }
});
