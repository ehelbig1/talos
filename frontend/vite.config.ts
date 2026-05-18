import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 3000,
    // Proxy API calls to the backend during dev.
    //
    // IMPORTANT: use API_PROXY_TARGET (no VITE_ prefix) for the server-side
    // proxy target.  Variables prefixed with VITE_ are statically inlined into
    // the client bundle by Vite — if we used VITE_API_URL here AND in
    // graphqlClient.ts, the browser would try to connect directly to the
    // Docker-internal hostname and fail with ERR_NAME_NOT_RESOLVED.
    //
    // The browser always uses relative paths (/graphql, /api, /ws) which the
    // Vite dev server transparently forwards to API_PROXY_TARGET.
    // Outside Docker, set API_PROXY_TARGET=http://localhost:8000 in your shell.
    proxy: {
      '/graphql': {
        target: process.env.API_PROXY_TARGET || 'http://localhost:8000',
        changeOrigin: true,
        // Only disable TLS cert verification in development.  Never set this
        // to false in a production build — it opens the door to MITM attacks.
        secure: process.env.NODE_ENV === 'production',
        cookieDomainRewrite: 'localhost',
        configure: (proxy, _options) => {
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            if (req.headers.cookie) {
              proxyReq.setHeader('cookie', req.headers.cookie);
            }
          });
        },
      },
      '/api': {
        target: process.env.API_PROXY_TARGET || 'http://localhost:8000',
        changeOrigin: true,
        secure: process.env.NODE_ENV === 'production',
        cookieDomainRewrite: 'localhost',
        configure: (proxy, _options) => {
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            if (req.headers.cookie) {
              proxyReq.setHeader('cookie', req.headers.cookie);
            }
          });
        },
      },
      '/auth/oauth': {
        target: process.env.API_PROXY_TARGET || 'http://localhost:8000',
        changeOrigin: true,
        secure: process.env.NODE_ENV === 'production',
        cookieDomainRewrite: 'localhost',
        configure: (proxy, _options) => {
          proxy.on('proxyReq', (proxyReq, req, _res) => {
            if (req.headers.cookie) {
              proxyReq.setHeader('cookie', req.headers.cookie);
            }
          });
        },
      },
      '/ws': {
        target: process.env.API_PROXY_TARGET || 'http://localhost:8000',
        changeOrigin: true,
        secure: process.env.NODE_ENV === 'production',
        ws: true,
        configure: (proxy, _options) => {
          proxy.on('proxyReqWs', (proxyReq, req, _socket, _options, _head) => {
            if (req.headers.cookie) {
              proxyReq.setHeader('cookie', req.headers.cookie);
            }
          });
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': '/src',
    },
  },
  // ✅ PRODUCTION BUILD OPTIMIZATIONS
  build: {
    // Target modern browsers for better tree-shaking
    target: 'es2020',

    // Enable minification
    minify: 'terser',

    // Terser options for production optimization
    terserOptions: {
      compress: {
        // Remove console.log in production for security and performance
        drop_console: process.env.NODE_ENV === 'production',
        drop_debugger: true,
        // Remove unreachable code
        dead_code: true,
        // Optimize boolean expressions
        booleans: true,
      },
      mangle: {
        // Mangle variable names for smaller bundle
        safari10: true,
      },
      format: {
        // Remove comments
        comments: false,
      },
    },

    // ✅ CODE SPLITTING: Manual chunks for better caching
    // Separate vendor code that changes less frequently from app code
    rollupOptions: {
      output: {
        // Manual chunk splitting strategy (avoid circular dependencies)
        manualChunks: (id) => {
          // Only process node_modules
          if (!id.includes('node_modules')) {
            return undefined; // App code stays in main chunk
          }

          // React core stays with the rest of the vendor bundle.
          // Splitting it into a separate chunk caused a runtime
          // "Cannot read properties of undefined (reading 'createContext')"
          // because some libraries in the catch-all `vendor` chunk called
          // React.createContext at module-evaluation time before
          // react-vendor had been fully evaluated by the browser. Falling
          // through to the catch-all `return 'vendor'` keeps React with
          // every consumer.
          // (Re-introduce a separate chunk only after auditing every
          // vendor lib for top-level React.createContext / hooks calls.)

          // React Flow - large visualization library
          if (id.includes('/@xyflow/')) {
            return 'xyflow';
          }

          // Zustand state management
          if (id.includes('/zustand/')) {
            return 'zustand';
          }

          // UI components (shadcn/ui and Radix)
          if (id.includes('/@radix-ui/') || id.includes('/class-variance-authority/')) {
            return 'ui-components';
          }

          // All other node_modules - common vendor chunk
          return 'vendor';
        },

        // Naming strategy for chunks (includes hash for cache busting)
        chunkFileNames: 'assets/[name]-[hash].js',
        entryFileNames: 'assets/[name]-[hash].js',
        assetFileNames: 'assets/[name]-[hash].[ext]',
      },
    },

    // Chunk size warning threshold (default: 500 KB)
    chunkSizeWarningLimit: 600,

    // Source maps for production debugging (optional - disable for smaller builds)
    sourcemap: process.env.NODE_ENV !== 'production',

    // CSS code splitting
    cssCodeSplit: true,

    // Optimize dependencies during build
    commonjsOptions: {
      include: [/node_modules/],
      extensions: ['.js', '.cjs'],
    },
  },

  // Optimize dependency pre-bundling in development
  optimizeDeps: {
    include: ['react', 'react-dom', '@xyflow/react', 'zustand'],
    exclude: [],
  },
});
