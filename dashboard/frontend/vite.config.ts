import path from "node:path";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// The dashboard talks to the FastAPI backend over the same origin: Vite proxies
// ``/api`` to it in development. This keeps CORS out of the picture and, more
// importantly, guarantees the AI API key never reaches the browser.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    host: "127.0.0.1",
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8756",
        changeOrigin: false,
        ws: false,
        // Server-Sent Events must not be buffered.
        configure: (proxy) => {
          proxy.on("proxyRes", (proxyRes) => {
            if (proxyRes.headers["content-type"]?.includes("text/event-stream")) {
              proxyRes.headers["cache-control"] = "no-cache";
            }
          });
        },
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
  },
});
