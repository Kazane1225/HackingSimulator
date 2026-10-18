import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Relative base so the build works on GitHub Pages under /<repo>/ as well as
// at the domain root (and inside the nginx Docker image) without extra config.
export default defineConfig({
  base: "./",
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    // Same-origin /api/ like the gateway in docker-compose.real.yml. Without a
    // running lab server the app keeps using the in-browser simulation.
    proxy: {
      "/api": {
        target: process.env.HACKLAB_SERVER ?? "http://localhost:3000",
        rewrite: (path) => path.replace(/^\/api/, ""),
      },
    },
  },
  preview: {
    host: true,
    port: 4173,
    proxy: {},
  },
});
