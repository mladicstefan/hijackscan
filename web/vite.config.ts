import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// `npm run dev`:   http://127.0.0.1:5173, live reload; /api requests go to `hijackscan serve` on port 8000.
// `npm run build`: web/dist/, which `hijackscan serve` then serves itself at http://127.0.0.1:8000/.
export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": "http://127.0.0.1:8000" },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
  },
});
