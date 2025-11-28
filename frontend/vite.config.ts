import { fileURLToPath, URL } from "url";

import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";
import legacy from "@vitejs/plugin-legacy";
import dynamicImportVars from "@rollup/plugin-dynamic-import-vars";

// https://vitejs.dev/config/
const apiPort = Number(process.env.MOCK_API_PORT || 8080);

export default defineConfig({
  base: "/",
  build: {
    rollupOptions: {
      plugins: [dynamicImportVars()],
    },
  },
  optimizeDeps: {
    exclude: ["@telekom/scale-components", "@telekom/scale-components-neutral", "@duetds/date-picker"],
  },
  ssr: {
    noExternal: ["@telekom/scale-components", "@telekom/scale-components-neutral", "@duetds/date-picker"],
  },
  server: {
    proxy: {
      "/api": `http://localhost:${apiPort}`,
    },
  },
  plugins: [
    legacy({
      targets: ["defaults", "not IE 11"],
    }),
    vue({
      template: {
        compilerOptions: {
          isCustomElement: (tag: string) => tag.startsWith("scale-"),
        },
      },
    }),
  ],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
});
