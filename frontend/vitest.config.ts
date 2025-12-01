import { fileURLToPath } from "url";
import { defineConfig, mergeConfig } from "vitest/config";
import viteConfig from "./vite.config";

export default mergeConfig(
  viteConfig,
  defineConfig({
    test: {
      globals: true,
      environment: "jsdom",
      include: ["src/**/*.{test,spec}.ts", "tests/**/*.{test,spec}.ts"],
      exclude: ["node_modules", "dist"],
      coverage: {
        provider: "v8",
        reporter: ["text", "json", "html"],
        reportsDirectory: "./coverage",
        include: ["src/**/*.ts", "src/**/*.vue"],
        exclude: [
          "src/**/*.d.ts",
          "src/main.ts",
          "src/shims-*.d.ts",
          "**/__tests__/**",
          "**/*.spec.ts",
          "**/*.test.ts",
        ],
      },
      setupFiles: ["./tests/setup.ts"],
      alias: {
        "@": fileURLToPath(new URL("./src", import.meta.url)),
      },
    },
  })
);
