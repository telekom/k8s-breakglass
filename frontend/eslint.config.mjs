import pluginVue from "eslint-plugin-vue";
import vuejsAccessibility from "eslint-plugin-vuejs-accessibility";
import eslintPluginPrettierRecommended from "eslint-plugin-prettier/recommended";
import { defineConfigWithVueTs, vueTsConfigs } from "@vue/eslint-config-typescript";

export default defineConfigWithVueTs(
  {
    ignores: [
      "dist",
      "dist-ssr",
      "node_modules",
      "coverage",
      "logs",
      "*.log",
      "npm-debug.log*",
      "yarn-debug.log*",
      "yarn-error.log*",
      "pnpm-debug.log*",
      "lerna-debug.log*",
      ".DS_Store",
      "*.local",
      ".vscode/**",
      ".idea/**",
      "*.suo",
      "*.ntvs*",
      "*.njsproj",
      "*.sln",
      "*.sw?",
      "public",
      "cypress/videos/**",
      "cypress/screenshots/**",
      "playwright-report/**",
      "playwright-report-e2e/**",
      "test-results/**",
      ".playwright/**",
    ],
  },
  pluginVue.configs["flat/recommended"],
  vueTsConfigs.recommended,
  ...vuejsAccessibility.configs["flat/recommended"],
  {
    rules: {
      "vue/attribute-hyphenation": "off",
      "vue/v-on-event-hyphenation": "off",
      "vue/no-deprecated-slot-attribute": "off",
      "no-console": ["error", { allow: ["warn", "error"] }],
      "vuejs-accessibility/label-has-for": "off",
      "vuejs-accessibility/form-control-has-label": "off",
      // radiogroup containers delegate focus to child role="radio" elements
      // via roving tabindex — the container itself must NOT be focusable.
      "vuejs-accessibility/interactive-supports-focus": "off",
    },
  },
  {
    // Disable one-component-per-file rule for test files; relax console usage
    files: ["**/*.spec.ts", "**/*.test.ts", "**/__tests__/**/*.ts"],
    rules: {
      "vue/one-component-per-file": "off",
      "no-console": "off",
    },
  },
  {
    // E2E test helpers and Playwright fixtures use console for debug output
    files: ["tests/e2e/**/*.ts", "tests/screenshots/**/*.ts"],
    rules: {
      "no-console": "off",
    },
  },
  {
    // Mock API server uses console for startup/debug output
    files: ["mock-api/**/*.mjs", "mock-api/**/*.js"],
    rules: {
      "no-console": "off",
    },
  },
  eslintPluginPrettierRecommended,
);
