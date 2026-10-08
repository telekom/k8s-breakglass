// Design-token guard: raw colours and pixel font sizes belong in
// src/assets/tokens.css only; everything else uses Scale/app tokens.
/** @type {import("stylelint").Config} */
export default {
  extends: ["stylelint-config-html/vue"],
  ignoreFiles: ["dist/**", "coverage/**", "playwright-report*/**", "test-results*/**", "node_modules/**"],
  rules: {
    "color-no-hex": true,
    "color-named": "never",
    "function-disallowed-list": ["rgb", "rgba", "hsl", "hsla", "hwb", "lab", "lch", "oklab", "oklch"],
    "declaration-property-value-disallowed-list": {
      "/^font(-size)?$/": ["/\\d(\\.\\d+)?px/"],
    },
    "declaration-property-value-allowed-list": {
      "z-index": ["/^var\\(--z-/", "0", "1", "-1", "auto"],
      "box-shadow": ["/^var\\(--(shadow|telekom-shadow)-/", "none"],
    },
  },
  overrides: [
    {
      files: ["src/assets/tokens.css"],
      rules: {
        "color-no-hex": null,
        "color-named": null,
        "function-disallowed-list": null,
        "declaration-property-value-disallowed-list": null,
      },
    },
  ],
};
