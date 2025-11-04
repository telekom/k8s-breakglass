// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/* eslint-env node */
require("@rushstack/eslint-patch/modern-module-resolution");

module.exports = {
  root: true,
  extends: ["plugin:vue/vue3-recommended", "@vue/eslint-config-typescript/recommended", "@vue/eslint-config-prettier"],
  env: {
    "vue/setup-compiler-macros": true,
  },
  rules: {
    "vue/hypenize-parameters": "off",
    "vue/v-on-event-hyphenation": "off",
  },
};
