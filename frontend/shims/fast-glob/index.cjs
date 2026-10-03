// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

// fast-glob compatible subset (default/async, sync, escapePath, convertPathToPattern,
// isDynamicPattern) used by build/lint tooling. Backed by tinyglobby to avoid the
// unpatched braces DoS advisory (GHSA-vfj7-8cjw-p6xm) pulled in via micromatch.
"use strict";

// CommonJS so both `require("fast-glob")` and default `import fg from "fast-glob"` consumers work.
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { glob, globSync, escapePath, convertPathToPattern, isDynamicPattern } = require("tinyglobby");

// fast-glob does not expand directory patterns; tinyglobby does by default.
const withDefaults = (options) => ({ expandDirectories: false, ...options });

function fg(patterns, options) {
  return glob(patterns, withDefaults(options));
}

fg.glob = fg;
fg.async = fg;
fg.sync = (patterns, options) => globSync(patterns, withDefaults(options));
fg.globSync = fg.sync;
fg.escapePath = escapePath;
fg.convertPathToPattern = convertPathToPattern;
fg.isDynamicPattern = isDynamicPattern;

module.exports = fg;
