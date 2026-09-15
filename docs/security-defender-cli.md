<!-- SPDX-FileCopyrightText: 2026 Deutsche Telekom AG -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# CLI security safeguards

Discovered OAuth credential endpoints and browser URLs must retain the configured authority's transport policy. HTTPS authorities reject HTTP downgrades, including loopback URLs. An explicitly configured HTTP authority remains supported for development. OAuth credential requests refuse redirects and use the configured CA and TLS settings, including refresh requests.

Device polling intervals are limited to five minutes and device-code lifetimes to 24 hours. Negative intervals and nonpositive lifetimes are rejected; zero interval uses the standard five-second default. API response decoding reads at most 1 MiB, error responses retain at most 1 MiB, and checksum files are limited to 4 KiB. Oversized successful responses/checksums fail instead of being parsed.

Human-readable tables, debug watch lines, device prompts/errors, API errors and update error bodies replace C0, DEL and C1 controls with spaces. Structured JSON/YAML data retains its original values. Config inspection masks nonempty inline client secrets without inventing secrets for environment/file references.

Cached-token keys include the provider identity, issuer, client ID, effective API server (including a server override), and configured API/OIDC CA filenames and TLS verification settings. Identical identity tuples share credentials across config files; scopes, grant type, credential source and CA file contents are not key components.

Existing provider-only cache entries are intentionally not migrated or reused. Run `bgctl auth login` again for each identity. Logout removes the current scoped entry. To remove legacy entries, delete the old provider key from the file token cache, or clear the entire bgctl token store and sign in again. For file storage the default cache is `~/.config/bgctl/tokens.json` (or the platform config directory); for keychain storage remove the `breakglass-bgctl` service's `tokens` entry using the OS credential manager. Clearing that entry signs out all cached identities.

Secret-bearing files use owner-only permissions on POSIX. Windows creates temporary files with a protected DACL granting access only to the process-token user before writing any secret bytes. Windows in-place fallback remains disabled. Windows-specific tests cover initial protection and replacement/readback, but must run on Windows to establish runtime evidence; cross-compilation alone does not establish ACL isolation.

Both advertised device-login verification URLs are validated before the manual
instruction is displayed or the selected URL is opened. The explicit
insecure-TLS and HTTP development settings remain available.

The `Windows Private File Security` CI job runs the native private-file tests on
`windows-latest`. It checks the protected, single-process-user ACL immediately
at temporary-file creation and after writing and replacing token files, with a
spoofed `USERNAME` environment variable. These Windows tests do not skip when ACL
inspection fails. Cross-compilation alone does not validate Windows ACL behavior.
