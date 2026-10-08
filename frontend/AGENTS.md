<!--
SPDX-FileCopyrightText: 2024 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Breakglass Frontend — Agent Instructions

This document provides conventions specifically for AI coding agents working in the `frontend` directory.

## Tech Stack
- Vue 3
- TypeScript
- Vite
- scale-components (Telekom UI library)

## Critical Rules
1. **Component Design**: Always use `scale-` components when available (e.g., `scale-button`, `scale-tag`, `scale-card`) rather than building custom UI from scratch.
2. **State Management**: Prefer the native Vue 3 Reactivity API (`ref`, `computed`, `watch`) over Pinia unless complex global state warrants it.
3. **Typing**: Use strict TypeScript. Avoid `any` types. Provide explicit types for all component props and emits.
4. **Styling**: Use the CSS custom properties in `frontend/src/assets/tokens.css` (e.g. `var(--space-md)`, `var(--shadow-card)`) rather than hardcoded values. Raw hex/rgb colours, px font sizes and raw shadows are only allowed in `tokens.css`; `npm run lint:styles` (stylelint, run in CI) enforces this.
   - Buttons: only Scale variants (`primary`, `secondary`, `ghost`); group them in `.ui-actions` rows instead of ad-hoc flex/margins.
   - Tooltips: icon-only buttons, disabled buttons (via `DisabledReason`, explaining why), status tags and non-obvious chips (via `HintTooltip`/`StatusTag`) need a `scale-tooltip` reachable on hover and keyboard focus. Do not add tooltips to labelled buttons or use native `title`.
   - Filters: one `.ui-toolbar` panel per list page, with the result count as its `.ui-toolbar-info` last line; no separate mobile layout.
   - Scale elements: never bind a dynamic `:class` on a `<scale-*>` element; Vue rewrites `class` and drops Stencil's `hydrated` flag, which hides the element. Express state with `aria-*`/`data-*` attributes (guarded by a `vue/no-restricted-syntax` rule in `eslint.config.mjs` and the theme-toggle browser regression).
   - Run the mock audits (`npm run test:a11y`: `ui-audit`, `ui-visual` and `ui-visual-audit` specs) after layout changes. Add new routes, dialogs and menus to `ui-visual-audit.a11y.spec.ts`.
5. **Testing**: All new services and components must have accompanying unit tests in `frontend/tests/unit`. We use Vitest for testing. Run tests via `npm test`.

## Architecture Notes
- `src/services/` contains API wrappers (e.g. `breakglass.ts`). Ensure error handling uses the `handleAxiosError` utility. In views, report caught errors with `reportError(err, fallback)` from `@/services/toast`, not `pushError`, so an error the HTTP layer already toasted is not shown twice.
- `src/components/` contains reusable UI pieces.
- `src/views/` contains route-level pages.

Date/time display uses native `Date`/`Intl`; verbose duration display uses the
installed `humanize-duration` package. Keep compact domain formatting local when
upstream output differs. A barrel re-export is not evidence of a real consumer:
check component/view call sites before adding or retaining utility APIs.
