<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Breakglass Frontend — Design System

> Audit date: 2026-05-14 · Scale version: `@telekom/scale-components ^3.0.0-beta.160`

This document describes the design system used in the Breakglass frontend: its token layer, theming model, Scale integration, utility classes, and component catalogue. It also records the audit findings from a review of the codebase against Telekom Scale conventions.

---

## 1. Stack

| Layer | Technology |
|-------|-----------|
| Framework | Vue 3 + TypeScript (Composition API) |
| Build | Vite |
| Design system | [Telekom Scale](https://telekom.github.io/scale/) `^3.0.0-beta.160` |
| Neutral theme | `@telekom/scale-components-neutral ^3.0.0-beta.160` |
| State | Pinia |
| Testing | Playwright (E2E + a11y axe-core), Vitest (unit) |
| Lint/format | ESLint + Prettier |

Scale is consumed as web components (`<scale-button>`, `<scale-card>`, `<scale-tag>`, etc.). All token overrides and theme variants live in [`src/assets/base.css`](src/assets/base.css). Every intentional deviation from Scale defaults is documented in [`SCALE_DEVIATIONS.md`](SCALE_DEVIATIONS.md).

---

## 2. Design Tokens

All tokens are CSS custom properties. Custom tokens either alias Scale tokens directly or compute from them; hardcoded values are a last resort and require a comment justifying the exception.

### 2.1 Spacing

Built on `--scl-spacing-*` primitives (2 · 4 · 8 · 12 · 16 · 24 · 32 · 40 · 48 · 64 · 80 px).

#### Semantic aliases

| Token | Maps to | Value | Use |
|-------|---------|-------|-----|
| `--space-2xs` | `--scl-spacing-2` | 2 px | hairline gaps |
| `--space-xs` | `--scl-spacing-4` | 4 px | tight internal padding |
| `--space-sm` | `--scl-spacing-8` | 8 px | chip padding, small gaps |
| `--space-md` | `--scl-spacing-12` | 12 px | default internal gaps |
| `--space-lg` | `--scl-spacing-16` | 16 px | section gaps |
| `--space-xl` | `--scl-spacing-24` | 24 px | large gaps, card padding |
| `--space-2xl` | `--scl-spacing-32` | 32 px | section separation |
| `--space-3xl` | `--scl-spacing-48` | 48 px | page-level gaps |

#### Contextual aliases

| Token | Value | Use |
|-------|-------|-----|
| `--card-padding` | `--scl-spacing-24` | primary card internal padding |
| `--card-padding-sm` | `--scl-spacing-16` | compact card padding |
| `--card-gap` | `--scl-spacing-16` | gap between card children |
| `--stack-gap-xs` | `--scl-spacing-4` | vertical stack (extra-small) |
| `--stack-gap-sm` | `--scl-spacing-8` | vertical stack (small) |
| `--stack-gap-md` | `--scl-spacing-12` | vertical stack (medium) |
| `--stack-gap-lg` | `--scl-spacing-16` | vertical stack (large) |
| `--stack-gap-xl` | `--scl-spacing-24` | vertical stack (extra-large) |
| `--grid-gap` | `--scl-spacing-16` | grid column/row gap |
| `--grid-gap-lg` | `--scl-spacing-24` | wide grid gap |

> **Naming note:** `--space-*` and `--stack-gap-*` overlap in value range. Prefer `--space-*` for padding/margin and `--stack-gap-*` only for flex/grid `gap` properties on vertical stacks. Both will be collapsed into a single scale in a future token cleanup.

### 2.2 Border Radius

All radius tokens alias `--telekom-radius-*` primitives.

| Token | Maps to | Value |
|-------|---------|-------|
| `--radius-xs` | `--telekom-radius-extra-small` | 0.125 rem |
| `--radius-sm` | `--telekom-radius-small` | 0.25 rem |
| `--radius-md` | `--telekom-radius-standard` | 0.5 rem |
| `--radius-lg` | `--telekom-radius-large` | 0.75 rem |
| `--radius-pill` | `--telekom-radius-pill` | 62.44 rem |

### 2.3 Typography

Typography is consumed directly from Scale tokens without local aliases:

- `--telekom-text-style-heading-1` through `--telekom-text-style-heading-6`
- `--telekom-text-style-body`, `--telekom-text-style-body-bold`
- `--telekom-text-style-small`, `--telekom-text-style-small-bold`
- `--telekom-text-style-caption`, `--telekom-text-style-badge`

Font family: `var(--scl-font-family-sans)` → "TeleNeo Web" → system-ui fallback.

### 2.4 Color Tokens

#### Surface

| Token | Light | Dark |
|-------|-------|------|
| `--surface-primary` | `--telekom-color-background-canvas` (#fff) | #000 |
| `--surface-elevated` | `--telekom-color-background-surface-subtle` (#efeff0) | #242426 |
| `--surface-card` | `--telekom-color-background-surface` (#fff) | #1c1c1e |
| `--surface-card-subtle` | 50% mix of `--telekom-color-ui-subtle` | #242426 |
| `--surface-card-translucent` | 80% opaque `--surface-card` | 80% opaque `--surface-card` |
| `--surface-toolbar` | `--telekom-color-background-surface` | #1c1c1e |

#### Semantic accents

| Token | Scale source |
|-------|-------------|
| `--accent-telekom` | `--telekom-color-primary-standard` (#e20074) |
| `--accent-warning` | `--telekom-color-functional-warning-standard` |
| `--accent-success` | `--telekom-color-functional-success-standard` |
| `--accent-info` | `--telekom-color-functional-informational-standard` |
| `--accent-critical` | `--telekom-color-functional-danger-standard` |

#### Semantic tone chips

Five tones (info / success / warning / danger / neutral) each expose three tokens: `--tone-chip-{tone}-bg`, `--tone-chip-{tone}-border`, `--tone-chip-{tone}-text`. All text values are overridden from Scale defaults to achieve WCAG AAA (7 : 1) contrast. See [§ 4](#4-scale-deviations) and [SCALE_DEVIATIONS.md §4](SCALE_DEVIATIONS.md) for contrast ratios.

#### Primary chip (Telekom magenta)

| Token | Light | Dark |
|-------|-------|------|
| `--chip-bg` | 7% magenta tint | `#3d0026` solid |
| `--chip-border` | 15% magenta tint | 35% magenta tint |
| `--chip-text` | `#8e004a` | `#ff8cc8` |

Magenta elements target AA (4.5 : 1) rather than AAA to preserve the Telekom brand identity; this is a documented product decision.

### 2.5 Other Tokens

| Token | Value | Notes |
|-------|-------|-------|
| `--shadow-card` | `--telekom-shadow-raised-standard` | with fallback values |
| `--border-strong` | `--telekom-color-ui-border-standard` | strengthened in dark mode |
| `--focus-outline` | `--telekom-color-functional-focus-standard` (#2238df) | black/white in high-contrast |

---

## 3. Themes

Theme switching is controlled by HTML attributes and system media queries. Scale's own theme switching (`[data-mode]`) is **not** used; the app manages its own `[data-theme]` attribute.

| Theme | Activation |
|-------|-----------|
| Light (default) | `:root` (no attribute) |
| Dark | `[data-theme="dark"]` on `<html>` |
| High-contrast light | `[data-high-contrast="true"]` on `<html>` |
| High-contrast dark | `[data-high-contrast="true"][data-theme="dark"]` on `<html>` |
| Windows forced-colors | `@media (forced-colors: active)` — automatic, no JS required |

All four theme combinations have full token coverage. The forced-colors layer remaps every surface, border, chip, and accent token to CSS system color keywords (`Canvas`, `CanvasText`, `ButtonText`, `Highlight`, `GrayText`, `LinkText`) so the OS palette takes over without layout breakage.

---

## 4. Scale Deviations

Full details and contrast ratios are in [`SCALE_DEVIATIONS.md`](SCALE_DEVIATIONS.md). Summary:

| # | What | Why |
|---|------|-----|
| 1 | `--telekom-color-text-and-icon-additional` overridden with `!important` | Scale default (`#595959`) fails WCAG AAA 7 : 1 on white |
| 2 | Primary button background pinned to `#e20074` | Scale's computed `#f61488` fails WCAG AA on white text |
| 3 | Active nav link uses `#8e004a` (light) / `#e20074` (dark) | Scale's `#e20074` fails AA on the nav active-surface background |
| 4 | Chip/tag text colours darkened (light) or lightened (dark) | Scale functional colours target AA; we need AAA on tinted backgrounds |
| 5 | Ghost button text in dark: `#93a8ff` | Scale default fails AAA on `#1c1c1e` |
| 6 | Dropdown label forced via `!important` | Inherited opacity-based colour can fall below 7 : 1 on subtle surfaces |
| 7 | `scale-tag` variants overridden via `--background`/`--color` + `::part(base)` | Double approach needed for Scale shadow DOM version compatibility |
| 8 | `scale-card` gets explicit border + `border-radius: var(--radius-lg)` | Card boundary needed for low-vision users; shadow alone insufficient in light mode |
| 9 | `scale-button` uses `--radius-pill` | Design decision: all buttons are fully rounded |
| 10 | `scale-modal` body uses `flex` + `gap` | Consistent internal spacing without margin hacks |
| 11 | Forced-colors layer | Scale does not handle `forced-colors` explicitly |
| 12 | 44 × 44 px touch targets in `[data-high-contrast]` | WCAG SC 2.5.5 AAA; Scale does not enforce this |

---

## 5. Utility Classes

Defined in `base.css`. Do not add component-specific styles here; use scoped styles inside `.vue` files instead.

### Layout

| Class | Description |
|-------|-------------|
| `.app-container` | Centred max-width (1240 px) page wrapper with responsive padding |
| `.ui-page` | Flex column with `--stack-gap-xl` between sections |
| `.ui-page-title` | Page-level `h1` style (`--telekom-text-style-heading-2`) |
| `.ui-page-subtitle` | Page subtitle in additional text colour |
| `.masonry-layout` | 3 → 2 → 1 column masonry grid for card grids (breakpoints: 1440 px, 768 px) |

### Toolbar

| Class | Description |
|-------|-------------|
| `.ui-toolbar` | Flex container: bordered + shadowed + card bg |
| `.ui-toolbar-field` | Flex-grow field slot (min 220 px) |
| `.ui-toolbar-actions` | Action button cluster |
| `.ui-toolbar-info` | Caption-size informational text |

### Info grid

| Class | Description |
|-------|-------------|
| `.ui-info-grid` | `auto-fit` grid of key-value cells (min 200 px) |
| `.ui-info-item` | Individual cell: label (uppercase, `--telekom-text-style-small`) + value (bold) |

### Pill / tag stack

| Class | Description |
|-------|-------------|
| `.ui-pill-stack` | Wrapping flex row of neutral tags |
| `.tone-chip` | Base semantic chip (pill shape, bordered) |
| `.tone-chip--{tone}` | Tone variant: `info` `success` `warning` `danger` `neutral` `muted` |

Tone chips also support session state aliases: `.tone-chip--active` = success, `.tone-chip--pending` = warning, `.tone-chip--rejected` = danger, `.tone-chip--expired` = neutral.

### Callout / inline banner

| Class | Description |
|-------|-------------|
| `.tone-callout` | Info box with 3 px left border accent |
| `.tone-callout--{tone}` | Same tone set as chip: `info` `success` `warning` `danger` `neutral` `muted` + state aliases |

### Misc

| Class | Description |
|-------|-------------|
| `.ui-section` | Flex column with `--stack-gap-sm` |
| `.ui-matching-summary` | Dashed-border summary box |
| `.ui-link-button` | Inline-flex text link that looks like a link-button |
| `.ui-link-button.small` | Smaller variant |
| `.ui-muted` | Additional text colour |
| `.center` | `text-align: center; width: 100%` |
| `.loading-state`, `.empty-state` | Dashed-border placeholder areas |
| `.skip-link` | Accessible skip-to-content link (visible on focus) |
| `.sr-only` | Visually hidden, screen-reader accessible |
| `.dev-debug-panel` | Collapsible debug panel (`<details>` element) — dev/test use only |

---

## 6. Component Library

26 Vue 3 components across three directories.

### 6.1 Common components (`src/components/common/`)

These are reusable across all views and should have zero domain knowledge.

#### StatusTag

Renders a `scale-tag` with automatic tone detection from a backend state string.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `status` | `string` | `""` | Backend state string (e.g. `"approved"`, `"pending"`) |
| `tone` | `StatusTone` | auto | Override automatic tone detection |
| `size` | `"small" \| "medium"` | `"medium"` | Size variant |
| `showIcon` | `boolean` | `false` | Prefix with a status icon |
| `uppercase` | `boolean` | `true` | Display label in uppercase |

**Tones:** `success` · `warning` · `danger` · `info` · `neutral` · `muted`

**Supported status strings:** `active` `approved` `running` (→ success) · `available` `scheduled` `queued` (→ info) · `pending` `waitingforscheduledtime` (→ warning) · `rejected` `withdrawn` `cancelled` `timeout` `idleexpired` (→ danger) · `expired` `completed` `ended` (→ muted) · all others (→ neutral)

**Accessibility:** label text is always present; icons carry `decorative` attribute so they are skipped by screen readers.

---

#### ChipRow

Wrapping flex row of `scale-tag` chips with built-in truncation and tooltip.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `items` | `ChipItem[]` | `[]` | Array of chip definitions |
| `defaultVariant` | `ChipItem["variant"]` | `"neutral"` | Fallback variant when item has none |
| `maxWidth` | `string` | `"300px"` | Max chip width before text truncates |
| `compact` | `boolean` | `false` | Reduces gap from `--space-sm` to `--stack-gap-xs` |

`ChipItem` shape: `{ id, label, value?, variant?, prefix?, truncate? }`

Supports a default slot for fully custom content (bypasses items prop).

On mobile (≤ 640 px), `maxWidth` resets to `100%` so chips fill the viewport.

---

#### PageHeader

Consistent page-level header: title, optional subtitle, optional badge, optional actions, optional breadcrumbs.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `title` | `string` | required | Page title (rendered as `h1`) |
| `subtitle` | `string` | `""` | Descriptive subtitle |
| `badge` | `string \| number` | `""` | Count/label badge next to title |
| `badgeVariant` | Scale tag variant | `"secondary"` | Badge colour |

**Slots:** `breadcrumbs` · `subtitle` (rich subtitle) · `actions` · default (arbitrary footer content)

On mobile (≤ 640 px) the title/subtitle stack and the aside fills full width.

---

#### ActionButton

`scale-button` wrapper with loading state, loading label, and pill radius enforcement.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `label` | `string` | required | Button text |
| `loadingLabel` | `string` | `""` | Replaces label while loading |
| `variant` | `"primary" \| "secondary" \| "danger"` | `"primary"` | Scale button variant |
| `loading` | `boolean` | `false` | Shows spinner, sets `aria-busy`, disables interaction |
| `disabled` | `boolean` | `false` | Disabled state |
| `size` | `"small" \| "medium" \| "large"` | `"medium"` | Scale size prop |
| `icon` | `string` | `""` | Prefix icon character/emoji (not for Scale icons) |

**Event:** `click(event: Event)` — only emitted when not loading or disabled.

Min-width is 8 rem; on mobile (≤ 640 px) it stretches to full width.

---

#### EmptyState

Centred placeholder displayed when a list has no items.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `title` | `string` | required | Heading |
| `message` | `string` | `""` | Supporting text |

---

#### ErrorBanner

Inline error message displayed inside a form or card context (not a toast).

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `error` | `string \| Error \| null` | `null` | Error to display |

Renders nothing when `error` is null.

---

#### ErrorBoundary

Vue error boundary wrapper. Catches errors from child components and renders a fallback message instead of crashing the page. No props; wrap any subtree that might throw.

---

#### LoadingState

Animated placeholder while data is loading.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `label` | `string` | `"Loading…"` | Screen-reader text |

---

#### ReasonPanel

Displays an approval or rejection reason in a styled callout.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `reason` | `string` | required | Reason text |
| `tone` | `StatusTone` | `"neutral"` | Callout colour tone |
| `label` | `string` | `"Reason"` | Section heading |

---

#### TimelineGrid

Event timeline table for displaying timestamped session activity.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `events` | `TimelineEvent[]` | `[]` | Array of `{ timestamp, label, detail? }` |

---

### 6.2 Domain components (`src/components/`)

These carry session/breakglass domain knowledge and are not intended for reuse outside of their specific view.

| Component | Description |
|-----------|-------------|
| `BreakglassSessionCard` | Full session card with status, metadata, and action buttons |
| `BreakglassCard` | Simplified listing card |
| `DebugSessionCard` | Debug-session listing card |
| `SessionSummaryCard` | Compact session summary for detail views |
| `SessionMetaGrid` | Key-value grid of session metadata |
| `ApprovalModalContent` | Modal body for approve/reject flows |
| `WithdrawConfirmDialog` | Confirmation dialog for session withdrawal |
| `AutoLogoutWarning` | Banner + timer warning before auto-logout |
| `CountdownTimer` | Countdown display widget |
| `IDPSelector` | Identity provider selection step |
| `ErrorToasts` | Global toast notification layer |
| `DebugPanel` | Collapsible developer debug panel |

### 6.3 Form components (`src/components/debug-session/`)

| Component | Description |
|-----------|-------------|
| `SessionConfigForm` | Multi-step session configuration form |
| `BindingOptionsGrid` | Selection grid for RBAC binding options |
| `ClusterSelectGrid` | Multi-cluster selection grid |
| `VariableForm` | Dynamic variable input form |

---

## 7. Status Tone Mapping

`src/utils/statusStyles.ts` provides the canonical `statusToneFor(state)` function. It normalises the backend state string (lowercase, strip whitespace) before looking it up.

```
active / approved / running → success
available / scheduled / queued → info
pending / waitingforscheduledtime / pendingrequest → warning
rejected / withdrawn / dropped / cancelled / timeout / approvaltimeout / idleexpired → danger
expired / completed / ended → muted
unknown / default / (unrecognised) → neutral
```

When adding new backend states, update the `STATE_TONE_MAP` in that file. Do not add tone mappings inside individual components.

---

## 8. Audit Findings

### 8.1 Score

| Category | Issues | Score |
|----------|--------|-------|
| Token coverage — colors | 0 | 10/10 |
| Token coverage — spacing | 14 hardcoded values (debug-session) | 6/10 |
| Token coverage — typography | 21 hardcoded `font-size` values | 5/10 |
| Token coverage — motion | 1 hardcoded transition | 9/10 |
| Token coverage — z-index | 1 hardcoded `z-index: 99` | 9/10 |
| Naming consistency | Minor `--space-*` vs `--stack-gap-*` overlap | 8/10 |
| Component props/states | Documented via JSDoc; no formal docs page | 7/10 |
| Scale alignment | All deviations justified and documented | 10/10 |
| Accessibility | Full WCAG AAA target with documented ratios | 10/10 |
| **Overall** | | **82/100** |

---

### 8.2 Token Coverage

#### Typography — 21 hardcoded `font-size` values

The `debug-session/` components and `BreakglassSessionCard` use raw `font-size` instead of `--telekom-text-style-*` tokens.

| File | Count | Example |
|------|-------|---------|
| `SessionConfigForm.vue` | 12 | `font-size: 0.875rem`, `0.75rem`, `0.6875rem`, `1.125rem`, `1rem` |
| `BindingOptionsGrid.vue` | 8 | `font-size: 0.625rem`, `0.875rem`, `1.125rem` |
| `BreakglassSessionCard.vue` | 4 | `font-size: 0.8em`, `0.85rem`, `0.75rem`, `0.9rem` |
| `WithdrawConfirmDialog.vue` | 1 | `font-size: 0.9rem` |

**Fix:** Replace with the closest Scale text-style token:

| Raw value | Scale token |
|-----------|-------------|
| `0.625rem` / `0.6875rem` / `0.7rem` | `--telekom-text-style-badge` |
| `0.75rem` | `--telekom-text-style-small` |
| `0.8125rem` (debug panel) | `--telekom-text-style-small` |
| `0.875rem` | `--telekom-text-style-caption` |
| `0.9rem` | `--telekom-text-style-caption` |
| `1rem` | `--telekom-text-style-body` |
| `1.125rem` | `--telekom-text-style-heading-6` |

#### Spacing — 14 hardcoded values in debug-session components

| File | Values |
|------|--------|
| `SessionConfigForm.vue` | `gap: 4px`, `gap: 2px`, `margin-top: 6px`, `margin-top: 0.25rem`, `padding: 1px 6px`, `padding: 0.125rem 0.5rem`, `gap: 0.25rem`, `margin-right: 0.25rem` |
| `BindingOptionsGrid.vue` | `gap: 2px`, `padding: 2px 8px`, `padding: 0.125rem 0.5rem`, `gap: 4px`, `letter-spacing: 0.5px` |

Values at or below 4 px (below `--space-xs`) are the main offenders. `--space-2xs` (2 px) and `--space-xs` (4 px) exist and should be used; 1 px hairlines are acceptable as-is.

#### Motion — 1 hardcoded transition

`base.css:896` inside `.dev-debug-panel`: `transition: transform 0.2s ease`

Should use `var(--telekom-motion-duration-immediate, 100ms) var(--telekom-motion-easing-standard)`.

#### Z-index — 1 hardcoded value

`base.css:468` `.skip-link`: `z-index: 99`

Add a `--z-skip-link: 99` token in `base.css :root` block and reference it here. This makes the stacking context explicit for future additions.

---

### 8.3 Naming Consistency

| Issue | Detail | Recommendation |
|-------|--------|----------------|
| Dual spacing scales | `--space-*` and `--stack-gap-*` have overlapping values (both include 4, 8, 12, 16, 24 px) | Adopt `--space-*` as the primary scale; deprecate `--stack-gap-*` in a future cleanup pass |
| `--cta-bg` orphaned token | Defined in `:root` but only consumed by `NotFoundView.vue` | Move into that view's scoped styles or document as a layout-level brand accent |
| `ui-link-button.small` modifier | Uses a plain `.small` class rather than a BEM modifier `--small` | Rename to `.ui-link-button--small` for consistency |

---

### 8.4 Missing Tokens

| Category | Gap | Suggestion |
|----------|-----|-----------|
| Breakpoints | Hardcoded `640px`, `768px`, `1440px` in media queries | Add `--bp-sm`, `--bp-md`, `--bp-xl` CSS custom properties (note: custom properties cannot be used inside `@media`; document them as SCSS/JS constants instead) |
| Z-index | Only one value exists and it is hardcoded | Create a z-index scale (`--z-skip-link`, `--z-modal`, `--z-toast`) in `:root` |
| Scale version lock | Package uses `^` (caret) on a beta release | Pin to an exact version (`3.0.0-beta.160`) until Scale reaches a stable release to prevent unexpected breaking changes on install |

---

## 9. Priority Actions

1. **Replace hardcoded `font-size` in debug-session components** — 21 instances across `SessionConfigForm.vue` and `BindingOptionsGrid.vue`; high impact, low risk, pure token substitution.

2. **Replace hardcoded spacing in debug-session components** — 14 instances; use `--space-2xs` / `--space-xs` instead of raw pixel values.

3. **Pin Scale to an exact beta version** — swap `^3.0.0-beta.160` → `3.0.0-beta.160` in `package.json` to prevent silent breaking changes.

4. **Add z-index tokens** — one token needed now; avoids future stacking conflicts as the UI grows.

5. **Audit `BreakglassSessionCard.vue`** — 4 hardcoded font-size values plus the most complex scoped stylesheet in the codebase; a focused review would catch any remaining spacing/colour issues.

6. **Deprecate `--stack-gap-*` aliases** — they duplicate `--space-*` values and add cognitive overhead. Mark deprecated in a comment, replace usages, then remove in a clean-up PR.
