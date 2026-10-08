<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Breakglass Frontend — Design System

> Audit date: 2026-10-07 · Scale version: `@telekom/scale-components 3.0.0-beta.162`

This document describes the design system used in the Breakglass frontend: its token layer, theming model, Scale integration, utility classes, and component catalogue. It also records the audit findings from a review of the codebase against Telekom Scale conventions.

---

## 1. Stack

| Layer | Technology |
|-------|-----------|
| Framework | Vue 3 + TypeScript (Composition API) |
| Build | Vite |
| Design system | [Telekom Scale](https://telekom.github.io/scale/) `3.0.0-beta.162` (pinned) |
| Neutral theme | `@telekom/scale-components-neutral 3.0.0-beta.162` |
| State | Pinia |
| Testing | Playwright (E2E + a11y axe-core), Vitest (unit) |
| Lint/format | ESLint + Prettier; Stylelint token guard (`npm run lint:styles`) |

Scale is consumed as web components (`<scale-button>`, `<scale-card>`, `<scale-tag>`, etc.). Design tokens and theme variants (light, dark, high-contrast, forced-colours) live in [`src/assets/tokens.css`](src/assets/tokens.css); global styles, Scale part overrides and layout primitives live in [`src/assets/base.css`](src/assets/base.css). Every intentional deviation from Scale defaults is documented in [`SCALE_DEVIATIONS.md`](SCALE_DEVIATIONS.md).

---

## 2. Design Tokens

All tokens are CSS custom properties. Custom tokens either alias Scale tokens directly or compute from them; hardcoded values are a last resort and require a comment justifying the exception.

`tokens.css` is the only file allowed to contain raw colour values. [`stylelint.config.mjs`](stylelint.config.mjs) enforces this in `src/**/*.{css,vue}`:

- no hex colours, named colours or `rgb()`/`hsl()`-style colour functions;
- no px `font`/`font-size` (use `--telekom-text-style-*`);
- `box-shadow` must be `var(--shadow-*)`, `var(--telekom-shadow-*)` or `none`;
- `z-index` must be `var(--z-*)` or a trivial stacking value (`-1`, `0`, `1`, `auto`).

CI runs it in the Frontend Tests job.

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
Native CTAs that are not covered by Scale component rendering use `--accent-primary-aaa` / `--accent-primary-aaa-hover`, derived from the active primary accent, so they satisfy AAA while preserving the configured brand flavour.

### 2.5 Neutral / OSS Theme

The neutral Scale package (`scale-components-neutral`) uses purple `#5300ff` as its primary colour. This is **intentional** — the OSS/neutral flavour is deliberately not Deutsche Telekom branded. No primary colour override is applied; all WCAG contrast overrides (text, chips, tags) still apply since they are independent of brand colour.

### 2.6 Z-Index Scale

| Token | Value | Use |
|-------|-------|-----|
| `--z-header` | 10 | Sticky Telekom header fallback |
| `--z-skip-link` | 99 | Skip-to-content link |
| `--z-auto-logout` | 3000 | Auto-logout warning overlay |
| `--z-toast` | 5000 | Toast notifications |
| `--z-modal` | 7000 | Modal dialogs |
| `--z-debug-panel` | 9999 | Developer debug panel |

### 2.7 Other Tokens

| Token | Value | Notes |
|-------|-------|-------|
| `--shadow-card` | `--telekom-shadow-raised-standard` | with fallback values |
| `--shadow-selected` | 3 px primary ring (`color-mix`) | selected option cards and presets |
| `--border-strong` | `--telekom-color-ui-border-standard` | strengthened in dark mode |
| `--focus-outline` | `--telekom-color-functional-focus-standard` (#2238df) | black/white in high-contrast |

---

## 3. Themes

Theme switching is controlled by HTML attributes and system media queries. The app manages its own `[data-theme]` attribute and intentionally mirrors the same value to Scale's `[data-mode]` attribute so Scale shadow-DOM tokens resolve to the matching palette.

| Theme | Activation |
|-------|-----------|
| Light (default) | `:root` or `[data-theme="light"][data-mode="light"]` on `<html>` |
| Dark | `[data-theme="dark"][data-mode="dark"]` on `<html>` |
| High-contrast | `[data-high-contrast="true"][data-theme="dark"][data-mode="dark"]` on `<html>` |
| Windows forced-colors | `@media (forced-colors: active)` — automatic, no JS required |

The UI exposes light, dark, and high-contrast modes. High contrast intentionally forces a dark canvas so Scale shadow-DOM tokens and app-level text/background tokens resolve to the same contrast model. The forced-colors layer remaps every surface, border, chip, and accent token to CSS system color keywords (`Canvas`, `CanvasText`, `ButtonText`, `Highlight`, `GrayText`, `LinkText`) so the OS palette takes over without layout breakage.

---

## 4. Scale Deviations

Full details and contrast ratios are in [`SCALE_DEVIATIONS.md`](SCALE_DEVIATIONS.md). Summary:

| # | What | Why |
|---|------|-----|
| 1 | `--telekom-color-text-and-icon-additional` overridden with `!important` | Scale default (`#595959`) fails WCAG AAA 7 : 1 on white |
| 2 | Primary button background pinned to `#e20074`, with black/white high-contrast overrides for both shadow-DOM parts and custom slotted labels | Scale's computed `#f61488` fails WCAG AA on white text; high-contrast buttons use maximum-contrast foreground/background pairs |
| 3 | Active nav link uses `#8e004a` (light) / `#e20074` (dark) | Scale's `#e20074` fails AA on the nav active-surface background |
| 4 | Chip/tag text colours darkened (light) or lightened (dark) | Scale functional colours target AA; we need AAA on tinted backgrounds |
| 5 | Ghost button text in dark: `#93a8ff` | Scale default fails AAA on `#1c1c1e` |
| 6 | Dropdown label forced via `!important` | Inherited opacity-based colour can fall below 7 : 1 on subtle surfaces |
| 7 | `scale-tag` variants overridden via `--background`/`--color` + `::part(base)` | Double approach needed for Scale shadow DOM version compatibility |
| 8 | `scale-card` gets explicit border + `border-radius: var(--radius-lg)` | Card boundary needed for low-vision users; shadow alone insufficient in light mode |
| 9 | *(removed)* `scale-button` keeps Scale's own radius and variants | — |
| 10 | `scale-modal` body/header spacing and modal/form action bars are standardized | Consistent internal spacing and action alignment without margin hacks |
| 11 | Forced-colors layer | Scale does not handle `forced-colors` explicitly |
| 12 | 44 × 44 px touch targets in `[data-high-contrast]` | WCAG SC 2.5.5 AAA; Scale does not enforce this |
| 13 | Neutral/OSS theme keeps purple primary — intentionally unbranded | N/A |
| 14 | `scale-telekom-*` header/nav fallback styles via `:not(:defined)` | Neutral package lacks Telekom-branded shell components; CSS provides a functional header layout |
| 15 | `scale-card::part(base)` border reset | Prevents double border (host + shadow DOM) for consistent card appearance |

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
| `.ui-toolbar` | The one filter panel per list page: a wrapping flex row with a `--space-md` gap, bordered, shadowed, card background. The same wrapping rules apply at every width, so mobile gets stacked full-width fields with no empty space and no separate column layout |
| `.ui-toolbar-field` | Flex-grow field slot (min `15rem`, full width when narrower) |
| `.ui-toolbar-toggle` | Checkbox/switch that keeps its natural width on the field row |
| `.ui-toolbar-group` / `-group-label` | Full-width row inside the panel, e.g. state checkboxes, with a caption label. Below 1040 px the options form an auto-fill grid (min `9rem`) so wrapped rows stay in columns |
| `.ui-toolbar-actions` | Action button cluster; text buttons share the row on ≤ 768 px |
| `.ui-toolbar-actions--end` | Pushes the cluster to the end of the toolbar |
| `.ui-toolbar-info` | The result count ("Showing 14 of 14 …"): last full-width line of the panel, directly under the controls it describes. Never put it in a separate card |

### Info grid

| Class | Description |
|-------|-------------|
| `.ui-info-grid` | `auto-fit` grid of key-value cells (min 200 px) |
| `.ui-info-item` | Individual cell: label (uppercase, `--telekom-text-style-small`) + value (bold) |

### Action rows

| Class | Description |
|-------|-------------|
| `.ui-actions` | Wrapping, end-aligned button row with one `--space-md` gap and a shared vertical centre; stacks full-width on ≤ 640 px |
| `.ui-actions--start` / `--center` | Alignment modifiers |
| `.modal-actions`, `.dialog-actions`, `.form-actions` | Same row plus a top border; text buttons get `--min-width: 8rem`. Inside `scale-modal` the row drops its border and fills Scale's footer: Scale draws the full-width header/footer separators itself, only while the body scrolls. Order is Cancel/secondary first, primary last |

Tags use `scale-tag` variants; the `--tone-chip-*` colour tokens back the tag overrides and constraint labels.

### Callout / inline banner

| Class | Description |
|-------|-------------|
| `.tone-callout` | Info box with 3 px left border accent |
| `.tone-callout--{tone}` | Same tone set as chip: `info` `success` `warning` `danger` `neutral` `muted` + state aliases |

### Misc

| Class | Description |
|-------|-------------|
| `.loading-state`, `.empty-state` | Bordered placeholder areas |
| `.skip-link` | Accessible skip-to-content link (visible on focus) |
| `.sr-only` | Visually hidden, screen-reader accessible |

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

`scale-button` wrapper with loading state and loading label.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `label` | `string` | required | Button text |
| `loadingLabel` | `string` | `""` | Replaces label while loading |
| `variant` | `"primary" \| "secondary" \| "ghost"` | `"primary"` | Scale button variant |
| `loading` | `boolean` | `false` | Shows spinner, sets `aria-busy`, disables interaction |
| `disabled` | `boolean` | `false` | Disabled state |
| `size` | `"small" \| "large"` | `"large"` | Scale size prop |

**Event:** `click(event: Event)` — only emitted when not loading or disabled.

Place it inside an action row (`.ui-actions` or a dialog footer); the row owns width and wrapping.

---

#### DisabledReason

Wrap every control that can be disabled. While `reason` is set, the wrapper becomes a focusable `scale-tooltip` trigger with the reason as its accessible description. It also takes hover, because the inert control below it cannot. With no reason the wrapper is transparent.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `reason` | `string` | `""` | Why the control is disabled; empty when enabled |

---

#### HintTooltip

Explains non-obvious, non-interactive content (status tags, badges, urgency, "Note required") in a `scale-tooltip`. With a non-empty `hint`, the wrapper is focusable and `aria-describedby` points at the hint. Session state hints come from `statusDescriptionFor()` in `src/utils/statusStyles.ts`; `StatusTag` applies them automatically.

| Prop | Type | Default | Description |
|------|------|---------|-------------|
| `hint` | `string` | `""` | Tooltip text; empty renders the content unchanged |
| `placement` | `string` | `"top"` | Scale tooltip placement |

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
| `CountdownTimer` | Focusable countdown (`role="timer"`) with the absolute expiry in a Scale tooltip |
| `IDPSelector` | Identity provider selection step |
| `ErrorToasts` | Global toast notification layer |
| `DebugPanel` | Developer debug panel behind a Scale icon-only toggle (dev builds only). The toggle sits in the page flow after the content, so it never covers page actions; only the opened panel floats |

### 6.3 Form components (`src/components/debug-session/`)

| Component | Description |
|-----------|-------------|
| `SessionConfigForm` | Multi-step session configuration form |
| `BindingOptionsGrid` | Selection grid for RBAC binding options |
| `ClusterSelectGrid` | Multi-cluster selection grid |
| `VariableForm` | Dynamic variable input form |

---

### 6.4 UI rules

**Component mapping.** Buttons → `scale-button`, tags/chips → `scale-tag`, tooltips → `scale-tooltip` (directly, or via `DisabledReason`/`HintTooltip`), dialogs → `scale-modal`, toasts → `scale-notification type="toast"` (rendered only by `ErrorToasts.vue`), banners → `scale-notification`, selects → `scale-dropdown-select`, inputs → `scale-text-field`/`scale-textarea`, cards → `scale-card`, app shell → `scale-telekom-header`, icons → `scale-icon-*` with `decorative` when there is a visible label. Do not build custom equivalents.

**Button variants.** Use one `primary` for the main action of a card, dialog or page. Use `secondary` for every other action, including Cancel, Back, Reject, Withdraw and Drop; the label states the risk. Use `ghost` only for low-emphasis inline actions such as info buttons in metadata grids. Use `size="small"` for inline toggles inside content, such as "Show all groups" and schedule toggles; action rows use the default large size. Put an icon before the label as a plain child of `scale-button`, with no `slot` attribute (Scale has no named icon slots, so slotted icons are not rendered). Size it `16` in small buttons and `20` in large ones, and add `decorative`. Icon-only buttons use `icon-only`, an `inner-aria-label`, and a `scale-tooltip` with the same text. Refresh buttons are icon-only secondary buttons with the label "Refresh …".

**Alignment.** Put every button group in `.ui-actions`, a dialog/form footer class, or `.ui-toolbar-actions`. Never set `width` on a `scale-button` host without also setting Scale's `--width`/`--min-width` hooks; otherwise the label floats inside a wider host. Buttons in a row must share a vertical centre (±1 px). Text buttons of the same size must share one height across the page. `ui-audit.a11y.spec.ts` checks both at 390 × 844, 768 × 1024, 1280 × 800 and 1920 × 1080, in light and dark themes.

**Tooltips.** Required on:

- every icon-only button;
- every disabled button, through `DisabledReason`, saying why it is disabled;
- session status tags and other non-obvious badges, through `HintTooltip`;
- countdowns;
- any text clipped with an ellipsis. Prefer wrapping (`overflow-wrap: anywhere`) to clipping.

Tooltips must open on hover and on keyboard focus. Do not add tooltips to buttons whose visible label already says everything.

**Header.** Nav labels are one or two short words (Request, Approvals, Reviews, My Requests, Sessions, Debug) and must never truncate; put the descriptive wording in the accessible name. The logo, app name, nav items and the theme/contrast/profile controls share one vertical centre (±1 px) at every width. The header icons (theme, contrast, profile, menu) sit at even centre-to-centre distances (±4 px) on both sides of the divider.

**Toasts.** `ErrorToasts.vue` renders one fixed stack of Scale `scale-notification type="toast"` elements, `--space-lg` below the measured bottom of the header bar, with a `--space-md` gap between toasts, Scale's own internal padding, and a width capped to the viewport minus the page gutter on mobile. Report caught errors with `reportError(err, fallback)` from `@/services/toast`, never `pushError(err.message)`: the HTTP layer already toasts backend errors, and `reportError` skips errors it has already reported. Identical concurrent messages are merged.

**Mobile menu.** Flyout links and the theme/contrast rows share the standard text colour in every theme. The current page is bold, carries `aria-current="page"`, and uses the brand colour in light mode (dark and high contrast keep the AAA text colour, like the desktop nav). Header function items (`scale-telekom-nav-item` around the profile menu and the menu trigger) use `variant="functions"`: a main-nav item rewrites `aria-current` on the first link it contains.

**Scale elements and classes.** Never bind a dynamic `:class` on a `<scale-*>` element. Vue rewrites the `class` attribute on update and drops Stencil's `hydrated` class, and Stencil then hides the element. Use static classes and express state with `aria-pressed`, `aria-*` or `data-*` attributes. `tests/unit/scaleClassBindings.spec.ts` and the visual audit's hydration check enforce this.

**Focus.** After navigation the router moves focus to the page `h1`, unless the user has already focused something else (e.g. opened the profile menu) in the meantime.

**States.** Use `LoadingState` for loading, `EmptyState` for empty lists (with a clear next step), and `ErrorBanner`/`scale-notification` for errors. Do not hand-roll placeholders.

**Adding new UI.**

1. Compose Scale components and tokens.
2. Put new tokens in `tokens.css`, with a dark/high-contrast value when the colour differs.
3. Use the action-row primitives for buttons.
4. Add tooltips per the rules above.
5. Add the route, dialog or menu to `tests/e2e/ui-audit.a11y.spec.ts` and `tests/e2e/ui-visual-audit.a11y.spec.ts`. The visual audit (`helpers/ui-visual-audit.ts`) checks every route, dialog, menu, and empty/error/stress list state at 4 viewports in light, dark and high contrast. It flags overlaps, clipped text without a tooltip, horizontal scroll, off-viewport content, uneven row centres and heights, gaps off the token scale, separators that stop short, boxes with empty space, mixed icon sizes, inconsistent card radii and paddings, wrapped checkbox/radio groups whose rows do not share columns, and Scale elements that lost their `hydrated` flag. It also checks that menus close on Escape and return focus. `ui-visual.a11y.spec.ts` holds the dedicated header, toast, dialog and filter regressions.
6. Run `npm run lint`, `npm run lint:styles`, `npm run typecheck` and `npm run test:a11y`.

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
| Token coverage — colors | Functional tokens cover product UI; a few fallback literals remain where custom debug/legacy surfaces need a safe value before tokens load | 9/10 |
| Token coverage — spacing | Product layout uses `--space-*` or `--scl-spacing-*`; isolated compact offsets remain in legacy/debug surfaces | 9/10 |
| Token coverage — typography | All 103+ `font-size` values replaced with Scale text-style tokens | 10/10 |
| Token coverage — motion | Motion uses `--telekom-motion-*` tokens with local fallback durations where components can render before tokens load | 9/10 |
| Token coverage — z-index | Full z-index scale in `:root` | 10/10 |
| Naming consistency | Minor `--space-*` vs `--stack-gap-*` overlap remains | 8/10 |
| Component props/states | Documented via JSDoc; no formal docs page | 7/10 |
| Scale alignment | All deviations justified and documented (15 total) | 10/10 |
| Accessibility | Full WCAG AAA target with documented ratios | 10/10 |
| Neutral theme support | Fallback header/nav for OSS variant | 9/10 |
| **Overall** | | **93/100** |

---

### 8.2 Completed Remediation (2026-05-17)

The following issues from the previous audit (2026-05-14) have been resolved:

#### Typography — 103+ hardcoded `font-size` values → 0

All hardcoded `font-size` declarations across 26 Vue files replaced with `font: var(--telekom-text-style-*)` tokens:

| Raw value range | Scale token |
|-----------------|-------------|
| 0.625–0.7 rem | `--telekom-text-style-badge` |
| 0.75–0.8125 rem | `--telekom-text-style-small` |
| 0.85–0.95 rem | `--telekom-text-style-caption` |
| 1 rem | `--telekom-text-style-body` |
| 1.1–1.17 rem | `--telekom-text-style-heading-6` |
| 1.25 rem | `--telekom-text-style-heading-5` |
| 1.4–1.5 rem | `--telekom-text-style-heading-4` |
| 1.75 rem | `--telekom-text-style-heading-3` |
| 2–2.5 rem | `--telekom-text-style-heading-2` |

#### Spacing — hardcoded values in ClusterSelectGrid, BindingOptionsGrid → tokenized

All sub-token spacing values (`0.125rem`, `0.375rem`, `0.25rem`, `0.5rem`) replaced with `--space-2xs`, `--space-xs`, `--space-sm` tokens.

#### Motion — all hardcoded transitions → Scale motion tokens

All `0.15s ease`, `0.2s ease`, `0.3s ease` transitions across App.vue, AutoLogoutWarning.vue, ClusterSelectGrid.vue, CountdownTimer.vue, DebugPanel.vue, DebugSessionCard.vue, PendingApprovalsView.vue, and SessionBrowser.vue replaced with `var(--telekom-motion-duration-*) var(--telekom-motion-easing-standard)`.

#### Z-index — full token scale added

Z-index tokens (`--z-header` through `--z-debug-panel`) defined in `:root` and consumed by all components.

#### Primary color — neutral/OSS theme

The neutral/OSS flavour intentionally keeps Scale's default purple primary (`#5300ff`). No runtime override is applied — the product is deliberately unbranded in this variant.

#### Selection glow — rgba hardcodes → `color-mix()`

`rgba(226, 0, 116, 0.15)` in ClusterSelectGrid.vue and BindingOptionsGrid.vue replaced with `color-mix(in srgb, var(--telekom-color-primary-standard) 15%, transparent)` so the glow follows the primary token.

#### Constraint tags — Tailwind-style rgba → Scale functional tokens

SessionConfigForm's node-selector, denied-label, and toleration tags used hardcoded `rgba(59, 130, 246, ...)` / `rgba(239, 68, 68, ...)` / `rgba(245, 158, 11, ...)`. Replaced with `var(--tone-chip-info-*)`, `var(--tone-chip-danger-*)`, `var(--tone-chip-warning-*)` tokens and `color-mix()` for borders.

#### Debug panel — hardcoded rgba and px → tokens

`rgba(255, 0, 0, 0.1)` and `rgba(255, 165, 0, 0.2)` replaced with `var(--telekom-color-functional-danger-subtle)` and `var(--telekom-color-functional-warning-subtle)`. All `2px`/`4px` padding replaced with `var(--space-2xs)`/`var(--space-xs)` tokens.

#### Remaining component spacing — px literals → tokens

Hardcoded `gap: 2px`, `gap: 4px`, `margin-top: 2px`, `margin-top: 4px` in DebugSessionDetails.vue, DebugSessionCard.vue, ClusterSelectGrid.vue, TimelineGrid.vue, and ErrorBanner.vue replaced with `var(--space-2xs)`, `var(--space-xs)`, `var(--space-sm)`, `var(--space-md)` tokens.

#### Neutral theme — removed magenta override

The runtime `<style>` injection in `main.ts` that overrode `--telekom-color-primary-standard` from `#5300ff` to `#e20074` has been removed. The neutral/OSS flavour is intentionally unbranded and should use Scale's default purple primary. The static `:root` override in base.css (which was dead code due to Scale CSS load order) has also been removed.

#### Borders — dashed → solid

All `border: 1px dashed` styles in base.css and EmptyState.vue updated to `border: 1px solid` for a cleaner, more professional appearance.

#### Neutral header fallback

CSS `:not(:defined)` rules provide a functional header, app shell layout, and desktop/mobile navigation when Scale Telekom components aren't registered (neutral/OSS package). Includes sticky positioning, primary-colour accent border, dark mode support, a constrained mobile fallback menu, and overflow protection below the mobile breakpoint.

#### Decorative gradient removed

`#app` radial-gradient background replaced with flat `background-color: var(--surface-primary)`.

---

### 8.3 Naming Consistency

| Issue | Detail | Recommendation |
|-------|--------|----------------|
| Dual spacing scales | `--space-*` and `--stack-gap-*` have overlapping values (both include 4, 8, 12, 16, 24 px) | Adopt `--space-*` as the primary scale; deprecate `--stack-gap-*` in a future cleanup pass |

---

### 8.4 Remaining Items

| Category | Detail | Priority |
|----------|--------|----------|
| Breakpoints | Hardcoded `640px`, `768px`, `1440px` in media queries | Low — CSS custom properties cannot be used in `@media`; document as constants |
| Spacing scale overlap | `--space-*` and `--stack-gap-*` should be unified | Low — both work; clean up in a future pass |

---

## 9. Priority Actions

1. **Unify spacing scale** — collapse `--stack-gap-*` into `--space-*` across all components.

2. **Document breakpoint constants** — add JS/TS constants for `640`, `768`, `1440` px breakpoints used in media queries.

3. **Deprecate `--stack-gap-*` aliases** — they duplicate `--space-*` values and add cognitive overhead. Mark deprecated in a comment, replace usages, then remove in a clean-up PR.
