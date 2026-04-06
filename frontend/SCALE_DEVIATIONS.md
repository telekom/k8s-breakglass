<!--
SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Scale Design System Deviations

This document catalogues every intentional deviation from the
[Telekom Scale Design System](https://telekom.github.io/scale/) defaults in the
Breakglass frontend and explains why each override exists.

**Guiding principle:** We follow Scale to the letter for layout, spacing,
typography, radius, and motion tokens. Colour overrides are applied **only**
where the Scale default fails WCAG AAA (7 : 1 contrast ratio for normal text,
4.5 : 1 for large text), with one explicit exception: Telekom magenta elements
(#e20074) such as primary buttons target AA compliance (4.5 : 1) to strictly
preserve the core brand identity per product decision.

All overrides live in
[`src/assets/base.css`](src/assets/base.css).

---

## 1. Text Colour — `--telekom-color-text-and-icon-additional`

| Mode | Scale Default | Our Override | Reason |
|------|---------------|--------------|--------|
| Light | `hsla(0,0%,0%,0.65)` ≈ `#595959` | `#4a4a4a` | Scale value yields ~5.9 : 1 on white — passes AA but fails AAA 7 : 1. Our solid override reaches ≈ 8.0 : 1. |
| Dark | Scale dark equivalent | `#c0c0c0` | Equivalent AAA fix for dark surfaces (`#1c1c1e`). |
| High-contrast light | — | `#1a1a1a` | Near-black for maximum readability. |
| High-contrast dark | — | `#e0e0e0` | Near-white for maximum readability. |

`!important` is required because Scale's own stylesheet loads **after** ours
and re-declares the variable on `:root`.

---

## 2. Primary Button Background

| Element | Scale Default | Our Override | Reason |
|---------|---------------|--------------|--------|
| `scale-button::part(variant-primary)` | `#f61488` (Scale computed) | `#e20074` (design token) | Scale's internal rendering produces a lighter #f61488 which only achieves 3.9:1 contrast against white text (fails AA). Pinning to the design-token value #e20074 yields 4.68:1 (AA compliant) while preserving the Telekom brand colour. |

---

## 3. Active Navigation Link

| Mode | Scale Default | Our Override | Reason |
|------|---------------|--------------|--------|
| Light | `#e20074` | `#8e004a` | Scale renders the active nav item with a tinted background; `#e20074` measures only 3.06:1 on that surface (fails WCAG AA). `#8e004a` achieves 9.34:1 on white and 8.13:1 on `#efeff0` (passes AAA on all Scale header surface variants including high-contrast mode). |
| Dark | `#e20074` | `#e20074` (via `var(--telekom-color-primary-standard)`) | Pinned to actual Telekom magenta. On dark header (#151517) this gives 4.59:1 (AA). Previously used #ff8cc8 for AAA but product decision prefers authentic brand colour. |

---

## 4. Chip / Tag Text Colours

Scale's functional colours are designed for AA compliance. We darken (light
mode) or lighten (dark mode) each hue to reach AAA on the corresponding tinted
background.

### Light Mode

| Tone | Scale Default | Our Override (`--tone-chip-*-text`) | Contrast on Bg |
|------|---------------|-------------------------------------|----------------|
| Primary (magenta) | `#e20074` | `#8e004a` | ≈ 9.5 : 1 on `color-mix(#e20074 7%)` |
| Info (blue) | `#2238df` | `#0d1570` | ≈ 12 : 1 on `#d3d7f9` |
| Success (green) | `#00b367` | `#004d30` | ≈ 9.8 : 1 on `#ccf0e1` |
| Warning (orange) | `#f97012` | `#6b3300` | ≈ 8.2 : 1 on `#fee2d0` |
| Danger (red) | `#e82010` | `#8a0700` | ≈ 8.0 : 1 on `#fad2cf` |

### Dark Mode

| Tone | Scale Default | Our Override | Contrast on Bg |
|------|---------------|--------------|----------------|
| Primary | — | `#ff8cc8` on `#3d0026` | 8.36 : 1 |
| Info | — | `#c5d0fc` on `#131f7b` | ≈ 7.5 : 1 |
| Success | — | `#7aedb8` on `#004829` | ≈ 7.8 : 1 |
| Warning | — | `#ffd4a8` on `#642d07` | ≈ 7.4 : 1 |
| Danger | — | `#ffc4bd` on `#5d0d06` | ≈ 7.2 : 1 |

Dark-mode chip backgrounds use **solid** colours (e.g. `#3d0026`) instead of
Scale's `color-mix()` translucent tints, because translucent overlays on dark
canvas produce inconsistent contrast depending on stacking context.

### High-Contrast Mode

Further overrides push text colours toward pure black (light) or pure white
(dark) for near-maximum contrast. Chip backgrounds in high-contrast light use
`color-mix(#730040 10%)` for a subtle tint without sacrificing readability.

### High-Contrast Dark Mode

HC-dark inherits dark-mode chip backgrounds but uses lighter text to guarantee
AAA 7 : 1 on those same backgrounds:

| Tone | Dark-Mode Text | HC-Dark Override | Contrast on Bg |
|------|----------------|------------------|----------------|
| Info | `#c5d0fc` | `#ccd8ff` on `#131f7b` | 9.8 : 1 |
| Success | `#7aedb8` | `#80f0c0` on `#004829` | 7.7 : 1 |
| Warning | `#ffd4a8` | `#ffd9b3` on `#642d07` | 8.2 : 1 |
| Danger | `#ffc4bd` | `#ffcec7` on `#5d0d06` | 9.8 : 1 |

---

## 5. Ghost Button Text (Dark Mode)

| Element | Scale Default | Our Override | Reason |
|---------|---------------|--------------|--------|
| `scale-button::part(variant-ghost)` | Scale's dark ghost text colour | `#93a8ff` | Default fails AAA on `#1c1c1e` surface. Lightened blue reaches 7 : 1+. |

---

## 6. Dropdown / Combobox Label

| Element | Scale Default | Our Override | Reason |
|---------|---------------|--------------|--------|
| `scale-dropdown::part(label)` | Inherits `--telekom-color-text-and-icon-additional` | Forced via `!important` to our AAA-compliant value | Inside subtle surfaces the inherited opacity-based colour sometimes falls below 7 : 1. |

---

## 7. `scale-tag` Variant Colours

All six `scale-tag` variants (`info`, `success`, `warning`, `danger`,
`neutral`, `primary`) are overridden via both CSS custom properties **and**
`::part(base)` with `!important`.

This double approach is necessary because Scale's shadow DOM renders the tag
colours internally. The `--background`/`--color` variables work for some Scale
versions, while `::part(base)` catches versions where the variables are not
propagated.

---

## 8. `scale-card` Border & Radius

| Property | Scale Default | Our Override | Reason |
|----------|---------------|--------------|--------|
| `border` | None | `1px solid var(--telekom-color-ui-border-standard)` | Cards need a visible boundary for users with low vision, especially in light mode where shadow alone is insufficient. |
| `border-radius` | Scale default | `var(--radius-lg)` = `0.75rem` | Matches our semantic token; still uses the Scale `--telekom-radius-large` token underneath. |

---

## 9. `scale-button` Pill Radius

| Property | Scale Default | Our Override | Reason |
|----------|---------------|--------------|--------|
| `border-radius` | Scale standard radius | `var(--radius-pill)` = `62.4375rem` | Design decision for Breakglass — fully rounded buttons match the Telekom brand aesthetic. Applied via `::part(button)` and `::part(base)` with `!important` to penetrate shadow DOM. |

---

## 10. `scale-modal` Internal Spacing

| Property | Scale Default | Our Override | Reason |
|----------|---------------|--------------|--------|
| `--spacing-y` | Scale default | `var(--space-lg)` = `16px` | Consistent internal spacing with the rest of our UI. |
| `::part(body)` layout | Block | `flex` column with `gap: var(--space-md)` | Ensures body content is evenly spaced without margin hacks. |

---

## 11. Forced-Colours / Windows High Contrast

Under `@media (forced-colors: active)`, all surface, chip, accent, and border
tokens are remapped to CSS system colour keywords (`Canvas`, `CanvasText`,
`ButtonText`, `Highlight`, `GrayText`, `LinkText`). Shadows are removed.

This is not a Scale deviation per se, but extends Scale's theme to a context
Scale does not explicitly handle.

---

## 12. Minimum Touch Target Size (High Contrast)

Under `[data-high-contrast="true"]`, all interactive elements (`scale-button`,
`button`, `a[role="button"]`, `[role="tab"]`, `[role="menuitem"]`,
`input[type="checkbox"]`, `input[type="radio"]`) receive
`min-height: 44px; min-width: 44px` per WCAG SC 2.5.5 (AAA target size).

Scale does not enforce this at the component level.

---

## What We Do NOT Override

Everything not listed above follows Scale defaults exactly:

- **Spacing tokens** (`--scl-spacing-*`) — used via semantic aliases
  (`--space-*`, `--card-padding`, `--stack-gap-*`, `--grid-gap`)
- **Typography** (`--scl-font-*`, `--telekom-text-style-*`)
- **Motion / easing** (`--telekom-motion-*`)
- **Radius tokens** (mapped 1 : 1 to `--telekom-radius-*`)
- **Shadow tokens** (`--telekom-shadow-*`)
- **Focus indicators** (uses `--telekom-color-functional-focus-standard`,
  except high-contrast which uses black/white)
- **Layout / grid** — all responsive breakpoints and container widths
- **Component behaviour** — no functional overrides to Scale components
