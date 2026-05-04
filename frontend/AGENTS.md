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
4. **Styling**: Use existing CSS custom properties (tokens) in `frontend/src/assets/base.css` (e.g. `var(--space-md)`) rather than hardcoding px or rem values.
5. **Testing**: All new services and components must have accompanying unit tests in `frontend/tests/unit`. We use Vitest for testing. Run tests via `npm test`.

## Architecture Notes
- `src/services/` contains API wrappers (e.g. `breakglass.ts`). Ensure error handling uses the `handleAxiosError` utility.
- `src/components/` contains reusable UI pieces.
- `src/views/` contains route-level pages.
