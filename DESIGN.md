<!--
SPDX-FileCopyrightText: 2024 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Breakglass Architecture & Design

This document details the architectural design and core concepts of the `k8s-breakglass` project.

## Overview

`k8s-breakglass` is a hub-and-spoke system designed to provide temporary, audited privilege escalation across multiple Kubernetes clusters from a single central management interface. 
It enables engineers to safely gain elevated access when needed (e.g., during an incident) while adhering to the principle of least privilege, with full auditability and automatic revocation.

## High-Level Architecture

The system consists of two primary components:
1. **Go-based Kubernetes Controller (Backend)**: Manages CRDs, interacts with the Kubernetes API, serves the RESTful Gin API, and runs the controller-runtime reconcilers.
2. **Vue 3 / TypeScript Frontend**: Provides an accessible, user-friendly interface for requesting, approving, and auditing breakglass sessions.

### Hub-and-Spoke Topology
- **Hub Cluster**: Where the `k8s-breakglass` controller and frontend are deployed. It stores all configuration (CRDs) and session states.
- **Spoke Clusters**: Remote clusters managed by the Hub. Breakglass sessions apply elevated RBAC permissions on these clusters dynamically.
- **ClusterConfig**: A CRD that defines connection and readiness status for spoke clusters. The controller periodically polls these clusters to ensure reachability.

## Core Concepts & CRDs

### 1. BreakglassEscalation
Defines a path for privilege escalation.
- **From**: The initial user group.
- **To**: The target elevated group (e.g., `cluster-admin`).
- **Clusters**: The target spoke clusters where the escalation is permitted.
- **Approvers**: Rules for who can approve the escalation (or if it is self-approving).
- **Limits**: Maximum duration and idle timeouts.

### 2. BreakglassSession
Represents an active or pending request for privilege escalation.
- **State Machine**: Transitions from `Pending` -> `Approved` (Active) -> `Expired`/`Withdrawn`/`Rejected`/`Timeout`.
- **Enforcement**: Once approved, the backend binds the user to the target group on the specified cluster. Once expired, the binding is revoked.

### 3. Identity & Auth Flow
- The system integrates with an **IdentityProvider** (e.g., Keycloak) via OIDC.
- The frontend authenticates the user, and the backend validates JWTs.
- User groups are resolved via Keycloak to determine which `BreakglassEscalation` paths are available.
- `DenyPolicy` CRDs can be used to explicitly block certain actions or users regardless of their group memberships.

## Technical Details

### Backend
- Built with `controller-runtime` and `kubebuilder`.
- Custom Gin HTTP Server (`pkg/api`) provides the REST interface for the frontend.
- Concurrency and safety are critical: the reconcilers use Kubernetes Server-Side Apply (SSA) for idempotent updates and deterministic monotonic merges.
- Comprehensive telemetry and Kubernetes Event Recording (`pkg/breakglass/eventrecorder`) track all lifecycle changes.

### Frontend
- Built with Vue 3, Vite, and strict TypeScript.
- **Design system**: the UI is built from [Telekom Scale](https://telekom.github.io/scale/) web components (`@telekom/scale-components`, plus the neutral flavour for OSS builds). Use a `scale-*` component whenever one exists (buttons, tags, tooltips, modals, notifications, dropdowns, text fields, cards, icons) instead of custom markup. Use `scale-icon-*` for icons; do not use emoji or inline SVG.
- **Tokens**: all colours, shadows and z-indexes come from Scale `--telekom-*` tokens or the app aliases in `frontend/src/assets/tokens.css`, which is the only file allowed to contain raw colour values. Spacing uses the `--space-*` scale; type uses `--telekom-text-style-*`. `npm run lint:styles` (stylelint, also run in CI) rejects hex, `rgb()`/`hsl()`, named colours and px font sizes elsewhere. It also requires `var(--shadow-*)` for box shadows and `var(--z-*)` for z-indexes.
- **Buttons**: use one `primary` button for the main action of a view, card or dialog. Use `secondary` for other actions and `ghost` for low-emphasis inline actions. Destructive actions use `secondary` with explicit wording. Put button rows in the shared `.ui-actions` / `.ui-toolbar-actions` primitives so buttons share one height and vertical centre and wrap evenly. Never size buttons with one-off pixel rules.
- **Tooltips**: every icon-only button has an accessible name and a matching `scale-tooltip`. A disabled button is wrapped in `DisabledReason`, which explains why it is disabled. Non-obvious status tags and badges use `HintTooltip`. All of these open on hover and on keyboard focus. Do not add tooltips that just repeat a visible label.
- **Themes and accessibility**: light, dark and high-contrast modes are mirrored to Scale's `data-mode`. Forced-colours is supported. The UI targets WCAG 2.1 AA. Playwright audits enforce axe, layout, keyboard, alignment and tooltip rules (`frontend/tests/e2e/ui-audit.a11y.spec.ts` on the mock API, `ui-alignment-tooltips.spec.ts` on kind).
- Designed to gracefully degrade or hide invalid actions (e.g., filtering out clusters that are not `Ready`).
- Detailed tokens, component mapping and deviations: `frontend/design.md` and `frontend/SCALE_DEVIATIONS.md`.

## Directory Structure Overview
Refer to `AGENTS.md` for specific rules for each folder, but the general layout is:
- `api/v1alpha1/`: CRD definitions.
- `pkg/breakglass/`: Domain logic (sessions, clusters, escalation).
- `pkg/api/`: REST API logic.
- `pkg/reconciler/`: Kubernetes controllers.
- `frontend/`: Vue application.
