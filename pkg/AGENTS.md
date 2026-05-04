<!--
SPDX-FileCopyrightText: 2024 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# Breakglass Controller Packages — Agent Instructions

This document provides conventions specifically for AI coding agents working in the `pkg` directory.

## Core Packages
- `pkg/api`: Contains the Gin REST API endpoints.
- `pkg/breakglass`: Core domain logic (session lifecycle, group checker, debug controllers).
- `pkg/cluster`: Multi-cluster management logic.
- `pkg/reconciler`: The core controller-runtime managers.

## Critical Rules
1. **Error Handling**: Use `fmt.Errorf("context: %w", err)` for proper error wrapping.
2. **Logging**: Use structured logging with `go.uber.org/zap` (`SugaredLogger`). Include relevant context (e.g., `escalation`, `group`, `user`).
3. **Event Recording**: When modifying status or reacting to significant state changes, emit a Kubernetes event using the `events.EventRecorder` (e.g., `pkg/breakglass/eventrecorder`).
4. **Testing**: Every new package or significant functionality requires unit tests with `>70%` coverage. 
5. **HTTP Server**: When modifying Gin endpoints in `pkg/api`, ensure you add telemetry/metrics calls where appropriate. Use standard HTTP constants (e.g., `http.MethodGet`).
