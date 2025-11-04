// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { reactive } from "vue";

export interface AppError {
  id: string;
  message: string;
  status?: number;
  cid?: string; // correlation id from backend
  ts: number;
}

const state = reactive<{ errors: AppError[] }>({ errors: [] });

export function pushError(message: string, status?: number, cid?: string) {
  const id = Math.random().toString(36).slice(2);
  state.errors.push({ id, message, status, cid, ts: Date.now() });
  // Auto-expire after 10s
  setTimeout(() => dismissError(id), 10000);
}

export function dismissError(id: string) {
  const idx = state.errors.findIndex((e) => e.id === id);
  if (idx >= 0) state.errors.splice(idx, 1);
}

export function useErrors() {
  return state;
}
