// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { defineStore } from "pinia";
import { reactive, watch } from "vue";

/**
 * Filter state shape for the Session Browser view.
 * Kept in sync with the FilterState type in SessionBrowser.vue.
 */
export interface FilterState {
  mine: boolean;
  approver: boolean;
  states: string[];
  cluster: string;
  group: string;
  user: string;
  name: string;
  onlyApprovedByMe: boolean;
}

const STORAGE_KEY = "breakglass_session_browser_filters";

/**
 * Current schema version — bump when FilterState shape changes.
 * On mismatch the stored state is discarded and defaults are used.
 */
const SCHEMA_VERSION = 1;

interface StoredPayload {
  version: number;
  filters: FilterState;
}

const DEFAULT_STATES = ["approved", "timeout", "withdrawn", "rejected"];

function defaultFilters(): FilterState {
  return {
    mine: true,
    approver: false,
    states: [...DEFAULT_STATES],
    cluster: "",
    group: "",
    user: "",
    name: "",
    onlyApprovedByMe: false,
  };
}

function loadFromStorage(): FilterState {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    if (!raw) return defaultFilters();

    const payload: StoredPayload = JSON.parse(raw);
    if (payload.version !== SCHEMA_VERSION || !payload.filters) {
      return defaultFilters();
    }

    // Validate shape — ensure all expected keys are present
    const f = payload.filters;
    if (typeof f.mine !== "boolean" || !Array.isArray(f.states)) {
      return defaultFilters();
    }

    return { ...defaultFilters(), ...f };
  } catch {
    return defaultFilters();
  }
}

function saveToStorage(filters: FilterState): void {
  try {
    const payload: StoredPayload = { version: SCHEMA_VERSION, filters };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // sessionStorage quota exceeded or unavailable — ignore silently
  }
}

/**
 * Pinia store for Session Browser filter state.
 *
 * Survives Vue Router navigation and persists across page reloads
 * within the same browser tab via sessionStorage.
 */
export const useSessionBrowserFilters = defineStore("sessionBrowserFilters", () => {
  const filters = reactive<FilterState>(loadFromStorage());

  // Persist every change to sessionStorage
  watch(
    () => ({ ...filters, states: [...filters.states] }),
    (current) => saveToStorage(current as FilterState),
    { deep: true },
  );

  function resetFilters() {
    const defaults = defaultFilters();
    Object.assign(filters, defaults);
  }

  return { filters, resetFilters, DEFAULT_STATES };
});
