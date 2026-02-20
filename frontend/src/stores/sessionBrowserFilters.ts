// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { defineStore } from "pinia";
import { reactive, watch } from "vue";

/**
 * Filter state shape for the Session Browser view.
 * This is the canonical definition — SessionBrowser.vue imports from this store.
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

    // Validate/coerce all fields to prevent runtime errors from corrupted storage
    const f = payload.filters;
    const defaults = defaultFilters();

    const safeStates = Array.isArray(f.states)
      ? f.states.filter((s): s is string => typeof s === "string")
      : defaults.states;

    return {
      mine: typeof f.mine === "boolean" ? f.mine : defaults.mine,
      approver: typeof f.approver === "boolean" ? f.approver : defaults.approver,
      onlyApprovedByMe:
        typeof f.onlyApprovedByMe === "boolean" ? f.onlyApprovedByMe : defaults.onlyApprovedByMe,
      states: safeStates.length > 0 ? safeStates : defaults.states,
      cluster: typeof f.cluster === "string" ? f.cluster : defaults.cluster,
      group: typeof f.group === "string" ? f.group : defaults.group,
      user: typeof f.user === "string" ? f.user : defaults.user,
      name: typeof f.name === "string" ? f.name : defaults.name,
    };
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
