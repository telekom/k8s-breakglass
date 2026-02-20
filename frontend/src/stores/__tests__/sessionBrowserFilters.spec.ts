// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect, beforeEach } from "vitest";
import { setActivePinia, createPinia } from "pinia";
import { useSessionBrowserFilters } from "@/stores/sessionBrowserFilters";

const STORAGE_KEY = "breakglass_session_browser_filters";

describe("useSessionBrowserFilters", () => {
  beforeEach(() => {
    sessionStorage.clear();
    setActivePinia(createPinia());
  });

  it("initialises with default filters when nothing is stored", () => {
    const store = useSessionBrowserFilters();

    expect(store.filters.mine).toBe(true);
    expect(store.filters.approver).toBe(false);
    expect(store.filters.states).toEqual(["approved", "timeout", "withdrawn", "rejected"]);
    expect(store.filters.cluster).toBe("");
    expect(store.filters.group).toBe("");
    expect(store.filters.user).toBe("");
    expect(store.filters.name).toBe("");
    expect(store.filters.onlyApprovedByMe).toBe(false);
  });

  it("restores filters from sessionStorage on init", () => {
    const stored = {
      version: 1,
      filters: {
        mine: false,
        approver: true,
        states: ["pending"],
        cluster: "prod",
        group: "admins",
        user: "alice",
        name: "session-1",
        onlyApprovedByMe: true,
      },
    };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(stored));

    const store = useSessionBrowserFilters();

    expect(store.filters.mine).toBe(false);
    expect(store.filters.approver).toBe(true);
    expect(store.filters.states).toEqual(["pending"]);
    expect(store.filters.cluster).toBe("prod");
    expect(store.filters.group).toBe("admins");
    expect(store.filters.user).toBe("alice");
    expect(store.filters.name).toBe("session-1");
    expect(store.filters.onlyApprovedByMe).toBe(true);
  });

  it("falls back to defaults when stored version mismatches", () => {
    const stored = { version: 999, filters: { mine: false, states: ["pending"] } };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(stored));

    const store = useSessionBrowserFilters();

    expect(store.filters.mine).toBe(true);
    expect(store.filters.states).toEqual(["approved", "timeout", "withdrawn", "rejected"]);
  });

  it("falls back to defaults when stored data is invalid JSON", () => {
    sessionStorage.setItem(STORAGE_KEY, "not-json!!!");

    const store = useSessionBrowserFilters();

    expect(store.filters.mine).toBe(true);
  });

  it("falls back to defaults when stored filters have wrong shape", () => {
    const stored = { version: 1, filters: { mine: "not-a-boolean", states: "not-an-array" } };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(stored));

    const store = useSessionBrowserFilters();

    expect(store.filters.mine).toBe(true);
    expect(store.filters.states).toEqual(["approved", "timeout", "withdrawn", "rejected"]);
  });

  it("persists filter changes to sessionStorage", async () => {
    const store = useSessionBrowserFilters();

    store.filters.mine = false;
    store.filters.cluster = "staging";

    // Wait for the watcher to trigger
    await new Promise((resolve) => setTimeout(resolve, 0));

    const raw = sessionStorage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!);
    expect(parsed.version).toBe(1);
    expect(parsed.filters.mine).toBe(false);
    expect(parsed.filters.cluster).toBe("staging");
  });

  it("resetFilters restores defaults", () => {
    const store = useSessionBrowserFilters();

    store.filters.mine = false;
    store.filters.cluster = "prod";
    store.filters.states = ["pending"];

    store.resetFilters();

    expect(store.filters.mine).toBe(true);
    expect(store.filters.cluster).toBe("");
    expect(store.filters.states).toEqual(["approved", "timeout", "withdrawn", "rejected"]);
  });

  it("survives store re-instantiation within same Pinia", () => {
    const store1 = useSessionBrowserFilters();
    store1.filters.cluster = "production";

    // Same pinia instance — should return the same store
    const store2 = useSessionBrowserFilters();
    expect(store2.filters.cluster).toBe("production");
  });
});
