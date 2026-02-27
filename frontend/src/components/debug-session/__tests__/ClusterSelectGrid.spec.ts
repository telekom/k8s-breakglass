// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import ClusterSelectGrid from "../ClusterSelectGrid.vue";
import type { AvailableClusterDetail } from "@/model/debugSession";

const baseClusters: AvailableClusterDetail[] = [
  {
    name: "cluster-a",
    displayName: "Cluster A",
    environment: "production",
    location: "eu-west",
    status: { healthy: true },
  },
  {
    name: "cluster-b",
    displayName: "Cluster B",
    environment: "staging",
    location: "us-east",
    status: { healthy: false },
  },
];

function factory(props: Partial<InstanceType<typeof ClusterSelectGrid>["$props"]> = {}) {
  return mount(ClusterSelectGrid, {
    props: {
      clusters: baseClusters,
      selectedCluster: "",
      loading: false,
      ...props,
    },
    // Stub custom elements that are not registered (Scale Design System)
    global: {
      stubs: {
        "scale-text-field": true,
        "scale-icon-content-link": true,
        "scale-icon-action-success": true,
        "scale-icon-action-random": true,
        "scale-icon-device-server": true,
        "scale-icon-navigation-double-right": true,
        LoadingState: true,
      },
    },
  });
}

describe("ClusterSelectGrid", () => {
  it("has the correct component name", () => {
    const wrapper = factory();
    expect(wrapper.vm.$options.name).toBe("ClusterSelectGrid");
  });

  it("renders cluster cards when clusters are provided", () => {
    const wrapper = factory();
    const cards = wrapper.findAll('[data-testid="cluster-card"]');
    expect(cards).toHaveLength(2);
  });

  it("shows loading state when loading prop is true", () => {
    const wrapper = factory({ loading: true });
    expect(wrapper.findComponent({ name: "LoadingState" }).exists()).toBe(true);
    expect(wrapper.findAll('[data-testid="cluster-card"]')).toHaveLength(0);
  });

  it("shows warning text when clusters array is empty", () => {
    const wrapper = factory({ clusters: [], loading: false });
    expect(wrapper.find(".warning-text").exists()).toBe(true);
    expect(wrapper.text()).toContain("No clusters are available");
  });

  it("emits update:selectedCluster when a cluster card is clicked", async () => {
    const wrapper = factory();
    const cards = wrapper.findAll('[data-testid="cluster-card"]');
    await cards[0]!.trigger("click");
    expect(wrapper.emitted("update:selectedCluster")).toBeTruthy();
    expect(wrapper.emitted("update:selectedCluster")![0]).toEqual(["cluster-a"]);
  });

  it("marks the selected cluster card with the selected class", () => {
    const wrapper = factory({ selectedCluster: "cluster-b" });
    const cards = wrapper.findAll('[data-testid="cluster-card"]');
    expect(cards[1]!.classes()).toContain("selected");
    expect(cards[0]!.classes()).not.toContain("selected");
  });

  it("sets aria-checked correctly on selected cluster", () => {
    const wrapper = factory({ selectedCluster: "cluster-a" });
    const cards = wrapper.findAll('[data-testid="cluster-card"]');
    expect(cards[0]!.attributes("aria-checked")).toBe("true");
    expect(cards[1]!.attributes("aria-checked")).toBe("false");
  });

  it("displays cluster filter when more than 5 clusters are provided", () => {
    const manyClusters: AvailableClusterDetail[] = Array.from({ length: 6 }, (_, i) => ({
      name: `cluster-${i}`,
      displayName: `Cluster ${i}`,
      status: { healthy: true },
    }));
    const wrapper = factory({ clusters: manyClusters });
    expect(wrapper.find('[data-testid="cluster-filter"]').exists()).toBe(true);
  });

  it("does not display cluster filter when 5 or fewer clusters", () => {
    const wrapper = factory();
    expect(wrapper.find('[data-testid="cluster-filter"]').exists()).toBe(false);
  });

  it("displays environment and location metadata", () => {
    const wrapper = factory();
    expect(wrapper.text()).toContain("production");
    expect(wrapper.text()).toContain("eu-west");
  });

  it("filters clusters by display name", async () => {
    const manyClusters: AvailableClusterDetail[] = Array.from({ length: 6 }, (_, i) => ({
      name: `cluster-${i}`,
      displayName: `Cluster ${i}`,
      environment: i < 3 ? "production" : "staging",
      location: "eu-west",
      status: { healthy: true },
    }));
    const wrapper = factory({ clusters: manyClusters });

    const vm = wrapper.vm as unknown as { clusterFilter: string };
    vm.clusterFilter = "Cluster 0";
    await wrapper.vm.$nextTick();
    const cards = wrapper.findAll('[data-testid="cluster-card"]');
    expect(cards).toHaveLength(1);
    expect(cards[0]!.text()).toContain("Cluster 0");
  });

  it("filters clusters by environment", async () => {
    const manyClusters: AvailableClusterDetail[] = Array.from({ length: 6 }, (_, i) => ({
      name: `cluster-${i}`,
      displayName: `Cluster ${i}`,
      environment: i < 3 ? "production" : "staging",
      location: "eu-west",
      status: { healthy: true },
    }));
    const wrapper = factory({ clusters: manyClusters });

    const vm = wrapper.vm as unknown as { clusterFilter: string };
    vm.clusterFilter = "staging";
    await wrapper.vm.$nextTick();
    const cards = wrapper.findAll('[data-testid="cluster-card"]');
    expect(cards).toHaveLength(3);
    // Verify the filtered cards are actually the staging clusters (indices 3-5)
    const cardTexts = cards.map((c) => c.text());
    for (const i of [3, 4, 5]) {
      expect(cardTexts.some((t) => t.includes(`Cluster ${i}`))).toBe(true);
    }
  });

  it("shows warning when no clusters match the filter", async () => {
    const manyClusters: AvailableClusterDetail[] = Array.from({ length: 6 }, (_, i) => ({
      name: `cluster-${i}`,
      displayName: `Cluster ${i}`,
      status: { healthy: true },
    }));
    const wrapper = factory({ clusters: manyClusters });

    const vm = wrapper.vm as unknown as { clusterFilter: string };
    vm.clusterFilter = "nonexistent";
    await wrapper.vm.$nextTick();
    expect(wrapper.findAll('[data-testid="cluster-card"]')).toHaveLength(0);
    expect(wrapper.text()).toContain("No clusters match");
  });
});
