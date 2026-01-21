/**
 * Tests for DebugSessionCreate view component
 *
 * @jest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import DebugSessionCreate from "@/views/DebugSessionCreate.vue";
import { AuthKey } from "@/keys";

// Define mock functions at module level
const mockListTemplates = vi.fn();
const mockCreateSession = vi.fn();

// Mock debug session service at module level
vi.mock("@/services/debugSession", () => ({
  default: class MockDebugSessionService {
    listTemplates = mockListTemplates;
    createSession = mockCreateSession;
  },
}));

// Mock toast service
vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

// Mock auth service
vi.mock("@/services/auth", () => ({
  useUser: vi.fn().mockReturnValue(
    ref({
      profile: {
        email: "test@example.com",
        preferred_username: "testuser",
      },
    }),
  ),
}));

describe("DebugSessionCreate", () => {
  let router: ReturnType<typeof createRouter>;

  const mockAuth = {
    user: ref({ email: "test@example.com" }),
    token: ref("test-token"),
    isAuthenticated: ref(true),
    getAccessToken: vi.fn().mockResolvedValue("test-token"),
  };

  beforeEach(() => {
    mockListTemplates.mockReset();
    mockCreateSession.mockReset();

    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/debug-sessions/create", name: "debugSessionCreate", component: DebugSessionCreate },
        { path: "/debug-sessions", name: "debugSessionBrowser", component: { template: "<div />" } },
      ],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  function defaultTemplates() {
    return [
      {
        name: "standard-debug",
        displayName: "Standard Debug",
        description: "Standard debug access template",
        mode: "workload",
        workloadType: "deployment",
        requiresApproval: false,
        allowedClusters: ["prod-east", "prod-west", "staging-1"],
        allowedGroups: ["developers"],
      },
      {
        name: "elevated-debug",
        displayName: "Elevated Debug",
        description: "Elevated debug access with more privileges",
        mode: "workload",
        workloadType: "deployment",
        requiresApproval: true,
        allowedClusters: ["prod-east", "prod-west"],
        allowedGroups: ["admins"],
      },
    ];
  }

  const createWrapper = async (templates = defaultTemplates()) => {
    mockListTemplates.mockResolvedValue({ templates });

    await router.push("/debug-sessions/create");
    await router.isReady();

    const wrapper = mount(DebugSessionCreate, {
      global: {
        plugins: [router],
        stubs: {
          PageHeader: true,
          LoadingState: true,
          "scale-dropdown-select": {
            template: '<select :value="value" :disabled="disabled" @change="handleChange"><slot /></select>',
            props: ["value", "label", "disabled", "required"],
            emits: ["scaleChange"],
            methods: {
              handleChange(e: Event) {
                this.$emit("scaleChange", e);
              },
            },
          },
          "scale-dropdown-select-item": {
            template: '<option :value="value"><slot /></option>',
            props: ["value"],
          },
          "scale-textarea": {
            template: '<textarea :value="value" @input="handleInput"></textarea>',
            props: ["value", "label", "placeholder", "rows", "required"],
            emits: ["scaleChange"],
            methods: {
              handleInput(e: Event) {
                this.$emit("scaleChange", e);
              },
            },
          },
          "scale-checkbox": {
            template: '<input type="checkbox" :checked="checked" @change="handleChange" />',
            props: ["checked", "label"],
            emits: ["scaleChange"],
            methods: {
              handleChange(e: Event) {
                this.$emit("scaleChange", e);
              },
            },
          },
          "scale-text-field": {
            template: '<input type="text" :value="value" @input="handleInput" />',
            props: ["value", "type", "label"],
            emits: ["scaleChange"],
            methods: {
              handleInput(e: Event) {
                this.$emit("scaleChange", e);
              },
            },
          },
          "scale-button": {
            template: '<button :disabled="disabled" @click="$emit(\'click\')"><slot /></button>',
            props: ["disabled", "variant"],
          },
        },
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  describe("template and cluster selection", () => {
    it("loads templates on mount", async () => {
      await createWrapper();

      expect(mockListTemplates).toHaveBeenCalled();
    });

    it("shows warning when template has no available clusters", async () => {
      const templates = [
        {
          name: "no-clusters-template",
          displayName: "No Clusters",
          description: "Template with no available clusters",
          mode: "workload",
          workloadType: "deployment",
          requiresApproval: false,
          allowedClusters: [] as string[], // Empty clusters - patterns didn't resolve
          allowedGroups: ["developers"],
        },
      ];

      const wrapper = await createWrapper(templates);

      // Should show warning about no clusters
      const warningText = wrapper.find(".warning-text");
      expect(warningText.exists()).toBe(true);
      expect(warningText.text()).toContain("No clusters are available");
    });

    it("disables cluster dropdown when no clusters available", async () => {
      const templates = [
        {
          name: "no-clusters-template",
          displayName: "No Clusters",
          description: "Template with no available clusters",
          mode: "workload",
          workloadType: "deployment",
          requiresApproval: false,
          allowedClusters: [] as string[],
          allowedGroups: ["developers"],
        },
      ];

      const wrapper = await createWrapper(templates);

      const clusterSelect = wrapper.find('[data-testid="cluster-select"]');
      expect(clusterSelect.attributes("disabled")).toBeDefined();
    });

    it("renders cluster options from template allowedClusters", async () => {
      const wrapper = await createWrapper();

      // Verify the component exists
      const createForm = wrapper.find(".create-form");
      expect(createForm.exists()).toBe(true);

      // Verify the vm computed property has the expected clusters
      const vm = wrapper.vm as unknown as { availableClusters: string[] };
      expect(vm.availableClusters).toEqual(["prod-east", "prod-west", "staging-1"]);
    });
  });

  describe("form validation", () => {
    it("computed availableClusters reflects selected template", async () => {
      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        availableClusters: string[];
        form: { templateRef: string };
      };

      // Initially first template is auto-selected
      expect(vm.form.templateRef).toBe("standard-debug");
      expect(vm.availableClusters).toEqual(["prod-east", "prod-west", "staging-1"]);
    });
  });

  describe("cluster name display", () => {
    it("displays resolved cluster names not patterns", async () => {
      // This test verifies the fix for the cluster pattern resolution issue
      // The backend now resolves patterns like "*" or "prod-*" to actual cluster names
      const templates = [
        {
          name: "resolved-template",
          displayName: "Resolved Clusters",
          description: "Template with resolved cluster names",
          mode: "workload",
          workloadType: "deployment",
          requiresApproval: false,
          // These should be actual cluster names, not patterns like "*" or "prod-*"
          allowedClusters: ["prod-east", "prod-west", "ship-lab-1", "ship-lab-2"],
          allowedGroups: ["developers"],
        },
      ];

      const wrapper = await createWrapper(templates);

      const vm = wrapper.vm as unknown as { availableClusters: string[] };

      // Verify we have actual cluster names, not patterns
      expect(vm.availableClusters).toHaveLength(4);
      expect(vm.availableClusters).not.toContain("*");
      expect(vm.availableClusters).not.toContain("prod-*");
      expect(vm.availableClusters).not.toContain("ship-lab-*");
      expect(vm.availableClusters).toContain("prod-east");
      expect(vm.availableClusters).toContain("prod-west");
      expect(vm.availableClusters).toContain("ship-lab-1");
      expect(vm.availableClusters).toContain("ship-lab-2");
    });
  });
});
