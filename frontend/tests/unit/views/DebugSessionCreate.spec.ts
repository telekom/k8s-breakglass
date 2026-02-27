/**
 * Tests for DebugSessionCreate view component
 *
 * @vitest-environment jsdom
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
const mockGetTemplateClusters = vi.fn();

// Mock debug session service at module level
vi.mock("@/services/debugSession", () => ({
  default: class MockDebugSessionService {
    listTemplates = mockListTemplates;
    createSession = mockCreateSession;
    getTemplateClusters = mockGetTemplateClusters;
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
    getUser: vi.fn().mockResolvedValue({
      profile: {
        email: "test@example.com",
        groups: ["test-group", "platform-oncall"],
      },
    }),
  };

  beforeEach(() => {
    mockListTemplates.mockReset();
    mockCreateSession.mockReset();
    mockGetTemplateClusters.mockReset();

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
        constraints: {
          maxDuration: "4h",
          defaultDuration: "1h",
        },
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
        schedulingOptions: {
          required: true,
          options: [
            { name: "sriov", displayName: "SRIOV Nodes", description: "High-performance network nodes", default: true },
            { name: "standard", displayName: "Standard Nodes", description: "Regular worker nodes" },
          ],
        },
        namespaceConstraints: {
          allowedPatterns: ["debug-*", "test-*"],
          allowedLabelSelectors: [{ matchLabels: { "debug-enabled": "true" } }],
          defaultNamespace: "debug-default",
          allowUserNamespace: true,
        },
      },
      {
        name: "network-debug",
        displayName: "Network Debug",
        description: "Network debugging with special scheduling",
        mode: "workload",
        workloadType: "daemonset",
        requiresApproval: true,
        allowedClusters: ["prod-east"],
        allowedGroups: ["netops"],
        schedulingOptions: {
          required: false,
          options: [
            { name: "sriov", displayName: "SRIOV Nodes" },
            { name: "dpdk", displayName: "DPDK Nodes" },
          ],
        },
        namespaceConstraints: {
          allowedPatterns: ["network-*"],
          allowedLabelSelectors: [
            { matchLabels: { team: "network" } },
            { matchExpressions: [{ key: "environment", operator: "In", values: ["prod", "staging"] }] },
          ],
          defaultNamespace: "network-debug",
          allowUserNamespace: true,
        },
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

    it("starts on step 1 (template selection)", async () => {
      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as { currentStep: number };
      expect(vm.currentStep).toBe(1);
    });

    it("moves to step 2 when clicking Next", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          { name: "prod-east", displayName: "Production East" },
          { name: "prod-west", displayName: "Production West" },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        currentStep: number;
        form: { templateRef: string };
      };

      // First template is auto-selected
      expect(vm.form.templateRef).toBe("standard-debug");

      // Click Next button
      const nextButton = wrapper.find('[data-testid="next-button"]');
      await nextButton.trigger("click");
      await flushPromises();

      // Should be on step 2 and have fetched cluster details
      expect(vm.currentStep).toBe(2);
      expect(mockGetTemplateClusters).toHaveBeenCalledWith("standard-debug");
    });

    it("shows warning when template has no available clusters in step 2", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "no-clusters-template",
        templateDisplayName: "No Clusters",
        clusters: [], // Empty clusters
      });

      const templates = [
        {
          name: "no-clusters-template",
          displayName: "No Clusters",
          description: "Template with no available clusters",
          mode: "workload",
          workloadType: "deployment",
          requiresApproval: false,
          allowedClusters: [],
          allowedGroups: ["developers"],
          constraints: { maxDuration: "4h", defaultDuration: "1h" },
        },
      ];

      const wrapper = await createWrapper(templates);

      const vm = wrapper.vm as unknown as { currentStep: number; goToStep2: () => void };

      // Go to step 2
      vm.goToStep2();
      await flushPromises();

      // Should show warning about no clusters
      const warningText = wrapper.find(".warning-text");
      expect(warningText.exists()).toBe(true);
      expect(warningText.text()).toContain("No clusters are available");
    });
  });

  describe("form validation", () => {
    it("auto-selects first template on mount", async () => {
      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        form: { templateRef: string };
      };

      // Initially first template is auto-selected
      expect(vm.form.templateRef).toBe("standard-debug");
    });
  });

  describe("cluster details display", () => {
    it("displays cluster cards with resolved constraints in step 2", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            environment: "production",
            constraints: { maxDuration: "2h" },
            approval: { required: true },
          },
          {
            name: "prod-west",
            displayName: "Production West",
            environment: "production",
            constraints: { maxDuration: "4h" },
            approval: { required: false },
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as { goToStep2: () => void };
      vm.goToStep2();
      await flushPromises();

      // Should display cluster grid with cards
      const clusterGrid = wrapper.find('[data-testid="cluster-grid"]');
      expect(clusterGrid.exists()).toBe(true);

      const clusterCards = wrapper.findAll('[data-testid="cluster-card"]');
      expect(clusterCards).toHaveLength(2);
    });
  });

  describe("namespace editability", () => {
    it("allows namespace editing when allowUserNamespace is true and patterns allow it", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            namespaceConstraints: {
              defaultNamespace: "debug-default",
              allowUserNamespace: true,
              allowedPatterns: ["debug-*", "test-*"],
            },
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        isNamespaceEditable: boolean;
      };
      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Namespace should be editable because allowUserNamespace is true and there are wildcard patterns
      expect(vm.isNamespaceEditable).toBe(true);
    });

    it("prevents namespace editing when there is a single exact pattern", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            namespaceConstraints: {
              defaultNamespace: "debug-only",
              allowUserNamespace: true,
              allowedPatterns: ["debug-only"], // Exact match, no wildcards
            },
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        isNamespaceEditable: boolean;
      };
      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Namespace should NOT be editable because there's only one exact pattern
      expect(vm.isNamespaceEditable).toBe(false);
    });

    it("prevents namespace editing when there is a hardcoded default with no patterns", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            namespaceConstraints: {
              defaultNamespace: "fixed-namespace",
              allowUserNamespace: true,
              allowedPatterns: [], // No patterns
            },
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        isNamespaceEditable: boolean;
      };
      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Namespace should NOT be editable because there's a hardcoded default with no patterns
      expect(vm.isNamespaceEditable).toBe(false);
    });
  });

  describe("session info summary", () => {
    it("displays approval requirement warning when approval is required", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            approval: {
              required: true,
              approverGroups: ["admin-approvers"],
            },
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        approvalInfo: { required: boolean; approverGroups?: string[] };
      };
      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Approval should be required
      expect(vm.approvalInfo.required).toBe(true);
      expect(vm.approvalInfo.approverGroups).toContain("admin-approvers");
    });

    it("displays impersonation info when impersonation is enabled", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            impersonation: {
              enabled: true,
              serviceAccount: "debug-sa",
              namespace: "system",
            },
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        impersonationInfo: { enabled: boolean; serviceAccount: string; namespace: string } | null;
      };
      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Impersonation info should be available
      expect(vm.impersonationInfo).toBeTruthy();
      expect(vm.impersonationInfo?.enabled).toBe(true);
      expect(vm.impersonationInfo?.serviceAccount).toBe("debug-sa");
    });

    it("displays required auxiliary resources", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            requiredAuxiliaryResourceCategories: ["logging", "monitoring"],
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        requiredAuxiliaryResources: string[];
      };
      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Required auxiliary resources should be available
      expect(vm.requiredAuxiliaryResources).toContain("logging");
      expect(vm.requiredAuxiliaryResources).toContain("monitoring");
    });
  });

  // -----------------------------------------------------------------
  // Cluster Search/Filter
  // -----------------------------------------------------------------
  describe("cluster filter", () => {
    function manyClustersMock() {
      return {
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: Array.from({ length: 8 }, (_, i) => ({
          name: `cluster-${i}`,
          displayName: `Cluster ${i}`,
          environment: i < 4 ? "production" : "staging",
          location: i % 2 === 0 ? "Frankfurt" : "Berlin",
          constraints: { maxDuration: "4h" },
          approval: { required: false },
        })),
      };
    }

    it("shows filter input when more than 5 clusters", async () => {
      mockGetTemplateClusters.mockResolvedValue(manyClustersMock());
      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as { goToStep2: () => void };
      vm.goToStep2();
      await flushPromises();

      expect(wrapper.find('[data-testid="cluster-filter"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="cluster-filter-input"]').exists()).toBe(true);
    });

    it("does not show filter when 5 or fewer clusters", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          { name: "c1", displayName: "C1" },
          { name: "c2", displayName: "C2" },
        ],
      });
      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as { goToStep2: () => void };
      vm.goToStep2();
      await flushPromises();

      expect(wrapper.find('[data-testid="cluster-filter"]').exists()).toBe(false);
    });

    it("filters clusters by name", async () => {
      mockGetTemplateClusters.mockResolvedValue(manyClustersMock());
      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        filteredClusterDetails: { name: string }[];
      };
      vm.goToStep2();
      await flushPromises();

      // All 8 should be shown initially
      expect(vm.filteredClusterDetails).toHaveLength(8);

      // Set the clusterFilter ref directly to simulate user typing
      const clusterFilter = wrapper.vm as unknown as { clusterFilter: string };
      clusterFilter.clusterFilter = "staging";
      await wrapper.vm.$nextTick();

      // Only clusters 4-7 have environment "staging"
      expect(vm.filteredClusterDetails).toHaveLength(4);
      expect(vm.filteredClusterDetails.every((c) => c.name.match(/cluster-[4-7]/))).toBe(true);

      // Filter by location
      clusterFilter.clusterFilter = "Frankfurt";
      await wrapper.vm.$nextTick();

      // Even-numbered clusters (0, 2, 4, 6) are in Frankfurt
      expect(vm.filteredClusterDetails).toHaveLength(4);

      // Filter with no match
      clusterFilter.clusterFilter = "nonexistent";
      await wrapper.vm.$nextTick();
      expect(vm.filteredClusterDetails).toHaveLength(0);
    });

    it("shows cluster count when filter is active", async () => {
      mockGetTemplateClusters.mockResolvedValue(manyClustersMock());
      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as { goToStep2: () => void };
      vm.goToStep2();
      await flushPromises();

      const countText = wrapper.find(".cluster-count");
      expect(countText.exists()).toBe(true);
      expect(countText.text()).toContain("Showing 8 of 8 clusters");
    });
  });

  // -----------------------------------------------------------------
  // Scheduling Constraint Details
  // -----------------------------------------------------------------
  describe("scheduling constraint details display", () => {
    it("shows scheduling options with constraint details", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "elevated-debug",
        templateDisplayName: "Elevated Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            schedulingOptions: {
              required: true,
              options: [
                {
                  name: "worker",
                  displayName: "Worker Nodes",
                  default: true,
                  schedulingConstraints: {
                    nodeSelector: { "node-role.kubernetes.io/worker": "" },
                    summary: "Worker nodes only",
                  },
                },
                {
                  name: "debug",
                  displayName: "Debug Nodes",
                  schedulingConstraints: {
                    nodeSelector: { "node.breakglass.io/debug": "true" },
                    deniedNodeLabels: { "node-role.kubernetes.io/control-plane": "" },
                    tolerations: [{ key: "debug-workload", operator: "Exists", effect: "NoSchedule" }],
                    summary: "Debug-labeled nodes",
                  },
                },
              ],
            },
          },
        ],
      });

      const templates = defaultTemplates();
      (templates[1]!.schedulingOptions!.options as unknown[]) = [
        {
          name: "worker",
          displayName: "Worker Nodes",
          default: true,
          schedulingConstraints: {
            nodeSelector: { "node-role.kubernetes.io/worker": "" },
          },
        },
        {
          name: "debug",
          displayName: "Debug Nodes",
          schedulingConstraints: {
            nodeSelector: { "node.breakglass.io/debug": "true" },
            deniedNodeLabels: { "node-role.kubernetes.io/control-plane": "" },
            tolerations: [{ key: "debug-workload", operator: "Exists", effect: "NoSchedule" }],
          },
        },
      ];
      const wrapper = await createWrapper(templates);

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string; templateRef: string };
      };

      // Select elevated-debug template
      vm.form.templateRef = "elevated-debug";
      await flushPromises();

      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Scheduling options section should be visible
      const schedulingSection = wrapper.find('[data-testid="scheduling-options-section"]');
      expect(schedulingSection.exists()).toBe(true);
    });
  });

  // -----------------------------------------------------------------
  // Binding Source Labels
  // -----------------------------------------------------------------
  describe("binding source labels", () => {
    it("shows binding source reference on binding option cards", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            bindingRef: { name: "binding-1", namespace: "breakglass" },
            bindingOptions: [
              {
                bindingRef: { name: "binding-sre", namespace: "breakglass", displayName: "SRE Access" },
                constraints: { maxDuration: "2h" },
                approval: { required: true, approverGroups: ["sre-leads"] },
              },
              {
                bindingRef: { name: "binding-oncall", namespace: "emergency-ns", displayName: "On-Call Access" },
                constraints: { maxDuration: "4h" },
                approval: { required: false },
              },
            ],
          },
        ],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
      };
      vm.goToStep2();
      await flushPromises();

      // Select the cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Binding options section should exist
      const bindingSection = wrapper.find('[data-testid="binding-options-section"]');
      expect(bindingSection.exists()).toBe(true);

      // Binding option cards should show source ref
      const sourceRefs = wrapper.findAll('[data-testid="binding-source-ref"]');
      expect(sourceRefs).toHaveLength(2);
      expect(sourceRefs[0]!.text()).toContain("breakglass/binding-sre");
      expect(sourceRefs[1]!.text()).toContain("emergency-ns/binding-oncall");
    });
  });

  // -----------------------------------------------------------------
  // Extra Deploy Variables
  // -----------------------------------------------------------------
  describe("extra deploy variables", () => {
    it("renders VariableForm when template has extraDeployVariables", async () => {
      const templates = defaultTemplates();
      (templates[0] as unknown as Record<string, unknown>).extraDeployVariables = [
        { name: "testVar", displayName: "Test Var", inputType: "text", required: false },
      ];

      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [{ name: "prod-east", displayName: "Production East" }],
      });

      const wrapper = await createWrapper(templates);

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        hasExtraDeployVariables: boolean;
      };
      vm.goToStep2();
      await flushPromises();

      // Select cluster
      vm.form.cluster = "prod-east";
      await flushPromises();

      // Template should have extra deploy variables
      expect(vm.hasExtraDeployVariables).toBe(true);
    });

    it("does not render extra variables section when template has none", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [{ name: "prod-east", displayName: "Production East" }],
      });

      const wrapper = await createWrapper();

      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
        hasExtraDeployVariables: boolean;
      };
      vm.goToStep2();
      await flushPromises();

      vm.form.cluster = "prod-east";
      await flushPromises();

      expect(vm.hasExtraDeployVariables).toBeFalsy();
    });
  });

  describe("auto-approve approval display", () => {
    it("shows auto-approve label when canAutoApprove is true and approval required", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            bindingRef: { name: "binding-1", namespace: "default" },
            bindingOptions: [
              {
                bindingRef: { name: "binding-1", namespace: "default" },
                displayName: "Standard",
                approval: { required: true, canAutoApprove: true, approverGroups: ["admins"] },
                constraints: { maxDuration: "2h" },
              },
              {
                bindingRef: { name: "binding-2", namespace: "default" },
                displayName: "Emergency",
                approval: { required: false },
                constraints: { maxDuration: "4h" },
              },
            ],
          },
        ],
      });

      const wrapper = await createWrapper();
      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
      };
      vm.goToStep2();
      await flushPromises();

      vm.form.cluster = "prod-east";
      await flushPromises();

      const html = wrapper.html();
      expect(html).toContain("Auto");
      expect(html).toContain("approval (eligible)");
    });

    it("shows Required label when canAutoApprove is false and approval required", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            bindingRef: { name: "binding-1", namespace: "default" },
            bindingOptions: [
              {
                bindingRef: { name: "binding-1", namespace: "default" },
                displayName: "Standard",
                approval: { required: true, canAutoApprove: false, approverGroups: ["admins"] },
                constraints: { maxDuration: "2h" },
              },
              {
                bindingRef: { name: "binding-2", namespace: "default" },
                displayName: "Emergency",
                approval: { required: false },
                constraints: { maxDuration: "4h" },
              },
            ],
          },
        ],
      });

      const wrapper = await createWrapper();
      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
      };
      vm.goToStep2();
      await flushPromises();

      vm.form.cluster = "prod-east";
      await flushPromises();

      const html = wrapper.html();
      expect(html).toContain("Required");
      expect(html).toContain("approval");
    });

    it("shows approver users when available", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            bindingRef: { name: "binding-1", namespace: "default" },
            bindingOptions: [
              {
                bindingRef: { name: "binding-1", namespace: "default" },
                displayName: "Standard",
                approval: {
                  required: true,
                  approverGroups: ["admins"],
                  approverUsers: ["alice@example.com", "bob@example.com"],
                },
                constraints: { maxDuration: "2h" },
              },
              {
                bindingRef: { name: "binding-2", namespace: "default" },
                displayName: "Emergency",
                approval: { required: false },
                constraints: { maxDuration: "4h" },
              },
            ],
          },
        ],
      });

      const wrapper = await createWrapper();
      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
      };
      vm.goToStep2();
      await flushPromises();

      vm.form.cluster = "prod-east";
      await flushPromises();

      const html = wrapper.html();
      expect(html).toContain("alice@example.com");
      expect(html).toContain("bob@example.com");
    });
  });

  describe("keyboard navigation", () => {
    it("cluster cards have role=radio with roving tabindex", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            bindingRef: { name: "binding-1", namespace: "default" },
            approval: { required: false },
            constraints: { maxDuration: "4h" },
          },
          {
            name: "prod-west",
            displayName: "Production West",
            bindingRef: { name: "binding-2", namespace: "default" },
            approval: { required: false },
            constraints: { maxDuration: "2h" },
          },
        ],
      });

      const wrapper = await createWrapper();
      const vm = wrapper.vm as unknown as { goToStep2: () => void };
      vm.goToStep2();
      await flushPromises();

      const clusterGrid = wrapper.find('[data-testid="cluster-grid"]');
      const clusterCards = clusterGrid.findAll('[role="radio"]');
      expect(clusterCards.length).toBeGreaterThanOrEqual(2);

      // First unselected card: tabindex 0 (first focusable), second: tabindex -1
      const firstCard = clusterCards[0]!;
      expect(firstCard.attributes("tabindex")).toBe("0");
      const secondCard = clusterCards[1]!;
      expect(secondCard.attributes("tabindex")).toBe("-1");
    });

    it("cluster radiogroup has correct aria-label", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            bindingRef: { name: "binding-1", namespace: "default" },
            approval: { required: false },
            constraints: { maxDuration: "4h" },
          },
        ],
      });

      const wrapper = await createWrapper();
      const vm = wrapper.vm as unknown as { goToStep2: () => void };
      vm.goToStep2();
      await flushPromises();

      const radiogroup = wrapper.find('[role="radiogroup"]');
      expect(radiogroup.exists()).toBe(true);
      expect(radiogroup.attributes("aria-label")).toContain("Select");
    });

    it("Enter/Space keydown handlers are bound on cluster cards", async () => {
      mockGetTemplateClusters.mockResolvedValue({
        templateName: "standard-debug",
        templateDisplayName: "Standard Debug",
        clusters: [
          {
            name: "prod-east",
            displayName: "Production East",
            bindingRef: { name: "binding-1", namespace: "default" },
            approval: { required: false },
            constraints: { maxDuration: "4h" },
          },
          {
            name: "prod-west",
            displayName: "Production West",
            bindingRef: { name: "binding-2", namespace: "default" },
            approval: { required: false },
            constraints: { maxDuration: "2h" },
          },
        ],
      });

      const wrapper = await createWrapper();
      const vm = wrapper.vm as unknown as {
        goToStep2: () => void;
        form: { cluster: string };
      };
      vm.goToStep2();
      await flushPromises();

      const cards = wrapper.findAll('[data-testid="cluster-card"]');
      expect(cards.length).toBeGreaterThanOrEqual(2);

      // Test Enter key selects the second cluster card
      await cards[1]!.trigger("keydown.enter");
      await flushPromises();

      expect(vm.form.cluster).toBe("prod-west");
      expect(cards[1]!.attributes("aria-checked")).toBe("true");

      // Test Space key selects the first cluster card back
      await cards[0]!.trigger("keydown.space");
      await flushPromises();

      expect(vm.form.cluster).toBe("prod-east");
      expect(cards[0]!.attributes("aria-checked")).toBe("true");
    });
  });
});
