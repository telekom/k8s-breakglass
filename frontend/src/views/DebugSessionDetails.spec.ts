// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { flushPromises, mount } from "@vue/test-utils";
import { ref } from "vue";
import { beforeEach, describe, expect, it, vi } from "vitest";
import DebugSessionDetails from "./DebugSessionDetails.vue";
import { AuthKey } from "@/keys";
import type { DebugSession } from "@/model/debugSession";

const mockGetSession = vi.fn();
const mockRouterPush = vi.fn();

vi.mock("vue-router", () => ({
  useRoute: () => ({ params: { name: "debug-logs-only-001" } }),
  useRouter: () => ({ push: mockRouterPush }),
}));

vi.mock("@/services/debugSession", () => ({
  default: vi.fn(function DebugSessionServiceMock() {
    return {
      getSession: mockGetSession,
      joinSession: vi.fn(),
      terminateSession: vi.fn(),
      renewSession: vi.fn(),
      approveSession: vi.fn(),
      rejectSession: vi.fn(),
    };
  }),
}));

vi.mock("@/services/auth", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@/services/auth")>();
  return {
    ...actual,
    useUser: () => ref({ profile: { email: "mock.user@breakglass.dev" } }),
  };
});

const activeLogsOnlySession: DebugSession = {
  metadata: {
    name: "debug-logs-only-001",
    namespace: "default",
  },
  spec: {
    templateRef: "logs-only",
    cluster: "test-cluster",
    requestedBy: "mock.user@breakglass.dev",
    requestedByEmail: "mock.user@breakglass.dev",
  },
  status: {
    state: "Active",
    startsAt: "2026-06-27T10:00:00Z",
    expiresAt: "2026-06-27T11:00:00Z",
    allowedPodOperations: {
      exec: false,
      attach: false,
      logs: true,
      portForward: false,
    },
    allowedPods: [
      {
        name: "debug-logs-only-001-pod",
        namespace: "debug",
        phase: "Running",
        nodeName: "worker-1",
        ready: true,
      },
    ],
  },
};

function mountDetails(session: DebugSession = activeLogsOnlySession) {
  mockGetSession.mockResolvedValue(session);
  return mount(DebugSessionDetails, {
    global: {
      provide: {
        [AuthKey as symbol]: { getAccessToken: vi.fn() },
      },
      stubs: {
        PageHeader: true,
        LoadingState: true,
        EmptyState: true,
        "scale-button": {
          template: "<button><slot /></button>",
        },
        "scale-tag": {
          template: "<span><slot /></span>",
        },
        "scale-modal": true,
        "scale-text-field": true,
        "scale-dropdown-select": true,
        "scale-icon-navigation-left": true,
      },
    },
  });
}

describe("DebugSessionDetails", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("does not offer a copyable exec command when exec is disallowed", async () => {
    const wrapper = mountDetails();
    await flushPromises();

    expect(wrapper.find('[data-testid="copy-exec-btn"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="exec-unavailable-message"]').text()).toContain("Exec is not allowed");
    expect(wrapper.text()).not.toContain("kubectl exec -it debug-logs-only-001-pod");
  });
});
