// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import SessionConfigForm from "../SessionConfigForm.vue";

const baseProps = {
  hasSchedulingOptions: false,
  canSelectNamespace: false,
  isNamespaceEditable: false,
  defaultNamespace: "default",
  durationOptions: [
    { value: "1h", label: "1 hour" },
    { value: "4h", label: "4 hours" },
  ],
  approvalInfo: { required: false },
  requiredAuxiliaryResources: [] as string[],
  hasExtraDeployVariables: false,
  extraDeployVariables: [],
  userGroups: [],
  selectedSchedulingOption: "",
  targetNamespace: "default",
  requestedDuration: "1h",
  reason: "",
  scheduledStartTime: "",
  useScheduledStart: false,
  extraDeployValues: {},
  showAdvancedOptions: false,
};

function factory(overrides: Record<string, unknown> = {}) {
  return mount(SessionConfigForm, {
    props: { ...baseProps, ...overrides },
    global: {
      stubs: {
        "scale-dropdown-select": true,
        "scale-dropdown-select-item": true,
        "scale-textarea": true,
        "scale-text-field": true,
        "scale-radio-button-group": true,
        "scale-radio-button": true,
        "scale-checkbox": true,
        "scale-icon-alert-information": true,
        "scale-icon-user-file-user": true,
        "scale-icon-action-add-circle": true,
        VariableForm: true,
      },
    },
  });
}

describe("SessionConfigForm", () => {
  it("has the correct component name", () => {
    const wrapper = factory();
    expect(wrapper.vm.$options.name).toBe("SessionConfigForm");
  });

  it("renders session details section by default", () => {
    const wrapper = factory();
    expect(wrapper.text()).toContain("Session Details");
  });

  it("does not render scheduling section when hasSchedulingOptions is false", () => {
    const wrapper = factory({ hasSchedulingOptions: false });
    expect(wrapper.find('[data-testid="scheduling-options-section"]').exists()).toBe(false);
  });

  it("renders scheduling section when hasSchedulingOptions is true", () => {
    const wrapper = factory({
      hasSchedulingOptions: true,
      schedulingOptions: {
        required: true,
        options: [{ name: "default", displayName: "Default Node" }],
      },
    });
    expect(wrapper.find('[data-testid="scheduling-options-section"]').exists()).toBe(true);
  });

  it("does not render namespace section when canSelectNamespace is false", () => {
    const wrapper = factory({ canSelectNamespace: false });
    expect(wrapper.find('[data-testid="namespace-section"]').exists()).toBe(false);
  });

  it("renders fixed namespace when canSelectNamespace is true but not editable", () => {
    const wrapper = factory({
      canSelectNamespace: true,
      isNamespaceEditable: false,
      defaultNamespace: "debug-ns",
    });
    const section = wrapper.find('[data-testid="namespace-section"]');
    expect(section.exists()).toBe(true);
    const fixedNs = wrapper.find('[data-testid="fixed-namespace"]');
    expect(fixedNs.exists()).toBe(true);
    expect(fixedNs.text()).toBe("debug-ns");
  });

  it("renders editable namespace input when isNamespaceEditable is true", () => {
    const wrapper = factory({
      canSelectNamespace: true,
      isNamespaceEditable: true,
    });
    expect(wrapper.find('[data-testid="namespace-input"]').exists()).toBe(true);
  });

  it("renders approval info when approval is required", () => {
    const wrapper = factory({
      approvalInfo: { required: true, approverGroups: ["team-leads"] },
    });
    expect(wrapper.text()).toContain("requires approval");
  });

  it("does not render extra variables section when hasExtraDeployVariables is false", () => {
    const wrapper = factory({ hasExtraDeployVariables: false });
    expect(wrapper.find('[data-testid="extra-variables-section"]').exists()).toBe(false);
  });

  it("renders extra variables section when hasExtraDeployVariables is true", () => {
    const wrapper = factory({
      hasExtraDeployVariables: true,
      extraDeployVariables: [{ name: "var1", displayName: "Var 1", inputType: "text" }],
    });
    expect(wrapper.find('[data-testid="extra-variables-section"]').exists()).toBe(true);
  });

  it("renders schedule checkbox", () => {
    const wrapper = factory();
    expect(wrapper.find('[data-testid="schedule-checkbox"]').exists()).toBe(true);
  });

  it("shows scheduled time input when useScheduledStart is true", () => {
    const wrapper = factory({ useScheduledStart: true });
    expect(wrapper.find('[data-testid="schedule-time-input"]').exists()).toBe(true);
  });

  it("hides scheduled time input when useScheduledStart is false", () => {
    const wrapper = factory({ useScheduledStart: false });
    expect(wrapper.find('[data-testid="schedule-time-input"]').exists()).toBe(false);
  });
});
