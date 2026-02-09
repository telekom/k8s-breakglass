/**
 * Tests for VariableForm component
 *
 * Covers all input types, validation, group filtering, advanced toggle,
 * and exposed isValid state.
 */

import { describe, it, expect } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import VariableForm from "@/components/debug-session/VariableForm.vue";
import type { ExtraDeployVariable, ExtraDeployValues } from "@/model/debugSession";

// Stub Scale components to make tests work without real web components
const scaleStubs = {
  "scale-checkbox": {
    template: '<input type="checkbox" :checked="checked" @change="$emit(\'scale-change\', $event)" />',
    props: ["checked", "label", "helperText"],
  },
  "scale-text-field": {
    template:
      '<input type="text" :value="value" :helper-text="helperText" @input="$emit(\'scale-input\', $event)" @change="$emit(\'scale-change\', $event)" />',
    props: [
      "value",
      "type",
      "label",
      "helperText",
      "required",
      "invalid",
      "helperTextInvalid",
      "min",
      "max",
      "placeholder",
    ],
  },
  "scale-dropdown-select": {
    template: '<select :value="value" @change="$emit(\'scale-change\', $event)"><slot /></select>',
    props: ["value", "label", "helperText", "required", "invalid"],
  },
  "scale-dropdown-select-item": {
    template: '<option :value="value"><slot /></option>',
    props: ["value"],
  },
  "scale-button": {
    template: "<button @click=\"$emit('click')\"><slot /></button>",
    props: ["variant", "size"],
  },
  "scale-icon-navigation-collapse-down": { template: "<span />" },
  "scale-icon-navigation-collapse-up": { template: "<span />" },
};

function mountForm(
  variables: ExtraDeployVariable[],
  modelValue: ExtraDeployValues = {},
  opts: { userGroups?: string[]; showAdvanced?: boolean } = {},
) {
  return mount(VariableForm, {
    props: {
      variables,
      modelValue,
      userGroups: opts.userGroups,
      showAdvanced: opts.showAdvanced,
    },
    global: { stubs: scaleStubs },
  });
}

// -------------------------------------------------------------------
// Helpers to build variable fixtures
// -------------------------------------------------------------------
function textVar(overrides: Partial<ExtraDeployVariable> = {}): ExtraDeployVariable {
  return {
    name: "myText",
    displayName: "My Text",
    description: "A text input",
    inputType: "text",
    ...overrides,
  };
}

function boolVar(overrides: Partial<ExtraDeployVariable> = {}): ExtraDeployVariable {
  return {
    name: "myBool",
    displayName: "My Boolean",
    inputType: "boolean",
    default: false,
    ...overrides,
  };
}

function numberVar(overrides: Partial<ExtraDeployVariable> = {}): ExtraDeployVariable {
  return {
    name: "myNum",
    displayName: "My Number",
    inputType: "number",
    ...overrides,
  };
}

function selectVar(overrides: Partial<ExtraDeployVariable> = {}): ExtraDeployVariable {
  return {
    name: "mySelect",
    displayName: "My Select",
    inputType: "select",
    options: [
      { value: "a", displayName: "Option A" },
      { value: "b", displayName: "Option B" },
    ],
    ...overrides,
  };
}

function storageSizeVar(overrides: Partial<ExtraDeployVariable> = {}): ExtraDeployVariable {
  return {
    name: "myStorage",
    displayName: "Storage Size",
    inputType: "storageSize",
    default: "10Gi",
    ...overrides,
  };
}

function multiSelectVar(overrides: Partial<ExtraDeployVariable> = {}): ExtraDeployVariable {
  return {
    name: "myMulti",
    displayName: "Multi Select",
    inputType: "multiSelect",
    options: [
      { value: "x", displayName: "X" },
      { value: "y", displayName: "Y" },
      { value: "z", displayName: "Z" },
    ],
    ...overrides,
  };
}

// ===================================================================
// Test suites
// ===================================================================
describe("VariableForm", () => {
  // -----------------------------------------------------------------
  // Rendering
  // -----------------------------------------------------------------
  describe("rendering", () => {
    it("renders nothing when no visible variables", () => {
      const wrapper = mountForm([]);
      expect(wrapper.find('[data-testid="variable-form"]').exists()).toBe(false);
    });

    it("renders a variable-form container when variables exist", () => {
      const wrapper = mountForm([textVar()]);
      expect(wrapper.find('[data-testid="variable-form"]').exists()).toBe(true);
    });

    it("renders text input field", () => {
      const wrapper = mountForm([textVar()]);
      expect(wrapper.find('[data-testid="variable-field-myText"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="input-myText"]').exists()).toBe(true);
    });

    it("renders boolean checkbox", () => {
      const wrapper = mountForm([boolVar()]);
      expect(wrapper.find('[data-testid="variable-field-myBool"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="input-myBool"]').exists()).toBe(true);
    });

    it("renders number input field", () => {
      const wrapper = mountForm([numberVar()]);
      expect(wrapper.find('[data-testid="variable-field-myNum"]').exists()).toBe(true);
    });

    it("renders select dropdown", () => {
      const wrapper = mountForm([selectVar()]);
      const field = wrapper.find('[data-testid="variable-field-mySelect"]');
      expect(field.exists()).toBe(true);
      // Options are rendered (scale-dropdown-select-item is a custom element, not <option>)
      const options = field.findAll("scale-dropdown-select-item");
      expect(options).toHaveLength(2);
    });

    it("renders storageSize input", () => {
      const wrapper = mountForm([storageSizeVar()]);
      expect(wrapper.find('[data-testid="variable-field-myStorage"]').exists()).toBe(true);
    });

    it("renders multiSelect checkboxes", () => {
      const wrapper = mountForm([multiSelectVar()]);
      const field = wrapper.find('[data-testid="variable-field-myMulti"]');
      expect(field.exists()).toBe(true);
      // 3 checkbox options (scale-checkbox is a custom element, not <input>)
      const checkboxes = field.findAll("scale-checkbox");
      expect(checkboxes).toHaveLength(3);
    });

    it("renders all input types together", () => {
      const wrapper = mountForm([textVar(), boolVar(), numberVar(), selectVar(), storageSizeVar(), multiSelectVar()]);
      expect(wrapper.findAll(".variable-field")).toHaveLength(6);
    });
  });

  // -----------------------------------------------------------------
  // Default values
  // -----------------------------------------------------------------
  describe("default values", () => {
    it("initializes values from defaults on mount", async () => {
      const wrapper = mountForm(
        [textVar({ default: "hello" }), boolVar({ default: true }), numberVar({ default: 42 })],
        {},
      );
      await flushPromises();

      // The component emits update:modelValue with defaults
      const emitted = wrapper.emitted("update:modelValue");
      expect(emitted).toBeTruthy();
      const lastEmit = emitted![emitted!.length - 1]![0] as ExtraDeployValues;
      expect(lastEmit.myText).toBe("hello");
      expect(lastEmit.myBool).toBe(true);
      expect(lastEmit.myNum).toBe(42);
    });

    it("does not overwrite existing values with defaults", async () => {
      const wrapper = mountForm([textVar({ default: "hello" })], { myText: "existing" });
      await flushPromises();

      // The existing value should be preserved
      const emitted = wrapper.emitted("update:modelValue");
      if (emitted) {
        const lastEmit = emitted[emitted.length - 1]![0] as ExtraDeployValues;
        expect(lastEmit.myText).toBe("existing");
      }
    });
  });

  // -----------------------------------------------------------------
  // Group filtering (allowedGroups)
  // -----------------------------------------------------------------
  describe("allowedGroups filtering", () => {
    it("hides variables when user is not in allowedGroups", () => {
      const vars = [textVar({ allowedGroups: ["admin-team"] })];
      const wrapper = mountForm(vars, {}, { userGroups: ["dev-team"] });
      expect(wrapper.find('[data-testid="variable-field-myText"]').exists()).toBe(false);
    });

    it("shows variables when user is in allowedGroups", () => {
      const vars = [textVar({ allowedGroups: ["admin-team"] })];
      const wrapper = mountForm(vars, {}, { userGroups: ["admin-team", "dev-team"] });
      expect(wrapper.find('[data-testid="variable-field-myText"]').exists()).toBe(true);
    });

    it("shows variables with no allowedGroups to everyone", () => {
      const vars = [textVar({ allowedGroups: undefined })];
      const wrapper = mountForm(vars, {}, { userGroups: [] });
      expect(wrapper.find('[data-testid="variable-field-myText"]').exists()).toBe(true);
    });

    it("hides group-restricted variables when userGroups is undefined", () => {
      const vars = [textVar({ allowedGroups: ["admin-team"] })];
      const wrapper = mountForm(vars, {}, { userGroups: undefined });
      expect(wrapper.find('[data-testid="variable-field-myText"]').exists()).toBe(false);
    });
  });

  // -----------------------------------------------------------------
  // Variable grouping (group field)
  // -----------------------------------------------------------------
  describe("variable grouping", () => {
    it("groups variables by their group field", () => {
      const vars = [
        textVar({ name: "v1", group: "Network" }),
        textVar({ name: "v2", group: "Network" }),
        textVar({ name: "v3" }), // ungrouped → "General"
      ];
      const wrapper = mountForm(vars);

      // Should have 2 groups: General and Network
      const groups = wrapper.findAll(".variable-group");
      expect(groups.length).toBeGreaterThanOrEqual(2);
    });

    it("shows group title when multiple groups exist", () => {
      const vars = [textVar({ name: "v1", group: "Security" }), textVar({ name: "v2" })];
      const wrapper = mountForm(vars);

      const titles = wrapper.findAll(".group-title");
      expect(titles.length).toBeGreaterThanOrEqual(1);
    });
  });

  // -----------------------------------------------------------------
  // Advanced variables toggle
  // -----------------------------------------------------------------
  describe("advanced variables", () => {
    it("hides advanced variables by default", () => {
      const vars = [textVar({ name: "basic" }), textVar({ name: "adv", advanced: true })];
      const wrapper = mountForm(vars);

      expect(wrapper.find('[data-testid="variable-field-basic"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="variable-field-adv"]').exists()).toBe(false);
    });

    it("shows advanced toggle button when advanced variables exist", () => {
      const vars = [textVar({ name: "adv", advanced: true })];
      const wrapper = mountForm(vars);

      expect(wrapper.find('[data-testid="toggle-advanced"]').exists()).toBe(true);
    });

    it("does not show advanced toggle when no advanced variables", () => {
      const vars = [textVar()];
      const wrapper = mountForm(vars);

      expect(wrapper.find('[data-testid="toggle-advanced"]').exists()).toBe(false);
    });

    it("shows advanced variables when showAdvanced prop is true", () => {
      const vars = [textVar({ name: "adv", advanced: true })];
      const wrapper = mountForm(vars, {}, { showAdvanced: true });

      expect(wrapper.find('[data-testid="advanced-section"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="variable-field-adv"]').exists()).toBe(true);
    });

    it("toggles advanced section on button click", async () => {
      const vars = [textVar({ name: "adv", advanced: true })];
      const wrapper = mountForm(vars);

      expect(wrapper.find('[data-testid="advanced-section"]').exists()).toBe(false);

      await wrapper.find('[data-testid="toggle-advanced"]').trigger("click");

      expect(wrapper.find('[data-testid="advanced-section"]').exists()).toBe(true);
    });
  });

  // -----------------------------------------------------------------
  // Validation
  // -----------------------------------------------------------------
  describe("validation", () => {
    it("exposes isValid as true when no required fields are missing", () => {
      const vars = [textVar({ required: false })];
      const wrapper = mountForm(vars);

      const exposed = wrapper.vm as unknown as { isValid: boolean };
      expect(exposed.isValid).toBe(true);
    });

    it("exposes isValid as false when required field is empty", () => {
      const vars = [textVar({ required: true })];
      const wrapper = mountForm(vars, {}); // no value provided

      const exposed = wrapper.vm as unknown as { isValid: boolean };
      expect(exposed.isValid).toBe(false);
    });

    it("exposes isValid as true when required field has a value", () => {
      const vars = [textVar({ required: true })];
      const wrapper = mountForm(vars, { myText: "filled" });

      const exposed = wrapper.vm as unknown as { isValid: boolean };
      expect(exposed.isValid).toBe(true);
    });

    it("validates text min/max length", () => {
      const vars = [textVar({ validation: { minLength: 5, maxLength: 10 } })];
      const wrapper = mountForm(vars, { myText: "hi" }); // too short

      const exposed = wrapper.vm as unknown as { isValid: boolean; errors: { field: string; message: string }[] };
      expect(exposed.isValid).toBe(false);
      expect(exposed.errors.some((e: { message: string }) => e.message.includes("at least 5"))).toBe(true);
    });

    it("validates text pattern", () => {
      const vars = [
        textVar({
          validation: {
            pattern: "^[a-z]+$",
            patternError: "Must be lowercase",
          },
        }),
      ];
      const wrapper = mountForm(vars, { myText: "UPPER" });

      const exposed = wrapper.vm as unknown as { isValid: boolean; errors: { field: string; message: string }[] };
      expect(exposed.isValid).toBe(false);
      expect(exposed.errors.some((e: { message: string }) => e.message === "Must be lowercase")).toBe(true);
    });

    it("validates number min/max", () => {
      const vars = [numberVar({ validation: { min: "1", max: "50" } })];
      const wrapper = mountForm(vars, { myNum: 100 });

      const exposed = wrapper.vm as unknown as { isValid: boolean };
      expect(exposed.isValid).toBe(false);
    });

    it("validates multiSelect minItems", () => {
      const vars = [multiSelectVar({ required: true, validation: { minItems: 2 } })];
      const wrapper = mountForm(vars, { myMulti: ["x"] }); // only 1 selected, need 2

      const exposed = wrapper.vm as unknown as { isValid: boolean; errors: { field: string; message: string }[] };
      expect(exposed.isValid).toBe(false);
      expect(exposed.errors.some((e: { message: string }) => e.message.includes("at least 2"))).toBe(true);
    });

    it("passes validation when all rules are satisfied", () => {
      const vars = [
        textVar({ required: true, validation: { minLength: 3, maxLength: 20, pattern: "^[a-z-]+$" } }),
        numberVar({ validation: { min: "1", max: "100" } }),
        selectVar({ required: true }),
      ];
      const wrapper = mountForm(vars, { myText: "hello-world", myNum: 50, mySelect: "a" });

      const exposed = wrapper.vm as unknown as { isValid: boolean };
      expect(exposed.isValid).toBe(true);
    });
  });

  // -----------------------------------------------------------------
  // Event emission
  // -----------------------------------------------------------------
  describe("events", () => {
    it("emits update:modelValue when text input changes", async () => {
      const wrapper = mountForm([textVar()], { myText: "" });

      // scale-text-field is a custom element; dispatch a real CustomEvent with detail
      const input = wrapper.find('[data-testid="input-myText"]');
      const event = new CustomEvent("scale-input", {
        bubbles: true,
        detail: { value: "new-value" },
      });
      Object.defineProperty(event, "target", { value: { value: "new-value" } });
      input.element.dispatchEvent(event);
      await flushPromises();

      const emitted = wrapper.emitted("update:modelValue");
      expect(emitted).toBeTruthy();
    });

    it("emits update:showAdvanced when toggle is clicked", async () => {
      const vars = [textVar({ name: "adv", advanced: true })];
      const wrapper = mountForm(vars);

      await wrapper.find('[data-testid="toggle-advanced"]').trigger("click");

      const emitted = wrapper.emitted("update:showAdvanced");
      expect(emitted).toBeTruthy();
      expect(emitted![0]![0]).toBe(true);
    });
  });

  describe("constraint hints in helper text", () => {
    it("shows validation constraints in helper text for text fields", () => {
      const vars: ExtraDeployVariable[] = [
        {
          name: "username",
          displayName: "Username",
          inputType: "text",
          required: true,
          description: "Enter your username",
          validation: { minLength: 3, maxLength: 20 },
        },
      ];
      const wrapper = mountForm(vars);
      const input = wrapper.find('[data-testid="input-username"]');
      // The helper text should now contain both description and constraint hints
      expect(input.attributes("helper-text")).toContain("Enter your username");
      expect(input.attributes("helper-text")).toContain("Required");
      expect(input.attributes("helper-text")).toContain("3–20 chars");
    });

    it("shows pattern validation in helper text", () => {
      const vars: ExtraDeployVariable[] = [
        {
          name: "email",
          displayName: "Email",
          inputType: "text",
          required: false,
          validation: { pattern: "^[a-z@.]+$", patternError: "lowercase email only" },
        },
      ];
      const wrapper = mountForm(vars);
      const input = wrapper.find('[data-testid="input-email"]');
      expect(input.attributes("helper-text")).toContain("lowercase email only");
    });

    it("shows number range constraints in helper text", () => {
      const vars: ExtraDeployVariable[] = [
        {
          name: "replicas",
          displayName: "Replicas",
          inputType: "number",
          required: true,
          description: "Number of replicas",
          validation: { min: "1", max: "10" },
        },
      ];
      const wrapper = mountForm(vars);
      const input = wrapper.find('[data-testid="input-replicas"]');
      expect(input.attributes("helper-text")).toContain("Range: 1–10");
      expect(input.attributes("helper-text")).toContain("Required");
    });

    it("shows only description when no validation rules", () => {
      const vars: ExtraDeployVariable[] = [
        {
          name: "comment",
          displayName: "Comment",
          inputType: "text",
          required: false,
          description: "Optional comment",
        },
      ];
      const wrapper = mountForm(vars);
      const input = wrapper.find('[data-testid="input-comment"]');
      expect(input.attributes("helper-text")).toBe("Optional comment");
    });

    it("shows empty helper text when no description and no validation", () => {
      const vars: ExtraDeployVariable[] = [
        {
          name: "bare",
          displayName: "Bare",
          inputType: "text",
          required: false,
        },
      ];
      const wrapper = mountForm(vars);
      const input = wrapper.find('[data-testid="input-bare"]');
      expect(input.attributes("helper-text")).toBe("");
    });

    it("shows multiSelect item constraints in description", () => {
      const vars: ExtraDeployVariable[] = [
        {
          name: "features",
          displayName: "Features",
          inputType: "multiSelect",
          required: true,
          description: "Select features",
          validation: { minItems: 1, maxItems: 3 },
          options: [
            { value: "a", displayName: "A" },
            { value: "b", displayName: "B" },
          ],
        },
      ];
      const wrapper = mountForm(vars);
      const desc = wrapper.find(".multi-select-description");
      expect(desc.exists()).toBe(true);
      expect(desc.text()).toContain("Select 1–3 items");
    });
  });
});
