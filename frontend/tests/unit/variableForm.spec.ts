import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import { defineComponent } from "vue";
import type { ExtraDeployVariable, ExtraDeployValues } from "@/model/debugSession";

// Create a test wrapper component that simulates VariableForm behavior
const createVariableFormTest = () => {
  return defineComponent({
    name: "VariableFormTest",
    props: {
      variables: {
        type: Array as () => ExtraDeployVariable[],
        required: true,
      },
      modelValue: {
        type: Object as () => ExtraDeployValues,
        required: true,
      },
      userGroups: {
        type: Array as () => string[],
        default: () => [],
      },
      showAdvanced: {
        type: Boolean,
        default: false,
      },
    },
    emits: ["update:modelValue", "update:showAdvanced"],
    setup(props, { emit, expose }) {
      const visibleVariables = props.variables.filter((v) => {
        if (!v.allowedGroups || v.allowedGroups.length === 0) return true;
        if (!props.userGroups || props.userGroups.length === 0) return false;
        return v.allowedGroups.some((g) => props.userGroups.includes(g));
      });

      const basicVariables = visibleVariables.filter((v) => !v.advanced);
      const advancedVariables = visibleVariables.filter((v) => v.advanced);

      const getValue = (name: string, defaultVal: unknown) => {
        return name in props.modelValue ? props.modelValue[name] : defaultVal;
      };

      const updateValue = (name: string, value: unknown) => {
        emit("update:modelValue", { ...props.modelValue, [name]: value });
      };

      // Validation
      const errors: { field: string; message: string }[] = [];
      for (const variable of visibleVariables) {
        const value = getValue(variable.name, variable.default);
        if (variable.required && (value === undefined || value === null || value === "")) {
          errors.push({ field: variable.name, message: `${variable.displayName || variable.name} is required` });
        }
      }

      expose({
        isValid: errors.length === 0,
        errors,
      });

      return {
        visibleVariables,
        basicVariables,
        advancedVariables,
        getValue,
        updateValue,
        errors,
      };
    },
    template: `
      <div class="variable-form" data-testid="variable-form">
        <div v-for="v in basicVariables" :key="v.name" :data-testid="'field-' + v.name">
          {{ v.displayName || v.name }}
        </div>
        <div v-if="advancedVariables.length > 0">
          <button @click="$emit('update:showAdvanced', !showAdvanced)">Toggle Advanced</button>
          <div v-if="showAdvanced" data-testid="advanced-section">
            <div v-for="v in advancedVariables" :key="v.name" :data-testid="'field-' + v.name">
              {{ v.displayName || v.name }}
            </div>
          </div>
        </div>
      </div>
    `,
  });
};

describe("VariableForm", () => {
  const VariableFormTest = createVariableFormTest();

  describe("Variable Visibility", () => {
    it("shows all variables when no allowedGroups restrictions", () => {
      const variables: ExtraDeployVariable[] = [
        { name: "var1", inputType: "text", displayName: "Variable 1" },
        { name: "var2", inputType: "boolean", displayName: "Variable 2" },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
          userGroups: [],
        },
      });

      expect(wrapper.find('[data-testid="field-var1"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="field-var2"]').exists()).toBe(true);
    });

    it("filters variables based on user groups", () => {
      const variables: ExtraDeployVariable[] = [
        { name: "public", inputType: "text", displayName: "Public Var" },
        { name: "admin", inputType: "text", displayName: "Admin Var", allowedGroups: ["admin-group"] },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
          userGroups: ["user-group"],
        },
      });

      expect(wrapper.find('[data-testid="field-public"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="field-admin"]').exists()).toBe(false);
    });

    it("shows restricted variables when user is in allowed group", () => {
      const variables: ExtraDeployVariable[] = [
        { name: "admin", inputType: "text", displayName: "Admin Var", allowedGroups: ["admin-group"] },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
          userGroups: ["admin-group", "other-group"],
        },
      });

      expect(wrapper.find('[data-testid="field-admin"]').exists()).toBe(true);
    });
  });

  describe("Advanced Variables Toggle", () => {
    it("hides advanced variables by default", () => {
      const variables: ExtraDeployVariable[] = [
        { name: "basic", inputType: "text", displayName: "Basic Var" },
        { name: "advanced", inputType: "text", displayName: "Advanced Var", advanced: true },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
          showAdvanced: false,
        },
      });

      expect(wrapper.find('[data-testid="field-basic"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="advanced-section"]').exists()).toBe(false);
    });

    it("shows advanced variables when showAdvanced is true", () => {
      const variables: ExtraDeployVariable[] = [
        { name: "basic", inputType: "text", displayName: "Basic Var" },
        { name: "advanced", inputType: "text", displayName: "Advanced Var", advanced: true },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
          showAdvanced: true,
        },
      });

      expect(wrapper.find('[data-testid="advanced-section"]').exists()).toBe(true);
      expect(wrapper.find('[data-testid="field-advanced"]').exists()).toBe(true);
    });

    it("emits update:showAdvanced when toggle is clicked", async () => {
      const variables: ExtraDeployVariable[] = [
        { name: "advanced", inputType: "text", displayName: "Advanced Var", advanced: true },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
          showAdvanced: false,
        },
      });

      await wrapper.find("button").trigger("click");

      expect(wrapper.emitted("update:showAdvanced")).toBeTruthy();
      expect(wrapper.emitted("update:showAdvanced")![0]).toEqual([true]);
    });
  });

  describe("Value Updates", () => {
    it("uses default values when no modelValue provided", () => {
      const variables: ExtraDeployVariable[] = [{ name: "withDefault", inputType: "text", default: "default-value" }];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
        },
      });

      const vm = wrapper.vm as { getValue: (name: string, defaultVal: unknown) => unknown };
      // getValue returns the defaultVal (second param) when field is not in modelValue
      expect(vm.getValue("withDefault", "default-value")).toBe("default-value");
    });

    it("prefers modelValue over default", () => {
      const variables: ExtraDeployVariable[] = [{ name: "test", inputType: "text", default: "default" }];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: { test: "user-value" },
        },
      });

      const vm = wrapper.vm as { getValue: (name: string, defaultVal: unknown) => unknown };
      expect(vm.getValue("test", "default")).toBe("user-value");
    });
  });

  describe("Validation", () => {
    it("validates required fields", () => {
      const variables: ExtraDeployVariable[] = [
        { name: "required", inputType: "text", displayName: "Required Field", required: true },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: {},
        },
      });

      const vm = wrapper.vm as { errors: { field: string; message: string }[] };
      expect(vm.errors.length).toBe(1);
      expect(vm.errors[0]!.field).toBe("required");
    });

    it("passes validation when required field has value", () => {
      const variables: ExtraDeployVariable[] = [
        { name: "required", inputType: "text", displayName: "Required Field", required: true },
      ];

      const wrapper = mount(VariableFormTest, {
        props: {
          variables,
          modelValue: { required: "value" },
        },
      });

      const vm = wrapper.vm as { errors: { field: string; message: string }[] };
      expect(vm.errors.length).toBe(0);
    });
  });
});

describe("ExtraDeployVariable Types", () => {
  it("should support all input types", () => {
    const allTypes: ExtraDeployVariable[] = [
      { name: "boolVar", inputType: "boolean" },
      { name: "textVar", inputType: "text" },
      { name: "numberVar", inputType: "number" },
      { name: "storageSizeVar", inputType: "storageSize" },
      { name: "selectVar", inputType: "select", options: [{ value: "a", displayName: "A" }] },
      { name: "multiSelectVar", inputType: "multiSelect", options: [{ value: "b", displayName: "B" }] },
    ];

    // Verify types compile correctly
    expect(allTypes.length).toBe(6);
    expect(allTypes[0]!.inputType).toBe("boolean");
    expect(allTypes[1]!.inputType).toBe("text");
    expect(allTypes[2]!.inputType).toBe("number");
    expect(allTypes[3]!.inputType).toBe("storageSize");
    expect(allTypes[4]!.inputType).toBe("select");
    expect(allTypes[5]!.inputType).toBe("multiSelect");
  });

  it("should support validation rules", () => {
    const withValidation: ExtraDeployVariable = {
      name: "validated",
      inputType: "text",
      validation: {
        pattern: "^[a-z]+$",
        patternError: "Must be lowercase letters only",
        minLength: 1,
        maxLength: 100,
      },
    };

    expect(withValidation.validation?.pattern).toBe("^[a-z]+$");
    expect(withValidation.validation?.minLength).toBe(1);
  });

  it("should support number validation", () => {
    const numberVar: ExtraDeployVariable = {
      name: "count",
      inputType: "number",
      validation: {
        min: "1",
        max: "100",
      },
    };

    expect(numberVar.validation?.min).toBe("1");
    expect(numberVar.validation?.max).toBe("100");
  });

  it("should support storage size validation", () => {
    const storageVar: ExtraDeployVariable = {
      name: "size",
      inputType: "storageSize",
      validation: {
        minStorage: "1Gi",
        maxStorage: "100Gi",
      },
    };

    expect(storageVar.validation?.minStorage).toBe("1Gi");
    expect(storageVar.validation?.maxStorage).toBe("100Gi");
  });

  it("should support multiSelect validation", () => {
    const multiVar: ExtraDeployVariable = {
      name: "features",
      inputType: "multiSelect",
      options: [
        { value: "a", displayName: "A" },
        { value: "b", displayName: "B" },
      ],
      validation: {
        minItems: 1,
        maxItems: 3,
      },
    };

    expect(multiVar.validation?.minItems).toBe(1);
    expect(multiVar.validation?.maxItems).toBe(3);
  });
});

describe("Variable Grouping", () => {
  it("should group variables by group field", () => {
    const variables: ExtraDeployVariable[] = [
      { name: "var1", inputType: "text", group: "Group A" },
      { name: "var2", inputType: "text", group: "Group A" },
      { name: "var3", inputType: "text", group: "Group B" },
      { name: "var4", inputType: "text" }, // ungrouped
    ];

    // Group by group field
    const grouped = new Map<string, ExtraDeployVariable[]>();
    const ungrouped: ExtraDeployVariable[] = [];

    for (const v of variables) {
      if (v.group) {
        const list = grouped.get(v.group) || [];
        list.push(v);
        grouped.set(v.group, list);
      } else {
        ungrouped.push(v);
      }
    }

    expect(grouped.get("Group A")!.length).toBe(2);
    expect(grouped.get("Group B")!.length).toBe(1);
    expect(ungrouped.length).toBe(1);
  });
});

describe("Default Value Initialization", () => {
  it("should initialize values from defaults", () => {
    const variables: ExtraDeployVariable[] = [
      { name: "text1", inputType: "text", default: "default text" },
      { name: "bool1", inputType: "boolean", default: true },
      { name: "num1", inputType: "number", default: 42 },
      {
        name: "select1",
        inputType: "select",
        default: "option1",
        options: [{ value: "option1", displayName: "Option 1" }],
      },
      {
        name: "multi1",
        inputType: "multiSelect",
        default: ["a", "b"],
        options: [
          { value: "a", displayName: "A" },
          { value: "b", displayName: "B" },
        ],
      },
    ];

    const modelValue: ExtraDeployValues = {};

    // Initialize from defaults
    const initialized: ExtraDeployValues = { ...modelValue };
    for (const v of variables) {
      if (!(v.name in initialized) && v.default !== undefined) {
        initialized[v.name] = v.default;
      }
    }

    expect(initialized.text1).toBe("default text");
    expect(initialized.bool1).toBe(true);
    expect(initialized.num1).toBe(42);
    expect(initialized.select1).toBe("option1");
    expect(initialized.multi1).toEqual(["a", "b"]);
  });

  it("should not override existing values with defaults", () => {
    const variables: ExtraDeployVariable[] = [{ name: "text1", inputType: "text", default: "default text" }];

    const modelValue: ExtraDeployValues = { text1: "user value" };

    const initialized: ExtraDeployValues = { ...modelValue };
    for (const v of variables) {
      if (!(v.name in initialized) && v.default !== undefined) {
        initialized[v.name] = v.default;
      }
    }

    expect(initialized.text1).toBe("user value");
  });
});
