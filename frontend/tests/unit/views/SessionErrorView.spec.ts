/**
 * Tests for SessionErrorView component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import SessionErrorView from "@/views/SessionErrorView.vue";

// Mock Scale components
const scaleStubs = {
  "scale-icon-action-circle-close": { template: "<span></span>" },
  "scale-notification": { template: "<div><slot /></div>", props: ["variant", "opened"] },
  "scale-button": {
    template: '<button @click="$emit(\'click\')"><slot /><slot name="icon-before" /></button>',
    props: ["variant"],
  },
  "scale-icon-home": { template: "<span></span>" },
};

describe("SessionErrorView", () => {
  const createWrapper = async (path: string) => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/", name: "home", component: { template: "<div>Home</div>" } },
        { path: "/sessions", name: "sessions", component: { template: "<div>Sessions</div>" } },
        { path: "/session", name: "session-error-base", component: SessionErrorView },
        { path: "/session/:name", name: "session-error-name", component: SessionErrorView },
      ],
    });

    await router.push(path);
    await router.isReady();

    return mount(SessionErrorView, {
      global: {
        plugins: [router],
        stubs: scaleStubs,
      },
    });
  };

  describe("Error Messages", () => {
    it("shows generic error for /session path", async () => {
      const wrapper = await createWrapper("/session");
      expect(wrapper.text()).toContain("Invalid session URL");
      expect(wrapper.text()).toContain("valid session approval link");
    });

    it("shows incomplete URL error for /session/:name without /approve", async () => {
      const wrapper = await createWrapper("/session/my-session-123");
      expect(wrapper.text()).toContain("Incomplete session URL");
      expect(wrapper.text()).toContain("my-session-123");
    });
  });

  describe("UI Elements", () => {
    it("displays error title", async () => {
      const wrapper = await createWrapper("/session");
      expect(wrapper.find(".error-title").text()).toBe("Invalid Session Link");
    });

    it("shows correct session URL format example", async () => {
      const wrapper = await createWrapper("/session");
      expect(wrapper.text()).toContain("/session/[session-name]/approve");
    });

    it("displays error notification", async () => {
      const wrapper = await createWrapper("/session");
      const notification = wrapper.find("scale-notification");
      expect(notification.exists()).toBe(true);
    });
  });

  describe("Navigation", () => {
    it("has action buttons", async () => {
      const wrapper = await createWrapper("/session");
      const buttons = wrapper.findAll("scale-button");
      expect(buttons.length).toBeGreaterThan(0);
    });
  });

  describe("Styling", () => {
    it("has proper container classes", async () => {
      const wrapper = await createWrapper("/session");
      expect(wrapper.find(".session-error-view").exists()).toBe(true);
      expect(wrapper.find(".error-container").exists()).toBe(true);
    });

    it("has error icon", async () => {
      const wrapper = await createWrapper("/session");
      expect(wrapper.find(".error-icon").exists()).toBe(true);
    });
  });
});
