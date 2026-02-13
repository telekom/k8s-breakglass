/**
 * Tests for NotFoundView component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect } from "vitest";
import { mount, RouterLinkStub } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import NotFoundView from "@/views/NotFoundView.vue";

describe("NotFoundView", () => {
  const createWrapper = () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/", name: "home", component: { template: "<div>Home</div>" } },
        { path: "/not-found", name: "not-found", component: NotFoundView },
      ],
    });

    return mount(NotFoundView, {
      global: {
        plugins: [router],
        stubs: {
          RouterLink: RouterLinkStub,
        },
      },
    });
  };

  it("renders the not found page", () => {
    const wrapper = createWrapper();
    expect(wrapper.find(".not-found").exists()).toBe(true);
  });

  it("displays 'Page not found' heading", () => {
    const wrapper = createWrapper();
    expect(wrapper.find("h1").text()).toBe("Page not found");
  });

  it("displays helpful message to user", () => {
    const wrapper = createWrapper();
    const paragraph = wrapper.find("p");
    // Note: The apostrophe may be a curly quote (') or straight quote (')
    expect(paragraph.text()).toMatch(/doesn.t exist/);
    expect(paragraph.text()).toContain("dashboard");
  });

  it("contains a link to the dashboard", () => {
    const wrapper = createWrapper();
    const link = wrapper.findComponent(RouterLinkStub);
    expect(link.exists()).toBe(true);
    expect(link.props("to")).toBe("/");
  });

  it("link text says 'Return to dashboard'", () => {
    const wrapper = createWrapper();
    const link = wrapper.find(".not-found__cta");
    expect(link.text()).toBe("Return to dashboard");
  });

  it("has proper styling classes", () => {
    const wrapper = createWrapper();
    expect(wrapper.find(".not-found__card").exists()).toBe(true);
  });
});
