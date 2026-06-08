/**
 * Tests for NotFoundView component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi } from "vitest";
import { mount } from "@vue/test-utils";
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
    const pushSpy = vi.spyOn(router, "push").mockResolvedValue(undefined);

    const wrapper = mount(NotFoundView, {
      global: {
        plugins: [router],
      },
    });

    return { wrapper, pushSpy };
  };

  it("renders the not found page", () => {
    const { wrapper } = createWrapper();
    expect(wrapper.find(".not-found").exists()).toBe(true);
  });

  it("displays 'Page not found' heading", () => {
    const { wrapper } = createWrapper();
    expect(wrapper.find("h1").text()).toBe("Page not found");
  });

  it("displays helpful message to user", () => {
    const { wrapper } = createWrapper();
    const paragraph = wrapper.find("p");
    // Note: The apostrophe may be a curly quote (') or straight quote (')
    expect(paragraph.text()).toMatch(/doesn.t exist/);
    expect(paragraph.text()).toContain("dashboard");
  });

  it("navigates to the dashboard with router push", async () => {
    const { wrapper, pushSpy } = createWrapper();
    const button = wrapper.find("scale-button");
    expect(button.exists()).toBe(true);
    expect(button.attributes("href")).toBeUndefined();
    expect(button.attributes("role")).toBe("link");
    expect(button.attributes("variant")).toBe("primary");
    await button.trigger("click");
    expect(pushSpy).toHaveBeenCalledWith("/");
  });

  it("supports keyboard navigation from the link role", async () => {
    const { wrapper, pushSpy } = createWrapper();
    const button = wrapper.find("scale-button");

    await button.trigger("keydown", { key: "Enter" });
    expect(pushSpy).toHaveBeenCalledWith("/");
  });

  it("button text says 'Return to dashboard'", () => {
    const { wrapper } = createWrapper();
    const button = wrapper.find("scale-button");
    expect(button.text()).toBe("Return to dashboard");
  });

  it("has proper styling classes", () => {
    const { wrapper } = createWrapper();
    expect(wrapper.find(".not-found__card").exists()).toBe(true);
  });
});
