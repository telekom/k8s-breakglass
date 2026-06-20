/**
 * Tests for NotFoundView component
 *
 * @vitest-environment jsdom
 */

import { afterEach, describe, it, expect, vi } from "vitest";
import { mount } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import NotFoundView from "@/views/NotFoundView.vue";

describe("NotFoundView", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  const createWrapper = async () => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/", name: "home", component: { template: "<div>Home</div>" } },
        { path: "/not-found", name: "not-found", component: NotFoundView },
      ],
    });
    await router.push("/not-found");
    await router.isReady();
    const pushSpy = vi.spyOn(router, "push").mockResolvedValue(undefined);

    const wrapper = mount(NotFoundView, {
      global: {
        plugins: [router],
      },
    });
    pushSpy.mockClear();

    return { wrapper, pushSpy };
  };

  it("renders the not found page", async () => {
    const { wrapper } = await createWrapper();
    expect(wrapper.find(".not-found").exists()).toBe(true);
  });

  it("displays 'Page not found' heading", async () => {
    const { wrapper } = await createWrapper();
    expect(wrapper.find("h1").text()).toBe("Page not found");
  });

  it("displays helpful message to user", async () => {
    const { wrapper } = await createWrapper();
    const paragraph = wrapper.find("p");
    // Note: The apostrophe may be a curly quote (') or straight quote (')
    expect(paragraph.text()).toMatch(/doesn.t exist/);
    expect(paragraph.text()).toContain("dashboard");
  });

  it("navigates to the dashboard with router push", async () => {
    const { wrapper, pushSpy } = await createWrapper();
    const link = wrapper.find("a.not-found__cta");
    expect(link.exists()).toBe(true);
    expect(link.attributes("href")).toBe("/");
    await link.trigger("click");
    expect(pushSpy).toHaveBeenCalledWith("/");
  });

  it("link text says 'Return to dashboard'", async () => {
    const { wrapper } = await createWrapper();
    const link = wrapper.find("a.not-found__cta");
    expect(link.text()).toBe("Return to dashboard");
  });

  it("has proper styling classes", async () => {
    const { wrapper } = await createWrapper();
    expect(wrapper.find(".not-found__card").exists()).toBe(true);
  });
});
