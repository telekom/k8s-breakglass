// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @vitest-environment jsdom
 */

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import MotdNotice from "@/components/common/MotdNotice.vue";
import { debugPodExecCommand, effectiveSessionMotd } from "@/utils/motd";
import type { DebugSession } from "@/model/debugSession";

const stubs = { "scale-notification": { template: "<div><slot name='text'/></div>" } };

describe("MotdNotice", () => {
  it("renders the message as text and links an https runbook", () => {
    const wrapper = mount(MotdNotice, {
      props: { motd: { message: "Purpose: test\n<b>not html</b>", runbookURL: "https://example.com/rb#section" } },
      global: { stubs },
    });
    expect(wrapper.find("[data-testid='motd-message']").text()).toContain("<b>not html</b>");
    expect(wrapper.find("b").exists()).toBe(false);
    const link = wrapper.find("[data-testid='motd-runbook-link']");
    expect(link.attributes("href")).toBe("https://example.com/rb#section");
    expect(link.attributes("rel")).toBe("noopener noreferrer");
  });

  it("does not link non-https runbook URLs", () => {
    const wrapper = mount(MotdNotice, {
      props: { motd: { message: "x", runbookURL: "javascript:alert(1)" } },
      global: { stubs },
    });
    expect(wrapper.find("[data-testid='motd-runbook-link']").exists()).toBe(false);
  });

  it("renders nothing without a message", () => {
    const wrapper = mount(MotdNotice, { props: { motd: null }, global: { stubs } });
    expect(wrapper.find("[data-testid='motd-notice']").exists()).toBe(false);
  });
});

describe("motd utilities", () => {
  const session = (status: DebugSession["status"]): DebugSession =>
    ({ metadata: { name: "s" }, spec: { templateRef: "t", cluster: "c", requestedBy: "u" }, status }) as DebugSession;

  it("prefers the binding motd over the template motd", () => {
    const template = { message: "template" };
    const binding = { message: "binding" };
    expect(
      effectiveSessionMotd(
        session({ state: "Active", resolvedTemplate: { motd: template } } as DebugSession["status"]),
      ),
    ).toBe(template);
    expect(
      effectiveSessionMotd(
        session({
          state: "Active",
          resolvedTemplate: { motd: template },
          resolvedBindingSpec: { motd: binding },
        } as DebugSession["status"]),
      ),
    ).toBe(binding);
    expect(effectiveSessionMotd(null)).toBeUndefined();
  });

  it("offers a plain interactive shell; the mounted hook prints the motd", () => {
    expect(debugPodExecCommand({ name: "pod", namespace: "ns" })).toBe("kubectl exec -it pod -n ns -- /bin/sh");
  });
});
