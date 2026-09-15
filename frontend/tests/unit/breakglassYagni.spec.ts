// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { beforeEach, describe, expect, it, vi } from "vitest";
import BreakglassService from "@/services/breakglass";

const { client } = vi.hoisted(() => ({ client: { get: vi.fn(), post: vi.fn() } }));
vi.mock("@/services/httpClient", () => ({ createAuthenticatedApiClient: () => client }));
vi.mock("@/services/logger", () => ({ debug: vi.fn(), handleAxiosError: vi.fn() }));

type Auth = ConstructorParameters<typeof BreakglassService>[0];

describe("BreakglassService enrichment boundaries", () => {
  let service: BreakglassService;

  beforeEach(() => {
    client.get.mockReset();
    client.post.mockReset();
    service = new BreakglassService({} as Auth);
  });

  it.each([{ data: [] }, { data: { items: [] } }, { data: null }, { data: {} }])(
    "does not fetch escalations for an empty response: $data",
    async ({ data }) => {
      client.get.mockResolvedValueOnce({ data });
      expect(await service.fetchPendingSessionsForApproval()).toEqual([]);
      expect(client.get).toHaveBeenCalledTimes(1);
    },
  );

  it("preserves backend reason precedence and normalizes stored reasons without enrichment", async () => {
    const top = { mandatory: true, description: "Backend" };
    const stored = { mandatory: false, description: "Stored" };
    const data = [
      { metadata: { name: "top" }, approvalReason: top, spec: { approvalReasonConfig: stored } },
      { metadata: { name: "stored" }, spec: { approvalReasonConfig: stored } },
    ];
    client.get.mockResolvedValueOnce({ data });
    expect(await service.fetchPendingSessionsForApproval()).toEqual([data[0], { ...data[1], approvalReason: stored }]);
    expect(data[1]).not.toHaveProperty("approvalReason");
    expect(client.get).toHaveBeenCalledTimes(1);
  });

  it("enriches legacy records by cluster and group without overwriting configured records", async () => {
    const reason = { mandatory: true, description: "Review required" };
    const configured = { metadata: { name: "configured" }, spec: { approvalReasonConfig: reason } };
    const legacy = { metadata: { name: "legacy" }, spec: { cluster: "c1", grantedGroup: "ops" } };
    const differentCluster = { metadata: { name: "other" }, spec: { cluster: "c2", grantedGroup: "ops" } };
    client.get.mockResolvedValueOnce({ data: [legacy, configured, differentCluster] }).mockResolvedValueOnce({
      data: [{ spec: { allowed: { clusters: ["c1"] }, escalatedGroup: "ops", approvalReason: reason } }],
    });
    expect(await service.fetchPendingSessionsForApproval()).toEqual([
      { ...legacy, approvalReason: reason },
      { ...configured, approvalReason: reason },
      differentCluster,
    ]);
    expect(legacy).not.toHaveProperty("approvalReason");
    expect(client.get).toHaveBeenCalledTimes(2);
    expect(client.get).toHaveBeenLastCalledWith("/breakglassEscalations");
  });

  it("keeps legacy records when escalation enrichment fails", async () => {
    const legacy = { metadata: { name: "legacy" }, spec: { cluster: "c1", grantedGroup: "ops" } };
    client.get.mockResolvedValueOnce({ data: [legacy] }).mockRejectedValueOnce(new Error("unavailable"));
    expect(await service.fetchPendingSessionsForApproval()).toEqual([legacy]);
  });

  it("propagates failure to load pending sessions", async () => {
    const error = new Error("pending request failed");
    client.get.mockRejectedValueOnce(error);
    await expect(service.fetchPendingSessionsForApproval()).rejects.toBe(error);
    expect(client.get).toHaveBeenCalledTimes(1);
  });
});
