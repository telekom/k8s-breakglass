import type { SessionCR } from "@/model/breakglass";
import { describeApprover, wasApprovedBy } from "@/utils/sessionFilters";

describe("sessionFilters", () => {
  const baseSession: SessionCR = {
    metadata: { name: "session-1" },
    spec: { grantedGroup: "grp", cluster: "c1" },
    status: { state: "approved" },
  } as SessionCR;

  it("detects approver via single approver field", () => {
    const session = {
      ...baseSession,
      status: { ...baseSession.status, approver: "approver@example.com" },
    } as SessionCR;

    expect(wasApprovedBy(session, "approver@example.com")).toBe(true);
    expect(wasApprovedBy(session, "other@example.com")).toBe(false);
  });

  it("detects approver via approvers array", () => {
    const session = {
      ...baseSession,
      status: { ...baseSession.status, approvers: ["a@example.com", "b@example.com"] },
    } as SessionCR;

    expect(wasApprovedBy(session, "b@example.com")).toBe(true);
  });

  it("falls back to conditions message", () => {
    const session = {
      ...baseSession,
      status: {
        ...baseSession.status,
        conditions: [{ type: "Approved", message: "Approved by approver@example.com" }],
      },
    } as SessionCR;

    expect(wasApprovedBy(session, "approver@example.com")).toBe(true);
  });

  it("describes the last approver where available", () => {
    const session = {
      ...baseSession,
      status: { ...baseSession.status, approvers: ["first@example.com", "second@example.com"] },
    } as SessionCR;

    expect(describeApprover(session)).toBe("second@example.com");
  });
});
