import { decideRejectOrWithdraw } from "./sessionActions";

describe("sessionActions", () => {
  it("returns withdraw when current user equals owner via spec.user", () => {
    const bg = { spec: { user: "me@example.com" } };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("withdraw");
  });

  it("returns withdraw when current user equals owner via spec.username", () => {
    const bg = { spec: { username: "me@example.com" } };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("withdraw");
  });

  it("returns withdraw when current user equals owner via spec.requester", () => {
    const bg = { spec: { requester: "me@example.com" } };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("withdraw");
  });

  it("returns reject for different user", () => {
    const bg = { spec: { user: "other@example.com" } };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("reject");
  });

  it("returns reject when no breakglass session provided", () => {
    expect(decideRejectOrWithdraw("me@example.com", undefined)).toBe("reject");
  });

  it("returns reject when current user email is undefined", () => {
    const bg = { spec: { user: "owner@example.com" } };
    expect(decideRejectOrWithdraw(undefined, bg)).toBe("reject");
  });

  it("returns reject when owner is empty", () => {
    const bg = { spec: { user: "" } };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("reject");
  });

  it("returns reject when no owner field exists", () => {
    const bg = { spec: {} };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("reject");
  });

  it("prioritizes spec.user over spec.username", () => {
    const bg = { spec: { user: "user@example.com", username: "username@example.com" } };
    expect(decideRejectOrWithdraw("user@example.com", bg)).toBe("withdraw");
    expect(decideRejectOrWithdraw("username@example.com", bg)).toBe("reject");
  });

  it("uses backend ownership metadata when it says the mapped username is not mine", () => {
    const bg = {
      spec: { user: "me@example.com", requesterEmail: "me@example.com" },
      approvalMeta: {
        canApprove: false,
        canReject: false,
        isRequester: false,
        isApprover: false,
        sessionState: "Pending",
      },
    };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("reject");
  });

  it("uses backend ownership metadata when the mapped username is mine", () => {
    const bg = {
      spec: { user: "oidc:opaque-expression-result", requesterEmail: "different@example.com" },
      approvalMeta: { canApprove: true, canReject: true, isRequester: true, isApprover: true, sessionState: "Pending" },
    };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("withdraw");
  });

  it("uses persisted requester email before legacy mapped username fallback", () => {
    const bg = { spec: { user: "oidc:opaque-expression-result", requesterEmail: "me@example.com" } };
    expect(decideRejectOrWithdraw("me@example.com", bg)).toBe("withdraw");
  });

  it("uses list ownership metadata for custom claim identities", () => {
    const bg = { spec: { user: "tdi_security_oidc:k834798" }, isRequester: true };
    expect(decideRejectOrWithdraw(undefined, bg)).toBe("withdraw");
  });

  it("honors an explicit negative list ownership result", () => {
    const bg = { spec: { user: "tdi_security_oidc:k834798" }, isRequester: false };
    expect(decideRejectOrWithdraw("tdi_security_oidc:k834798", bg)).toBe("reject");
  });

  it("prefers list ownership metadata over stale detail metadata", () => {
    const bg = {
      spec: { user: "tdi_security_oidc:k834798" },
      isRequester: false,
      approvalMeta: {
        canApprove: false,
        canReject: true,
        isRequester: true,
        isApprover: false,
        sessionState: "Pending",
      },
    };
    expect(decideRejectOrWithdraw("tdi_security_oidc:k834798", bg)).toBe("reject");
  });
});
