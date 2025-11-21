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
});
