import { describe, expect, it } from "vitest";
import { currentUserIdentifier } from "./currentUserIdentity";

describe("currentUserIdentifier", () => {
  it("uses profile email first", () => {
    expect(
      currentUserIdentifier({
        profile: { email: "profile@example.com", preferred_username: "profile-user" },
        email: "top@example.com",
        preferred_username: "top-user",
      }),
    ).toBe("profile@example.com");
  });

  it("falls back through profile preferred username and top-level claims", () => {
    expect(currentUserIdentifier({ profile: { preferred_username: "profile-user" }, email: "top@example.com" })).toBe(
      "profile-user",
    );
    expect(currentUserIdentifier({ email: "top@example.com", preferred_username: "top-user" })).toBe("top@example.com");
    expect(currentUserIdentifier({ preferred_username: "top-user" })).toBe("top-user");
  });

  it("returns an empty string when no identifier is available", () => {
    expect(currentUserIdentifier(null)).toBe("");
    expect(currentUserIdentifier({ profile: {} })).toBe("");
  });
});
