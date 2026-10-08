import { vi, type MockInstance } from "vitest";
import { dismissError, pushError, pushSuccess, useErrors } from "./toast";

describe("toast service", () => {
  const store = useErrors();
  let randomSpy: MockInstance;

  beforeEach(() => {
    vi.useFakeTimers();
    randomSpy = vi.spyOn(Math, "random").mockReturnValue(0.123456789);
    store.errors.splice(0, store.errors.length);
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    randomSpy.mockRestore();
  });

  it("pushError records error level entries and auto-dismisses them", () => {
    pushError("failed request");

    expect(store.errors).toHaveLength(1);
    expect(store.errors[0]).toMatchObject({
      message: "failed request",
      type: "error",
      autoHideDuration: 10000,
      opened: true,
    });

    vi.advanceTimersByTime(11000);
    expect(store.errors).toHaveLength(0);
  });

  it("pushError treats 2xx status codes as success toasts", () => {
    pushError("created", 201, "cid-1");

    expect(store.errors[0]).toMatchObject({
      cid: "cid-1",
      type: "success",
      autoHideDuration: 6000,
    });

    vi.advanceTimersByTime(7000);
    expect(store.errors).toHaveLength(0);
  });

  it("pushSuccess adds dismissible success entries", () => {
    pushSuccess("all done");
    expect(store.errors[0]).toMatchObject({ message: "all done", type: "success" });

    const id = store.errors[0]!.id;
    dismissError(id);
    expect(store.errors).toHaveLength(0);
  });

  it("shows one toast for identical concurrent errors and keeps the most specific status", () => {
    pushError("Request failed with status code 500");
    pushError("Request failed with status code 500", 500, "cid-9");
    pushError("Request failed with status code 500");

    expect(store.errors).toHaveLength(1);
    expect(store.errors[0]).toMatchObject({ status: 500, cid: "cid-9", type: "error" });

    pushError("A different failure");
    pushSuccess("Request failed with status code 500");
    expect(store.errors).toHaveLength(3);
  });

  it("shows the message again once the previous toast is gone", () => {
    pushError("flaky");
    dismissError(store.errors[0]!.id);
    pushError("flaky");
    expect(store.errors).toHaveLength(1);
  });
});
