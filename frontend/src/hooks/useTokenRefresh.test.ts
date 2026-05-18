import { renderHook } from "../test-utils";
import { useTokenRefresh } from "./useTokenRefresh";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as auth from "@/lib/auth";

describe("useTokenRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(auth, "refreshAccessToken").mockResolvedValue({
      user: {
        id: "user-1",
        email: "test@example.com",
        name: "Test User",
        twoFactorEnabled: false,
        isTwoFactorVerified: false,
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("refreshes token immediately on mount", () => {
    renderHook(() => useTokenRefresh());
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(1);
  });

  it("sets up an interval to refresh token", () => {
    renderHook(() => useTokenRefresh());

    // Fast-forward 14 minutes
    vi.advanceTimersByTime(14 * 60 * 1000);

    // Should have been called twice: once on mount, once after interval
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(2);

    // Fast-forward another 14 minutes
    vi.advanceTimersByTime(14 * 60 * 1000);
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(3);
  });

  it("cleans up interval on unmount", () => {
    const { unmount } = renderHook(() => useTokenRefresh());

    unmount();

    vi.advanceTimersByTime(14 * 60 * 1000);
    // Should still only be 1 (from initial mount)
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(1);
  });
});
