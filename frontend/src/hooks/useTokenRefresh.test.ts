import { renderHook } from "../test-utils";
import {
  REFRESH_INTERVAL_MS,
  nextRefreshDelay,
  refreshDue,
  useTokenRefresh,
} from "./useTokenRefresh";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as auth from "@/lib/auth";
import { LAST_REFRESH_STORAGE_KEY } from "@/lib/session";

describe("useTokenRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    localStorage.removeItem(LAST_REFRESH_STORAGE_KEY);
    vi.spyOn(auth, "refreshAccessToken").mockImplementation(async () => {
      // What session.refreshSession records on success.
      localStorage.setItem(LAST_REFRESH_STORAGE_KEY, String(Date.now()));
      return {
        user: {
          id: "user-1",
          email: "test@example.com",
          name: "Test User",
          twoFactorEnabled: false,
          isTwoFactorVerified: false,
        },
      };
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it("does not refresh on mount: the session was just validated", () => {
    renderHook(() => useTokenRefresh());
    expect(auth.refreshAccessToken).not.toHaveBeenCalled();
  });

  it("refreshes every interval", async () => {
    renderHook(() => useTokenRefresh());
    await vi.advanceTimersByTimeAsync(REFRESH_INTERVAL_MS);
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(REFRESH_INTERVAL_MS);
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(2);
  });

  it("skips a tick when another tab refreshed within the interval", async () => {
    renderHook(() => useTokenRefresh());
    await vi.advanceTimersByTimeAsync(REFRESH_INTERVAL_MS - 60_000);
    // Another tab refreshed; this tab's timer must not rotate again.
    localStorage.setItem(LAST_REFRESH_STORAGE_KEY, String(Date.now()));
    await vi.advanceTimersByTimeAsync(60_000);
    expect(auth.refreshAccessToken).not.toHaveBeenCalled();
    await vi.advanceTimersByTimeAsync(REFRESH_INTERVAL_MS);
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(1);
  });

  it("with Web Locks only the leader tab runs the timer", async () => {
    let held = false;
    const waiting: Array<() => void> = [];
    vi.stubGlobal("navigator", {
      locks: {
        request: (
          _name: string,
          _opts: unknown,
          cb: () => Promise<void>,
        ): Promise<void> => {
          const run = () => {
            held = true;
            return cb().then(() => {
              held = false;
              waiting.shift()?.();
            });
          };
          if (!held) return run();
          return new Promise<void>((resolve) =>
            waiting.push(() => void run().then(resolve)),
          );
        },
      },
    });
    const leader = renderHook(() => useTokenRefresh());
    renderHook(() => useTokenRefresh()); // a second tab
    await vi.advanceTimersByTimeAsync(REFRESH_INTERVAL_MS);
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(1);
    leader.unmount(); // the follower takes over
    await vi.advanceTimersByTimeAsync(REFRESH_INTERVAL_MS);
    expect(auth.refreshAccessToken).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it("cleans up on unmount", async () => {
    const { unmount } = renderHook(() => useTokenRefresh());
    unmount();
    await vi.advanceTimersByTimeAsync(REFRESH_INTERVAL_MS * 2);
    expect(auth.refreshAccessToken).not.toHaveBeenCalled();
  });
});

describe("refresh scheduling", () => {
  it("schedules from the last refresh by any tab", () => {
    expect(nextRefreshDelay(1000, null)).toBe(REFRESH_INTERVAL_MS);
    expect(nextRefreshDelay(REFRESH_INTERVAL_MS + 5000, 0)).toBe(0);
    expect(nextRefreshDelay(60_000, 0)).toBe(REFRESH_INTERVAL_MS - 60_000);
    expect(refreshDue(60_000, 0)).toBe(false);
    expect(refreshDue(REFRESH_INTERVAL_MS, 0)).toBe(true);
    expect(refreshDue(5, null)).toBe(true);
  });
});
