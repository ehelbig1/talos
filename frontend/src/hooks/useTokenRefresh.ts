import { useEffect, useRef } from "react";
import { refreshAccessToken } from "@/lib/auth";

/**
 * Automatically refreshes the access token before it expires.
 *
 * Access tokens expire after 15 minutes. This hook refreshes them
 * every 14 minutes to ensure uninterrupted access.
 *
 * The refresh token (valid for 7 days) is stored in an httpOnly cookie
 * and is automatically sent by the browser.
 */
export function useTokenRefresh() {
  const refreshIntervalRef = useRef<number | null>(null);

  useEffect(() => {
    // Refresh token every 14 minutes (before 15-minute expiration)
    const REFRESH_INTERVAL = 14 * 60 * 1000; // 14 minutes in milliseconds

    const performRefresh = async () => {
      try {
        await refreshAccessToken();
        // if (import.meta.env.DEV) console.log("[Auth] Access token refreshed successfully");
      } catch (error) {
        // if (import.meta.env.DEV) console.error("[Auth] Failed to refresh token:", error);
        // If refresh fails, user will be prompted to log in again on next request
        // The graphqlClient already handles this with automatic retry
      }
    };

    // Start the refresh interval
    refreshIntervalRef.current = window.setInterval(
      performRefresh,
      REFRESH_INTERVAL,
    );

    // Also refresh immediately on mount (in case we're close to expiration)
    performRefresh();

    // Cleanup on unmount
    return () => {
      if (refreshIntervalRef.current !== null) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, []);
}
