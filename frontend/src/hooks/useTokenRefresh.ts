import { useEffect } from "react";
import { refreshAccessToken } from "@/lib/auth";
import { lastRefreshTime } from "@/lib/session";

/** Access tokens live 15 minutes; refresh a minute before. */
export const REFRESH_INTERVAL_MS = 14 * 60 * 1000;
const LEADER_LOCK = "talos-session-refresh-timer";

/**
 * How long until the next timer refresh. `lastRefreshAt` is the last
 * successful refresh by ANY tab (`session.lastRefreshTime`); unknown means
 * the session was only just validated (this hook mounts after `me` or a
 * login succeeded), so a full interval.
 */
export function nextRefreshDelay(
  now: number,
  lastRefreshAt: number | null,
): number {
  if (lastRefreshAt === null) return REFRESH_INTERVAL_MS;
  return Math.min(
    REFRESH_INTERVAL_MS,
    Math.max(0, lastRefreshAt + REFRESH_INTERVAL_MS - now),
  );
}

/** Is a timer tick due to refresh? Not when any tab refreshed within the
 *  interval (a second of slack for timer jitter). Unknown is due. */
export function refreshDue(now: number, lastRefreshAt: number | null): boolean {
  return (
    lastRefreshAt === null || now - lastRefreshAt >= REFRESH_INTERVAL_MS - 1000
  );
}

/**
 * Keeps the access token fresh with ONE timer per browser.
 *
 * No refresh on mount: the hook mounts only after the session was validated
 * (`me` or a login), and a request whose token expires first recovers
 * through `session.recoverSession`. Tabs elect one leader through the Web
 * Locks API; only the leader runs the timer and another tab takes over when
 * it closes. Without Web Locks every tab runs the timer, and a tick skips
 * when another tab refreshed within the interval (the shared timestamp).
 */
export function useTokenRefresh() {
  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let releaseLeadership: (() => void) | null = null;

    const schedule = () => {
      timer = setTimeout(tick, nextRefreshDelay(Date.now(), lastRefreshTime()));
    };
    const tick = async () => {
      timer = null;
      if (stopped) return;
      // Another tab may have refreshed while this timer waited.
      if (refreshDue(Date.now(), lastRefreshTime())) {
        try {
          await refreshAccessToken();
        } catch {
          // The next request recovers (or signs the user out) on its own.
        }
      }
      if (!stopped) schedule();
    };

    const locks =
      typeof navigator !== "undefined" ? navigator.locks : undefined;
    const abort = new AbortController();
    if (locks?.request) {
      locks
        .request(
          LEADER_LOCK,
          { signal: abort.signal },
          () =>
            new Promise<void>((resolve) => {
              if (stopped) return resolve();
              releaseLeadership = resolve;
              schedule();
            }),
        )
        .catch(() => {
          // AbortError: unmounted before this tab became leader.
        });
    } else {
      schedule();
    }

    return () => {
      stopped = true;
      if (timer !== null) clearTimeout(timer);
      abort.abort();
      releaseLeadership?.();
    };
  }, []);
}
