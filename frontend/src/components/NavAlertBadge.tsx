import { NavLink } from "react-router";
import { Bell } from "lucide-react";
import { useOpsAlertsDigestQuery } from "@/generated/graphql";
import { navAlertSummary, severityStyle } from "@/lib/alertSeverity";
import { cn } from "@/lib/utils";

/**
 * A count of active alerts in the nav, linking to the Alerts page. Nothing
 * is drawn when there is nothing to act on, so the nav stays five entries on
 * a quiet day. Noise-severity alerts are not counted; the colour is the most
 * urgent severity present.
 */
export function NavAlertBadge() {
  const { data } = useOpsAlertsDigestQuery(
    {},
    { refetchInterval: 60_000, refetchOnWindowFocus: true },
  );
  const { count, worst } = navAlertSummary(
    data?.opsAlertsDigest?.activeBySeverity ?? [],
  );
  if (count === 0) return null;
  const label = `${count} active alert${count === 1 ? "" : "s"}`;
  return (
    <NavLink
      to="/alerts"
      aria-label={label}
      title={label}
      className={({ isActive }) =>
        cn(
          "inline-flex items-center gap-1.5 h-7 px-2.5 rounded-full border text-2xs font-semibold tabular-nums transition-ui",
          severityStyle(worst),
          isActive && "ring-2 ring-primary/30",
        )
      }
    >
      <Bell className="w-3.5 h-3.5" aria-hidden />
      {count > 99 ? "99+" : count}
    </NavLink>
  );
}
