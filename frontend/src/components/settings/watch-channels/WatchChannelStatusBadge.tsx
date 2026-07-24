/**
 * Status pills shared by the watch-channel tables.
 */

import React from "react";
import { AlertTriangle } from "lucide-react";
import type { RecentFailure } from "./api";

/** Small status pill — `ok` renders primary, `warn` renders warning. */
export function WatchChannelStatusBadge({
  tone,
  children,
}: {
  tone: "ok" | "warn";
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <span
      className={
        tone === "ok"
          ? "inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20"
          : "inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-warning/10 text-warning border border-warning/20"
      }
    >
      {children}
    </span>
  );
}

/** Destructive pill with the failure details in the hover tooltip. */
export function RecentFailureBadge({
  failure,
  label,
}: {
  failure: RecentFailure;
  label: string;
}): React.ReactElement {
  return (
    <span
      className="inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full bg-destructive/10 text-destructive border border-destructive/20"
      title={`${failure.error_message}\n\nFailed at: ${new Date(failure.failed_at).toLocaleString()}`}
    >
      <AlertTriangle size={10} />
      {label}
    </span>
  );
}
