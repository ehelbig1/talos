import React from "react";
import type { NodeStatusType } from "@/store/executionStore";

export const STATUS_BORDER: Record<NodeStatusType, string> = {
  idle: "border-l-muted-foreground/30",
  running: "border-l-info",
  success: "border-l-success",
  failed: "border-l-destructive",
  skipped: "border-l-muted-foreground/50",
  awaiting_approval: "border-l-warning",
};

const STATUS_DOT: Record<NodeStatusType, string> = {
  idle: "bg-muted-foreground/30",
  running: "bg-info animate-status-pulse",
  success: "bg-success",
  failed: "bg-destructive",
  skipped: "bg-muted-foreground/50",
  awaiting_approval: "bg-warning",
};

export const StatusDot = React.memo(function StatusDot({
  status,
}: {
  status: NodeStatusType;
}) {
  return (
    <div
      className={`w-2 h-2 rounded-full shrink-0 ${STATUS_DOT[status]}`}
      aria-label={`Status: ${status}`}
    />
  );
});
