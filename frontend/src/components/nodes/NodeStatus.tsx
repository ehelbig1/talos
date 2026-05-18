import React from "react";
import { NodeStatusType } from "@/store/executionStore";

export const STATUS_BORDER: Record<NodeStatusType, string> = {
  idle: "border-l-muted-foreground/30",
  running: "border-l-blue-500",
  success: "border-l-green-500",
  failed: "border-l-red-500",
  awaiting_approval: "border-l-amber-400",
};

const STATUS_DOT: Record<NodeStatusType, string> = {
  idle: "bg-muted-foreground/30",
  running: "bg-blue-500 animate-status-pulse",
  success: "bg-green-500",
  failed: "bg-red-500",
  awaiting_approval: "bg-amber-400 animate-pulse",
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
