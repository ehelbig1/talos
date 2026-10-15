import React from "react";
import { Activity } from "lucide-react";
import { cn } from "@/lib/utils";

interface WorkflowStatusProps {
  name: string;
  isDirty: boolean;
  runStatus?: {
    status: string;
  };
}

export function WorkflowStatus({
  name,
  isDirty,
  runStatus,
}: WorkflowStatusProps) {
  const healthPill = runStatus ? (
    <div
      className={cn(
        "flex items-center gap-2 px-3 py-1.5 rounded-full text-2xs font-semibold uppercase tracking-wider border transition-premium",
        runStatus.status === "success"
          ? "bg-success/10 text-success border-success/20"
          : runStatus.status === "failed"
            ? "bg-destructive/10 text-destructive border-destructive/20"
            : "bg-warning/10 text-warning border-warning/20 animate-pulse",
      )}
    >
      <Activity
        className={cn(
          "w-3 h-3",
          runStatus.status === "running" && "animate-spin",
        )}
      />
      {runStatus.status === "success"
        ? "Succeeded"
        : runStatus.status === "failed"
          ? "Failed"
          : "Running…"}
    </div>
  ) : null;

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-semibold text-white tracking-tight font-outfit truncate max-w-[220px]">
          {name}
        </h2>
        {isDirty && (
          <div className="px-2 py-0.5 rounded-full bg-warning/10 border border-warning/20">
            <span className="text-2xs font-semibold text-warning uppercase tracking-wider">
              Unsaved
            </span>
          </div>
        )}
      </div>
      {healthPill}
    </div>
  );
}
