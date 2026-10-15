import React from "react";
import { Activity } from "lucide-react";
import { cn } from "@/lib/utils";

interface WorkflowStatusProps {
  isDirty: boolean;
  runStatus?: {
    status: string;
  };
}

/** The two things worth knowing at a glance: unsaved edits, last run. */
export function WorkflowStatus({ isDirty, runStatus }: WorkflowStatusProps) {
  if (!isDirty && !runStatus) return null;
  const pill =
    "inline-flex items-center gap-1.5 h-7 px-2.5 rounded-lg text-2xs font-semibold border whitespace-nowrap";
  return (
    <div className="flex items-center gap-1.5">
      {isDirty && (
        <span
          className={cn(pill, "bg-warning/10 text-warning border-warning/20")}
        >
          Unsaved
        </span>
      )}
      {runStatus && (
        <span
          className={cn(
            pill,
            runStatus.status === "success"
              ? "bg-success/10 text-success border-success/20"
              : runStatus.status === "failed"
                ? "bg-destructive/10 text-destructive border-destructive/20"
                : "bg-warning/10 text-warning border-warning/20",
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
        </span>
      )}
    </div>
  );
}
