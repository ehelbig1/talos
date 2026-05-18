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

export function WorkflowStatus({ name, isDirty, runStatus }: WorkflowStatusProps) {
  const healthPill = runStatus ? (
    <div
      className={cn(
        "flex items-center gap-2 px-3 py-1.5 rounded-full text-[9px] font-black uppercase tracking-[0.2em] border transition-premium",
        runStatus.status === "success"
          ? "bg-success/10 text-success border-success/20 shadow-[0_0_15px_hsla(var(--success),0.1)]"
          : runStatus.status === "failed"
            ? "bg-destructive/10 text-destructive border-destructive/20 shadow-[0_0_15px_hsla(var(--destructive),0.1)]"
            : "bg-warning/10 text-warning border-warning/20 animate-pulse",
      )}
    >
      <Activity className={cn("w-3 h-3", runStatus.status === "running" && "animate-spin")} />
      {runStatus.status === "success"
        ? "Operational"
        : runStatus.status === "failed"
          ? "Fault Detected"
          : "Syncing..."}
    </div>
  ) : null;

  return (
    <div className="flex flex-col items-end gap-1">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-black text-white tracking-tight font-outfit">
          {name}
        </h2>
        {isDirty && (
          <div className="px-2 py-0.5 rounded-full bg-warning/10 border border-warning/20 shadow-[0_0_10px_hsla(var(--warning),0.1)]">
            <span className="text-[8px] font-black text-warning uppercase tracking-widest">
              Uncommitted
            </span>
          </div>
        )}
      </div>
      {healthPill}
    </div>
  );
}
