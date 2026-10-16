import React, { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  useGetResourceQuotasQuery,
  useUpdateResourceQuotasMutation,
} from "@/generated/graphql";
import {
  Gauge,
  Zap,
  BarChart3,
  AlertTriangle,
  Activity,
  Database,
  Server,
  Edit2,
  Save,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { toast } from "sonner";

function usagePercent(used: number, limit: number): number {
  if (limit === 0) return 0;
  return Math.min(100, Math.round((used / limit) * 100));
}

function usageColor(pct: number): string {
  if (pct >= 90) return "bg-destructive";
  if (pct >= 75) return "bg-warning";
  return "bg-primary";
}

function usageText(pct: number): string {
  if (pct >= 90) return "text-destructive";
  if (pct >= 75) return "text-warning";
  return "text-primary";
}

function getMetricIcon(metric: string) {
  const m = metric.toLowerCase();
  if (m.includes("cpu")) return Activity;
  if (m.includes("memory")) return Zap;
  if (m.includes("storage") || m.includes("db")) return Database;
  if (m.includes("workflow") || m.includes("execution")) return BarChart3;
  if (m.includes("node") || m.includes("vm")) return Server;
  return Gauge;
}

export function ResourceQuotas() {
  const { data, isLoading, refetch } = useGetResourceQuotasQuery(undefined, {
    refetchInterval: 30000,
  });

  const [isEditing, setIsEditing] = useState(false);
  const [editedLimits, setEditedLimits] = useState({
    cpuCores: 0,
    memoryGb: 0,
    storageGb: 0,
    concurrentExecutions: 0,
  });

  const { mutate: updateQuotas, isPending: isUpdating } =
    useUpdateResourceQuotasMutation({
      onSuccess: () => {
        toast.success("Resource quotas updated successfully");
        setIsEditing(false);
        refetch();
      },
      onError: (err: Error) => {
        toast.error(
          sanitizeErrorMessage(
            err.message || "Failed to update resource quotas",
          ),
        );
      },
    });

  const q = data?.resourceQuotas;

  // Seed the editable form from the fetched quota whenever the quota
  // changes (incl. the 30s refetch) and the user isn't mid-edit. Done
  // during render via the "store information from previous renders"
  // pattern (https://react.dev/learn/you-might-not-need-an-effect)
  // instead of a setState-in-effect. We always advance the trackers when
  // either input changes so that leaving edit mode re-syncs to the
  // latest quota — matching the previous effect's [q, isEditing] deps.
  const [lastQuota, setLastQuota] = useState(q);
  const [lastIsEditing, setLastIsEditing] = useState(isEditing);
  if (q !== lastQuota || isEditing !== lastIsEditing) {
    setLastQuota(q);
    setLastIsEditing(isEditing);
    if (q && !isEditing) {
      setEditedLimits({
        cpuCores: q.cpuCores,
        memoryGb: q.memoryGb,
        storageGb: q.storageGb,
        concurrentExecutions: q.concurrentExecutions,
      });
    }
  }

  const quotaList = q
    ? [
        {
          key: "cpuCores",
          metric: "CPU",
          unit: "cores",
          used: q.usedCpu,
          limit: q.cpuCores,
          editedValue: editedLimits.cpuCores,
        },
        {
          key: "memoryGb",
          metric: "Memory",
          unit: "GB",
          used: q.usedMemory,
          limit: q.memoryGb,
          editedValue: editedLimits.memoryGb,
        },
        {
          key: "storageGb",
          metric: "Storage",
          unit: "GB",
          used: q.usedStorage,
          limit: q.storageGb,
          editedValue: editedLimits.storageGb,
        },
        {
          key: "concurrentExecutions",
          metric: "Concurrent runs",
          unit: "runs",
          used: q.activeExecutions,
          limit: q.concurrentExecutions,
          editedValue: editedLimits.concurrentExecutions,
        },
      ]
    : [];

  const handleSave = () => {
    updateQuotas({
      input: {
        cpuCores: Number(editedLimits.cpuCores),
        memoryGb: Number(editedLimits.memoryGb),
        storageGb: Number(editedLimits.storageGb),
        concurrentExecutions: Number(editedLimits.concurrentExecutions),
      },
    });
  };

  if (isLoading) {
    return (
      <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 animate-pulse">
        <div className="h-4 w-48 bg-white/5 rounded-full mb-10" />
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {[1, 2, 3, 4].map((i) => (
            <div
              key={i}
              className="h-48 bg-white/[0.02] border border-white/5 rounded-2xl"
            />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-10 relative overflow-hidden group">
      <div className="flex items-center justify-between mb-10 relative z-10">
        <div className="flex items-center gap-5">
          <div className="w-14 h-14 bg-primary/10 border border-primary/20 rounded-2xl flex items-center justify-center transition-ui">
            <Gauge className="w-7 h-7 text-primary" />
          </div>
          <div>
            <h3 className="text-2xl md:text-3xl font-semibold text-white tracking-tight font-outfit leading-tight">
              Resource quotas
            </h3>
            <p className="text-xs text-muted-foreground/70 font-semibold mt-2 leading-none">
              {isEditing
                ? "Editing limits"
                : "Current usage against your limits"}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-4">
          {isEditing ? (
            <>
              <Button
                variant="outline"
                onClick={() => setIsEditing(false)}
                disabled={isUpdating}
              >
                <X className="w-4 h-4" />
                Cancel
              </Button>
              <Button onClick={handleSave} disabled={isUpdating}>
                <Save className="w-4 h-4" />
                {isUpdating ? "Saving…" : "Save limits"}
              </Button>
            </>
          ) : (
            <Button variant="outline" onClick={() => setIsEditing(true)}>
              <Edit2 className="w-4 h-4 text-primary transition-ui" />
              Edit limits
            </Button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 relative z-10">
        {quotaList.map((item) => {
          const Icon = getMetricIcon(item.metric);
          const pct = usagePercent(item.used, item.limit);
          return (
            <div
              key={item.metric}
              className={cn(
                "bg-black/40 border rounded-2xl p-8 transition-ui group/item relative overflow-hidden",
                isEditing
                  ? "border-primary/40"
                  : "border-white/5 hover:border-white/10",
              )}
            >
              <div className="flex items-center justify-between mb-8 relative z-10">
                <div className="flex items-center gap-5">
                  <div className="w-12 h-12 bg-white/5 border border-white/10 rounded-xl flex items-center justify-center transition-ui">
                    <Icon
                      className={cn(
                        "w-6 h-6",
                        isEditing ? "text-primary" : "text-white/70",
                      )}
                    />
                  </div>
                  <div className="flex-1 min-w-0">
                    <h4 className="text-sm font-semibold text-white leading-none truncate">
                      {item.metric}
                    </h4>
                    <p className="text-xs text-muted-foreground/60 font-bold mt-1.5 leading-none">
                      {isEditing ? "New limit" : "In use"}
                    </p>
                  </div>
                </div>
                {!isEditing && (
                  <div className="shrink-0 ml-4">
                    <span
                      className={cn(
                        "text-2xl md:text-3xl font-semibold tabular-nums tracking-tight leading-none",
                        usageText(pct),
                      )}
                    >
                      {pct}%
                    </span>
                  </div>
                )}
              </div>

              {isEditing ? (
                <div className="space-y-4 relative z-10">
                  <div className="relative group/input">
                    <input
                      type="number"
                      value={item.editedValue}
                      onChange={(e) =>
                        setEditedLimits((prev) => ({
                          ...prev,
                          [item.key]: e.target.value,
                        }))
                      }
                      className="w-full h-14 px-6 bg-black/60 border border-white/5 rounded-2xl text-xl font-semibold text-white focus:outline-none focus:ring-4 focus:ring-primary/10 transition-ui font-mono pr-24"
                      min="0"
                    />
                    <div className="absolute right-6 top-1/2 -translate-y-1/2 text-xs font-semibold text-muted-foreground/70 pointer-events-none">
                      {item.unit}
                    </div>
                  </div>
                  <div className="flex items-center gap-3 px-1">
                    <Activity className="w-3.5 h-3.5 text-success/40" />
                    <p className="text-xs text-muted-foreground/50 font-semibold">
                      Currently using {item.used} {item.unit}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="space-y-5 relative z-10">
                  <div className="h-3 w-full bg-white/5 rounded-full overflow-hidden border border-white/5 p-0.5">
                    <div
                      className={cn(
                        "h-full rounded-full transition-ui ease-out",
                        usageColor(pct),
                      )}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <div className="flex justify-between items-center text-xs font-semibold">
                    <div className="flex items-center gap-3 text-muted-foreground/70">
                      <span className="text-white">{item.used}</span>
                      <span className="opacity-20 text-2xs">of</span>
                      <span className="text-white/60">
                        {item.limit} {item.unit}
                      </span>
                    </div>
                    {pct > 80 && (
                      <div className="flex items-center gap-2 text-destructive bg-destructive/10 px-3 py-1 rounded-full border border-destructive/20">
                        <AlertTriangle className="w-3 h-3" />
                        <span>Near limit</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="mt-12 pt-8 border-t border-white/5 flex items-center justify-between relative z-10">
        <div className="flex items-center gap-4">
          <div className="w-2 h-2 rounded-full bg-success" />
          <p className="text-xs text-muted-foreground/50 font-semibold flex items-center gap-3">
            Updated {new Date().toLocaleTimeString()}
          </p>
        </div>
        {!isEditing && (
          <button
            type="button"
            className="text-xs font-semibold text-primary hover:text-white transition-ui flex items-center gap-3 group/btn"
          >
            Usage report
            <div className="w-5 h-5 rounded-lg bg-primary/10 flex items-center justify-center group-hover/btn:bg-primary group-hover/btn:text-black transition-ui">
              <BarChart3 className="w-3 h-3" />
            </div>
          </button>
        )}
      </div>
    </div>
  );
}
