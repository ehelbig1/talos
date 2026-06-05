import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { LoadingSpinner } from "@/components/LoadingSpinner";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import {
  GitBranch,
  Plus,
  RotateCcw,
  CheckCircle2,
  ChevronDown,
  Clock,
  Tag,
  GitCommit,
  Diff,
  PlusCircle,
  MinusCircle,
  RefreshCw,
  Gauge,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDate } from "@/lib/format";
import {
  WorkflowVersionItem,
  useWorkflowVersionsQuery,
  usePublishWorkflowVersionMutation,
  useRollbackWorkflowVersionMutation,
  useGetVersionDiffSummaryQuery,
  useGetWorkflowChangelogQuery,
  useSetConcurrencyLimitMutation,
} from "@/generated/graphql";
import { Dialog } from "@/components/ui/dialog";

type PanelTab = "versions" | "diff" | "changelog" | "config";

interface WorkflowVersionsPanelProps {
  workflowId: string;
  workflowName: string;
  onClose: () => void;
}

export default function WorkflowVersionsPanel({
  workflowId,
  workflowName,
  onClose,
}: WorkflowVersionsPanelProps) {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<PanelTab>("versions");
  const [showPublishForm, setShowPublishForm] = useState(false);
  const [publishDescription, setPublishDescription] = useState("");
  const [rollbackTargetId, setRollbackTargetId] = useState<string | null>(null);

  const { data, isLoading } = useWorkflowVersionsQuery({ workflowId });
  const versions = data?.workflowVersions ?? [];

  const { data: diffData, isLoading: diffLoading } =
    useGetVersionDiffSummaryQuery(
      { workflowId },
      { enabled: activeTab === "diff" },
    );
  const diff = diffData?.getVersionDiffSummary;

  const { data: changelogData, isLoading: changelogLoading } =
    useGetWorkflowChangelogQuery(
      { workflowId },
      { enabled: activeTab === "changelog" },
    );
  const changelog = changelogData?.getWorkflowChangelog ?? [];

  const [concurrencyInput, setConcurrencyInput] = useState("");
  const concurrencyMutation = useSetConcurrencyLimitMutation({
    onSuccess: (data) => {
      if (data.setConcurrencyLimit) {
        toast.success(
          concurrencyInput === ""
            ? "Concurrency limit cleared (unlimited)"
            : `Concurrency limit set to ${concurrencyInput}`,
        );
      }
    },
    onError: () => toast.error("Failed to update concurrency limit"),
  });

  const publishMutation = usePublishWorkflowVersionMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["WorkflowVersions", { workflowId }],
      });
      toast.success("Version published successfully");
      setPublishDescription("");
      setShowPublishForm(false);
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to publish version"),
      );
    },
  });

  const rollbackMutation = useRollbackWorkflowVersionMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["WorkflowVersions", { workflowId }],
      });
      toast.success("Rolled back successfully");
      setRollbackTargetId(null);
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to rollback version"),
      );
    },
  });

  const handlePublish = () => {
    publishMutation.mutate({
      workflowId,
      description: publishDescription || undefined,
    });
  };

  const handleRollback = () => {
    if (!rollbackTargetId) return;
    rollbackMutation.mutate({ workflowId, versionId: rollbackTargetId });
  };

  return (
    <Dialog
      open={true}
      onClose={onClose}
      title="Version History"
      className="max-w-2xl"
    >
      <div className="space-y-6 relative z-10 p-2 -mt-4">
        <div className="flex items-center justify-between mb-2">
          <p className="text-[11px] text-muted-foreground/60 font-medium truncate max-w-[300px] uppercase tracking-widest">
            {workflowName}
          </p>
          <Button
            onClick={() => setShowPublishForm((v) => !v)}
            className="bg-primary hover:bg-primary/90 text-white shadow-lg shadow-primary/20 font-black px-4 h-9 rounded-xl transition-premium hover:scale-[1.02] text-[10px] gap-1.5 uppercase tracking-widest border border-white/10"
          >
            <Plus className="w-3.5 h-3.5" />
            Snapshot Current
          </Button>
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-white/5">
          {(["versions", "diff", "changelog", "config"] as PanelTab[]).map(
            (tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={cn(
                  "px-6 py-3 text-[9px] font-black uppercase tracking-[0.2em] rounded-t-xl transition-premium border-b-2 -mb-px",
                  activeTab === tab
                    ? "text-primary border-primary bg-primary/5"
                    : "text-muted-foreground/40 border-transparent hover:text-white hover:bg-white/5",
                )}
              >
                {tab === "versions"
                  ? "Versions"
                  : tab === "diff"
                    ? "Changes"
                    : tab === "changelog"
                      ? "Changelog"
                      : "Config"}
              </button>
            ),
          )}
        </div>

        {showPublishForm && (
          <div className="p-6 border border-primary/20 bg-primary/5 rounded-[1.5rem] space-y-4 animate-in slide-in-from-top-4 duration-500 glass-light shadow-2xl">
            <div className="flex items-center gap-2">
              <div className="w-1.5 h-1.5 rounded-full bg-primary animate-pulse shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
              <p className="text-[10px] font-black uppercase tracking-[0.3em] text-primary">
                Finalizing Protocol Snapshot
              </p>
            </div>
            <textarea
              placeholder="Description (optional) — e.g. Add retry logic to Step 3"
              value={publishDescription}
              onChange={(e) => setPublishDescription(e.target.value)}
              rows={2}
              className="w-full bg-surface-4/60 border border-white/10 focus:border-primary/40 focus:outline-none focus:ring-1 focus:ring-primary/20 rounded-xl px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground/20 resize-none transition-premium font-medium"
            />
            <div className="flex justify-end gap-3">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setShowPublishForm(false);
                  setPublishDescription("");
                }}
                disabled={publishMutation.isPending}
                className="text-muted-foreground/40 hover:text-white font-black text-[9px] h-9 px-6 uppercase tracking-widest"
              >
                Cancel
              </Button>
              <Button
                size="sm"
                onClick={handlePublish}
                disabled={publishMutation.isPending}
                className="bg-primary hover:bg-primary/90 text-white font-black px-8 h-9 rounded-xl text-[9px] transition-premium uppercase tracking-widest border border-white/10 shadow-xl"
              >
                {publishMutation.isPending ? (
                  <div className="flex items-center gap-2">
                    <LoadingSpinner className="w-3.5 h-3.5" />
                    <span>SYNCHRONIZING...</span>
                  </div>
                ) : (
                  "COMMIT SNAPSHOT"
                )}
              </Button>
            </div>
          </div>
        )}

        <div className="max-h-[460px] overflow-y-auto custom-scrollbar border border-white/5 rounded-[1.5rem] bg-surface-4/20 shadow-inner">
          {activeTab === "diff" && (
            <div className="p-8">
              {diffLoading ? (
                <div className="flex items-center justify-center py-12">
                  <LoadingSpinner className="w-6 h-6 text-primary" />
                </div>
              ) : !diff ? (
                <p className="text-[10px] font-black uppercase tracking-[0.2em] text-muted-foreground/30 text-center py-12">
                  No telemetry delta available.
                </p>
              ) : !diff.hasPublishedVersion ? (
                <div className="text-center py-12 opacity-30">
                  <Diff className="w-10 h-10 text-muted-foreground mx-auto mb-6" />
                  <p className="text-[10px] font-black uppercase tracking-[0.3em]">
                    No published version to diff against.
                  </p>
                </div>
              ) : (
                <div className="space-y-8">
                  <div className="bg-white/[0.02] border border-white/5 rounded-2xl px-6 py-5 shadow-xl glass-light">
                    <p className="text-xs text-muted-foreground/80 leading-relaxed font-medium">
                      {diff.summary}
                    </p>
                  </div>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-6">
                    {[
                      {
                        label: "Nodes Added",
                        value: diff.nodesAdded,
                        icon: <PlusCircle className="w-4 h-4" />,
                        color: "text-success bg-success/5 border-success/10",
                      },
                      {
                        label: "Nodes Changed",
                        value: diff.nodesChanged,
                        icon: <RefreshCw className="w-4 h-4" />,
                        color: "text-warning bg-warning/5 border-warning/10",
                      },
                      {
                        label: "Nodes Removed",
                        value: diff.nodesRemoved,
                        icon: <MinusCircle className="w-4 h-4" />,
                        color:
                          "text-destructive bg-destructive/5 border-destructive/10",
                      },
                      {
                        label: "Edges Added",
                        value: diff.edgesAdded,
                        icon: <PlusCircle className="w-4 h-4" />,
                        color: "text-success bg-success/5 border-success/10",
                      },
                      {
                        label: "Edges Removed",
                        value: diff.edgesRemoved,
                        icon: <MinusCircle className="w-4 h-4" />,
                        color:
                          "text-destructive bg-destructive/5 border-destructive/10",
                      },
                    ].map(({ label, value, icon, color }) => (
                      <div
                        key={label}
                        className={cn(
                          "rounded-2xl border p-5 flex flex-col gap-2 transition-premium hover:scale-105",
                          color,
                        )}
                      >
                        <div className="flex items-center gap-2 opacity-60">
                          {icon}
                          <span className="text-[9px] font-black uppercase tracking-[0.2em]">
                            {label}
                          </span>
                        </div>
                        <span className="text-3xl font-black font-outfit tabular-nums">
                          {value}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === "changelog" && (
            <div className="p-8">
              {changelogLoading ? (
                <div className="flex items-center justify-center py-12">
                  <LoadingSpinner className="w-6 h-6 text-primary" />
                </div>
              ) : changelog.length === 0 ? (
                <div className="text-center py-12 opacity-30">
                  <GitCommit className="w-10 h-10 text-muted-foreground mx-auto mb-6" />
                  <p className="text-[10px] font-black uppercase tracking-[0.3em]">
                    No changelog entries yet.
                  </p>
                </div>
              ) : (
                <div className="relative space-y-0">
                  <div className="absolute left-[18px] top-0 bottom-0 w-px bg-white/5" />
                  {changelog.map((entry) => (
                    <div
                      key={entry.versionNumber}
                      className="flex gap-6 pb-8 last:pb-0 group"
                    >
                      <div className="w-9 h-9 rounded-full bg-surface-3 border border-white/10 flex items-center justify-center shrink-0 z-10 text-[9px] font-black text-primary shadow-2xl transition-premium group-hover:scale-110">
                        v{entry.versionNumber}
                      </div>
                      <div className="flex-1 pt-1.5 min-w-0">
                        <p className="text-sm font-bold text-white group-hover:text-primary transition-premium">
                          {entry.summary}
                        </p>
                        {entry.description && (
                          <p className="text-xs text-muted-foreground/60 mt-2 leading-relaxed font-medium">
                            {entry.description}
                          </p>
                        )}
                        <p className="text-[9px] text-muted-foreground/30 mt-3 font-black uppercase tracking-widest">
                          {formatDate(entry.publishedAt)}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {activeTab === "versions" && isLoading ? (
            <div className="p-20 flex flex-col items-center justify-center gap-4">
              <LoadingSpinner className="w-8 h-8 text-primary" />
              <p className="text-xs text-muted-foreground/60 uppercase tracking-widest font-black animate-pulse">
                Loading Versions...
              </p>
            </div>
          ) : activeTab === "versions" && versions.length === 0 ? (
            <div className="p-20 flex flex-col items-center justify-center gap-4 opacity-20">
              <div className="w-14 h-14 rounded-full bg-surface-3/60 border border-white/5 flex items-center justify-center text-muted-foreground">
                <Tag size={28} />
              </div>
              <p className="text-[10px] font-black uppercase tracking-[0.3em] text-center max-w-[260px] leading-relaxed">
                No protocol snapshots recorded. Synchronize current state to
                initialize.
              </p>
            </div>
          ) : activeTab === "versions" ? (
            <div className="divide-y divide-white/5">
              {versions.map((v: WorkflowVersionItem) => (
                <div
                  key={v.id}
                  className={cn(
                    "px-8 py-6 flex items-center justify-between gap-6 group transition-premium",
                    v.isActive ? "bg-primary/[0.03]" : "hover:bg-white/[0.015]",
                  )}
                >
                  <div className="flex items-center gap-6 min-w-0">
                    <div
                      className={cn(
                        "w-10 h-10 rounded-xl flex items-center justify-center text-[10px] font-black shrink-0 border transition-premium",
                        v.isActive
                          ? "bg-primary/10 border-primary/30 text-primary shadow-[0_0_15px_hsla(var(--primary),0.2)]"
                          : "bg-surface-3 border-white/5 text-muted-foreground/40 group-hover:border-white/10",
                      )}
                    >
                      V{v.versionNumber}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-3 mb-1.5">
                        {v.isActive && (
                          <span className="inline-flex items-center gap-1.5 px-2 py-0.5 bg-primary/10 border border-primary/20 text-[9px] font-black text-primary rounded-md uppercase tracking-widest animate-status-pulse">
                            <CheckCircle2 className="w-2.5 h-2.5" />
                            Live
                          </span>
                        )}
                        <span
                          className={cn(
                            "text-sm truncate font-bold",
                            v.description
                              ? "text-white"
                              : "text-muted-foreground/30 italic",
                          )}
                        >
                          {v.description || "No identifier"}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-[9px] font-black text-muted-foreground/30 uppercase tracking-[0.2em]">
                        <Clock className="w-3 h-3" />
                        {formatDate(v.publishedAt)}
                      </div>
                    </div>
                  </div>

                  <div className="shrink-0">
                    {v.isActive ? (
                      <span className="px-4 py-2 bg-primary/5 border border-primary/10 text-[9px] font-black text-primary/60 rounded-xl uppercase tracking-widest">
                        ORCHESTRATING
                      </span>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setRollbackTargetId(v.id)}
                        disabled={rollbackMutation.isPending}
                        className="opacity-0 group-hover:opacity-100 text-muted-foreground/40 hover:text-primary hover:bg-primary/5 h-9 px-5 font-black transition-premium text-[9px] gap-2 uppercase tracking-widest border border-white/5 rounded-xl hover:border-primary/20"
                      >
                        <RotateCcw className="w-3.5 h-3.5" />
                        Rollback
                      </Button>
                    )}
                  </div>
                </div>
              ))}
            </div>
          ) : null}

          {activeTab === "config" && (
            <div className="p-8 space-y-8">
              {/* Concurrency limit */}
              <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-6 glass-light shadow-xl">
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-10 h-10 bg-primary/10 border border-primary/20 rounded-xl flex items-center justify-center">
                    <Gauge className="w-5 h-5 text-primary" />
                  </div>
                  <div>
                    <h4 className="text-sm font-black text-white uppercase tracking-tight">
                      Capability Ceiling
                    </h4>
                    <p className="text-[10px] font-bold text-muted-foreground/40 mt-1 uppercase tracking-widest">
                      Max simultaneous executions. Null for unbounded capacity.
                    </p>
                  </div>
                </div>
                <div className="flex gap-4">
                  <div className="relative flex-1 group">
                    <div className="absolute -inset-0.5 bg-primary/20 rounded-xl blur opacity-0 group-focus-within:opacity-100 transition-premium" />
                    <input
                      type="number"
                      min={1}
                      value={concurrencyInput}
                      onChange={(e) => setConcurrencyInput(e.target.value)}
                      placeholder="UNBOUNDED"
                      className="w-full bg-surface-4/60 border border-white/10 focus:border-primary/40 focus:outline-none focus:ring-1 focus:ring-primary/40 rounded-xl px-5 py-3 text-sm text-white placeholder:text-muted-foreground/20 transition-premium relative z-10 font-medium"
                    />
                  </div>
                  <Button
                    size="sm"
                    onClick={() =>
                      concurrencyMutation.mutate({
                        workflowId,
                        maxConcurrent: concurrencyInput
                          ? parseInt(concurrencyInput, 10) || undefined
                          : undefined,
                      })
                    }
                    disabled={concurrencyMutation.isPending}
                    className="bg-primary hover:bg-primary/90 text-white font-black px-8 rounded-xl text-[10px] h-12 uppercase tracking-widest shadow-xl transition-premium border border-white/10"
                  >
                    {concurrencyMutation.isPending
                      ? "SYNCHRONIZING..."
                      : "SAVE LIMIT"}
                  </Button>
                  {concurrencyInput && (
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => {
                        setConcurrencyInput("");
                        concurrencyMutation.mutate({
                          workflowId,
                          maxConcurrent: undefined,
                        });
                      }}
                      className="text-muted-foreground/40 hover:text-white text-[9px] font-black uppercase tracking-widest px-4 h-12"
                    >
                      Clear
                    </Button>
                  )}
                </div>
              </div>

              <div className="text-center py-6">
                <p className="text-[9px] font-black text-muted-foreground/20 uppercase tracking-[0.3em]">
                  Extended system parameters available in next update
                </p>
              </div>
            </div>
          )}
        </div>
      </div>

      {rollbackTargetId && (
        <Dialog
          open={true}
          onClose={() => setRollbackTargetId(null)}
          title="Confirm Rollback"
          className="max-w-sm"
        >
          <div className="p-2 text-center space-y-6">
            <div className="w-16 h-16 bg-warning/10 border border-warning/20 rounded-[1.5rem] flex items-center justify-center text-warning mx-auto shadow-2xl">
              <RotateCcw size={28} />
            </div>
            <div>
              <p className="text-sm text-muted-foreground/60 font-bold uppercase tracking-widest leading-relaxed px-4">
                The selected snapshot will be re-synchronized as the primary
                execution logic. Existing telemetry remains preserved.
              </p>
            </div>
            <div className="flex items-center gap-4 pt-4">
              <Button
                variant="ghost"
                onClick={() => setRollbackTargetId(null)}
                className="flex-1 text-[10px] font-black uppercase tracking-widest h-12 rounded-2xl"
              >
                Abort
              </Button>
              <Button
                onClick={handleRollback}
                disabled={rollbackMutation.isPending}
                className="flex-1 bg-warning hover:bg-warning/90 text-background font-black h-12 rounded-2xl transition-premium shadow-2xl border border-white/10 uppercase tracking-widest text-[10px]"
              >
                {rollbackMutation.isPending ? (
                  <div className="flex items-center gap-2">
                    <LoadingSpinner className="w-4 h-4" />
                    <span>SYNCHRONIZING...</span>
                  </div>
                ) : (
                  "CONFIRM ROLLBACK"
                )}
              </Button>
            </div>
          </div>
        </Dialog>
      )}
    </Dialog>
  );
}
