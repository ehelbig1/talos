import React, { useState, useMemo, lazy, Suspense } from "react";
import { useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

const WorkflowExecutionHistory = lazy(
  () => import("@/components/settings/WorkflowExecutionHistory"),
);
const WorkflowVersionsPanel = lazy(
  () => import("@/components/settings/WorkflowVersionsPanel"),
);
import { gql, subscribeWorkflowExecutions } from "@/lib/graphqlClient";
import { useEffect, useCallback } from "react";
import {
  useListActorsQuery,
  useWorkflowsQuery,
  useTriggerWorkflowMutation,
  useLatestWorkflowExecutionsQuery,
  useDeleteWorkflowMutation,
  useGetApprovalsQuery,
  useMySchedulesQuery,
  WorkflowsQuery,
  ListActorsQuery,
  LatestWorkflowExecutionsQuery,
  MySchedulesQuery,
} from "@/generated/graphql";
import { useWorkflowStore } from "@/store/workflowStore";
import { ConfirmDialog, SkeletonStatRow } from "@/components/ui";
import { usePersistedExecutionStore } from "@/store/executionStore";
import { cn } from "@/lib/utils";
import type { WorkflowRunStatus } from "@/store/executionStore";
import {
  Bot,
  Search,
  X,
  Filter,
  Activity,
  Plus,
  Command,
  ArrowRight,
  ChevronDown,
} from "lucide-react";

import WorkflowStatsPanel from "./WorkflowStatsPanel";
import ActorsPanel from "./ActorsPanel";
import WorkflowCard from "./WorkflowCard";
import EmptyState from "./EmptyState";
import type { Workflow, WorkflowSchedule } from "./WorkflowCard";

export default function Dashboard() {
  const navigate = useNavigate();
  const clearWorkflow = useWorkflowStore((s) => s.clearWorkflow);
  const workflowStatuses = usePersistedExecutionStore(
    (s) => s.workflowStatuses,
  );
  const setWorkflowStatus = usePersistedExecutionStore(
    (s) => s.setWorkflowStatus,
  );

  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<"name" | "lastRun" | "status">("name");
  const [statusFilter, setStatusFilter] = useState<
    "all" | "success" | "failed" | "idle"
  >("all");
  const [historyWorkflow, setHistoryWorkflow] = useState<Workflow | null>(null);
  const [versionsWorkflow, setVersionsWorkflow] = useState<Workflow | null>(
    null,
  );
  const [workflowToDelete, setWorkflowToDelete] = useState<Workflow | null>(
    null,
  );
  const queryClient = useQueryClient();

  const deleteWorkflowMutation = useDeleteWorkflowMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["Workflows"] });
      toast.success("Workflow deleted");
      setWorkflowToDelete(null);
    },
    onError: () => {
      toast.error("Failed to delete workflow");
      setWorkflowToDelete(null);
    },
  });

  const { data: approvalsData } = useGetApprovalsQuery(
    {},
    { refetchInterval: 30_000, refetchOnWindowFocus: true },
  );
  const pendingApprovalCount =
    approvalsData?.pendingApprovals?.filter((a) => a.status === "pending")
      .length ?? 0;

  const { data: schedulesData } = useMySchedulesQuery(undefined, {
    staleTime: 60_000,
    select: (d: MySchedulesQuery) => d.mySchedules,
  });
  const schedulesByWorkflowId = React.useMemo(() => {
    const map: Record<string, WorkflowSchedule> = {};
    for (const s of schedulesData ?? []) {
      map[s.workflowId] = {
        cronExpression: s.cronExpression,
        isEnabled: s.isEnabled,
        nextTriggerAt: s.nextTriggerAt,
      };
    }
    return map;
  }, [schedulesData]);

  const { data: workflows = [], isLoading } = useWorkflowsQuery(undefined, {
    staleTime: 60_000,
    select: (data: WorkflowsQuery) => data.workflows,
  });

  const { data: actorsData } = useListActorsQuery(undefined, {
    staleTime: 30_000,
    refetchInterval: 30_000,
    select: (data: ListActorsQuery) => data.actors,
  });

  const actorIdToName = useMemo(() => {
    const map: Record<string, string> = {};
    for (const a of actorsData ?? []) {
      map[a.id] = a.name;
    }
    return map;
  }, [actorsData]);

  const handleNew = () => {
    clearWorkflow();
    navigate("/editor");
  };

  const handleEdit = (workflow: Workflow) => {
    navigate(`/editor/${workflow.id}`);
  };

  const triggerWorkflowMutation = useTriggerWorkflowMutation();

  const handleRun = async (workflow: Workflow) => {
    try {
      const res = await triggerWorkflowMutation.mutateAsync({
        workflowId: workflow.id,
      });
      if (res.triggerWorkflow) {
        toast.success("Workflow triggered");
      }
    } catch {
      toast.error("Failed to trigger workflow");
    }
  };

  const filteredWorkflows = useMemo(() => {
    let result = [...workflows];

    // Search filter
    if (search) {
      const q = search.toLowerCase();
      result = result.filter((w) => w.name.toLowerCase().includes(q));
    }

    // Status filter
    if (statusFilter !== "all") {
      result = result.filter((w) => {
        const s = workflowStatuses[w.id];
        if (statusFilter === "idle") return !s;
        return s?.status === statusFilter;
      });
    }

    // Sort
    result.sort((a, b) => {
      if (sortBy === "name") return a.name.localeCompare(b.name);
      if (sortBy === "status") {
        const sa = workflowStatuses[a.id]?.status ?? "idle";
        const sb = workflowStatuses[b.id]?.status ?? "idle";
        return sa.localeCompare(sb);
      }
      if (sortBy === "lastRun") {
        const ra = workflowStatuses[a.id]?.runAt ?? "";
        const rb = workflowStatuses[b.id]?.runAt ?? "";
        return rb.localeCompare(ra); // newest first
      }
      return 0;
    });

    return result;
  }, [workflows, search, sortBy, statusFilter, workflowStatuses]);

  // ---------------------------------------------------------------------
  // Periodic refetch of latest workflow execution status.
  // ---------------------------------------------------------------------
  const hasRunningWorkflow = Object.values(workflowStatuses).some(
    (s) => s.status === "running",
  );
  const { data: latestExecutionsData } = useLatestWorkflowExecutionsQuery(
    { workflowIds: workflows.map((w) => w.id) },
    {
      enabled: workflows.length > 0,
      // Frequency significantly reduced; WebSocket handles immediate start-up telemetry.
      // Heartbeat refetch remains as a fallback for terminal state transitions.
      refetchInterval: 30_000,
      refetchOnWindowFocus: true,
    },
  );

  React.useEffect(() => {
    if (latestExecutionsData?.latestWorkflowExecutions) {
      latestExecutionsData.latestWorkflowExecutions.forEach(
        (
          exec: LatestWorkflowExecutionsQuery["latestWorkflowExecutions"][0],
        ) => {
          // Normalize backend status strings to the frontend's expected values.
          const raw = exec.status;
          let status: WorkflowRunStatus["status"];
          if (raw === "completed") {
            status = "success";
          } else if (
            raw === "failed" ||
            raw === "cancelled" ||
            raw === "timed_out"
          ) {
            status = "failed";
          } else if (raw === "running") {
            status = "running";
          } else {
            status = "failed";
          }
          setWorkflowStatus(exec.workflowId, {
            status,
            runAt: exec.startedAt,
            error: exec.errorMessage ?? undefined,
          });
        },
      );
    }
  }, [latestExecutionsData, setWorkflowStatus]);

  // ── Real-time Subscriptions ──────────────────────────────────────────────────

  useEffect(() => {
    if (!workflows.length) return;

    const unsubscribe = subscribeWorkflowExecutions((event) => {
      // Map backend status to frontend WorkflowRunStatus
      let status: WorkflowRunStatus["status"];
      if (event.status === "completed") {
        status = "success";
      } else if (
        event.status === "failed" ||
        event.status === "cancelled" ||
        event.status === "timed_out"
      ) {
        status = "failed";
      } else if (event.status === "running") {
        status = "running";
      } else {
        status = "failed";
      }

      // Immediate state update for the UI card
      setWorkflowStatus(event.workflowId, {
        status,
        runAt: event.startedAt,
        error: event.errorMessage,
      });

      // Invalidate the query to ensure secondary UI elements (e.g., stats panels) stay in sync
      queryClient.invalidateQueries({ queryKey: ["LatestWorkflowExecutions"] });

      // Feedback toast for major transitions
      if (status === "success") {
        toast.success(
          `Workflow complete: ${workflows.find((w) => w.id === event.workflowId)?.name || "Protocol"}`,
        );
      } else if (status === "failed") {
        toast.error(
          `Workflow failed: ${workflows.find((w) => w.id === event.workflowId)?.name || "Protocol"}`,
        );
      } else if (status === "running") {
        toast.info(
          `Workflow initiated: ${workflows.find((w) => w.id === event.workflowId)?.name || "Protocol"}`,
          {
            icon: <Activity size={14} className="text-primary" />,
            duration: 2000,
          },
        );
      }
    });

    return unsubscribe;
  }, [workflows, queryClient, setWorkflowStatus]);

  if (isLoading) {
    return (
      <div className="h-full overflow-auto bg-background relative text-foreground/80 custom-scrollbar">
        <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-surface-1 via-background to-background" />
        <div className="relative max-w-7xl mx-auto px-10 py-16">
          <div className="mb-12 h-12 w-80 rounded-2xl animate-pulse bg-surface-3/40" />
          <SkeletonStatRow className="mb-12" />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
            {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
              <div
                key={i}
                className="bg-surface-3/20 border border-white/5 rounded-[2.5rem] h-[300px] animate-pulse"
              />
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto bg-background relative text-foreground/80 custom-scrollbar">
      {/* Dynamic background */}
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-primary/10 via-background to-background opacity-50" />
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_bottom_left,_var(--tw-gradient-stops))] from-surface-2/20 via-transparent to-transparent opacity-30" />

      <div className="relative max-w-7xl mx-auto px-10 py-16 animate-in fade-in slide-in-from-bottom-4 duration-1000">
        {/* Header Section */}
        <header className="flex flex-col lg:flex-row lg:items-center justify-between gap-10 mb-16">
          <div className="space-y-4">
            <div className="flex items-center gap-6">
              <div className="w-16 h-16 rounded-[2rem] bg-primary/10 border border-primary/20 flex items-center justify-center shadow-[0_0_40px_hsla(var(--primary),0.1)] relative">
                <div className="absolute inset-0 bg-primary/5 rounded-full blur-2xl animate-pulse" />
                <Activity className="w-8 h-8 text-primary relative z-10" />
              </div>
              <div>
                <h1 className="text-5xl font-black text-white tracking-tighter font-outfit uppercase leading-none mb-2">
                  Control Center
                </h1>
                <div className="flex items-center gap-4">
                  {pendingApprovalCount > 0 && (
                    <button
                      onClick={() => navigate("/settings")}
                      className="px-4 py-1.5 text-[10px] font-black bg-warning/10 text-warning border border-warning/20 rounded-full uppercase tracking-[0.2em] hover:bg-warning/20 transition-premium animate-status-pulse shadow-[0_0_15px_hsla(var(--warning),0.3)]"
                    >
                      {pendingApprovalCount} Operational Gate
                      {pendingApprovalCount !== 1 ? "s" : ""}
                    </button>
                  )}
                  <div className="flex items-center gap-2 text-muted-foreground/40 font-black text-[10px] uppercase tracking-[0.3em]">
                    <span className="w-1.5 h-1.5 rounded-full bg-primary shadow-[0_0_8px_hsla(var(--primary),0.5)]" />
                    SYSTEM OPERATIONAL
                  </div>
                </div>
              </div>
            </div>
          </div>

          <button
            onClick={handleNew}
            className="px-10 py-5 bg-primary text-white text-xs font-black rounded-[1.5rem] transition-premium shadow-[0_15px_35px_-5px_hsla(var(--primary),0.4)] hover:shadow-[0_20px_45px_-5px_hsla(var(--primary),0.5)] hover:scale-105 active:scale-95 flex items-center gap-4 group border border-white/20 uppercase tracking-[0.2em]"
          >
            <div className="p-1 rounded-lg bg-white/20 group-hover:rotate-90 transition-premium">
              <Plus className="w-5 h-5" />
            </div>
            Provision Workflow
          </button>
        </header>

        {/* Top Panels Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-10 mb-16">
          <div className="lg:col-span-1">
            <ActorsPanel />
          </div>
          <div className="lg:col-span-3">
            <WorkflowStatsPanel />
          </div>
        </div>

        {/* Filter Bar */}
        <div className="flex flex-col xl:flex-row items-center gap-8 mb-12 p-3 bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2rem] shadow-2xl glass gpu">
          <div className="relative flex-1 w-full group/search">
            <div className="absolute -inset-0.5 bg-primary/20 rounded-2xl blur opacity-0 group-focus-within/search:opacity-100 transition-premium pointer-events-none" />
            <Search className="absolute left-6 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground/30 group-focus-within/search:text-primary transition-premium z-10" />
            <input
              type="text"
              placeholder="SEARCH AUTOMATED PIPELINES..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full bg-surface-4/40 border border-white/5 text-white rounded-2xl pl-16 pr-6 py-4 text-[11px] font-black uppercase tracking-[0.2em] focus:outline-none focus:border-primary/40 focus:ring-1 focus:ring-primary/40 transition-premium placeholder:text-muted-foreground/20 relative z-0"
            />
          </div>

          <div className="flex flex-col md:flex-row items-center gap-6 w-full xl:w-auto">
            <div className="relative group w-full md:w-56">
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
                className="w-full appearance-none bg-surface-4/40 border border-white/5 text-muted-foreground/60 rounded-2xl pl-6 pr-12 py-4 text-[10px] font-black uppercase tracking-[0.2em] focus:outline-none focus:border-primary/50 transition-premium cursor-pointer hover:text-white hover:bg-surface-4 hover:border-white/10"
              >
                <option value="name">SORT: IDENTIFIER</option>
                <option value="lastRun">SORT: RECENT</option>
                <option value="status">SORT: STATUS</option>
              </select>
              <ChevronDown className="absolute right-5 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground/30 pointer-events-none group-hover:text-primary transition-premium" />
            </div>

            <div className="flex p-1.5 bg-surface-4/40 rounded-2xl border border-white/5 shrink-0 overflow-x-auto no-scrollbar glass-light">
              {(["all", "success", "failed", "idle"] as const).map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={cn(
                    "px-6 py-2.5 text-[9px] font-black uppercase tracking-[0.2em] rounded-xl transition-premium whitespace-nowrap active:scale-95",
                    statusFilter === s
                      ? "bg-primary text-white shadow-xl shadow-primary/20"
                      : "text-muted-foreground/40 hover:text-white hover:bg-white/5",
                  )}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Workflow Grid */}
        <section className="relative">
          {workflows.length === 0 ? (
            <EmptyState onNew={handleNew} />
          ) : filteredWorkflows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-40 bg-surface-3/20 border border-white/5 rounded-[4rem] backdrop-blur-3xl glass-dark animate-in fade-in zoom-in-95 duration-700">
              <div className="w-24 h-24 rounded-[3rem] bg-surface-4/60 border border-white/10 flex items-center justify-center mb-10 shadow-2xl relative">
                <div className="absolute -inset-4 bg-primary/5 rounded-full blur-3xl opacity-50" />
                <Search className="w-12 h-12 text-muted-foreground/20 relative z-10" />
              </div>
              <h2 className="text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-4">
                No results found
              </h2>
              <p className="text-muted-foreground/40 text-sm max-w-sm font-bold uppercase tracking-widest leading-relaxed mb-10 text-center">
                The telemetry query &quot;{search.toUpperCase()}&quot; did not
                return any active automation pipelines.
              </p>
              <button
                onClick={() => {
                  setSearch("");
                  setStatusFilter("all");
                }}
                className="px-10 py-4 text-[10px] font-black text-primary uppercase tracking-[0.3em] hover:bg-primary/10 rounded-2xl transition-premium border border-primary/20 active:scale-95"
              >
                Reset System Filters
              </button>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-10">
              {filteredWorkflows.map((workflow) => (
                <WorkflowCard
                  key={workflow.id}
                  workflow={workflow}
                  runStatus={workflowStatuses[workflow.id]}
                  onEdit={() => handleEdit(workflow)}
                  onRun={() => handleRun(workflow)}
                  onHistory={() => setHistoryWorkflow(workflow)}
                  onVersions={() => setVersionsWorkflow(workflow)}
                  onDelete={() => setWorkflowToDelete(workflow)}
                  schedule={schedulesByWorkflowId[workflow.id]}
                  actorName={
                    workflow.actorId
                      ? actorIdToName[workflow.actorId]
                      : undefined
                  }
                />
              ))}

              {/* Add New Workflow Card */}
              <button
                onClick={handleNew}
                className="
                  group relative flex flex-col items-center justify-center gap-6
                  p-10 bg-surface-3/10 border-2 border-dashed border-white/10
                  rounded-[2.5rem] transition-premium
                  hover:bg-primary/5 hover:border-primary/40 hover:scale-[1.02]
                  active:scale-[0.98] min-h-[300px] backdrop-blur-3xl glass-dark
                "
              >
                <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium rounded-[2.5rem]" />
                <div className="w-20 h-20 rounded-[2rem] bg-surface-4 border border-white/10 text-muted-foreground/30 group-hover:text-primary group-hover:scale-110 group-hover:rotate-90 transition-premium flex items-center justify-center shadow-2xl relative z-10">
                  <Plus className="w-10 h-10" />
                </div>
                <div className="text-center relative z-10">
                  <span className="block text-xl font-black text-white/40 group-hover:text-white tracking-tighter font-outfit uppercase transition-premium">
                    New Workflow
                  </span>
                  <span className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-[0.4em] mt-2 block transition-premium group-hover:text-primary/40">
                    Provision Capacity
                  </span>
                </div>
              </button>
            </div>
          )}
        </section>
      </div>

      {/* Overlays */}
      <ConfirmDialog
        open={workflowToDelete !== null}
        title="Decommission Workflow"
        message={
          workflowToDelete
            ? `Confirming permanent decommissioning of "${workflowToDelete.name}". All operational data will be purged.`
            : ""
        }
        confirmLabel="Purge"
        destructive
        isLoading={deleteWorkflowMutation.isPending}
        onConfirm={() => {
          if (workflowToDelete)
            deleteWorkflowMutation.mutate({ id: workflowToDelete.id });
        }}
        onCancel={() => setWorkflowToDelete(null)}
      />

      <Suspense fallback={null}>
        {historyWorkflow && (
          <WorkflowExecutionHistory
            workflowId={historyWorkflow.id}
            workflowName={historyWorkflow.name}
            onClose={() => setHistoryWorkflow(null)}
          />
        )}
        {versionsWorkflow && (
          <WorkflowVersionsPanel
            workflowId={versionsWorkflow.id}
            workflowName={versionsWorkflow.name}
            onClose={() => setVersionsWorkflow(null)}
          />
        )}
      </Suspense>
    </div>
  );
}

const LIST_ACTORS = gql`
  query ListActors {
    actors {
      id
      name
      status
      executionCount
    }
  }
`;

const WORKFLOWS_QUERY = gql`
  query Workflows {
    workflows {
      id
      name
      graphJson
      actorId
      maxConcurrentExecutions
      intent
    }
  }
`;

const TRIGGER_WORKFLOW = gql`
  mutation TriggerWorkflow($workflowId: UUID!) {
    triggerWorkflow(workflowId: $workflowId) {
      id
      status
    }
  }
`;

const LATEST_WORKFLOW_EXECUTIONS = gql`
  query LatestWorkflowExecutions($workflowIds: [UUID!]!) {
    latestWorkflowExecutions(workflowIds: $workflowIds) {
      workflowId
      status
      startedAt
      errorMessage
    }
  }
`;
