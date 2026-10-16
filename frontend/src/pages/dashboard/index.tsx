import React, { useState, useMemo, lazy, Suspense } from "react";
import { Select } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { useNavigate } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { userFacingErrorMessage } from "@/lib/sanitize";

const WorkflowExecutionHistoryDialog = lazy(
  () => import("@/components/settings/WorkflowExecutionHistoryDialog"),
);
const WorkflowVersionsPanel = lazy(
  () => import("@/components/settings/WorkflowVersionsPanel"),
);
import { gql, subscribeWorkflowExecutions } from "@/lib/graphqlClient";
import { useEffect } from "react";
import type {
  ListActorsQuery,
  LatestWorkflowExecutionsQuery,
  MySchedulesQuery,
} from "@/generated/graphql";
import {
  useListActorsQuery,
  useTriggerWorkflowMutation,
  useDeleteWorkflowMutation,
  useGetApprovalsQuery,
  useMySchedulesQuery,
} from "@/generated/graphql";
import { useWorkflowStore } from "@/store/workflowStore";
import {
  Button,
  ConfirmDialog,
  PageHeader,
  SkeletonStatRow,
  PageContainer,
} from "@/components/ui";
import { usePersistedExecutionStore } from "@/store/executionStore";
import { cn } from "@/lib/utils";
import type { WorkflowRunStatus } from "@/store/executionStore";
import { Search, Plus, ChevronDown } from "lucide-react";

import WorkflowStatsPanel from "./WorkflowStatsPanel";
import ActorsPanel from "./ActorsPanel";
import WorkflowCard from "./WorkflowCard";
import {
  useDashboardWorkflows,
  useLatestExecutions,
} from "@/lib/dashboardData";
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
    onError: (err) => {
      // A refusal (running executions, referenced as a sub-workflow) says why.
      toast.error(userFacingErrorMessage(err, "Failed to delete workflow"));
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

  const { data: workflowsData, isLoading } = useDashboardWorkflows();
  const workflows = useMemo(
    () => workflowsData?.workflows ?? [],
    [workflowsData],
  );
  const workflowsTruncated = workflowsData?.truncated ?? false;

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
  const workflowIds = useMemo(() => workflows.map((w) => w.id), [workflows]);
  const { data: latestExecutionsData } = useLatestExecutions(workflowIds);

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
          `Workflow complete: ${workflows.find((w) => w.id === event.workflowId)?.name || "workflow"}`,
        );
      } else if (status === "failed") {
        toast.error(
          `Workflow failed: ${workflows.find((w) => w.id === event.workflowId)?.name || "workflow"}`,
        );
      } else if (status === "running") {
        toast.info(
          `Workflow started: ${workflows.find((w) => w.id === event.workflowId)?.name || "workflow"}`,
          { duration: 2000 },
        );
      }
    });

    return unsubscribe;
  }, [workflows, queryClient, setWorkflowStatus]);

  if (isLoading) {
    return (
      <div className="h-full overflow-auto bg-background text-foreground/80 custom-scrollbar">
        <PageContainer>
          <div className="mb-8 h-12 w-80 rounded-2xl animate-pulse bg-surface-3/40" />
          <SkeletonStatRow className="mb-8" />
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8">
            {[0, 1, 2, 3, 4, 5, 6, 7].map((i) => (
              <div
                key={i}
                className="bg-surface-3/20 border border-white/5 rounded-2xl h-[300px] animate-pulse"
              />
            ))}
          </div>
        </PageContainer>
      </div>
    );
  }

  return (
    <div className="h-full overflow-auto bg-background text-foreground/80 custom-scrollbar">
      <PageContainer>
        <PageHeader
          title="Workflows"
          description={
            <div className="flex items-center gap-3">
              <span>
                {workflows.length} workflow{workflows.length === 1 ? "" : "s"}
              </span>
              {pendingApprovalCount > 0 && (
                <button
                  onClick={() => navigate("/settings#approvals")}
                  className="px-2.5 py-0.5 text-xs font-medium bg-warning/10 text-warning border border-warning/20 rounded-full hover:bg-warning/20 transition-ui"
                >
                  {pendingApprovalCount} pending approval
                  {pendingApprovalCount !== 1 ? "s" : ""}
                </button>
              )}
            </div>
          }
          actions={
            <Button onClick={handleNew}>
              <Plus className="w-4 h-4" />
              New workflow
            </Button>
          }
        />

        {workflows.length > 0 && (
          <>
            {/* Top Panels Grid */}
            <div className="flex flex-col lg:flex-row gap-5 mb-8 empty:hidden">
              <ActorsPanel />
              <div className="flex-1 min-w-0">
                <WorkflowStatsPanel />
              </div>
            </div>

            {/* Filter Bar */}
            <div className="flex flex-col md:flex-row md:items-center gap-3 mb-8">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                <Input
                  type="search"
                  placeholder="Search workflows"
                  aria-label="Search workflows"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-9 pr-4"
                />
              </div>

              <div className="flex items-center gap-3">
                <div className="relative">
                  <Select
                    value={sortBy}
                    aria-label="Sort workflows"
                    onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
                    className="text-muted-foreground pl-3 pr-9"
                  >
                    <option value="name">Sort by name</option>
                    <option value="lastRun">Sort by last run</option>
                    <option value="status">Sort by status</option>
                  </Select>
                  <ChevronDown className="absolute right-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
                </div>

                <div
                  className="flex p-1 bg-surface-3/60 rounded-xl border border-white/10 shrink-0"
                  role="group"
                  aria-label="Filter by status"
                >
                  {(
                    [
                      ["all", "All"],
                      ["success", "Succeeded"],
                      ["failed", "Failed"],
                      ["idle", "Never run"],
                    ] as const
                  ).map(([s, label]) => (
                    <button
                      key={s}
                      onClick={() => setStatusFilter(s)}
                      aria-pressed={statusFilter === s}
                      className={cn(
                        "px-3 h-8 text-xs font-medium rounded-lg transition-ui whitespace-nowrap",
                        statusFilter === s
                          ? "bg-white/10 text-white"
                          : "text-muted-foreground hover:text-white",
                      )}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}

        {/* Workflow Grid */}
        <section className="relative">
          {workflowsTruncated && (
            <p role="status" className="mb-4 text-sm text-warning">
              Showing the first {workflows.length} workflows; more exist.
            </p>
          )}
          {workflows.length === 0 ? (
            <EmptyState onNew={handleNew} />
          ) : filteredWorkflows.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 bg-surface-3/40 border border-white/5 rounded-2xl">
              <div className="w-14 h-14 rounded-2xl bg-surface-4/60 border border-white/10 flex items-center justify-center mb-5">
                <Search className="w-6 h-6 text-muted-foreground" />
              </div>
              <h2 className="text-lg font-semibold text-white font-outfit mb-2">
                No matching workflows
              </h2>
              <p className="text-muted-foreground text-sm max-w-sm leading-relaxed mb-6 text-center">
                {search.trim()
                  ? `Nothing matches “${search.trim()}” with the current filter.`
                  : "Nothing matches the current filter."}
              </p>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setSearch("");
                  setStatusFilter("all");
                }}
              >
                Clear search and filters
              </Button>
            </div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-5">
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
                className="group flex flex-col items-center justify-center gap-4 p-8 bg-transparent border-2 border-dashed border-white/10 rounded-2xl transition-ui hover:bg-primary/5 hover:border-primary/40 min-h-[220px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/30"
              >
                <div className="w-12 h-12 rounded-xl bg-surface-4 border border-white/10 text-muted-foreground group-hover:text-primary transition-ui flex items-center justify-center">
                  <Plus className="w-6 h-6" />
                </div>
                <span className="text-sm font-medium text-muted-foreground group-hover:text-white transition-ui">
                  New workflow
                </span>
              </button>
            </div>
          )}
        </section>
      </PageContainer>

      {/* Overlays */}
      <ConfirmDialog
        open={workflowToDelete !== null}
        title="Delete workflow?"
        message={
          workflowToDelete
            ? `“${workflowToDelete.name}” and its run history will be deleted. This cannot be undone.`
            : ""
        }
        confirmLabel="Delete"
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
          <WorkflowExecutionHistoryDialog
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

const _LIST_ACTORS = gql`
  query ListActors {
    actors {
      id
      name
      status
      executionCount
    }
  }
`;

const _WORKFLOWS_QUERY = gql`
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

const _TRIGGER_WORKFLOW = gql`
  mutation TriggerWorkflow($workflowId: UUID!) {
    triggerWorkflow(workflowId: $workflowId) {
      id
      status
    }
  }
`;

const _LATEST_WORKFLOW_EXECUTIONS = gql`
  query LatestWorkflowExecutions($workflowIds: [UUID!]!) {
    latestWorkflowExecutions(workflowIds: $workflowIds) {
      workflowId
      status
      startedAt
      errorMessage
    }
  }
`;
