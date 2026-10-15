import React, { useState, useMemo } from "react";
import { useParams, useNavigate } from "react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ChevronLeft, X } from "lucide-react";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { cn } from "@/lib/utils";
import {
  getActor,
  updateActorStatus,
  terminateActor,
  getActorWorkflows,
  getActorActionLog,
  type ActorDetails,
  type ActorActionLogEntry,
  type ActorWorkflowItem,
} from "@/lib/graphqlApi";

import { statusColors, TabBar, type Tab } from "./actor-detail/shared";
import { SummaryPanel } from "./actor-detail/SummaryPanel";
import { WorkflowsPanel } from "./actor-detail/WorkflowsPanel";
import { MemoryPanel } from "./actor-detail/MemoryPanel";
import { BudgetPanel } from "./actor-detail/BudgetPanel";
import { PoliciesPanel } from "./actor-detail/PoliciesPanel";
import { LogPanel } from "./actor-detail/LogPanel";
import { HandoffsPanel } from "./actor-detail/HandoffsPanel";
import { Button, PageHeader } from "@/components/ui";

export default function ActorDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<Tab>("summary");

  const {
    data: actor,
    isLoading,
    error,
  } = useQuery<ActorDetails>({
    queryKey: ["actor", id],
    queryFn: () => getActor(id!),
    enabled: !!id,
  });

  const { data: workflows = [] } = useQuery<ActorWorkflowItem[]>({
    queryKey: ["actorWorkflows", id],
    queryFn: () => getActorWorkflows(id!),
    enabled: !!id,
  });

  const { data: logEntries = [] } = useQuery<ActorActionLogEntry[]>({
    queryKey: ["actorActionLog", id, 50],
    queryFn: () => getActorActionLog(id!, 50),
    enabled: !!id,
  });

  const toggleMut = useMutation({
    mutationFn: (status: "active" | "suspended") =>
      updateActorStatus(id!, status),
    onSuccess: (updated) => {
      queryClient.invalidateQueries({ queryKey: ["actor", id] });
      queryClient.invalidateQueries({ queryKey: ["actors"] });
      toast.success(`Actor is now ${updated.status}`);
    },
    onError: (e: Error) => toast.error(sanitizeErrorMessage(e.message)),
  });

  const terminateMut = useMutation({
    mutationFn: () => terminateActor(id!, false),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["actors"] });
      toast.success("Actor deleted");
      navigate("/actors");
    },
    onError: (e: Error) => toast.error(sanitizeErrorMessage(e.message)),
  });

  const handoffEntries = useMemo(
    () =>
      logEntries.filter((e) => e.actionType.toLowerCase().includes("handoff")),
    [logEntries],
  );
  const showHandoffs = handoffEntries.length > 0;

  if (isLoading) {
    return (
      <div className="flex flex-col h-full bg-background overflow-hidden">
        <div className="h-24 w-full bg-surface-3/40 border-b border-white/5 animate-shimmer" />
        <div className="flex-1 p-8 pt-12">
          <div className="max-w-7xl mx-auto space-y-12">
            <div className="grid grid-cols-4 gap-6">
              {[0, 1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="h-32 rounded-2xl bg-surface-3/20 border border-white/5 animate-shimmer"
                />
              ))}
            </div>
            <div className="h-[400px] rounded-3xl bg-surface-3/20 border border-white/5 animate-shimmer" />
          </div>
        </div>
      </div>
    );
  }

  if (error || !actor) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-6 bg-background">
        <div className="w-16 h-16 rounded-2xl bg-destructive/10 flex items-center justify-center text-destructive mb-4">
          <X className="w-8 h-8" />
        </div>
        <p className="text-xl font-semibold text-white tracking-tight">
          Actor not found
        </p>
        <p className="text-muted-foreground font-medium">
          This actor does not exist or you do not have access to it.
        </p>
        <button
          onClick={() => navigate("/actors")}
          className="px-6 py-2.5 text-sm font-semibold text-primary-foreground bg-primary rounded-xl transition-premium flex items-center gap-2"
        >
          <ChevronLeft className="w-4 h-4" /> Return to Registry
        </button>
      </div>
    );
  }

  const colors = statusColors(actor.status);
  const isTerminated = actor.status === "terminated";

  return (
    <div className="flex flex-col h-full bg-background overflow-hidden relative">
      <div className="fixed inset-0 pointer-events-none bg-[radial-gradient(ellipse_at_top_right,_var(--tw-gradient-stops))] from-primary/5 via-background to-background opacity-50" />

      <div className="w-full max-w-7xl mx-auto px-6 md:px-8 pt-6 shrink-0 relative z-30">
        <PageHeader
          backTo={{ to: "/actors", label: "Actors" }}
          title={
            <span className="inline-flex items-center gap-3 flex-wrap">
              {actor.name}
              <span
                className={cn(
                  "px-2.5 py-0.5 rounded-full border border-white/5 text-xs font-semibold inline-flex items-center gap-2 align-middle",
                  colors.badge,
                )}
              >
                <span
                  className={cn(
                    "w-1.5 h-1.5 rounded-full",
                    colors.dot,
                    actor.status === "active" && "animate-status-pulse",
                  )}
                />
                {actor.status}
              </span>
            </span>
          }
          description={actor.description || "No description"}
          actions={
            !isTerminated && (
              <Button
                variant="outline"
                onClick={() =>
                  toggleMut.mutate(
                    actor.status === "active" ? "suspended" : "active",
                  )
                }
                disabled={toggleMut.isPending}
              >
                {toggleMut.isPending
                  ? "Saving…"
                  : actor.status === "active"
                    ? "Suspend actor"
                    : "Activate actor"}
              </Button>
            )
          }
          className="mb-4"
        />
      </div>

      {/* Tabs Sticky Bar */}
      <TabBar
        active={activeTab}
        onChange={setActiveTab}
        counts={{
          workflows: workflows.length,
          log: logEntries.length,
          handoffs: handoffEntries.length,
        }}
        showHandoffs={showHandoffs}
      />

      {/* Content Area */}
      <div className="flex-1 overflow-auto custom-scrollbar relative z-10">
        <div className="max-w-7xl mx-auto px-8 py-8">
          {activeTab === "summary" && (
            <SummaryPanel
              actor={actor}
              logEntries={logEntries}
              workflows={workflows}
              onToggle={() =>
                toggleMut.mutate(
                  actor.status === "active" ? "suspended" : "active",
                )
              }
              onTerminate={() => terminateMut.mutate()}
              togglePending={toggleMut.isPending}
              terminatePending={terminateMut.isPending}
            />
          )}
          {activeTab === "workflows" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <WorkflowsPanel actorId={id!} />
            </div>
          )}
          {activeTab === "memory" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <MemoryPanel actorId={id!} />
            </div>
          )}
          {activeTab === "budget" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <BudgetPanel actorId={id!} actor={actor} />
            </div>
          )}
          {activeTab === "policies" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <PoliciesPanel />
            </div>
          )}
          {activeTab === "log" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <LogPanel actorId={id!} />
            </div>
          )}
          {activeTab === "handoffs" && (
            <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
              <HandoffsPanel entries={logEntries} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
