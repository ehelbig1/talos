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
import { Button, PageContainer, PageHeader } from "@/components/ui";

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
      <div className="h-full overflow-auto bg-background custom-scrollbar">
        <PageContainer>
          <div className="space-y-12">
            <div className="h-12 w-80 rounded-2xl bg-surface-3/40 animate-shimmer" />
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
              {[0, 1, 2, 3].map((i) => (
                <div
                  key={i}
                  className="h-32 rounded-2xl bg-surface-3/20 border border-white/5 animate-shimmer"
                />
              ))}
            </div>
            <div className="h-[400px] rounded-2xl bg-surface-3/20 border border-white/5 animate-shimmer" />
          </div>
        </PageContainer>
      </div>
    );
  }

  if (error || !actor) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-6 bg-background">
        <div className="w-14 h-14 rounded-2xl bg-destructive/10 flex items-center justify-center text-destructive mb-4">
          <X className="w-7 h-7" />
        </div>
        <p className="text-xl font-semibold text-white tracking-tight">
          Actor not found
        </p>
        <p className="text-muted-foreground font-medium">
          This actor does not exist or you do not have access to it.
        </p>
        <Button onClick={() => navigate("/actors")}>
          <ChevronLeft className="w-4 h-4" /> Back to actors
        </Button>
      </div>
    );
  }

  const colors = statusColors(actor.status);
  const isTerminated = actor.status === "terminated";

  return (
    <div className="h-full overflow-auto bg-background custom-scrollbar">
      <PageContainer>
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
                <span className={cn("w-1.5 h-1.5 rounded-full", colors.dot)} />
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

        <div className="pt-8">
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
            <div>
              <WorkflowsPanel actorId={id!} />
            </div>
          )}
          {activeTab === "memory" && (
            <div>
              <MemoryPanel actorId={id!} />
            </div>
          )}
          {activeTab === "budget" && (
            <div>
              <BudgetPanel actorId={id!} actor={actor} />
            </div>
          )}
          {activeTab === "policies" && (
            <div>
              <PoliciesPanel />
            </div>
          )}
          {activeTab === "log" && (
            <div>
              <LogPanel actorId={id!} />
            </div>
          )}
          {activeTab === "handoffs" && (
            <div>
              <HandoffsPanel entries={logEntries} />
            </div>
          )}
        </div>
      </PageContainer>
    </div>
  );
}
