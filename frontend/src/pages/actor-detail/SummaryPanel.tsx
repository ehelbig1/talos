import React, { useState, useMemo } from "react";
import { Textarea } from "@/components/ui/textarea";
import { Select } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Sparkles,
  Pencil,
  Play,
  Pause,
  Square,
  Activity,
  Save,
  CalendarClock,
  Copy,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { ConfirmDialog } from "@/components/ui";
import {
  updateActor,
  cloneActor,
  getMyCapabilityCeiling,
  type ActorDetails,
  type ActorActionLogEntry,
  type ActorWorkflowItem,
} from "@/lib/graphqlApi";
import {
  getCapabilityConfig,
  isAiWorkflow,
  ceilingOptions,
} from "@/lib/capabilityConfig";
import { useGetCapabilityWorldHierarchyQuery } from "@/generated/graphql";
import { ageDays } from "@/lib/formatTime";
import { CapabilityBadge } from "@/components/CapabilityBadge";
import {
  StatCard,
  ACTION_ICONS,
  humanizeLogEntry,
  relativeTime,
} from "./shared";

interface SummaryPanelProps {
  actor: ActorDetails;
  logEntries: ActorActionLogEntry[];
  workflows: ActorWorkflowItem[];
  onToggle: () => void;
  onTerminate: () => void;
  togglePending: boolean;
  terminatePending: boolean;
}

export function SummaryPanel({
  actor,
  logEntries,
  workflows,
  onToggle,
  onTerminate,
  togglePending,
  terminatePending,
}: SummaryPanelProps) {
  const [showTerminateConfirm, setShowTerminateConfirm] = useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const isTerminated = actor.status === "terminated";

  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState(actor.name);
  const [editDesc, setEditDesc] = useState(actor.description ?? "");
  const [editWorld, setEditWorld] = useState(actor.maxCapabilityWorld);
  const { data: ceilingWorld } = useQuery({
    queryKey: ["myCapabilityCeiling"],
    queryFn: getMyCapabilityCeiling,
    staleTime: 60_000,
  });
  const { data: hierarchyData } = useGetCapabilityWorldHierarchyQuery();
  const worldOptions = ceilingOptions(
    hierarchyData?.capabilityWorldHierarchy ?? [],
    ceilingWorld,
  );
  // An actor already holding a world the backend no longer serves keeps it
  // visible as its current value, but it cannot be re-selected.
  const editOptions = worldOptions.some(
    (o) => o.world === actor.maxCapabilityWorld,
  )
    ? worldOptions
    : [{ world: actor.maxCapabilityWorld, permitted: false }, ...worldOptions];

  const { mutate: doUpdate, isPending: updatePending } = useMutation({
    mutationFn: () =>
      updateActor(actor.id.toString(), {
        name: editName.trim() || undefined,
        description: editDesc,
        maxCapabilityWorld:
          editWorld !== actor.maxCapabilityWorld ? editWorld : undefined,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["actor", actor.id.toString()],
      });
      setEditing(false);
      toast.success("Actor updated");
    },
    onError: (e) => toast.error(sanitizeErrorMessage(String(e))),
  });

  const { mutate: doClone, isPending: clonePending } = useMutation({
    mutationFn: () => cloneActor(actor.id.toString()),
    onSuccess: (cloned) => {
      queryClient.invalidateQueries({ queryKey: ["actors"] });
      toast.success(`Cloned as "${cloned.name}" — click to open`, {
        action: {
          label: "Open",
          onClick: () => navigate(`/actors/${cloned.id}`),
        },
        duration: 6000,
      });
    },
    onError: (e) => toast.error(sanitizeErrorMessage(String(e))),
  });

  const isAiActor = useMemo(
    () => workflows.some((wf) => wf.graphJson && isAiWorkflow(wf.graphJson)),
    [workflows],
  );

  const recentEntries = logEntries.slice(0, 5);
  const ageDaysNum = ageDays(actor.createdAt);
  const ageLabel =
    ageDaysNum === 0
      ? "Today"
      : ageDaysNum === 1
        ? "1 day"
        : `${ageDaysNum} days`;

  return (
    <div className="space-y-8">
      <ConfirmDialog
        open={showTerminateConfirm}
        title="Delete actor"
        message={`Delete actor "${actor.name}"? Its workflows will stop running as it. This cannot be undone.`}
        confirmLabel="Delete actor"
        destructive
        isLoading={terminatePending}
        onConfirm={() => {
          setShowTerminateConfirm(false);
          onTerminate();
        }}
        onCancel={() => setShowTerminateConfirm(false)}
      />

      {/* Main Identity & Control Center */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left: Identity & Metadata */}
        <div className="lg:col-span-2 space-y-8">
          <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-8 relative overflow-hidden group">
            <div className="relative z-10">
              {editing ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-muted-foreground ml-1">
                        Name
                      </label>
                      <Input
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        maxLength={100}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs font-semibold text-muted-foreground ml-1">
                        Capability Ceiling
                      </label>
                      <Select
                        value={editWorld}
                        onChange={(e) => setEditWorld(e.target.value)}
                      >
                        {editOptions.map(({ world, permitted }) => (
                          <option
                            key={world}
                            value={world}
                            disabled={
                              !permitted && world !== actor.maxCapabilityWorld
                            }
                            className="bg-surface-4 text-white"
                          >
                            {getCapabilityConfig(world).label} Level
                          </option>
                        ))}
                      </Select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs font-semibold text-muted-foreground ml-1">
                      Functional Description
                    </label>
                    <Textarea
                      value={editDesc}
                      onChange={(e) => setEditDesc(e.target.value)}
                      rows={3}
                      placeholder="What does this actor do?"
                      className="resize-none"
                    />
                  </div>

                  <div className="flex gap-3 pt-2">
                    <Button
                      onClick={() => doUpdate()}
                      disabled={updatePending || !editName.trim()}
                    >
                      <Save className="w-4 h-4" />
                      {updatePending ? "Saving…" : "Save"}
                    </Button>
                    <Button
                      variant="outline"
                      onClick={() => {
                        setEditing(false);
                        setEditName(actor.name);
                        setEditDesc(actor.description ?? "");
                        setEditWorld(actor.maxCapabilityWorld);
                      }}
                    >
                      Cancel
                    </Button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-4">
                      <div className="flex items-center gap-3 flex-wrap">
                        <CapabilityBadge
                          world={actor.maxCapabilityWorld}
                          size="md"
                        />
                        {isAiActor && (
                          <span className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 text-primary text-2xs font-semibold uppercase tracking-wider px-3 py-1 shadow-sm">
                            <Sparkles className="w-3 h-3" />
                            Generated
                          </span>
                        )}
                      </div>
                      <h2 className="text-2xl font-semibold text-white tracking-tight leading-none group-hover:text-primary transition-colors">
                        {actor.name}
                      </h2>
                      {actor.description ? (
                        <p className="text-muted-foreground font-medium text-lg leading-relaxed max-w-2xl">
                          {actor.description}
                        </p>
                      ) : (
                        <p className="text-muted-foreground/60 font-semibold italic text-xs">
                          No description yet.
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="mt-8 pt-8 border-t border-white/5 flex flex-wrap gap-8">
                    <div className="space-y-1">
                      <div className="text-xs font-semibold text-muted-foreground/70">
                        Created
                      </div>
                      <div className="text-sm font-semibold text-white flex items-center gap-2">
                        <CalendarClock className="w-4 h-4 text-primary" />
                        {relativeTime(actor.createdAt)}
                      </div>
                    </div>
                    {actor.lastActiveAt && (
                      <div className="space-y-1">
                        <div className="text-xs font-semibold text-muted-foreground/70">
                          Last Activity
                        </div>
                        <div className="text-sm font-semibold text-white flex items-center gap-2">
                          <Activity className="w-4 h-4 text-success" />
                          {relativeTime(actor.lastActiveAt)}
                        </div>
                      </div>
                    )}
                  </div>

                  {!isTerminated && (
                    <div className="mt-8 flex items-center gap-4">
                      <button
                        onClick={() => setEditing(true)}
                        className="p-3 rounded-xl bg-surface-4/60 border border-white/5 text-muted-foreground hover:text-primary hover:bg-surface-4 hover:border-primary/20 transition-ui group/btn"
                        title="Edit actor"
                        aria-label="Edit actor"
                      >
                        <Pencil className="w-4 h-4 transition-transform" />
                      </button>
                      <button
                        onClick={() => doClone()}
                        disabled={clonePending}
                        className="p-3 rounded-xl bg-surface-4/60 border border-white/5 text-muted-foreground hover:text-info hover:bg-surface-4 hover:border-info/20 transition-ui group/btn disabled:opacity-30"
                        title="Duplicate actor"
                        aria-label="Duplicate actor"
                      >
                        <Copy className="w-4 h-4 transition-transform" />
                      </button>
                      <div className="h-6 w-px bg-white/5 mx-2" />
                      <button
                        onClick={() => setShowTerminateConfirm(true)}
                        className="p-3 rounded-xl bg-destructive/5 border border-destructive/10 text-destructive/60 hover:text-destructive hover:bg-destructive/10 transition-ui group/btn"
                        title="Delete actor"
                        aria-label="Delete actor"
                      >
                        <Square className="w-4 h-4 transition-transform" />
                      </button>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
            <StatCard
              label="Cycles"
              value={actor.executionCount}
              accent="text-primary"
            />
            <StatCard
              label="Logic Nodes"
              value={actor.workflowCount}
              accent="text-info"
            />
            <StatCard
              label="Auth Level"
              value={getCapabilityConfig(actor.maxCapabilityWorld).level}
              accent="text-success"
              sub={getCapabilityConfig(actor.maxCapabilityWorld).label}
            />
            <StatCard
              label="Persistence"
              value={ageLabel}
              accent="text-warning"
            />
          </div>
        </div>

        {/* Right: Quick Telemetry & Actions */}
        <div className="space-y-8">
          {/* Recent Activity Feed */}
          <div className="bg-surface-3/40 border border-white/5 rounded-2xl p-8 h-full">
            <div className="flex items-center justify-between mb-8">
              <h3 className="text-xs font-semibold text-white">
                Recent activity
              </h3>
              <Activity className="w-4 h-4 text-primary" />
            </div>

            {recentEntries.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/5 flex items-center justify-center text-muted-foreground/50 mb-4">
                  <Activity className="w-6 h-6" />
                </div>
                <p className="text-xs font-semibold text-muted-foreground/70">
                  No activity detected.
                </p>
              </div>
            ) : (
              <div className="space-y-6">
                {recentEntries.map((entry) => (
                  <div
                    key={entry.id}
                    className="flex items-start gap-4 group/entry"
                  >
                    <div className="w-8 h-8 rounded-xl bg-surface-4/60 border border-white/5 flex items-center justify-center text-primary shrink-0 transition-ui group-hover/entry:bg-primary/10 group-hover/entry:border-primary/20">
                      {ACTION_ICONS[entry.actionType.toLowerCase()] ?? (
                        <Activity className="w-3.5 h-3.5" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold text-white leading-snug truncate group-hover/entry:text-primary transition-colors">
                        {humanizeLogEntry(entry)}
                      </p>
                      <time className="text-xs font-medium text-muted-foreground/70 mt-1 block">
                        {relativeTime(entry.timestamp)}
                      </time>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {!isTerminated && (
              <div className="mt-12 pt-8 border-t border-white/5 space-y-4">
                <h3 className="text-xs font-semibold text-white mb-4">
                  Status
                </h3>
                <button
                  onClick={onToggle}
                  disabled={togglePending}
                  className={cn(
                    "w-full flex items-center justify-between p-4 rounded-2xl border transition-ui disabled:opacity-30",
                    actor.status === "active"
                      ? "bg-warning/5 border-warning/10 text-warning hover:bg-warning/10"
                      : "bg-success/5 border-success/10 text-success hover:bg-success/10",
                  )}
                >
                  <span className="text-xs font-semibold">
                    {actor.status === "active"
                      ? "Suspend actor"
                      : "Activate actor"}
                  </span>
                  {actor.status === "active" ? (
                    <Pause className="w-4 h-4" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )}
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
