import React, { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQueryClient } from "@tanstack/react-query";
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
  type ActorDetails,
  type ActorActionLogEntry,
  type ActorWorkflowItem,
} from "@/lib/graphqlApi";
import {
  getCapabilityConfig,
  isAiWorkflow,
  CAPABILITY_WORLDS,
} from "@/lib/capabilityConfig";
import { ageDays } from "@/lib/formatTime";
import {
  statusColors,
  CapabilityBadge,
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
  const colors = statusColors(actor.status);
  const isTerminated = actor.status === "terminated";

  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState(actor.name);
  const [editDesc, setEditDesc] = useState(actor.description ?? "");
  const [editWorld, setEditWorld] = useState(actor.maxCapabilityWorld);

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
    <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
      <ConfirmDialog
        open={showTerminateConfirm}
        title="Decommission Protocol"
        message={`Permanently decommission identity "${actor.name}"? This will suspend all active operational threads and cannot be reversed.`}
        confirmLabel="Decommission"
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
          <div className="bg-surface-3/40 border border-white/5 rounded-[3rem] p-8 glass relative overflow-hidden group">
            <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50" />

            <div className="relative z-10">
              {editing ? (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="space-y-2">
                      <label className="text-[10px] font-black text-muted-foreground uppercase tracking-widest ml-1">
                        Identity Name
                      </label>
                      <input
                        value={editName}
                        onChange={(e) => setEditName(e.target.value)}
                        maxLength={100}
                        className="w-full bg-surface-4/60 border border-white/10 rounded-2xl px-5 py-3 text-sm text-white focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/50 transition-premium"
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-[10px] font-black text-muted-foreground uppercase tracking-widest ml-1">
                        Capability Ceiling
                      </label>
                      <select
                        value={editWorld}
                        onChange={(e) => setEditWorld(e.target.value)}
                        className="w-full bg-surface-4/60 border border-white/10 rounded-2xl px-5 py-3 text-sm text-white focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/50 transition-premium appearance-none cursor-pointer"
                      >
                        {Object.entries(CAPABILITY_WORLDS).map(([key, cfg]) => (
                          <option
                            key={key}
                            value={key}
                            className="bg-surface-4 text-white"
                          >
                            {cfg.label} Level
                          </option>
                        ))}
                      </select>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-[10px] font-black text-muted-foreground uppercase tracking-widest ml-1">
                      Functional Description
                    </label>
                    <textarea
                      value={editDesc}
                      onChange={(e) => setEditDesc(e.target.value)}
                      rows={3}
                      placeholder="Define identity operational parameters..."
                      className="w-full bg-surface-4/60 border border-white/10 rounded-2xl px-5 py-4 text-sm text-white placeholder-muted-foreground/30 focus:outline-none focus:ring-2 focus:ring-primary/20 focus:border-primary/50 transition-premium resize-none"
                    />
                  </div>

                  <div className="flex gap-3 pt-2">
                    <button
                      onClick={() => doUpdate()}
                      disabled={updatePending || !editName.trim()}
                      className="flex items-center gap-2 text-[10px] font-black uppercase tracking-widest bg-primary text-primary-foreground px-6 py-3 rounded-xl transition-premium hover:shadow-lg hover:shadow-primary/20 active:scale-95 disabled:opacity-50"
                    >
                      <Save className="w-4 h-4" />
                      {updatePending ? "Syncing..." : "Update Protocol"}
                    </button>
                    <button
                      onClick={() => {
                        setEditing(false);
                        setEditName(actor.name);
                        setEditDesc(actor.description ?? "");
                        setEditWorld(actor.maxCapabilityWorld);
                      }}
                      className="text-[10px] font-black uppercase tracking-widest text-muted-foreground bg-white/5 px-6 py-3 rounded-xl hover:bg-white/10 hover:text-foreground transition-premium active:scale-95"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <>
                  <div className="flex items-start justify-between gap-4">
                    <div className="space-y-4">
                      <div className="flex items-center gap-3 flex-wrap">
                        <CapabilityBadge world={actor.maxCapabilityWorld} />
                        {isAiActor && (
                          <span className="inline-flex items-center gap-2 rounded-full border border-primary/20 bg-primary/5 text-primary text-[9px] font-black uppercase tracking-widest px-3 py-1 shadow-sm">
                            <Sparkles className="w-3 h-3" />
                            AI Synthetic
                          </span>
                        )}
                      </div>
                      <h2 className="text-4xl font-black text-white tracking-tighter leading-none group-hover:text-primary transition-colors duration-500">
                        {actor.name}
                      </h2>
                      {actor.description ? (
                        <p className="text-muted-foreground font-medium text-lg leading-relaxed max-w-2xl">
                          {actor.description}
                        </p>
                      ) : (
                        <p className="text-muted-foreground/30 font-black uppercase tracking-widest italic text-xs">
                          No active operational parameters defined.
                        </p>
                      )}
                    </div>
                  </div>

                  <div className="mt-8 pt-8 border-t border-white/5 flex flex-wrap gap-8">
                    <div className="space-y-1">
                      <div className="text-[10px] font-black text-muted-foreground/40 uppercase tracking-widest">
                        Protocol Created
                      </div>
                      <div className="text-sm font-black text-white flex items-center gap-2">
                        <CalendarClock className="w-4 h-4 text-primary" />
                        {relativeTime(actor.createdAt)}
                      </div>
                    </div>
                    {actor.lastActiveAt && (
                      <div className="space-y-1">
                        <div className="text-[10px] font-black text-muted-foreground/40 uppercase tracking-widest">
                          Last Activity
                        </div>
                        <div className="text-sm font-black text-white flex items-center gap-2">
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
                        className="p-3 rounded-xl bg-surface-4/60 border border-white/5 text-muted-foreground hover:text-primary hover:bg-surface-4 hover:border-primary/20 transition-premium group/btn"
                        title="Modify Identity"
                      >
                        <Pencil className="w-4 h-4 group-hover/btn:scale-110 transition-transform" />
                      </button>
                      <button
                        onClick={() => doClone()}
                        disabled={clonePending}
                        className="p-3 rounded-xl bg-surface-4/60 border border-white/5 text-muted-foreground hover:text-sky-400 hover:bg-surface-4 hover:border-sky-400/20 transition-premium group/btn disabled:opacity-30"
                        title="Duplicate Prototype"
                      >
                        <Copy className="w-4 h-4 group-hover/btn:scale-110 transition-transform" />
                      </button>
                      <div className="h-6 w-px bg-white/5 mx-2" />
                      <button
                        onClick={() => setShowTerminateConfirm(true)}
                        className="p-3 rounded-xl bg-destructive/5 border border-destructive/10 text-destructive/60 hover:text-destructive hover:bg-destructive/10 transition-premium group/btn"
                        title="Terminate identity"
                      >
                        <Square className="w-4 h-4 group-hover/btn:scale-110 transition-transform" />
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
              accent="text-sky-400"
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
          <div className="bg-surface-3/40 border border-white/5 rounded-[3rem] p-8 glass h-full">
            <div className="flex items-center justify-between mb-8">
              <h3 className="text-xs font-black text-white uppercase tracking-widest">
                Live Telemetry
              </h3>
              <Activity className="w-4 h-4 text-primary animate-status-pulse" />
            </div>

            {recentEntries.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <div className="w-12 h-12 rounded-2xl bg-white/5 border border-white/5 flex items-center justify-center text-muted-foreground/20 mb-4">
                  <Activity className="w-6 h-6" />
                </div>
                <p className="text-[10px] font-black text-muted-foreground/40 uppercase tracking-widest">
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
                    <div className="w-8 h-8 rounded-xl bg-surface-4/60 border border-white/5 flex items-center justify-center text-primary shrink-0 transition-premium group-hover/entry:bg-primary/10 group-hover/entry:border-primary/20">
                      {ACTION_ICONS[entry.actionType.toLowerCase()] ?? (
                        <Activity className="w-3.5 h-3.5" />
                      )}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-black text-white leading-snug truncate group-hover/entry:text-primary transition-colors">
                        {humanizeLogEntry(entry)}
                      </p>
                      <time className="text-[9px] font-black text-muted-foreground/40 uppercase tracking-widest mt-1 block">
                        {relativeTime(entry.timestamp)}
                      </time>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {!isTerminated && (
              <div className="mt-12 pt-8 border-t border-white/5 space-y-4">
                <h3 className="text-xs font-black text-white uppercase tracking-widest mb-4">
                  Identity Controls
                </h3>
                <button
                  onClick={onToggle}
                  disabled={togglePending}
                  className={cn(
                    "w-full flex items-center justify-between p-4 rounded-2xl border transition-premium active:scale-[0.98] disabled:opacity-30",
                    actor.status === "active"
                      ? "bg-warning/5 border-warning/10 text-warning hover:bg-warning/10"
                      : "bg-success/5 border-success/10 text-success hover:bg-success/10",
                  )}
                >
                  <span className="text-[10px] font-black uppercase tracking-widest">
                    {actor.status === "active"
                      ? "Suspend Identity"
                      : "Deploy Identity"}
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
