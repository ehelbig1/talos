import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { SectionHeader } from "@/components/ui/SectionHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Dialog } from "@/components/ui/dialog";
import { ConfirmDialog } from "@/components/ui/ConfirmDialog";
import {
  Clock,
  Calendar,
  Plus,
  Trash2,
  Edit2,
  X,
  ToggleLeft,
  ToggleRight,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { formatDate } from "@/lib/format";
import { relativeTime } from "@/lib/formatTime";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import type { WorkflowScheduleObj } from "@/generated/graphql";
import {
  useMySchedulesQuery,
  useCreateScheduleMutation,
  useUpdateScheduleMutation,
  useDeleteScheduleMutation,
  useWorkflowsQuery,
} from "@/generated/graphql";

// ─── Cron examples ────────────────────────────────────────────────────────────

const CRON_EXAMPLES = [
  { label: "Every hour", value: "0 * * * *" },
  { label: "Daily at midnight", value: "0 0 * * *" },
  { label: "Every Monday 9am", value: "0 9 * * 1" },
  { label: "Every 5 minutes", value: "*/5 * * * *" },
] as const;

// ─── Add Schedule Dialog ──────────────────────────────────────────────────────

interface AddScheduleDialogProps {
  open: boolean;
  onClose: () => void;
  workflows: Array<{ id: string; name: string }>;
}

function AddScheduleDialog({
  open,
  onClose,
  workflows,
}: AddScheduleDialogProps) {
  const queryClient = useQueryClient();
  const [workflowId, setWorkflowId] = useState("");
  const [cron, setCron] = useState("");
  const [timezone, setTimezone] = useState("UTC");

  const createMutation = useCreateScheduleMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["MySchedules"] });
      toast.success("Schedule created");
      onClose();
      setWorkflowId("");
      setCron("");
      setTimezone("UTC");
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to create schedule"),
      );
    },
  });

  const handleSubmit = () => {
    if (!workflowId || !cron) return;
    createMutation.mutate({ workflowId, cronExpression: cron, timezone });
  };

  const isValid = workflowId !== "" && cron.trim() !== "";

  return (
    <Dialog open={open} onClose={onClose}>
      <div
        className="bg-surface-3/95 backdrop-blur-3xl border border-white/10 shadow-[0_0_80px_rgba(0,0,0,0.6)] rounded-[2.5rem] overflow-hidden w-[560px] animate-in zoom-in-95 fade-in duration-300 relative"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="absolute inset-0 bg-gradient-to-br from-amber-500/10 via-transparent to-transparent opacity-50 pointer-events-none" />

        {/* Header */}
        <div className="px-10 py-8 border-b border-white/5 flex items-center justify-between bg-white/[0.02] relative z-10">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-amber-500/10 rounded-2xl flex items-center justify-center border border-amber-500/20 text-amber-500 shadow-[0_0_20px_hsla(var(--warning),0.1)]">
              <Clock size={24} />
            </div>
            <div>
              <h3 className="text-xl font-black text-white tracking-tight font-outfit uppercase">
                Temporal Protocol
              </h3>
              <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-[0.2em] mt-1">
                Automated Execution Sequence
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="w-10 h-10 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 text-muted-foreground hover:text-white transition-premium"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="p-10 space-y-8 relative z-10">
          {/* Workflow picker */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 ml-1">
              Target Workflow
            </label>
            <div className="relative group">
              <select
                value={workflowId}
                onChange={(e) => setWorkflowId(e.target.value)}
                className="w-full h-14 px-6 bg-black/40 border border-white/5 rounded-2xl text-xs font-black uppercase tracking-widest text-white focus:outline-none focus:border-amber-500/40 focus:ring-4 focus:ring-amber-500/10 transition-premium shadow-inner appearance-none cursor-pointer"
              >
                <option value="" disabled className="bg-surface-3">
                  SELECT_DESTINATION...
                </option>
                {workflows.map((wf) => (
                  <option key={wf.id} value={wf.id} className="bg-surface-3">
                    {wf.name.toUpperCase()}
                  </option>
                ))}
              </select>
              <div className="absolute right-5 top-1/2 -translate-y-1/2 pointer-events-none text-muted-foreground/30">
                <ChevronRight size={14} className="rotate-90" />
              </div>
            </div>
          </div>

          {/* Cron expression */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 ml-1">
              Cron Cadence
            </label>
            <Input
              placeholder="0 * * * * (MIN HR DAY MON WEEK)"
              value={cron}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setCron(e.target.value)
              }
              className="bg-black/40 border-white/5 focus:border-amber-500/40 focus:ring-amber-500/10 h-14 rounded-2xl text-xs font-black tracking-widest uppercase px-6"
            />

            {/* Cron example chips */}
            <div className="flex flex-wrap gap-2.5 pt-2">
              {CRON_EXAMPLES.map((ex) => (
                <button
                  key={ex.value}
                  onClick={() => setCron(ex.value)}
                  className={cn(
                    "px-4 py-2 rounded-xl border text-[9px] font-black uppercase tracking-widest transition-premium active:scale-95",
                    cron === ex.value
                      ? "bg-amber-500/10 border-amber-500/30 text-amber-400 shadow-lg shadow-amber-500/5"
                      : "bg-white/5 border-white/5 text-muted-foreground/40 hover:border-white/10 hover:text-white",
                  )}
                >
                  {ex.label}
                  <span className="ml-2 font-mono text-[8px] opacity-40">
                    [{ex.value}]
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Timezone */}
          <div className="space-y-3">
            <label className="text-[10px] font-black uppercase tracking-[0.3em] text-muted-foreground/40 ml-1">
              Temporal Zone
            </label>
            <Input
              placeholder="UTC"
              value={timezone}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setTimezone(e.target.value)
              }
              className="bg-black/40 border-white/5 focus:border-amber-500/40 focus:ring-amber-500/10 h-14 rounded-2xl text-xs font-black tracking-widest uppercase px-6"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="px-10 py-8 bg-white/[0.02] border-t border-white/5 flex justify-end gap-5 relative z-10">
          <Button
            variant="ghost"
            onClick={onClose}
            disabled={createMutation.isPending}
            className="text-[10px] font-black tracking-[0.2em] text-muted-foreground hover:text-white"
          >
            ABORT
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={createMutation.isPending || !isValid}
            variant="premium"
            className="px-10 h-14 shadow-2xl"
          >
            {createMutation.isPending
              ? "SYNCHRONIZING..."
              : "SYNTHESIZE SCHEDULE"}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}

// ─── Inline edit form ─────────────────────────────────────────────────────────

interface EditFormProps {
  schedule: WorkflowScheduleObj;
  onDone: () => void;
}

function EditForm({ schedule, onDone }: EditFormProps) {
  const queryClient = useQueryClient();
  const [cron, setCron] = useState(schedule.cronExpression);
  const [timezone, setTimezone] = useState(schedule.timezone);

  const updateMutation = useUpdateScheduleMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["MySchedules"] });
      toast.success("Schedule updated");
      onDone();
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to update schedule"),
      );
    },
  });

  const handleSave = () => {
    updateMutation.mutate({
      workflowId: schedule.workflowId,
      cronExpression: cron,
      timezone,
    });
  };

  return (
    <div className="mt-6 pt-6 border-t border-white/5 space-y-5 animate-in slide-in-from-top-2 duration-300">
      <div className="grid grid-cols-2 gap-5">
        <div className="space-y-2">
          <label className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/30 ml-1">
            CRON_CADENCE
          </label>
          <Input
            value={cron}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setCron(e.target.value)
            }
            className="bg-black/40 border-white/5 focus:border-amber-500/40 h-10 text-[11px] font-black tracking-widest uppercase rounded-xl px-4"
          />
        </div>
        <div className="space-y-2">
          <label className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/30 ml-1">
            TIME_ZONE
          </label>
          <Input
            value={timezone}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setTimezone(e.target.value)
            }
            className="bg-black/40 border-white/5 focus:border-amber-500/40 h-10 text-[11px] font-black tracking-widest uppercase rounded-xl px-4"
          />
        </div>
      </div>
      <div className="flex items-center gap-3 justify-end">
        <Button
          variant="ghost"
          size="sm"
          onClick={onDone}
          disabled={updateMutation.isPending}
          className="text-[9px] font-black tracking-widest h-9 px-4"
        >
          DISCARD
        </Button>
        <Button
          size="sm"
          onClick={handleSave}
          disabled={updateMutation.isPending || !cron.trim()}
          variant="premium"
          className="h-9 px-6 text-[9px]"
        >
          {updateMutation.isPending ? "UPDATING..." : "COMMIT CHANGES"}
        </Button>
      </div>
    </div>
  );
}

// ─── Schedule Card ────────────────────────────────────────────────────────────

interface ScheduleCardProps {
  schedule: WorkflowScheduleObj;
  workflowName: string;
}

function ScheduleCard({ schedule, workflowName }: ScheduleCardProps) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);

  const toggleMutation = useUpdateScheduleMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["MySchedules"] });
      toast.success(
        schedule.isEnabled ? "Schedule disabled" : "Schedule enabled",
      );
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to update schedule"),
      );
    },
  });

  const deleteMutation = useDeleteScheduleMutation({
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["MySchedules"] });
      toast.success("Schedule deleted");
      setConfirmDelete(false);
    },
    onError: (err: Error) => {
      toast.error(
        sanitizeErrorMessage(err.message || "Failed to delete schedule"),
      );
      setConfirmDelete(false);
    },
  });

  const handleToggle = () => {
    toggleMutation.mutate({
      workflowId: schedule.workflowId,
      isEnabled: !schedule.isEnabled,
    });
  };

  return (
    <>
      <div
        className={cn(
          "group bg-white/[0.02] border rounded-[2rem] p-8 hover:bg-white/[0.04] transition-premium relative overflow-hidden",
          schedule.isEnabled
            ? "border-amber-500/10 hover:border-amber-500/30"
            : "border-white/5 opacity-60 hover:opacity-100",
        )}
      >
        <div className="absolute inset-0 bg-gradient-to-r from-amber-500/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />

        <div className="flex items-start justify-between gap-6 relative z-10">
          {/* Left: workflow name + cron */}
          <div className="flex items-start gap-6 min-w-0">
            <div
              className={cn(
                "w-14 h-14 rounded-2xl flex items-center justify-center border shrink-0 shadow-2xl transition-premium group-hover:scale-110",
                schedule.isEnabled
                  ? "bg-amber-500/10 border-amber-500/20 text-amber-500 shadow-[0_0_20px_hsla(var(--warning),0.1)]"
                  : "bg-white/5 border-white/5 text-muted-foreground/30",
              )}
            >
              <Clock size={24} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-4 flex-wrap">
                <span className="text-xl font-black text-white tracking-tight font-outfit uppercase truncate group-hover:text-amber-400 transition-premium">
                  {workflowName}
                </span>
                <span
                  className={cn(
                    "text-[9px] font-black uppercase tracking-[0.2em] px-3 py-1 rounded-full border shadow-sm",
                    schedule.isEnabled
                      ? "bg-amber-500/10 border-amber-500/30 text-amber-400"
                      : "bg-white/5 border-white/10 text-muted-foreground/40",
                  )}
                >
                  {schedule.isEnabled ? "ACTIVE_SEQUENCE" : "PAUSED"}
                </span>
              </div>
              <div className="flex items-center gap-3 mt-3">
                <div className="flex items-center gap-2 text-xs font-black font-mono text-amber-400/70 bg-amber-500/5 border border-amber-500/10 px-3 py-1 rounded-xl">
                  {schedule.cronExpression}
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/20" />
                <span className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-widest">
                  ZONE: {schedule.timezone}
                </span>
              </div>
            </div>
          </div>

          {/* Right: actions */}
          <div className="flex items-center gap-3 shrink-0 pt-1">
            {/* Toggle */}
            <button
              type="button"
              onClick={handleToggle}
              disabled={toggleMutation.isPending}
              className={cn(
                "w-11 h-11 flex items-center justify-center rounded-2xl border transition-premium active:scale-90 shadow-xl",
                schedule.isEnabled
                  ? "bg-amber-500/10 border-amber-500/20 text-amber-400 hover:bg-amber-500/20"
                  : "bg-white/5 border-white/5 text-muted-foreground/30 hover:text-white hover:bg-white/10",
              )}
            >
              {toggleMutation.isPending ? (
                <div className="w-4 h-4 border-2 border-amber-500/20 border-t-amber-500 rounded-full animate-spin" />
              ) : schedule.isEnabled ? (
                <ToggleRight size={22} />
              ) : (
                <ToggleLeft size={22} />
              )}
            </button>
            {/* Edit */}
            <button
              type="button"
              onClick={() => setEditing((v) => !v)}
              className={cn(
                "w-11 h-11 flex items-center justify-center rounded-2xl border transition-premium active:scale-90 shadow-xl",
                editing
                  ? "bg-white/10 border-white/20 text-white"
                  : "bg-white/5 border-white/5 text-muted-foreground/40 hover:text-white hover:bg-white/10",
              )}
            >
              <Edit2 size={16} />
            </button>
            {/* Delete */}
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              className="w-11 h-11 flex items-center justify-center rounded-2xl border bg-white/5 border-white/5 text-muted-foreground/30 hover:text-destructive hover:border-destructive/30 hover:bg-destructive/10 transition-premium active:scale-90 shadow-xl"
            >
              <Trash2 size={16} />
            </button>
          </div>
        </div>

        {/* Timing info */}
        <div className="mt-8 flex items-center gap-8 pl-20 relative z-10">
          <div className="flex flex-col gap-1">
            <span className="text-[9px] font-black uppercase tracking-widest text-muted-foreground/20">
              NEXT_WINDOW
            </span>
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground font-black uppercase tracking-tighter">
              <Calendar className="w-3.5 h-3.5 opacity-30" />
              {schedule.nextTriggerAt
                ? formatDate(schedule.nextTriggerAt)
                : "—"}
            </div>
          </div>
          <div className="w-px h-8 bg-white/5" />
          <div className="flex flex-col gap-1">
            <span className="text-[9px] font-black uppercase tracking-widest text-muted-foreground/20">
              PREVIOUS_RUN
            </span>
            <div className="flex items-center gap-2 text-[11px] text-muted-foreground font-black uppercase tracking-tighter">
              <Clock className="w-3.5 h-3.5 opacity-30" />
              {relativeTime(schedule.lastTriggeredAt)}
            </div>
          </div>
        </div>

        {/* Inline edit form */}
        {editing && (
          <EditForm schedule={schedule} onDone={() => setEditing(false)} />
        )}
      </div>

      <ConfirmDialog
        open={confirmDelete}
        title="Terminate Schedule"
        message={`ABORT AUTOMATION SEQUENCE FOR "${workflowName.toUpperCase()}"? THIS ACTION WILL SUSPEND ALL SCHEDULED OPERATIONAL TASKS.`}
        confirmLabel="TERMINATE SEQUENCE"
        destructive
        isLoading={deleteMutation.isPending}
        onConfirm={() =>
          deleteMutation.mutate({ workflowId: schedule.workflowId })
        }
        onCancel={() => setConfirmDelete(false)}
      />
    </>
  );
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function SchedulesManager() {
  const [showAdd, setShowAdd] = useState(false);

  const { data: schedulesData, isLoading: schedulesLoading } =
    useMySchedulesQuery();
  const { data: workflowsData } = useWorkflowsQuery({});

  const schedules = schedulesData?.mySchedules ?? [];
  const workflows = React.useMemo(
    () => workflowsData?.workflows ?? [],
    [workflowsData],
  );

  // Build a quick-lookup map: workflowId → name
  const workflowNameMap = React.useMemo<Record<string, string>>(() => {
    const map: Record<string, string> = {};
    for (const wf of workflows) {
      map[String(wf.id)] = wf.name;
    }
    return map;
  }, [workflows]);

  return (
    <div className="max-w-6xl mx-auto py-4 space-y-10 animate-in fade-in slide-in-from-bottom-4 duration-700">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="w-16 h-16 bg-amber-500/10 border border-amber-500/20 rounded-[2rem] flex items-center justify-center text-amber-500 shadow-[0_0_30px_hsla(var(--warning),0.1)] relative">
            <div className="absolute inset-0 bg-amber-500/5 rounded-full blur-xl animate-pulse" />
            <Clock size={32} className="relative z-10" />
          </div>
          <div>
            <SectionHeader
              level="h2"
              className="text-3xl font-black text-white tracking-tighter font-outfit uppercase mb-1"
            >
              Scheduled Sequences
            </SectionHeader>
            <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.3em]">
              Autonomous Operational Automation
            </p>
          </div>
        </div>
        <Button
          onClick={() => setShowAdd(true)}
          variant="premium"
          className="h-14 px-8 shadow-2xl"
        >
          <Plus className="w-5 h-5 mr-2" />
          Establish Schedule
        </Button>
      </div>

      {/* Content */}
      {schedulesLoading ? (
        <div className="flex flex-col items-center justify-center py-32 gap-6">
          <div className="w-16 h-16 border-4 border-amber-500/10 border-t-amber-500 rounded-full animate-spin shadow-2xl" />
          <p className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.4em] animate-status-pulse">
            Synchronizing Time-Stream...
          </p>
        </div>
      ) : schedules.length === 0 ? (
        <div className="bg-surface-3/20 backdrop-blur-3xl border border-white/5 rounded-[3rem] p-24 glass-dark text-center flex flex-col items-center">
          <div className="w-24 h-24 rounded-[3rem] bg-white/[0.02] border border-white/5 flex items-center justify-center text-muted-foreground/10 mb-8 shadow-2xl">
            <Calendar size={48} />
          </div>
          <h3 className="text-2xl font-black text-white tracking-tight uppercase mb-4">
            No Automation Detected
          </h3>
          <p className="text-sm text-muted-foreground/40 font-bold uppercase tracking-widest max-w-sm mb-10 leading-relaxed">
            Temporal sequences are not currently initialized. Establish a
            schedule to automate complex workflow operations.
          </p>
          <Button
            onClick={() => setShowAdd(true)}
            variant="premium"
            className="px-10 h-14"
          >
            <Plus className="w-5 h-5 mr-2" />
            Configure First Sequence
          </Button>
        </div>
      ) : (
        <div className="space-y-4">
          {schedules.map((schedule) => (
            <ScheduleCard
              key={schedule.id}
              schedule={schedule}
              workflowName={
                workflowNameMap[String(schedule.workflowId)] ??
                `Sequence ${String(schedule.workflowId).slice(0, 8)}`
              }
            />
          ))}
        </div>
      )}

      {/* Summary strip */}
      {schedules.length > 0 && (
        <div className="flex items-center gap-10 px-10 py-6 bg-surface-3/40 border border-white/5 rounded-[2rem] relative overflow-hidden group">
          <div className="absolute inset-0 bg-gradient-to-r from-amber-500/5 via-transparent to-transparent opacity-30 pointer-events-none" />

          <div className="flex items-center gap-3 relative z-10">
            <div className="w-2 h-2 rounded-full bg-amber-500 shadow-[0_0_8px_hsla(var(--warning),0.5)]" />
            <span className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.2em]">
              <strong className="text-white">{schedules.length}</strong>{" "}
              TOTAL_SEQUENCES
            </span>
          </div>

          <div className="flex items-center gap-3 relative z-10">
            <div className="w-2 h-2 rounded-full bg-success shadow-[0_0_8px_hsla(var(--success),0.5)]" />
            <span className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.2em]">
              <strong className="text-white">
                {schedules.filter((s) => s.isEnabled).length}
              </strong>{" "}
              ACTIVE_NODES
            </span>
          </div>

          <div className="flex items-center gap-3 relative z-10">
            <div className="w-2 h-2 rounded-full bg-white/10" />
            <span className="text-[10px] text-muted-foreground/40 font-black uppercase tracking-[0.2em]">
              <strong className="text-white">
                {schedules.filter((s) => !s.isEnabled).length}
              </strong>{" "}
              SUSPENDED
            </span>
          </div>

          <div className="ml-auto relative z-10">
            <span className="text-[10px] text-muted-foreground/20 font-black uppercase tracking-[0.4em]">
              TEMPORAL_MONITOR_ONLINE
            </span>
          </div>
        </div>
      )}

      {/* Add dialog */}
      <AddScheduleDialog
        open={showAdd}
        onClose={() => setShowAdd(false)}
        workflows={workflows.map((wf) => ({
          id: String(wf.id),
          name: wf.name,
        }))}
      />
    </div>
  );
}
