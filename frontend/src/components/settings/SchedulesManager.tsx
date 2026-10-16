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
        className="bg-surface-3/95 border border-white/10 rounded-2xl overflow-hidden w-[560px] relative"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-10 py-8 border-b border-white/5 flex items-center justify-between bg-white/[0.02] relative z-10">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 bg-warning/10 rounded-2xl flex items-center justify-center border border-warning/20 text-warning">
              <Clock size={24} />
            </div>
            <div>
              <h3 className="text-xl font-semibold text-white tracking-tight font-outfit">
                New schedule
              </h3>
              <p className="text-xs text-muted-foreground/70 font-bold mt-1">
                Run a workflow on a cron schedule
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="w-10 h-10 flex items-center justify-center rounded-xl bg-white/5 border border-white/10 text-muted-foreground hover:text-white transition-ui"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="p-10 space-y-8 relative z-10">
          {/* Workflow picker */}
          <div className="space-y-3">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Target Workflow
            </label>
            <div className="relative group">
              <select
                value={workflowId}
                onChange={(e) => setWorkflowId(e.target.value)}
                className="w-full h-14 px-6 bg-black/40 border border-white/5 rounded-2xl text-sm font-semibold text-white focus:outline-none focus:border-warning/40 focus:ring-4 focus:ring-warning/10 transition-ui appearance-none cursor-pointer"
              >
                <option value="" disabled className="bg-surface-3">
                  Select a workflow…
                </option>
                {workflows.map((wf) => (
                  <option key={wf.id} value={wf.id} className="bg-surface-3">
                    {wf.name}
                  </option>
                ))}
              </select>
              <div className="absolute right-5 top-1/2 -translate-y-1/2 pointer-events-none text-muted-foreground/60">
                <ChevronRight size={14} className="rotate-90" />
              </div>
            </div>
          </div>

          {/* Cron expression */}
          <div className="space-y-3">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Cron Cadence
            </label>
            <Input
              placeholder="0 * * * * (MIN HR DAY MON WEEK)"
              value={cron}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setCron(e.target.value)
              }
              className="bg-black/40 border-white/5 focus:border-warning/40 focus:ring-warning/10 h-14 rounded-2xl text-sm font-semibold px-6"
            />

            {/* Cron example chips */}
            <div className="flex flex-wrap gap-2.5 pt-2">
              {CRON_EXAMPLES.map((ex) => (
                <button
                  key={ex.value}
                  onClick={() => setCron(ex.value)}
                  className={cn(
                    "px-4 py-2 rounded-xl border text-2xs font-semibold transition-ui",
                    cron === ex.value
                      ? "bg-warning/10 border-warning/30 text-warning shadow-warning/5"
                      : "bg-white/5 border-white/5 text-muted-foreground/70 hover:border-white/10 hover:text-white",
                  )}
                >
                  {ex.label}
                  <span className="ml-2 font-mono text-2xs opacity-40">
                    [{ex.value}]
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* Timezone */}
          <div className="space-y-3">
            <label className="text-xs font-semibold text-muted-foreground/70 ml-1">
              Time zone
            </label>
            <Input
              placeholder="UTC"
              value={timezone}
              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                setTimezone(e.target.value)
              }
              className="bg-black/40 border-white/5 focus:border-warning/40 focus:ring-warning/10 h-14 rounded-2xl text-sm font-semibold px-6"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="px-10 py-8 bg-white/[0.02] border-t border-white/5 flex justify-end gap-5 relative z-10">
          <Button
            variant="ghost"
            onClick={onClose}
            disabled={createMutation.isPending}
            className="text-xs font-semibold tracking-wider text-muted-foreground hover:text-white"
          >
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={createMutation.isPending || !isValid}
            className="px-10 h-14"
          >
            {createMutation.isPending ? "Creating…" : "Create schedule"}
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
    <div className="mt-6 pt-6 border-t border-white/5 space-y-5">
      <div className="grid grid-cols-2 gap-5">
        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground/60 ml-1">
            Cron expression
          </label>
          <Input
            value={cron}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setCron(e.target.value)
            }
            className="bg-black/40 border-white/5 focus:border-warning/40 h-10 text-sm font-semibold rounded-xl px-4"
          />
        </div>
        <div className="space-y-2">
          <label className="text-xs font-medium text-muted-foreground/60 ml-1">
            Time zone
          </label>
          <Input
            value={timezone}
            onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
              setTimezone(e.target.value)
            }
            className="bg-black/40 border-white/5 focus:border-warning/40 h-10 text-sm font-semibold rounded-xl px-4"
          />
        </div>
      </div>
      <div className="flex items-center gap-3 justify-end">
        <Button
          variant="ghost"
          size="sm"
          onClick={onDone}
          disabled={updateMutation.isPending}
          className="text-2xs font-semibold tracking-wider h-9 px-4"
        >
          Cancel
        </Button>
        <Button
          size="sm"
          onClick={handleSave}
          disabled={updateMutation.isPending || !cron.trim()}
          className="h-9 px-6 text-2xs"
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
          "group bg-white/[0.02] border rounded-2xl p-8 hover:bg-white/[0.04] transition-ui relative overflow-hidden",
          schedule.isEnabled
            ? "border-warning/10 hover:border-warning/30"
            : "border-white/5 opacity-60 hover:opacity-100",
        )}
      >
        <div className="flex items-start justify-between gap-6 relative z-10">
          {/* Left: workflow name + cron */}
          <div className="flex items-start gap-6 min-w-0">
            <div
              className={cn(
                "w-14 h-14 rounded-2xl flex items-center justify-center border shrink-0 transition-ui",
                schedule.isEnabled
                  ? "bg-warning/10 border-warning/20 text-warning"
                  : "bg-white/5 border-white/5 text-muted-foreground/60",
              )}
            >
              <Clock size={24} />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-4 flex-wrap">
                <span className="text-xl font-semibold text-white font-outfit truncate group-hover:text-warning transition-ui">
                  {workflowName}
                </span>
                <span
                  className={cn(
                    "text-2xs font-semibold uppercase tracking-wider px-3 py-1 rounded-full border shadow-sm",
                    schedule.isEnabled
                      ? "bg-warning/10 border-warning/30 text-warning"
                      : "bg-white/5 border-white/10 text-muted-foreground/70",
                  )}
                >
                  {schedule.isEnabled ? "Enabled" : "Paused"}
                </span>
              </div>
              <div className="flex items-center gap-3 mt-3">
                <div className="flex items-center gap-2 text-xs font-semibold font-mono text-warning/70 bg-warning/5 border border-warning/10 px-3 py-1 rounded-xl">
                  {schedule.cronExpression}
                </div>
                <ChevronRight className="w-3.5 h-3.5 text-muted-foreground/50" />
                <span className="text-xs text-muted-foreground/70 font-semibold">
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
                "w-11 h-11 flex items-center justify-center rounded-2xl border transition-ui",
                schedule.isEnabled
                  ? "bg-warning/10 border-warning/20 text-warning hover:bg-warning/20"
                  : "bg-white/5 border-white/5 text-muted-foreground/60 hover:text-white hover:bg-white/10",
              )}
            >
              {toggleMutation.isPending ? (
                <div className="w-4 h-4 border-2 border-warning/20 border-t-warning rounded-full animate-spin" />
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
              aria-label="Edit schedule"
              aria-pressed={editing}
              className={cn(
                "w-11 h-11 flex items-center justify-center rounded-2xl border transition-ui",
                editing
                  ? "bg-white/10 border-white/20 text-white"
                  : "bg-white/5 border-white/5 text-muted-foreground/70 hover:text-white hover:bg-white/10",
              )}
            >
              <Edit2 size={16} />
            </button>
            {/* Delete */}
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              aria-label="Delete schedule"
              className="w-11 h-11 flex items-center justify-center rounded-2xl border bg-white/5 border-white/5 text-muted-foreground/60 hover:text-destructive hover:border-destructive/30 hover:bg-destructive/10 transition-ui"
            >
              <Trash2 size={16} />
            </button>
          </div>
        </div>

        {/* Timing info */}
        <div className="mt-8 flex items-center gap-8 pl-20 relative z-10">
          <div className="flex flex-col gap-1">
            <span className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/50">
              Next run
            </span>
            <div className="flex items-center gap-2 text-xs text-muted-foreground font-semibold tracking-tighter">
              <Calendar className="w-3.5 h-3.5 opacity-30" />
              {schedule.nextTriggerAt
                ? formatDate(schedule.nextTriggerAt)
                : "—"}
            </div>
          </div>
          <div className="w-px h-8 bg-white/5" />
          <div className="flex flex-col gap-1">
            <span className="text-2xs font-semibold uppercase tracking-wider text-muted-foreground/50">
              Last run
            </span>
            <div className="flex items-center gap-2 text-xs text-muted-foreground font-semibold tracking-tighter">
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
        title="Delete schedule"
        message={`Delete the schedule for "${workflowName}"? The workflow will no longer run on this schedule.`}
        confirmLabel="Delete schedule"
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
    <div className="max-w-6xl mx-auto py-4 space-y-10">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="w-16 h-16 bg-warning/10 border border-warning/20 rounded-2xl flex items-center justify-center text-warning relative">
            <Clock size={32} className="relative z-10" />
          </div>
          <div>
            <SectionHeader
              level="h2"
              className="text-3xl font-semibold text-white tracking-tight font-outfit mb-1"
            >
              Schedules
            </SectionHeader>
            <p className="text-xs text-muted-foreground/70 font-semibold">
              Workflows that run on a timer
            </p>
          </div>
        </div>
        <Button onClick={() => setShowAdd(true)} className="h-14 px-8">
          <Plus className="w-5 h-5 mr-2" />
          New schedule
        </Button>
      </div>

      {/* Content */}
      {schedulesLoading ? (
        <div className="flex flex-col items-center justify-center py-32 gap-6">
          <div className="w-16 h-16 border-4 border-warning/10 border-t-warning rounded-full animate-spin" />
          <p className="text-xs text-muted-foreground/70 font-semibold">
            Synchronizing Time-Stream...
          </p>
        </div>
      ) : schedules.length === 0 ? (
        <div className="bg-surface-3/20 border border-white/5 rounded-2xl p-24 bg-surface-3 border border-white/10 text-center flex flex-col items-center">
          <div className="w-24 h-24 rounded-2xl bg-white/[0.02] border border-white/5 flex items-center justify-center text-muted-foreground/30 mb-8">
            <Calendar size={48} />
          </div>
          <h3 className="text-2xl font-semibold text-white tracking-tight mb-4">
            No schedules yet
          </h3>
          <p className="text-sm text-muted-foreground/70 max-w-sm mb-10 leading-relaxed">
            Create a schedule to run a workflow automatically.
          </p>
          <Button onClick={() => setShowAdd(true)} className="px-10 h-14">
            <Plus className="w-5 h-5 mr-2" />
            Create schedule
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
                `Workflow ${String(schedule.workflowId).slice(0, 8)}`
              }
            />
          ))}
        </div>
      )}

      {/* Summary strip */}
      {schedules.length > 0 && (
        <div className="flex items-center gap-10 px-10 py-6 bg-surface-3/40 border border-white/5 rounded-2xl relative overflow-hidden group">
          <div className="flex items-center gap-3 relative z-10">
            <div className="w-2 h-2 rounded-full bg-warning" />
            <span className="text-xs text-muted-foreground/70 font-semibold">
              <strong className="text-white">{schedules.length}</strong>{" "}
              schedules
            </span>
          </div>

          <div className="flex items-center gap-3 relative z-10">
            <div className="w-2 h-2 rounded-full bg-success" />
            <span className="text-xs text-muted-foreground/70 font-semibold">
              <strong className="text-white">
                {schedules.filter((s) => s.isEnabled).length}
              </strong>{" "}
              enabled
            </span>
          </div>

          <div className="flex items-center gap-3 relative z-10">
            <div className="w-2 h-2 rounded-full bg-white/10" />
            <span className="text-xs text-muted-foreground/70 font-semibold">
              <strong className="text-white">
                {schedules.filter((s) => !s.isEnabled).length}
              </strong>{" "}
              paused
            </span>
          </div>

          <div className="ml-auto relative z-10">
            <span className="text-xs text-muted-foreground/50 font-semibold">
              Scheduler running
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
