import React, { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  Clock,
  CheckCircle2,
  XCircle,
  UserCheck,
  History,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Check,
  X,
  User,
  ExternalLink,
  Zap,
} from "lucide-react";
import { cn } from "@/lib/utils";

import {
  useGetApprovalsQuery,
  useApproveExecutionMutation,
  useDenyExecutionMutation,
} from "@/generated/graphql";

type Tab = "pending" | "decided";

export function ApprovalQueue() {
  const [activeTab, setActiveTab] = useState<Tab>("pending");
  const queryClient = useQueryClient();

  const { data, isLoading } = useGetApprovalsQuery(
    {},
    {
      refetchInterval: 10_000,
      refetchOnWindowFocus: true,
    },
  );

  const approvals = data?.pendingApprovals ?? [];

  const approveMutation = useApproveExecutionMutation({
    onSuccess: () => {
      toast.success("Execution authorized");
      queryClient.invalidateQueries({ queryKey: ["GetApprovals"] });
    },
    onError: () => {
      toast.error("Failed to authorize execution");
    },
  });

  const denyMutation = useDenyExecutionMutation({
    onSuccess: () => {
      toast.success("Execution rejected");
      queryClient.invalidateQueries({ queryKey: ["GetApprovals"] });
    },
    onError: () => {
      toast.error("Failed to reject execution");
    },
  });

  const handleDecision = (
    approvalId: string,
    decision: "approved" | "denied",
  ) => {
    if (decision === "approved") {
      approveMutation.mutate({ id: approvalId });
    } else {
      denyMutation.mutate({ id: approvalId });
    }
  };

  if (isLoading) {
    return (
      <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl animate-pulse">
        <div className="h-4 w-48 bg-white/5 rounded-full mb-10" />
        <div className="space-y-4">
          {[1, 2].map((i) => (
            <div
              key={i}
              className="h-32 bg-white/[0.02] border border-white/5 rounded-[2rem]"
            />
          ))}
        </div>
      </div>
    );
  }

  const pending = approvals.filter((a) => a.status === "pending");
  const decided = approvals.filter((a) => a.status !== "pending");

  return (
    <div className="bg-surface-3/40 backdrop-blur-3xl border border-white/5 rounded-[2.5rem] p-10 shadow-2xl relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-br from-warning/5 via-transparent to-transparent opacity-30 pointer-events-none" />

      {/* Header */}
      <div className="flex items-center justify-between mb-10 relative z-10">
        <div className="flex items-center gap-5">
          <div className="w-14 h-14 bg-warning/10 border border-warning/20 rounded-2xl flex items-center justify-center shadow-[0_0_30px_hsla(var(--warning),0.1)]">
            <UserCheck className="w-7 h-7 text-warning" />
          </div>
          <div>
            <h3 className="text-xl md:text-2xl font-black text-white tracking-tight font-outfit uppercase leading-tight">
              Authorization Queue
            </h3>
            <p className="text-[10px] text-muted-foreground/40 font-bold uppercase tracking-[0.3em] mt-2">
              Human-in-the-loop Governance
            </p>
          </div>
        </div>
        <div className="flex flex-col items-end">
          <span className="text-3xl font-black text-white leading-none tracking-tighter">
            {activeTab === "pending" ? pending.length : decided.length}
          </span>
          <span className="text-[9px] text-warning font-black uppercase tracking-widest mt-1">
            {activeTab === "pending" ? "Active Requests" : "Recent Decisions"}
          </span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-8 p-1 bg-black/40 border border-white/5 rounded-2xl relative z-10">
        <button
          type="button"
          onClick={() => setActiveTab("pending")}
          className={cn(
            "flex-1 flex items-center justify-center gap-3 py-4 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-premium",
            activeTab === "pending"
              ? "bg-warning/10 text-warning border border-warning/20 shadow-lg"
              : "text-muted-foreground/40 hover:text-white",
          )}
        >
          <Clock className="w-4 h-4" />
          Pending
          {pending.length > 0 && (
            <span className="bg-warning text-black text-[9px] font-black rounded-full px-2 py-0.5 min-w-[1.4rem] text-center shadow-[0_0_10px_hsla(var(--warning),0.5)]">
              {pending.length}
            </span>
          )}
        </button>
        <button
          type="button"
          onClick={() => setActiveTab("decided")}
          className={cn(
            "flex-1 flex items-center justify-center gap-3 py-4 rounded-xl text-[10px] font-black uppercase tracking-[0.2em] transition-premium",
            activeTab === "decided"
              ? "bg-primary/10 text-primary border border-primary/20 shadow-lg"
              : "text-muted-foreground/40 hover:text-white",
          )}
        >
          <History className="w-4 h-4" />
          History
        </button>
      </div>

      {activeTab === "pending" ? (
        <div className="space-y-4 relative z-10">
          {pending.length === 0 ? (
            <div className="text-center py-20 bg-white/[0.01] border border-dashed border-white/5 rounded-[2.5rem] relative group overflow-hidden">
              <div className="absolute inset-0 bg-success/5 opacity-0 group-hover:opacity-100 transition-premium blur-3xl pointer-events-none" />
              <CheckCircle2 className="w-16 h-16 text-success/20 mb-6 mx-auto group-hover:text-success/40 transition-premium" />
              <p className="text-sm text-muted-foreground font-black uppercase tracking-[0.2em]">All Systems Authorized</p>
              <p className="text-[10px] text-muted-foreground/30 font-bold uppercase tracking-widest mt-2">
                No manual intervention required at this time.
              </p>
            </div>
          ) : (
            pending.map((approval) => (
              <div
                key={approval.id}
                className="bg-white/[0.02] border border-white/5 rounded-[2rem] p-6 hover:bg-white/[0.04] hover:border-white/10 transition-premium group relative overflow-hidden"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-warning/5 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-premium pointer-events-none" />
                
                <div className="flex items-center justify-between mb-5 relative z-10">
                  <div className="flex items-center gap-4">
                    <div className="w-2.5 h-2.5 rounded-full bg-warning animate-status-pulse shadow-[0_0_10px_hsla(var(--warning),0.5)]" />
                    <span className="text-xs font-black font-mono text-primary bg-primary/5 border border-primary/10 px-3 py-1 rounded-xl uppercase tracking-tighter">
                      EXECUTION_ID: {approval.executionId.slice(0, 12)}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 text-[9px] text-muted-foreground/40 font-black uppercase tracking-widest">
                    <Clock className="w-3.5 h-3.5 opacity-40" />
                    {new Date(approval.requestedAt).toLocaleString()}
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 mb-6 relative z-10">
                  {approval.requiredFor.map((op: string) => (
                    <div
                      key={op}
                      className="flex items-center gap-2 px-3 py-1.5 rounded-xl bg-black/40 border border-white/5 text-[9px] font-black text-white uppercase tracking-widest group-hover:border-warning/30 transition-premium shadow-sm"
                    >
                      <ShieldAlert className="w-3 h-3 text-warning" />
                      {op}
                    </div>
                  ))}
                </div>

                <div className="grid grid-cols-2 gap-4 relative z-10">
                  <Button
                    className="h-14 rounded-2xl font-black text-[10px] uppercase tracking-[0.2em] shadow-xl bg-success/10 hover:bg-success text-success hover:text-black border border-success/20 transition-premium"
                    onClick={() => handleDecision(approval.id, "approved")}
                  >
                    <Check className="w-4 h-4 mr-3" />
                    Authorize Protocol
                  </Button>
                  <Button
                    variant="ghost"
                    className="h-14 rounded-2xl font-black text-[10px] uppercase tracking-[0.2em] text-muted-foreground/40 hover:text-destructive hover:bg-destructive/10 border border-transparent hover:border-destructive/20 transition-premium"
                    onClick={() => handleDecision(approval.id, "denied")}
                  >
                    <X className="w-4 h-4 mr-3" />
                    Terminate Sequence
                  </Button>
                </div>
              </div>
            ))
          )}
        </div>
      ) : (
        <div className="space-y-4 relative z-10">
          {decided.length === 0 ? (
            <div className="text-center py-20 bg-white/[0.01] border border-dashed border-white/5 rounded-[2.5rem]">
              <History className="w-16 h-16 text-muted-foreground/10 mb-6 mx-auto" />
              <p className="text-sm text-muted-foreground/40 font-black uppercase tracking-[0.2em]">Archive Empty</p>
            </div>
          ) : (
            decided.map((approval) => (
              <div
                key={approval.id}
                className="bg-white/[0.01] border border-white/5 rounded-[2rem] p-6 opacity-60 hover:opacity-100 transition-premium grayscale hover:grayscale-0"
              >
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-4">
                    {approval.status === "approved" ? (
                      <div className="w-8 h-8 bg-success/10 border border-success/20 rounded-xl flex items-center justify-center">
                        <ShieldCheck className="w-4 h-4 text-success" />
                      </div>
                    ) : (
                      <div className="w-8 h-8 bg-destructive/10 border border-destructive/20 rounded-xl flex items-center justify-center">
                        <ShieldX className="w-4 h-4 text-destructive" />
                      </div>
                    )}
                    <span className="text-xs font-black font-mono text-muted-foreground/60 uppercase tracking-tighter">
                      EXECUTION_ID: {approval.executionId.slice(0, 12)}
                    </span>
                    <span
                      className={cn(
                        "text-[9px] font-black uppercase tracking-widest px-2.5 py-1 rounded-xl border shadow-sm",
                        approval.status === "approved"
                          ? "text-success bg-success/5 border-success/10"
                          : "text-destructive bg-destructive/5 border-destructive/10",
                      )}
                    >
                      {approval.status.toUpperCase()}
                    </span>
                  </div>
                  <div className="text-[10px] text-muted-foreground/30 font-black uppercase tracking-tighter">
                    {approval.decidedAt
                      ? new Date(approval.decidedAt).toLocaleString()
                      : "ARCHIVED"}
                  </div>
                </div>

                {approval.reason && (
                  <div className="bg-black/20 border border-white/5 p-4 rounded-2xl mb-5">
                    <p className="text-[11px] text-muted-foreground/60 italic font-medium">
                      "{approval.reason}"
                    </p>
                  </div>
                )}

                <div className="flex items-center gap-6 pt-4 border-t border-white/5">
                  <div className="flex items-center gap-2 text-[9px] text-muted-foreground/40 font-black uppercase tracking-widest">
                    <User className="w-3.5 h-3.5 opacity-30" />
                    AUTHORIZED_BY: {approval.decidedBy ? approval.decidedBy.slice(0, 8) : "SYSTEM_CORE"}
                  </div>
                  <button className="flex items-center gap-2 text-[9px] text-primary/40 hover:text-primary font-black uppercase tracking-widest transition-premium ml-auto">
                    <ExternalLink className="w-3.5 h-3.5" />
                    Review Audit Trail
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      )}

      <div className="mt-10 pt-6 border-t border-white/5 flex items-center justify-between relative z-10">
        <div className="flex items-center gap-3">
          <Zap className="w-4 h-4 text-warning opacity-30" />
          <p className="text-[9px] text-muted-foreground/20 font-black uppercase tracking-[0.3em]">
            Operational Sovereignty Active &bull; Real-Time Governance
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse shadow-[0_0_8px_hsla(var(--success),0.5)]" />
          <span className="text-[9px] text-muted-foreground/40 font-black uppercase tracking-widest">
            Telemetry Feed Live
          </span>
        </div>
      </div>
    </div>
  );
}

