import React, { useEffect } from "react";
import { subscribeCompilation } from "@/lib/graphqlClient";
import { useCompilationStore } from "@/store/compilationStore";
import { Loader2, CheckCircle2, AlertCircle, Cpu, Zap, X } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * CompilationStatus Component
 * 
 * Listens to real-time compilation telemetry events and displays 
 * active build progress in a premium, floating status indicator.
 */
export function CompilationStatus() {
  const { jobs, updateJob, removeJob } = useCompilationStore();
  // Track per-job dismiss timers so we can cancel them on unmount and avoid
  // scheduling duplicate timers if a terminal event fires more than once.
  const dismissTimers = React.useRef<Map<string, ReturnType<typeof setTimeout>>>(new Map());

  useEffect(() => {
    // MCP-928 (2026-05-14): schedule auto-removal in ONE place so
    // both the subscription handler and the stale-job watchdog can
    // share it. Pre-fix only the subscription handler scheduled the
    // timer; the watchdog's `updateJob({status: "failed"})` mutated
    // the zustand store directly (zustand setters don't fan out to
    // unrelated subscribers), so watchdog-flagged stale jobs sat
    // in the UI as "failed" forever instead of auto-clearing after
    // 8s. The MCP-888 comment block promised the auto-remove path
    // would fire — fix the implementation to match the comment.
    const scheduleAutoRemove = (jobId: string) => {
      if (dismissTimers.current.has(jobId)) return;
      const timer = setTimeout(() => {
        removeJob(jobId);
        dismissTimers.current.delete(jobId);
      }, 8000); // 8 seconds allows user to see the result
      dismissTimers.current.set(jobId, timer);
    };

    // Subscribe to global compilation updates
    const unsubscribe = subscribeCompilation((event) => {
      updateJob(event);

      // If compilation is finished (success or failure),
      // schedule auto-removal after a grace period — but only once per job.
      if (event.status === "success" || event.status === "failed") {
        scheduleAutoRemove(event.jobId);
      }
    });

    // MCP-888 (2026-05-14): stale-job watchdog. Without it, a
    // compilation that stops receiving updates (worker crashed mid-
    // build, dropped NATS messages, broker outage) shows a
    // perpetually-active "Live" badge with no way for the user to
    // learn the build is actually frozen. Every 30s, scan active
    // jobs and synthesize a `failed` event for any job whose
    // `lastUpdated` is older than STALE_THRESHOLD. 5-minute
    // threshold is generous for slow cargo-component compiles
    // while still catching genuinely dead builds.
    //
    // MCP-928 (2026-05-14): the watchdog now also calls
    // `scheduleAutoRemove` directly after flagging the job —
    // updateJob() alone won't trigger the subscription handler's
    // auto-cleanup branch (zustand setters don't broadcast to
    // unrelated subscribers).
    const STALE_THRESHOLD_MS = 5 * 60 * 1000;
    const watchdog = setInterval(() => {
      const now = Date.now();
      const currentJobs = useCompilationStore.getState().jobs;
      for (const job of Object.values(currentJobs)) {
        if (job.status === "success" || job.status === "failed") continue;
        if (now - job.lastUpdated > STALE_THRESHOLD_MS) {
          // Preserve userId from the existing job record so the
          // store's identity invariant holds.
          updateJob({
            jobId: job.jobId,
            userId: job.userId,
            status: "failed",
            progress: job.progress,
            message: "Build timed out — no updates received for 5 minutes",
          });
          scheduleAutoRemove(job.jobId);
        }
      }
    }, 30 * 1000);

    // On unmount: unsubscribe from the stream and cancel all pending timers.
    return () => {
      unsubscribe();
      clearInterval(watchdog);
      dismissTimers.current.forEach((timer) => clearTimeout(timer));
      dismissTimers.current.clear();
    };
  }, [updateJob, removeJob]);

  const activeJobs = Object.values(jobs);
  if (activeJobs.length === 0) return null;

  return (
    <div className="fixed bottom-8 right-8 z-[100] flex flex-col gap-4 max-w-sm w-full animate-in slide-in-from-right-8 duration-500 ease-premium">
      {activeJobs.map((job) => (
        <div
          key={job.jobId}
          className={cn(
            "p-6 rounded-[2rem] border shadow-2xl glass-dark flex flex-col gap-4 relative overflow-hidden transition-premium",
            job.status === "failed" 
              ? "border-destructive/20 bg-destructive/5 shadow-destructive/10" 
              : "border-white/5 bg-surface-2/40 shadow-black/40"
          )}
        >
          {/* Animated Background Gradient for Active Jobs */}
          {(job.status !== "success" && job.status !== "failed") && (
            <div className="absolute inset-0 bg-gradient-to-r from-primary/5 via-transparent to-primary/5 animate-pulse pointer-events-none" />
          )}

          {/* Progress Bar Track */}
          <div className="absolute bottom-0 left-0 h-1 bg-white/5 w-full" />
          
          {/* Active Progress Bar */}
          <div 
            className={cn(
              "absolute bottom-0 left-0 h-1 transition-all duration-1000 ease-premium-out",
              job.status === "success" ? "bg-success shadow-[0_0_15px_hsla(var(--success),0.6)]" :
              job.status === "failed" ? "bg-destructive shadow-[0_0_15px_hsla(var(--destructive),0.6)]" :
              "bg-primary shadow-[0_0_15px_hsla(var(--primary),0.6)]"
            )}
            style={{ width: `${(job.progress || 0) * 100}%` }}
          />

          <div className="flex items-start gap-4 relative z-10">
            {/* Status Icon Container */}
            <div className={cn(
              "w-12 h-12 rounded-[1.25rem] flex items-center justify-center shrink-0 border relative transition-premium",
              job.status === "success" ? "bg-success/10 border-success/20 text-success" :
              job.status === "failed" ? "bg-destructive/10 border-destructive/20 text-destructive" :
              "bg-primary/10 border-primary/20 text-primary"
            )}>
              {job.status === "success" ? <CheckCircle2 className="w-6 h-6" /> :
               job.status === "failed" ? <AlertCircle className="w-6 h-6" /> :
               <Cpu className="w-6 h-6 animate-pulse" />}
              
              {/* Micro-glow for active state */}
              {(job.status !== "success" && job.status !== "failed") && (
                <div className="absolute -inset-2 bg-primary/20 rounded-full blur-xl animate-pulse" />
              )}
            </div>

            <div className="flex flex-col gap-1 min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="text-[9px] font-black uppercase tracking-[0.25em] text-white/30 truncate">
                  Build Log :: {job.jobId.slice(0, 8)}
                </span>
                {(job.status !== "success" && job.status !== "failed") && (
                    <div className="flex items-center gap-1.5">
                        <div className="w-1.5 h-1.5 rounded-full bg-primary animate-ping" />
                        <span className="text-[8px] font-black text-primary uppercase tracking-tighter">Live</span>
                    </div>
                )}
              </div>
              
              <h4 className="text-xs font-black text-white uppercase tracking-tight truncate font-outfit leading-tight mt-0.5">
                {job.message || "Synthesizing Module..."}
              </h4>

              <div className="flex items-center gap-2 mt-1.5">
                 <div className={cn(
                    "px-2 py-0.5 rounded-md text-[8px] font-black uppercase tracking-widest",
                    job.status === "success" ? "bg-success/20 text-success" :
                    job.status === "failed" ? "bg-destructive/20 text-destructive" :
                    "bg-primary/20 text-primary"
                 )}>
                    {job.status}
                 </div>
                 {job.progress !== undefined && (
                     <span className="text-[10px] font-black text-white/20 tabular-nums">
                        {Math.round(job.progress * 100)}%
                     </span>
                 )}
              </div>
            </div>

            {/* Manual Dismiss Button */}
            {(job.status === "success" || job.status === "failed") && (
              <button 
                onClick={() => removeJob(job.jobId)}
                className="text-white/20 hover:text-white hover:bg-white/5 rounded-lg p-1 transition-premium active:scale-90"
              >
                <X className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
