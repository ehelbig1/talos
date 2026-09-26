import { useEffect, useRef } from "react";
import { useQueryClient } from "@tanstack/react-query";
import type {
  WorkflowExecutionUpdate,
  ExecutionUpdate,
} from "@/lib/graphqlClient";
import {
  subscribeWorkflowExecutions,
  subscribeExecution,
  subscribeLlmStream,
} from "@/lib/graphqlClient";
import {
  useEphemeralExecutionStore,
  usePersistedExecutionStore,
} from "@/store/executionStore";
import { toast } from "sonner";

// MCP-889 (2026-05-14): stuck-execution watchdog threshold. If a
// detail subscription receives no events for this long AND no node
// is in awaiting_approval state, treat the execution as terminally
// stuck (worker crash, missed terminal event during WS reconnect,
// NATS broker outage). 15 min is generous for slow-LLM workflows
// while still catching genuinely dead runs within an operator-
// tolerable window.
const EXECUTION_IDLE_TIMEOUT_MS = 15 * 60 * 1000;
const WATCHDOG_INTERVAL_MS = 30 * 1000;
/** Grace period after the terminal lifecycle event for final node events. */
const TERMINAL_CLEANUP_DELAY_MS = 1000;

/**
 * The node an `llmStream` token belongs to. The stream carries no node id
 * (the server yields bare strings), so a token is attributed only when
 * exactly one node is running; with parallel LLM nodes it is dropped rather
 * than shown under the wrong node.
 */
export function streamingTokenTarget(
  nodeStatuses: Record<string, { status: string }>,
): string | null {
  const running = Object.entries(nodeStatuses).filter(
    ([, s]) => s.status === "running",
  );
  return running.length === 1 ? running[0][0] : null;
}

/**
 * A hook that listens for real-time workflow execution events and synchronizes
 * them with the execution store. This ensures the UI (Canvas, Terminal, Inspector)
 * stays in sync with ANY execution happening for the current workflow, whether
 * triggered manually, via webhook, or by a schedule.
 */
export function useActiveExecutionSync(workflowId: string | null) {
  const queryClient = useQueryClient();
  const setNodeStatus = useEphemeralExecutionStore((s) => s.setNodeStatus);
  const setNodeResult = useEphemeralExecutionStore((s) => s.setNodeResult);
  const setRunning = useEphemeralExecutionStore((s) => s.setRunning);
  const addEvent = useEphemeralExecutionStore((s) => s.addEvent);
  const clearCurrentExecution = useEphemeralExecutionStore(
    (s) => s.clearCurrentExecution,
  );
  const setWorkflowStatus = usePersistedExecutionStore(
    (s) => s.setWorkflowStatus,
  );

  const executionSubscriptionRef = useRef<(() => void) | null>(null);
  const activeExecutionIdRef = useRef<string | null>(null);
  const startTimeRef = useRef<number | null>(null);
  // MCP-889: track last detail-subscription event for the watchdog.
  const lastEventTimeRef = useRef<number | null>(null);
  const watchdogIntervalRef = useRef<ReturnType<typeof setInterval> | null>(
    null,
  );
  const cleanupTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Execution-level WAITING (suspended run): a legitimate long pause.
  const pausedRef = useRef(false);

  useEffect(() => {
    if (!workflowId) return;

    // Listen for global workflow execution lifecycle updates
    const unsubscribeLifecycle = subscribeWorkflowExecutions(
      (event: WorkflowExecutionUpdate) => {
        // We only care about events for the current workflow context
        if (event.workflowId !== workflowId) return;

        if (event.status === "running") {
          // A new execution started for this workflow!
          // If we're already tracking this one, ignore.
          // If it's a new one, switch our detail subscription to it.
          if (activeExecutionIdRef.current !== event.executionId) {
            // eslint-disable-next-line react-hooks/immutability -- runtime-safe forward reference: this runs inside an async NATS subscription callback (fires after the hook body has assigned setupDetailSubscription, declared below), so the binding always exists. Reordering the ~120-line declaration above this effect isn't worth the risk for a compiler-ordering hint.
            setupDetailSubscription(event.executionId);
          }
        } else if (event.status === "completed" || event.status === "failed") {
          // The workflow finished. If it's the one we're tracking, mark it done.
          if (activeExecutionIdRef.current === event.executionId) {
            const now = new Date().toISOString();
            setWorkflowStatus(workflowId, {
              status: event.status === "completed" ? "success" : "failed",
              runAt: now,
              error: event.errorMessage,
            });

            // Cleanup detail subscription after a small delay to ensure final
            // events arrive. Tracked so unmount (or a newer run) cancels it:
            // an orphaned timer could clear a run started in the meantime.
            if (cleanupTimerRef.current) clearTimeout(cleanupTimerRef.current);
            cleanupTimerRef.current = setTimeout(() => {
              cleanupTimerRef.current = null;
              if (activeExecutionIdRef.current === event.executionId) {
                clearCurrentExecution();
                if (executionSubscriptionRef.current) {
                  executionSubscriptionRef.current();
                  executionSubscriptionRef.current = null;
                }
                activeExecutionIdRef.current = null;
                // MCP-889: clear stale-detection watchdog now that the
                // lifecycle event delivered the terminal status normally.
                if (watchdogIntervalRef.current) {
                  clearInterval(watchdogIntervalRef.current);
                  watchdogIntervalRef.current = null;
                }
              }
            }, TERMINAL_CLEANUP_DELAY_MS);
          }
        }

        // Invalidate queries to refresh history lists, etc.
        queryClient.invalidateQueries({
          queryKey: ["LatestWorkflowExecutions"],
        });
        queryClient.invalidateQueries({
          queryKey: ["workflow-execution-history", workflowId],
        });
      },
    );

    return () => {
      unsubscribeLifecycle();
      if (executionSubscriptionRef.current) {
        executionSubscriptionRef.current();
        executionSubscriptionRef.current = null;
      }
      activeExecutionIdRef.current = null;
      if (cleanupTimerRef.current) {
        clearTimeout(cleanupTimerRef.current);
        cleanupTimerRef.current = null;
      }
      // MCP-889: cancel any pending watchdog on hook teardown.
      if (watchdogIntervalRef.current) {
        clearInterval(watchdogIntervalRef.current);
        watchdogIntervalRef.current = null;
      }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `setupDetailSubscription` is intentionally omitted: it's a plain (non-memoized) function recreated every render, so listing it would re-run this effect on every render and tear down + re-establish the NATS lifecycle subscription each time. It's only ever invoked from inside the async subscription callback (see the forward-reference note above), where the latest closure is fine. The listed deps are the store setters + ids that actually affect what the subscription does.
  }, [
    workflowId,
    queryClient,
    setNodeStatus,
    setNodeResult,
    setRunning,
    addEvent,
    clearCurrentExecution,
    setWorkflowStatus,
  ]);

  const setupDetailSubscription = (execId: string) => {
    // Cleanup previous subscriptions if any
    if (executionSubscriptionRef.current) {
      executionSubscriptionRef.current();
    }
    // Cancel any prior watchdog / pending cleanup before a new execution.
    if (watchdogIntervalRef.current) {
      clearInterval(watchdogIntervalRef.current);
      watchdogIntervalRef.current = null;
    }
    if (cleanupTimerRef.current) {
      clearTimeout(cleanupTimerRef.current);
      cleanupTimerRef.current = null;
    }
    pausedRef.current = false;

    activeExecutionIdRef.current = execId;
    startTimeRef.current = Date.now();
    lastEventTimeRef.current = Date.now();
    setRunning(execId, workflowId!);

    // MCP-889 (2026-05-14): stuck-execution watchdog. Without it, a
    // detail subscription that loses its terminal lifecycle event
    // (worker crash, missed event during WS reconnect, NATS broker
    // outage) leaves the UI in "running" state forever. Every 30s,
    // check if the detail stream has been idle past
    // EXECUTION_IDLE_TIMEOUT_MS AND no node is awaiting approval
    // (which is a legitimate long-pause state). On stale, toast the
    // user with a refresh hint, clear local execution state, and
    // tear down the subscription so a re-trigger isn't blocked.
    watchdogIntervalRef.current = setInterval(() => {
      const last = lastEventTimeRef.current;
      const active = activeExecutionIdRef.current;
      if (!last || !active || active !== execId) return;

      // If any node is awaiting approval, or the run itself is suspended,
      // the idle is legitimate — either can sit for hours/days.
      const state = useEphemeralExecutionStore.getState();
      const anyAwaitingApproval = Object.values(state.nodeStatuses).some(
        (s) => s.status === "awaiting_approval",
      );
      if (anyAwaitingApproval || pausedRef.current) return;

      if (Date.now() - last > EXECUTION_IDLE_TIMEOUT_MS) {
        toast.warning(
          "Execution stream idle — final status unclear. Refresh history to confirm.",
        );
        clearCurrentExecution();
        if (executionSubscriptionRef.current) {
          executionSubscriptionRef.current();
          executionSubscriptionRef.current = null;
        }
        activeExecutionIdRef.current = null;
        if (watchdogIntervalRef.current) {
          clearInterval(watchdogIntervalRef.current);
          watchdogIntervalRef.current = null;
        }
        // Refresh history queries so the user can see the real
        // post-incident state on the executions list.
        queryClient.invalidateQueries({
          queryKey: ["LatestWorkflowExecutions"],
        });
        queryClient.invalidateQueries({
          queryKey: ["workflow-execution-history", workflowId],
        });
      }
    }, WATCHDOG_INTERVAL_MS);

    const unsubscribeExec = subscribeExecution(
      execId,
      (ev: ExecutionUpdate) => {
        lastEventTimeRef.current = Date.now();
        const elapsedMs =
          startTimeRef.current !== null ? Date.now() - startTimeRef.current : 0;
        addEvent({ ...ev, elapsedMs });

        if (!ev.nodeId) {
          // Execution-level WAITING = the run is suspended; anything else
          // from the run means it is not (or no longer) paused.
          pausedRef.current = ev.status === "WAITING";
        }

        // Handle node-level status changes
        if (ev.nodeId) {
          if (ev.status === "COMPLETED") {
            setNodeStatus(ev.nodeId, {
              status: "success",
              durationMs: ev.durationMs,
            });
            if (ev.logMessage) {
              try {
                setNodeResult(ev.nodeId, JSON.parse(ev.logMessage));
              } catch {
                setNodeResult(ev.nodeId, ev.logMessage);
              }
            }
          } else if (ev.status === "FAILED") {
            setNodeStatus(ev.nodeId, {
              status: ev.errorRecovery ? "success" : "failed",
              error: ev.errorRecovery ? undefined : ev.logMessage,
              durationMs: ev.durationMs,
            });
          } else if (ev.status === "RUNNING") {
            setNodeStatus(ev.nodeId, {
              status: "running",
              startedAt: Date.now(),
            });
          } else if (ev.status === "WAITING") {
            // Node-level WAITING: paused on an approval gate.
            setNodeStatus(ev.nodeId, { status: "awaiting_approval" });
          } else if (ev.status === "SKIPPED") {
            setNodeStatus(ev.nodeId, { status: "skipped" });
          }
        }
      },
    );

    const unsubscribeLlm = subscribeLlmStream(execId, (token) => {
      const state = useEphemeralExecutionStore.getState();
      const runningNodeId = streamingTokenTarget(state.nodeStatuses);
      if (runningNodeId) {
        state.appendNodeStreamingContent(runningNodeId, token);
      }
    });

    executionSubscriptionRef.current = () => {
      unsubscribeExec();
      unsubscribeLlm();
    };
  };
}
