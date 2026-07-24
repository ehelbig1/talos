/**
 * Run-orchestration layer for the Actor Strategic Compare page: owns the
 * per-actor lane state, sequential trigger + live execution subscriptions,
 * the 3s output-polling loop with its 10-minute safety stop, and full
 * unmount teardown (MCP-892).
 */

import { useState, useEffect, useCallback, useRef } from "react";
import { toast } from "sonner";
import { sanitizeErrorMessage } from "@/lib/sanitize";
import { subscribeExecution, type ExecutionUpdate } from "@/lib/graphqlClient";
import {
  getWorkflowExecutionHistory,
  triggerWorkflowAsActor,
  type ActorSummary,
} from "@/lib/graphqlApi";
import type { ExecStatus, LaneState } from "./types";

export function useCompareRun({
  selectedWorkflowId,
  selectedActorIds,
  activeActors,
}: {
  selectedWorkflowId: string;
  selectedActorIds: Set<string>;
  activeActors: ActorSummary[];
}) {
  const [lanes, setLanes] = useState<LaneState[]>([]);
  const [running, setRunning] = useState(false);

  // Subscriptions cleanup refs
  const unsubscribesRef = useRef<Array<() => void>>([]);
  // MCP-892 (2026-05-14): track the output-polling interval and safety-
  // stop timeout so unmount can cancel them. Pre-fix navigating away
  // mid-comparison left the 3s interval AND the 10min setTimeout
  // running until the safety stop fired naturally — the interval
  // then fired `setLanes` setState on an unmounted component (React
  // warning + leaked closure references).
  const outputPollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(
    null,
  );
  const outputPollTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );

  // Cleanup subscriptions on unmount
  useEffect(() => {
    return () => {
      unsubscribesRef.current.forEach((fn) => fn());
      // MCP-892: also cancel any pending output-poll interval +
      // safety-stop timeout so unmount fully tears down side effects.
      if (outputPollIntervalRef.current) {
        clearInterval(outputPollIntervalRef.current);
        outputPollIntervalRef.current = null;
      }
      if (outputPollTimeoutRef.current) {
        clearTimeout(outputPollTimeoutRef.current);
        outputPollTimeoutRef.current = null;
      }
    };
  }, []);

  const updateLane = useCallback(
    (actorId: string, patch: Partial<LaneState>) => {
      setLanes((prev) =>
        prev.map((l) => (l.actor.id === actorId ? { ...l, ...patch } : l)),
      );
    },
    [],
  );

  const handleRun = async () => {
    if (!selectedWorkflowId) {
      toast.error("Select a workflow first");
      return;
    }
    if (selectedActorIds.size < 2) {
      toast.error("Select at least 2 actors to compare");
      return;
    }

    // Cancel existing subscriptions
    unsubscribesRef.current.forEach((fn) => fn());
    unsubscribesRef.current = [];

    const chosenActors = activeActors.filter((a) => selectedActorIds.has(a.id));

    // Initialise lanes
    setLanes(
      chosenActors.map((actor) => ({
        actor,
        executionId: null,
        status: "triggering",
        logs: [],
        output: null,
        errorMessage: null,
        durationMs: null,
        startedAt: null,
      })),
    );
    setRunning(true);

    // Trigger one execution per actor (sequentially to avoid rate-limiting)
    for (const actor of chosenActors) {
      try {
        const execution = await triggerWorkflowAsActor(
          selectedWorkflowId,
          actor.id,
        );
        const execId = execution.id;

        // Capture the queued-at timestamp inside the state updater (as the
        // live-update handler below does) so Date.now() isn't called in
        // render-reachable scope (react-hooks/purity).
        setLanes((prev) =>
          prev.map((l) =>
            l.actor.id === actor.id
              ? {
                  ...l,
                  executionId: execId,
                  status: "queued",
                  startedAt: Date.now(),
                }
              : l,
          ),
        );

        // Subscribe to live updates for this execution
        const unsub = subscribeExecution(execId, (event: ExecutionUpdate) => {
          setLanes((prev) =>
            prev.map((l) => {
              if (l.actor.id !== actor.id) return l;
              const newLogs = event.logMessage
                ? [...l.logs, event.logMessage]
                : l.logs;
              let newStatus: ExecStatus = l.status;
              if (event.status === "running") newStatus = "running";
              else if (event.status === "completed") newStatus = "completed";
              else if (event.status === "failed") newStatus = "failed";
              else if (event.status === "cancelled") newStatus = "cancelled";

              const now = Date.now();
              const durationMs =
                newStatus === "completed" || newStatus === "failed"
                  ? l.startedAt
                    ? now - l.startedAt
                    : null
                  : l.durationMs;

              return {
                ...l,
                status: newStatus,
                logs: newLogs,
                durationMs,
                errorMessage:
                  newStatus === "failed"
                    ? (event.logMessage ?? l.errorMessage)
                    : l.errorMessage,
              };
            }),
          );
        });
        unsubscribesRef.current.push(unsub);
      } catch (err) {
        updateLane(actor.id, {
          status: "failed",
          errorMessage: sanitizeErrorMessage(String(err)),
        });
      }
    }

    // Poll for final output once each execution completes
    startOutputPolling(chosenActors.map((a) => a.id));
  };

  const startOutputPolling = (actorIds: string[]) => {
    // MCP-892: cancel any prior interval/timeout before starting a
    // new comparison run (handleReset doesn't fire when user just
    // clicks Run again).
    if (outputPollIntervalRef.current) {
      clearInterval(outputPollIntervalRef.current);
    }
    if (outputPollTimeoutRef.current) {
      clearTimeout(outputPollTimeoutRef.current);
    }
    const interval = setInterval(async () => {
      setLanes((current) => {
        // Check if all lanes are terminal
        const allDone = current.every(
          (l) =>
            l.status === "completed" ||
            l.status === "failed" ||
            l.status === "cancelled" ||
            l.status === "idle",
        );
        if (allDone) {
          clearInterval(interval);
          setRunning(false);
        }
        return current;
      });

      // Fetch output for completed lanes that still lack output
      setLanes((current) =>
        current.map((l) => {
          if (
            (l.status === "completed" || l.status === "failed") &&
            l.executionId &&
            l.output === null &&
            actorIds.includes(l.actor.id)
          ) {
            // Fire-and-forget fetch
            getWorkflowExecutionHistory(selectedWorkflowId, 50)
              .then((history) => {
                const match = history.find((e) => e.id === l.executionId);
                if (match) {
                  setLanes((prev) =>
                    prev.map((lane) =>
                      lane.executionId === l.executionId
                        ? {
                            ...lane,
                            output:
                              match.outputData != null
                                ? typeof match.outputData === "string"
                                  ? match.outputData
                                  : JSON.stringify(match.outputData)
                                : lane.output,
                            errorMessage:
                              match.errorMessage ?? lane.errorMessage,
                            durationMs: match.durationMs ?? lane.durationMs,
                          }
                        : lane,
                    ),
                  );
                }
              })
              .catch((err: unknown) => {
                if (import.meta.env.DEV)
                  console.warn("Failed to load execution history:", err);
              });
          }
          return l;
        }),
      );
    }, 3000);
    outputPollIntervalRef.current = interval;

    // Safety stop after 10 minutes
    outputPollTimeoutRef.current = setTimeout(() => {
      clearInterval(interval);
      outputPollIntervalRef.current = null;
      outputPollTimeoutRef.current = null;
      setRunning(false);
    }, 600_000);
  };

  const handleReset = () => {
    unsubscribesRef.current.forEach((fn) => fn());
    unsubscribesRef.current = [];
    setLanes([]);
    setRunning(false);
  };

  const allDone =
    lanes.length > 0 &&
    lanes.every(
      (l) =>
        l.status === "completed" ||
        l.status === "failed" ||
        l.status === "cancelled",
    );

  return { lanes, running, allDone, handleRun, handleReset };
}
