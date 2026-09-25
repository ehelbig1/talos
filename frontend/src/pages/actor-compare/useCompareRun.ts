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

const TERMINAL: ReadonlySet<ExecStatus> = new Set([
  "completed",
  "failed",
  "cancelled",
  "idle",
]);
/** History reads per completed lane before its output is given up on. */
const MAX_OUTPUT_FETCH_ATTEMPTS = 5;

/**
 * A lane's status after one `executionUpdates` event. The server sends the
 * uppercase `ExecutionStatus` values; only an execution-level event (no
 * `nodeId`) can end the run — a node's COMPLETED/FAILED is not the run's.
 */
export function laneStatusFromEvent(
  current: ExecStatus,
  event: Pick<ExecutionUpdate, "status" | "nodeId">,
): ExecStatus {
  if (TERMINAL.has(current)) return current;
  if (!event.nodeId) {
    if (event.status === "COMPLETED") return "completed";
    if (event.status === "FAILED") return "failed";
  }
  if (event.status === "RUNNING" || event.status === "WAITING") {
    return "running";
  }
  return current;
}

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
  // The polling loop reads the latest lanes here instead of via an updater.
  const lanesRef = useRef<LaneState[]>(lanes);
  useEffect(() => {
    lanesRef.current = lanes;
  }, [lanes]);

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
          const now = Date.now();
          setLanes((prev) =>
            prev.map((l) => {
              if (l.actor.id !== actor.id) return l;
              const newStatus = laneStatusFromEvent(l.status, event);
              const ended =
                newStatus !== l.status &&
                (newStatus === "completed" || newStatus === "failed");
              return {
                ...l,
                status: newStatus,
                logs: event.logMessage ? [...l.logs, event.logMessage] : l.logs,
                durationMs:
                  ended && l.startedAt ? now - l.startedAt : l.durationMs,
                errorMessage:
                  ended && newStatus === "failed"
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
    // Side effects live here, never inside a `setLanes` updater (React may
    // invoke an updater twice). Each finished lane's output is read until
    // it is found, at most MAX_OUTPUT_FETCH_ATTEMPTS times — not every tick.
    const resolved = new Set<string>();
    const attempts = new Map<string, number>();
    let inFlight = false;
    const stop = () => {
      clearInterval(interval);
      outputPollIntervalRef.current = null;
      if (outputPollTimeoutRef.current) {
        clearTimeout(outputPollTimeoutRef.current);
        outputPollTimeoutRef.current = null;
      }
      setRunning(false);
    };
    const interval = setInterval(() => {
      if (inFlight) return;
      const current = lanesRef.current.filter((l) =>
        actorIds.includes(l.actor.id),
      );
      const pending = current.filter(
        (l): l is LaneState & { executionId: string } =>
          (l.status === "completed" || l.status === "failed") &&
          l.executionId !== null &&
          l.output === null &&
          !resolved.has(l.executionId) &&
          (attempts.get(l.executionId) ?? 0) < MAX_OUTPUT_FETCH_ATTEMPTS,
      );
      if (pending.length === 0) {
        if (current.every((l) => TERMINAL.has(l.status))) stop();
        return;
      }
      for (const l of pending) {
        attempts.set(l.executionId, (attempts.get(l.executionId) ?? 0) + 1);
      }
      inFlight = true;
      getWorkflowExecutionHistory(selectedWorkflowId, 50)
        .then((history) => {
          const byId = new Map(history.map((e) => [e.id, e]));
          for (const l of pending) {
            if (byId.has(l.executionId)) resolved.add(l.executionId);
          }
          setLanes((prev) =>
            prev.map((lane) => {
              const match = lane.executionId
                ? byId.get(lane.executionId)
                : undefined;
              if (!match) return lane;
              return {
                ...lane,
                output:
                  match.outputData != null
                    ? typeof match.outputData === "string"
                      ? match.outputData
                      : JSON.stringify(match.outputData)
                    : lane.output,
                errorMessage: match.errorMessage ?? lane.errorMessage,
                durationMs: match.durationMs ?? lane.durationMs,
              };
            }),
          );
        })
        .catch((err: unknown) => {
          if (import.meta.env.DEV)
            console.warn("Failed to load execution history:", err);
        })
        .finally(() => {
          inFlight = false;
        });
    }, 3000);
    outputPollIntervalRef.current = interval;

    // Safety stop after 10 minutes
    outputPollTimeoutRef.current = setTimeout(stop, 600_000);
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
