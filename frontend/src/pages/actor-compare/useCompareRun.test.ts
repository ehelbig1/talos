/**
 * The compare page's run orchestration: lane status follows the server's
 * uppercase `ExecutionStatus` values (a lowercase comparison left every lane
 * "queued" forever), and a finished lane's output is fetched ONCE, outside
 * any state updater.
 */
import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ExecutionUpdate } from "@/lib/graphqlClient";

const handlers: Array<(ev: ExecutionUpdate) => void> = [];
vi.mock("@/lib/graphqlClient", () => ({
  subscribeExecution: vi.fn(
    (_id: string, cb: (ev: ExecutionUpdate) => void) => {
      handlers.push(cb);
      return () => {};
    },
  ),
}));
vi.mock("@/lib/graphqlApi", () => ({
  triggerWorkflowAsActor: vi.fn(async (_wf: string, actorId: string) => ({
    id: `exec-${actorId}`,
  })),
  getWorkflowExecutionHistory: vi.fn(async () => [
    { id: "exec-a", outputData: null, errorMessage: null, durationMs: 5 },
    { id: "exec-b", outputData: { ok: 1 }, errorMessage: null, durationMs: 7 },
  ]),
}));

import { getWorkflowExecutionHistory } from "@/lib/graphqlApi";
import { laneStatusFromEvent, useCompareRun } from "./useCompareRun";

const actors = [
  { id: "a", name: "A" },
  { id: "b", name: "B" },
] as never[];

describe("laneStatusFromEvent", () => {
  it("maps the server's uppercase values; only an execution-level event ends the run", () => {
    expect(laneStatusFromEvent("queued", { status: "RUNNING" })).toBe(
      "running",
    );
    expect(
      laneStatusFromEvent("running", { status: "COMPLETED", nodeId: "n1" }),
    ).toBe("running");
    expect(laneStatusFromEvent("running", { status: "COMPLETED" })).toBe(
      "completed",
    );
    expect(laneStatusFromEvent("running", { status: "FAILED" })).toBe("failed");
    expect(laneStatusFromEvent("completed", { status: "RUNNING" })).toBe(
      "completed",
    );
  });
});

describe("useCompareRun", () => {
  beforeEach(() => {
    handlers.length = 0;
    vi.mocked(getWorkflowExecutionHistory).mockClear();
    vi.useFakeTimers();
  });
  afterEach(() => vi.useRealTimers());

  it("fetches each finished lane's output once, then stops polling", async () => {
    const { result } = renderHook(() =>
      useCompareRun({
        selectedWorkflowId: "wf",
        selectedActorIds: new Set(["a", "b"]),
        activeActors: actors,
      }),
    );
    await act(async () => {
      await result.current.handleRun();
    });
    expect(handlers).toHaveLength(2);
    act(() => {
      handlers[0]({ executionId: "exec-a", status: "COMPLETED" });
      handlers[1]({ executionId: "exec-b", status: "COMPLETED" });
    });
    expect(result.current.lanes.map((l) => l.status)).toEqual([
      "completed",
      "completed",
    ]);
    for (let i = 0; i < 10; i++) {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000);
      });
    }
    // One read resolved both lanes — lane a's null output is not re-read
    // every 3 s.
    expect(getWorkflowExecutionHistory).toHaveBeenCalledTimes(1);
    expect(result.current.lanes[1].output).toBe('{"ok":1}');
    expect(result.current.running).toBe(false);
  });
});
