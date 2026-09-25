/**
 * The editor's live-execution sync, driven through scripted subscriptions.
 * The server sends `ExecutionStatus` values (WAITING / SKIPPED …); the hook
 * compared against "AwaitingApproval", which the server never sends, so a
 * node paused on an approval gate stayed "running" and the stuck-run
 * watchdog could clear a legitimately paused run.
 */
import React from "react";
import { act, renderHook } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type {
  ExecutionUpdate,
  WorkflowExecutionUpdate,
} from "@/lib/graphqlClient";

const lifecycle: Array<(ev: WorkflowExecutionUpdate) => void> = [];
const detail: Array<(ev: ExecutionUpdate) => void> = [];
vi.mock("@/lib/graphqlClient", () => ({
  subscribeWorkflowExecutions: vi.fn(
    (cb: (ev: WorkflowExecutionUpdate) => void) => {
      lifecycle.push(cb);
      return () => {};
    },
  ),
  subscribeExecution: vi.fn(
    (_id: string, cb: (ev: ExecutionUpdate) => void) => {
      detail.push(cb);
      return () => {};
    },
  ),
  subscribeLlmStream: vi.fn(() => () => {}),
}));
vi.mock("sonner", () => ({ toast: { warning: vi.fn() } }));

import {
  streamingTokenTarget,
  useActiveExecutionSync,
} from "./useActiveExecutionSync";
import { useEphemeralExecutionStore } from "@/store/executionStore";

const WF = "wf-1";

function mount() {
  const qc = new QueryClient();
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={qc}>{children}</QueryClientProvider>
  );
  return renderHook(() => useActiveExecutionSync(WF), { wrapper });
}

function start(execId = "e1") {
  act(() => {
    lifecycle[lifecycle.length - 1]({
      workflowId: WF,
      executionId: execId,
      userId: "u",
      status: "running",
      startedAt: "",
    });
  });
}

function emit(ev: Omit<ExecutionUpdate, "executionId">) {
  act(() => detail[detail.length - 1]({ executionId: "e1", ...ev }));
}

describe("useActiveExecutionSync", () => {
  beforeEach(() => {
    lifecycle.length = 0;
    detail.length = 0;
    vi.useFakeTimers();
    useEphemeralExecutionStore.setState({
      nodeStatuses: {},
      isRunning: false,
      currentExecutionId: null,
    });
  });
  afterEach(() => vi.useRealTimers());

  it("maps node-level WAITING to awaiting approval and SKIPPED to skipped", () => {
    mount();
    start();
    emit({ nodeId: "n1", status: "RUNNING" });
    emit({ nodeId: "n1", status: "WAITING" });
    emit({ nodeId: "n2", status: "SKIPPED" });
    const s = useEphemeralExecutionStore.getState().nodeStatuses;
    expect(s.n1.status).toBe("awaiting_approval");
    expect(s.n2.status).toBe("skipped");
  });

  it("the watchdog leaves a node awaiting approval alone", () => {
    mount();
    start();
    emit({ nodeId: "n1", status: "WAITING" });
    act(() => vi.advanceTimersByTime(20 * 60 * 1000));
    expect(useEphemeralExecutionStore.getState().isRunning).toBe(true);
  });

  it("the watchdog leaves a suspended run (execution-level WAITING) alone, and clears an idle one", () => {
    mount();
    start();
    emit({ status: "WAITING" });
    act(() => vi.advanceTimersByTime(20 * 60 * 1000));
    expect(useEphemeralExecutionStore.getState().isRunning).toBe(true);
    // Control: once the run reports anything else, a long idle is stuck.
    emit({ status: "RUNNING" });
    act(() => vi.advanceTimersByTime(20 * 60 * 1000));
    expect(useEphemeralExecutionStore.getState().isRunning).toBe(false);
  });

  it("unmount cancels the pending terminal cleanup so it cannot clear a newer run", () => {
    const { unmount } = mount();
    start();
    act(() => {
      lifecycle[0]({
        workflowId: WF,
        executionId: "e1",
        userId: "u",
        status: "completed",
        startedAt: "",
      });
    });
    unmount();
    // A run started elsewhere within the grace period.
    act(() => useEphemeralExecutionStore.getState().setRunning("e2", "wf-2"));
    act(() => vi.advanceTimersByTime(2000));
    const st = useEphemeralExecutionStore.getState();
    expect(st.isRunning).toBe(true);
    expect(st.currentExecutionId).toBe("e2");
  });
});

describe("streamingTokenTarget", () => {
  it("attributes a token only when exactly one node is running", () => {
    expect(streamingTokenTarget({ a: { status: "running" } })).toBe("a");
    expect(
      streamingTokenTarget({
        a: { status: "running" },
        b: { status: "running" },
      }),
    ).toBeNull();
    expect(streamingTokenTarget({ a: { status: "success" } })).toBeNull();
  });
});
