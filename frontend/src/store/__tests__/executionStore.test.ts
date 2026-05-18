import { describe, it, expect, beforeEach } from "vitest";
import {
  useEphemeralExecutionStore,
  usePersistedExecutionStore,
} from "../executionStore";

describe("executionStore", () => {
  beforeEach(() => {
    useEphemeralExecutionStore.getState().resetNodeStatuses();
    useEphemeralExecutionStore.getState().clearCurrentExecution();
    usePersistedExecutionStore.getState().workflowStatuses = {};
  });

  it("sets node status correctly", () => {
    const store = useEphemeralExecutionStore.getState();
    store.setNodeStatus("node-1", { status: "running" });

    expect(
      useEphemeralExecutionStore.getState().nodeStatuses["node-1"],
    ).toEqual({ status: "running" });
  });

  it("sets node result correctly", () => {
    const store = useEphemeralExecutionStore.getState();
    const result = { output: "success" };
    store.setNodeResult("node-1", result);

    expect(useEphemeralExecutionStore.getState().nodeResults["node-1"]).toEqual(
      result,
    );
  });

  it("sets running state and resets ephemeral data", () => {
    const store = useEphemeralExecutionStore.getState();
    store.setNodeStatus("old-node", { status: "success" });

    store.setRunning("exec-123", "wf-456");

    const state = useEphemeralExecutionStore.getState();
    expect(state.currentExecutionId).toBe("exec-123");
    expect(state.currentWorkflowId).toBe("wf-456");
    expect(state.isRunning).toBe(true);
    expect(state.nodeStatuses).toEqual({});
    expect(state.nodeResults).toEqual({});
  });

  it("persists workflow status", () => {
    const store = usePersistedExecutionStore.getState();
    const status = { status: "success" as const, runAt: "2024-01-01" };
    store.setWorkflowStatus("wf-1", status);

    expect(
      usePersistedExecutionStore.getState().workflowStatuses["wf-1"],
    ).toEqual(status);
  });

  it("adds and limits events", () => {
    const store = useEphemeralExecutionStore.getState();
    const event = { executionId: "1", status: "ok", elapsedMs: 100 };

    store.addEvent(event);
    expect(useEphemeralExecutionStore.getState().events).toHaveLength(1);
    expect(useEphemeralExecutionStore.getState().events[0]).toEqual(event);
  });
});
