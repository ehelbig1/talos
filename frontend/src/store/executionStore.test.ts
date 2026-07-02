import { describe, it, expect, beforeEach } from "vitest";
import {
  useEphemeralExecutionStore,
  usePersistedExecutionStore,
} from "./executionStore";

describe("executionStore", () => {
  describe("useEphemeralExecutionStore", () => {
    beforeEach(() => {
      useEphemeralExecutionStore.setState({
        nodeStatuses: {},
        nodeResults: {},
        events: [],
        currentExecutionId: null,
        currentWorkflowId: null,
        isRunning: false,
      });
    });

    it("sets node status", () => {
      useEphemeralExecutionStore
        .getState()
        .setNodeStatus("node-1", { status: "running" });
      expect(
        useEphemeralExecutionStore.getState().nodeStatuses["node-1"],
      ).toEqual({ status: "running" });
    });

    it("sets node result", () => {
      const result = { data: 123 };
      useEphemeralExecutionStore.getState().setNodeResult("node-1", result);
      expect(useEphemeralExecutionStore.getState().nodeResults["node-1"]).toBe(
        result,
      );
    });

    it("adds events and limits count", () => {
      const store = useEphemeralExecutionStore.getState();
      const event = {
        nodeId: "n1",
        status: "COMPLETED",
        elapsedMs: 100,
      } as any;
      store.addEvent(event);
      expect(useEphemeralExecutionStore.getState().events).toHaveLength(1);
    });

    it("stores the event payload it was given", () => {
      const event = { executionId: "1", status: "ok", elapsedMs: 100 } as any;
      useEphemeralExecutionStore.getState().addEvent(event);
      expect(useEphemeralExecutionStore.getState().events[0]).toEqual(event);
    });

    it("starts running and clears previous state", () => {
      const store = useEphemeralExecutionStore.getState();
      store.setNodeStatus("old-node", { status: "success" });

      store.setRunning("exec-1", "wf-1");

      const state = useEphemeralExecutionStore.getState();
      expect(state.isRunning).toBe(true);
      expect(state.currentExecutionId).toBe("exec-1");
      expect(state.currentWorkflowId).toBe("wf-1");
      expect(state.nodeStatuses).toEqual({});
    });

    it("clears current execution", () => {
      const store = useEphemeralExecutionStore.getState();
      store.setRunning("exec-1", "wf-1");
      store.clearCurrentExecution();
      expect(useEphemeralExecutionStore.getState().isRunning).toBe(false);
      expect(
        useEphemeralExecutionStore.getState().currentExecutionId,
      ).toBeNull();
    });

    it("resets node statuses", () => {
      const store = useEphemeralExecutionStore.getState();
      store.setNodeStatus("n1", { status: "success" });
      store.setNodeResult("n1", { ok: true });
      store.resetNodeStatuses();
      expect(useEphemeralExecutionStore.getState().nodeStatuses).toEqual({});
      expect(useEphemeralExecutionStore.getState().nodeResults).toEqual({});
    });
  });

  describe("usePersistedExecutionStore", () => {
    beforeEach(() => {
      usePersistedExecutionStore.setState({
        workflowStatuses: {},
      });
    });

    it("sets workflow status", () => {
      const status = {
        status: "success",
        runAt: new Date().toISOString(),
      } as any;
      usePersistedExecutionStore.getState().setWorkflowStatus("wf-1", status);
      expect(
        usePersistedExecutionStore.getState().workflowStatuses["wf-1"],
      ).toEqual(status);
    });
  });
});
