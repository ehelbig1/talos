import { describe, it, expect, beforeEach } from "vitest";
import {
  MAX_STREAMING_CHARS,
  boundStreamingText,
  flushExecutionUpdates,
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
        processedLogs: [],
        nodeStreamingContent: {},
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
      flushExecutionUpdates();
      expect(useEphemeralExecutionStore.getState().events).toHaveLength(1);
    });

    it("stores the event payload it was given", () => {
      const event = { executionId: "1", status: "ok", elapsedMs: 100 } as any;
      useEphemeralExecutionStore.getState().addEvent(event);
      flushExecutionUpdates();
      expect(useEphemeralExecutionStore.getState().events[0]).toEqual(event);
    });

    it("buffers a burst of events into ONE store update, bounded at 5000", () => {
      let notifications = 0;
      const unsub = useEphemeralExecutionStore.subscribe(() => notifications++);
      const store = useEphemeralExecutionStore.getState();
      for (let i = 0; i < 6000; i++) {
        store.addEvent({
          executionId: "e",
          status: "RUNNING",
          elapsedMs: i,
        } as never);
      }
      expect(notifications).toBe(0);
      flushExecutionUpdates();
      unsub();
      expect(notifications).toBe(1);
      const state = useEphemeralExecutionStore.getState();
      expect(state.events).toHaveLength(5000);
      expect(state.processedLogs).toHaveLength(5000);
      // The newest are kept, with increasing row keys.
      expect(state.events[4999].elapsedMs).toBe(5999);
      expect(state.processedLogs[4999].seq).toBeGreaterThan(
        state.processedLogs[0].seq,
      );
    });

    it("streams tokens in batches and bounds each node's text", () => {
      const store = useEphemeralExecutionStore.getState();
      store.appendNodeStreamingContent("n1", "a".repeat(MAX_STREAMING_CHARS));
      store.appendNodeStreamingContent("n1", "tail");
      flushExecutionUpdates();
      const text =
        useEphemeralExecutionStore.getState().nodeStreamingContent.n1;
      expect(text.length).toBe(MAX_STREAMING_CHARS);
      expect(text.endsWith("tail")).toBe(true);
      expect(boundStreamingText("short")).toBe("short");
    });

    it("a new run discards events buffered for the previous one", () => {
      const store = useEphemeralExecutionStore.getState();
      store.addEvent({ executionId: "old", status: "RUNNING" } as never);
      store.setRunning("new", "wf");
      flushExecutionUpdates();
      expect(useEphemeralExecutionStore.getState().events).toEqual([]);
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
