import { create } from "zustand";
import { persist } from "zustand/middleware";
import { useShallow } from "zustand/react/shallow";

import type { ExecutionUpdate } from "@/lib/graphqlClient";

export type NodeStatusType =
  | "idle"
  | "running"
  | "success"
  | "failed"
  | "awaiting_approval";

export interface NodeStatus {
  status: NodeStatusType;
  error?: string;
  durationMs?: number;  // Execution duration when completed/failed
  startedAt?: number;   // Unix timestamp ms when node started running
}

export interface WorkflowRunStatus {
  status: "success" | "failed" | "running";
  runAt: string;
  error?: string;
}

export interface TimedEvent extends ExecutionUpdate {
  elapsedMs: number;
}

export interface LogEntry {
  text: string;
  level: string;
  timestamp: string;
  nodeId?: string;
  structured?: {
    type: "llm_stream" | "tool_call" | "token_usage";
    content?: string;
    toolName?: string;
    arguments?: string;
    inputTokens?: number;
    outputTokens?: number;
  };
}

interface ExecutionStore {
  // Per-node status — reset each session (not persisted)
  nodeStatuses: Record<string, NodeStatus>;
  // Per-workflow last-run status — persisted so Dashboard shows it after refresh
  workflowStatuses: Record<string, WorkflowRunStatus>;
  currentExecutionId: string | null;
  currentWorkflowId: string | null;
  isRunning: boolean;

  setNodeStatus(nodeId: string, s: NodeStatus): void;
  setWorkflowStatus(workflowId: string, s: WorkflowRunStatus): void;
  setRunning(execId: string, workflowId: string): void;
  clearEvents(): void;
  clearCurrentExecution(): void;
  resetNodeStatuses(): void;
}

// We split into two stores: persisted (workflow statuses) and ephemeral (node statuses).
// This avoids persisting large node status maps while keeping dashboard data across reloads.
export interface PersistedSlice {
  workflowStatuses: Record<string, WorkflowRunStatus>;
  setWorkflowStatus(workflowId: string, s: WorkflowRunStatus): void;
}

export const usePersistedExecutionStore = create<PersistedSlice>()(
  persist(
    (set) => ({
      workflowStatuses: {},
      setWorkflowStatus: (workflowId, s) =>
        set((state) => ({
          workflowStatuses: { ...state.workflowStatuses, [workflowId]: s },
        })),
    }),
    {
      name: "talos_execution_state",
      // Use sessionStorage instead of localStorage so execution history is not
      // readable by other same-origin scripts across browser sessions (L3).
      storage: {
        getItem: (name) => {
          const str = sessionStorage.getItem(name);
          if (!str) return null;
          try {
            const data = JSON.parse(str);
            return data;
          } catch {
            return null;
          }
        },
        setItem: (name, value) =>
          sessionStorage.setItem(name, JSON.stringify(value)),
        removeItem: (name) => sessionStorage.removeItem(name),
      },
    },
  ),
);

export interface EphemeralSlice {
  nodeStatuses: Record<string, NodeStatus>;
  nodeResults: Record<string, unknown>;
  nodeStreamingContent: Record<string, string>;
  events: TimedEvent[];
  processedLogs: LogEntry[];
  currentExecutionId: string | null;
  currentWorkflowId: string | null;
  isRunning: boolean;

  setNodeStatus(nodeId: string, s: NodeStatus): void;
  setNodeResult(nodeId: string, result: unknown): void;
  appendNodeStreamingContent(nodeId: string, token: string): void;
  setRunning(execId: string, workflowId: string): void;
  addEvent(event: TimedEvent): void;
  clearEvents(): void;
  clearCurrentExecution(): void;
  resetNodeStatuses(): void;
}

export const useEphemeralExecutionStore = create<EphemeralSlice>()((set) => ({
  nodeStatuses: {},
  nodeResults: {},
  nodeStreamingContent: {},
  events: [],
  processedLogs: [],
  currentExecutionId: null,
  currentWorkflowId: null,
  isRunning: false,

  setNodeStatus: (nodeId, s) =>
    set((state) => ({
      nodeStatuses: { ...state.nodeStatuses, [nodeId]: s },
    })),

  setNodeResult: (nodeId, result) =>
    set((state) => ({
      nodeResults: { ...state.nodeResults, [nodeId]: result },
    })),

  appendNodeStreamingContent: (nodeId, token) =>
    set((state) => ({
      nodeStreamingContent: {
        ...state.nodeStreamingContent,
        [nodeId]: (state.nodeStreamingContent[nodeId] || "") + token,
      },
    })),

  addEvent: (event) =>
    set((state) => {
      // Process the event into a LogEntry immediately
      let level = "[INFO]";
      if (event.status === "FAILED") level = "[ERROR]";
      if (event.logMessage?.toLowerCase().includes("warn")) level = "[WARN]";

      const timestamp = `+${(event.elapsedMs / 1000).toFixed(1)}s`;
      const text = event.logMessage || event.status || "";

      let structured: LogEntry["structured"] | undefined;
      if (
        event.logMessage &&
        (event.logMessage.startsWith("{") || event.logMessage.startsWith("["))
      ) {
        try {
          const parsed = JSON.parse(event.logMessage);
          if (parsed.type === "llm_stream" || parsed.provider) {
            structured = {
              type: "llm_stream",
              content: parsed.text || parsed.content || event.logMessage,
            };
          } else if (parsed.tool_call || parsed.tool_name) {
            structured = {
              type: "tool_call",
              toolName: parsed.tool_name || parsed.tool_call?.name,
              arguments:
                typeof parsed.arguments === "string"
                  ? parsed.arguments
                  : JSON.stringify(parsed.arguments ?? ""),
            };
          } else if (parsed.input_tokens || parsed.output_tokens) {
            structured = {
              type: "token_usage",
              inputTokens: parsed.input_tokens,
              outputTokens: parsed.output_tokens,
            };
          }
        } catch {
          // not structured
        }
      }

      const newLog: LogEntry = {
        text,
        level,
        timestamp,
        nodeId: event.nodeId,
        structured,
      };

      return {
        events: [...state.events, event].slice(-5000),
        processedLogs: [...state.processedLogs, newLog].slice(-5000),
      };
    }),

  setRunning: (execId, workflowId) =>
    set({
      currentExecutionId: execId,
      currentWorkflowId: workflowId,
      isRunning: true,
      nodeStatuses: {},
      nodeResults: {},
      nodeStreamingContent: {},
      events: [],
      processedLogs: [],
    }),

  clearEvents: () => set({ events: [], processedLogs: [] }),

  clearCurrentExecution: () =>
    set({ currentExecutionId: null, isRunning: false }),

  resetNodeStatuses: () => set({ nodeStatuses: {}, nodeResults: {}, nodeStreamingContent: {} }),
}));

// Unified facade that combines both stores — uses useShallow to prevent new object
// reference on every render which would cause infinite re-render loops.
export const useExecutionStore = (): ExecutionStore => {
  const persisted = usePersistedExecutionStore(
    useShallow((s) => ({
      workflowStatuses: s.workflowStatuses,
      setWorkflowStatus: s.setWorkflowStatus,
    }))
  );
  const ephemeral = useEphemeralExecutionStore(
    useShallow((s) => ({
      nodeStatuses: s.nodeStatuses,
      currentExecutionId: s.currentExecutionId,
      currentWorkflowId: s.currentWorkflowId,
      isRunning: s.isRunning,
      setNodeStatus: s.setNodeStatus,
      setRunning: s.setRunning,
      clearEvents: s.clearEvents,
      clearCurrentExecution: s.clearCurrentExecution,
      resetNodeStatuses: s.resetNodeStatuses,
    }))
  );

  return {
    nodeStatuses: ephemeral.nodeStatuses,
    workflowStatuses: persisted.workflowStatuses,
    currentExecutionId: ephemeral.currentExecutionId,
    currentWorkflowId: ephemeral.currentWorkflowId,
    isRunning: ephemeral.isRunning,
    setNodeStatus: ephemeral.setNodeStatus,
    setWorkflowStatus: persisted.setWorkflowStatus,
    setRunning: ephemeral.setRunning,
    clearEvents: ephemeral.clearEvents,
    clearCurrentExecution: ephemeral.clearCurrentExecution,
    resetNodeStatuses: ephemeral.resetNodeStatuses,
  };
};

// Direct access to the stores (for use outside React components)
export const getExecutionStore = () => ({
  ...useEphemeralExecutionStore.getState(),
  ...usePersistedExecutionStore.getState(),
});
