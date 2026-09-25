import { create } from "zustand";
import { persist } from "zustand/middleware";
import { useShallow } from "zustand/react/shallow";

import type { ExecutionUpdate } from "@/lib/graphqlClient";

export type NodeStatusType =
  | "idle"
  | "running"
  | "success"
  | "failed"
  | "skipped"
  | "awaiting_approval";

export interface NodeStatus {
  status: NodeStatusType;
  error?: string;
  durationMs?: number; // Execution duration when completed/failed
  startedAt?: number; // Unix timestamp ms when node started running
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
  /** Monotonic per page: a stable render key as the window slides. */
  seq: number;
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

  appendNodeStreamingContent: (nodeId, token) => {
    pending.tokens.set(nodeId, (pending.tokens.get(nodeId) ?? "") + token);
    scheduleFlush();
  },

  addEvent: (event) => {
    pending.events.push(event);
    if (pending.events.length > MAX_EVENTS) {
      pending.events.splice(0, pending.events.length - MAX_EVENTS);
    }
    scheduleFlush();
  },

  setRunning: (execId, workflowId) => {
    discardPending();
    set({
      currentExecutionId: execId,
      currentWorkflowId: workflowId,
      isRunning: true,
      nodeStatuses: {},
      nodeResults: {},
      nodeStreamingContent: {},
      events: [],
      processedLogs: [],
    });
  },

  clearEvents: () => {
    discardPending();
    set({ events: [], processedLogs: [] });
  },

  clearCurrentExecution: () =>
    set({ currentExecutionId: null, isRunning: false }),

  resetNodeStatuses: () => {
    pending.tokens.clear();
    set({ nodeStatuses: {}, nodeResults: {}, nodeStreamingContent: {} });
  },
}));

// ── Batched appends ─────────────────────────────────────────────────────────
//
// Events and LLM tokens arrive one WebSocket frame at a time. Applying each
// one copied the whole 5000-entry window (twice) and notified every
// subscriber per event / per token. They are buffered and applied at most
// every FLUSH_INTERVAL_MS (a timer, not rAF: rAF stops in a background tab
// and the buffer would grow while nobody looks).

const MAX_EVENTS = 5000;
/** Streaming text kept per node; older text is dropped from the front. */
export const MAX_STREAMING_CHARS = 64_000;
const FLUSH_INTERVAL_MS = 50;

const pending = {
  events: [] as TimedEvent[],
  tokens: new Map<string, string>(),
  timer: null as ReturnType<typeof setTimeout> | null,
};
let logSeq = 0;

function scheduleFlush() {
  if (pending.timer === null) {
    pending.timer = setTimeout(flushExecutionUpdates, FLUSH_INTERVAL_MS);
  }
}

function discardPending() {
  if (pending.timer !== null) clearTimeout(pending.timer);
  pending.timer = null;
  pending.events = [];
  pending.tokens.clear();
}

/** Keep the newest `max` characters of streamed text. */
export function boundStreamingText(text: string, max = MAX_STREAMING_CHARS) {
  return text.length > max ? "…" + text.slice(text.length - max + 1) : text;
}

function toLogEntry(event: TimedEvent): LogEntry {
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

  return {
    seq: ++logSeq,
    text,
    level,
    timestamp,
    nodeId: event.nodeId,
    structured,
  };
}

/** Apply every buffered event and token now. Called by the timer; tests
 *  call it directly. */
export function flushExecutionUpdates() {
  if (pending.timer !== null) clearTimeout(pending.timer);
  pending.timer = null;
  const events = pending.events;
  const tokens = pending.tokens;
  pending.events = [];
  pending.tokens = new Map();
  if (events.length === 0 && tokens.size === 0) return;
  useEphemeralExecutionStore.setState((state) => {
    const patch: Partial<EphemeralSlice> = {};
    if (events.length > 0) {
      patch.events = state.events.concat(events).slice(-MAX_EVENTS);
      patch.processedLogs = state.processedLogs
        .concat(events.map(toLogEntry))
        .slice(-MAX_EVENTS);
    }
    if (tokens.size > 0) {
      const streaming = { ...state.nodeStreamingContent };
      for (const [nodeId, text] of tokens) {
        streaming[nodeId] = boundStreamingText(
          (streaming[nodeId] ?? "") + text,
        );
      }
      patch.nodeStreamingContent = streaming;
    }
    return patch;
  });
}

// Unified facade that combines both stores — uses useShallow to prevent new object
// reference on every render which would cause infinite re-render loops.
export const useExecutionStore = (): ExecutionStore => {
  const persisted = usePersistedExecutionStore(
    useShallow((s) => ({
      workflowStatuses: s.workflowStatuses,
      setWorkflowStatus: s.setWorkflowStatus,
    })),
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
    })),
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
