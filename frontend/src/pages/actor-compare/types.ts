/**
 * Shared types for the Actor Strategic Compare page.
 */

import type { ActorSummary } from "@/lib/graphqlApi";

export interface WorkflowOption {
  id: string;
  name: string;
}

export type ExecStatus =
  | "idle"
  | "triggering"
  | "queued"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface LaneState {
  actor: ActorSummary;
  executionId: string | null;
  status: ExecStatus;
  logs: string[];
  output: string | null;
  errorMessage: string | null;
  durationMs: number | null;
  startedAt: number | null;
}
