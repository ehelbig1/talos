/**
 * Logout leaves nothing of the previous user's session in this tab: the
 * persisted run history in sessionStorage and the editor's dirty state were
 * both left behind.
 */
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/graphqlClient", () => ({
  graphqlRequest: vi.fn(async () => ({ logout: true })),
}));

import { logout } from "../auth";
import { usePersistedExecutionStore } from "@/store/executionStore";
import { useWorkflowStore } from "@/store/workflowStore";

afterEach(() => vi.unstubAllGlobals());

describe("logout", () => {
  it("clears the persisted execution history and the editor", async () => {
    vi.stubGlobal("location", { href: "/editor" });
    usePersistedExecutionStore
      .getState()
      .setWorkflowStatus("wf-1", { status: "failed", runAt: "t" });
    expect(sessionStorage.getItem("talos_execution_state")).not.toBeNull();
    useWorkflowStore
      .getState()
      .addNode("00000000-0000-0000-0000-000000000001", "M", { x: 0, y: 0 });

    await logout();

    expect(sessionStorage.getItem("talos_execution_state")).toBeNull();
    expect(usePersistedExecutionStore.getState().workflowStatuses).toEqual({});
    expect(useWorkflowStore.getState().isDirty).toBe(false);
    expect(useWorkflowStore.getState().nodes).toEqual([]);
  });
});
