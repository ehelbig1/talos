/**
 * Unsaved editor changes are not lost: a save clears the dirty flag only if
 * nothing was edited while it was in flight, a stale load response cannot
 * overwrite a newer one, and leaving a dirty editor asks first.
 */
import React from "react";
import { act, render, renderHook, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryRouter, RouterProvider } from "react-router";
import { graphql, HttpResponse, delay } from "msw";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { server } from "../../../vitest.setup";
import { loadWorkflowById } from "../workflowLoader";
import { useWorkflowStore } from "@/store/workflowStore";
import { useWorkflowSave } from "@/hooks/useWorkflowSave";
import {
  UnsavedChangesGuard,
  shouldBlockNavigation,
} from "@/components/UnsavedChangesGuard";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

function addNode() {
  useWorkflowStore
    .getState()
    .addNode("00000000-0000-0000-0000-000000000001", "M", { x: 0, y: 0 });
}

function workflowResponse(id: string, name: string) {
  return {
    data: {
      workflow: {
        id,
        name,
        graphJson: JSON.stringify({ nodes: [], edges: [] }),
        graphVersion: 1,
        actorId: null,
        maxConcurrentExecutions: 1,
        intent: {},
      },
    },
  };
}

beforeEach(() => {
  useWorkflowStore.getState().clearWorkflow();
});

describe("workflow store edit generation", () => {
  it("markClean(generation) refuses once an edit happened after it", () => {
    addNode();
    const gen = useWorkflowStore.getState().editGeneration;
    addNode();
    expect(useWorkflowStore.getState().markClean(gen)).toBe(false);
    expect(useWorkflowStore.getState().isDirty).toBe(true);
    const now = useWorkflowStore.getState().editGeneration;
    expect(useWorkflowStore.getState().markClean(now)).toBe(true);
    expect(useWorkflowStore.getState().isDirty).toBe(false);
  });
});

describe("useWorkflowSave", () => {
  function mount() {
    const qc = new QueryClient();
    const wrapper = ({ children }: { children: React.ReactNode }) => (
      <QueryClientProvider client={qc}>{children}</QueryClientProvider>
    );
    return renderHook(
      () => useWorkflowSave({ workflowId: null, workflowName: "W" }),
      { wrapper },
    );
  }

  it("an edit made while the save is in flight keeps the editor dirty", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    server.use(
      graphql.mutation("CreateWorkflow", async () => {
        await gate;
        return HttpResponse.json({
          data: {
            createWorkflow: {
              id: "wf-1",
              name: "W",
              intent: {},
              graphVersion: 1,
            },
          },
        });
      }),
    );
    addNode();
    const { result } = mount();
    let saving!: Promise<void>;
    act(() => {
      saving = result.current.handleSave();
    });
    await act(async () => {
      await delay(20);
      addNode(); // edited during the save
      release();
      await saving;
    });
    expect(useWorkflowStore.getState().isDirty).toBe(true);
    expect(useWorkflowStore.getState().workflowId).toBe("wf-1");
  });

  it("control: with no edit during the save the editor is clean", async () => {
    server.use(
      graphql.mutation("CreateWorkflow", () =>
        HttpResponse.json({
          data: {
            createWorkflow: {
              id: "wf-1",
              name: "W",
              intent: {},
              graphVersion: 1,
            },
          },
        }),
      ),
    );
    addNode();
    const { result } = mount();
    await act(async () => {
      await result.current.handleSave();
    });
    expect(useWorkflowStore.getState().isDirty).toBe(false);
  });
});

describe("loadWorkflowById", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("a response that arrives after a newer load started is dropped", async () => {
    server.use(
      graphql.query("GetWorkflowLoader", async ({ variables }) => {
        if (variables.id === "wf-slow") {
          await delay(60);
          return HttpResponse.json(workflowResponse("wf-slow", "Slow"));
        }
        return HttpResponse.json(workflowResponse("wf-fast", "Fast"));
      }),
    );
    const slow = loadWorkflowById("wf-slow");
    const fast = loadWorkflowById("wf-fast");
    await expect(fast).resolves.toBe(true);
    await expect(slow).resolves.toBe(false);
    expect(useWorkflowStore.getState().workflowName).toBe("Fast");
  });

  it("a load its caller no longer wants is not applied", async () => {
    server.use(
      graphql.query("GetWorkflowLoader", () =>
        HttpResponse.json(workflowResponse("wf-1", "One")),
      ),
    );
    const applied = await loadWorkflowById("wf-1", { isCurrent: () => false });
    expect(applied).toBe(false);
    expect(useWorkflowStore.getState().workflowId).toBeNull();
  });
});

describe("unsaved-changes guard", () => {
  it("shouldBlockNavigation: dirty blocks, gaining the workflow's own URL does not", () => {
    expect(shouldBlockNavigation(false, null, "/editor", "/")).toBe(false);
    expect(shouldBlockNavigation(true, null, "/editor", "/")).toBe(true);
    expect(shouldBlockNavigation(true, "wf-1", "/editor", "/editor/wf-1")).toBe(
      false,
    );
    expect(
      shouldBlockNavigation(true, "wf-1", "/editor/wf-1", "/editor/wf-2"),
    ).toBe(true);
  });

  it("leaving a dirty editor asks before navigating, and cancel stays", async () => {
    const router = createMemoryRouter(
      [
        { path: "/editor", element: <UnsavedChangesGuard /> },
        { path: "/", element: <div>home</div> },
      ],
      { initialEntries: ["/editor"] },
    );
    render(<RouterProvider router={router} />);
    addNode();
    await act(async () => {
      await router.navigate("/");
    });
    expect(screen.getByText(/Leave and discard them/)).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/editor");
    await act(async () => {
      screen.getByRole("button", { name: "Cancel" }).click();
    });
    expect(router.state.location.pathname).toBe("/editor");
    // Discarding proceeds.
    await act(async () => {
      await router.navigate("/");
    });
    await act(async () => {
      screen.getByRole("button", { name: "Discard" }).click();
    });
    expect(router.state.location.pathname).toBe("/");
    expect(useWorkflowStore.getState().isDirty).toBe(false);
  });

  it("registers a beforeunload prompt only while dirty", () => {
    const add = vi.spyOn(window, "addEventListener");
    const router = createMemoryRouter(
      [{ path: "/editor", element: <UnsavedChangesGuard /> }],
      { initialEntries: ["/editor"] },
    );
    render(<RouterProvider router={router} />);
    expect(add.mock.calls.some(([t]) => t === "beforeunload")).toBe(false);
    act(() => addNode());
    expect(add.mock.calls.some(([t]) => t === "beforeunload")).toBe(true);
    add.mockRestore();
  });
});
